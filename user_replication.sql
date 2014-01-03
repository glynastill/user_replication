-- ***************************************************************************************************************
-- User management routines - Glyn Astill 21/03/2008
--
-- Creates table and triggers to create, alter and drop users based on inserts into the table
-- Creates a set of functions to manage users via rows in the table
-- Once the table is put into (slony) replication then users sould get replicated on all nodes.
-- ***************************************************************************************************************

SET search_path TO public;

DROP TABLE IF EXISTS public.replicated_users;
CREATE TABLE public.replicated_users
(
  username text PRIMARY KEY,
  password BYTEA NOT NULL,
  options text
);  

--

DROP FUNCTION IF EXISTS public.decrypt_replicated_users(bytea, text);
CREATE OR REPLACE FUNCTION public.decrypt_replicated_users(in_pass bytea, in_username text) 
RETURNS text AS 
$BODY$
DECLARE
	v_use_hkey boolean;
BEGIN
  	v_use_hkey := false;
  	IF (v_use_hkey) THEN
  		RETURN pgp_sym_decrypt(in_pass, hkey(in_username));
  	ELSE
  		RETURN convert_from(in_pass, 'latin1');
  	END IF;
END;
$BODY$ 
LANGUAGE plpgsql IMMUTABLE;
REVOKE ALL ON FUNCTION public.decrypt_replicated_users(bytea, text) FROM PUBLIC;
  
--

DROP FUNCTION IF EXISTS public.encrypt_replicated_users(text, text);
CREATE OR REPLACE FUNCTION public.encrypt_replicated_users(in_pass text, in_username text) 
RETURNS bytea AS 
$BODY$
DECLARE
	v_use_hkey boolean;
BEGIN
  	v_use_hkey := false;
  	IF (v_use_hkey) THEN
  		RETURN pgp_sym_encrypt(in_pass, hkey(in_username));
  	ELSE
  		RETURN convert_to('md5' || md5(in_pass  || in_username), 'latin1');
  	END IF;
END;
$BODY$ 
LANGUAGE plpgsql IMMUTABLE;
REVOKE ALL ON FUNCTION public.encrypt_replicated_users(text, text) FROM PUBLIC;
  
--

DROP FUNCTION IF EXISTS public.replicate_users();
CREATE OR REPLACE FUNCTION public.replicate_users() 
RETURNS TRIGGER AS 
$BODY$
DECLARE
	v_query text;
	v_query2 text;
	v_query3 text;
	v_notice text;
BEGIN

	v_query := '';
	v_query2 := '';
	v_query3 := '';
	v_notice := '';

	IF (TG_OP <> 'DELETE') THEN
		IF ((upper(NEW.options) ~ 'SUPERUSER') OR (upper(NEW.options) ~ 'CREATEDB') OR (upper(NEW.options) ~ 'CREATEROLE')) THEN
			RAISE NOTICE 'USER REPLICATION SYSTEM: Sorry, restricted to creating users without SUPERUSER or CREATE options.';
			RETURN NULL;
		END IF;
	END IF;

	IF (TG_OP = 'INSERT') THEN
		IF ((NEW.username IS NOT NULL) AND (NEW.username <> '')) THEN   
			IF ((public.decrypt_replicated_users(NEW.password, NEW.username) IS NOT NULL) AND (public.decrypt_replicated_users(NEW.password, NEW.username) <> '')) THEN
				v_query := 'CREATE USER ' || quote_ident(NEW.username) || ' WITH ENCRYPTED PASSWORD  ' || quote_literal(public.decrypt_replicated_users(NEW.password, NEW.username)) || ' ';
			ELSE  
				v_query := 'CREATE USER ' || quote_ident(NEW.username) || ' ';
			END IF;

			IF ((NEW.options IS NOT NULL) AND (NEW.options <> '') and (upper(NEW.options) ~ 'IN GROUP')) THEN
				v_query := v_query || NEW.options;
			END IF;

			v_notice := 'Create user: ' || NEW.username;
		ELSE
			v_notice := 'Create user failed: no username supplied';
		END IF;

		RAISE NOTICE 'USER REPLICATION SYSTEM: %', v_notice;

		IF (v_query <> '') THEN
			EXECUTE v_query;
			RETURN NEW;
		END IF;
	ELSEIF (TG_OP = 'UPDATE') THEN
		IF (NEW.username = OLD.username) THEN
			IF ((NEW.username IS NOT NULL) AND (NEW.username <> '')) THEN   
				IF ((public.decrypt_replicated_users(NEW.password, NEW.username) IS NOT NULL) AND (public.decrypt_replicated_users(NEW.password, NEW.username) <> '')) THEN
					v_query := 'ALTER USER ' || quote_ident(NEW.username) || ' WITH ENCRYPTED PASSWORD  ' || quote_literal(public.decrypt_replicated_users(NEW.password, NEW.username));
					v_notice := 'Alter user: change password for ' || NEW.username;
				END IF;
				IF ((NEW.options IS NOT NULL) AND (NEW.options <> '')) THEN
					v_query2 := 'GRANT ' || replace(replace(NEW.options, 'IN GROUP ', ''),'in group ','') || ' TO ' || quote_ident(NEW.username);

					IF (v_notice = '') THEN
						v_notice := 'Alter user: ' || NEW.username || ' ' || NEW.options;
					ELSE 
	    					v_notice := v_notice || ' ' || NEW.options;
	  				END IF;

	  				IF ((OLD.options IS NOT NULL) AND (OLD.options <> '')) THEN
						v_query3 := 'REVOKE ' || replace(replace(OLD.options, 'IN GROUP ', ''),'in group ','') || ' FROM ' || quote_ident(NEW.username);
						v_notice := v_notice || ' (revoked ' || replace(replace(OLD.options, 'IN GROUP ', ''),'in group ','') || ')';
					END IF;
				END IF;

				IF (((NEW.options IS NULL) OR (NEW.options = '')) AND ((public.decrypt_replicated_users(NEW.password, NEW.username) IS NULL) OR (public.decrypt_replicated_users(NEW.password, NEW.username) = ''))) THEN 
					v_notice := 'Alter user failed: no actions supplied';
				END IF;
			ELSE
				v_notice := 'Alter user failed: no username supplied';
			END IF;
		ELSE 
			v_notice := 'Alter user failed: cannot change username';
		END IF;

		RAISE NOTICE 'USER REPLICATION SYSTEM: %', v_notice;

		IF ((v_query <> '') or (v_query2 <> '')) THEN
			IF (v_query <> '') THEN
				EXECUTE v_query;
			END IF;
	
			IF (v_query2 <> '') THEN
				EXECUTE v_query3;
			END IF;

			IF (v_query3 <> '') THEN
				EXECUTE v_query2;
			END IF;
	
			IF ((NEW.options IS NULL) OR (NEW.options = '')) THEN
				NEW.options := OLD.options;
			END IF;
	
			IF ((public.decrypt_replicated_users(NEW.password, NEW.username) IS NULL) OR (public.decrypt_replicated_users(NEW.password, NEW.username) = '')) THEN
				NEW.password := OLD.password;
			END IF;
	
			RETURN NEW;
		END IF;
	ELSEIF (TG_OP = 'DELETE') THEN
		IF ((OLD.username IS NOT NULL) AND (OLD.username <> '')) THEN
			v_query := 'DROP USER ' || quote_ident(OLD.username);
			v_notice := 'Drop user: ' || OLD.username;
		ELSE
			v_notice := 'Drop user failed: no username supplied';
		END IF;

		RAISE NOTICE 'USER REPLICATION SYSTEM: %', v_notice;

		IF (v_query <> '') THEN
			EXECUTE v_query;
			RETURN OLD;
		END IF;
	END IF;

	RETURN NULL;
  
END;
$BODY$ 
LANGUAGE plpgsql VOLATILE SECURITY DEFINER;
REVOKE ALL ON FUNCTION public.replicate_users() FROM PUBLIC;

--

CREATE TRIGGER replicate_users_trigger 
BEFORE INSERT OR UPDATE OR DELETE ON public.replicated_users
FOR EACH ROW EXECUTE PROCEDURE public.replicate_users() ;
ALTER TABLE public.replicated_users ENABLE ALWAYS TRIGGER replicate_users_trigger;

--

DROP FUNCTION IF EXISTS public.create_replicated_user(text, text, text);
CREATE OR REPLACE FUNCTION public.create_replicated_user(cusername text, cpassword text, coptions text) 
RETURNS boolean AS $BODY$    
BEGIN  
	INSERT into public.replicated_users (username, password, options) VALUES (cusername,public.encrypt_replicated_users(cpassword, cusername),coptions);
	IF FOUND THEN
		RETURN true;
	ELSE
		RETURN false;
	END IF;
END;
$BODY$ 
LANGUAGE plpgsql VOLATILE SECURITY DEFINER;
REVOKE ALL ON FUNCTION public.create_replicated_user(cusername text, cpassword text, coptions text) FROM PUBLIC;
   
--

DROP FUNCTION IF EXISTS public.drop_replicated_user(text);
CREATE OR REPLACE FUNCTION public.drop_replicated_user(cusername text) 
RETURNS boolean AS 
$BODY$
BEGIN
	DELETE FROM public.replicated_users WHERE username=cusername; 
	IF FOUND THEN
		RETURN true;
	ELSE
		RETURN false;
	END IF;
END;
$BODY$ 
LANGUAGE plpgsql VOLATILE SECURITY DEFINER;
REVOKE ALL ON FUNCTION public.drop_replicated_user(cusername text) FROM PUBLIC;

--

DROP FUNCTION IF EXISTS public.alter_replicated_user(text, text, text);
CREATE OR REPLACE FUNCTION public.alter_replicated_user(cusername text, cpassword text, coptions text) RETURNS boolean AS $BODY$
BEGIN  
	UPDATE public.replicated_users SET password = public.encrypt_replicated_users(cpassword, cusername), options =  coptions WHERE username = cusername;
	IF FOUND THEN
		RETURN true;
	ELSE
		RETURN false;
	END IF;
END;
$BODY$
LANGUAGE plpgsql VOLATILE SECURITY DEFINER;
REVOKE ALL ON FUNCTION public.alter_replicated_user(cusername text, cpassword text, coptions text) FROM PUBLIC;

--
   
DROP FUNCTION IF EXISTS public.check_replicated_user(text);
CREATE OR REPLACE FUNCTION public.check_replicated_user(usr text) 
RETURNS integer AS
$BODY$
DECLARE 
	v_num integer;
BEGIN
	SELECT INTO v_num count(*) FROM public.replicated_users WHERE username = usr;
	RETURN v_num;
END;
$BODY$
LANGUAGE plpgsql STABLE SECURITY DEFINER;
REVOKE ALL ON FUNCTION public.check_replicated_user(usr text) FROM PUBLIC;

--

DROP FUNCTION IF EXISTS public.detail_replicated_user(text);
CREATE OR REPLACE FUNCTION public.detail_replicated_user(cusername text) 
RETURNS text AS 
$BODY$
DECLARE
	v_user_detail_rec record;
	v_strresult text;
BEGIN
	v_strresult := '';
	SELECT INTO v_user_detail_rec username, public.decrypt_replicated_users(password, username) AS "password", options FROM public.replicated_users WHERE username=cusername;
	IF FOUND THEN
		v_strresult :=  'Username : ' || v_user_detail_rec.username || E'\nPassword : ' || v_user_detail_rec.password || E'\nOptions  : ' || v_user_detail_rec.options || E'\n';
		RETURN v_strresult;
	ELSE
		v_strresult := 'Replicated user not found : ' || cusername || E'\n';
		RETURN v_strresult;
	END IF;
END;
$BODY$ 
LANGUAGE plpgsql STABLE SECURITY DEFINER;
REVOKE ALL ON FUNCTION public.detail_replicated_user(cusername text) FROM PUBLIC;

-- ***************************************************************************************************************
-- Other unrelated useful functions
-- ***************************************************************************************************************

-- Check for logged in user sessions > 1. Note that pooled sessions persist for connection_life_time or equivalent after logout.   
-- DROP FUNCTION IF EXISTS public.check_user_session(text, text);
-- CREATE OR REPLACE FUNCTION public.check_user_session(uame text, dname text) 
-- RETURNS boolean AS
-- $BODY$
-- 	SELECT CASE WHEN count(*) > 1 THEN true ELSE false END FROM pg_stat_activity WHERE "usename" = $1 AND "datname" = $2;
-- $BODY$ 
-- LANGUAGE sql STABLE;

-- Check if a user is logged in
-- DROP FUNCTION IF EXISTS public.check_user_logged(text, text);
-- CREATE OR REPLACE FUNCTION public.check_user_logged(uame text, dname text)
-- RETURNS boolean AS
-- $BODY$
-- 	SELECT CASE WHEN count(*) >= 1 THEN true ELSE false END FROM pg_stat_activity WHERE "usename" = $1 AND "datname" = $2;
-- $BODY$
-- LANGUAGE sql STABLE;