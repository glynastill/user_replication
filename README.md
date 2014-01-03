user_replication
================

A basic table and trigger based user replication example for use
with PostgreSQL and Slony-I.

About
-----

This is something I created back in 2008 to easily keep users in sync 
across a slony cluster.

The supplied functions have various limitations, one of which is the "options" 
field only being useful for managing role membership, anything more complicated 
will most likely fail without further work.

It has the option to store the standard postgresql md5 encrypted passwords, or 
or allow unencrypted password retrieval via a PGP encryption using a symmetric-key
obfuscated during construction with a (rather horrible) c function named "hkey".

If you want to use the hkey obfuscation functionality see *Using the hkey obfuscation*
below.

To use execute the sql script on each node:

    # psql -d <db> user_replication.sql

Now put the 'replicated_users' table into replication using slony and users
can be managed by the create_replicated_user etc functions.

SELECT create_replicated_user('superted', 'test', 'IN GROUP users');
SELECT detail_replicated_user('superted');
SELECT alter_replicated_user('superted', 'test', 'IN GROUP admins');
SELECT alter_replicated_user('superted', 'test', 'IN GROUP admins');

Using the hkey obfuscation
--------------------------

    # cd hkey
    # make
    # make install
    # /usr/local/pgsql/bin/psql -d <db> -U <user> < hkey.sql

Then alter "v_use_hkey := false" to "v_use_hkey := true" in both the
decrypt_replicated_users and encrypt_replicated_users functions.
