//Glyn 08/05/2008 -- Function to obfuscate enctryption key generation based on username

#include "postgres.h"
#include "fmgr.h"
#include <string.h>

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

Datum hkey( PG_FUNCTION_ARGS );

PG_FUNCTION_INFO_V1( hkey );
Datum
hkey( PG_FUNCTION_ARGS )
{
   // variable declarations
   char key[] = "91836zi8euwq45270";
   text *uname;
   int keylen;
   int unamelen;
   text *keying;

   // Get arguments.  If we declare our function as STRICT, then this check is superfluous.
   if( PG_ARGISNULL(0) ) {
      PG_RETURN_NULL();
   }
   uname = PG_GETARG_TEXT_P(0);

   // Calculate string sizes.
   keylen = strlen(key);
   unamelen = VARSIZE(uname) - VARHDRSZ;

   // Allocate memory and set data structure size.
   // Don't forget to add the type overhead (size of the length of the word at the start of the value) of int4 / VARHDRSZ
   keying = (text *)palloc( keylen + unamelen + VARHDRSZ);

   // VARATT_SIZEP depreciated as of 8.3
   //VARATT_SIZEP( keying ) = keylen + unamelen  + VARHDRSZ;
   SET_VARSIZE(keying, keylen + unamelen  + VARHDRSZ);

   // Construct keying string.
   strncpy( VARDATA(keying), key, keylen );
   strncpy( VARDATA(keying) + keylen,
            VARDATA(uname),
            unamelen );

   PG_RETURN_TEXT_P( keying );
}
