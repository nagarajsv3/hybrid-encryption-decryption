1. Message Level Encryption is based on JOSE standards
2. Lets use bouncy castle for converting PEM file content to private key
3. Keytool generates in java readable format
4. Openssl generates certs in pem format

**_Loading Private Keys_**
PKCS#8 -> 
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----

**_PKCS#1 keys_**
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----

**_ASN1 Decoder_**
https://lapo.it/asn1js/