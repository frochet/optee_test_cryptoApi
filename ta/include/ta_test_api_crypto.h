

#ifndef TA_TEST_API_CRYPTO_H
#define TA_TEST_API_CRYPTO_H

/* TA UUID */
#define TA_TEST_API_CRYPTO {0xe1ee6b22, 0x560b, 0x11e4, \
		{ 0xaa, 0x81, 0x00, 0x25, 0x22, 0x21, 0xc4, 0xf0} }

/*The TAFs ID implemented in this TA*/

#define CMD_ENCRYPT_INIT	0
#define CMD_ENCRYPT_UPDATE	1
#define CMD_ENCRYPT_FINAL	2
#define CMD_DIGEST_INIT 	3
#define CMD_DIGEST_UPDATE 	4
#define CMD_DIGEST_FINAL	5
#define CMD_CREATE_KEY		6


typedef struct sess_data{
	TEE_Operationhandle *op_cipher;
	TEE_Operationhandle *op_digest;
}Sess_data;

#endif /*TA_TEST_API_CRYPTO_H*/