

#define STR_TRACE_USER_TA "TEST_CRYPTO"

#include <stdlib.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_test_api_crypto.h" //todo check .h directory

typedef struct sess_data{
	TEE_OperationHandle *op_cipher;
	TEE_OperationHandle *op_digest;
}Sess_data;

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}


void TA_DestroyEntryPoint(void)
{
	//nothing to do
	return;
}
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, 
				TEE_Param params[4], void **sess_ctx)
{
	Sess_data *data;

	//unused parameters
	(void)&params;
	(void)&param_types;
 	
 	/* allocate handles which will be used during the session*/
	data = TEE_Malloc(sizeof(Sess_data), 0);
	data->op_cipher = TEE_Malloc(sizeof(TEE_OperationHandle), 0);
	data->op_digest = TEE_Malloc(sizeof(TEE_OperationHandle), 0);
	*sess_ctx = data;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{	

	TEE_Free(((Sess_data *)sess_ctx)->op_cipher);
	TEE_Free(((Sess_data *)sess_ctx)->op_digest);
	TEE_Free(sess_ctx);
}

static TEE_Result encrypt_init(Sess_data* sessiondata,
	 uint32_t param_types, TEE_Param params[4])
{
	// uint32_t exp_param_types = TEE_PARAM_TYPES(
	// 	TEE_PARAM_TYPE_VALUE_INPUT,
	// 	TEE_MEMREF_PARTIAL_INPUT,
	// 	TEE_NONE,
	// 	TEE_NONE);
	// if (params_types != exp_param_types)
	// 	return TEE_ERROR_BAD_PARAMETERS;
	TEE_Result res;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	TEE_ObjectHandle *key = TEE_Malloc(sizeof(TEE_ObjectHandle), 0);
	TEE_ObjectInfo *keyInfo = TEE_Malloc(sizeof(TEE_ObjectInfo), 0);

	(void)&param_types;
	/* Opening persistant object and getting key */
	AMSG("Opening Key Object with KeyID=%d\n", params[0].value.a);
	//printf("KeyID: %d\n", params[0].value.a);
	res = TEE_OpenPersistentObject(
			TEE_STORAGE_PRIVATE,
			&params[0].value.a,
			sizeof(uint32_t),
			flags,
			key);

	TEE_GetObjectInfo(
			*key,
			keyInfo);

	AMSG("Key Info, objectType: %x, objectUsage:  %x, objectSize: %d, handleFlags:%x, datasize: %d\n",
		keyInfo->objectType, keyInfo->objectUsage, keyInfo->objectSize, keyInfo->handleFlags, keyInfo->dataSize);


	if (res != TEE_SUCCESS)
		return res;

	AMSG("Allocating operation\n");
	/*Allocating opration */
	res = TEE_AllocateOperation(
		sessiondata->op_cipher,
		TEE_ALG_AES_CTS,
		TEE_MODE_ENCRYPT,
		128);

	if (res != TEE_SUCCESS)
		return res;

	AMSG("Operation allocated successfuly\n");
	/* Setting operation key */

	/*
		Following code is getting Panic message ????
	*/

	res = TEE_SetOperationKey(
		*(sessiondata->op_cipher),
		*key);
	if (res != TEE_SUCCESS)
		return res;

	AMSG("Key set for the encrypt operation\n");

	TEE_Free(key);
	TEE_Free(keyInfo);
	return res;
}

/*
* Create and store a 128-bits AES key as a persistent object.
*/

static TEE_Result key_generation(void)
{

	/* Allocate AES key object */

	TEE_Result res;
	/* implementation constant TEE_MALLOC_FILL_ZERO is not coded !*/
	TEE_ObjectHandle *key = TEE_Malloc(sizeof(TEE_ObjectHandle), 0);
	TEE_ObjectHandle *persKey = TEE_Malloc(sizeof(TEE_ObjectHandle), 0);
	//TEE_ObjectInfo *keyInfo = TEE_Malloc(sizeof(TEE_ObjectInfo), 0);
	//TEE_ObjectInfo *keyInfo2 = TEE_Malloc(sizeof(TEE_ObjectInfo), 0);

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	uint32_t objectID = 1;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, key);

	if (res != TEE_SUCCESS)
		return res; 

	/* Generate the key */

	res = TEE_GenerateKey(*key, 128, NULL, 0);

	if (res != TEE_SUCCESS)
		return res;

	// TEE_GetObjectInfo(
	// 	*key,
	// 	keyInfo);


//	AMSG("Key Info - objectType: %x, objectUsage:  %x, objectSize: %d, handleFlags:%x, datasize: %d, dataposition: %d\n",
//		keyInfo->objectType, keyInfo->objectUsage, keyInfo->objectSize, keyInfo->handleFlags, keyInfo->dataSize, keyInfo->dataPosition);

	/* Create a persistent key object from the transient key object 
	   KeyID is 1
	 */

	res = TEE_CreatePersistentObject(
			TEE_STORAGE_PRIVATE,
			&objectID, sizeof(uint32_t),
			flags,
			*key,
			NULL,
			0,
			persKey);
	AMSG("AES key created !\n");
	//TEE_GetObjectInfo(
	//	*persKey,
	//	keyInfo2);

	//AMSG("Key Info - objectType: %x, objectUsage:  %x, objectSize: %d, handleFlags:%x  datasize: %d, dataposition: %d\n",
		//keyInfo2->objectType, keyInfo2->objectUsage, keyInfo2->objectSize, keyInfo2->handleFlags, keyInfo2->dataSize, keyInfo2->dataPosition);
	/* Persistent object is created, we don't need the transient object anymore	*/

	TEE_FreeTransientObject(*key);

	return res;

}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, 
						uint32_t param_types, TEE_Param params[4])
{


	switch (cmd_id) {
		case CMD_CREATE_KEY: 
			(void)&params;
			return key_generation();
		case CMD_ENCRYPT_INIT: return encrypt_init((Sess_data*)sess_ctx, param_types, params);
		case CMD_ENCRYPT_UPDATE: 
		case CMD_ENCRYPT_FINAL: 
		case CMD_DIGEST_INIT: 
		case CMD_DIGEST_UPDATE: 
		case CMD_DIGEST_FINAL:

		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}

