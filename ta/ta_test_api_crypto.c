

#define STR_TRACE_USER_TA "TEST_CRYPTO"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_test_api_crypto.h" //todo check .h directory


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

	//unused parameters
	(void)&params
 	
 	/* allocate handles which will be used during the session*/
	Sess_data *data = malloc(sizeof(Sess_data));
	*sess_ctx = data;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	free(sess_ctx);
}

static TEE_Result encrypt_init(Sess_data* sessiondata,
	 uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEEC_VALUE_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_NONE,
		TEEC_NONE);
	if (params_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Opening persistant object and getting key */
	TEE_Result res;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ; 
	TEE_ObjectHandle *key;
	res = TEE_OpenPersistentObject(
			TEE_STORAGE_PRIVATE,
			&params[0].value.a,
			sizeof(uint32_t),
			flags,
			key);

	if (res != TEE_SUCCESS)
		return res;
	/* Setting operation key */


	/*Allocating opration */

	res = TEE_AllocateOperation(
		sessiondata->op_cipher,
		TEE_ALG_AES_CTS,
		TEE_MODE_ENCRYPT,
		128);

	res = TEE_SetOperationKey(
		*(sessiondata->op_cipher),
		*key);
	if (res != TEE_SUCCESS)
		return res;

	return res;
}

/*
* Create and store a 128-bits AES key as a persistent object.
*/

static TEE_Result key_generation(void)
{

	/* Allocate AES key object */

	TEE_Result res;
	TEE_ObjectHandle *key;
	TEE_ObjectHabdke *persKey;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, key);

	if (res != TEEC_SUCCESS)
		return res; 

	/* Generate the key */

	res = TEE_GenerateKey(&key, 128);

	if (res != TEEC_SUCCESS)
		return res;

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCES_WRITE;

	/* Create a persistent key object from the transient key object 
	   KeyID is 1
	 */

	res = TEE_CreatePersistentObject(
			TEE_STORAGE_PRIVATE,
			1, sizeof(uint32_t),
			flags,
			&key,
			NULL,
			0,
			persKey);
	AMSG("AES key created !\n");
	/* Persistent object is created, we don't need the transient object anymore	*/

	TEE_FreeTransientObject(&key);

	return res;

}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, 
						uint32_t param_types, TEE_Param params[4])
{


	switch (cmd_id) {
		case CMD_CREATE_KEY: 
			(void)&params
			return key_generation();
		case CMD_ENCRYPT_INIT: return encrypt_init((Sess_data*)sess_ctx, param_types, params);
		case CMD_ENCRYPT_UPDATE: break;
		case CMD_ENCRYPT_FINAL: break;
		case CMD_DIGEST_INIT: break;
		case CMD_DIGEST_UPDATE: break;
		case CMD_DIGEST_FINAL: break;

		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}

