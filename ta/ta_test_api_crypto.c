

#define STR_TRACE_USER_TA "TEST_CRYPTO"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "ta_test_api_crypto.h"


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

	//todo

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{

}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, 
						uint32_t param_types, TEE_Paramn params[4])
{

	(void)&sess_ctx;

	switch (cmd_id) {
		case CMD_ENCRYPT_INIT:break;
		case CMD_ENCRYPT_UPDATE: break;
		case CMD_ENCRYPT_FINAL: break;
		case CMD_DIGEST_INIT: break;
		case CMD_DIGEST_UPDATE: break;
		case CMD_DIGEST_FINAL: break;

		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}