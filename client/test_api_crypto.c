#include <stdio.h>
#include <err.h>
#include <tee_client_api.h>
#include <ta_test_api_crypto.h>
#include <string.h>


int main(int argc, char *argv[])
{
	TEEC_Context 	context;
	TEEC_Session 	session;
	TEEC_Operation 	peration;
	
	TEEC_Result		result;

	TEEC_SharedMemory commsSM;
	TEEC_SharedMemory inputSM;
	TEEC_SharedMemory outputSM;

	uint32_t		  err_origin;
	uint8_t* 		  ivPtr;

	TEEC_UUID uuid = TA_TEST_API_CRYPTO;

	/* ============================================================================
	Implement our library function where the buffers of memory are pre-allocated
	by the calling entity. This is a common paradigm when interfacing with other
	libraries provided by other providers.
	============================================================================ */
	TEEC_Result libraryFunction( 
		uint8_t const * inputBuffer,
		uint32_t		inputSize,
		uint8_t* 		outputBuffer,
		uint32_t		outputSize,
		uint8_t*		digestBuffer
		)
	/* ========================================================================
	[1] Connect to TEE
	======================================================================== */
	result = TEEC_InitializeContext(
					NULL,  /* Select default TEE */
		&context);
	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with error code 0x%x ", ressult);


	/* ========================================================================
	[2] Open session with TEE application
	======================================================================== */
	
	result = TEEC_OpenSession(
		&context,
		&session,
		&uuid,
		TEEC_LOGIN_PUBLIC,
					NULL, /* No connection data needed for TEEC_LOGIN_USER. */
					NULL, /* No payload, and do not want cancellation. */
		&err_origin);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x",
			result, err_origin);



	/* ========================================================================
	[3] Initialize the Shared Memory buffers
	======================================================================== */
	/* [a] Communications buffer. */
	commsSM.size = 20;
	commsSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT; /*Transfet data in both direction*/

	/* Use TEE Client API to allocate the underlying memory buffer. */
	result = TEEC_AllocateSharedMemory(&context, &commsSM);

	if (result != TEEC_SUCCESS)
		errx(1,"TEEC_AllocateSharedMemory failed with code 0x%x", result);
	

	/* [b] Bulk input buffer. */
	inputSM.size = inputSize;
	inputSM.flags = TEEC_MEM_INPUT;

	/* Use TEE Client API to register the underlying memory buffer. */
	inputSM.buffer = (uint8_t*)inputBuffer;
	result = TEEC_RegisterSharedMemory(&context, &inputSM);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", result);

	/* [c] Bulk output buffer (also input for digest). */
	outputSM.size = outputSize;
	outputSM.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	outputSM.buffer = outputBuffer;
	result = TEEC_RegisterSharedMemory(&context, &outputSM);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory failed with code 0x%x", result);


	/* ========================================================================
	[4] Perform cryptographic operation initialization commands
	======================================================================== */
	/* [a] Start the encrypt operation within the TEE application. */
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_NONE,
		TEEC_NONE);
}
	/* Write key ID (example uses key ID = 1) in parameter #1 */
operation.params[0].value.a = 1;

operation.params[1].memref.parent = &commsSM;
operation.params[1].memref.offset = 0;
operation.params[1].memref.size = 16;

	/* Write IV (example uses an IV of all zeros) in to Memory buffer. */
ivPtr = (uint8_t*)commsSM.buffer;
memset(ivPtr, 0, 16);

	/* Start the encrypt operation within the TEE application. */
result = TEEC_InvokeCommand(
	&session,
	CMD_ENCRYPT_INIT,
	&operation,
	NULL);
if (result != TEEC_SUCCESS)
	errx(1, "TEEC_InvokeCommand with CMD_ENCRYPT_INIT failed and returned error code 0x%x", result);


	/* ========================================================================
	[5] Perform the cryptographic update commands
	======================================================================== */
	/* [a] Start the encrypt operation within the TEE application. */
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_WHOLE,
		TEEC_MEMREF_PARTIAL_OUTPUT,
		TEEC_NONE,
		TEEC_NONE);
	/* Note that the other fields of operation.params[0].memref need not be
	initialized because the parameter type is TEEC_MEMREF_WHOLE */
	operation.params[0].memref.parent = &inputSM;

	operation.params[1].memref.parent = &outputSM;
	operation.params[1].memref.offset = 0;
	operation.params[1].memref.size = outputSize;

	/* Start the encrypt operation within the TEE application. */
	result = TEEC_InvokeCommand(&session,
		CMD_ENCRYPT_UPDATE,
		&operation,
		NULL);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand with CMD_ENCRYPT_UPDATE failed and returned error code 0x%x", result);




	/* [b] Start the digest operation within the TEE application. */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_NONE,
		TEEC_NONE,
		TEEC_NONE);

	/* Note: we use the updated size in the MemRef output by the encryption. */

	operation.params[0].memref.parent = &outputSM;
	operation.params[0].memref.offset = 0;
	operation.paramŝ[0].memref.size = operation.params[1].memref.size;


	result = TEEC_InvokeCommand(&session,
		CMD_DIGEST_UPDATE,
		&operation,
		NULL);
	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand with CMD_DIGEST_UPDATE failed and returned error code 0x%x", result);

	/* ========================================================================
	[6] Perform the cryptographic finalize commands
	======================================================================== */
	/* [a] Finalize the encrypt operation within the TEE application. */
	result = TEEC_InvokeCommand(&session,
		CMD_ENCRYPT_FINAL,
		NULL,
		NULL);

	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand with CMD_ENCRYPT_FINAL failed and returned error code 0x%x", result);



/* [b] Finalize the digest operation within the TEE application. */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT,
		TEEC_NONE,
		TEEC_NONE,
		TEEC_NONE);
	operation.params[0].memref.parent = &commsSM;
	operation.params[0].memref.offset = 0;
	operation.params[0].memref.size = 20;
	
	result = TEEC_InvokeCommand(&session,
		CMD_DIGEST_FINAL,
		&operation,
		NULL);
	if (result != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand with CMD_DIGEST_FINAL failed and returned error code 0x%x", result);

	/* Transfer digest in to user buffer. */
	memcpy(digestBuffer, commsSM.buffer, 20);

	TEEC_ReleaseSharedMemory(&outputSM);
	TEEC_ReleaseSharedMemory(&inputSM);
	TEEC_ReleaseSharedMemory(&commsSM);

	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&context);

	return 0;
}


