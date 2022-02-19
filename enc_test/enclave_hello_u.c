#include "enclave_hello_u.h"
#include <errno.h>

typedef struct ms_enclaveChangeBuffer_t {
	char* ms_buf;
	size_t ms_len;
} ms_enclaveChangeBuffer_t;

typedef struct ms_enclaveStringSave_t {
	char* ms_input;
	size_t ms_len;
} ms_enclaveStringSave_t;

typedef struct ms_enclaveStringLoad_t {
	char* ms_output;
	size_t ms_len;
} ms_enclaveStringLoad_t;

typedef struct ms_enclaveSaveInt_t {
	int ms_input;
} ms_enclaveSaveInt_t;

typedef struct ms_enclaveLoadInt_t {
	int ms_retval;
} ms_enclaveLoadInt_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL enclave_hello_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_hello_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_hello_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_hello_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_hello_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[5];
} ocall_table_enclave_hello = {
	5,
	{
		(void*)(uintptr_t)enclave_hello_sgx_oc_cpuidex,
		(void*)(uintptr_t)enclave_hello_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)enclave_hello_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)enclave_hello_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)enclave_hello_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t enclaveChangeBuffer(sgx_enclave_id_t eid, char* buf, size_t len)
{
	sgx_status_t status;
	ms_enclaveChangeBuffer_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_enclave_hello, &ms);
	return status;
}

sgx_status_t enclaveStringSave(sgx_enclave_id_t eid, char* input, size_t len)
{
	sgx_status_t status;
	ms_enclaveStringSave_t ms;
	ms.ms_input = input;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_enclave_hello, &ms);
	return status;
}

sgx_status_t enclaveStringLoad(sgx_enclave_id_t eid, char* output, size_t len)
{
	sgx_status_t status;
	ms_enclaveStringLoad_t ms;
	ms.ms_output = output;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_enclave_hello, &ms);
	return status;
}

sgx_status_t enclaveSaveInt(sgx_enclave_id_t eid, int input)
{
	sgx_status_t status;
	ms_enclaveSaveInt_t ms;
	ms.ms_input = input;
	status = sgx_ecall(eid, 3, &ocall_table_enclave_hello, &ms);
	return status;
}

sgx_status_t enclaveLoadInt(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enclaveLoadInt_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_enclave_hello, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

