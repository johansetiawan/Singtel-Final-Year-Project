#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_start_tls_client_t {
	char* ms_ip;
	char* ms_bytearr;
	int64_t ms_filelen;
	Sizes ms_s;
	server_msg0 ms_msg0;
	server_msg1full ms_msg1;
} ms_ecall_start_tls_client_t;

typedef struct ms_encryption_t {
	long int ms_retval;
	char* ms_inputarr;
	long int ms_inputlen;
	char* ms_encarr;
	long int ms_enclen;
	char* ms_macarr;
} ms_encryption_t;

typedef struct ms_ocall_sgx_clock_t {
	long int ms_retval;
} ms_ocall_sgx_clock_t;

typedef struct ms_ocall_sgx_time_t {
	time_t ms_retval;
	time_t* ms_timep;
	int ms_t_len;
} ms_ocall_sgx_time_t;

typedef struct ms_ocall_sgx_localtime_t {
	struct tm* ms_retval;
	time_t* ms_timep;
	int ms_t_len;
} ms_ocall_sgx_localtime_t;

typedef struct ms_ocall_sgx_gmtime_r_t {
	struct tm* ms_retval;
	time_t* ms_timep;
	int ms_t_len;
	struct tm* ms_tmp;
	int ms_tmp_len;
} ms_ocall_sgx_gmtime_r_t;

typedef struct ms_ocall_sgx_gettimeofday_t {
	int ms_retval;
	void* ms_tv;
	int ms_tv_size;
} ms_ocall_sgx_gettimeofday_t;

typedef struct ms_ocall_sgx_getsockopt_t {
	int ms_retval;
	int ms_s;
	int ms_level;
	int ms_optname;
	char* ms_optval;
	int ms_optval_len;
	int* ms_optlen;
} ms_ocall_sgx_getsockopt_t;

typedef struct ms_ocall_sgx_setsockopt_t {
	int ms_retval;
	int ms_s;
	int ms_level;
	int ms_optname;
	void* ms_optval;
	int ms_optlen;
} ms_ocall_sgx_setsockopt_t;

typedef struct ms_ocall_sgx_socket_t {
	int ms_retval;
	int ms_af;
	int ms_type;
	int ms_protocol;
} ms_ocall_sgx_socket_t;

typedef struct ms_ocall_sgx_listen_t {
	int ms_retval;
	int ms_s;
	int ms_backlog;
} ms_ocall_sgx_listen_t;

typedef struct ms_ocall_sgx_bind_t {
	int ms_retval;
	int ms_s;
	void* ms_addr;
	int ms_addr_size;
} ms_ocall_sgx_bind_t;

typedef struct ms_ocall_sgx_connect_t {
	int ms_retval;
	int ms_s;
	void* ms_addr;
	int ms_addrlen;
} ms_ocall_sgx_connect_t;

typedef struct ms_ocall_sgx_accept_t {
	int ms_retval;
	int ms_s;
	void* ms_addr;
	int ms_addr_size;
	int* ms_addrlen;
} ms_ocall_sgx_accept_t;

typedef struct ms_ocall_sgx_shutdown_t {
	int ms_retval;
	int ms_fd;
	int ms_how;
} ms_ocall_sgx_shutdown_t;

typedef struct ms_ocall_sgx_read_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	int ms_n;
} ms_ocall_sgx_read_t;

typedef struct ms_ocall_sgx_write_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	int ms_n;
} ms_ocall_sgx_write_t;

typedef struct ms_ocall_sgx_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_sgx_close_t;

typedef struct ms_ocall_sgx_getenv_t {
	int ms_retval;
	char* ms_env;
	int ms_envlen;
	char* ms_ret_str;
	int ms_ret_len;
} ms_ocall_sgx_getenv_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_readCKfile_t {
	char* ms_retval;
	char* ms_file;
} ms_ocall_readCKfile_t;

typedef struct ms_ocall_get_epid_group_id_t {
	uint32_t* ms_retval;
	uint32_t* ms_extended_epid_group_id;
} ms_ocall_get_epid_group_id_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecall_start_tls_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_start_tls_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_start_tls_client_t* ms = SGX_CAST(ms_ecall_start_tls_client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_ip = ms->ms_ip;
	size_t _len_ip = 16;
	char* _in_ip = NULL;
	char* _tmp_bytearr = ms->ms_bytearr;
	int64_t _tmp_filelen = ms->ms_filelen;
	size_t _len_bytearr = _tmp_filelen;
	char* _in_bytearr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ip, _len_ip);
	CHECK_UNIQUE_POINTER(_tmp_bytearr, _len_bytearr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ip != NULL && _len_ip != 0) {
		_in_ip = (char*)malloc(_len_ip);
		if (_in_ip == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_ip, _tmp_ip, _len_ip);
	}
	if (_tmp_bytearr != NULL && _len_bytearr != 0) {
		_in_bytearr = (char*)malloc(_len_bytearr);
		if (_in_bytearr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_bytearr, _tmp_bytearr, _len_bytearr);
	}

	ecall_start_tls_client(_in_ip, _in_bytearr, _tmp_filelen, ms->ms_s, ms->ms_msg0, ms->ms_msg1);
err:
	if (_in_ip) free(_in_ip);
	if (_in_bytearr) free(_in_bytearr);

	return status;
}

static sgx_status_t SGX_CDECL sgx_encryption(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encryption_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encryption_t* ms = SGX_CAST(ms_encryption_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_inputarr = ms->ms_inputarr;
	long int _tmp_inputlen = ms->ms_inputlen;
	size_t _len_inputarr = _tmp_inputlen;
	char* _in_inputarr = NULL;
	char* _tmp_encarr = ms->ms_encarr;
	long int _tmp_enclen = ms->ms_enclen;
	size_t _len_encarr = _tmp_enclen;
	char* _in_encarr = NULL;
	char* _tmp_macarr = ms->ms_macarr;
	size_t _len_macarr = 16;
	char* _in_macarr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_inputarr, _len_inputarr);
	CHECK_UNIQUE_POINTER(_tmp_encarr, _len_encarr);
	CHECK_UNIQUE_POINTER(_tmp_macarr, _len_macarr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_inputarr != NULL && _len_inputarr != 0) {
		_in_inputarr = (char*)malloc(_len_inputarr);
		if (_in_inputarr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_inputarr, _tmp_inputarr, _len_inputarr);
	}
	if (_tmp_encarr != NULL && _len_encarr != 0) {
		if ((_in_encarr = (char*)malloc(_len_encarr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encarr, 0, _len_encarr);
	}
	if (_tmp_macarr != NULL && _len_macarr != 0) {
		if ((_in_macarr = (char*)malloc(_len_macarr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_macarr, 0, _len_macarr);
	}

	ms->ms_retval = encryption(_in_inputarr, _tmp_inputlen, _in_encarr, _tmp_enclen, _in_macarr);
err:
	if (_in_inputarr) free(_in_inputarr);
	if (_in_encarr) {
		memcpy(_tmp_encarr, _in_encarr, _len_encarr);
		free(_in_encarr);
	}
	if (_in_macarr) {
		memcpy(_tmp_macarr, _in_macarr, _len_macarr);
		free(_in_macarr);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_ecall_start_tls_client, 0},
		{(void*)(uintptr_t)sgx_encryption, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[25][2];
} g_dyn_entry_table = {
	25,
	{
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_sgx_clock(long int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_clock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_clock_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_clock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_clock_t));

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_time(time_t* retval, time_t* timep, int t_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timep = t_len;

	ms_ocall_sgx_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_time_t);
	void *__tmp = NULL;

	void *__tmp_timep = NULL;
	ocalloc_size += (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) ? _len_timep : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_time_t));

	if (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) {
		ms->ms_timep = (time_t*)__tmp;
		__tmp_timep = __tmp;
		memset(__tmp_timep, 0, _len_timep);
		__tmp = (void *)((size_t)__tmp + _len_timep);
	} else if (timep == NULL) {
		ms->ms_timep = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_t_len = t_len;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (timep) memcpy((void*)timep, __tmp_timep, _len_timep);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_localtime(struct tm** retval, const time_t* timep, int t_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timep = t_len;

	ms_ocall_sgx_localtime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_localtime_t);
	void *__tmp = NULL;

	ocalloc_size += (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) ? _len_timep : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_localtime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_localtime_t));

	if (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) {
		ms->ms_timep = (time_t*)__tmp;
		memcpy(__tmp, timep, _len_timep);
		__tmp = (void *)((size_t)__tmp + _len_timep);
	} else if (timep == NULL) {
		ms->ms_timep = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_t_len = t_len;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_gmtime_r(struct tm** retval, const time_t* timep, int t_len, struct tm* tmp, int tmp_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timep = t_len;
	size_t _len_tmp = tmp_len;

	ms_ocall_sgx_gmtime_r_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_gmtime_r_t);
	void *__tmp = NULL;

	void *__tmp_tmp = NULL;
	ocalloc_size += (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) ? _len_timep : 0;
	ocalloc_size += (tmp != NULL && sgx_is_within_enclave(tmp, _len_tmp)) ? _len_tmp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_gmtime_r_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_gmtime_r_t));

	if (timep != NULL && sgx_is_within_enclave(timep, _len_timep)) {
		ms->ms_timep = (time_t*)__tmp;
		memcpy(__tmp, timep, _len_timep);
		__tmp = (void *)((size_t)__tmp + _len_timep);
	} else if (timep == NULL) {
		ms->ms_timep = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_t_len = t_len;
	if (tmp != NULL && sgx_is_within_enclave(tmp, _len_tmp)) {
		ms->ms_tmp = (struct tm*)__tmp;
		__tmp_tmp = __tmp;
		memset(__tmp_tmp, 0, _len_tmp);
		__tmp = (void *)((size_t)__tmp + _len_tmp);
	} else if (tmp == NULL) {
		ms->ms_tmp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tmp_len = tmp_len;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (tmp) memcpy((void*)tmp, __tmp_tmp, _len_tmp);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_gettimeofday(int* retval, void* tv, int tv_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tv = tv_size;

	ms_ocall_sgx_gettimeofday_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_gettimeofday_t);
	void *__tmp = NULL;

	void *__tmp_tv = NULL;
	ocalloc_size += (tv != NULL && sgx_is_within_enclave(tv, _len_tv)) ? _len_tv : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_gettimeofday_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_gettimeofday_t));

	if (tv != NULL && sgx_is_within_enclave(tv, _len_tv)) {
		ms->ms_tv = (void*)__tmp;
		__tmp_tv = __tmp;
		memcpy(__tmp_tv, tv, _len_tv);
		__tmp = (void *)((size_t)__tmp + _len_tv);
	} else if (tv == NULL) {
		ms->ms_tv = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tv_size = tv_size;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (tv) memcpy((void*)tv, __tmp_tv, _len_tv);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getsockopt(int* retval, int s, int level, int optname, char* optval, int optval_len, int* optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optval = optval_len;
	size_t _len_optlen = 4;

	ms_ocall_sgx_getsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getsockopt_t);
	void *__tmp = NULL;

	void *__tmp_optval = NULL;
	void *__tmp_optlen = NULL;
	ocalloc_size += (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) ? _len_optval : 0;
	ocalloc_size += (optlen != NULL && sgx_is_within_enclave(optlen, _len_optlen)) ? _len_optlen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getsockopt_t));

	ms->ms_s = s;
	ms->ms_level = level;
	ms->ms_optname = optname;
	if (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) {
		ms->ms_optval = (char*)__tmp;
		__tmp_optval = __tmp;
		memset(__tmp_optval, 0, _len_optval);
		__tmp = (void *)((size_t)__tmp + _len_optval);
	} else if (optval == NULL) {
		ms->ms_optval = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_optval_len = optval_len;
	if (optlen != NULL && sgx_is_within_enclave(optlen, _len_optlen)) {
		ms->ms_optlen = (int*)__tmp;
		__tmp_optlen = __tmp;
		memcpy(__tmp_optlen, optlen, _len_optlen);
		__tmp = (void *)((size_t)__tmp + _len_optlen);
	} else if (optlen == NULL) {
		ms->ms_optlen = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (optval) memcpy((void*)optval, __tmp_optval, _len_optval);
		if (optlen) memcpy((void*)optlen, __tmp_optlen, _len_optlen);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_setsockopt(int* retval, int s, int level, int optname, const void* optval, int optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optval = optlen;

	ms_ocall_sgx_setsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_setsockopt_t);
	void *__tmp = NULL;

	ocalloc_size += (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) ? _len_optval : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_setsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_setsockopt_t));

	ms->ms_s = s;
	ms->ms_level = level;
	ms->ms_optname = optname;
	if (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) {
		ms->ms_optval = (void*)__tmp;
		memcpy(__tmp, optval, _len_optval);
		__tmp = (void *)((size_t)__tmp + _len_optval);
	} else if (optval == NULL) {
		ms->ms_optval = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_optlen = optlen;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_socket(int* retval, int af, int type, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_socket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_socket_t));

	ms->ms_af = af;
	ms->ms_type = type;
	ms->ms_protocol = protocol;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_listen(int* retval, int s, int backlog)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_listen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_listen_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_listen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_listen_t));

	ms->ms_s = s;
	ms->ms_backlog = backlog;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_bind(int* retval, int s, const void* addr, int addr_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addr_size;

	ms_ocall_sgx_bind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_bind_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_bind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_bind_t));

	ms->ms_s = s;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (void*)__tmp;
		memcpy(__tmp, addr, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_addr_size = addr_size;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_connect(int* retval, int s, const void* addr, int addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addrlen;

	ms_ocall_sgx_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_connect_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_connect_t));

	ms->ms_s = s;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (void*)__tmp;
		memcpy(__tmp, addr, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_addrlen = addrlen;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_accept(int* retval, int s, void* addr, int addr_size, int* addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addr_size;
	size_t _len_addrlen = 4;

	ms_ocall_sgx_accept_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_accept_t);
	void *__tmp = NULL;

	void *__tmp_addr = NULL;
	void *__tmp_addrlen = NULL;
	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;
	ocalloc_size += (addrlen != NULL && sgx_is_within_enclave(addrlen, _len_addrlen)) ? _len_addrlen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_accept_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_accept_t));

	ms->ms_s = s;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (void*)__tmp;
		__tmp_addr = __tmp;
		memset(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_addr_size = addr_size;
	if (addrlen != NULL && sgx_is_within_enclave(addrlen, _len_addrlen)) {
		ms->ms_addrlen = (int*)__tmp;
		__tmp_addrlen = __tmp;
		memcpy(__tmp_addrlen, addrlen, _len_addrlen);
		__tmp = (void *)((size_t)__tmp + _len_addrlen);
	} else if (addrlen == NULL) {
		ms->ms_addrlen = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (addr) memcpy((void*)addr, __tmp_addr, _len_addr);
		if (addrlen) memcpy((void*)addrlen, __tmp_addrlen, _len_addrlen);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_shutdown(int* retval, int fd, int how)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_shutdown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_shutdown_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_shutdown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_shutdown_t));

	ms->ms_fd = fd;
	ms->ms_how = how;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_read(int* retval, int fd, void* buf, int n)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_ocall_sgx_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_read_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_read_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_n = n;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_write(int* retval, int fd, const void* buf, int n)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_ocall_sgx_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_write_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_write_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_n = n;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sgx_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_close_t));

	ms->ms_fd = fd;
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sgx_getenv(int* retval, const char* env, int envlen, char* ret_str, int ret_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_env = envlen;
	size_t _len_ret_str = ret_len;

	ms_ocall_sgx_getenv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sgx_getenv_t);
	void *__tmp = NULL;

	void *__tmp_ret_str = NULL;
	ocalloc_size += (env != NULL && sgx_is_within_enclave(env, _len_env)) ? _len_env : 0;
	ocalloc_size += (ret_str != NULL && sgx_is_within_enclave(ret_str, _len_ret_str)) ? _len_ret_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sgx_getenv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sgx_getenv_t));

	if (env != NULL && sgx_is_within_enclave(env, _len_env)) {
		ms->ms_env = (char*)__tmp;
		memcpy(__tmp, env, _len_env);
		__tmp = (void *)((size_t)__tmp + _len_env);
	} else if (env == NULL) {
		ms->ms_env = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_envlen = envlen;
	if (ret_str != NULL && sgx_is_within_enclave(ret_str, _len_ret_str)) {
		ms->ms_ret_str = (char*)__tmp;
		__tmp_ret_str = __tmp;
		memset(__tmp_ret_str, 0, _len_ret_str);
		__tmp = (void *)((size_t)__tmp + _len_ret_str);
	} else if (ret_str == NULL) {
		ms->ms_ret_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_ret_len = ret_len;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ret_str) memcpy((void*)ret_str, __tmp_ret_str, _len_ret_str);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		memcpy(__tmp, str, _len_str);
		__tmp = (void *)((size_t)__tmp + _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readCKfile(char** retval, const char* file)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file = file ? strlen(file) + 1 : 0;

	ms_ocall_readCKfile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readCKfile_t);
	void *__tmp = NULL;

	ocalloc_size += (file != NULL && sgx_is_within_enclave(file, _len_file)) ? _len_file : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readCKfile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readCKfile_t));

	if (file != NULL && sgx_is_within_enclave(file, _len_file)) {
		ms->ms_file = (char*)__tmp;
		memcpy(__tmp, file, _len_file);
		__tmp = (void *)((size_t)__tmp + _len_file);
	} else if (file == NULL) {
		ms->ms_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_epid_group_id(uint32_t** retval, uint32_t* extended_epid_group_id)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_extended_epid_group_id = 2;

	ms_ocall_get_epid_group_id_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_epid_group_id_t);
	void *__tmp = NULL;

	ocalloc_size += (extended_epid_group_id != NULL && sgx_is_within_enclave(extended_epid_group_id, _len_extended_epid_group_id)) ? _len_extended_epid_group_id : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_epid_group_id_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_epid_group_id_t));

	if (extended_epid_group_id != NULL && sgx_is_within_enclave(extended_epid_group_id, _len_extended_epid_group_id)) {
		ms->ms_extended_epid_group_id = (uint32_t*)__tmp;
		memcpy(__tmp, extended_epid_group_id, _len_extended_epid_group_id);
		__tmp = (void *)((size_t)__tmp + _len_extended_epid_group_id);
	} else if (extended_epid_group_id == NULL) {
		ms->ms_extended_epid_group_id = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;
	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) memcpy((void*)cpuinfo, __tmp_cpuinfo, _len_cpuinfo);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

