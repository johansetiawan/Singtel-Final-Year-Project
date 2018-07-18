#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_start_tls_client_t {
	char* ms_ip;
	char* ms_bytearr;
	int64_t ms_filelen;
	Sizes ms_s;
} ms_ecall_start_tls_client_t;

typedef struct ms_encryption_t {
	long int ms_retval;
	char* ms_inputarr;
	long int ms_inputlen;
	char* ms_encarr;
	long int ms_enclen;
	char* ms_macarr;
} ms_encryption_t;

typedef struct ms_ecall_ra_init_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t ms_key;
	int ms_b_pse;
	sgx_ra_context_t* ms_ctx;
} ms_ecall_ra_init_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

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

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_clock(void* pms)
{
	ms_ocall_sgx_clock_t* ms = SGX_CAST(ms_ocall_sgx_clock_t*, pms);
	ms->ms_retval = ocall_sgx_clock();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_time(void* pms)
{
	ms_ocall_sgx_time_t* ms = SGX_CAST(ms_ocall_sgx_time_t*, pms);
	ms->ms_retval = ocall_sgx_time(ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_localtime(void* pms)
{
	ms_ocall_sgx_localtime_t* ms = SGX_CAST(ms_ocall_sgx_localtime_t*, pms);
	ms->ms_retval = ocall_sgx_localtime((const time_t*)ms->ms_timep, ms->ms_t_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_gmtime_r(void* pms)
{
	ms_ocall_sgx_gmtime_r_t* ms = SGX_CAST(ms_ocall_sgx_gmtime_r_t*, pms);
	ms->ms_retval = ocall_sgx_gmtime_r((const time_t*)ms->ms_timep, ms->ms_t_len, ms->ms_tmp, ms->ms_tmp_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_gettimeofday(void* pms)
{
	ms_ocall_sgx_gettimeofday_t* ms = SGX_CAST(ms_ocall_sgx_gettimeofday_t*, pms);
	ms->ms_retval = ocall_sgx_gettimeofday(ms->ms_tv, ms->ms_tv_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getsockopt(void* pms)
{
	ms_ocall_sgx_getsockopt_t* ms = SGX_CAST(ms_ocall_sgx_getsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_getsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optval_len, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_setsockopt(void* pms)
{
	ms_ocall_sgx_setsockopt_t* ms = SGX_CAST(ms_ocall_sgx_setsockopt_t*, pms);
	ms->ms_retval = ocall_sgx_setsockopt(ms->ms_s, ms->ms_level, ms->ms_optname, (const void*)ms->ms_optval, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_socket(void* pms)
{
	ms_ocall_sgx_socket_t* ms = SGX_CAST(ms_ocall_sgx_socket_t*, pms);
	ms->ms_retval = ocall_sgx_socket(ms->ms_af, ms->ms_type, ms->ms_protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_listen(void* pms)
{
	ms_ocall_sgx_listen_t* ms = SGX_CAST(ms_ocall_sgx_listen_t*, pms);
	ms->ms_retval = ocall_sgx_listen(ms->ms_s, ms->ms_backlog);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_bind(void* pms)
{
	ms_ocall_sgx_bind_t* ms = SGX_CAST(ms_ocall_sgx_bind_t*, pms);
	ms->ms_retval = ocall_sgx_bind(ms->ms_s, (const void*)ms->ms_addr, ms->ms_addr_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_connect(void* pms)
{
	ms_ocall_sgx_connect_t* ms = SGX_CAST(ms_ocall_sgx_connect_t*, pms);
	ms->ms_retval = ocall_sgx_connect(ms->ms_s, (const void*)ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_accept(void* pms)
{
	ms_ocall_sgx_accept_t* ms = SGX_CAST(ms_ocall_sgx_accept_t*, pms);
	ms->ms_retval = ocall_sgx_accept(ms->ms_s, ms->ms_addr, ms->ms_addr_size, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_shutdown(void* pms)
{
	ms_ocall_sgx_shutdown_t* ms = SGX_CAST(ms_ocall_sgx_shutdown_t*, pms);
	ms->ms_retval = ocall_sgx_shutdown(ms->ms_fd, ms->ms_how);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_read(void* pms)
{
	ms_ocall_sgx_read_t* ms = SGX_CAST(ms_ocall_sgx_read_t*, pms);
	ms->ms_retval = ocall_sgx_read(ms->ms_fd, ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_write(void* pms)
{
	ms_ocall_sgx_write_t* ms = SGX_CAST(ms_ocall_sgx_write_t*, pms);
	ms->ms_retval = ocall_sgx_write(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_close(void* pms)
{
	ms_ocall_sgx_close_t* ms = SGX_CAST(ms_ocall_sgx_close_t*, pms);
	ms->ms_retval = ocall_sgx_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sgx_getenv(void* pms)
{
	ms_ocall_sgx_getenv_t* ms = SGX_CAST(ms_ocall_sgx_getenv_t*, pms);
	ms->ms_retval = ocall_sgx_getenv((const char*)ms->ms_env, ms->ms_envlen, ms->ms_ret_str, ms->ms_ret_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readCKfile(void* pms)
{
	ms_ocall_readCKfile_t* ms = SGX_CAST(ms_ocall_readCKfile_t*, pms);
	ms->ms_retval = ocall_readCKfile((const char*)ms->ms_file);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[28];
} ocall_table_Enclave = {
	28,
	{
		(void*)Enclave_ocall_sgx_clock,
		(void*)Enclave_ocall_sgx_time,
		(void*)Enclave_ocall_sgx_localtime,
		(void*)Enclave_ocall_sgx_gmtime_r,
		(void*)Enclave_ocall_sgx_gettimeofday,
		(void*)Enclave_ocall_sgx_getsockopt,
		(void*)Enclave_ocall_sgx_setsockopt,
		(void*)Enclave_ocall_sgx_socket,
		(void*)Enclave_ocall_sgx_listen,
		(void*)Enclave_ocall_sgx_bind,
		(void*)Enclave_ocall_sgx_connect,
		(void*)Enclave_ocall_sgx_accept,
		(void*)Enclave_ocall_sgx_shutdown,
		(void*)Enclave_ocall_sgx_read,
		(void*)Enclave_ocall_sgx_write,
		(void*)Enclave_ocall_sgx_close,
		(void*)Enclave_ocall_sgx_getenv,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_readCKfile,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_create_session_ocall,
		(void*)Enclave_exchange_report_ocall,
		(void*)Enclave_close_session_ocall,
		(void*)Enclave_invoke_service_ocall,
	}
};
sgx_status_t ecall_start_tls_client(sgx_enclave_id_t eid, char* ip, char* bytearr, int64_t filelen, Sizes s)
{
	sgx_status_t status;
	ms_ecall_start_tls_client_t ms;
	ms.ms_ip = ip;
	ms.ms_bytearr = bytearr;
	ms.ms_filelen = filelen;
	ms.ms_s = s;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t encryption(sgx_enclave_id_t eid, long int* retval, char* inputarr, long int inputlen, char* encarr, long int enclen, char* macarr)
{
	sgx_status_t status;
	ms_encryption_t ms;
	ms.ms_inputarr = inputarr;
	ms.ms_inputlen = inputlen;
	ms.ms_encarr = encarr;
	ms.ms_enclen = enclen;
	ms.ms_macarr = macarr;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_ra_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t key, int b_pse, sgx_ra_context_t* ctx)
{
	sgx_status_t status;
	ms_ecall_ra_init_t ms;
	ms.ms_key = key;
	ms.ms_b_pse = b_pse;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = (sgx_ra_msg2_t*)p_msg2;
	ms.ms_p_qe_target = (sgx_target_info_t*)p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

