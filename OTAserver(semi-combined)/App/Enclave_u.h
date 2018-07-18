#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "time.h"
#include "stdint.h"
#include "sgx_uae_service.h"
#include "sgx_quote.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tae_service.h"
#include "sgx_utils.h"
#include "sgx_urts.h"
#include "sgx_tkey_exchange.h"
#include "sgx_error.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Sizes {
	int64_t header;
	int64_t mac;
	int64_t sig;
	int64_t enc;
	int64_t file;
} Sizes;

long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_clock, ());
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_time, (time_t* timep, int t_len));
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_localtime, (const time_t* timep, int t_len));
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gmtime_r, (const time_t* timep, int t_len, struct tm* tmp, int tmp_len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_gettimeofday, (void* tv, int tv_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getsockopt, (int s, int level, int optname, char* optval, int optval_len, int* optlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_setsockopt, (int s, int level, int optname, const void* optval, int optlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_socket, (int af, int type, int protocol));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_listen, (int s, int backlog));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_bind, (int s, const void* addr, int addr_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_connect, (int s, const void* addr, int addrlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_accept, (int s, void* addr, int addr_size, int* addrlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_shutdown, (int fd, int how));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_read, (int fd, void* buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_write, (int fd, const void* buf, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_close, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sgx_getenv, (const char* env, int envlen, char* ret_str, int ret_len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readCKfile, (const char* file));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));

sgx_status_t ecall_start_tls_client(sgx_enclave_id_t eid, char* ip, char* bytearr, int64_t filelen, Sizes s);
sgx_status_t encryption(sgx_enclave_id_t eid, long int* retval, char* inputarr, long int inputlen, char* encarr, long int enclen, char* macarr);
sgx_status_t ecall_ra_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t key, int b_pse, sgx_ra_context_t* ctx);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
