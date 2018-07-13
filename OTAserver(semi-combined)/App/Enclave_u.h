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

typedef struct server_msg0 {
	unsigned char type[50];
	uint32_t epid;
} server_msg0;

typedef struct server_msg1full {
	unsigned char type[50];
	sgx_target_info_t target_info;
	sgx_epid_group_id_t gid;
} server_msg1full;

typedef struct client_msg2 {
	unsigned char type[50];
	sgx_spid_t spid[16];
	uint16_t quote_type;
	uint32_t sig_rl_size;
	uint8_t sig_rl[500];
} client_msg2;

typedef struct server_msg3 {
	unsigned char type[50];
	sgx_ps_sec_prop_desc_t ps_sec_prop;
	uint8_t quote[2048];
} server_msg3;

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
uint32_t* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_epid_group_id, (uint32_t* extended_epid_group_id));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ecall_start_tls_client(sgx_enclave_id_t eid, char* ip, char* bytearr, int64_t filelen, Sizes s, server_msg0 msg0, server_msg1full msg1);
sgx_status_t encryption(sgx_enclave_id_t eid, long int* retval, char* inputarr, long int inputlen, char* encarr, long int enclen, char* macarr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
