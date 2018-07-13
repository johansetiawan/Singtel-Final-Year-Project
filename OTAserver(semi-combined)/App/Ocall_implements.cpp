#include "Ocall_implements.h"
#include "Enclave_u.h"

#include "sgx_uae_service.h"
#include "sgx_quote.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "stdlib.h"
#include "sgx_tae_service.h"
#include <string.h>

long ocall_sgx_clock(void)
{
	struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
	return tstart.tv_sec * 1000000 + tstart.tv_nsec/1000; // Return micro seconds
}

time_t ocall_sgx_time(time_t *timep, int t_len)
{
	return 	time(timep);
}

struct tm *ocall_sgx_localtime(const time_t *timep, int t_len)
{
	return localtime(timep);
}

struct tm *ocall_sgx_gmtime_r(const time_t *timep, int t_len, struct tm *tmp, int tmp_len)
{
	return gmtime_r(timep, tmp);
}

int ocall_sgx_gettimeofday(void *tv, int tv_size)
{
	return gettimeofday((struct timeval *)tv, NULL);
}

int ocall_sgx_getsockopt(int s, int level, int optname, char *optval, int optval_len, int* optlen)
{
    return getsockopt(s, level, optname, optval, (socklen_t *)optlen);
}

int ocall_sgx_setsockopt(int s, int level, int optname, const void *optval, int optlen)
{
	return setsockopt(s, level, optname, optval, optlen);
}

int ocall_sgx_socket(int af, int type, int protocol)
{
	int retv;
	retv = socket(af, type, protocol);
	return retv;
}

int ocall_sgx_bind(int s, const void *addr, int addr_size)
{
	return bind(s, (struct sockaddr *)addr, addr_size);
}

int ocall_sgx_listen(int s, int backlog)
{
	return listen(s, backlog);
}

int ocall_sgx_connect(int s, const void *addr, int addrlen)
{
	int retv = connect(s, (struct sockaddr *)addr, addrlen);
	return retv;
}

int ocall_sgx_accept(int s, void *addr, int addr_size, int *addrlen)
{
	return accept(s, (struct sockaddr *)addr, (socklen_t *)addrlen);
}

int ocall_sgx_shutdown(int fd, int how)
{
	return shutdown(fd, how);
}

int ocall_sgx_read(int fd, void *buf, int n)
{
	return read(fd, buf, n);
}

int ocall_sgx_write(int fd, const void *buf, int n)
{
	return write(fd, buf, n);
}

int ocall_sgx_close(int fd)
{
	return close(fd);
}

int ocall_sgx_getenv(const char *env, int envlen, char *ret_str,int ret_len)
{
	const char *env_val = getenv(env);
	if(env_val == NULL){
		return -1;
	}
	memcpy(ret_str, env_val, strlen(env_val)+1);
	return 0;
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

void ocall_sgx_exit(int e)
{
	exit(e);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

char *ocall_readCKfile(const char *file)
{
    FILE *fp;
    char *ck = (char *)calloc(256,sizeof(char *));
    char line[255];
    fp = fopen(file,"r");
    if(fp==NULL){
        printf("file not found\n");
        return NULL;
    }
    while(fgets(line, 255, fp)!=NULL){
        sprintf(ck,"%s%s",ck,line);
    }
    int str = strlen(ck)-1;
    if(ck[str] == '\n'){
        ck[str]='\0';
    }
    fclose(fp);
    return ck;
}

uint32_t* ocall_get_epid_group_id(uint32_t *extended_epid_group_id) {
	 sgx_get_extended_epid_group_id(extended_epid_group_id);
	 return(extended_epid_group_id);
}


