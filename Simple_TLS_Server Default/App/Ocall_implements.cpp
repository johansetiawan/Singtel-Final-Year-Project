#include "Ocall_implements.h"
#include "Enclave_u.h"



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

int ocall_SGXenc(sgx_enclave_id_t eid, const char *to, const char *from)
{

	printf("Starting encryption...\n");

	int fd_to, fd_from;
    char buf[BUFFERSIZE];
    ssize_t nread;
    int saved_errno;
    int runningNo=0;

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0)
        return -1;

    fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_to < 0)
        goto out_error;

    while (nread = read(fd_from, buf, sizeof buf), nread > 0)
    {
        
    	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + nread+1); 
    	char *encMessage = (char *) malloc(sizeof buf + encMessageLen);
    	////printf("%d Enc: input len %zu\n",runningNo, nread);
    	//encryptMessage(eid, buf, nread, encMessage, encMessageLen);

        char *out_ptr = encMessage;
        ssize_t nwritten;

        do {
            nwritten = write(fd_to, out_ptr, encMessageLen);
            
            if (nwritten >= 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
            }
            else if (errno != EINTR)
            {
                goto out_error;
            }
        } while (nread > 0);
    runningNo++;    
    }
	printf("nread :)  %zu\n", nread);
    if (nread == 0)
    {
        if (close(fd_to) < 0)
        {
            fd_to = -1;
            goto out_error;
        }
        close(fd_from);
        /* Success! */
        return 0;
    }

  out_error:
    saved_errno = errno;

    close(fd_from);
    if (fd_to >= 0)
        close(fd_to);

    errno = saved_errno;
	printf("ERROR :)  %d\n", errno);
    return -1;
}
