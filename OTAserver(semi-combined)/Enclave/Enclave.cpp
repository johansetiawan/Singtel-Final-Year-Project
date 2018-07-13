
#include "Ocall_wrappers.h"
#include "Enclave_t.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "sgx_uae_service.h"
#include "sgx_quote.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "stdlib.h"
#include "sgx_tae_service.h"
#include "sgx_utils.h"
#include <string.h>


#define	INADDR_NONE		((unsigned long int) 0xffffffff)

#define BUFLEN 4200


static const unsigned char key[] = { 
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf 
};
static const unsigned char iv[] = { 
	0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
};

static void init_openssl()
{
	OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_ciphers();
	SSL_load_error_strings();
}

static void cleanup_openssl()
{
    EVP_cleanup();
}

static int
isascii(int c)
{
	return((c & ~0x7F) == 0);
}

/* inet_aton from https://android.googlesource.com/platform/bionic.git/+/android-4.0.1_r1/libc/inet/inet_aton.c */
static int inet_aton(const char *cp, struct in_addr *addr)
{
	u_long val, base, n;
	char c;
	u_long parts[4], *pp = parts;

	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
		val = 0; base = 10;
		if (*cp == '0') {
			if (*++cp == 'x' || *cp == 'X')
				base = 16, cp++;
			else
				base = 8;
		}
		while ((c = *cp) != '\0') {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				cp++;
				continue;
			}
			if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) + 
					(c + 10 - (islower(c) ? 'a' : 'A'));
				cp++;
				continue;
			}
			break;
		}
		if (*cp == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16-bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3 || val > 0xff)
				return (0);
			*pp++ = val, cp++;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && (!isascii(*cp) || !isspace(*cp)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

		case 1:				/* a -- 32 bits */
			break;

		case 2:				/* a.b -- 8.24 bits */
			if (val > 0xffffff)
				return (0);
			val |= parts[0] << 24;
			break;

		case 3:				/* a.b.c -- 8.8.16 bits */
			if (val > 0xffff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16);
			break;

		case 4:				/* a.b.c.d -- 8.8.8.8 bits */
			if (val > 0xff)
				return (0);
			val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
			break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}

static in_addr_t inet_addr(const char *cp)
{
	struct in_addr val;

	if (inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}

static int create_socket_client(const char *ip, uint32_t port) 
{
	int sockfd;
	struct sockaddr_in dest_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
		printe("socket");
		exit(EXIT_FAILURE);
    }
	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(port);
	dest_addr.sin_addr.s_addr = (long)inet_addr(ip);
	memset(&(dest_addr.sin_zero), '\0', 8);
	printl("Connecting...");
	if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1) {
		printe("Cannot connect");
        exit(EXIT_FAILURE);
	}

	return sockfd;
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();//TLSv1_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printe("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

static X509 *generateCertificate(const char *certStr)
{
    BIO *bio;
    X509 *cert;
    bio=BIO_new(BIO_s_mem());
    if(BIO_puts(bio,certStr) <= 0){
        printf("puts not succ\n");
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if(cert == NULL){
        printf("no cert\n");
    }
    BIO_free(bio);
    return(cert);
}

static EVP_PKEY *generateKey(const char *keyStr)
{
    BIO *bio;
    EVP_PKEY *key;
    bio=BIO_new(BIO_s_mem());
    BIO_puts(bio,keyStr);
    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if(key == NULL){
        printf("no key\n");
    }
    BIO_free(bio);
    return(key);
}


static void showCerts(SSL *ctx){
	X509 *cert;
	char *line;

	cert=SSL_get_peer_certificate(ctx);
	if(cert!=NULL){
		printf("Server certificate:\n");
		line=X509_NAME_oneline(X509_get_subject_name(cert),0,0);
		printf("Subject: %s\n", line);
		free(line);
		line=X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}else{
		printf("Info: No client certificates configured\n");
	}
}

static bool verifyClient(X509 *client){
	X509 *root;
	char *str;
	ocall_readCKfile(&str,"certs/ca.cert.pem");
	root=generateCertificate(str);

	EVP_PKEY * pubkey = X509_get_pubkey(root);

	if( X509_verify(client,pubkey)>0 ){
		return true;
	}
	return false;
}


void ecall_start_tls_client(char *ip, char *bytearr, int64_t filelen, Sizes size, server_msg0 msg0, server_msg1full msg1)
{
	SSL *ssl;
	int sock;
    SSL_CTX *ctx;
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    const char *serv_ip = ip;
    uint32_t serv_port = 4433;

    //RA variables
	uint32_t p_quote_size;
    //sgx_target_info_t target_info;
    sgx_report_data_t report_data;
    sgx_report_t report;
    const sgx_quote_nonce_t p_nonce = (sgx_quote_nonce_t) {0};
    sgx_report_t qe_report;
    sgx_quote_t p_quote;
    int ret = 0;

    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    init_openssl();
    ctx = create_context();

    //ocall to retrieve cert and key strings
    char *certStr,*keyStr;
    ocall_readCKfile(&certStr,"certs/clientssl.cert.pem");
    ocall_readCKfile(&keyStr,"certs/client.key.pem");
 
    //convert strings into x509 and evp keys and load into context
    if(SSL_CTX_use_certificate(ctx, generateCertificate(certStr)) <= 0){
        printf("no cert loaded into ctx\n");
    }
    if(SSL_CTX_use_PrivateKey(ctx, generateKey(keyStr)) <=0 ){
        printf("no key loaded into ctx\n");
    }
    
    SSL_CTX_set_options(ctx, flags);
    sock = create_socket_client(serv_ip, serv_port);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
	if (SSL_connect(ssl) <= 0) {
        printe("SSL_connect");
        exit(EXIT_FAILURE);
	}
	printl("Connected to OTAclient");
 	showCerts(ssl);
 	printf("Verifying client certificate\n");
 	//verify client cert
 	if( !verifyClient(SSL_get_peer_certificate(ssl)) ){
 		printf("Client certificate verify failed\n" );
 		const char *send_buf = "Client verify failed";
		SSL_write(ssl, send_buf, strlen(send_buf)+1);
 		printf("Close SSL/TLS client");
 		SSL_free(ssl);
	    SSL_CTX_free(ctx);
	    sgx_close(sock);
	    cleanup_openssl();
 	}else{
	 	printf("Client Verified\n");
	    printl("ciphersuit: %s", SSL_get_current_cipher(ssl)->name);

		//start of RA
	    server_msg0 enclave_msg0;
	    enclave_msg0 = msg0;
	    unsigned char server_msg0Array[sizeof(server_msg0)];
	    memcpy(&server_msg0Array,&enclave_msg0,sizeof(server_msg0));
	    SSL_write(ssl,&server_msg0Array,sizeof(server_msg0));

	    //prepare to receive msg0 success
	    char receivedStrings[100];
	    int receive = 0;
        receive = SSL_read(ssl, &receivedStrings, sizeof(receivedStrings)+1);
        if(strcmp(receivedStrings,"RA_MSG0_SUCCESSA") == 0) {
        	printf("string != RA_MSG0_SUCCESS");
        }
        
	    server_msg1full enclave_msg1;
	    enclave_msg1 = msg1;
		unsigned char server_msg1Array[sizeof(server_msg1full)];
	    memcpy(&server_msg1Array,&enclave_msg1,sizeof(server_msg1full)); 
	    SSL_write(ssl,&server_msg1Array,sizeof(server_msg1full));
	    } 



////start of msg2 and msg3 
	   	int received = -1;
	    char buf[1024];
	    received = SSL_read(ssl, buf, sizeof(buf)); //expecting to receive msg2
	   	client_msg2* enclave_msg2 = (client_msg2*) buf;
	   	char msg_2_type[13];
	   	memcpy(msg_2_type, &enclave_msg2->type, 13);
	   	if (strcmp(msg_2_type,"TYPE_RA_MSG2") != 0) {
	   		printl("Remote attestation halted at client msg2");
	   	}

    ret = sgx_create_report(&msg1.target_info, &report_data, &report);
    if (ret != 1) {
    	ret = 1;
        printf("sgx_create_report function failed. report unsuccessfully generated");
    }
    ret = sgx_calc_quote_size(enclave_msg2->sig_rl, enclave_msg2->sig_rl_size, &p_quote_size);
    if (ret != 1) {
    	ret = 1;
        printf("sgx_calc_quote_size function failed. Quotesize unsuccessfully generated");
    }
     	ret = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, enclave_msg2->spid, &p_nonce, enclave_msg2->sig_rl, enclave_msg2->sig_rl_size, &qe_report, &p_quote, p_quote_size);
    if (ret != 1) {
    	ret = 1;
        printf("sgx_get_quote function failed. Quote unsuccessfully generated");
    }
    //generating msg3
    int ps_sec_prop = 0;
    server_msg3 msg3;
    char msg3type[13] = "TYPE_RA_MSG3";
    memcpy(&msg3.type, &msg3type, 14);
    memcpy(&msg3.quote, &p_quote, p_quote_size);
    memcpy(&msg3.ps_sec_prop, &ps_sec_prop, 1);

    //receive acknowledgement from OTAclient to recieve update
    printf("awaiting update acknowledgement from OTAclient\n");
    received=SSL_read(ssl,buf,sizeof(buf));
    buf[received] = 0;
    printf("%s\n", buf);
    if(strcmp(buf,"yes") == 0){
    	/* Send buffer to TLS server */
	    const char *send_buf = "Update Server sending update...";
		SSL_write(ssl, send_buf, strlen(send_buf)+1);
			//send size struct to server
			char sizestructarr [sizeof(size)];
			memcpy(&sizestructarr,&size,sizeof(size));
			//SSL_write(ssl,&filelen,sizeof(long));
			SSL_write(ssl,&sizestructarr,sizeof(sizestructarr));

			//send file
			int datasent;
			long totalsent=0, seg;

			if(size.file>16384){
				seg=size.file/16384;
				datasent = SSL_write(ssl,bytearr,size.file);
				totalsent = datasent;

				for(int i=0;i<seg-1;i++){
					datasent=SSL_write(ssl,bytearr+totalsent,size.file-totalsent);
					totalsent=totalsent+datasent;
					//printf("%d\n",SSL_get_error(ssl,datasent));
				}
				SSL_write(ssl,bytearr+totalsent,size.file-totalsent);
			}else{
				SSL_write(ssl,bytearr,size.file);
			}
			printl("Sending complete");
		    printl("Close SSL/TLS client");
		    SSL_free(ssl);
		    SSL_CTX_free(ctx);
		    sgx_close(sock);
		    cleanup_openssl();
	    }else{
	    	printf("OTAclient denied update\n");
	    	printf("Close SSL/TLS client");
	 		SSL_free(ssl);
		    SSL_CTX_free(ctx);
		    sgx_close(sock);
		    cleanup_openssl();
		}
	}

long encryption(char *inputarr, long inputlen, char *encarr, long enclen, char *macarr)
{	
	EVP_CIPHER_CTX *ctx;
	long len=0;
	ctx = EVP_CIPHER_CTX_new();
	//set cipher type and mode
	EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	//load key and iv
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	//encrypt plaintext
	EVP_EncryptUpdate(ctx,(unsigned char*)encarr,(int*)&enclen,(unsigned char*)inputarr,inputlen);
	EVP_EncryptFinal_ex(ctx, (unsigned char*)encarr+enclen, (int*)&len);
	//get mac
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, (unsigned char*)macarr);
	EVP_CIPHER_CTX_free(ctx);
	enclen += len;
	return enclen;
}


