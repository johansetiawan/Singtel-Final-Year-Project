/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <resolv.h>
#include <netdb.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/tls1.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "sgx_uae_service.h"
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include "sgx_quote.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "stdlib.h"
#include "sgx_tae_service.h"
#include "sgx_utils.h"
#include <stdint.h>
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12
#define FAIL    -1

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

//remote attestation variables

    struct msg01_struct{
        unsigned char type[50];
        uint32_t epid;
        sgx_ra_msg1_t msg1;
    };

    struct client_msg4{
    unsigned char  type[50];
    unsigned char attestation_status[50];
    };

    #define PSE_RETRIES 5   
    #define OPT_PSE 0x01
/*    sgx_status_t ecall_sgx_status, status;
    sgx_ra_context_t raCtx = 0xdeadbeef;
    sgx_status_t *pse_status;
    sgx_ra_msg1_t msg1;
    sgx_ra_msg2_t *msg2;
    sgx_ra_msg3_t *msg3 = NULL;
    uint32_t msg3_size;
    client_msg4 *msg4;
    int b_pse;
    sgx_ecall_get_ga_trusted_t p_get_ga;
    msg01_struct msg01;
    uint32_t extended_epid_group_id = 0;*/

        static const sgx_ec256_public_t client_pub_key = {
    {
        0x2a, 0xd4, 0x1f, 0x00, 0xaf, 0x85, 0xfb, 0x86,
        0x4d, 0x89, 0x86, 0x33, 0xab, 0x1e, 0xfc, 0x6f,
        0xf0, 0xe8, 0x97, 0x7b, 0x24, 0x52, 0xcf, 0x3a,
        0x39, 0x8f, 0xd5, 0x2b, 0x2d, 0x1f, 0x25, 0x9d
    },
    {
        0x98, 0x46, 0xf2, 0x98, 0x08, 0xb0, 0xa8, 0x54,
        0xac, 0xa0, 0x66, 0x8b, 0x94, 0xf9, 0xb6, 0x9b,
        0x39, 0x16, 0x6b, 0x73, 0xe0, 0xe3, 0x44, 0xd8,
        0x9f, 0x33, 0x9f, 0xfc, 0x4d, 0xf1, 0x57, 0xd8
    }
};

    static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
 
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
SSL_CTX* InitCTX(void){   
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    
    //change algo to accept only ecdsa and ecdhe
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    OpenSSL_add_all_ciphers();

    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get client certificates (if available) */
    if ( cert != NULL )
    {
        printf("Client certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("Info: No server certificates configured.\n");
}


bool remoteAttestation(char *ip, sgx_enclave_id_t global_eid){
    //remote attestation variables 
    sgx_status_t ecall_sgx_status, status;
    sgx_ra_context_t raCtx = 0xdeadbeef;
    sgx_status_t *pse_status;
    sgx_ra_msg1_t msg1;
    sgx_ra_msg2_t *msg2;
    sgx_ra_msg3_t *msg3 = NULL;
    uint32_t msg3_size;
    client_msg4 *msg4;
    int b_pse = 0;
    sgx_ecall_get_ga_trusted_t p_get_ga;
    msg01_struct msg01;
    uint32_t extended_epid_group_id = 0;


    SSL_library_init();
    // Initialise IAS socket
    SSL_CTX *ctx;
    int fd;
    SSL *ssl;

    ctx=InitCTX();
    LoadCertificates(ctx,"certs/clientssl.cert.pem","certs/client.key.pem");

    //connecting to IAS
    fd = OpenConnection(ip, 4433);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd); 

    int e,f;
    e=SSL_connect(ssl);
    if ( e == FAIL ){
        ERR_print_errors_fp(stderr);
        printf("failed to connect to OTA client\n");
        printf("%d\n",e);
        f= SSL_get_error(ssl,e);
        printf("%d\n", f);
        return false;
    }else{
        printf("OPENSSL Version = %s\n", SSLeay_version(SSLEAY_VERSION));
        printf("Connected to OTAclient\n");
        //exchange msg--------------------------------------------------------------------
            //start of ecall for init_ra
        status  = ecall_ra_init(global_eid, &ecall_sgx_status, def_service_public_key, b_pse, &raCtx);
        if (status != SGX_SUCCESS) { //check for ecall success
            printf("ecall_ra_init failed, error : %08x\n", status);
            return false;
        }
        if (ecall_sgx_status != SGX_SUCCESS) { //check for ecall return value 
            printf("sgx_ra_init failed, error : %08x\n", status);
            return false;
        }
        /* --------------------- Generation of message 0||1 --------------------- */
        status = sgx_get_extended_epid_group_id(&extended_epid_group_id);
        if (status != SGX_SUCCESS) { //check for ecall success
            printf("sgx_get_extended_epid_group_id failed, error : %08x\n", status);
            return false;
        }
        //start of sgx_get_msg1
        status= sgx_ra_get_msg1(raCtx, global_eid, sgx_ra_get_ga, &msg1);
        if (status != SGX_SUCCESS) { //check for ecall success
            printf("sgx_ra_get_msg1 failed, error : %08x\n", status);
            return false;
        }

        unsigned char msg01Array[sizeof(msg01_struct)];
        unsigned char msg01type[14] = "TYPE_RA_MSG01";
        memcpy(&msg01.type, &msg01type, 14);
        memcpy(&msg01.msg1, &msg1, sizeof(sgx_ra_msg1_t));
        memcpy(&msg01.epid, &extended_epid_group_id, sizeof(uint32_t));
        memcpy(&msg01Array, &msg01, sizeof(msg01_struct));
        printf("Size of msg1 : %d\n", sizeof(msg1));
        // sending of msg01 will happen here
        printf("Sending msg1\n");
        SSL_write(ssl, msg01Array, sizeof(msg01Array)+1);
        printf("Send msg1 success\n");
        //receiving of msg2 will happen here rmbr to memcpy buf to &msg2
        //start of ecall for sgx_ra_proc_msg2
        int64_t received;
        char buf[1024] = {0};
        printf("Waiting for msg2 from client\n");
        received=SSL_read(ssl,buf,sizeof(buf));
        printf("Received msg2 from client\n");
        msg2 = (sgx_ra_msg2_t*) buf;
        buf[received] = 0;
        printf("%s\n", buf);
        status = sgx_ra_proc_msg2(raCtx, global_eid, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size, &msg3, &msg3_size);
        if (status != SGX_SUCCESS) { //check for ecall success
            printf("sgx_ra_proc_msg2 failed, error : %08x\n", status);
            return false;
        }
        free(msg2);
        //sending of msg3 will happen here
        unsigned char msg3Array[sizeof(sgx_ra_msg3_t)];
        memcpy(&msg3Array, &msg3, sizeof(sgx_ra_msg3_t));
        SSL_write(ssl, msg3Array, sizeof(msg3Array)+1);
        free(msg3);
        //receive msg4
        received=SSL_read(ssl,buf,sizeof(buf));
        buf[received] = 0;
        int checkvalue = strcmp(buf, "IAS_QUOTE_OK");
        if (checkvalue != 0) {
            printf("Attestation String != IAS_QUOTE_OK\n");
            printf("Attestation String : %s\n", buf);
            return false;
        }
                
        //--------------------------------------------------------------------------------
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);

    }
    return true;
}



/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    if(argc != 2){
        printf("Usage: %s <ipaddr>\n", argv[0]);
        exit(0);
    }

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    //read update file = filearr, filelen
    FILE *fp;
    char *filearr;
    int64_t filelen;
    fp = fopen("ota/mrt.jpg", "rb");
    //fp = fopen("ota/updateFile.txt","rb");
    fseek(fp, 0, SEEK_END);
    filelen = ftell(fp);
    rewind(fp);
    filearr = (char *)malloc((filelen)*sizeof(char));   
    fread(filearr, filelen, 1, fp);
    fclose(fp);

    //read header = headerarr, headerlen
    char *headerarr;
    int64_t headerlen;
    fp = fopen("ota/header.txt","rb");
    fseek(fp, 0, SEEK_END);
    headerlen = ftell(fp);
    rewind(fp);
    headerarr = (char *)malloc((headerlen)*sizeof(char));   
    fread(headerarr, headerlen, 1, fp);
    fclose(fp);

    //join header and file tgt = hAfarr, hAflen
    char *hAfarr=(char *)malloc((filelen+headerlen)*sizeof(char));
    int64_t hAflen = filelen+headerlen;
    memcpy(hAfarr,headerarr,headerlen);
    memcpy(hAfarr+headerlen,filearr,filelen);

    //file encryption = encarr, enclen, macarr, maclen
    char *encarr = (char *) malloc((filelen)*sizeof(filearr));
    char *macarr = (char *) malloc((16)*sizeof(char));
    int64_t maclen=16,enclen=hAflen,len;
    printf("before encryption %ld\n", enclen);
    encryption(global_eid,&enclen,hAfarr,hAflen,encarr,enclen,macarr);
    //encryption(global_eid,&test,filearr,filelen,encarr,enclen,macarr);
    printf("after encryption %ld\n", enclen);

    //read private key
    EVP_PKEY *privKey;
    FILE *privFP = fopen("ota/key.pem","r");
    privKey = PEM_read_PrivateKey(privFP, NULL, NULL, (char*)"5470");
    fclose(privFP);
    if(privKey == NULL){
        fprintf(stderr, "Private key not found\n");
        exit(-1);
    }
    //gen sig from enc = sigarr, siglen
    EVP_MD_CTX *mdctx;
    char *sigarr=(char *)malloc((128)*sizeof(char));
    int64_t siglen=0;
    //mdctx = EVP_MD_CTX_new();
    mdctx = EVP_MD_CTX_create();
    EVP_SignInit(mdctx, EVP_sha256());
    EVP_SignUpdate(mdctx, encarr, enclen);
    if(EVP_SignFinal(mdctx, (unsigned char*)sigarr, (unsigned int*)&siglen, privKey) == 0){
        fprintf(stderr, "Signing failed\n");
        exit(-1);
    }
    printf("Signature created\n");
    //EVP_MD_CTX_free(mdctx);
    EVP_MD_CTX_destroy(mdctx);

    //create struct to hold sizes of file components
    Sizes size;
    size.file=headerlen+siglen+maclen+enclen;
    //size.file=maclen+enclen;
    size.header=headerlen;
    size.sig=siglen;
    size.mac=maclen;
    size.enc=enclen;

    printf("header size: %ld\n", size.header);
    printf("sig size: %ld\n", size.sig);
    printf("mac size: %ld\n", size.mac);
    printf("enc size: %ld\n", size.enc);
    printf("file size: %ld\n", size.file);

    //put everything into one big array
    char *finalarr = (char *)malloc((size.file)*sizeof(char));
    memcpy(finalarr,headerarr,headerlen);
    memcpy(finalarr+headerlen,sigarr,siglen);
    memcpy(finalarr+headerlen+siglen,macarr,maclen);
    memcpy(finalarr+headerlen+siglen+maclen,encarr,enclen);
    //memcpy(finalarr,macarr,size.mac);
    //memcpy(finalarr+maclen,encarr,size.enc);
    //memcpy(finalarr,filearr,filelen);
    
    //change argv[1] to get input from GUI instead of command line
    bool ra = remoteAttestation(argv[1], global_eid);
    if(ra){
        /* Start TLS Server in Enclave */
        //change argv[1] to get input from GUI instead of command line
        ecall_start_tls_client(global_eid,argv[1],finalarr,size.file,size);
    }else{
        printf("Remote Attestation failed\n");
    }

    
    
    free(filearr);
    free(headerarr);
    free(hAfarr);
    free(encarr);
    free(macarr);
    free(sigarr);
    free(finalarr);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("End of application.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

