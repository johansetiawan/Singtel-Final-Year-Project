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

#include "sgx_uae_service.h"
#include "sgx_quote.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "stdlib.h"
#include "sgx_tae_service.h"
#include "sgx_utils.h"
#include <stdint.h>
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;


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

server_msg0 gen_server_msg0(server_msg0 msg0) {
    uint32_t extended_epid_group_id = 0;
    sgx_get_extended_epid_group_id(&extended_epid_group_id);
    unsigned char msg0type[13] = "TYPE_RA_MSG0";
    memcpy(&msg0.type, &msg0type, 14);
    memcpy(&msg0.epid, &extended_epid_group_id, sizeof(extended_epid_group_id));
//check if msg0 is generated properly
    printf("generated msg0, type = %s\n", msg0.type);
    return msg0;
}

server_msg1full gen_server_msg1(server_msg1full msg1) {
    //variables needed
    sgx_target_info_t p_target_info;
    sgx_epid_group_id_t p_gid;

    sgx_init_quote(&p_target_info, &p_gid); //have to use p_target_info
    char msg1type[13] = "TYPE_RA_MSG1";
    memcpy(&msg1.type, &msg1type, 14);
    memcpy(&msg1.gid, &p_gid, sizeof(sgx_epid_group_id_t));
   // memcpy(&msg1.target_info, &p_target_info, sizeof(sgx_target_info_t));
    printf("generated msg1, type = %s\n", msg1.type);
    return msg1;
}


server_msg3 gen_server_msg3(client_msg2 msg2, server_msg3 msg3, int ps_sec_prop) {
    //variables needed
    uint32_t p_quote_size;
    sgx_target_info_t target_info;
    sgx_report_data_t report_data;
    sgx_report_t report;
    const sgx_quote_nonce_t p_nonce = (sgx_quote_nonce_t) {0};
    sgx_report_t p_qe_report;
    sgx_quote_t p_quote;
    int ret = 0;
    sgx_spid_t *spid = (sgx_spid_t*) msg2.spid;

    

}





/*    
    bool msg2check = false;
    int receive = 0;
    unsigned char *msg0success[30];
    unsigned char *buf[1024] = {0};
    char receivedStrings[100];

    //msg1 variables
    sgx_target_info_t p_target_info;
    sgx_epid_group_id_t p_gid;

    //msg2 variables
    uint32_t p_quote_size;
    sgx_target_info_t target_info;
    sgx_report_data_t report_data;
    sgx_report_t report;
    const sgx_quote_nonce_t p_nonce = (sgx_quote_nonce_t) {0};
    sgx_report_t p_qe_report;
    sgx_quote_t p_quote;*/


/*    int ret = 0; //declaration of var ret with type sgx_status_t
    uint32_t *extended_epid_group_id = 0;
    uint8_t gidbuffer[4];
    uint32_t *epid_group_id;
    ocall_get_epid_group_id(&epid_group_id, extended_epid_group_id);
    receive = SSL_read(ssl, receivedStrings, sizeof(receivedStrings)); // initial read to tell server remote attestation process is starting (from client)
        if (receivedStrings == "initRA") {
            memset(&buf[0], 0, sizeof(buf)); //function to clear array*/
/*            server_msg0 msg0;
            unsigned char msg0type[13] = "TYPE_RA_MSG0";
            memcpy(&msg0.type, &msg0type, 14);
            memcpy(&msg0.epid, epid_group_id, sizeof(epid_group_id));

            //*(uint32_t*)((uint8_t*)msg0 + sizeof(msgHeader)) = extended_epid_group_id;
            printf("msg0 generated\n");
            //convert struct msg0 to bytes so that client can receive through SSL
            unsigned char casted_msg0[sizeof(msg0)];
            printf("compiled until before first msg sent");
            memcpy(&casted_msg0, &msg0, sizeof(msg0));
            //send msg1 to client
            SSL_write(ssl, casted_msg0, sizeof(casted_msg0)+1);
        }
            //prepare to receive msg0 success
            receive = SSL_read(ssl, &receivedStrings, sizeof(receivedStrings)+1);
            if (receivedStrings != "RA_MSG0_SUCCESS") { //set to how nic declare
                return false;
            }
*/
/*            //send msg1
            sgx_init_quote(&p_target_info, &p_gid);
            //generate msg1
            server_msg1 msg1;
            char msg1type[13] = "TYPE_RA_MSG1";
            memcpy(&msg1.type, &msg1type, 14);
            memcpy(&msg1.gid, &p_gid, sizeof(sgx_epid_group_id_t));
            
            //convert struct msg1 to bytes so that client can receive through SSL
            unsigned char casted_msg1[sizeof(msg1)];
            memcpy(&casted_msg1, &msg1, sizeof(msg1));
            //send msg1 to client
            SSL_write(ssl, casted_msg1, sizeof(casted_msg1)+1);

            //prepare to receive msg2
            receive = SSL_read(ssl, &buf, sizeof(buf));
            client_msg2 *msg2 = (client_msg2*) buf;
            memset(&buf[0], 0, sizeof(buf)); //function to clear array
            char* msg2type= "TYPE_RA_MSG2";
            int check = strncmp ((char*) msg2->type,msg2type, strlen(msg2type));
            if (check != 0) {
                return false;
            }
            else {
                //check against sigrl if got time
                sgx_calc_quote_size(msg2->sig_rl, msg2->sig_rl_size, &p_quote_size);
                sgx_create_report(&target_info, &report_data, &report);
                sgx_spid_t *spid = (sgx_spid_t*) msg2->spid;
                ret = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, spid, &p_nonce, msg2->sig_rl, msg2->sig_rl_size, &p_qe_report, &p_quote, p_quote_size);
                if (&p_quote == NULL) {
                    return false;
                }
                else {
                    printf("ra test stop\n");
                }
            }*/
                /*server_msg3 msg3; 
                msg3->type = TYPE_RA_MSG3;
                msg3->quote = p_quote;
                msg3->ps_sec_prop = 0;
                unsigned char casted_msg3[sizeof(msg3)];
                memcpy(&casted_msg3, &msg3, sizeof(msg3));
                SSL_write(ssl, casted_msg3, strlen(casted_msg3) + 1);
            }
            receive = SSL_read(ssl, &buf, sizeof(buf));
            client_msg4 msg4 = (client_msg4*) buf;
            memset(&buf[0], 0, sizeof(buf)); //function to clear array
            if (msg4.type != "TYPE_RA_MSG4") {
                return false;
            }
            else {
                if(msg4.attestation_status == ""){
                    return TRUE;
                } //set to correct status                   
            }*/
     



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

    //start generation of messages to be used for RA
    server_msg0 msg0;
    server_msg1full msg1;
    msg0 = gen_server_msg0(msg0);
    msg1 = gen_server_msg1(msg1);
    
    /* Start TLS Server in Enclave */
    //change argv[1] to get input from GUI instead of command line
    ecall_start_tls_client(global_eid,argv[1],finalarr,size.file,size, msg0, msg1);
    
    free(filearr);
    free(headerarr);
    free(hAfarr);
    free(encarr);
    free(macarr);
    free(sigarr);
    free(finalarr);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: Sample TLS Client successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

