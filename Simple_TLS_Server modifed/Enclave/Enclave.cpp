#include "Ocall_wrappers.h"
#include "Enclave_t.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>



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

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_server_method();
    //TLSv1_2_server_method()
    //SSLv23_server_method()
    //SSLv3_server_method()

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


static void configure_context(SSL_CTX *ctx)
{   
    char *certStr;
    ocall_readCertFile(&certStr,"server.cert.pem");
    char *keyStr;
    ocall_readKeyFile(&keyStr,"server.key.pem");
    //load cert and key into ctx
	if(SSL_CTX_use_certificate(ctx, generateCertificate(certStr)) <= 0){
        printf("no cert loaded into ctx\n");
    }
    if(SSL_CTX_use_PrivateKey(ctx, generateKey(keyStr)) <=0 ){
        printf("no key loaded into ctx\n");
    }

    //set mutual authentication here
    //state that client must send cert over for verification
    //SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);
    //compare the certs received from the client to the one the server have, to complete authentication
    //SSL_CTX_load_verify_locations(ctx,"client.cert.pem",".");
    //scan all certs stated and list them as acceptable CAs for client
    //char *clientStr;
    //ocall_readCertFile(&clientStr,"client.cert.pem");
    //SSL_CTX_add_client_CA_list(ctx, generateCertificate(clientStr));
    

}

static int create_socket_server(int port)
{
    int s, optval = 1;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
    	printe("sgx_socket");
		exit(EXIT_FAILURE);
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
		printe("sgx_setsockopt");
		exit(EXIT_FAILURE);
    }
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    	printe("sgx_bind");
		exit(EXIT_FAILURE);
    }
    if (listen(s, 128) < 0) {
    	printe("sgx_listen");
		exit(EXIT_FAILURE);
    }
    return s;
}

void ecall_start_tls_server(void)
{
    int sock;
    SSL_CTX *ctx;

    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    init_openssl();
    ctx = create_context();
    configure_context(ctx);
    


    sock = create_socket_server(4433);
    if(sock < 0) {
		printe("create_socket_client");
		exit(EXIT_FAILURE);
    }

    /* Handle SSL/TLS connections */
    while(1) {
        struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *cli;
        unsigned char read_buf[1024];
        int r = 0;
        printl("Wait for new connection...");
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            printe("Unable to accept");
            exit(EXIT_FAILURE);
        }

		cli = SSL_new(ctx);
        SSL_set_fd(cli, client);
		if (SSL_accept(cli) <= 0) {
            printe("SSL_accept");
            exit(EXIT_FAILURE);
        }
		
        printl("ciphersuit: %s", SSL_get_current_cipher(cli)->name);
        /* Receive buffer from TLS server */
        // send file here
        r = SSL_read(cli, read_buf, sizeof(read_buf));
        printl("read_buf: length = %d : %s", r, read_buf);
        memset(read_buf, 0, sizeof(read_buf));        
        
		//ocall_SGXenc("./1.enc", "./mrt.jpg");
		
        printl("Close SSL/TLS client");
        SSL_free(cli);
        sgx_close(client);
    }

    sgx_close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
