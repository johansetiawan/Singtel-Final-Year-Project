#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/buffer.h>
#include <openssl/pem.h> 
#include <openssl/evp.h> 
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/tls1.h>
 
#define FAIL    -1

 
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
    SSL_METHOD *method;
    SSL_CTX *ctx;
    
    //change algo to accept only ecdsa and ecdhe
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    OpenSSL_add_all_ciphers();

    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    //TLSv1_2_client_method
    //SSLv23_client_method
    //SSLv3_client_method
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    //state that server must send its cert over for verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    //compare cert sent over from server to trusted cert to verify server
    SSL_CTX_load_verify_locations(ctx,"ca.cert.pem", NULL);
    

    return ctx;
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No server certificates configured.\n");

}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    //set the local certificate from CertFile 
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    //set the private key from KeyFile (may be the same as CertFile) 
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // verify private key 
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
 
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;

    //buffer for holding messages
    char buf[1024];
    char acClientRequest[1024] ={0};


    //check if successfully received message from client
    int bytes;

    //for arguments and command
    char *hostname, *portnum;
    
    // check arguments and command
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();

    //assign destination address (Server) and port number (must be same as that assigned by server)
    hostname=strings[1];
    portnum=strings[2];
 
    ctx = InitCTX();
    LoadCertificates(ctx, "client.cert.pem", "client.key.pem"); /* load certs,key --> give relative file path to keys and certs */
    //connecting as TCP, haven't initialise SSL
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    /* attach the socket descriptor */
    SSL_set_fd(ssl, server);    
    //start SSL connection
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {  
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* display server certs */


        char msg[1024] ={0};
        const char *cpMessage = "%s"; 
        
        //gather client input
        //printf("msg= ");
        //scanf("%s",msg);

        const char *send_buf = "Hello TLS Server!";
        

        /* construct reply */
        //sprintf(destination buffer,client input)
        //sprintf(acClientRequest, msg);   
        
        //send message to server
        SSL_write(ssl, send_buf, strlen(send_buf)+1);
        //SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */

        //receive message from server and display
        //bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        //buf[bytes] = 0;
        //printf("Received: \"%s\"\n", buf);


        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}