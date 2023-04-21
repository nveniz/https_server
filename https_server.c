#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    /* set the type of connection to TCP/IP */
    addr.sin_family = AF_INET;
    /* set the server port number */
    addr.sin_port = htons(port);
    /* set our address to any interface */
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    /* bind serv information to s socket */
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    /* start listening allowing a queue of up to 1 pending connection */
    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}
void cleanup_openssl()
{
    EVP_cleanup();
}


SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    /* The actual protocol version used will be negotiated to the 
     * highest version mutually supported by the client and the server.      
     * The supported protocols are SSLv3, TLSv1, TLSv1.1 and TLSv1.2. 
     */
    method = SSLv23_server_method();
    //method = TLSv1_2_server_method(); 

    /* creates a new SSL_CTX object as framework to establish TLS/SSL or   
     * DTLS enabled connections. It initializes the list of ciphers, the 
     * session cache setting, the callbacks, the keys and certificates, 
     * and the options to its default values
     */
    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert using dedicated pem files */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
 
     
    int sock;
    SSL_CTX *ctx;

    /* initialize OpenSSL */
    init_openssl();

    /* Initialize queue */
    //TODO

    /* Parse Config file */
    //TODO

    /* setting up algorithms needed by TLS */
    ctx = create_context();

    /* specify the certificate and private key to use */
    configure_context(ctx);

    sock = create_socket(4433);

    /* Create Threads */
    //TODO



    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";
	
	/* Server accepts a new connection on a socket.
         * Server extracts the first connection on the queue 
         * of pending connections, create a new socket with the same 
         * socket type protocol and address family as the specified 
         * socket, and allocate a new file descriptor for that socket.
         */
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

	/* Add new client to the requests queue */
	//TODO
	



/*----------------------This will be done in the thread function--------------------------
 *
 *         * creates a new SSL structure which is needed to hold the data 
 *         * for a TLS/SSL connection
 *         * 
 *        ssl = SSL_new(ctx);
 *        SSL_set_fd(ssl, client);
 *
 *        * wait for a TLS/SSL client to initiate a TLS/SSL handshake *
 *        if (SSL_accept(ssl) <= 0) {
 *            ERR_print_errors_fp(stderr);
 *        }
 *         * if TLS/SSL handshake was successfully completed, a TLS/SSL 
 *         * connection has been established
 *         *
 *        else {
 *             * writes num bytes from the buffer reply into the 
 *             * specified ssl connection
 *             *
 *            SSL_write(ssl, reply, strlen(reply));
 *        }
 *
 *	* close ssl connection *
 *	SSL_shutdown(ssl);
 *        * free an allocated SSL structure *
 *        SSL_free(ssl);
 *        close(client);
 *----------------------------------------------------------------------------------------*/
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
