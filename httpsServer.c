#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/types.h>




#define LINE_BUFSIZE 512
typedef struct{
    char *home;
    char *ca;
    char *key;
    int threads;
    int port;
}HTTPS_Config;

typedef struct{
   // REQUESTS *req;
    HTTPS_Config *conf;
}HTTPS_Server;



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

HTTPS_Server *https_server_init(HTTPS_Config){


}

HTTPS_Config *https_config_read(char *configname){
    
    HTTPS_Config *conf = (HTTPS_Config*)malloc(sizeof(HTTPS_Config));
    if(conf == NULL){
        perror("http_config_read malloc:");
        return NULL;
    }



    char *line = (char *)malloc(sizeof(char)*LINE_BUFSIZE);
    if(line == NULL){
        perror("http_config_read malloc:");
        return NULL;
    }

    FILE* fp;
    fp = fopen(configname, "r");
    if (fp == NULL) {
        printf("Error opening configuration file!\n");
        exit(1);
    }

    int count=1;
    while (fgets(line, LINE_BUFSIZE, fp) != NULL) {
        // Check if line is a comment or empty
        while(isspace(*line) && *line != '\0'){
            line++;
        }
        if (*line == '\0' || *line == '#') {
            continue;
        }

        // Parse the line based on the configuration option
        if (strncmp(line, "THREADS", strlen("THREADS")) == 0) {

            char *str = strchr(line, '=') + 1;
            char *tmp;
            conf->threads = strtol(str, &tmp, 10);
            if(strcmp(tmp,"\n\0")){
                fprintf(stderr, "UCY-HTTPS: Config Syntax error: Line %d, THREADS must be a number. unknown: %s\n",count,str);
                return NULL;
            }

        } else if (strncmp(line, "PORT", strlen("PORT")) == 0) {

            char *str = strchr(line, '=') + 1;
            char *tmp;
            conf->port = strtol(str, &tmp, 10);
            if(strcmp(tmp,"\n\0")){
                fprintf(stderr, "UCY-HTTPS: Config Syntax error: Line %d, PORT must be a number. unknown: %s\n",count,str);
                return NULL;
            }else if(conf->port > 65535){
                fprintf(stderr, "UCY-HTTPS: Config Syntax error: Line %d, PORT number is invalid.\n",count,str);
                return NULL;
            }

        } else if (strncmp(line, "HOME", strlen("HOME")) == 0) {

            char *str = strchr(line, '=') + 1;
            int homelen = strlen(str);
            conf->home = (char *)malloc(sizeof(char)*homelen);
            if(conf->home == NULL){
                perror("http_config_read malloc:");
                return NULL;
            }
            strcpy(conf->home, str);
            if(*(conf->home+homelen-1) == '\n') *(conf->home+homelen-1) = '\0';
            DIR* dir = opendir(conf->home);
            if (dir) {
                /* Directory exists. */
               closedir(dir);
            } else if (ENOENT == errno) {
                /* Directory does not exist. */
                fprintf(stderr, "UCY-HTTPS: Config Directory Error: Line %d, %s\n",count,strerror(errno));
                return NULL;
            }else {
                /* opendir() failed for some other reason. */
                fprintf(stderr, "UCY-HTTPS: Config Directory Error: Line %d, %s\n",count,strerror(errno));
                return NULL;
            }

        } else if (strncmp(line, "CERTIFICATE", strlen("CERTIFICATE")) == 0) {
            char *str = strchr(line, '=') + 1;
            int len = strlen(str);
            conf->ca = (char *)malloc(sizeof(char)*len);
            if(conf->ca == NULL){
                perror("http_config_read malloc:");
                return NULL;
            }
            strcpy(conf->ca, str);
            if(*(conf->ca+len-1) == '\n') *(conf->ca+len-1) = '\0';
            FILE *ftmp = fopen(conf->ca, "r");
            if(ftmp == NULL){
                fprintf(stderr, "UCY-HTTPS: Config Certificate file Error: Line %d, %s\n",count,strerror(errno));
                return NULL;
            }
            fclose(ftmp);
            

        } else if (strncmp(line, "KEY", strlen("Key")) == 0) {

            char *str = strchr(line, '=') + 1;
            int len = strlen(str);
            conf->key = (char *)malloc(sizeof(char)*len);
            if(conf->key == NULL){
                perror("http_config_read malloc:");
                return NULL;
            }
            strcpy(conf->key, str);
            if(*(conf->key+len-1) == '\n') *(conf->key+len-1) = '\0';
            FILE *ftmp = fopen(conf->key, "r");
            if(ftmp == NULL){
                fprintf(stderr, "UCY-HTTPS: Config Key file Error: Line %d, %s\n",count,strerror(errno));
                return NULL;
            }
            fclose(ftmp);

        } else {
            fprintf(stderr, "UCY-HTTPS: Config Syntax error: Line %d, Unknown option: %s\n",count,line);
            return NULL;
        }

        count++;
    }
    fclose(fp);

    printf("Threads: %d\n", conf->threads);
    printf("Port: %d\n", conf->port);
    printf("Home: %s\n", conf->home);
    
}


int https_server(HTTPS_Server)
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
	



    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}


void https_server_thread(){

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



void main(){
    https_config_read("config");

}
