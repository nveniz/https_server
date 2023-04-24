#include "types.h"
#include "requestQueue.h"
#include "handleMessages.h"

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

void configure_context(SSL_CTX *ctx, char *cert, char *key)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert using dedicated pem files */
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}

HTTPS_Server *https_server_init(HTTPS_Config *conf){
     if(conf == NULL){
        fprintf(stderr, "https_server_init: HTTPS_Config object cannot be NULL!\n");
	    exit(EXIT_FAILURE);
    }

    HTTPS_Server *server = (HTTPS_Server *)malloc(sizeof(HTTPS_Server));

    if(server == NULL){
        perror("https_server_init malloc:");
	    exit(EXIT_FAILURE);
    }

    /* initialize OpenSSL */
    init_openssl();

    /* setting up algorithms needed by TLS */
    SSL_CTX *ctx = create_context();

    /* specify the certificate and private key to use */
    configure_context(ctx, conf->cert, conf->key);
    
    /* Create server listening socket */
    server->socket = create_socket(conf->port);
      
    /* Initialize requests queue */
    requests_init(&server->req, ctx);
    
    server->conf = conf;
    
    return server;

}


void https_server_cleanup(HTTPS_Server *server){
    /* Clean up requests queue */
    requests_cleanup(server->req);
    /* Close socket */
    close(server->socket);
    /* Cleanup openssl */
    cleanup_openssl();
    
    /* Free config strings */
    free(server->conf->home);
    free(server->conf->cert);
    free(server->conf->key);
    
    /* Free structures */
    free(server->conf);
    free(server);


}

HTTPS_Config *https_config_read(char *configname){
    
    HTTPS_Config *conf = (HTTPS_Config*)malloc(sizeof(HTTPS_Config));
    if(conf == NULL){
        perror("http_config_read malloc:");
	    exit(EXIT_FAILURE);
    }



    char *line = (char *)malloc(sizeof(char)*LINE_BUFSIZE);
    if(line == NULL){
        perror("http_config_read malloc:");
	    exit(EXIT_FAILURE);
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
            	exit(EXIT_FAILURE);
            }else if(conf->threads <= 0){
                fprintf(stderr, "UCY-HTTPS: Config Syntax error: Line %d, THREADS number is invalid.\n",count,str);
	            exit(EXIT_FAILURE);
            }

        } else if (strncmp(line, "PORT", strlen("PORT")) == 0) {

            char *str = strchr(line, '=') + 1;
            char *tmp;
            conf->port = strtol(str, &tmp, 10);
            if(strcmp(tmp,"\n\0")){
                fprintf(stderr, "UCY-HTTPS: Config Syntax error: Line %d, PORT must be a number. unknown: %s\n",count,str);
            	exit(EXIT_FAILURE);
            }else if(conf->port > 65535 || conf->port <= 0){
                fprintf(stderr, "UCY-HTTPS: Config Syntax error: Line %d, PORT number is invalid.\n",count,str);
	            exit(EXIT_FAILURE);
            }

        } else if (strncmp(line, "HOME", strlen("HOME")) == 0) {

            char *str = strchr(line, '=') + 1;
            int homelen = strlen(str);
            conf->home = (char *)malloc(sizeof(char)*homelen);
            if(conf->home == NULL){
                perror("http_config_read malloc:");
	            exit(EXIT_FAILURE);
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
            	exit(EXIT_FAILURE);
            }else {
                /* opendir() failed for some other reason. */
                fprintf(stderr, "UCY-HTTPS: Config Directory Error: Line %d, %s\n",count,strerror(errno));
	            exit(EXIT_FAILURE);
            }

        } else if (strncmp(line, "CERTIFICATE", strlen("CERTIFICATE")) == 0) {
            char *str = strchr(line, '=') + 1;
            int len = strlen(str);
            conf->cert = (char *)malloc(sizeof(char)*len);
            if(conf->cert == NULL){
                perror("http_config_read malloc:");
            	exit(EXIT_FAILURE);
            }
            strcpy(conf->cert, str);
            if(*(conf->cert+len-1) == '\n') *(conf->cert+len-1) = '\0';
            FILE *ftmp = fopen(conf->cert, "r");
            if(ftmp == NULL){
                fprintf(stderr, "UCY-HTTPS: Config Certificate file Error: Line %d, %s\n",count,strerror(errno));
	            exit(EXIT_FAILURE);
            }
            fclose(ftmp);
            

        } else if (strncmp(line, "KEY", strlen("Key")) == 0) {

            char *str = strchr(line, '=') + 1;
            int len = strlen(str);
            conf->key = (char *)malloc(sizeof(char)*len);
            if(conf->key == NULL){
                perror("http_config_read malloc:");
	            exit(EXIT_FAILURE);
            }
            strcpy(conf->key, str);
            if(*(conf->key+len-1) == '\n') *(conf->key+len-1) = '\0';
            FILE *ftmp = fopen(conf->key, "r");
            if(ftmp == NULL){
                fprintf(stderr, "UCY-HTTPS: Config Key file Error: Line %d, %s\n",count,strerror(errno));
            	exit(EXIT_FAILURE);
            }
            fclose(ftmp);

        } else {
            fprintf(stderr, "UCY-HTTPS: Config Syntax error: Line %d, Unknown option: %s\n",count,line);
        	exit(EXIT_FAILURE);
        }

        count++;
    }
    fclose(fp);
    return conf;

  //  printf("Threads: %d\n", conf->threads);
  //  printf("Port: %d\n", conf->port);
  //  printf("Home: %s\n", conf->home);
    
}
void *https_server_thread(void *srv){
    HTTPS_Server *server = (HTTPS_Server *) srv;
    int client;
	SSL *ssl;
    REQUEST *rqst;
    RESPONSE *rspns;
	/* Buf size is 8K */
	int buf_size = 8192;
	char *buf[buf_size];

    int keep_alive = 1;

    https_request_init(&rqst);
    https_response_init(&rspns);

	while(1){

		requests_get(server->req, &client);
        /* Creating the TLS handshake with the client fd and SSL_CTX */
		ssl = SSL_new(server->req->ctx);
		SSL_set_fd(ssl, client);
        /* wait for a TLS/SSL client to initiate a TLS/SSL handshake */
		if (SSL_accept(ssl) <= 0) {
            send_response_msg(NULL, client, 525, strerror(errno));
            keep_alive = 0;
		}

        /* if TLS/SSL handshake was successfully completed, a TLS/SSL
		 * connection has been established
		 */
        while(keep_alive){

            char *request;
            int requestlen=0;
            int ret = ssl_dyn_read(ssl, &request, &requestlen); 
            switch (ret){
                case -1:
                    send_response_msg(ssl, 0, 413, "Server out of memory");
                case -2: 
                    send_response_msg(ssl, 0, 500 , "SSL_read failed");
            }
		    /* Most http server implementation limit the header size
		    * to 8K even though there is no limit in the RFC
		    *
		    * The buffer needs to be parsed as a header at first
		    * in order to find the size of the HTTP body using
		    * the Content-length in the header*/

		    /* Parse the http request*/
            if(!parse_request(ssl, request, rqst)){
            
		        /* Handle and respond to the request */
		        handle_request(ssl, rqst, rspns, server->conf->home);    
                keep_alive = rspns->keep_alive;
            }

        }
		/* Close sockets after the HTTP close */
        close(client);
	}
}

int https_server(HTTPS_Server *server)
{
    if(server == NULL){
        fprintf(stderr,"https_server: HTTPS_Server not initialized!\n");
        exit(EXIT_FAILURE);
    }
    /* Create Threads */
    for(int i=0; i<server->conf->threads; i++){
        pthread_t thread;
        pthread_create(&thread, NULL, https_server_thread, server);
    }
    
    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
	
	    /* Server accepts a new connection on a socket.
         * Server extracts the first connection on the queue 
         * of pending connections, create a new socket with the same 
         * socket type protocol and address family as the specified 
         * socket, and allocate a new file descriptor for that socket.
         */
        int client = accept(server->socket, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

	    /* Add new client to the requests queue */
        requests_add(server->req, client);	

    }
}

void main(){
    HTTPS_Config *conf = https_config_read("config");

    HTTPS_Server *server = https_server_init(conf);

    https_server(server);

    https_server_cleanup(server);



}
