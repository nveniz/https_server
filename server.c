#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>


#define MAX_REQUEST_SIZE 1024 // maximum size of the HTTP request
#define URL_BUFSIZE 512
#define LINE_BUFSIZE 512

#define PATH_BUFSIZE ( URL_BUFSIZE + LINE_BUFSIZE ) // maximum size of the HTTP request


#define HTTP_VERSION "HTTP/1.1"

char* webroot;
int port;
int threads;

typedef enum {unknown_method, GET, POST, DELETE, HEAD} Method;
typedef enum {unknown_con_type, plain, html, php, python, jpeg, gif, pdf, other}ContentType;

typedef struct http_request{
    Method method;
    char *uri;
    int keep_alive;
    ContentType content_type;
    int content_length;
    char *body;
} REQUEST;

typedef struct http_response{
    int status_code;
    char *status_msg;
    int keep_alive;
    ContentType content_type;
    int content_length;
    char *body;
} RESPONSE;

/* Function to parse server's conf file */
void parse_conf();

/* Function to handle incoming clients */   //TODO LAST
// void handle_client(QUEUE q);



/* Function to send HTTP response */        //TODO
void send_response(SSL *socket, RESPONSE *rspns);

/* Function to execute a script and capture output */ //DONE
int execute_script(char* file_path, RESPONSE* rspns);

/* Function to extract the file extension from a URI */ //DONE
char* get_file_extension(char* uri);

/* Function to generate an appropriate content type based on file extension */ //DONE
ContentType get_content_type(char* file_ext);

/* Function to handle HTTP GET requests */ //TODO
void handle_get(REQUEST *reqst,  RESPONSE *rspns );

/* Function to handle HTTP POST requests */ //TODO
void handle_post(REQUEST *reqst,  RESPONSE *rspns );

/* Function to handle HTTP HEAD requests */ //TODO
int handle_head(REQUEST *reqst,  RESPONSE *rspns );

/* Function to handle HTTP DELETE requests */ //TODO
int handle_delete(REQUEST *reqst,  RESPONSE *rspns );

/* Function to parse the client's request*/ //DONE
int parse_request(char *request, REQUEST *rqst);

/* Function to handle incoming requests */  //DONE
void handle_request(SSL *socket, REQUEST *rqst, RESPONSE *rspns);

ContentType getcontent_type_enum(char *buf);

Method getmethod_enum(char *buf);

char *getcontent_type_str(ContentType content_type);

void parse_conf(){
    FILE* fp;
    char line[LINE_BUFSIZE];
    char home[LINE_BUFSIZE];

    fp = fopen("server.conf", "r");
    if (fp == NULL) {
        printf("Error opening configuration file!\n");
        exit(1);
    }

    while (fgets(line, LINE_BUFSIZE, fp) != NULL) {
        // Check if line is a comment or empty
        if (line[0] == '#' || strncmp(line, "\r\n", strlen("\r\n")) == 0) {
            continue;
        }

        // Parse the line based on the configuration option
        if (strncmp(line, "THREADS", strlen("THREADS")) == 0) {
            threads = atoi(strchr(line, '=') + 1);
        } else if (strncmp(line, "PORT", strlen("PORT")) == 0) {
            port = atoi(strchr(line, '=') + 1);
        } else if (strncmp(line, "HOME", strlen("HOME")) == 0) {
            strcpy(home, strchr(line, '=') + 1);
            // Remove trailing newline character
            home[strcspn(home, "\n")] = 0;
        }
    }
    webroot=home;

    fclose(fp);

    printf("Threads: %d\n", threads);
    printf("Port: %d\n", port);
    printf("Home: %s\n", home);
}

char* get_file_extension(char* uri) {
    char* ext = strrchr(uri, '.');
    if (ext == NULL || ext == uri) {
        return ""; // No extension found
    }
    return ext + 1;
}

/* Function to execute a script and capture output */
int execute_script(char* file_path,RESPONSE* rspns) {
    int output_size=1024;
    char* output_buffer=(char*)(malloc(output_size*sizeof(char)));
    FILE *fp;
    int bytes_read = 0;
    char command[PATH_BUFSIZE];

    // Determine the file extension
    char* file_ext = get_file_extension(file_path);

    // Determine the interpreter command
    char* interpreter_command;
    if (strcmp(file_ext, "py") == 0) {
        interpreter_command = "python3";
    } else if (strcmp(file_ext, "php") == 0) {
        interpreter_command = "php";
    } else {
        printf("Unsupported file extension\n");
        return -1; // Unsupported file extension
    }

    // Construct the command to execute the script
    snprintf(command, PATH_BUFSIZE, "%s %s", interpreter_command, file_path);

    // Open a pipe to the script interpreter
    fp = popen(command, "r");
    if (fp == NULL) {
        return -1; // Error opening pipe
    }

    // Read the output from the pipe
    while (fgets(output_buffer + bytes_read, output_size - bytes_read, fp) != NULL) {
        bytes_read += strlen(output_buffer + bytes_read);

        // If the buffer is full, allocate a larger buffer
        if (bytes_read >= output_size - 1) {
            output_size *= 2;
            output_buffer = realloc(output_buffer, output_size);
            if (output_buffer == NULL) {
                pclose(fp);
                return -1; // Error reallocating buffer
            }
        }
    }
    rspns->status_code=200;
    rspns->status_msg="OK";
    rspns->body=output_buffer;
    rspns->content_length=strlen(rspns->body);
    // Close the pipe
    pclose(fp);

    return bytes_read;
}


void send_response(SSL *socket, RESPONSE *rspns){
    int bufsize = 1024;
    char buf[bufsize];


    snprintf(buf, bufsize, "%s %d %s\
            \r\nServer: UCY-HTTPS-SERVER\
            \r\nContent-Length: %d\
            \r\nConnection: %s\
            \r\nContent-Type: %s\r\n\r\n"
            ,HTTP_VERSION, rspns->status_code, rspns->status_msg, rspns->content_length,  
            (rspns->keep_alive == 1)?"keep-alive":"closed", getcontent_type_str(rspns->content_type));

    SSL_write(socket, buf, bufsize);

    if(rspns-> body != NULL){
        SSL_write(socket, rspns->body, rspns->content_length);
    }

}

void handle_request(SSL *socket, REQUEST *rqst, RESPONSE *rspns){
    // switch(rqst->method){
    //     case GET:
    //         handle_get(rqst, rspns);
    //         break;
    //     case POST:
    //         handle_post(rqst, rspns);
    //         break;
    //     case DELETE:
    //         handle_delete(rqst, rspns);
    //         break;
    //     case HEAD:
    //         handle_head(rqst, rspns);
    //         break;
    // }
    // send_response(socket, rspns);
}

void handle_get(REQUEST *reqst,  RESPONSE *rspns ){
    // Open the requested file
    char* path = reqst->uri;
    if (strcmp(path, "/") == 0) {
        path = "/index.html";
    }
    char file_path[PATH_BUFSIZE];
    snprintf(file_path, PATH_BUFSIZE, "%s%s", webroot, path);
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        rspns->status_code=404;
        rspns->status_msg="Not Found";
        return;
    }

    char* file_ext = get_file_extension(file_path);
    rspns->content_type=getcontent_type_enum(file_ext);
    // *** How we handle connection header? ***

    if(strcmp(file_ext, "py") == 0 || strcmp(file_ext, "php") == 0){
        execute_script(file_path,rspns);
        return;
    }

    rspns->status_code=200;
    rspns->status_msg="OK";
     
    // Determine the file's size
    fseek(file, 0, SEEK_END);
    rspns->content_length= ftell(file);
    fseek(file, 0, SEEK_SET);
  
    rspns->body = realloc(rspns->body, rspns->content_length);
    
    int byte_read = fread(rspns->body, 1, sizeof(rspns->content_length), file);



    // Read file content
    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // send_response_body(client_sock, buffer, bytes_read);
        rspns->content_length+=bytes_read;
        rspns->body = realloc(rspns->body, rspns->content_length);
        snprintf(rspns->body,rspns->content_length, "%s%s", rspns->body, buffer);
    }

    // Close the file
    fclose(file);
}

/*
void handle_request(int client_sock, char* method, char* uri, char* http_version, char* user_agent, char* host, char* connection, char* content_type, char* post_data) {
    // Open the requested file
    char* path = uri;
    if (strcmp(path, "/") == 0) {
        path = "/index.html";
    }
    char file_path[PATH_BUFSIZE];
    // snprintf(file_path, PATH_BUFSIZE, "webroot%s", path);
    FILE* file = fopen(path, "r");
    if (file == NULL) {
        printf("404 Not found");
        // send_error_response(client_sock, 404, "Not Found");
        return;
    }

    // Determine the file's size
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // TO-DO combine response headers in char* not char**
    // // Set the response headers
    // char content_length_header[64];
    // snprintf(content_length_header, 64, "Content-Length: %lu", file_size);
    // char* response_headers[] = {
    //     "HTTP/1.1 200 OK",
    //     "Content-Type: text/html",
    //     content_length_header,
    //     "Connection: close",
    //     NULL
    // };

    // // Send the response headers
    // send_response_headers(client_sock, response_headers);

    // Send the file contents
    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // send_response_body(client_sock, buffer, bytes_read);
        printf("%s",buffer);
    }

    // Close the file
    fclose(file);
}
*/

int handle_head(REQUEST *rqst, RESPONSE *rspns){
 
    handle_get(rqst, rspns);
    
    if(rspns->body != NULL){
        free(rspns->body);
        rspns->body == NULL;
    }
}

int handle_delete(REQUEST *rqst, RESPONSE *rspns){
    char *uri = rqst->uri;
    char path[PATH_BUFSIZE];
    if (strcmp(uri, "/") == 0) {
        uri = "/index.html";
    }
    snprintf(path, PATH_BUFSIZE, "%s%s", webroot, uri);

    if(remove(path)){
        int errnum = errno;
        //if(errno == ENOENT ){
            rspns->status_code = 404;

            char msg[] = " cannot be found on the server!\r\n";
            rspns->content_length = strlen(msg)+strlen(uri);

            rspns->body = realloc(rspns->body, sizeof(char)*(rspns->content_length));
            if(rspns->body == NULL){
                perror("Not enough memory!");
                return -1;
            }
            snprintf(rspns->body, rspns->content_length, "%s%s", uri, msg);
            rspns->content_type = plain;
            rspns->keep_alive = rqst->keep_alive;
        //}
        perror("DELETE request");
        return -1;
    }

    rspns->status_code = 200;
    
    char msg[] = " deleted successfully!\r\n";
    rspns->content_length = strlen(msg)+strlen(uri);
    
    rspns->body = realloc(rspns->body, sizeof(char)*(rspns->content_length));
    if(rspns->body == NULL){
        perror("Not enough memory!");
        return -1;
    }
    snprintf(rspns->body, rspns->content_length, "%s%s", uri, msg);
    rspns->content_type = plain;
    rspns->keep_alive = rqst->keep_alive;
    return 0;    
}

/* if return -1, invalid request */
//TODO
int parse_request(char *request, REQUEST *reqst ){
    

    char *rest = strdup(request);
    int i = 0;
     
    // Extract the method
    char *token = strtok_r(rest, " ", &rest);
   

    if (token == NULL) {
        return -1; // invalid request
    }

    /* Get method */
    reqst->method = getmethod_enum(token);
    
    if(reqst->method == unknown_method){
        return -1;
    }
    

    /* Extract the URI */
    token = strtok_r(rest, " ", &rest);
    
    if (token == NULL) {
        return -1; // invalid request
    }

    if(strlen(token)+1 > URL_BUFSIZE){
        fprintf(stderr,"URL bigger than bufsize!\n");
        return -1;
    }
    memcpy(reqst->uri, token, strlen(token)+1); // copy the URI string
    

    // Extract the HTTP version
    token = strtok_r(rest, "\r\n", &rest);

    if (token == NULL) {
        return -1; // invalid request
    }
    // Check that the HTTP version is valid
    if (strncmp(token, "HTTP/1.1", strlen("HTTP/1.1"))) {
        
        return -1; // invalid request
    }

    // Extract the User-Agent header
    while (rest != NULL) {
        token = strtok_r(rest, "\r\n", &rest);
        
        if (token == NULL || strcmp(token,"")==0) {
            break; // no more headers
        }
        if (strncmp(token, "Connection: ", strlen("Connection: ")) == 0) {
            /* If connection is not keep_alive */
            if(strncmp(token + strlen("Connection: "), "keep-alive", strlen("keep-alive")) != 0){
                reqst->keep_alive = 0;
            }
        } else if (strncmp(token, "Content-Type: ", strlen("Content-Type: ")) == 0) {
            /* Get content type from string */
            reqst->content_type = getcontent_type_enum(token + strlen("Content-Type: "));

        } else if (strncmp(token, "Content-Length: ", strlen("Content-Length: ")) == 0) {
            errno = 0;
            reqst->content_length = strtol(token+strlen("Content-Length: "), NULL, 2);
            if(errno != 0){
                perror("Parsing content_length");
                return -1;
            }
        }
    }
    ;
    // Extract the post data for POST requests
    if(reqst->method == POST){
        if(reqst->content_type == unknown_con_type ){
            return -1;
        }
        reqst->body = (char *)malloc(sizeof(char)*reqst->content_length);
        
        char *body = strstr(request, "\r\n\r\n");
        memcpy(reqst->body, body+2, reqst->content_length);
    }
    // printf("%d\n",reqst->method);
    // printf("%s\n",reqst->uri);
    // printf("%d\n",reqst->keep_alive);
    // printf("%s\n",getcontent_type_str(reqst->content_type));
    // printf("%d\n%s\n%d\n%s\n%d\n%s\n",reqst->method,reqst->uri,reqst->keep_alive,getcontent_type_str(reqst->content_type),reqst->content_length,reqst->body);
    
    printf("token= %d\n",reqst->content_length);
    return 0;
}


int http_request_init(REQUEST* rqst){
    if (rqst == NULL){
        return 1;
    }
    rqst->uri = (char *)malloc(sizeof(char)*URL_BUFSIZE);
    if(rqst->uri == NULL){
        return 1;   
    }
    rqst->method = unknown_method;
    rqst->content_type = unknown_con_type;
    rqst->keep_alive = 1;

    return 0;
}


int http_response_init(RESPONSE* rspns){
    if ( rspns == NULL){
        return 1;
    }
}

Method getmethod_enum(char *buf){
    if(!strncmp("GET", buf, strlen("GET"))) return GET;
    else if(!strncmp("POST", buf, strlen("POST"))) return POST;
    else if(!strncmp("DELETE", buf, strlen("DELETE"))) return DELETE;
    else if(!strncmp("HEAD", buf, strlen("HEAD"))) return HEAD;
    
    return unknown_method;
}

ContentType getcontent_type_enum(char *buf){
    if(!strncmp("text/html", buf, strlen("text/html"))) return html;
    else if(!strncmp("text/x-php", buf, strlen("text/x-php"))) return php;
    else if(!strncmp("text/plain", buf, strlen("text/plain"))) return plain;
    else if(!strncmp("image/jpeg", buf, strlen("image/jpeg"))) return jpeg;
    else if(!strncmp("application/x-python-code", buf, strlen("application/x-python-code"))) return python;
    else if(!strncmp("image/gif", buf, strlen("image/gif"))) return gif;
    else if(!strncmp("application/pdf", buf, strlen("application/pdf"))) return pdf;
    return other;
}

char * getcontent_type_str(ContentType content_type){
    switch(content_type){
        case html:
            return "text/html";
        case php:
            return "text/x-php";
        case plain:
            return "text/plain";
        case jpeg:
            return "image/jpeg";
        case python:
            return "application/x-python-code";
        case gif:
            return "image/gif";
        case pdf:
            return "application/pdf";
       defult:
            return "application/octet-stream";
    }
}

ContentType get_content_type(char *ext){
        if(!strncmp(ext, ".txt", strlen(".txt")) ||
           !strncmp(ext, ".sed", strlen(".sed")) ||
           !strncmp(ext, ".awk", strlen(".awk")) ||
           !strncmp(ext, ".c", strlen(".c")) ||
           !strncmp(ext, ".h", strlen(".h"))) {
            
            return plain;

        } else if (!strncmp(ext, ".html", strlen(".html")) ||
            !strncmp(ext, ".htm", strlen(".htm"))) {
            
            return html;

        } else if (!strncmp(ext, ".php", strlen(".php"))) {

            return php;

        } else if (!strncmp(ext, ".py", strlen(".py"))){

            return python;

        } else if (!strncmp(ext, ".jpeg", strlen(".jpeg")) || 
            !strncmp(ext, ".jpg", strlen(".jpg"))){

            return jpeg;

        } else if (!strncmp(ext, ".gif", strlen(".gif"))){

            return gif;

        } else if (!strncmp(ext, ".pdf", strlen(".pdf"))){

            return pdf;

        } else {
            return other;
        }
}

void print_request_struct(REQUEST* reqst){
    printf("%d\n%s\n%d\n%d\n%s\n",reqst->method,reqst->uri,reqst->keep_alive,reqst->content_length,reqst->body);
}

int main(){

    
    //  // Read the request data from the client socket
    // int request_len = recv(client_sock, request, MAX_REQUEST_SIZE - 1, 0);
    // if (request_len < 0) {
    //     perror("recv failed");
    //     close(client_sock);
    //     return NULL;
    // }
    
    // request[request_len] = '\0'; // add terminate character
    REQUEST* reqst = (REQUEST *) malloc(sizeof(REQUEST));
    http_request_init(reqst);

    RESPONSE* rspns = (RESPONSE*) malloc(sizeof(RESPONSE));
    http_response_init(rspns);

    

    char request[] = "POST ../test.py HTTP/1.1\r\nUser-Agent: My_web_browser\r\nContent-Length: 3\r\nContent-Type: txt/html\r\nHost: astarti.cs.ucy.ac.cy:30000\r\nConnection: keep-alive\r\n\r\nhtml data";
    parse_conf();

    // printf("%s",request);
    parse_request(request,reqst);
    print_request_struct(reqst);



    
    // Parse the request
    // if (parse_result == -1) {
    //     printf("Invalid request\n");
    //     close(client_sock);
    //     return NULL;
    // }
    
}


