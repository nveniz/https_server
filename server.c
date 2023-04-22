#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>


#define MAX_REQUEST_SIZE 1024 // maximum size of the HTTP request
#define URL_BUFSIZE 256
//#define PATH_MAX 512 // maximum size of the HTTP request
#define MAX_LINE_LENGTH 50

#define HTTP_VERSION "HTTP/1.1"


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
int execute_script(char* script_name, char* output_buffer, int output_size);

/* Function to extract the file extension from a URI */ //DONE
char* get_file_extension(char* uri);

/* Function to generate an appropriate content type based on file extension */ //DONE
char* get_content_type(char* file_ext);

/* Function to handle HTTP GET requests */ //TODO
void handle_get(REQUEST *reqst,  RESPONSE *rspns );

/* Function to handle HTTP POST requests */ //TODO
void handle_post(REQUEST *reqst,  RESPONSE *rspns );

/* Function to handle HTTP HEAD requests */ //TODO
void handle_head(REQUEST *reqst,  RESPONSE *rspns );

/* Function to handle HTTP DELETE requests */ //TODO
void handle_delete(REQUEST *reqst,  RESPONSE *rspns );

/* Function to parse the client's request*/ //DONE
int parse_request(char *request, REQUEST *rqst);

/* Function to handle incoming requests */  //DONE
void handle_request(SSL *socket, REQUEST *rqst, RESPONSE *rspns);

ContentType getcontent_type_enum(char *buf);

Method getmethod_enum(char *buf);

char * getcontent_type_str(ContentType content_type);

void parse_conf(){
    FILE* fp;
    char line[MAX_LINE_LENGTH];
    int threads = 0;
    int port = 0;
    char home[MAX_LINE_LENGTH];

    fp = fopen("server.conf", "r");
    if (fp == NULL) {
        printf("Error opening configuration file!\n");
        exit(1);
    }

    while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
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
int execute_script(char* script_name, char* output_buffer, int output_size) {
    FILE *fp;
    int bytes_read = 0;
    char command[PATH_MAX];

    // Determine the file extension
    char* file_ext = get_file_extension(script_name);

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
    snprintf(command, PATH_MAX, "%s %s", interpreter_command, script_name);

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
    printf("%s", output_buffer);
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
    SSL_write(socket, rspns->body, rspns->content_length);





//    //snprintf(response_headers, MAX_REQUEST_SIZE, "%s %s %s\nContent-Type: %s\nContent-Length: %d\nConnection: %s\n\n", http_version, status_code, status_msg, content_type, content_length, connection);






//    char response_headers[MAX_REQUEST_SIZE];
//    //snprintf(response_headers, MAX_REQUEST_SIZE, "%s %s %s\nContent-Type: %s\nContent-Length: %d\nConnection: %s\n\n", http_version, status_code, status_msg, content_type, content_length, connection);
//    int headers_len = strlen(response_headers);
//
//    // Send headers
//    if (send(client_sock, response_headers, headers_len, 0) < 0) {
//        perror("Error sending response headers");
//        return;
//    }
//
//    // Send content
//    if (content_length > 0 && send(client_sock, content, content_length, 0) < 0) {
//        perror("Error sending response body");
//        return;
//    }
}


void send_response_headers(int client_sock, char* response_headers) {
// Send the response headers to the client
//    int bytes_sent = 0;
//    int total_bytes_sent = 0;
//    int response_length = strlen(response_headers);
//
//    while (total_bytes_sent < response_length) {
//        bytes_sent = send(client_sock, response_headers + total_bytes_sent, response_length - total_bytes_sent, 0);
//
//        if (bytes_sent == -1) {
//            perror("Error sending response headers");
//            break;
//        }
//
//        total_bytes_sent += bytes_sent;
//    }
}

void send_response_body(int client_sock, char* buffer, int bytes_read) {
//    int bytes_sent = 0;
//    while (bytes_sent < bytes_read) {
//        int result = send(client_sock, buffer + bytes_sent, bytes_read - bytes_sent, 0);
//        if (result == -1) {
//            perror("send");
//            break;
//        }
//        bytes_sent += result;
//    }
}

void send_error_response(int client_sock, int status_code, char *message) {
//    char response[1024];
//    sprintf(response, "HTTP/1.1 %d %s\r\nContent-Length: %ld\r\n\r\n%s",
//            status_code, message, strlen(message), message);
//    send(client_sock, response, strlen(response), 0);
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

/*
void handle_request(int client_sock, char* method, char* uri, char* http_version, char* user_agent, char* host, char* connection, char* content_type, char* post_data) {
    // Open the requested file
    char* path = uri;
    if (strcmp(path, "/") == 0) {
        path = "/index.html";
    }
    char file_path[PATH_MAX];
    // snprintf(file_path, PATH_MAX, "webroot%s", path);
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

/* if return -1, invalid request */
//TODO
int parse_request(char *request, REQUEST *reqst ){

    char* request_copy = (char*)(malloc(strlen(request)+1));
    memcpy(request_copy,request,strlen(request)+1);
    request_copy[strlen(request_copy)+1]='\0';
    char *token;
    char *rest = request_copy;
    int i = 0;

    // Extract the method
    token = strtok_r(rest, " ", &rest);
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
    token = strtok_r(rest, "\n", &rest);
    if (token == NULL) {
        return -1; // invalid request
    }
    // Check that the HTTP version is valid
    if (strncmp(token, "HTTP/1.1", strlen("HTTP/1.1"))) {
        
        return -1; // invalid request
    }

    // Extract the User-Agent header
    while (rest != NULL) {
        token = strtok_r(rest, "\n", &rest);
        if (*token == '\r') {
            break; // no more headers
        }
        if (strncmp(token, "Connection: ", strlen("Connection: ")) == 0) {
            /* If connection is not keep_alive */
            if(strncmp(token + strlen("Connection: "), "keep-alive", strlen("keep-alive"))){
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
    // Extract the post data for POST requests
    if(reqst->method == POST){
        if(reqst->content_type == unknown_con_type ){
            return -1;
        }
        reqst->body = (char *)malloc(sizeof(char)*reqst->content_length);
        
        char *body = strstr(request, "\r\n\r\n");
        memcpy(reqst->body, body, reqst->content_length);
    }

    free(request_copy); 
    return 0;
}


int http_request_init(REQUEST** rqst){
    *rqst = (REQUEST *) malloc(sizeof(REQUEST));
    if (*rqst == NULL){
        return 1;
    }
    (*rqst)->uri = (char *)malloc(sizeof(char)*URL_BUFSIZE);
    if((*rqst)->uri == NULL){
        return 1;   
    }
    (*rqst)->method = unknown_method;
    (*rqst)->content_type = unknown_con_type;
    (*rqst)->keep_alive = 1;

    return 0;

}

int http_response_init(RESPONSE** rspns){
    *rspns = (RESPONSE*) malloc(sizeof(RESPONSE));
    if ( *rspns == NULL){
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

char * get_content_type(char *ext){
        if(!strncmp(ext, ".txt", strlen(".txt")) ||
           !strncmp(ext, ".sed", strlen(".sed")) ||
           !strncmp(ext, ".awk", strlen(".awk")) ||
           !strncmp(ext, ".c", strlen(".c")) ||
           !strncmp(ext, ".h", strlen(".h"))) {
            
            return getcontent_type_str(plain);

        } else if (!strncmp(ext, ".html", strlen(".html")) ||
            !strncmp(ext, ".htm", strlen(".htm"))) {
            
            return getcontent_type_str(html);

        } else if (!strncmp(ext, ".php", strlen(".php"))) {

            return getcontent_type_str(php);

        } else if (!strncmp(ext, ".py", strlen(".py"))){

            return getcontent_type_str(python);

        } else if (!strncmp(ext, ".jpeg", strlen(".jpeg")) || 
            !strncmp(ext, ".jpg", strlen(".jpg"))){

            return getcontent_type_str(jpeg);

        } else if (!strncmp(ext, ".gif", strlen(".gif"))){

            return getcontent_type_str(gif);

        } else if (!strncmp(ext, ".pdf", strlen(".pdf"))){

            return getcontent_type_str(pdf);

        } else {
            return getcontent_type_str(other);
        }
}

int main(){
    char* output_buffer=(char*)(malloc(5*sizeof(char)));
    execute_script("../test.py",output_buffer,5);
    
    parse_conf();
    
    //  // Read the request data from the client socket
    // int request_len = recv(client_sock, request, MAX_REQUEST_SIZE - 1, 0);
    // if (request_len < 0) {
    //     perror("recv failed");
    //     close(client_sock);
    //     return NULL;
    // }
    
    // request[request_len] = '\0'; // add terminate character

    char request[] = "POST ../test.py HTTP/1.1\nUser-Agent: My_web_browser\nContent-Type: txt/html\nHost: astarti.cs.ucy.ac.cy:30000\nConnection: keep-alive\n\nhtml data";
    char method[16];
    char uri[256];
    char http_version[16];
    char user_agent[256];
    char host[256];
    char connection[256];
    char content_type[16];
    char post_data[1024];
    
    // Parse the request
    // if (parse_result == -1) {
    //     printf("Invalid request\n");
    //     close(client_sock);
    //     return NULL;
    // }
    
}


