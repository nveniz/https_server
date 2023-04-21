#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#define MAX_REQUEST_SIZE 1024 // maximum size of the HTTP request
#define URL_BUFSIZE 256
#define PATH_MAX 512 // maximum size of the HTTP request

#define HTTP_VERSION "HTTP/1.1"


typedef enum method {unknown, GET, POST, DELETE, HEAD} Method;
typedef enum content_type{unknown, plain, html, php, python, jpeg, gif, pdf}ContentType;

typdef struct http_request{
    enum method = unknown;
    char *uri;
    int keep-alive=1;
    enum content_type = unknown;
    int content_length;
    char *body;
}REQUEST;

typdef struct http_response{
    enum method = unknown;
    int status_code;
    char *status_msg;
    enum content_type;
    int content_length;
    char *body;

}RESPONSE;

/* Function to handle incoming clients */   //INCOMPLETE
void handle_client(QUEUE q);

/* Function to handle incoming requests */  //TO-DO
void handle_request(int client_sock, REQUEST *rqst);

/* Function to send HTTP response */        //DONE
void send_response(int client_sock, RESPONSE *rspns);

/* Function to execute a script and capture output */
int execute_script(char* script_name, char* script_args, char* output_buffer, int output_size);

/* Function to extract the file extension from a URI */     //DONE_WORKING
char* get_file_extension(char* uri);

/* Function to generate an appropriate content type based on file extension */
char* get_content_type(char* file_ext);

/* Function to handle HTTP GET requests */
void handle_get(REQUEST *reqst,  RESPONSE *rspns );

/* Function to handle HTTP POST requests */
void handle_post(REQUEST *reqst,  RESPONSE *rspns );

/* Function to handle HTTP HEAD requests */
void handle_head(REQUEST *reqst,  RESPONSE *rspns );

/* Function to handle HTTP DELETE requests */
void handle_delete(REQUEST *reqst,  RESPONSE *rspns );

/* Function to parse the client's request*/     //DONE
int parse_request(char *request, REQUEST *rqst);



char* get_file_extension(char* uri) {
    char* ext = strrchr(uri, '.');
    if (ext == NULL || ext == uri) {
        return ""; // No extension found
    }
    return ext + 1;
}

/* Function to execute a script and capture output */
int execute_script(char* script_name, char* script_args, char* output_buffer, int output_size) {
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
    if (script_args == NULL) {
        snprintf(command, PATH_MAX, "%s %s", interpreter_command, script_name);
    } else {
        snprintf(command, PATH_MAX, "%s %s %s", interpreter_command, script_name, script_args);
    }

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


void send_response(int client_sock, RESPONSE *rspns){
    char response_headers[MAX_REQUEST_SIZE];
    snprintf(response_headers, MAX_REQUEST_SIZE, "%s %s %s\nContent-Type: %s\nContent-Length: %d\nConnection: %s\n\n", http_version, status_code, status_msg, content_type, content_length, connection);
    int headers_len = strlen(response_headers);

    // Send headers
    if (send(client_sock, response_headers, headers_len, 0) < 0) {
        perror("Error sending response headers");
        return;
    }

    // Send content
    if (content_length > 0 && send(client_sock, content, content_length, 0) < 0) {
        perror("Error sending response body");
        return;
    }
}


void send_response_headers(int client_sock, char* response_headers) {
    // Send the response headers to the client
    int bytes_sent = 0;
    int total_bytes_sent = 0;
    int response_length = strlen(response_headers);

    while (total_bytes_sent < response_length) {
        bytes_sent = send(client_sock, response_headers + total_bytes_sent, response_length - total_bytes_sent, 0);

        if (bytes_sent == -1) {
            perror("Error sending response headers");
            break;
        }

        total_bytes_sent += bytes_sent;
    }
}

void send_response_body(int client_sock, char* buffer, int bytes_read) {
    int bytes_sent = 0;
    while (bytes_sent < bytes_read) {
        int result = send(client_sock, buffer + bytes_sent, bytes_read - bytes_sent, 0);
        if (result == -1) {
            perror("send");
            break;
        }
        bytes_sent += result;
    }
}

void send_error_response(int client_sock, int status_code, char *message) {
    char response[1024];
    sprintf(response, "HTTP/1.1 %d %s\r\nContent-Length: %ld\r\n\r\n%s",
            status_code, message, strlen(message), message);
    send(client_sock, response, strlen(response), 0);
}


void handle_request(SSL socket, REQUEST *rqst){
    switch(reqst->method){
        case GET:
            handle_get(rqst, rspns);
            break;
        case POST:
            handle_post(rqst, rspns);
            break;
        case DELETE:
            handle_delete(rqst, rspns);
            break;
        case HEAD:
            handle_head(rqst, rspns);
            break;
    }
    send_response(SSL socket, rspns);
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
int parse_request(char *request, REQEUST *reqst ){

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
    reqst->method = getmethod(token);
    if(reqst->method == unknown){
        return -1;
    }

    /* Extract the URI */
    token = strtok_r(rest, " ", &rest);
    if (token == NULL) {
        return -1; // invalid request
    }

    memcpy(uri, token, strlen(token)+1); // copy the URI string

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
        if (token == '\r') {
            break; // no more headers
        }
        if (strncmp(token, "Connection: ", strlen("Connection: ")) == 0) {
            /* If connection is not keep-alive */
            if(strncmp(token + strlen("Connection: "), "keep-alive", strlen("keep-alive"))){
                reqst->keep-alive = 0;
            }
        } else if (strncmp(token, "Content-Type: ", strlen("Content-Type: ")) == 0) {
            /* Get content type from string */
            reqst->content-type = getcontent-type_enum(token + strlen("Content-Type: "));

        } else if (strncmp(token, "Content-Length: ", strlen("Content-Length: ")) == 0) {
            erro = 0;
            reqst->content_length = strtol(token+strlen("Content-Length: "), NULL, 2);
            if(erro != 0){
                perror("Parsing content-length");
                return -1;
            }
        }
    }
    // Extract the post data for POST requests
    if(reqst->method == POST){
        if(reqst->content_type == unknown ){
            return -1;
        }
        reqst->body = (char *)malloc(sizeof(char)*reqst->content_length);
        
        char *body = strstr(request, "\r\n\r\n");
        memcpy(reqst->body, body, reqst->content_length);
    }

    free(request_copy); 
    return 0;
}



int http_request_init(REQUEST **reqst){
    *reqst = (REQUEST *) malloc(sizeof(REQUEST));
    if ( reqst == NULL){
        return 1;
    }
    reqst->uri = (char *)malloc(sizeof(char)*URL_BUFSIZE);
    if(reqst->uri == NULL){
        return 1;   
    }
    return 0;

}

int http_response_init(RESPONSE **rspns){
    *rspns = (RESPONSE*) malloc(sizeof(RESPONSE));
    if ( rspns == NULL){
        return 1;
    }
}

Method getmethod_enum(char *buf){
    if(!strncmp("GET", buf, strlen("GET")) return GET;
    else if(!strncmp("POST", buf, strlen("POST")) return POST;
    else if(!strncmp("DELETE", buf, strlen("DELETE")) return DELETE;
    else if(!strncmp("HEAD", buf, strlen("HEAD")) return HEAD;
    
    return unknown;
}

ContentType getcontent-type_enum(char *buf){
    if(!strncmp("text/html", buf, strlen("text/html")) return html;
    else if(!strncmp("text/x-php", buf, strlen("text/x-php")) return php;
    else if(!strncmp("text/plain", buf, strlen("text/plain")) return plain;
    else if(!strncmp("image/jpeg", buf, strlen("image/jpeg")) return jpeg;
    else if(!strncmp("application/x-python-code", buf, strlen("application/x-python-code")) return python;
    else if(!strncmp("image/gif", buf, strlen("image/gif")) return gif;
    else if(!strncmp("application/pdf", buf, strlen("application/pdf")) return pdf;
    return other;
}
int main(){
    char* output_buffer=(char*)(malloc(5*sizeof(char)));
    execute_script("../test.py",NULL,output_buffer,5);
    
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
    int parse_result = parse_request(request, method, uri, http_version, user_agent, host, connection,content_type,post_data);
    // if (parse_result == -1) {
    //     printf("Invalid request\n");
    //     close(client_sock);
    //     return NULL;
    // }
    
    handle_request(1,method,uri,http_version,user_agent, host, connection,content_type,post_data);
    printf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",method,uri,http_version,user_agent,host,connection,content_type,post_data);
}


