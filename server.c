#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <sys/stat.h>
#include <fcntl.h>


#define MAX_REQUEST_SIZE 1024 // maximum size of the HTTP request
#define URL_BUFSIZE 512
#define LINE_BUFSIZE 512
#define PATH_BUFSIZE ( URL_BUFSIZE + LINE_BUFSIZE ) // maximum size of the HTTP request
#define HTTP_VERSION "HTTP/1.1"

char* webroot="webroot/";
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

/* Prin functions for debugging */


void print_response_struct (RESPONSE* rspns);
void print_request_struct(REQUEST* reqst);

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

const char *getcontent_type_str(ContentType content_type);


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


char *get_status_msg(int status_code){
    switch(status_code){
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 307: return "Temporary Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Time-out";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Request Entity Too Large";
        case 414: return "Request-URI Too Large";
        case 415: return "Unsupported Media Type";
        case 416: return "Requested range not satisfiable";
        case 417: return "Expectation Failed";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Time-out";
        case 505: return "HTTP Version not supported";
        default: return NULL;
    }
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
        rspns->content_type=plain;
    } else if (strcmp(file_ext, "php") == 0) {
        interpreter_command = "php";
        rspns->content_type=html;
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
    rspns->body=output_buffer;
    rspns->content_length=strlen(rspns->body);
    // Close the pipe
    pclose(fp);

    return bytes_read;
}


void send_response(SSL *socket, RESPONSE *rspns){
    int bufsize = 1024;
    char buf[bufsize];
    printf("-------------------Response struct----------------\n");
    rspns->status_msg = NULL;
    print_response_struct (rspns);
    snprintf(buf, bufsize, "%s %d %s"
            "\r\nServer: UCY-HTTPS-SERVER"
            "\r\nContent-Length: %d"
            "\r\nConnection: %s"
            "\r\nContent-Type: %s\r\n\r\n"
            ,HTTP_VERSION, rspns->status_code, get_status_msg(rspns->status_code), rspns->content_length,  
            (rspns->keep_alive == 1)?"keep-alive":"closed", getcontent_type_str(rspns->content_type));

//    SSL_write(socket, buf, bufsize);
//    if(rspns-> body != NULL){
//        SSL_write(socket, rspns->body, rspns->content_length);
//    }

    printf("-------------------Send response----------------\n");
    write(1, buf,strlen(buf));

    printf("-----------Body----------\n");
    printf("%s\n", rspns->body);
    printf("----\n");
    write(1, rspns->body, strlen(rspns->body));
    //rspns->content_length);
    printf("------------------------------------------------\n");
}

void handle_request(SSL *socket, REQUEST *rqst, RESPONSE *rspns){
    printf("-------------------Request struct----------------\n");
    print_request_struct(rqst);
     switch(rqst->method){
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
     send_response(socket, rspns);
}

void handle_post(REQUEST *reqst,  RESPONSE *rspns ) {
    // Extract path from uri
    char* has_slash = strchr(reqst->uri, '/');
    if (has_slash == NULL) {
        rspns->status_code=400;
        rspns->body="Invalid URI";
        rspns->content_length=strlen("Invalid URI");
        rspns->content_type=plain;
        return;
    }
    

    /* Append webroot directory to uri */
    size_t path_len = strlen(webroot)+strlen(reqst->uri)+1;
    char path[path_len];
    snprintf(path, path_len, "%s%s", webroot, reqst->uri);


    // Create necessary folders if they do not exist
    char* folder_path = strdup(path);
    char* last_slash = strrchr(folder_path, '/');
    if (last_slash != NULL) {
        *last_slash = '\0';
        if (mkdir(folder_path, S_IRWXU) == -1 && errno != EEXIST) {
            rspns->status_code=500;
            rspns->body="Failed to create directory";
            rspns->content_length=strlen("Failed to create directory");
            rspns->content_type=plain;
            free(folder_path);
            return;
        }
    }
    free(folder_path);

    char* ext = get_file_extension(path);
    if (ext == NULL) {
        rspns->status_code=400;
        rspns->body="Invalid file extension";
        rspns->content_length=strlen("Invalid file extension");
        rspns->content_type=plain;
        return;
    }
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        rspns->status_code=500;
        rspns->body="Failed to save file";
        rspns->content_length=strlen("Failed to save file");
        rspns->content_type=plain;
        return;
    }
    fwrite(reqst->body, reqst->content_length, 1, fp);
    fclose(fp);

    // Send success response
    rspns->status_code=201;
    rspns->body="File saved successfully";
    rspns->content_length=strlen("File saved successfully");
    rspns->content_type=plain;
}


void handle_get(REQUEST *reqst,  RESPONSE *rspns ){
    // Open the requested file
    char* path = reqst->uri;
    if (strcmp(path, "/") == 0) {
        path = "/index.html";
    }
    size_t file_path_len = strlen(webroot)+strlen(path);
    char file_path[file_path_len];
    snprintf(file_path, file_path_len, "%s%s", webroot, path);
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        rspns->status_code=404;
        rspns->content_type=plain;
        return;
    }

    char* file_ext = get_file_extension(file_path);
    rspns->content_type=get_content_type(file_ext);
    // *** How we handle connection header? ***

    if(strcmp(file_ext, "py") == 0 || strcmp(file_ext, "php") == 0){
        execute_script(file_path,rspns);
        return;
    }

    rspns->status_code=200;
     
    // Determine the file's size
    fseek(file, 0, SEEK_END);
    rspns->content_length= ftell(file);
    fseek(file, 0, SEEK_SET);
  
    rspns->body = realloc(rspns->body, sizeof(char)*rspns->content_length);
    
    int byte_read = fread(rspns->body, 1, sizeof(char)*rspns->content_length, file);
    if(byte_read != rspns->content_length){
        fprintf(stderr,"something is wrong!\n");
    }


   // Close the file
    fclose(file);
}

int handle_head(REQUEST *rqst, RESPONSE *rspns){
 
    handle_get(rqst, rspns);
    
    if(rspns->body != NULL){
        free(rspns->body);
        rspns->body = NULL;
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

            char msg[] = " cannot be found on the server!";
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
    
    char msg[] = " deleted successfully!";
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
    do{
        token = strtok_r(rest, "\n", &rest);
        
        if (strncmp(token, "Connection: ", strlen("Connection: ")) == 0) {
            /* If connection is not keep_alive */
            if(strncmp(token + strlen("Connection: "), "keep-alive", strlen("keep-alive")) != 0){
                reqst->keep_alive = 0;
            }
        } else if (strncmp(token, "Content-Type: ", strlen("Content-Type: ")) == 0) {
            /* Get content type from string */
            reqst->content_type = getcontent_type_enum(token + strlen("Content-Type: "));
            printf("Getcontent_type_str: %s\n", getcontent_type_str(reqst->content_type));

        } else if (strncmp(token, "Content-Length: ", strlen("Content-Length: ")) == 0) {
            errno = 0;
            reqst->content_length = (int)strtol(token+strlen("Content-Length: "), NULL, 10);
            printf("token = %d\n",reqst->content_length);
            if(errno != 0){
                perror("Parsing content_length");
                return -1;
            }
        }

        if (!strcmp(token,"\r")) {
            break;
        }
        
    }while(token != NULL);

    // Extract the post data for POST requests
    if(reqst->method == POST){
        
        if(reqst->content_type == unknown_con_type ||
           rest == NULL){
            return -1;
        }
        reqst->body = (char *)malloc(sizeof(char)*reqst->content_length);
        memcpy(reqst->body, rest, reqst->content_length);
    }
    // printf("%d\n",reqst->method);
    // printf("%s\n",reqst->uri);
    // printf("%d\n",reqst->keep_alive);
    // printf("%s\n",getcontent_type_str(reqst->content_type));
    // printf("%d\n%s\n%d\n%s\n%d\n%s\n",reqst->method,reqst->uri,reqst->keep_alive,getcontent_type_str(reqst->content_type),reqst->content_length,reqst->body);
    
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

const char *getcontent_type_str(ContentType content_type){
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
       default:
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

void print_request_struct (REQUEST* reqst){
    printf("Method: %d\n"
           "URI: %s\n"
           "Connection: %d\n"
           "Content-Type: %s : %d\n"
           "Content-Length:%d\n"
           "Body:%s\n",
           reqst->method,reqst->uri,reqst->keep_alive,
           getcontent_type_str(reqst->content_type), reqst->content_type,reqst->content_length,reqst->body);
}
void print_response_struct (RESPONSE* rspns){
    printf("Status code: %d\n"
           "Status-Message: %s\n"
           "Connection: %d\n"
           "Content-Type: %s\n"
           "Content-Length:%d\n"
           "Body:%s\n",
           rspns->status_code, get_status_msg(rspns->status_code), rspns->keep_alive, 
           getcontent_type_str(rspns->content_type),rspns->content_length, rspns->body); 
}


int main(){

   REQUEST* reqst = (REQUEST *) malloc(sizeof(REQUEST));
    http_request_init(reqst);

    RESPONSE* rspns = (RESPONSE*) malloc(sizeof(RESPONSE));
    http_response_init(rspns);

    

    char post_request[] = "POST /test.txt HTTP/1.1"
                     "\r\nUser-Agent: My_web_browser"
                     "\r\nContent-Length: 28"
                     "\r\nContent-Type: text/plain"
                     "\r\nHost: astarti.cs.ucy.ac.cy:30000"
                     "\r\nConnection: keep-alive"
                     "\r\n"
                     "\r\nThis is a test for HTTP POST";


    char get_request[] = "GET / HTTP/1.1" //Tested works
                      "\r\nUser-Agent: My_web_browser"
                      "\r\nHost: astarti.cs.ucy.ac.cy:30000"
                      "\r\nConnection: keep-alive"
                      "\r\n";
    char get_request_script[] = "GET /test.py HTTP/1.1" //Tested works
                      "\r\nUser-Agent: My_web_browser"
                      "\r\nHost: astarti.cs.ucy.ac.cy:30000"
                      "\r\nConnection: keep-alive"
                      "\r\n";

    char head_request[] = "HEAD / HTTP/1.1" //Tested Works 
                      "\r\nUser-Agent: My_web_browser"
                      "\r\nHost: astarti.cs.ucy.ac.cy:30000"
                      "\r\nConnection: keep-alive"
                      "\r\n";
    char delete_request[] = "DELETE /delete.tmp HTTP/1.1"
                      "\r\nUser-Agent: My_web_browser"
                      "\r\nHost: astarti.cs.ucy.ac.cy:30000"
                      "\r\nConnection: keep-alive"
                      "\r\n";

    parse_request(post_request,reqst);
    handle_request(NULL, reqst, rspns);

//    printf("%s\n", getcontent_type_str(1));
       
}


