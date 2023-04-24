#include "types.h"

int https_request_init(REQUEST** rqst);

int https_response_init(RESPONSE** rspns);

int ssl_dyn_read(SSL *ssl, char **buf, int *buf_len);

Method get_method_enum(char *buf);

ContentType get_content_type_enum(char *buf);

const char *get_content_type_str(ContentType content_type);

ContentType get_content_type(char *ext);

char *get_status_msg(int status_code);

void print_request_struct (REQUEST* reqst);

void print_response_struct (RESPONSE* rspns);

void send_response_msg(SSL *socket, int client, int status_code, char *body);

void send_response(SSL *socket, RESPONSE *rspns);

int parse_request(SSL *socket, char *request, REQUEST *reqst );    

int execute_script(SSL *socket, char* file_path,RESPONSE* rspns);

void handle_request(SSL *socket, REQUEST *rqst, RESPONSE *rspns, char *webroot);

int handle_post(SSL *socket, REQUEST *reqst,  RESPONSE *rspns, char *webroot);

int handle_get(SSL *socket, REQUEST *reqst,  RESPONSE *rspns, char *webroot);

int handle_head(SSL *socket, REQUEST *rqst, RESPONSE *rspns, char *webroot);

int handle_delete(SSL *socket, REQUEST *rqst, RESPONSE *rspns, char *webroot);

char * get_method_str(Method method);

int https_request_init(REQUEST** rqst){
    *rqst = (REQUEST *) malloc(sizeof(REQUEST));
    if ((*rqst) == NULL){
        return -1;
    }
    (*rqst)->uri = (char *)malloc(sizeof(char)*URL_BUFSIZE);
    if((*rqst)->uri == NULL){
        return -1;   
    }
    (*rqst)->method = unknown_method;
    (*rqst)->content_type = unknown_con_type;
    (*rqst)->keep_alive = 1;

    return 0;
}


int https_response_init(RESPONSE** rspns){
    *rspns = (RESPONSE*) malloc(sizeof(RESPONSE));
    if ( *(rspns) == NULL){
        return 1;
    }
    (*rspns)->content_type = unknown_con_type;
}


int ssl_dyn_read(SSL *ssl, char **buf, int *buf_len) {
    int read_len = 0, total_len = 0;
    char *new_buf;
    do {
        // Increase buffer size by 1024 bytes
        *buf_len += 1024;
        new_buf = realloc(*buf, *buf_len);
        if (!new_buf) {
            #ifndef debugHandleMessages
            log_err_no(errno, "ssl_dyn_read realloc");
            #endif
            return -1;
        }
        *buf = new_buf;
        // Read up to 1024 bytes from the SSL connection
        read_len = SSL_read(ssl, *buf + total_len, 1024);
        if (read_len <= 0) {
            #ifndef debugHandleMessages
            log_err_no(errno,"ssl_dyn_read: SSL_read failed");
            #endif
            return -2;
        }
        total_len += read_len;
    } while (read_len == 1024); // Continue reading if we read a full 1024 bytes
    return total_len;
}

Method get_method_enum(char *buf){
    if(!strncmp("GET", buf, strlen("GET"))) return GET;
    else if(!strncmp("POST", buf, strlen("POST"))) return POST;
    else if(!strncmp("DELETE", buf, strlen("DELETE"))) return DELETE;
    else if(!strncmp("HEAD", buf, strlen("HEAD"))) return HEAD;
    
    return unknown_method;
}

char * get_method_str(Method method){
    if(method == GET) return "GET";
    else if(method == POST) return "POST";
    else if(method == DELETE) return "DELETE";
    else if(method == HEAD) return "HEAD";
    
    return "UNKOWN METHOD";
}


ContentType get_content_type_enum(char *buf){
    if(!strncmp("text/html", buf, strlen("text/html"))) return html;
    if(!strncmp("text/css", buf, strlen("text/css"))) return css;
    else if(!strncmp("text/x-php", buf, strlen("text/x-php"))) return php;
    else if(!strncmp("text/plain", buf, strlen("text/plain"))) return plain;
    else if(!strncmp("image/jpeg", buf, strlen("image/jpeg"))) return jpeg;
    else if(!strncmp("application/x-python-code", buf, strlen("application/x-python-code"))) return python;
    else if(!strncmp("image/gif", buf, strlen("image/gif"))) return gif;
    else if(!strncmp("application/pdf", buf, strlen("application/pdf"))) return pdf;
    return other;
}

const char *get_content_type_str(ContentType content_type){
    switch(content_type){
        case html:
            return "text/html";
        case css:
            return "text/css";
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
        if(!strcmp(ext, ".txt") ||
           !strcmp(ext, ".sed") ||
           !strcmp(ext, ".awk") ||
           !strcmp(ext, ".c") ||
           !strcmp(ext, ".h")) {
            
            return plain;

        } else if (!strcmp(ext, ".html") ||
            !strcmp(ext, ".htm")) {
            
            return html;

        } else if (!strcmp(ext, ".php")) {

            return php;

        } else if (!strcmp(ext, ".py")){

            return python;

        } else if (!strcmp(ext, ".jpeg") || 
            !strcmp(ext, ".jpg")){

            return jpeg;

        } else if (!strcmp(ext, ".gif")){

            return gif;

        } else if (!strcmp(ext, ".pdf")){

            return pdf;

        } else if (!strcmp(ext, ".css")){

            return css;

        } else {
            return other;
        }
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
        case 525: return "TLS/SSL handshake failed";
        default: return NULL;
    }
}

char* get_file_extension(char* uri) {
    char* ext = strrchr(uri, '.');
    if (ext == NULL || ext == uri) {
        return ""; // No extension found
    }
    return ext;
}

void print_request_struct (REQUEST* reqst){
    printf("Method: %s\n"
           "URI: %s\n"
           "Connection: %s\n"
           "Content-Type: %s\n"
           "Content-Length:%d\n"
           "Body:%s\n",
           get_method_str(reqst->method),reqst->uri,(reqst->keep_alive == 1)?"keep-alive":"closed",
           get_content_type_str(reqst->content_type),reqst->content_length,reqst->body);
}

int is_str_space(char * str){
    char *tmp = str;
    while(*tmp !='\0'){
        if(!isspace(*tmp))
            return 0;
        tmp++;
    }
    return 0;
}

void print_response_struct (RESPONSE* rspns){
    printf("Status code: %d\n"
           "Status-Message: %s\n"
           /"Connection: %s\n"
           "Content-Type: %s\n"
           "Content-Length:%d\n"
           "Body:%s\n",
           rspns->status_code, get_status_msg(rspns->status_code), (rspns->keep_alive == 1)?"keep-alive":"closed", 
           get_content_type_str(rspns->content_type),rspns->content_length, rspns->body); 

}
void send_response_msg(SSL *socket, int client, int status_code, char *body){
    int bufsize = 2048;
    char buf[bufsize];
    int bodylen = strlen(body);


    snprintf(buf, bufsize, "%s %d %s"
            "\r\nServer: %s"
            "\r\nContent-Length: %d"
            "\r\nConnection: %s"
            "\r\nContent-Type: %s\r\n\r\n",
            HTTP_VERSION, status_code, get_status_msg(status_code),SERVER_NAME,
            bodylen,  "closed", 
            get_content_type_str(plain));

    #ifndef debugHandleMessages
    if(socket != NULL){
        SSL_write(socket, buf, strlen(buf));
        if(body != NULL){
            SSL_write(socket, body, bodylen);
        }
    } else {
        write(client, buf, strlen(buf));
        if(body !=NULL){
            write(client, body, bodylen);
        }
    }
    snprintf(buf, bufsize,"RESPONSE: %d %s", 
            status_code, get_status_msg(status_code));
    log_msg(buf);
    #else
    printf("-------------------Response struct----------------\n");
         write(1, buf, strlen(buf));
        if(body !=NULL){
            write(1, body, bodylen);
        }
    #endif

}
void send_response(SSL *socket, RESPONSE *rspns){
    int bufsize = 2048;
    char buf[bufsize];

    #ifdef debugHandleMessages
    printf("-------------------Response struct----------------\n");
    rspns->status_msg = NULL;
    print_response_struct (rspns);
    #endif

    snprintf(buf, bufsize, "%s %d %s"
            "\r\nServer: %s"
            "\r\nContent-Length: %d"
            "\r\nConnection: %s"
            "\r\nContent-Type: %s\r\n\r\n",
            HTTP_VERSION, rspns->status_code, get_status_msg(rspns->status_code),SERVER_NAME,
            rspns->content_length,  (rspns->keep_alive == 1)?"keep-alive":"closed", 
            get_content_type_str(rspns->content_type));
 
    #ifndef debugHandleMessages
    SSL_write(socket, buf, strlen(buf));
    if(rspns-> body != NULL){
        SSL_write(socket, rspns->body, rspns->content_length);

    }
    snprintf(buf, bufsize, "RESPONSE: %d %s", 
            rspns->status_code, get_status_msg(rspns->status_code));
    log_msg(buf);
    #endif

}


int parse_request(SSL *socket,char *request, REQUEST *reqst ){    

    char *rest = strdup(request);
    int i = 0;
     
    // Extract the method
    char *token = strtok_r(rest, " ", &rest);
   

    if (token == NULL) {
        
        send_response_msg(socket,0, 400, "Not in the currect format");
        return -1; // invalid request
    }

    /* Get method */
    reqst->method = get_method_enum(token);
    
    if(reqst->method == unknown_method){
        send_response_msg(socket,0, 501, "This method is not supported by the server");
        return -1;
    }
    

    /* Extract the URI */
    token = strtok_r(rest, " ", &rest);
    
    if (token == NULL) {
        send_response_msg(socket,0, 400, "Not in the currect format");
        return -1; // invalid request
    }

    if(strlen(token)+1 > URL_BUFSIZE){
        send_response_msg(socket,0, 414, "URI too large for the server");
        return -1;
    }
    memcpy(reqst->uri, token, strlen(token)+1); // copy the URI string
    

    // Extract the HTTP version
    token = strtok_r(rest, "\r\n", &rest);

    if (token == NULL) {
        send_response_msg(socket,0, 400, "Not in the currect format");
        return -1; // invalid request
    }
    // Check that the HTTP version is valid
    if (strncmp(token, "HTTP/1.1", strlen("HTTP/1.1"))) {
        
        send_response_msg(socket,0, 505, "Unsupported HTTP version");
        return -1; // invalid request
    }

    token = strtok_r(rest, "\n", &rest);
    // Extract the User-Agent header
    while(token != NULL){
       
        if (strncmp(token, "Connection: ", strlen("Connection: ")) == 0) {
            /* If connection is not keep_alive */
            if(strncmp(token + strlen("Connection: "), "keep-alive", strlen("keep-alive")) != 0){
                reqst->keep_alive = 0;
            }
        } else if (strncmp(token, "Content-Type: ", strlen("Content-Type: ")) == 0) {
            /* Get content type from string */
            reqst->content_type = get_content_type_enum(token + strlen("Content-Type: "));
            printf("Getcontent_type_str: %s\n", get_content_type_str(reqst->content_type));

        } else if (strncmp(token, "Content-Length: ", strlen("Content-Length: ")) == 0) {
            errno = 0;
            char *tmp;
            reqst->content_length = (int)strtol(token+strlen("Content-Length: "), &tmp, 10);
            //if(strcmp(tmp,"\0") && strcmp(tmp," ")){
            if(is_str_space(tmp)){
                printf("tmp: %s\n",tmp);
                send_response_msg(socket,0, 400, "Not in the currect format");
                return -1;
            }
            if(errno != 0){
                 
                send_response_msg(socket,0, 500, "Parsing content length");
                #ifndef debugHandleMessages
                log_err_no(errno,"HEADER parsing content length");
                #endif
                return -1;
            }
        }

        if (!strcmp(token,"\r")) {
            break;
        }
        token = strtok_r(rest, "\n", &rest);
    }

    // Extract the post data for POST requests
    if(reqst->method == POST){
        
        if(reqst->content_type == unknown_con_type ||
           rest == NULL){
           send_response_msg(socket,0, 415, "Media type is not support");
           return -1;
        }
        reqst->body = (char *)realloc(reqst->body ,sizeof(char)*reqst->content_length);
        memcpy(reqst->body, rest, reqst->content_length);
    }
    return 0;
}

/* Function to execute a script and capture output */
int execute_script(SSL *socket, char* file_path,RESPONSE* rspns) {
    int output_size=1024;
    char* output_buffer=(char*)(malloc(output_size*sizeof(char)));
    FILE *fp;
    int bytes_read = 0;
    char command[PATH_BUFSIZE];

    // Determine the file extension
    char* file_ext = get_file_extension(file_path);

    // Determine the interpreter command
    char* interpreter_command;
    if (strcmp(file_ext, ".py") == 0) {
        interpreter_command = "python3";
        rspns->content_type=plain;
    } else if (strcmp(file_ext, ".php") == 0) {
        interpreter_command = "php";
        rspns->content_type=html;
    }

    // Construct the command to execute the script
    snprintf(command, PATH_BUFSIZE, "%s %s", interpreter_command, file_path);

    // Open a pipe to the script interpreter
    fp = popen(command, "r");
    if (fp == NULL) {
        #ifndef debugHandleMessages
        log_err_no(errno,"GET script execution");
        #endif
        send_response_msg(socket, 0, 500, "Failed to execute script");       
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
                #ifndef debugHandleMessages
                log_err_no(errno,"GET script execution");
                #endif
                send_response_msg(socket, 0, 500, "Failed to allocate memory");       
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

void handle_request(SSL *socket, REQUEST *rqst, RESPONSE *rspns, char *webroot){
    #ifdef debugHandleMessages 
    printf("-------------------Request struct----------------\n");
    print_request_struct(rqst);
    #else
    char buf[1024];
    sprintf(buf, "REQUEST: %s %s", get_method_str(rqst->method),rqst->uri);
    log_msg(buf);
    #endif
    int ret = 1;
    rspns->keep_alive=rqst->keep_alive;
    switch(rqst->method){
        case GET:
            ret = handle_get(socket, rqst, rspns, webroot);
            break;
        case POST:
            ret = handle_post(socket, rqst, rspns, webroot);
            break;
        case DELETE:
            ret = handle_delete(socket, rqst, rspns, webroot);
            break;
        case HEAD:
            ret = handle_head(socket, rqst, rspns, webroot);
            break;
    }
     if(ret != -1)
        send_response(socket, rspns);
}

int handle_post(SSL *socket, REQUEST *reqst,  RESPONSE *rspns, char *webroot) {
    // Extract path from uri
    char* has_slash = strchr(reqst->uri, '/');
    if (has_slash == NULL) {
        send_response_msg(socket, 0, 400, "Invalid URI");
        return -1;
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
            #ifndef debugHandleMessages
            log_err_no(errno, "POST mkdir");
            #endif
            send_response_msg(socket, 0, 500, "Failed to create directory");       
            return -1;
        }
    }
    free(folder_path);

    char* ext = get_file_extension(path);
    if (ext == NULL) {
        send_response_msg(socket, 0, 400, "Invalid file extention");       
        return -1;
    }
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        #ifndef debugHandleMessages
        log_err_no(errno, "POST fopen");
        #endif
        send_response_msg(socket, 0, 500, "Failed to save file");       
        return -1;
    }
    fwrite(reqst->body, reqst->content_length, 1, fp);
    fclose(fp);

    // Send success response
    char msg[] = "File saved successfully!";
    rspns->content_length = strlen(msg)+strlen(path)+1;
    rspns->body = (char *)realloc(rspns->body, sizeof(char)*rspns->content_length);
    if(rspns->body == NULL){
        #ifndef debugHandleMessages
        log_err_no(errno, "POST realloc");
        #endif
        send_response_msg(socket, 0, 500, "Failed to allocate memory");
        return -1;
    }
    snprintf(rspns->body, rspns->content_length, "%s%s", path, msg);
    rspns->status_code=201;
    rspns->content_type=plain;
    return 0;
}


int handle_get(SSL *socket, REQUEST *reqst,  RESPONSE *rspns, char *webroot){
    // Open the requested file
    char* path = reqst->uri;
    if (strcmp(path, "/") == 0) {
        path = "/index.html";
    }
    size_t file_path_len = strlen(webroot)+strlen(path)+1;
    char file_path[file_path_len];
    snprintf(file_path, file_path_len, "%s%s", webroot, path);

    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        send_response_msg(socket, 0, 404, "Page not found!\n");
        return -1;
    }
    char* file_ext = get_file_extension(file_path);
    if (file_ext == NULL) {
        send_response_msg(socket, 0, 400, "Invalid file extention");       
        return -1;
    }
    rspns->content_type=get_content_type(file_ext);
    // *** How we handle connection header? ***

    if(strcmp(file_ext, ".py") == 0 || strcmp(file_ext, ".php") == 0){
        return execute_script(socket, file_path,rspns);
    }

    rspns->status_code=200;
     
    // Determine the file's size
    fseek(file, 0, SEEK_END);
    rspns->content_length= ftell(file);
    fseek(file, 0, SEEK_SET);
  
    rspns->body = realloc(rspns->body, sizeof(char)*rspns->content_length);
    if(rspns->body == NULL){
        char buf[100];
        sprintf(buf,"%s realloc",get_method_str(reqst->method));
        #ifndef debugHandleMessages
        log_err_no(errno, buf);
        #endif
        send_response_msg(socket, 0, 500, "Failed to allocate memory");
        return -1;
    }
    
    int byte_read = fread(rspns->body, 1, sizeof(char)*rspns->content_length, file);
    if(byte_read != rspns->content_length){
        char buf[100];
        sprintf(buf,"%s fread: bytes read not equal content length",get_method_str(reqst->method));
        #ifndef debugHandleMessages
        log_err(buf);
        #endif
        send_response_msg(socket, 0, 500, "Failed to read file");
        return -1;
    }


   // Close the file
    fclose(file);
    return 0;
}

int handle_head(SSL *socket, REQUEST *rqst, RESPONSE *rspns, char *webroot){
 
    handle_get(socket, rqst, rspns, webroot);
    
    if(rspns->body != NULL){
        free(rspns->body);
        rspns->body = NULL;
    }
}

int handle_delete(SSL *socket, REQUEST *rqst, RESPONSE *rspns, char *webroot){
    char *uri = rqst->uri;
    char path[PATH_BUFSIZE];
    if (strcmp(uri, "/") == 0) {
        uri = "/index.html";
    }
    snprintf(path, PATH_BUFSIZE, "%s%s", webroot, uri);

    if(remove(path)){
        

        if(errno == ENOENT ){
            send_response_msg(socket, 0, 404, "Failed cannot be found");

        } else{
            send_response_msg(socket, 0, 400, strerror(errno));
        }
        return -1;
    }

    rspns->status_code = 200;
    
    char msg[] = " deleted successfully!";
    rspns->content_length = strlen(msg)+strlen(uri);
    
    rspns->body = realloc(rspns->body, sizeof(char)*(rspns->content_length));
    if(rspns->body == NULL){
        #ifndef debugHandleMessages
        log_err_no(errno, "DELETE realloc");
        #endif
        send_response_msg(socket, 0, 500, "Failed to allocate memory");
        return -1;
    }
    snprintf(rspns->body, rspns->content_length, "%s%s", uri, msg);
    rspns->content_type = plain;
    rspns->keep_alive = rqst->keep_alive;
    return 0;    
}


#ifdef debugHandleMessages
void print_menu() {
    printf("===== MENU =====\n");
    printf("1. Test POST Request\n");
    printf("2. Test GET Request\n");
    printf("3. Test GET Request for python or php script\n");
    printf("4. Test HEAD Request\n");
    printf("5. Test DELETE Request\n");
    printf("6. Exit\n");
}

int main(){
    char post_request[] = "POST /test.txt HTTP/1.1"
                     "\r\nUser-Agent: My_web_browser"
                     "\r\nContent-Length: 28"
                     "\r\nContent-Type: text/plain"
                     "\r\nHost: astarti.cs.ucy.ac.cy:30000"
                     "\r\nConnection: close"
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

    
    int choice = 0;
    REQUEST *reqst;
    RESPONSE *rspns;
    https_request_init(&reqst);
    https_response_init(&rspns);
    do {
        print_menu();
        printf("Enter your choice: ");
        scanf("%d", &choice);
        switch (choice) {
            case 1:
                parse_request(NULL,post_request,reqst);
               printf("okay\n");
                handle_request(NULL, reqst, rspns, "webroot");
                break;
            case 2:
                parse_request(NULL, get_request,reqst);
                printf("okay\n");
                handle_request(NULL, reqst, rspns, "webroot");
                break;
            case 3:
                parse_request(NULL, get_request_script,reqst);
                printf("okay\n");
                handle_request(NULL, reqst, rspns, "webroot");
                break;
            case 4:
                parse_request(NULL, head_request,reqst);
                printf("okay\n");
                handle_request(NULL, reqst, rspns, "webroot");
                break;
            case 5:
                parse_request(NULL, delete_request,reqst);
                printf("okay\n");
                handle_request(NULL, reqst, rspns, "webroot");
                break;
            case 6:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    reqst->content_length=0;
    reqst->content_type=unknown_con_type;
    free(reqst->body);
    reqst->body=NULL;
    } while (choice != 6);
}
#endif


