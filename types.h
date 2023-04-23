#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MAX_REQUEST_SIZE 1024 // maximum size of the HTTP request
#define URL_BUFSIZE 512
#define LINE_BUFSIZE 512
#define PATH_BUFSIZE ( URL_BUFSIZE + LINE_BUFSIZE ) // maximum size of the HTTP request
#define HTTP_VERSION "HTTP/1.1"
#define SERVER_NAME "UCY-HTTPS"


typedef enum {unknown_method, GET, POST, DELETE, HEAD} Method;
typedef enum {unknown_con_type, plain, html, css, php, python, jpeg, gif, pdf, other}ContentType;

typedef struct{
	struct Node *head;
	struct Node *tail;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	SSL_CTX *ctx;
}REQUESTS;

typedef struct Node{
	struct Node *next;
	int socket;
}NODE;

typedef struct{
    char *home;
    char *cert;
    char *key;
    int threads;
    int port;
}HTTPS_Config;

typedef struct{
    REQUESTS *req;
    HTTPS_Config *conf;
    int socket;

}HTTPS_Server;

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

#endif
