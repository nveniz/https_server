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

#include "handleMessages.h"
#include "requestQueue.h"


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
    int socket;

}HTTPS_Server;

HTTPS_Server *https_server_init(HTTPS_Config *conf);

void https_server_cleanup(HTTPS_Server *server);

HTTPS_Config *https_config_read(char *configname);

int https_server(HTTPS_Server *server);

void https_server_thread(HTTPS_Server *server);
