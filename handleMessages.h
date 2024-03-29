//#include "types.h"


int ssl_dyn_read(SSL *ssl, char **buf, int *buf_len);

int https_request_init(REQUEST** rqst);

int https_response_init(RESPONSE** rspns);

int parse_request(SSL *socket, char *request, REQUEST *rqst);

void handle_request(SSL *socket, REQUEST *rqst, RESPONSE *rspns, char *webroot);

void handle_get(SSL *socket, REQUEST *reqst,  RESPONSE *rspns, char *webroot);

void handle_post(SSL *socket, REQUEST *reqst,  RESPONSE *rspns, char *webroot);

int handle_head(SSL *socket, REQUEST *reqst,  RESPONSE *rspns, char *webroot);

int handle_delete(SSL *socket, REQUEST *reqst,  RESPONSE *rspns, char *webroot);

void send_response_msg(SSL *socket, int client, int status_code, char *body);

void send_response(SSL *socket, RESPONSE *rspns);

void print_response_struct (RESPONSE* rspns);

void print_request_struct(REQUEST* reqst);

