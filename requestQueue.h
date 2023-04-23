//#include "types.h"

int requests_empty(REQUESTS *q);

int requests_init(REQUESTS **q, SSL_CTX *ctx);

int requests_add(REQUESTS *q, int client_soc);

void requests_get(REQUESTS *q, int *socket);

void requests_cleanup(REQUESTS *q);
