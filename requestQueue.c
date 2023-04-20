#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>



/*----------Test case -------------
 * This queue has been tested using
 * the main function then can be seen
 * at below
 *
 * Output:
 *
 * 0 -> 1 -> 2 -> 3 -> 4 -> NULL
 * Popped queue: 0
 * Popped queue: 1
 * 2 -> 3 -> 4 -> 6 -> 7 -> NULL
 * Popped queue: 2
 * Popped queue: 3
 * Popped queue: 4
 * Popped queue: 6
 * 7 -> NULL
 * 7 -> 7 -> 7 -> NULL
 *
 * The queue works as expected
 * the thread sychronization part
 * has not been tested yet
 *
 */



typedef struct{
	struct Node *head;
	struct Node *tail;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	SSL_CTX *ctx;
}QUEUE;

typedef struct Node{
	struct Node *next;
	int socket;
}NODE;


int requests_empty(QUEUE *q){
	return (q->head == NULL && q->tail == NULL)?1:0;
}


int queue_init(QUEUE **q, SSL_CTX *ctx){
	*q = (QUEUE*)malloc(sizeof(QUEUE));
	if(*q == NULL){
		return 1;
	}
	(*q)->head = NULL;
	(*q)->tail = NULL;
	if(pthread_mutex_init(&(*q)->mtx, NULL) != 0){
		return 1;
	}
	if(pthread_cond_init(&(*q)->cond,NULL) != 0){
		return 1;
	}
	(*q)->ctx = ctx;
	return 0;
}

int queue_add(QUEUE *q, int client_soc){
	/* Locking queue for concarency */
	pthread_mutex_lock(&q->mtx);

	/* Adding element to queue */
	NODE *new =(NODE*)malloc(sizeof(NODE));
	if(new == NULL){
		return 1;
	}
	new->next = NULL;
	new->socket = client_soc;

	if(queue_empty(q)){
		q->head = new;
		q->tail = new;
	}else {
		q->tail->next = new;
		q->tail = new;
	}
	
	/* Unlocking queue */
	pthread_mutex_unlock(&q->mtx);
	
	/* Signal waiting threads. */
	pthread_cond_signal(&q->cond);
	return 0;
}

void queue_get(QUEUE *q, int *socket){
	pthread_mutex_lock(&q->mtx);

    	/* Wait for element to become available. */
    	while (queue_empty(q))
        	pthread_cond_wait(&q->cond, &q->mtx);

    	/* We have an element. Pop it normally and return it in socket. */
	NODE *tmp = q->head;
	if (q->head == q->tail) {
		q->head = NULL;
		q->tail = NULL;
	} else {
		q->head = tmp->next;
	}
	*socket = tmp->socket;

	free(tmp);

	pthread_mutex_unlock(&q->mtx);
}

void queue_print(QUEUE *q){
	NODE *tmp = q->head;
	while(tmp != NULL){
		printf("%d -> ",tmp->socket);
		tmp = tmp->next;
	}
	printf("NULL\n");
}



int thread_serve( QUEUE *q ){

	int client;
	SSL *ssl;
	/* Buf size is 8K */
	int buf_size = 8192;
	char *buf[buf_size];
	
	while(1){

		queue_get(q, &client);

		/* Creating the TLS handshake with the client fd and SSL_CTX */

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		
		/* wait for a TLS/SSL client to initiate a TLS/SSL handshake */
		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		}
		/* if TLS/SSL handshake was successfully completed, a TLS/SSL
		 * connection has been established
		 */


		/* Most http server implementation limit the header size
		 * to 8K even though there is no limit in the RFC
		 * 
		 * The buffer needs to be parsed as a header at first
		 * in order to find the size of the HTTP body using
		 * the Content-length in the header*/
		SSL_read(ssl, buf, buf_size);
	
		/* Parse the http request*/
		//TODO
		
		/* Call the neccesary function depending on the request */
		//TODO
	
		
		/* Managed keep-alive sockets */
		//TODO
		
		/* Close sockets after the HTTP close */
		//TODO
	}
}


#ifdef DEBUG
void main(){
	QUEUE *q;
	queue_init(&q);
	int get;
	for (int i=0; i<5;i++){
		queue_add(q, i);
	}
	queue_print(q);

	queue_get(q,&get);
	printf("Popped queue: %d\n", get);
	queue_get(q,&get);
	printf("Popped queue: %d\n", get);
	queue_add(q, 6);
	queue_add(q, 7);
	queue_print(q);
	for (int i=0; i<4;i++){
		queue_get(q, &get);
		printf("Popped queue: %d\n", get);
	}
	queue_print(q);
	queue_add(q, 7);
	queue_add(q, 7);
	queue_print(q);
}
#endif
