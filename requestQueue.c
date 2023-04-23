#include "types.h"

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

int requests_empty(REQUESTS *q){
	return (q->head == NULL && q->tail == NULL)?1:0;
}


int requests_init(REQUESTS **q, SSL_CTX *ctx){
	*q = (REQUESTS*)malloc(sizeof(REQUESTS));
	if(*q == NULL){
        perror("requests_init: malloc: ");
		return 1;
	}
	(*q)->head = NULL;
	(*q)->tail = NULL;
	if(pthread_mutex_init(&(*q)->mtx, NULL) != 0){
        perror("requests_init: mutex_init: ");
		return 1;
	}
	if(pthread_cond_init(&(*q)->cond,NULL) != 0){
        perror("requests_init: cond_init: ");
		return 1;
	}
	(*q)->ctx = ctx;
	return 0;
}

int requests_add(REQUESTS *q, int client_soc){
	/* Locking queue for concarency */
	pthread_mutex_lock(&q->mtx);

	/* Adding element to queue */
	NODE *new =(NODE*)malloc(sizeof(NODE));
	if(new == NULL){
        perror("requests_add: malloc: ");
        exit(EXIT_FAILURE);
	}
	new->next = NULL;
	new->socket = client_soc;

	if(requests_empty(q)){
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

void requests_get(REQUESTS *q, int *socket){
	pthread_mutex_lock(&q->mtx);

    	/* Wait for element to become available. */
    	while (requests_empty(q))
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

void requests_print(REQUESTS *q){
	NODE *tmp = q->head;
	while(tmp != NULL){
		printf("%d -> ",tmp->socket);
		tmp = tmp->next;
	}
	printf("NULL\n");
}

void requests_cleanup(REQUESTS *q){

    while(q->head != NULL){
        NODE *tmp = q->head;
        q->head = q->head->next;
        free(tmp);
    }

    SSL_CTX_free(q->ctx);
    if(pthread_mutex_destroy(&q->mtx)){
        perror("request_cleanup: mutex_destroy: ");
        exit(EXIT_FAILURE);
    }   
    if(pthread_cond_destroy(&q->cond)){
        perror("request_cleanup: cond_destroy: ");
        exit(EXIT_FAILURE);
    }
    
    free(q);
}

#ifdef DEBUG
void main(){
	REQUESTS *q;
	requests_init(&q);
	int get;
	for (int i=0; i<5;i++){
		requests_add(q, i);
	}
	requests_print(q);

	requests_get(q,&get);
	printf("Popped queue: %d\n", get);
	requests_get(q,&get);
	printf("Popped queue: %d\n", get);
	requests_add(q, 6);
	requests_add(q, 7);
	requests_print(q);
	for (int i=0; i<4;i++){
		requests_get(q, &get);
		printf("Popped queue: %d\n", get);
	}
	requests_print(q);
	requests_add(q, 7);
	requests_add(q, 7);
	requests_print(q);
}
#endif
