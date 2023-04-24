#include "types.h"
char* current_time() {
    time_t t = time(NULL);
    char *time=ctime(&t);
    time[strlen(time)-1] = '\0';
    return time;
}
void handle_err(char *str) {
    char *time = current_time();
    printf(RED"[%s]: %s: %s\n"reset,time,SERVER_NAME,str);
}
void handle_err_no(int no, char *str){
    char *time = current_time();
    printf(RED"[%s]: %s: %s: %s\n"reset,time,SERVER_NAME,str, strerror(no));
}
void log_msg(char *str){
    char *time = current_time();
    printf("[%s]: %s: %s\n",time,SERVER_NAME,str);
}
void log_err(char *str){
    char *time = current_time();
    printf(RED"[%s]: %s: %s\n"reset,time,SERVER_NAME,str);
}
void log_err_no(int no, char *str){
    char *time = current_time();
    printf(RED"[%s]: %s: %s\n"reset,time,SERVER_NAME,str,strerror(no));
}
