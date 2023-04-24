#include "time.h"
#define RED "\e[0;31m"
#define reset "\e[0m"
char* current_time();
void handle_err(char *str);
void handle_err_no(int no, char *str);
void log_msg(char *str);
void log_err(char *str);
void log_err_no(int no, char *str);
