#pragma once


#define LOGDIR "opt/log/"
#define LOG_FILENAME "algo_service.log"
#define LINE_LEN 128
#define KEY_LEN 128
#define VALUE_LEN 128


#ifdef DEBUG
#define DEBUGLOG(fmt,...) {if(1)\
		{logoutPut(__FILE__, __LINE__, "[DEBUG]", fmt, ##__VA_ARGS__);}}
#else
#define DEBUGLOG(...)
#endif

char KLogDir[128];
