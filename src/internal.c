#include "internal.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

char KLogDir[128] = {0};

void cpy_str(char* to, char* from) {
	memcpy(to, from, strlen(from));
}
char* my_itoa(int num,char* str,int radix)
{/*索引表*/
    char index[]="0123456789ABCDEF";
    unsigned unum;/*中间变量*/
    int i=0,j,k;
    /*确定unum的值*/
    if(radix==10&&num<0)/*十进制负数*/
    {
        unum=(unsigned)-num;
        str[i++]='-';
    }
    else unum=(unsigned)num;/*其他情况*/
    /*转换*/
    do{
        str[i++]=index[unum%(unsigned)radix];
        unum/=radix;
       }while(unum);
    str[i]='\0';
    /*逆序*/
    if(str[0]=='-')
        k=1;/*十进制负数*/
    else
        k=0;

    for(j=k;j<=(i-1)/2;j++)
    {       char temp;
        temp=str[j];
        str[j]=str[i-1+k-j];
        str[i-1+k-j]=temp;
    }
    return str;
}

int logoutPut(char *filename, int line, char* level, char *fmt, ...)
{
	char *buf = NULL;
	va_list ap;
	int n = 0, size = 2000;
	char logfile[1024] = {0};
	FILE *m_fp = NULL;

	if((buf = (char *)malloc(size * sizeof(char)+1)) == NULL)
		return -1;

	memset(buf,0x00,2000);

	if(strlen(KLogDir) > 0)
		sprintf(logfile, "%s/%s", KLogDir, LOG_FILENAME);
	else
		sprintf(logfile, "%s", LOG_FILENAME);
	
	m_fp = fopen(logfile, "a+");

	if(m_fp == NULL){
		printf("fopen %s fails\n", logfile);
		free(buf);
		buf = NULL;
		return -1;
	}

    while(1){
    	va_start(ap, fmt);
    	n = vsnprintf(buf, size, fmt, ap);
    	va_end(ap);
    	if(n > -1 && n < size)
    		break;
    	size *= 2;
    	if((buf = (char *)realloc(buf, size * sizeof(char))) == NULL)
    		break;
    	memset(buf, 0x00, size * sizeof(char));
    }

	time_t mytime;
	struct tm *mytm;
	time(&mytime);
	mytm = localtime(&mytime);
	fprintf(m_fp, "%d-%02d-%02d %02d:%02d:%02d %s %s:%d %s\n", mytm->tm_year + 1900,
			mytm->tm_mon + 1, mytm->tm_mday, mytm->tm_hour, mytm->tm_min, mytm->tm_sec,
			level, filename, line, buf);

	fflush(m_fp);
	fclose(m_fp);
	m_fp = NULL;

	printf("%d-%02d-%02d %02d:%02d:%02d %s %s:%d %s \n", mytm->tm_year + 1900,
			mytm->tm_mon + 1, mytm->tm_mday, mytm->tm_hour, mytm->tm_min, mytm->tm_sec,
			level, filename, line, buf);

	free(buf);
	buf = NULL;
	return 0;
}

