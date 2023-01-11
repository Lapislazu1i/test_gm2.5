#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>


#include <iostream>
#include <sstream>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
using namespace std;


int test1() {

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    const SSL_METHOD* meth = SSLv23_client_method();
    SSL_CTX* ctx = SSL_CTX_new(meth);
    const char* host = "cn.bing.com";
    struct hostent* hosten = NULL;
    hosten = gethostbyname(host);
    if (hosten == NULL) {
        printf("gethostname err\n");
        return -1;
    }


    std::stringstream stream;
    stream << "GET /"
           << " HTTP/1.1\r\n";
    stream << "Accept: */*\r\n";
    // stream << "Accept-Encoding: gzip, deflate,
    // br\r\n";//不要编码，否则还得多一个解码的步骤
    stream << "Accept-Language: zh-Hans-CN, zh-Hans; q=0.8, en-US; q=0.5, en; "
              "q=0.3\r\n";
    stream << "Connection: Close\r\n";
    stream << "Host: " << host << "\r\n";
    stream << "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 "
              "Safari/537.36 Edge/17.17134\r\n";
    stream << "\r\n";
    std::string sendData = stream.str();
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        printf("socket err\n");
        return -1;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr = *(in_addr*)hosten->h_addr_list[0];
    auto ipa = *hosten->h_addr_list[0];
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, hosten->h_addr_list[0], str, sizeof(str));
    printf("ip: %s\n", str);
    if (-1 == connect(fd, (struct sockaddr*)&addr, sizeof(addr))) {
        printf("connect error");
        return -1;
    }
    int ret = 0;
    SSL* ssl = SSL_new(ctx);
    if (ssl == NULL) {
        std::cout << "SSL NEW error";
        return -1;
    }
    //将SSL与TCP SOCKET 连接
    SSL_set_fd(ssl, fd);
    // SSL连接
    ret = SSL_connect(ssl);

    if (ret == -1) {
        std::cout << "SSL ACCEPT error ";
        return -1;
    }
    ret = SSL_write(ssl, sendData.c_str(), sendData.size());
    if (ret == -1) {
        cout << "SSL write error !";
        return -1;
    }

    char* rec = new char[1024 * 1024]();
    int start = 0;
    while ((ret = SSL_read(ssl, rec + start, 1024)) > 0) {
        start += ret;
    }
    rec[start] = 0;
    std::cout << rec;
    SSL_shutdown(ssl);
    //释放SSL套接字
    SSL_free(ssl);
    //释放SSL会话环境
    SSL_CTX_free(ctx);

    close(fd);
}


int main() { test1(); }