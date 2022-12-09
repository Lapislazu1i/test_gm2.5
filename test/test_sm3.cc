#include "openssl/sm3.h"
#include "cstring"
#include "cstdlib"
#include "cstdio"
int main()
{
    const char* in = "21341234";
    unsigned char* buf = new unsigned char[1024]();
    unsigned char* buf1 = new unsigned char[1024]();
    sm3((const unsigned char*)in, std::strlen(in), buf);
    sm3_ctx_t sm3;
    sm3_init(&sm3);
    sm3_update(&sm3, (const unsigned char*)in, 4);
    sm3_update(&sm3, (const unsigned char*)in , 4);
    sm3_final(&sm3, buf1);
    int retv = 0;
    for(int i = 0; i < 32; ++i) {
        if(buf[i] != buf1[i]) {
            ++retv;
        }
    }
    std::printf("res: %d\n", retv);
    std::printf("sign: %s, len: %ld\n", buf, strlen((char*)buf));
}