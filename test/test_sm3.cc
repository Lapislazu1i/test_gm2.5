#include "openssl/sm3.h"
#include "cstring"
#include "cstdlib"
#include "cstdio"
#include "openssl/evp.h"
int test1()
{
    const char* in = "123456";
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
    return 0;
}

int test2()
{
    const char* in = "123456";
    size_t inlen = strlen(in);
    unsigned char* buf = new unsigned char[1024]();
    unsigned char* buf1 = new unsigned char[1024]();
    unsigned int hashLen = 0;
    EVP_MD_CTX* ctx = NULL;
    const EVP_MD* md;
    md = EVP_sm3();
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinal(ctx, buf, &hashLen);
    EVP_MD_CTX_free(ctx);
    sm3((const unsigned char*)in, std::strlen(in), buf1);
    int boolsize = 0;
    for(int i = 0; i < hashLen; ++i) {
        if(buf[i] != buf1[i]) {
            ++boolsize;
        }
    }
    printf("end: %d\n", boolsize);
}

int main()
{
    test2();
    return 0;
}