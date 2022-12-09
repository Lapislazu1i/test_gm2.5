#include "openssl/e_os2.h"
#include "openssl/sha.h"
#include <stdio.h>
#include <stdlib.h>
#include<string.h>

int test1()
{
    int ret = 0;
    unsigned char* in = (unsigned char*)malloc(1024);
    unsigned char* out = new unsigned char[1024]();
    size_t outlen = 0;
    for(int i = 0; i < 966; ++i) {
        in[i] = 'a';
    }
    size_t inlen = strlen((char*)in);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, inlen);
    SHA256_Final(out, &ctx);
    printf("sig: %s, len: %ld\n", out, strlen((char*)out));
    return ret;
}

int test2()
{
    int ret = 0;
    unsigned char* in = (unsigned char*)malloc(1024);
    unsigned char* out = new unsigned char[1024]();
    unsigned char* out1 = new unsigned char[1024]();
    size_t outlen = 0;
    for(int i = 0; i < 966; ++i) {
        in[i] = 'a';
    }
    size_t inlen = strlen((char*)in);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, inlen);
    SHA256_Final(out, &ctx);
    printf("sig: %s, len: %ld\n", out, strlen((char*)out));
    SHA256(in, inlen, out1);
    printf("sig: %s, len: %ld\n", out, strlen((char*)out));
    int bl = 0;
    for(int i = 0; i < 32; ++i) {
        if(out[i] != out1[i]) {
            ++bl;
        }
    }
    printf("bl: %d\n", bl);
    return ret;
}

int main()
{
    int ret = 0;
    ret = test2();
    return ret;
}