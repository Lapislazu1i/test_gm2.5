#include "openssl/sms4.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>

int pkcs7_padding(int multipleSize, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	int ret = 0;
	int padlen = multipleSize - (inlen % multipleSize);
	int len = inlen + padlen;

	memcpy(out, in, inlen);
	memset(out + inlen, padlen, padlen);
	*outlen = len;

	return ret;
}

int unpkcs7_padding(int multipleSize, unsigned char* in, size_t inlen, int* len)
{
	int ret = 0;
	int fin = (int)in[inlen-1];

	if(fin==0) {
		fin = multipleSize;
	}
	for(int i=0; i < fin; ++i) {
		if(in[inlen-1] != in[inlen-1-i]) {
			ret = -1;
			return ret;
		}
	}
	memset(in + inlen - fin, 0x00, fin);
	*len = inlen - fin;
	return ret;
}

int test1()
{
    int ret = 0;
    const char* pkey = "1234567812345678";
    const char* in = "1234567812345678";
    unsigned char* encode = (unsigned char*) malloc(1024);
    memset(encode, 0, 1024);
    unsigned char* decode = (unsigned char*) malloc(1024);
    memset(decode, 0, 1024);

    sms4_key_t skey;
    sms4_key_t sdkey;
    sms4_set_encrypt_key(&skey, (unsigned char*)pkey);
    sms4_set_decrypt_key(&sdkey, (unsigned char*)pkey);
    sms4_ecb_encrypt((unsigned char*)in, encode, &skey, 1);
    printf("enlen: %ld", strlen((char*)encode));
    sms4_ecb_encrypt(encode, decode, &sdkey, 0);
    printf("en: %s, de: %s\n", encode, decode);
    return ret;

}

int test2()
{
    int ret = 0;
    char pkey[16];
    const char* in = "12345678123456781";
    char iv[16];
    char iv2[16];
    for(int i = 0; i < 16; ++i) {
        pkey[i] = 'b';
  
        iv[i] = 'a';
        iv2[i] = 'a';
    }
    unsigned char* encode = (unsigned char*) malloc(1024);
    memset(encode, 0, 1024);
    unsigned char* decode = (unsigned char*) malloc(1024);
    memset(decode, 0, 1024);

    sms4_key_t skey;
    sms4_key_t sdkey;
    sms4_set_encrypt_key(&skey, (unsigned char*)pkey);
    sms4_set_decrypt_key(&sdkey, (unsigned char*)pkey);
    sms4_cbc_encrypt((unsigned char*)in, encode, 17, &skey, (unsigned char*)iv, 1);
    sms4_cbc_encrypt(encode, decode, strlen((const char*)encode), &sdkey, (unsigned char*)iv2, 0);
    printf("enlen: %ld\n", strlen((char*)encode));
    printf("ori: %s, en: %s, de: %s\n", in, encode, decode);
    return ret;

}

int test3()
{
    int ret = 0;
    char pkey[16];
    const char* in = "1234567812345678";
    char iv[16];
    char iv2[16];
    for(int i = 0; i < 16; ++i) {
        pkey[i] = 'b';
  
        iv[i] = 'a';
        iv2[i] = 'a';
    }
    unsigned char* encode = (unsigned char*) malloc(1024);
    memset(encode, 0, 1024);
    unsigned char* decode = (unsigned char*) malloc(1024);
    memset(decode, 0, 1024);
    int num = 0;
    int num2 = 0;
    sms4_key_t skey;

    sms4_set_encrypt_key(&skey, (unsigned char*)pkey);

    sms4_ofb128_encrypt((unsigned char*)in, encode, strlen(in), &skey, (unsigned char*)iv, &num);
    printf("num: %d\n", num);
    sms4_ofb128_encrypt(encode, decode, strlen(in), &skey, (unsigned char*)iv2, &num);
    printf("num: %d\n", num);

    printf("enlen: %ld\n", strlen((char*)encode));
    printf("ori: %s, en: %s, de: %s\n", in, encode, decode);
    return ret;

}

int test4()
{
    size_t inlen = 33;
    unsigned char* in = (unsigned char*)malloc(inlen);
    for(int i = 0;i < inlen; ++i) {
        in[i] = 'a';
    }
    unsigned char* pad = (unsigned char*)malloc(128);
    memset(pad, 0, 128);
    size_t padlen = 0;
    pkcs7_padding(16, in, inlen, pad, &padlen);
    printf("enpad: %s, len: %ld\n", pad, padlen);
    int unplen = 0;
    unpkcs7_padding(16, pad, padlen, &unplen);
    printf("unp: %s, len: %d\n", pad, unplen);
}


int main()
{
    int ret = 0;
    ret = test3();
    void (*abc)();
    std::string in;
    int a = 127;
    in.push_back(49);
    printf("ss: %s, len: %ld\n", in.c_str(), in.size());
    int b = in.back();
    printf("b: %d\n", b);
    return ret;
}