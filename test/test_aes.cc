#include "openssl/aes.h"
#include "openssl/evp.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
unsigned char* get_16key()
{
    unsigned char* str = (unsigned char*)malloc(16);
    memset(str, 0, 16);
    for(int i = 0; i < 16; ++i) {
        str[i] = 'a';
    }
    return str;
}

unsigned char* get_32key()
{
    unsigned char* str = (unsigned char*)malloc(32);
    memset(str, 0, 32);
    for(int i = 0; i < 32; ++i) {
        str[i] = 'a';
    }
    return str;
}

int test1()
{
    unsigned char* key = get_16key();
    unsigned char* iv = get_16key();
    unsigned char* iv1 = get_16key();
    unsigned char* in =  get_16key();
    size_t inlen = strlen((char*)in);
    const char* in1 = "asds";
    size_t inlen1 = strlen(in1);
    unsigned char* en =  new unsigned char[32]();
    unsigned char* de =  new unsigned char[32]();
    AES_KEY enkey;
    AES_KEY dekey;
    AES_set_encrypt_key(key, 128, &enkey);
    AES_set_decrypt_key(key, 128, &dekey);
    AES_cbc_encrypt((const unsigned char*)in1, en, inlen1, &enkey, iv, 1);
    AES_cbc_encrypt((const unsigned char*)en, de, inlen, &dekey, iv1, 0);
    printf("de: %s, len: %ld\n", de, strlen((char*)de));

    
    return 0;
}

int test2()
{
    unsigned char* key = get_32key();
    unsigned char* iv = get_16key();
    unsigned char* iv1 = get_16key();
    unsigned char* in =  get_32key();
    size_t inlen = strlen((char*)in);
    const char* in1 = "8cc72b05705d5c46f412af8cbed55aad1asas";
    size_t inlen1 = strlen(in1);
    unsigned char* en =  new unsigned char[2048]();
    unsigned char* de =  new unsigned char[2048]();
    AES_KEY enkey;
    AES_KEY dekey;
    AES_set_encrypt_key(key, 256, &enkey);
    AES_set_decrypt_key(key, 256, &dekey);
    AES_ecb_encrypt((const unsigned char*)in1, en, &enkey, 1);
    printf("en: %s, len: %ld\n", en, strlen((char*)en));
    AES_ecb_encrypt((const unsigned char*)en, de, &dekey, 0);
    printf("de: %s, len: %ld\n", de, strlen((char*)de));

    
    return 0;
}

int test3()
{
    int ret = 0;
    unsigned char* key = get_16key();
    unsigned char* iv = get_16key();
    unsigned char* iv1 = get_16key();
    unsigned char* in =  get_16key();
    size_t inlen = strlen((char*)in);
    const char* in1 = "asdsasdsasdsasds";
    size_t inlen1 = strlen(in1);
    unsigned char* en =  new unsigned char[32]();
    unsigned char* de =  new unsigned char[32]();
    AES_KEY enkey;
    AES_KEY dekey;
    ret = AES_set_encrypt_key(key, 128, &enkey);
    ret = AES_set_decrypt_key(key, 128, &dekey);
    int num  = 0 ;
    AES_ofb128_encrypt((const unsigned char*)in1, en, inlen1, &enkey, iv, &num);
    printf("en: %s, len: %ld\n", en, strlen((char*)en));
    AES_ofb128_encrypt((const unsigned char*)en, de, inlen, &enkey, iv1, &num);
    printf("de: %s, len: %ld\n", de, strlen((char*)de));

    
    return 0;
}

int test4()
{
    unsigned char* key = get_16key();
    unsigned char* iv = get_16key();
    unsigned char* iv1 = get_16key();
    unsigned char* in =  get_16key();
    size_t inlen = strlen((char*)in);
    char in1[1024] = {0};
    for(int i = 0; i < 16; ++i) {
        in1[i] = 'a';
    }
    size_t inlen1 = strlen(in1);
    unsigned char* en =  new unsigned char[32]();
    unsigned char* de =  new unsigned char[32]();
    AES_KEY enkey;
    AES_KEY dekey;
    AES_set_encrypt_key(key, 128, &enkey);
    AES_set_decrypt_key(key, 128, &dekey);
    int num  = 0 ;
    AES_cfb128_encrypt((const unsigned char*)in1, en, inlen1, &enkey, iv, &num, 1);
    printf("en: %s, len: %ld\n", en, strlen((char*)en));
    AES_cfb128_encrypt((const unsigned char*)en, de, inlen1, &enkey, iv1, &num, 0);
    printf("de: %s, len: %ld\n", de, strlen((char*)de));

    
    return 0;
}

int test5()
{
    unsigned char* key = get_16key();
    unsigned char* key1 = get_16key();
    unsigned char* iv = get_16key();
    unsigned char* iv1 = get_16key();
    unsigned char* in =  get_32key();
    size_t inlen = strlen((char*)in);
    char* in1 = new char[4069]();
    for(int i = 0; i < 16; ++i) {
        in1[i] = 'a';
    }
    size_t inlen1 = strlen(in1);
    unsigned char* en =  new unsigned char[2048]();
    unsigned char* de =  new unsigned char[2048]();

    const EVP_CIPHER * evpcipher =EVP_get_cipherbyname("aes-128-ecb");
     const EVP_CIPHER * evpcipher1 =EVP_get_cipherbyname("aes-128-ecb");
    EVP_CIPHER_CTX  * evpctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX  * evpctx1 = EVP_CIPHER_CTX_new();
    int outl = 0;
    int out2 = 0;

    EVP_EncryptInit_ex(evpctx, evpcipher, NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(evpctx, 0);
    EVP_EncryptUpdate(evpctx, en, &outl, in, 16);
    EVP_EncryptFinal_ex(evpctx, en, &outl);
    printf("en: %s, len: %d\n", en, outl);


    EVP_DecryptInit_ex(evpctx1, evpcipher, NULL, key1, iv1);
    EVP_CIPHER_CTX_set_padding(evpctx1, 0);
    EVP_DecryptUpdate(evpctx1, de, &out2, en, 16);
    EVP_DecryptFinal_ex(evpctx1, de, &out2);
    printf("de: %s, len: %d\n", de, out2);
    
    EVP_CIPHER_CTX_free(evpctx);
    return 0;
}

int test6()
{
    unsigned char* key = get_16key();
    unsigned char* key1 = get_16key();
    unsigned char* iv = get_16key();
    unsigned char* iv1 = get_16key();
    unsigned char* in =  get_32key();
    size_t inlen = strlen((char*)in);
    char* in1 = new char[4069]();
    for(int i = 0; i < 256; ++i) {
        in1[i] = 'a';
    }
    size_t inlen1 = strlen(in1);
    unsigned char* en =  new unsigned char[2048]();
    unsigned char* de =  new unsigned char[2048]();

    const EVP_CIPHER * evpcipher =EVP_get_cipherbyname("aes-128-ecb");
     const EVP_CIPHER * evpcipher1 =EVP_get_cipherbyname("aes-128-ecb");
    EVP_CIPHER_CTX  * evpctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX  * evpctx1 = EVP_CIPHER_CTX_new();
    int outl = 0;
    int out2 = 0;
    
    EVP_EncryptInit_ex(evpctx, evpcipher, NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(evpctx, 0);
    EVP_EncryptUpdate(evpctx, en, &outl, in, 16);
    EVP_EncryptFinal_ex(evpctx, en, &outl);
    printf("en: %s, len: %d\n", en, outl);


    EVP_DecryptInit_ex(evpctx1, evpcipher, NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(evpctx1, 0);
    EVP_DecryptUpdate(evpctx1, de, &out2, en, 16);
    EVP_DecryptFinal_ex(evpctx1, de, &out2);
    printf("de: %s, len: %d\n", de, out2);


    EVP_CIPHER_CTX_free(evpctx);
    return 0;
}

void fun(int p){
	if(p==0) return;
	if(p){
		//printf("%2d",p%10);//逆序输出各位 
		fun(p/16);
		printf("%x\n",p%16);//正序输出各位 
	}
	
}


int main()
{
    int ret = 0;
    ret = test6();
    return ret;
}