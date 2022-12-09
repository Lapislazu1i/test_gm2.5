#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include"openssl/rsa.h"
#include"openssl/obj_mac.h"
int test1()
{
    int ret = 0;
    RSA *rsa = RSA_new();
    BIGNUM* bne = BN_new();
    ret=BN_set_word(bne,RSA_F4);
    ret = RSA_generate_key_ex(rsa,1024,bne,NULL);

    return ret;
}

int test2()
{
    printf("\nRSA_generate_key_ex TESTING...\n\n");
    RSA *rsa = RSA_new();
    int ret = 0;
    BIGNUM *bne=BN_new();
    ret=BN_set_word(bne,RSA_F4);
    ret = RSA_generate_key_ex(rsa,512,bne,NULL);

    unsigned char plain[64]="Hello world!";
    for(int i = 0; i < 64; ++i) {
        plain[i] = 'b';
    }
    unsigned char cipper[64]={0};
    unsigned char newplain[64]={0};
    size_t outl=64;
    size_t outl2 = 64;
    printf("%s\n", plain);
    for(int i =0;i<strlen((char*)plain);i++){
        printf("%02x ",plain[i]);
    }
    printf("\n---------------\n");
    RSA_public_encrypt(strlen((char*)plain),plain,cipper,rsa,RSA_NO_PADDING);
    for(int i =0;i<outl;i++){
        printf("%02x ",cipper[i]);
        if((i+1)%10 ==0) printf("\n");
    }
    printf("\n");
    RSA_private_decrypt(outl,cipper,newplain,rsa,RSA_NO_PADDING);

    printf("-----------------\n%s\n", newplain);
    for(int i =0;i<outl2;i++) {
        printf("%02x ",newplain[i]);
    }
    printf("out1: %ld, out2: %ld\n", outl, outl2);

}

int test3()
{
    printf("\nRSA_encrypt TESTING...\n\n");
    RSA *rsa = RSA_new();
    int ret = 0;
    BIGNUM *bne=BN_new();
    ret=BN_set_word(bne,RSA_F4);
    ret = RSA_generate_key_ex(rsa,512,bne,NULL);

    unsigned char plain[512]="Hello world!";
    for(int i = 0;i < 22; ++i) {
        plain[i] = 'a';
    }
    unsigned char cipper[512]={0};
    unsigned char newplain[512]={0};
    size_t outl=512;
    size_t outl2;
    printf("%s\n", plain);
    for(int i =0;i<strlen((char*)plain);i++){
        printf("%02x ",plain[i]);
    }
    printf("\n---------------\n");
    outl=RSA_public_encrypt(strlen((char*)plain),plain,cipper,rsa,RSA_PKCS1_OAEP_PADDING);
    printf("outl: %ld\n", strlen((char*)cipper));
    for(int i =0;i<outl;i++){
        printf("%02x ",cipper[i]);
        if((i+1)%10 ==0) printf("\n");
    }
    printf("\n");
    outl2=RSA_private_decrypt(outl,cipper,newplain,rsa,RSA_PKCS1_OAEP_PADDING);
    printf("outl2: %ld, %ld\n", outl2, strlen((char*)newplain));
    printf("-----------------\n%s\n", newplain);
    for(int i =0;i<outl2;i++) {
        printf("%02x ",newplain[i]);
    }
    printf("\n");
    return 0;

}

int test4()
{
    printf("\nRSA_varify TESTING...\n\n");
    RSA *rsa = RSA_new();
    int ret = 0;
    BIGNUM *bne=BN_new();
    ret=BN_set_word(bne,RSA_F4);
    ret = RSA_generate_key_ex(rsa,1024,bne,NULL);
    
    unsigned char plain[512]= { 0 };
    for(int i = 0; i < 98; ++i) {
        plain[i] = 'b';
    }
    unsigned char cipper[512]={0};
    unsigned char newplain[512]={0};
    size_t outl=0;
    size_t outl2 = 512;
    printf("%s\n", plain);
    for(int i =0;i<strlen((char*)plain);i++){
        printf("%02x ",plain[i]);
    }
    printf("\n---------------\n");
    RSA_sign(NID_sha256, plain, strlen((char*)plain),cipper, (unsigned int*)&outl, rsa);
    printf("out1: %ld\n", outl);
    for(int i =0;i<outl+2;i++){
        printf("%02x ",cipper[i]);
        if((i+1)%10 ==0) printf("\n");
    }
    printf("\n");
    
    ret = RSA_verify(NID_sha256, plain, strlen((char*)plain), cipper,outl, rsa);
    printf("ret: %d\n", ret);
    printf("-----------------\n%s\n", newplain);
    for(int i =0;i<strlen((char*)cipper);i++) {
        printf("%02x ",cipper[i]);
    }
    printf("\n");
    return 0;

}


int test5()
{
    printf("\nRSA_encrypt TESTING...\n\n");
    RSA *rsa = RSA_new();
    int ret = 0;
    BIGNUM *bne=BN_new();
    ret=BN_set_word(bne,RSA_F4);
    ret = RSA_generate_key_ex(rsa,1024,bne,NULL);

    unsigned char plain[1024]="Hello world!";
    for(int i = 0;i < 85; ++i) {
        plain[i] = 'a';
    }
    unsigned char cipper[1024]={0};
    unsigned char newplain[1024]={0};
    size_t outl=1024;
    size_t outl2;
    printf("%s\n", plain);
    for(int i =0;i<strlen((char*)plain);i++){
        printf("%02x ",plain[i]);
    }
    printf("\n---------------\n");
    outl=RSA_public_encrypt(strlen((char*)plain),plain,cipper,rsa,RSA_PKCS1_OAEP_PADDING);
    printf("outl: %ld\n", strlen((char*)cipper));
    for(int i =0;i<outl;i++){
        printf("%02x ",cipper[i]);
        if((i+1)%10 ==0) printf("\n");
    }
    printf("\n");
    outl2=RSA_private_decrypt(outl,cipper,newplain,rsa,RSA_PKCS1_OAEP_PADDING);
    printf("outl2: %ld, %ld\n", outl2, strlen((char*)newplain));
    printf("-----------------\n%s\n", newplain);
    for(int i =0;i<outl2;i++) {
        printf("%02x ",newplain[i]);
    }
    printf("\n");
    return 0;

}

int main()
{
    int ret = 0;
    ret = test4();
    return 0;
}