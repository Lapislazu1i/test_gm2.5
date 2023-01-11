#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/evp.h"

#include "openssl/sm2.h"
#include "openssl/ossl_typ.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
using namespace std;



#define Result_EncErr -1
#define Result_OK 0
/**
 使用gmssl SM2加密

 @param inData 需要加密的数据
 @param inDataLen 需要加密的数据长度
 @param pubKey 公钥（point2oct）
 @param pubKeyLen 公钥长度
 @param encryptData 加密后的数据
 @return 0：成功/非0：失败
 */
int sm2EncryptWithGmssl(
    unsigned char *inData,
    unsigned long inDataLen,
    unsigned char *pubKey,
    unsigned long pubKeyLen,
    SM2CiphertextValue **encryptData)
{
    int resultCode = Result_OK;
    //公钥
    EC_KEY *ec_key = NULL;
    //公钥
    EC_POINT *publicKey = NULL;
    // ec_group
    EC_GROUP *ec_group = NULL;
    // ctx
    BN_CTX *ctx = NULL;

    //判断输入参数是否为空
    if (inData == NULL || inDataLen == 0 || pubKey == NULL || pubKeyLen == 0 || encryptData == NULL)
    {
        resultCode = -1;
        return -1;
    }

    //获取公钥
    ctx = BN_CTX_new();
    ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    publicKey = EC_POINT_new(ec_group);
    int mark = EC_POINT_oct2point(ec_group, publicKey, pubKey, pubKeyLen, ctx);
    if (mark != 1)
    {
        resultCode = Result_EncErr;
        goto err;
    }

    //初始化数据
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_set_public_key(ec_key, publicKey);

    //调用gmssl SM2加密
    if (!(*encryptData = SM2_do_encrypt(EVP_sm3(), inData, inDataLen, ec_key)))
    {
        resultCode = Result_EncErr;
        goto err;
    }

err:
    if (ec_key != NULL)
    {
        EC_KEY_free(ec_key);
    }
    if (ec_group != NULL)
    {
        EC_GROUP_free(ec_group);
    }
    if (ctx != NULL)
    {
        BN_CTX_free(ctx);
    }
    if (publicKey != NULL)
    {
        EC_POINT_free(publicKey);
    }
    return resultCode;
}
/**
 使用GMSSL解密

 @param cv 加密数据
 @param d 私钥
 @param decryptData 解密数据
 @param decryptDataLen 解密数据长度
 @return 0成功/其它失败
 */
int sm2DecryptWithGmssl(SM2CiphertextValue *cv, const BIGNUM *d, unsigned char *decryptData, unsigned long *decryptDataLen)
{
    int resultCode = 0;
    BN_CTX *ctx = NULL;

    EC_GROUP *ec_group = NULL;
    EC_KEY *ec_key = NULL;
    // bn_prime
    BIGNUM *prime = NULL;

    //判断输入参数是否为空
    if (cv == NULL || d == NULL || decryptData == NULL)
    {
        resultCode = -1;
        goto end;
    }

    //初始化
    ctx = BN_CTX_new();
    ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    //设置私钥
    ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, ec_group);
    EC_KEY_set_private_key(ec_key, d);
    // prime
    //  prime = BN_new();
    //  BN_hex2bn(&prime,SM2_n);

    // C = C1||C3||C2 -- C为加密数据encryptData
    if (!SM2_do_decrypt(EVP_sm3(), cv, decryptData, decryptDataLen, ec_key))
    {
        resultCode = -1;
        goto end;
    }
    printf("\n Decrypt Data-->%s\n", decryptData);
end:
    if (ctx != NULL)
    {
        BN_CTX_free(ctx);
    }
    if (ec_group != NULL)
    {
        EC_GROUP_free(ec_group);
    }
    if (ec_key != NULL)
    {
        EC_KEY_free(ec_key);
    }
    if (prime != NULL)
    {
        BN_free(prime);
    }
    if (d != NULL)
    {
        //BN_free(d);
    }
    return resultCode;
}
int test2()
{

    EC_KEY *keypair = NULL;
    EC_GROUP *group1 = NULL;

    BN_CTX *ctx = NULL;

    ctx = BN_CTX_new();
    keypair = EC_KEY_new();
    if (!keypair)
    {
        printf("Failed to Gen Key");
        exit(1);
    }

    group1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    if (group1 == NULL)
    {
        printf("Failed to Gen Key");
        exit(1);
    }

    int ret1 = EC_KEY_set_group(keypair, group1);
    if (ret1 != 1)
    {
        printf("Failed to Gen Key");
        exit(1);
    }

    int ret2 = EC_KEY_generate_key(keypair);
    if (ret2 != 1)
    {
        printf("Failed to Gen Key");
        exit(1);
    }
    
    const char* input = "nihao";
    char encode[1024] = {0};
    char decode[1024] = {0};
    size_t inlen = strlen(input);
    size_t enlen = 0;
    size_t delen = 0;
	unsigned char* pubkey = new unsigned char[1024];
	EC_KEY_key2buf(keypair, POINT_CONVERSION_UNCOMPRESSED, &pubkey, ctx);
	const EC_POINT* pbkey = EC_KEY_get0_public_key(keypair);
	unsigned char* pbkeyb = new unsigned char[1024];
	EC_POINT_point2oct(group1, pbkey, POINT_CONVERSION_UNCOMPRESSED, pbkeyb, 1024, ctx);
	SM2CiphertextValue* encd = NULL;
    sm2EncryptWithGmssl((unsigned char*)input, inlen, pbkeyb, strlen((const char*)pubkey), &encd);
	unsigned char* pubkeyp = new unsigned char[1024];
	i2o_SM2CiphertextValue(group1, encd, &pubkeyp);
	printf("en:%s\n", pubkeyp);
	const BIGNUM* pkey = EC_KEY_get0_private_key(keypair);

	
    sm2DecryptWithGmssl(encd, pkey, (unsigned char*)decode, &delen);
	printf("---------------\n");
	printf("en:%s\n", decode);
}


int test3()
{
	unsigned char* input = new unsigned char[1024];
    for(int i = 0; i < 256; ++i)
    {
        input[i] = 'a';
    }
	//init
	BN_CTX* ctx = BN_CTX_new();
    EC_KEY* keypair = EC_KEY_new();
	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_set_group(keypair, group);
	EC_KEY_generate_key(keypair);

	// get public key and private key

	// EC_KEY_key2buf(keypair, POINT_CONVERSION_UNCOMPRESSED, &pubkey, ctx);
	const BIGNUM* prikey = EC_KEY_get0_private_key(keypair);
	const EC_POINT* pubkey = EC_KEY_get0_public_key(keypair);

	EC_KEY* publicKey = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_set_public_key(publicKey, pubkey);

	EC_KEY* privateKey = EC_KEY_new();
    EC_KEY_set_group(privateKey, group);
    EC_KEY_set_private_key(privateKey, prikey);

	unsigned char* endata = (unsigned char*)malloc(1024);
	size_t enlen = 128;
	unsigned char* dedata = (unsigned char*)malloc(1024);
	size_t delen = 128;
	SM2CiphertextValue *enms2 = SM2_do_encrypt(EVP_sm3(),(const unsigned char*) input, strlen(input), publicKey);
	// SM2_encrypt(NID_sm3, (const unsigned char*)input, strlen(input), (unsigned char*)endata, &enlen, publicKey);

	printf("endata:%s, len:%ld\n", endata, enlen);
    unsigned char* pout = (unsigned char*)malloc(1024);
    size_t poutlen = 1024;
    SM2CiphertextValue *enms3 = SM2CiphertextValue_new();
    i2o_SM2CiphertextValue(EC_KEY_get0_group(keypair), enms2, &pout);
    o2i_SM2CiphertextValue(EC_KEY_get0_group(keypair), EVP_sm3(), &enms3,(const unsigned char**) &pout, poutlen);

    SM2_do_decrypt(EVP_sm3(), enms2, dedata, &delen, privateKey);
	// SM2_decrypt(NID_sm3, (const unsigned char*)endata, enlen, (unsigned char*)dedata, &delen, privateKey);
	printf("result:%s, len:%ld\n", dedata, delen);

    // deinit
    EC_KEY_free(keypair);
    EC_KEY_free(publicKey);
    EC_KEY_free(privateKey);


    BN_CTX_free(ctx);

}

int test4()
{
    int ret = 0;
    char* id = new char[1024]();
    for(int i = 0; i < 16; ++i) {
        id[i] = 'a';
    }
    int idlen = strlen(id);
    BN_CTX* ctx = BN_CTX_new();
    EC_KEY* keypair = EC_KEY_new();
	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_set_group(keypair, group);
	EC_KEY_generate_key(keypair);

    // const int buflen = 1024;
    // unsigned char* sig = (unsigned char*)malloc(buflen);
    // memset(sig, 0, buflen);
    // unsigned int siglen = 1024;
    // ret = SM2_sign(NID_sm3, (const unsigned char *)id, idlen, sig, &siglen, keypair);
    // printf("siglen: %d\n", siglen);
    // ret = SM2_verify(NID_sm3, (const unsigned char *)id, idlen, sig, siglen, keypair);
    // printf("ret: %d\n", ret);

    ECDSA_SIG* esig = SM2_do_sign((const unsigned char *)id, idlen, keypair);
    int tmplen = i2d_ECDSA_SIG(esig,NULL);
    unsigned char* dsig = new unsigned char[tmplen]();
    memset(dsig, 0, tmplen);
    
    size_t dsiglen = 0;
    
    ECDSA_SIG* esig1 = ECDSA_SIG_new();

    dsiglen = i2d_ECDSA_SIG(esig,&dsig);
    printf("dsignlen: %ld\n", dsiglen);
    int dsiglen1 = 0;
    d2i_ECDSA_SIG(&esig1, (const unsigned char **)&dsig,dsiglen);


    if (SM2_do_verify((const unsigned char *)id, idlen, esig, keypair) == 1) {
        printf("ec do true\n");
        return 0;
    }
    if (SM2_verify(NID_sm3, (const unsigned char *)id, idlen, dsig, 4096, keypair) == 1) {
        printf("ec true\n");
        return 0;
    }
    ECDSA_SIG_free(esig);
    printf("ret: %d\n", ret);
}

int test5()
{
    int ret = 0;
    char* id = "iodjfiodsfjdsifodsfiodjfiodsfjdsifodsfiodjfiodsfjdsifodsfdsfdsssfiojfoijeiwojroijrewoirewjrjo";
    int idlen = strlen(id);
    BN_CTX* ctx = BN_CTX_new();
    EC_KEY* keypair = EC_KEY_new();
	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_set_group(keypair, group);
	EC_KEY_generate_key(keypair);
    unsigned char out[512] = {0};
    size_t outlen = 512;
    unsigned char out1[512] = {0};
    size_t outlen1 = 512;
    size_t bl = 0;
    SM2_compute_id_digest(EVP_sm3(), id, idlen, out, &outlen, keypair);
    SM2_compute_id_digest(EVP_sm3(), id, idlen, out1, &outlen1, keypair);
    for(int i = 0; i < 32; ++i) {
        if(out[i] != out1[i]) {
            bl++;
        }
    }
    printf("ret: %ld\n", bl);
    printf("z: %s, len: %ld\n", out, outlen);
    return ret;
}
int test6()
{
    int ret = 0;
    char* id = new char[1024]();
    for(int i = 0; i < 16; ++i) {
        id[i] = 'a';
    }
    int idlen = strlen(id);
    BN_CTX* ctx = BN_CTX_new();
    EC_KEY* keypair = EC_KEY_new();
	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_set_group(keypair, group);
	EC_KEY_generate_key(keypair);

    constexpr unsigned int dsigSize = 4096;
    unsigned char* dsig = new unsigned char[dsigSize]();
    unsigned int dsigLen = 0;

    // const int buflen = 1024;
    // unsigned char* sig = (unsigned char*)malloc(buflen);
    // memset(sig, 0, buflen);
    // unsigned int siglen = 1024;
    ret = SM2_sign(0, (const unsigned char *)id, idlen, dsig, &dsigLen, keypair);
    printf("dsiglen: %d\n", dsigLen);
    // printf("siglen: %d\n", siglen);
    // ret = SM2_verify(NID_sm3, (const unsigned char *)id, idlen, sig, siglen, keypair);
    // printf("ret: %d\n", ret);

    if (SM2_verify(0, (const unsigned char *)id, idlen, dsig, dsigLen, keypair) == 1) {
        printf("ec true\n");
        return 0;
    }
    printf("ret: %d\n", ret);
    return ret;
}

int test7()
{
    int ret = 0;
    constexpr int inSize = 32;
    unsigned char* input = new unsigned char[1024]();
    for(int i = 0; i < inSize; ++i){
        input[i] = 'a';
    }
    int inputLen = inSize;
	//init
	BN_CTX* ctx = BN_CTX_new();
    EC_KEY* keypair = EC_KEY_new();
	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_set_group(keypair, group);
	EC_KEY_generate_key(keypair);

	// get public key and private key

	// EC_KEY_key2buf(keypair, POINT_CONVERSION_UNCOMPRESSED, &pubkey, ctx);
	const BIGNUM* prikey = EC_KEY_get0_private_key(keypair);
	const EC_POINT* pubkey = EC_KEY_get0_public_key(keypair);

	EC_KEY* publicKey = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_set_public_key(publicKey, pubkey);

	EC_KEY* privateKey = EC_KEY_new();
    EC_KEY_set_group(privateKey, group);
    EC_KEY_set_private_key(privateKey, prikey);

	unsigned char* endata = new unsigned char[1024]();
	size_t enlen = 1024;
	unsigned char* dedata = new unsigned char[1024]();
	size_t delen = 1024;
	// SM2CiphertextValue *enms2 = SM2_do_encrypt(EVP_sm3(),(const unsigned char*) input, strlen(input), publicKey);
	SM2_encrypt(NID_sm3, (const unsigned char*)input, inputLen, (unsigned char*)endata, &enlen, keypair);

	printf("endata:%s, len:%ld\n", endata, enlen);
    unsigned char* pout = (unsigned char*)malloc(1024);
    size_t poutlen = 1024;
    SM2CiphertextValue *enms3 = SM2CiphertextValue_new();
    // i2o_SM2CiphertextValue(EC_KEY_get0_group(keypair), enms2, &pout);
    // o2i_SM2CiphertextValue(EC_KEY_get0_group(keypair), EVP_sm3(), &enms3,(const unsigned char**) &pout, poutlen);

    // SM2_do_decrypt(EVP_sm3(), enms2, dedata, &delen, privateKey);
	SM2_decrypt(NID_sm3, (const unsigned char*)endata, enlen, (unsigned char*)dedata, &delen, keypair);
    printf("dedata: %s, len: %ld\n", dedata, delen);
    EC_KEY_free(keypair);
    EC_KEY_free(publicKey);
    EC_KEY_free(privateKey);


    BN_CTX_free(ctx);

    return ret;
}

int testz()
{
    int ret = 0;

    const char* id = "12345";
    size_t id_len = strlen(id);
    BIGNUM *a = NULL, *b = NULL, *xG = NULL, *yG = NULL, *xP = NULL, *yP = NULL;
    BN_CTX* bnCtx = BN_CTX_new();
	unsigned char a_bytes[32], b_bytes[32], xG_bytes[32], yG_bytes[32], xP_bytes[32], yP_bytes[32], len_bytes[2];

	BN_CTX* ctx = BN_CTX_new();
    EC_KEY* keypair = EC_KEY_new();
	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_set_group(keypair, group);
	EC_KEY_generate_key(keypair);

	// get public key and private key

	// EC_KEY_key2buf(keypair, POINT_CONVERSION_UNCOMPRESSED, &pubkey, ctx);
	const BIGNUM* prikey = EC_KEY_get0_private_key(keypair);
	const EC_POINT* pubkey = EC_KEY_get0_public_key(keypair);

	a = BN_new();
	b = BN_new();
	xG = BN_new();
	yG = BN_new();
	xP = BN_new();
	yP = BN_new();
	if (!a || !b || !xG || !yG || !xP || !yP)
	{
        ret = -1;
        return ret;
	}

    const EC_POINT* G = EC_GROUP_get0_generator(group);
    ret = EC_GROUP_get_curve_GFp(group, NULL, a, b, bnCtx);
    ret =  EC_POINT_get_affine_coordinates_GFp(group, G, xG, yG, bnCtx);
    ret = EC_POINT_get_affine_coordinates_GFp(group, pubkey, xP, yP, bnCtx);
    if(ret == 0) {
        return -1;
    }
    BN_bn2bin(a, a_bytes);
    BN_bn2bin(b, b_bytes);
    BN_bn2bin(xG, xG_bytes);
    BN_bn2bin(yG, yG_bytes);
    BN_bn2bin(xP, xP_bytes);
    BN_bn2bin(yP, yP_bytes);
    len_bytes[0] = ((id_len * 8) >> 8) & 0xff;
    len_bytes[1] = (id_len * 8) & 0xff;
    sm3_ctx_t sm3;
    unsigned char digest[64] = {};
    sm3_init(&sm3);
    sm3_update(&sm3, len_bytes, 2);
    sm3_update(&sm3, (unsigned char*)id, id_len);
    sm3_update(&sm3, a_bytes, 32);
    sm3_update(&sm3, b_bytes, 32);
    sm3_update(&sm3, xG_bytes, 32);
    sm3_update(&sm3, yG_bytes, 32);
    sm3_update(&sm3, xP_bytes, 32);
    sm3_update(&sm3, yP_bytes, 32);
    sm3_final(&sm3, digest);
    
    printf("digest: %s, len: %ld\n", digest, strlen((char*)digest));
ERR:
    if(a) {
        BN_free(a);
    }

	if (b) BN_free(b);
	if (xG) BN_free(xG);
	if (yG) BN_free(yG);
	if (xP) BN_free(xP);
	if (yP) BN_free(yP);
	return ret;
}

int test_gen_key()
{
	const char* input = "123qwe";
	//init
	BN_CTX* ctx = BN_CTX_new();
    EC_KEY* keypair = EC_KEY_new();
	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
	EC_KEY_set_group(keypair, group);
	EC_KEY_generate_key(keypair);

	// get public key and private key

	// EC_KEY_key2buf(keypair, POINT_CONVERSION_UNCOMPRESSED, &pubkey, ctx);
	const BIGNUM* prikey = EC_KEY_get0_private_key(keypair);
	const EC_POINT* pubkey = EC_KEY_get0_public_key(keypair);

	EC_KEY* publicKey = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_set_public_key(publicKey, pubkey);

	EC_KEY* privateKey = EC_KEY_new();
    EC_KEY_set_group(privateKey, group);
    EC_KEY_set_private_key(privateKey, prikey);

	unsigned char* endata = (unsigned char*)malloc(1024);
	size_t enlen = 128;
	unsigned char* dedata = (unsigned char*)malloc(1024);
	size_t delen = 128;
	SM2CiphertextValue *enms2 = SM2_do_encrypt(EVP_sm3(),(const unsigned char*) input, strlen(input), publicKey);
	// SM2_encrypt(NID_sm3, (const unsigned char*)input, strlen(input), (unsigned char*)endata, &enlen, publicKey);

	printf("endata:%s, len:%ld\n", endata, enlen);
    unsigned char* pout = (unsigned char*)malloc(1024);
    size_t poutlen = 1024;
    SM2CiphertextValue *enms3 = SM2CiphertextValue_new();
    i2o_SM2CiphertextValue(EC_KEY_get0_group(keypair), enms2, &pout);
    o2i_SM2CiphertextValue(EC_KEY_get0_group(keypair), EVP_sm3(), &enms3,(const unsigned char**) &pout, poutlen);

    SM2_do_decrypt(EVP_sm3(), enms2, dedata, &delen, privateKey);
	// SM2_decrypt(NID_sm3, (const unsigned char*)endata, enlen, (unsigned char*)dedata, &delen, privateKey);
	printf("result:%s, len:%ld\n", dedata, delen);

    // deinit
    EC_KEY_free(keypair);
    EC_KEY_free(publicKey);
    EC_KEY_free(privateKey);


    BN_CTX_free(ctx);

}
int main()
{
    int ret = 0;
    ret = testz();
    return ret;
}
