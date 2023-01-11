#include "string.h"
#include "stdlib.h"
#include "stdio.h"
void hex_encode(const char *readbuf, char *writebuf, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        char *l = (char *)(2 * i + ((char *)writebuf));
        sprintf(l, "%02x", readbuf[i]);
    }
}

static const unsigned char acl_hex_chars[] = "0123456789ABCDEF";
/**
 * 将二进制数据进行编码，一个字节转换成两个字节后，从而转为文本字符串
 * @param ptr {const char*} 二进制数据
 * @param len {int} ptr 数据的长度
 * @return {ACL_VSTRING*} 转换结果，必须调用free释放
 */
unsigned char *acl_hex_encode(const char *in, int len)
{
    unsigned char *out = (unsigned char *)malloc(len * 2 + 1);
    int out_index = 0;
    const unsigned char *cp;
    int ch;
    int count;

    for (cp = (const unsigned char *)(in), count = len; count > 0; count--, cp++)
    {
        ch = *cp;
        out[out_index++] = acl_hex_chars[(ch >> 4) & 0xf];
        out[out_index++] = acl_hex_chars[ch & 0xf];
    }
    out[out_index] = 0;
    return (out);
}

/**
 * 将编码后的数据进行解码
 * @param ptr {const char*} 编码数据
 * @param len {int} ptr 数据长度
 * @return {ACL_VSTRING*} 解码结果:
 *              非NULL表示成功，这时必须调用free释放
 *              为NULL表示解码失败，原因是参数错误
 */
unsigned char *acl_hex_decode(const char *in, int len)
{
    unsigned char *out = (unsigned char *)malloc(len / 2 + 1);
    int out_index = 0;
    const unsigned char *cp;
    int count;
    unsigned int hex;
    unsigned int bin;

    for (cp = (const unsigned char *)(in), count = len; count > 0; cp += 2, count -= 2)
    {
        if (count < 2)
            return (0);
        hex = cp[0];
        if (hex >= '0' && hex <= '9')
            bin = (hex - '0') << 4;
        else if (hex >= 'A' && hex <= 'F')
            bin = (hex - 'A' + 10) << 4;
        else if (hex >= 'a' && hex <= 'f')
            bin = (hex - 'a' + 10) << 4;
        else
            return (0);
        hex = cp[1];
        if (hex >= '0' && hex <= '9')
            bin |= (hex - '0');
        else if (hex >= 'A' && hex <= 'F')
            bin |= (hex - 'A' + 10);
        else if (hex >= 'a' && hex <= 'f')
            bin |= (hex - 'a' + 10);
        else
            return (0);
        out[out_index++] = bin;
    }
    out[out_index] = 0;
    return out;
}

int test1()
{
    const char *in = "ddD";
    char *buf = (char *)malloc(1024);
    memset(buf, 0, 1024);
    char *dec = (char *)malloc(1024);
    memset(dec, 0, 1024);
    hex_encode((const char *)in, buf, strlen(in));
    printf("en: %s, len: %ld\n", buf, strlen(buf));
    return 0;
}

int test2()
{
    const char *key = "ddD";
    char *enc = (char *)acl_hex_encode(key, strlen(key));
    char *dec = (char *)acl_hex_decode(enc, strlen(enc));
    printf("enc: [%s], dec: [%s]\n", enc, dec);
    free(dec);
    free(enc);
    return 0;
}
int main(int argc, char** argv)
{
    // int ret = 0;
    // ret = test2();

    // const  char* in = "15z";

    // int a = (*in >> 2) & 0xf;
    // a = 47;
    // printf("%d, %x\n", a, a);
    // printf("str: %s\n", in);
    printf("argc: %d\n", argc);
    for(int i = 0; i < argc; ++i) {
        printf("%s\n", argv[i]);
    }
}