int pfx_trans()
{
    int ret = 0;
    int i = 0;
    int len = 0;
    int nwrite = 0;
    int nread = 0;
    int port = 0;
    int timeo = 0;
    
    char buf[4096] = {0};
    char outbuffer[4096] = {0};
    char pfxpath[1024] = {0};
    char ip[32] = {0};
    char password[64] = {0};
    char servername[256] = {0};

    printf("\n");
    printf("<------------开始使用外传 pfx 进行TLS通信------------>\n");
    printf("请输入pfx的路径含文件名：\n");
    scanf("%s", pfxpath);
    printf("输入的pfx的路径含文件名为：%s\n", pfxpath);
    printf("请输入pfx的保存密码：\n");
    scanf("%s", password);
    printf("请输入指定服务器名称指示（SNI）：\n");
    scanf("%s", servername);
    printf("输入的指定服务器名称指示为：%s\n", servername);
    printf("请输入要设定的超时时间：\n");
    scanf("%d", &timeo);
    printf("输入的超时时间为：%d\n", timeo);
    printf("请输入连接对端的ip：\n");
    scanf("%s", ip);
    printf("输入的连接对端的ip为：%s\n", ip);
    printf("请输入连接对端的端口号：\n");
    scanf("%d", &port);
    printf("输入的连接对端的端口号为：%d\n", port);
    const char *mypfxpath = "/usrdata/jit5g/t2.pfx";
    const char *mypassword = "111111";
    const char *myip = "101.132.251.234";
    const char* myservername = "certapi-pki-uat.carobo.cn";
    int myport = 18444;
    while (1)
    {
        void *tlsctx = NULL;
        uint32_t verify_result = 0;
        // ret = jitiot_tls_connect_pfx(&tlsctx, &verify_result, ip, port, servername, timeo, pfxpath, password);
        sleep(1);
        ret = jitiot_tls_connect_pfx(&tlsctx, &verify_result, myip, myport, myservername, timeo, mypfxpath, mypassword);
        if (ret == 0)
        {
            printf("<------------建立连接成功------------>\n");
        }
        else
        {
            printf("<------------建立连接失败------------>\n");
            printf("错误码[0x%08x]\n", ret);
            continue;
        }
        len = sprintf((char *)buf, GET_REQUEST);
        printf("传输的数据为：%s\n", buf);
        printf("<------------开始进行数据传输------------>\n");
        ret = postData(tlsctx, nwrite, buf, strlen(buf), outbuffer, sizeof(outbuffer), &nread);
        if (ret == 0)
        {
            printf("<------------读取响应数据成功------------>\n");
            printf("响应数据内容为：\n");
            printf("%s\n", outbuffer);
            memset(outbuffer, 0, sizeof(outbuffer));
        }
        ret = jitiot_tls_free(tlsctx);
        if (ret == 0)
        {
            printf("<------------断开TLS连接并释放资源成功------------>\n");
        }
        else
        {
            printf("<------------释放资源失败------------>\n");
            printf("错误码[0x%08x]\n", ret);
            continue;
        }
    }

    printf("<------------完成使用外传 pfx 进行TLS通信------------>\n");
    return 0;
}
