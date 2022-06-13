#include<stdio.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <openssl/ssl.h>
#include <unistd.h>


const int buff_size = 4096;

int main()
{
    // https://www.binarytides.com/socket-programming-c-linux-tutorial/
    int socket_desc;
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    struct sockaddr_in server;
    SSL_CTX * ctx = NULL;
    SSL * ssl = NULL;

    if (socket_desc == -1)
    {
        printf("error could not create socket");
    }

    server.sin_addr.s_addr = inet_addr("147.32.232.212");
    server.sin_family = AF_INET;
    server.sin_port = htons(443);

    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        printf("connect error\n");
        return 1;
    }

    SSL_library_init();

    ctx = SSL_CTX_new(TLS_client_method());

    if(!ctx)
    {
        printf("error setting ssl context\n");
        return 1;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl,socket_desc);
    SSL_set_tlsext_host_name(ssl, "fit.cvut.cz");

    if(SSL_connect(ssl) <= 0)
    {
        printf("error connecting ssl\n");
        return 1;
    }

    // https://wiki.openssl.org/index.php/SSL/TLS_Client
    // https://zakird.com/2013/10/13/certificate-parsing-with-openssl
    X509 * certificate = SSL_get_peer_certificate(ssl);

    FILE * certFile = fopen("cert.pem","w");
    PEM_write_X509(certFile, certificate);
    fclose(certFile);
    
    SSL_CTX_load_verify_locations(ctx,"cert.pem",NULL);
    SSL_get_verify_result(ssl);

    if(SSL_write(ssl,"GET /cs/fakulta/o-fakulte HTTP/1.1\r\nConnection: close\r\nHost: fit.cvut.cz\r\n\r\n",sizeof("GET /cs/fakulta/o-fakulte HTTP/1.1\r\nConnection: close\r\nHost: fit.cvut.cz\r\n\r\n")) <= 0)
    {
        printf("error or nothing written\n");
        return 1;
    }

    FILE * fileOutput = fopen("fit-cvut-cz.txt","w");
    if(!fileOutput)
    {
        printf("error opening output file\n");
        return 1;
    }

    unsigned char* buffer = (unsigned char*)malloc(sizeof(unsigned char) * buff_size);
    int result = 1;
    while(result != 0)
    {
        result = SSL_read(ssl, buffer, sizeof(buffer));
        fwrite(buffer, sizeof(unsigned char), result, fileOutput);
    }

    fclose(fileOutput);
    free(buffer);

    printf("success!\n");
    printf("cipher used: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));

    printf("cipher list:\n");
    buffer = NULL;
    for(int i = 0; ;i++)
    {
        buffer=(unsigned char *)SSL_get_cipher_list(ssl,i);
        if(buffer != NULL)
        {
            printf("%s\n", buffer);
        }
        else
        {
            break;
        }
    }
    
    SSL_shutdown(ssl);
    close(socket_desc);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}