#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cstdio>
#include <string>
#include <string.h>

using namespace std;

const int buffer_size = 4096;
const int block_size = 16;

void checkArgs(int argc, char** args)
{
    if(argc != 3)
    {
        cout << "Error: wrong argument count" << endl;
        cout << "Usage: " << args[0] << " private.pem in_file_sealed" << endl;
        exit(EXIT_FAILURE);
    }
}

EVP_PKEY * loadPrivateKey(char * file)
{
    FILE* privateKeyFile = fopen(file, "r");
    if(!privateKeyFile)
    {
        cout << "Error: opening private key file" << file << endl;
        exit(EXIT_FAILURE);
    }
    EVP_PKEY * privateKey = NULL;
    privateKey = PEM_read_PrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);
    if(privateKey == NULL)
    {
        cout << "Error: reading private key" << endl;
        exit(EXIT_FAILURE);
    }
    return privateKey;
}

FILE * openInputDataFile(char * file)
{
    FILE * fileInput = fopen(file,"r");
    if(!fileInput)
    {
        cout << "Error: opening input data file" << file << endl;
        exit(EXIT_FAILURE);
    }
    return fileInput;
}

string createFileName(char * file)
{
    string outputFileName = file;
    string extension = outputFileName.substr(outputFileName.find_last_of(".") + 1);
    unsigned int position = outputFileName.find(".");
    string extractName = (string::npos == position)? outputFileName : outputFileName.substr(0, position);
    outputFileName = extractName + "_opened." + extension;
    return outputFileName;
}

void readHead(FILE* fileInput, char* cipherName, char* cipherMode, int &keyLen, unsigned int &ivLen, unsigned char* iv, unsigned char* symEncKey, unsigned int &symEncKeyLen)
{
    if(fread(iv,sizeof(unsigned char),EVP_MAX_IV_LENGTH,fileInput) != EVP_MAX_IV_LENGTH)
    {
        cout << "Error: reading IV" << endl;
        exit(EXIT_FAILURE);
    }
    if(fread(symEncKey,sizeof(unsigned char),symEncKeyLen,fileInput) != symEncKeyLen)
    {
        cout << "Error: reading symetric key" << endl;
        exit(EXIT_FAILURE);
    }
}

void decryptAES_128_CBC(FILE * fileInput, FILE * fileOutput, EVP_PKEY * privateKey, unsigned char* symEncKey, unsigned int &symEncKeyLen, unsigned char* iv)
{
    if(!fileInput)
    {
        cout << "Error: input file is not opened" << endl;
        exit(EXIT_FAILURE);
    }
    if(!fileOutput)
    {
        cout << "Error: output file is not opened" << endl;
        exit(EXIT_FAILURE);
    }
    const EVP_CIPHER * cipher = EVP_aes_128_cbc(); 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!EVP_OpenInit(ctx, cipher, symEncKey, symEncKeyLen, iv, privateKey))
    {
        cout << "Error: OpenInit" << endl;
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_SUCCESS);
    }

    unsigned char* input;
    unsigned char* output;
    int outputLen = 0;
    int result = 1;
    input = (unsigned char*)malloc(sizeof(unsigned char)*buffer_size);
    output = (unsigned char*)malloc(sizeof(unsigned char)*buffer_size + block_size);
    while(result != 0)
    {
        result = fread(input,sizeof(unsigned char),buffer_size,fileInput);
        if(!EVP_OpenUpdate(ctx,output,&outputLen,input,result))
        {
            EVP_CIPHER_CTX_free(ctx);
            cout << "Error: decrypt open update" << endl;;
            free(input);
            free(output);
            exit(EXIT_FAILURE);
        }
        fwrite(output, sizeof(unsigned char), outputLen, fileOutput);
    }
    free(output);
    free(input);

    output = (unsigned char*)malloc(sizeof(unsigned char)*buffer_size + block_size);
    if(!EVP_OpenFinal(ctx,output,&outputLen))
    {
        EVP_CIPHER_CTX_free(ctx);
        cout << "Error: decrypt open final" << endl;
        free(output);
        exit(EXIT_FAILURE);
    }
    fwrite(output,sizeof(unsigned char),outputLen,fileOutput);
    EVP_CIPHER_CTX_free(ctx);
    free(output);
}

int main(int argc, char** args)
{
    checkArgs(argc, args);
    OpenSSL_add_all_ciphers();

    // nacteni soukromeho RSA klice
    EVP_PKEY * privateKey = loadPrivateKey(args[1]);

    unsigned int symEncKeyLen;
    unsigned char* symEncKey;
    unsigned char iv[EVP_MAX_IV_LENGTH];
    symEncKeyLen = EVP_PKEY_size(privateKey);
    symEncKey = (unsigned char *)malloc(EVP_PKEY_size(privateKey));
    unsigned int ivLen;
    int keyLen = 128;
    char* cipherName = (char*)malloc(32);
    char* cipherMode = (char*)malloc(32);

    FILE * fileInput = openInputDataFile(args[2]);
    // slozeni jmena vystupniho souboru
    string outputFileName = createFileName(args[2]);
    const char* outputFileNameArray = outputFileName.c_str();
    FILE * fileOutput = fopen(outputFileNameArray, "w");
    if(!fileOutput)
    {
        cout << "Error: opening output file" << endl;
        exit(EXIT_FAILURE);
    }

    readHead(fileInput, cipherName, cipherMode, keyLen, ivLen, iv, symEncKey, symEncKeyLen);

    decryptAES_128_CBC(fileInput, fileOutput, privateKey, symEncKey, symEncKeyLen, iv);

    fclose(fileInput);
    fclose(fileOutput);
    free(symEncKey);
    free(cipherName);
    free(cipherMode);
    EVP_PKEY_free(privateKey);


    return 0;
}
