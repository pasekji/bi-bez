#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cstdio>
#include <string>

using namespace std;

const int buffer_size = 4096;
const int block_size = 16;

void checkArgs(int argc, char** args)
{
    if(argc != 3)
    {
        cout << "Error: wrong argument count" << endl;
        cout << "Usage: " << args[0] << " public.pem in_file" << endl;
        exit(EXIT_FAILURE);
    }
}

EVP_PKEY * loadPublicKey(char * file)
{
    FILE* publicKeyFile = fopen(file, "r");
    if(!publicKeyFile)
    {
        cout << "Error: opening public key file" << file << endl;
        exit(EXIT_FAILURE);
    }
    EVP_PKEY * publicKey = NULL;
    publicKey = PEM_read_PUBKEY(publicKeyFile, NULL, NULL, NULL);
    fclose(publicKeyFile);
    if(publicKey == NULL)
    {
        cout << "Error: reading public key" << endl;
        exit(EXIT_FAILURE);
    }
    return publicKey;
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

FILE * openOutputDataFile(char * file)
{
    FILE * fileOutput = fopen(file,"w");
    if(!fileOutput)
    {
        cout << "Error: opening output data file" << file << endl;
        exit(EXIT_FAILURE);
    }
    return fileOutput;
}

string createFileName(char * file)
{
    string outputFileName = file;
    string extension = outputFileName.substr(outputFileName.find_last_of(".") + 1);
    unsigned int position = outputFileName.find(".");
    string extractName = (string::npos == position)? outputFileName : outputFileName.substr(0, position);
    outputFileName = extractName + "_sealed." + extension;
    return outputFileName;
}

void encryptAES_128_CBC(EVP_PKEY * publicKey, FILE * fileOutput, FILE * fileInput, unsigned char* symEncKey, int &symEncKeyLen, unsigned char* iv, const char* cipherName, const char* cipherMode, const unsigned int keyLen)
{
    if(!fileInput)
    {
        cout << "Error: input file is not opened" << endl;
        exit(EXIT_FAILURE);
    }
    if(!fileOutput)
    {
        cout << "Error: temp file is not opened" << endl;
        exit(EXIT_FAILURE);
    }
    const EVP_CIPHER * cipher = EVP_aes_128_cbc(); 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // sifrovani symetrickeho klice
    if(!EVP_SealInit(ctx, cipher, &symEncKey, &symEncKeyLen, iv, &publicKey, 1))
    {
        EVP_CIPHER_CTX_free(ctx);
        cout << "Error: SealInit" << endl;
        exit(EXIT_FAILURE);
    }

    fwrite(iv,sizeof(unsigned char),EVP_MAX_IV_LENGTH,fileOutput);
    fwrite(symEncKey,sizeof(unsigned char),symEncKeyLen,fileOutput);

    // sealupdate na jednotlive chunky vstupnich dat
    unsigned char* input;
    unsigned char* output;
    int outputLen = 0;
    int result = 1;
    input = (unsigned char*)malloc(sizeof(unsigned char)*buffer_size);
    output = (unsigned char*)malloc(sizeof(unsigned char)*buffer_size + block_size);
    while(result != 0)
    {
        result = fread(input,sizeof(unsigned char),buffer_size,fileInput);
        if(!EVP_SealUpdate(ctx,output,&outputLen,input,result))
        {
            EVP_CIPHER_CTX_free(ctx);
            cout << "Error: encrypt seal update" << endl;;
            free(output);
            free(input);
            exit(EXIT_FAILURE);
        }
        fwrite(output, sizeof(unsigned char), outputLen, fileOutput);
    }
    free(output);
    free(input);

    // zapis final do temp souboru
    output = (unsigned char*)malloc(sizeof(unsigned char)*buffer_size + block_size);
    if(!EVP_SealFinal(ctx,output,&outputLen)) 
    {
        EVP_CIPHER_CTX_free(ctx);
        cout << "Error: encrypt seal final" << endl;
        free(output);
        exit(EXIT_FAILURE);
    }
    fwrite(output, sizeof(unsigned char), outputLen, fileOutput);
    EVP_CIPHER_CTX_free(ctx);
    free(output);
}


int main(int argc, char** args)
{

    checkArgs(argc, args);
    OpenSSL_add_all_ciphers();

    // nacteni verejneho RSA klice
    EVP_PKEY * publicKey = loadPublicKey(args[1]); 

    // otevreni vstupniho datoveho souboru
    FILE * fileInput = openInputDataFile(args[2]);

    // inicializace
    unsigned char* symEncKey = (unsigned char*)malloc(EVP_PKEY_size(publicKey));
    const unsigned int keyLen = 128;
    const char* cipherName = "AES";
    const char* cipherMode = "CBC";
    int symEncKeyLen;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    // slozeni jmena vystupniho souboru
    string outputFileNameS = createFileName(args[2]);
    const char* outputFileName = outputFileNameS.c_str();
    char* outputFileNameArray = strdup(outputFileName);
    FILE * fileOutput = openOutputDataFile(outputFileNameArray);

    // sifrovani
    encryptAES_128_CBC(publicKey, fileOutput, fileInput, symEncKey, symEncKeyLen, iv, cipherName, cipherMode, keyLen);

    fclose(fileInput);
    fclose(fileOutput);
    free(symEncKey);
    free(outputFileNameArray);
    EVP_PKEY_free(publicKey);

    return 0;

}