// Jiří Pašek (pasekji1)
// kompilace: g++ -Wall -pedantic img-enc-dec.cpp -o img-enc-dec -lcrypto 
// použití: ./img-enc-dec [encrypt/decrypt] [ecb/cbc] vstupni_soubor vystupni_soubor

#include <openssl/evp.h>
#include <string.h>
#include <iostream>
#include <fstream>

using namespace std;

typedef struct
{
	char  idlength;
	char  colourmaptype;
	char  datatypecode;
	short int colourmaporigin;
	short int colourmaplength;
	char  colourmapdepth;
	short int x_origin;
	short int y_origin;
	short width;
	short height;
	char  bitsperpixel;
	char  imagedescriptor;
} HEADER;

unsigned char key[EVP_MAX_KEY_LENGTH] = "desne tajnej klic";
unsigned char iv[EVP_MAX_IV_LENGTH] = "init vector";


int main(int argc, char** args)
{
	if (argc != 5)
	{
		cout << "Wrong number of arguments." << endl;
		exit(1);
	}
	string direction = args[1];
	string mode = args[2];
	string filename = args[3];
	string ouputFileName = args[4];

	bool encrypt;
	if (direction == "encrypt")
		encrypt = true;
	else if (direction == "decrypt")
		encrypt = false;
	else
	{
		cout << "Wrong arg1" << endl;
		exit(1);
	}
	bool ecb;
	if (mode == "ecb")
		ecb = true;
	else if (mode == "cbc")
		ecb = false;
	else
	{
		cout << "Wrong arg2" << endl;
		exit(1);
	}

	std::fstream fhout;

	const char* filenm = filename.c_str();
	FILE * fh = fopen(filenm,"r");
	
	if(!fh)
	{
		cout << "error opening input file" << endl;
		exit(1);
	}

	HEADER header;
	fread((char*)&header, sizeof(header), 1, fh);

	int colourMapSize;
	if (header.colourmaptype == 0)
		colourMapSize = 0;
	else if (header.colourmaptype == 1)
		colourMapSize = header.colourmaplength*header.colourmapdepth/8;
	else
	{
		cout << "Color Map Type field contains either 0 or 1. ";
		exit(1);
	}
	int skipSize = header.idlength + colourMapSize;
	int imageBytesSize;
	unsigned char* skippedBytes = (unsigned char*)malloc(sizeof(unsigned char)*skipSize);
	fread(skippedBytes, sizeof(unsigned char), skipSize, fh);
	unsigned char* imageBytes = (unsigned char*)malloc(sizeof(unsigned char)*2048);
	fhout.open(ouputFileName, std::fstream::out | std::fstream::binary);
	if(!fhout.is_open())
	{
		cout << "error opening output file" << endl;
		exit(1);
	}	
	fhout.write((char*)&header, sizeof(header));
	fhout.write((char*)skippedBytes, skipSize);
	unsigned char* output; 
	int outputsize = 0;
	unsigned int result = 1;

	if (encrypt)
	{
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		if(!EVP_EncryptInit_ex(ctx, ecb ? EVP_aes_128_ecb() : EVP_aes_128_cbc(), NULL, key, iv))
		{
			EVP_CIPHER_CTX_free(ctx);
			cout << "ecrypt init fail" << endl;
			free(skippedBytes);
			free(imageBytes);
			exit(1); 	
		}
		while(result != 0)
		{
			result = fread(imageBytes,sizeof(unsigned char),2048,fh);
			imageBytesSize = result;
			output = (unsigned char*)malloc(sizeof(unsigned char)*2048);
			if(!EVP_EncryptUpdate(ctx, output, &outputsize, imageBytes, imageBytesSize))
			{
				EVP_CIPHER_CTX_free(ctx);
				cout << "ecrypt update fail" << endl;
				free(skippedBytes);
				free(imageBytes);
				free(output);
				exit(1);
			}
			if(fhout.good() && fhout.is_open())
			{
				fhout.write((char*)output, outputsize);
			}
			else
			{
				cout << "output stream failed" << endl;
				EVP_CIPHER_CTX_free(ctx);
				free(skippedBytes);
				free(imageBytes);
				free(output);
				fhout.close();
				exit(1);
			}
			free(output);
		}

		output = (unsigned char*)malloc(sizeof(unsigned char)*2048);
		if(!EVP_EncryptFinal(ctx, output, &outputsize))
		{
			EVP_CIPHER_CTX_free(ctx);
			cout << "ecrypt final fail" << endl;	
		}

		if(fhout.good() && fhout.is_open())
			fhout.write((char*)output, outputsize);
		else
		{
			cout << "output stream failed" << endl;
			EVP_CIPHER_CTX_free(ctx);
			free(skippedBytes);
			free(imageBytes);
			free(output);
			fhout.close();
			exit(1);
		}
		free(output);
		EVP_CIPHER_CTX_free(ctx);
	}
	else
	{
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		if(!EVP_DecryptInit_ex(ctx, ecb ? EVP_aes_128_ecb() : EVP_aes_128_cbc(), NULL, key, iv))
		{
			EVP_CIPHER_CTX_free(ctx);
			cout << "decrypt init fail" << endl;
			free(skippedBytes);
			free(imageBytes);
			exit(1); 	
		}
		while(result != 0)
		{
			result = fread(imageBytes,sizeof(unsigned char),2048,fh);
			imageBytesSize = result;
			output = (unsigned char*)malloc(sizeof(unsigned char)*2148);
			if(!EVP_DecryptUpdate(ctx, output, &outputsize, imageBytes, imageBytesSize))
			{
				EVP_CIPHER_CTX_free(ctx);
				cout << "decrypt update fail" << endl;
				free(skippedBytes);
				free(imageBytes);
				free(output);
				exit(1);
			}
			if(fhout.good() && fhout.is_open())
			{
				fhout.write((char*)output, outputsize);
			}
			else
			{
				cout << "output stream failed" << endl;
				EVP_CIPHER_CTX_free(ctx);
				free(skippedBytes);
				free(imageBytes);
				free(output);
				fhout.close();
				exit(1);
			}
			free(output);
		}

		output = (unsigned char*)malloc(sizeof(unsigned char)*2148);
		if(!EVP_DecryptFinal(ctx, output, &outputsize))
		{
			EVP_CIPHER_CTX_free(ctx);
			cout << "decrypt final fail" << endl;	
		}
		if(fhout.good() && fhout.is_open())
			fhout.write((char*)output, outputsize);
		else
		{
			cout << "output stream failed" << endl;
			EVP_CIPHER_CTX_free(ctx);
			free(skippedBytes);
			free(imageBytes);
			free(output);
			fhout.close();
			exit(1);
		}
		free(output);
		EVP_CIPHER_CTX_free(ctx);
	}
	free(skippedBytes);
	free(imageBytes);

	return 0;
}
