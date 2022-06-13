#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>


unsigned char byteTurnOver(unsigned char byte)
{
	unsigned char res = 0;
	for (int i = 0; i < 8; i++)
	{
		res <<= 1;
		res += byte % 2;
		byte >>= 1;
	}
	return res;
}

int nullBitCount(unsigned char* hash)
{
	int res = 0;
	while (*hash == 0)
	{
		res += 8;
		hash++;
	}
	unsigned char turnOver = byteTurnOver(*hash);
	while (turnOver)
	{
		if (turnOver % 2 == 0)
		{
			res++;
			turnOver /= 2;
		}
		else
			break;
	}
	return res;
}

int main (int argc, char * argv[])
{
	if (argc != 2)
	{
		printf("Invalid arg count.\n");
		return 1;
	}
    
	int bitsNeeded;
	if (sscanf(argv[1], "%d", &bitsNeeded) != 1)
	{
		printf("Arg must be a number.\n");
		return 1;
	}

	char text[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	char hashFunction[] = "sha384";

	EVP_MD_CTX * ctx;
	const EVP_MD * type;
	unsigned char hash[EVP_MAX_MD_SIZE];

	OpenSSL_add_all_digests();
	type = EVP_get_digestbyname(hashFunction);
	ctx = EVP_MD_CTX_new();

	if (!type)
    {
		printf("Hash function %s does not exist.\n", hashFunction);
		return 1;
	}

	if (ctx == NULL)
		return 2;

	long long int i = 0;
	long long int upperBound = 9223372036854775807;
	unsigned int length;
	bool hashFound = false;

	while (i < upperBound)
	{
		if (!EVP_DigestInit_ex(ctx, type, NULL))
		{
			EVP_MD_CTX_free(ctx);
			return 3;
		}

		sprintf(text, "%lld", i);
		
		if (!EVP_DigestUpdate(ctx, text, strlen(text)))
		{
			EVP_MD_CTX_free(ctx);
			return 4;
		}

		if (!EVP_DigestFinal_ex(ctx, hash, &length))
		{
			EVP_MD_CTX_free(ctx);
			return 5;
		}
		
		if (nullBitCount(hash) >= bitsNeeded)
		{
            printf("Text in hex form: ");
            for(unsigned int j = 0; j < strlen(text); j++)
                printf("%02x", text[j]);
            printf("\n");
            printf("Hash: ");
			for (unsigned int i = 0; i < length; i++)
				printf("%02x", hash[i]);
			printf("\n");
			hashFound = true;
			break;
		}
		i++;
	}

	if(!hashFound)
		printf("Upper limit has been reached! Hash not found.\n");

	EVP_MD_CTX_free(ctx);
	return 0;
}