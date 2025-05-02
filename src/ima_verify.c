#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include "../inc/ima_verify.h"

extern int32_t  parseTemplateImaNg(uint8_t* eventData,uint32_t length,Ima_ng* ref);
extern uint16_t getHashLength(uint16_t hashType);
extern uint16_t initEvpHashingCtx(EVP_MD_CTX** mdctx, uint16_t hashType );

void displayDigest(uint8_t *pcr, int32_t n)
{
	for (int32_t i = 0; i < n; i++)
		printf("%x", pcr[i] );
	printf("\n");
}



void calculateQuote(ImaEventSha256* events, uint32_t count,uint8_t pcrs[30][EVP_MAX_MD_SIZE],uint16_t hashType ){
	uint32_t outputLength = 0;
    uint16_t hashLength = getHashLength(hashType);
    EVP_MD_CTX* mdctx;
    for(uint32_t i=0;i < count; i++ ) {
		ImaEventSha256* eref = &events[i];
        initEvpHashingCtx(&mdctx,hashType);
		EVP_DigestUpdate(mdctx,pcrs[eref->pcrIndex] ,hashLength);	
        EVP_DigestUpdate(mdctx,eref->hashOfTemplate,hashLength);
        EVP_DigestFinal_ex(mdctx, pcrs[eref->pcrIndex], &outputLength);
        EVP_MD_CTX_free(mdctx); // probably can be optimised away 
	}
	displayDigest(pcrs[10],SHA256_DIGEST_LENGTH);
}


/*

int32_t main(int32_t argc, char* argv[] ) {
    
    int fd = open("test/binary_runtime_measurements_sha256",O_RDONLY);
    uint8_t pcr[30][EVP_MAX_MD_SIZE];
    ImaEventSha256 buf [4000] = {0};
    uint32_t count = readImaLog(fd,CRYPTO_AGILE_SHA256,buf,4000);
    calculateQuote(buf,count,pcr,CRYPTO_AGILE_SHA256);
    close(fd);
    return 0;
}
*/