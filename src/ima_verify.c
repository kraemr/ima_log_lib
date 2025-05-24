#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <tss2/tss2_tpm2_types.h>
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



void calculateQuoteStep(ImaEventSha256* eref,uint8_t pcrs[30][EVP_MAX_MD_SIZE]){
        uint32_t t = 0;
        EVP_MD_CTX* mdctx;
        initEvpHashingCtx(&mdctx,CRYPTO_AGILE_SHA256);
		EVP_DigestUpdate(mdctx,pcrs[eref->pcrIndex] ,SHA256_DIGEST_LENGTH);	
        EVP_DigestUpdate(mdctx,eref->hashOfTemplate,SHA256_DIGEST_LENGTH);
        EVP_DigestFinal_ex(mdctx, pcrs[eref->pcrIndex], &t);
        EVP_MD_CTX_free(mdctx); // probably can be optimised away */
}

int32_t verifyQuoteStep(ImaEventSha256* eref,uint8_t pcrs[30][EVP_MAX_MD_SIZE],uint8_t quoteDigest[EVP_MAX_MD_SIZE]) {
    uint8_t temp[SHA256_DIGEST_LENGTH];
    uint32_t t = 0;
    calculateQuoteStep(eref,pcrs);
    
    EVP_MD_CTX* mdctx;
    initEvpHashingCtx(&mdctx,CRYPTO_AGILE_SHA256);
	EVP_DigestUpdate(mdctx,pcrs[eref->pcrIndex] ,SHA256_DIGEST_LENGTH);	
    EVP_DigestFinal_ex(mdctx, temp, &t);
    EVP_MD_CTX_free(mdctx); // probably can be optimised away */
    printf("verifyQuoteStep pcr: ");
    displayDigest(pcrs[eref->pcrIndex], SHA256_DIGEST_LENGTH);
    printf(" quoteDigest: ");
    displayDigest(temp, SHA256_DIGEST_LENGTH);
    
    return memcmp(temp, quoteDigest, SHA256_DIGEST_LENGTH) == 0;
}


void calculateQuote(ImaEventSha256* events, uint32_t count,uint8_t pcrs[30][EVP_MAX_MD_SIZE],uint16_t hashType ){
	uint32_t outputLength = 0;
    uint16_t hashLength = getHashLength(hashType);
    EVP_MD_CTX* mdctx;
    uint8_t temp [SHA256_DIGEST_LENGTH] = {0};
    for(uint32_t i=0;i < count; i++ ) {
		ImaEventSha256* eref = &events[i];
        initEvpHashingCtx(&mdctx,hashType);
		EVP_DigestUpdate(mdctx,pcrs[eref->pcrIndex] ,hashLength);	
        EVP_DigestUpdate(mdctx,eref->hashOfTemplate,hashLength);
        EVP_DigestFinal_ex(mdctx, pcrs[eref->pcrIndex], &outputLength);
        EVP_MD_CTX_free(mdctx);


	  //  displayDigest(pcrs[10],SHA256_DIGEST_LENGTH);
    }
	
}


/*
#include <tss2/tss2_mu.h>

int32_t main(int32_t argc, char* argv[] ) {    
    int fd = open("test/bs256_1",O_RDONLY);
    uint8_t pcr[30][EVP_MAX_MD_SIZE];
    memset(pcr[10],0,EVP_MAX_MD_SIZE);

    ImaEventSha256 buf [10000] = {0};
    
    uint32_t count = readImaLog(fd,CRYPTO_AGILE_SHA256,buf,10000);
    calculateQuote(buf,count,pcr,CRYPTO_AGILE_SHA256);
    displayDigest(pcr[10], SHA256_DIGEST_LENGTH);
    memset(pcr[10],0,EVP_MAX_MD_SIZE);
    displayDigest(pcr[10], SHA256_DIGEST_LENGTH);

    for (int i = 0; i < count; i++) {
        verifyQuoteStep(&buf[i],pcr,pcr[0]);
    }

    close(fd);
    return 0;
}
*/