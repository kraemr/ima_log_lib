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

// return value is the amount of events read
// type of tail depends on the hashType
uint64_t readImaLogSha256(int fd, ImaEventSha256* imaBuffer,uint32_t bufferSize) {
    uint32_t nbytes = sizeof(uint32_t) * 2 + SHA256_DIGEST_LENGTH; // pcr index 4 bytes, after that 4 bytes and the the len of the HASH    
    uint32_t bytesRead =0;
    uint32_t imaCount = 0; 
    ImaEventSha256* event = NULL;
    while( imaCount < bufferSize && ( read(fd,&imaBuffer[imaCount], nbytes) ) ){
        if( imaCount >= bufferSize ){
            return imaCount;
        }
        event = &imaBuffer[imaCount];
        bytesRead = read(fd,event->templateName,event->templateNameLength);
        bytesRead = read(fd,&event->templateDataLength,sizeof(uint32_t));
        event->templateData = (void *)malloc(event->templateDataLength * sizeof(uint8_t));
        bytesRead = read(fd,event->templateData,event->templateDataLength);
        imaCount++;
    }
    return imaCount;
}

//
uint64_t readImaLog(int fd,uint32_t hashType, ...) {
    uint64_t ret = 0;
    va_list args;
    va_start(args, hashType); 
    
    if(hashType == CRYPTO_AGILE_SHA256){
        ImaEventSha256* sha256Events = va_arg(args, ImaEventSha256*);
        uint32_t bufferSize = va_arg(args,uint32_t);
        ret =  readImaLogSha256(fd,sha256Events,bufferSize);
    }

    else if(hashType == CRYPTO_AGILE_SHA1){
        printf("SHA1 Unsupported for now");
        abort();
    }

    else if(hashType == CRYPTO_AGILE_SHA384){
        printf("SHA384 Unsupported for now");
        abort();
    }

    else if(hashType == CRYPTO_AGILE_SHA512){
        printf("SHA512 Unsupported for now");
        abort();
    }

    

    va_end(args);
    return ret;
}



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