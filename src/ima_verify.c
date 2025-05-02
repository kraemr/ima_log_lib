#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include "../inc/ima_verify.h"

extern int32_t  parseTemplateImaNg(uint8_t* eventData,uint32_t length,Ima_ng* ref);
const uint16_t HASH_LENGTHS[] = {
    SHA_DIGEST_LENGTH,
    SHA256_DIGEST_LENGTH,
    SHA384_DIGEST_LENGTH,
    SHA512_DIGEST_LENGTH
};

// so in general an imaEvent is like this:
// Pcr index (1 byte), Hash of template (size depends) 
// ... needs types for Sha1,Sha256 for now,
void displayDigest(uint8_t *pcr, int32_t n)
{
	for (int32_t i = 0; i < n; i++)
		printf("%x", pcr[i] );
	printf("\n");
}

void displayN(uint8_t *pcr, int32_t n)
{
	for (int32_t i = 0; i < n; i++)
		printf("%c", pcr[i] );
	printf("\n");
}

// return value is the amount of events read
// type of tail depends on the hashType
uint64_t readIMALogSha256(int fd, ImaEventSha256* imaBuffer,uint32_t bufferSize, uint16_t hashType) {
    uint16_t hashLen = HASH_LENGTHS[hashType];  
    uint32_t nbytes = sizeof(uint32_t) * 2 + hashLen;
    uint32_t bytesRead =0;
    uint32_t imaCount = 0; 
    ImaEventSha256* event = NULL;
   // printf("imaCOunt = %u\n",imaCount);
    while( imaCount < bufferSize && ( read(fd,&imaBuffer[imaCount], nbytes) ) ){
        if( imaCount >= bufferSize ){
            return imaCount;
        }
        event = &imaBuffer[imaCount];
        
        bytesRead = read(fd,event->templateName,event->templateNameLength);
        bytesRead = read(fd,&event->templateDataLength,sizeof(uint32_t));
        event->templateData = (void *)malloc(event->templateDataLength * sizeof(uint8_t));
        bytesRead = read(fd,event->templateData,event->templateDataLength);
        event->parsedTemplateData = malloc(sizeof(Ima_ng) );
        parseTemplateImaNg(event->templateData,event->templateDataLength,event->parsedTemplateData);
        event->templateType = TEMPLATE_IMA_NG;
        Ima_ng test = *(Ima_ng*)event->parsedTemplateData;
        //displayDigest(event->hashOfTemplate,SHA256_DIGEST_LENGTH);
        //displayDigest(test.hashO,SHA256_DIGEST_LENGTH);
        imaCount++;
        //printf("%u %u \n",test.hashType,test.hashLength);
       // free(event->templateData);
       // free(event->parsedTemplateData);
    }
    return imaCount;
}


void calculateQuote(ImaEventSha256* events, uint32_t count,uint8_t pcrs[30][EVP_MAX_MD_SIZE] ){
	//uint8_t zeroes[EVP_MAX_MD_SIZE] = {0};
	uint32_t output_length = 0;
	//memcpy(pcrs[10],zeroes,SHA256_DIGEST_LENGTH);
    for(uint32_t i=0;i < count; i++ ) {
		ImaEventSha256* eref = &events[i];
	    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
		EVP_DigestUpdate(mdctx,pcrs[eref->pcrIndex] ,SHA256_DIGEST_LENGTH);	
        EVP_DigestUpdate(mdctx,eref->hashOfTemplate,SHA256_DIGEST_LENGTH);
        EVP_DigestFinal_ex(mdctx, pcrs[eref->pcrIndex], &output_length);
        EVP_MD_CTX_free(mdctx); // probably can be optimised away 
	}
	printf("PCR_AGGREGATE: ");
	displayDigest(pcrs[10],SHA256_DIGEST_LENGTH);
}

/*

int32_t main(int32_t argc, char* argv[] ) {
    
    int fd = open("test/binary_runtime_measurements_sha256",O_RDONLY);
    uint8_t pcr[30][EVP_MAX_MD_SIZE];
    ImaEventSha256 buf [4000] = {0};
    uint32_t count = readIMALogSha256(fd,buf,4000,CRYPTO_AGILE_SHA256);
    calculateQuote(buf,count,pcr);
    close(fd);
    return 0;
}
*/