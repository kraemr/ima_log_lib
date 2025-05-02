#include "../inc/types.h"
#include <unistd.h>



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
