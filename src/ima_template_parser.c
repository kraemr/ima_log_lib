
/*
ima_ng has: hashlen 4byte, hash of hashlen length,
*/
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>
#include "../inc/types.h"

const int HASH_TYPES_LENGTH = 2;
const char* HASH_TYPES[] = {
    "sha1:\0",
    "sha256:\0",
};


uint32_t castToUint32(uint8_t* buf){
    return buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
}

// receives sha1\0 for example, return would be CRYPTO_AGILE_SHA1
uint16_t detectHashType(uint8_t* buf) {
    for(uint16_t i = 0; i < HASH_TYPES_LENGTH; i++ ){
        uint8_t nbytes = strlen(HASH_TYPES[i]) + 1; // we also count nul byte

        if(strcmp(HASH_TYPES[i],(char*)buf) == 0) {
            return i; // i corresponds to the defined CRYPTO_AGILE values
        }
    
    }
    return UINT16_MAX;
}

// parses the eventData as Ima-Ng
// non 0 return means error
int32_t  parseTemplateImaNg(uint8_t* eventData,uint32_t length,Ima_ng* ref){
    uint32_t offset = 0;
    
    ref->hashLength = castToUint32(&eventData[offset]);
    offset += 4;
    ref->hashType = detectHashType(&eventData[offset]);
    
    if(ref->hashType != UINT16_MAX ){
        ref->hashLength -= ( strlen(HASH_TYPES[ref->hashType]) + 1 );
    }else{
        return 1;
    }
    offset += (strlen(HASH_TYPES[ref->hashType]) + 1);
    ref->hash = &eventData[offset];
    offset += ref->hashLength;    
    ref->fileNameLength = castToUint32(&eventData[offset]);
    offset += 4;
    ref->fileName = (char*)&eventData[offset];
    return 0;
}