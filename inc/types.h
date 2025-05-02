

#ifndef IMA_VERIFY_TYPES_H
    #define IMA_VERIFY_TYPES_H
    #include <openssl/sha.h>
    #include <openssl/evp.h>
#include <stdint.h>

    #define CRYPTO_AGILE_SHA1   0
    #define CRYPTO_AGILE_SHA256 1
    #define CRYPTO_AGILE_SHA384 2
    #define CRYPTO_AGILE_SHA512 3

    #define TEMPLATE_IMA_NG 0


    typedef struct Ima_ng {
        uint32_t hashLength;
        uint16_t hashType;
        uint8_t* hash;
        uint32_t fileNameLength;
        char* fileName;
    }Ima_ng;

    typedef struct ImaEventSha256 {
        uint32_t pcrIndex;
        uint8_t hashOfTemplate[SHA256_DIGEST_LENGTH]; // This part is annoyin ... either we need to do some c++ shenanigans or we do some void* magic ...
    
        uint32_t templateNameLength;
        char templateName[16];
    
        uint32_t templateDataLength;
        void* templateData; // contains the hash we actually care about

        uint8_t templateType;
        void* parsedTemplateData; // contains a struct that points to data in templateData for easy access

    }ImaEventSha256;

    typedef struct ImaEventSha1 {
        uint32_t pcrIndex;
        uint8_t hashOfTemplate[SHA_DIGEST_LENGTH]; // This part is annoyin ... either we need to do some c++ shenanigans or we do some void* magic ...
    
        uint32_t templateNameLength;
        char templateName[16];
    
        uint32_t templateDataLength;
        void* templateData; // contains the hash we actually care about

        uint8_t templateType;
        void* parsedTemplateData; // contains a struct that points to data in templateData for easy access

    }ImaEventSha1;

#endif 