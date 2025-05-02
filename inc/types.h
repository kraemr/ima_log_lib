

#ifndef IMA_VERIFY_TYPES_H
    #define IMA_VERIFY_TYPES_H
    #include <openssl/sha.h>
    #include <openssl/evp.h>
#include <stdint.h>
    #define TEMPLATE_IMA_NG 0
    #define CRYPTO_AGILE_SHA1   0
    #define CRYPTO_AGILE_SHA256 1
    #define CRYPTO_AGILE_SHA384 2
    #define CRYPTO_AGILE_SHA512 3
    typedef struct Ima_ng {
        uint32_t hashLength;
        uint16_t hashType;
        uint8_t* hash;
        uint32_t fileNameLength;
        char* fileName;
    }Ima_ng;

    typedef struct ImaEventSha256 {
        uint32_t pcrIndex;
        uint8_t hashOfTemplate[SHA256_DIGEST_LENGTH];
        uint32_t templateNameLength;
        char templateName[16];
        uint32_t templateDataLength;
        uint8_t* templateData; // contains the hash we actually care about
    }ImaEventSha256;

    typedef struct ImaEventSha1 {
        uint32_t pcrIndex;
        uint8_t hashOfTemplate[SHA_DIGEST_LENGTH];
        uint32_t templateNameLength;
        char templateName[16];
        uint32_t templateDataLength;
        uint8_t* templateData; // contains the hash we actually care about
    }ImaEventSha1;

        typedef struct ImaEventSha384 {
        uint32_t pcrIndex;
        uint8_t hashOfTemplate[SHA384_DIGEST_LENGTH];
        uint32_t templateNameLength;
        char templateName[16];
        uint32_t templateDataLength;
        uint8_t* templateData; // contains the hash we actually care about
    }ImaEventSha384;

        typedef struct ImaEventSha512 {
        uint32_t pcrIndex;
        uint8_t hashOfTemplate[SHA512_DIGEST_LENGTH];
        uint32_t templateNameLength;
        char templateName[16];
        uint32_t templateDataLength;
        uint8_t* templateData; // contains the hash we actually care about
    }ImaEventSha512;


#endif 