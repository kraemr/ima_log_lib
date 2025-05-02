#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include "../inc/types.h"
#include <stdint.h>




const uint16_t HASH_LENGTHS[] = {
    SHA_DIGEST_LENGTH,
    SHA256_DIGEST_LENGTH,
    SHA384_DIGEST_LENGTH,
    SHA512_DIGEST_LENGTH
};


uint16_t initEvpHashingCtx(EVP_MD_CTX** mdctx, uint16_t hashType ){
    (*mdctx) = EVP_MD_CTX_new();
    int32_t ret = 0;
    switch (hashType) {
        case CRYPTO_AGILE_SHA1:   ret = EVP_DigestInit_ex((*mdctx), EVP_sha1(), NULL);break;
        case CRYPTO_AGILE_SHA256: ret = EVP_DigestInit_ex((*mdctx), EVP_sha256(), NULL);break;
        case CRYPTO_AGILE_SHA384: ret = EVP_DigestInit_ex((*mdctx), EVP_sha384(), NULL);break;
        case CRYPTO_AGILE_SHA512: ret = EVP_DigestInit_ex((*mdctx), EVP_sha512(), NULL);break;
        default: return 0;
    }
    return ret;
}
    

uint16_t getHashLength(uint16_t hashType) {
    if( hashType > 3){
        return 0;
    }
    return HASH_LENGTHS[hashType];
}

