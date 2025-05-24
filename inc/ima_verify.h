
#include "types.h"
#include <stdint.h>
extern uint16_t initEvpHashingCtx(EVP_MD_CTX** mdctx, uint16_t hashType );
extern uint64_t readImaLog(int fd,uint32_t hashType, ...);
extern void calculateQuote(ImaEventSha256* events, uint32_t count,uint8_t pcrs[30][EVP_MAX_MD_SIZE],uint16_t hashType );
extern int32_t verifyQuoteStep(ImaEventSha256* eref,uint8_t pcrs[30][EVP_MAX_MD_SIZE],uint8_t quoteDigest[EVP_MAX_MD_SIZE]);