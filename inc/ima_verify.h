#include "types.h"

extern uint64_t readIMALogSha256(int fd, ImaEventSha256* imaBuffer,uint32_t bufferSize, uint16_t hashType);
extern void calculateQuote(ImaEventSha256* events, uint32_t count,uint8_t pcrs[30][EVP_MAX_MD_SIZE] );
