#include <mctp.h>
#define RNG_REQ_CODE 1

typedef struct {
  mctp_message_header_t  mctp_header;
  uint8_t  req;
  uint64_t padding;
} SECURE_SESSION_REQUEST_RNG;

typedef struct {
  mctp_message_header_t        mctp_header;
  uint32_t					   rng;
} SECURE_SESSION_RESPONSE_RNG;