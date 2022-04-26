#include <mctp.h>
#define RNG_REQ_CODE 1

typedef struct {
  mctp_message_header_t  mctp_header;
  uint8  req;
  uint64 padding;
} SECURE_SESSION_REQUEST_RNG;

typedef struct {
  mctp_message_header_t        mctp_header;
  uint32					   rng;
} SECURE_SESSION_RESPONSE_RNG;