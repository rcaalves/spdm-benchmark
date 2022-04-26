#define RNG_REQ_CODE 1

typedef struct {
  mctp_message_header_t  MctpHeader;
  uint8  Req;
  uint64 padding;
} SECURE_SESSION_REQUEST_RNG;

typedef struct {
  mctp_message_header_t			MctpHeader;
  uint32						Rng;
} SECURE_SESSION_RESPONSE_RNG;