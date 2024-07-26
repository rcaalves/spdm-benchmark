#define RNG_REQ_CODE 1

typedef struct {
  mctp_message_header_t  MctpHeader;
  uint8_t  Req;
  uint64_t padding;
} rng_secure_session_request_t;

typedef struct {
  mctp_message_header_t			MctpHeader;
  uint32_t						Rng;
} rng_secure_session_response_t;