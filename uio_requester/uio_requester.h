#include"spdm_common_lib.h"
#include "uio_requester_aux.h"

return_status uio_requester_init (struct uio_requester_t *uior);
void *uio_requester_init_spdm (void);
void uio_requester_get_random_no_spdm();
void uio_requester_write_to_tamper(uint32_t);

#define DONE() \
  do { \
    if (uio_requester.spdm_context) free(uio_requester.spdm_context); \
    close(uio_requester.fd_cycles); \
    close(uio_requester.fd_taskclock); \
    close(uio_requester.fd_instructions); \
    INFO_PRINT("Finish\n"); \
    if (RETURN_ERROR(status)) { \
      ERROR_PRINT("(with errors)\n"); \
      return -1; \
    } \
    return 0; \
  } while(0)

#define CHECK_ERROR(str_print) \
  do { \
    if (RETURN_ERROR(status)) { \
      ERROR_PRINT (str_print); ERROR_PRINT (" - %x\n", (uint32)status); \
      DONE(); \
    } \
  } while (0)
