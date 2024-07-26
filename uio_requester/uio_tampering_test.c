#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "uio_requester.h"
#include "uio_requester_aux.h"

int main(int argc, char *argv[]) {
  libspdm_return_t          status = LIBSPDM_STATUS_SUCCESS;
  struct uio_requester_t    uio_requester;

  uint8_t measurement_buf_before[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
  uint8_t measurement_buf_after[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
  size_t  measurement_size_before, measurement_size_after;

  printf("Establishing SPDM session... ");

  status = uio_requester_init(&uio_requester);
  CHECK_ERROR("Could not init...");

  uio_requester.spdm_context = uio_requester_init_spdm();
  if (!uio_requester.spdm_context) {
    ERROR_PRINT("Could not init SPDM...\n");
    DONE();
  }
  status = uio_spdm_init_connection(&uio_requester, false); // stats gathered inside
  CHECK_ERROR("spdm_init_connection() failed...");
  status = spdm_uio_load_certificates(uio_requester.spdm_context);
  CHECK_ERROR ("spdm_uio_load_certificates error ");
  status = uio_do_authentication_via_spdm (&uio_requester, false); // stats gathered inside
  CHECK_ERROR ("uio_do_authentication_via_spdm error ");
  printf("OK\n");

  printf("\n");
  printf("Getting device measurement:\n");
  measurement_size_before = sizeof(measurement_buf_before);
  memset(&measurement_buf_before, 0, measurement_size_before);
  status = get_measurement_to_buffer(&uio_requester, 1, (uint8_t*) measurement_buf_before, &measurement_size_before);
  CHECK_ERROR ("get_measurement_to_buffer ERROR");
  print_measurement((spdm_measurement_block_dmtf_t *)measurement_buf_before);

  printf("\n");
  printf("Tampering device... ");
  uio_requester_write_to_tamper(0);
  printf("OK\n");

  printf("\n");
  printf("Getting device measurements after tampering:\n");
  measurement_size_after = sizeof(measurement_buf_after);
  memset(&measurement_buf_after, 0, measurement_size_after);
  status = get_measurement_to_buffer(&uio_requester, 1, (uint8_t*) measurement_buf_after, &measurement_size_after);
  CHECK_ERROR ("get_measurement_to_buffer ERROR");
  print_measurement((spdm_measurement_block_dmtf_t *)measurement_buf_after);

  printf("\n");
  if (measurement_size_before != measurement_size_after ||
      memcmp(measurement_buf_before, measurement_buf_after, measurement_size_before) != 0)
    printf("Measurements mismatch!\n");
  else
    printf("Measurements did not change...\n");

  return 0;
}
