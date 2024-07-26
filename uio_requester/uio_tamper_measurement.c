#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "uio_requester.h"

int main(int argc, char *argv[]) {
  libspdm_return_t          status = LIBSPDM_STATUS_SUCCESS;
  struct uio_requester_t    uio_requester;

  long measurement_number_user = 0;

  if (argc > 1) {
    measurement_number_user = strtol(argv[1], NULL, 10);
  } else {
    printf("Usage:\n");
    printf("\t%s <measurement number>\n", argv[0]);
    return -1;
  }

  status = uio_requester_init(&uio_requester);
  CHECK_ERROR("Could not init...");

  printf("\n");
  printf("Attemping to tamper device measurement #%ld...\n", measurement_number_user);
  uio_requester_write_to_tamper(measurement_number_user-1);
  printf("\n");

  return 0;
}