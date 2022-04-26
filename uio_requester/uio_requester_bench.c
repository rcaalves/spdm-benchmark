#include <stdlib.h>
#include <stdio.h>

#include "uio_requester.h"
#include "uio_requester_aux.h"

int main(int argc, char *argv[]) {
  return_status           status = RETURN_SUCCESS;
  struct uio_requester_t  uio_requester;

  status = uio_requester_init(&uio_requester);
  CHECK_ERROR("Could not init...");

  INFO_PRINT("\nuio_requester_init_spdm");
  RESET_N_ENABLE(uio_requester.fd_cycles);
  uio_requester.spdm_context = uio_requester_init_spdm();
  DISABLE_N_READ(uio_requester.fd_cycles, "init_spdm");
  if (!uio_requester.spdm_context) {
    ERROR_PRINT("Could not init SPDM...\n");
    DONE();
  }

  INFO_PRINT("\nspdm_init_connection");
  status = uio_spdm_init_connection(&uio_requester, TRUE); // stats gathered inside
  CHECK_ERROR("spdm_init_connection() failed...");

  INFO_PRINT("\nspdm_uio_load_certificates");
  RESET_N_ENABLE(uio_requester.fd_cycles);
  status = spdm_uio_load_certificates(uio_requester.spdm_context);
  DISABLE_N_READ(uio_requester.fd_cycles, "load_certificates");
  CHECK_ERROR ("spdm_uio_load_certificates error ");

  INFO_PRINT("\ndo_authentication_via_spdm");
  status = uio_do_authentication_via_spdm (&uio_requester, TRUE); // stats gathered inside
  CHECK_ERROR ("uio_do_authentication_via_spdm error ");

  INFO_PRINT("\ndo_measurement_via_spdm");
  status = uio_do_measurement_via_spdm (&uio_requester); // stats gathered inside
  CHECK_ERROR ("do_measurement_via_spdm error");

  INFO_PRINT("\ndo_session_via_spdm no PSK");
  status = uio_do_session_via_spdm (&uio_requester, FALSE, &uio_do_rng_app_session_via_spdm); // stats gathered inside
  CHECK_ERROR ("do_session_via_spdm no PSK error");

  INFO_PRINT("\ndo_session_via_spdm PSK");
  status = uio_do_session_via_spdm (&uio_requester, TRUE, &uio_do_rng_app_session_via_spdm); // stats gathered inside
  CHECK_ERROR ("do_session_via_spdm PSK error");

  INFO_PRINT("\nuio_requester_get_random_no_spdm");
  RESET_N_ENABLE(uio_requester.fd_cycles);
  uio_requester_get_random_no_spdm();
  DISABLE_N_READ(uio_requester.fd_cycles, "get_random_no_spdm");

  return 0;
}

