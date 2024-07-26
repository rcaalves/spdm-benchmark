#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "uio_requester.h"
#include "uio_requester_aux.h"
#include "spdm_requester_lib.h"
#include "spdm_crypt_ext_lib/spdm_crypt_ext_lib.h"

int main(int argc, char *argv[]) {
  libspdm_return_t           status = LIBSPDM_STATUS_SUCCESS;
  struct uio_requester_t  uio_requester;
  uint8_t measurement_buf_retrieved[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
  uint8_t *measurement_buf_file;
  size_t measurement_size_retrieved;
  size_t measurement_size_file;
  spdm_measurement_block_dmtf_t *measurement_block_dmtf;
  long measurement_number_user = 0;
  uint8_t number_of_blocks;
  uint8_t request_attribute;
  uint8_t content_changed;
  int i, attempts = 0;

  measurement_size_file = 0;

  if (argc > 1) {
    measurement_number_user = strtol(argv[1], NULL, 10);
  }

  if (argc > 2) {
    if (!libspdm_read_input_file(argv[2], (void**)&measurement_buf_file, &measurement_size_file))
      return -1;

    printf("Contents of input measurement file (%s) is:\n\t", argv[2]);
    for (i = 0; i < measurement_size_file; i++) {
      printf("%02X ", measurement_buf_file[i]);
      if ( (i+1) % 16 == 0 )
        printf("\n\t");
    }
  } else {
    printf("Warning: no reference measurement file given.\n");
  }

  printf("\n");
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
  printf("Retrieving number of measurements...\n");
  request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
  // transcript may be out of sync, so we try more than once
  do {
    status = libspdm_get_measurement (
          uio_requester.spdm_context,
          NULL,
          request_attribute,
          SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
          m_use_slot_id & 0xF,
          &content_changed,
          &number_of_blocks,
          NULL,
          NULL
          );
  } while(LIBSPDM_STATUS_IS_ERROR(status) && attempts < 3);

  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    ERROR_PRINT("Could not get number of measurements (%X)\n", status);
    return status;
  }
  printf("\tDevice contains %d measurements\n", number_of_blocks);

  if (measurement_number_user > number_of_blocks || measurement_number_user < 1) {
    printf("User requested measurement #%ld, which is not available.\n", measurement_number_user);
    return -1;
  }

  printf("\n");
  printf("User requested measurement #%ld. Its content is:\n", measurement_number_user);
  measurement_size_retrieved = sizeof(measurement_buf_retrieved);
  memset(&measurement_buf_retrieved, 0, measurement_size_retrieved);
  status = get_measurement_to_buffer(&uio_requester, measurement_number_user, (uint8_t*) measurement_buf_retrieved, &measurement_size_retrieved);
  CHECK_ERROR ("get_measurement_to_buffer ERROR");
  measurement_block_dmtf = (spdm_measurement_block_dmtf_t *)measurement_buf_retrieved;
  print_measurement(measurement_block_dmtf);

  if (measurement_block_dmtf->measurement_block_common_header.measurement_specification !=
      SPDM_MEASUREMENT_SPECIFICATION_DMTF) {
    printf("Measurement specification unknown (0x%X)\n", measurement_block_dmtf->measurement_block_common_header.measurement_specification);
    return -1;
  }

  if (!measurement_size_file) {
    return 0;
  }

  if (!(measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_type &
      SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM)) {
    INFO_PRINT("Should calculate hash from file content\n");
    libspdm_data_parameter_t parameter;
    uint32_t measurement_hash_algo;
    size_t data_size = sizeof(measurement_hash_algo);
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    uint8_t hash[128];
    size_t hash_size;

    libspdm_get_data(uio_requester.spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &measurement_hash_algo, &data_size);
    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);

    libspdm_measurement_hash_all(measurement_hash_algo, measurement_buf_file, measurement_size_file, hash);
    memcpy(measurement_buf_file, hash, hash_size);
    measurement_size_file = hash_size;
    for (i = 0; i < measurement_size_file; i++) {
      INFO_PRINT("%02X ", measurement_buf_file[i]);
      if ( (i+1) % 16 == 0 )
        INFO_PRINT("\n");
    }
    INFO_PRINT("\n");
  }


  if (measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_size != measurement_size_file ||
      memcmp(((uint8_t*)(measurement_block_dmtf+1)), measurement_buf_file, measurement_size_file) != 0)
    printf("\nMeasurements mismatch!\n\n");
  else
    printf("\nMeasurement from file and retrieved measurement match!\n\n");

  return 0;
}