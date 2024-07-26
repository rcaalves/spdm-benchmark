#include "uio_requester_aux.h"
#include "spdm_requester_lib.h"
#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "uio_spdm_rng.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

libspdm_return_t
uio_spdm_init_connection (
      void                 *opaque,
      char                 collect_stats
  )
{
  libspdm_return_t          status;
  libspdm_context_t         *spdm_context;
  struct uio_requester_t *uior;

  uior = opaque;
  spdm_context = uior->spdm_context;

  if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
  status = libspdm_get_version (spdm_context, NULL, NULL);
  if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "get_version"); }
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    return status;
  }

  if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
  status = libspdm_get_capabilities (spdm_context);
  if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "get_capabilities"); }
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    return status;
  }

  if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
  status = libspdm_negotiate_algorithms (spdm_context);
  if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "negotiate_algorithms"); }
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    return status;
  }

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t
uio_do_authentication_via_spdm (
  void *opaque,
  char  collect_stats
  )
{
  libspdm_return_t        status;
  uint8_t                 slot_mask;
  uint8_t                 total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
  uint8_t                 measurement_hash[LIBSPDM_MAX_HASH_SIZE];
  size_t                  cert_chain_size;
  uint8_t                 cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
  libspdm_context_t       *spdm_context;
  struct uio_requester_t  *uior;

  uior = opaque;
  spdm_context = uior->spdm_context;

  if ((spdm_context->local_context.capability.flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) != 0) {
    if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
    libspdm_zero_mem (total_digest_buffer, sizeof(total_digest_buffer));
    status = libspdm_get_digest (spdm_context, NULL, &slot_mask, total_digest_buffer);
    if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "get_digest"); }
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
      return status;
    }

    if (m_use_slot_id != 0xFF) {
      if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
      cert_chain_size = sizeof(cert_chain);
      libspdm_zero_mem (cert_chain, sizeof(cert_chain));
      status = libspdm_get_certificate (spdm_context, NULL, m_use_slot_id, &cert_chain_size, cert_chain);
      if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "get_certificate"); }
      if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
      }
    }
  }

  if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
  libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
  status = libspdm_challenge (spdm_context, NULL, m_use_slot_id, m_use_measurement_summary_hash_type, measurement_hash, &slot_mask);
  if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "challenge"); }
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    return status;
  }

  // status = spdm_authentication (
  //            spdm_context,
  //            &slot_mask,
  //            &total_digest_buffer,
  //            m_use_slot_id,
  //            &cert_chain_size,
  //            cert_chain,
  //            m_use_measurement_summary_hash_type,
  //            measurement_hash
  //            );
  // if (RETURN_ERROR(status)) {
  //   return status;
  // }
  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t
uio_do_measurement_via_spdm (
  void *opaque
  )
{
  libspdm_return_t        status;
  uint8_t                 number_of_blocks;
  uint8_t                 number_of_block;
  uint32_t                measurement_record_length;
  uint8_t                 measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
  uint8_t                 index;
  uint8_t                 request_attribute;
  uint8_t                 content_changed;
  void                    *spdm_context;
  struct uio_requester_t  *uior;

  uior = opaque;
  spdm_context = uior->spdm_context;

  // if (m_use_measurement_operation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
    //
    // request all at one time.
    //
  RESET_N_ENABLE(uior->fd_cycles);
  request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
  measurement_record_length = sizeof(measurement_record);
  status = libspdm_get_measurement (
             spdm_context,
             NULL,
             request_attribute,
             SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
             m_use_slot_id & 0xF,
             &content_changed,
             &number_of_block,
             &measurement_record_length,
             measurement_record
             );
  DISABLE_N_READ(uior->fd_cycles, "get_measurement_all");
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    return status;
  }
  // } else {
  RESET_N_ENABLE(uior->fd_cycles);
  request_attribute = 0;
  //
  // 1. query the total number of measurements available.
  //
  status = libspdm_get_measurement (
            spdm_context,
            NULL,
            request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
            m_use_slot_id & 0xF,
            NULL,
            &number_of_blocks,
            NULL,
            NULL
            );

  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    return status;
  }
  LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "number_of_blocks - 0x%x\n", number_of_blocks));
  for (index = 1; index <= number_of_blocks; index++) {
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "index - 0x%x\n", index));
    // there 3 mesurements at specific indexes (0x10, 0xFD, 0xFE) which are not contiguous
    uint8_t temp_index = index;
    if (temp_index == number_of_blocks - 2)
      temp_index = LIBSPDM_MEASUREMENT_INDEX_SVN;
    if (temp_index == number_of_blocks - 1)
      temp_index = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST;
    if (temp_index == number_of_blocks)
      temp_index = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_DEVICE_MODE;
    //
    // 2. query measurement one by one
    // get signature in last message only.
    //
    if (index == number_of_blocks) {
      request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    }
    measurement_record_length = sizeof(measurement_record);
    status = libspdm_get_measurement (
              spdm_context,
              NULL,
              request_attribute,
              temp_index,
              m_use_slot_id & 0xF,
              &content_changed,
              &number_of_block,
              &measurement_record_length,
              measurement_record
              );
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
      return status;
    }
  }
  DISABLE_N_READ(uior->fd_cycles, "get_measurement_one_by_one");
  // }

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t get_measurement_to_buffer(void *opaque, uint8_t index, uint8_t *out_buf, size_t *buf_len) {
  libspdm_return_t               status;
  uint8_t                        number_of_block;
  uint32_t                       measurement_record_length;
  uint8_t                        measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
  uint8_t                        request_attribute;
  uint8_t                        content_changed;
  void                            *spdm_context;
  struct                          uio_requester_t *uior;
  int                             attempts = 0;

  uior = opaque;
  spdm_context = uior->spdm_context;

  request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
  measurement_record_length = sizeof(measurement_record);

  // transcript may be out of sync, so we try more than once
  do {
    status = libspdm_get_measurement (
          spdm_context,
          NULL,
          request_attribute,
          index,
          m_use_slot_id & 0xF,
          &content_changed,
          &number_of_block,
          &measurement_record_length,
          measurement_record
          );
  } while(LIBSPDM_STATUS_IS_ERROR(status) && attempts < 3);

  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    *buf_len = 0;
  } else {
    *buf_len = LIBSPDM_MIN(*buf_len, measurement_record_length);
    memcpy(out_buf, measurement_record, *buf_len);
  }

  return status;
}

typedef struct {
  libspdm_data_type_t        data_type;
  char                    *string;
} DATA_TYPE_STRING;

spdm_vendor_defined_request_mine_t  m_vendor_defined_request = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_VENDOR_DEFINED_REQUEST,
    0, // Param1
    0, // Param2
  },
  SPDM_REGISTRY_ID_PCISIG, // standardID
  2, // len
  SPDM_VENDOR_ID_PCISIG, // vendorID
  sizeof(pci_protocol_header_t) + sizeof(pci_ide_km_query_t), // payload_length
  {
    PCI_PROTOCOL_ID_IDE_KM,
  },
  {
    {
      PCI_IDE_KM_OBJECT_ID_QUERY,
    },
    0, // Reserved
    0, // port_index
  }
};

secure_session_request_mine_t  m_secure_session_request = {
  {
    MCTP_MESSAGE_TYPE_PLDM
  },
  {
    0x80,
    PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY,
    PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID,
  },
};

SECURE_SESSION_REQUEST_RNG m_secure_rng_request = {
  {
    MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI
  },
  RNG_REQ_CODE,
};

libspdm_return_t
uio_do_app_session_via_spdm (
  void                            *spdm_context,
  uint32_t                          session_id
  )
{
  libspdm_return_t                      status = LIBSPDM_STATUS_SUCCESS;
  spdm_vendor_defined_request_mine_t    request;
  size_t                                request_size;
  spdm_vendor_defined_response_mine_t   response;
  size_t                                response_size;
  secure_session_response_mine_t        app_response;
  size_t                                app_response_size;

  if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
    libspdm_copy_mem (&request, sizeof(request), &m_vendor_defined_request, sizeof(m_vendor_defined_request));

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = libspdm_send_receive_data (spdm_context, &session_id, false, &request, request_size, &response, &response_size);
    LIBSPDM_ASSERT (LIBSPDM_STATUS_IS_SUCCESS(status));

    LIBSPDM_ASSERT (response_size == sizeof(spdm_vendor_defined_response_mine_t));
    LIBSPDM_ASSERT (response.header.request_response_code == SPDM_VENDOR_DEFINED_RESPONSE);
    LIBSPDM_ASSERT (response.standard_id == SPDM_REGISTRY_ID_PCISIG);
    LIBSPDM_ASSERT (response.vendor_id == SPDM_VENDOR_ID_PCISIG);
    LIBSPDM_ASSERT (response.payload_length == sizeof(pci_protocol_header_t) + sizeof(pci_ide_km_query_resp_t));
    LIBSPDM_ASSERT (response.pci_protocol.protocol_id == PCI_PROTOCOL_ID_IDE_KM);
    LIBSPDM_ASSERT (response.pci_ide_km_query_resp.header.object_id == PCI_IDE_KM_OBJECT_ID_QUERY_RESP);
  }

  if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
    app_response_size = sizeof(app_response);
    status = libspdm_send_receive_data (spdm_context, &session_id, true, &m_secure_session_request, sizeof(m_secure_session_request), &app_response, &app_response_size);
    LIBSPDM_ASSERT(LIBSPDM_STATUS_IS_SUCCESS(status));

    LIBSPDM_ASSERT (app_response_size == sizeof(app_response));
    LIBSPDM_ASSERT (app_response.mctp_header.message_type == MCTP_MESSAGE_TYPE_PLDM);
    LIBSPDM_ASSERT (app_response.pldm_header.pldm_type == PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY);
    LIBSPDM_ASSERT (app_response.pldm_header.pldm_command_code == PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID);
    LIBSPDM_ASSERT (app_response.pldm_response_header.pldm_completion_code == PLDM_BASE_CODE_SUCCESS);
  }

  return status;
}

libspdm_return_t
uio_do_rng_app_session_via_spdm (
  void                            *spdm_context,
  uint32_t                        session_id
  )
{
  libspdm_return_t                   status = LIBSPDM_STATUS_INVALID_PARAMETER;
  SECURE_SESSION_RESPONSE_RNG        app_response_rng;
  size_t                             app_response_size;

  if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
    app_response_size = sizeof(app_response_rng);
    INFO_PRINT("Request random number\n");
    status = libspdm_send_receive_data (spdm_context, &session_id, true, &m_secure_rng_request, sizeof(m_secure_rng_request), &app_response_rng, &app_response_size);
    INFO_PRINT("Received random number is %d\n", app_response_rng.rng);
  } else {
    printf("NOT IMPLEMENTED\n");
  }

  return status;
}

libspdm_return_t
uio_do_session_via_spdm (
  void                 *opaque,
  bool                  use_psk,
  // bool              update_key,
  app_fun_t             app_fun
  )
{
  libspdm_return_t                    status = LIBSPDM_STATUS_SUCCESS;
  uint32_t                            session_id;
  uint8_t                             heartbeat_period;
  uint8_t                             measurement_hash[LIBSPDM_MAX_HASH_SIZE];
  libspdm_session_info_t              *session_info;
  uint8_t                             req_slot_id_param;
  void                                *spdm_context;
  struct                              uio_requester_t *uior;
  char                                label[100];

  uior = opaque;
  spdm_context = uior->spdm_context;

  heartbeat_period = 0;
  libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

  if (!use_psk) {
    RESET_N_ENABLE(uior->fd_cycles);
    status = libspdm_send_receive_key_exchange (spdm_context, m_use_measurement_summary_hash_type, m_use_slot_id, m_session_policy, &session_id, &heartbeat_period, &req_slot_id_param, measurement_hash);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
      LIBSPDM_DEBUG ((LIBSPDM_DEBUG_INFO, "Spdm_start_session - spdm_send_receive_key_exchange - %p\n", status));
      return status;
    }

    session_info = libspdm_get_session_info_via_session_id (spdm_context, session_id);
    // DISABLE_N_READ(uior->fd_cycles, "Key_exchange_noPSK");
    if (session_info == NULL) {
      LIBSPDM_ASSERT (false);
      return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    switch (session_info->mut_auth_requested) {
    case 0:
      break;
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED:
      break;
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST:
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS:
      // RESET_N_ENABLE(uior->fd_cycles);
      status = libspdm_encapsulated_request (spdm_context, &session_id, session_info->mut_auth_requested, &req_slot_id_param);
      // DISABLE_N_READ(uior->fd_cycles, "Mutual_auth");
      LIBSPDM_DEBUG ((LIBSPDM_DEBUG_INFO, "spdm_start_session - spdm_encapsulated_request - %p\n", status));
      if (LIBSPDM_STATUS_IS_ERROR(status)) {
        printf("spdm_start_session - spdm_encapsulated_request - fail %x\n", status);
        return status;
      }
      break;
    default:
      printf("spdm_start_session - unknown mut_auth_requested - 0x%x\n", session_info->mut_auth_requested);
      fflush(stdout);
      LIBSPDM_DEBUG ((LIBSPDM_DEBUG_INFO, "spdm_start_session - unknown mut_auth_requested - 0x%x\n", session_info->mut_auth_requested));
      return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    DISABLE_N_READ(uior->fd_cycles, "key_exchange");

    if (req_slot_id_param == 0xF) {
      req_slot_id_param = 0xFF;
    }
    RESET_N_ENABLE(uior->fd_cycles);
    status = libspdm_send_receive_finish (spdm_context, session_id, req_slot_id_param);
    DISABLE_N_READ(uior->fd_cycles, "finish");
    LIBSPDM_DEBUG ((LIBSPDM_DEBUG_INFO, "spdm_start_session - spdm_send_receive_finish - %p\n", status));
  } else {
    RESET_N_ENABLE(uior->fd_cycles);
    status = libspdm_send_receive_psk_exchange (spdm_context, LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING), m_use_measurement_summary_hash_type, m_session_policy, &session_id, &heartbeat_period, measurement_hash);
    DISABLE_N_READ(uior->fd_cycles, "key_exchangePSK");
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
      LIBSPDM_DEBUG ((LIBSPDM_DEBUG_INFO, "spdm_start_session - spdm_send_receive_psk_exchange - %p\n", status));
      return status;
    }
    if (libspdm_is_capabilities_flag_supported(spdm_context, true, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
      RESET_N_ENABLE(uior->fd_cycles);
      status = libspdm_send_receive_psk_finish (spdm_context, session_id);
      DISABLE_N_READ(uior->fd_cycles, "finishPSK");
      LIBSPDM_DEBUG ((LIBSPDM_DEBUG_INFO, "spdm_start_session - spdm_send_receive_psk_finish - %p\n", status));
    }
  }

  // spdm_start_session was dismembered to allow measuring each message timing
  // status = spdm_start_session (
  //            spdm_context,
  //            use_psk,
  //            m_use_measurement_summary_hash_type,
  //            m_use_slot_id,
  //            &session_id,
  //            &heartbeat_period,
  //            measurement_hash
  //            );
  // if (RETURN_ERROR(status)) {
  //   ERROR_PRINT ("Spdm_start_session - %x\n", (uint32_t)status);
  //   return status;
  // }

  // app_fun (spdm_context, session_id);

  strcpy(label, "heartbeat");
  if (use_psk) strcat(label, "PSK"); else strcat(label, "NoPSK");
  RESET_N_ENABLE(uior->fd_cycles);
  status = libspdm_heartbeat (spdm_context, session_id);
  DISABLE_N_READ(uior->fd_cycles, label);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    ERROR_PRINT ("spdm_heartbeat - %x\n", (uint32_t)status);
  }

  // if (update_key) {
  strcpy(label, "key_update");
  if (use_psk) strcat(label, "PSK"); else strcat(label, "NoPSK");
  RESET_N_ENABLE(uior->fd_cycles);
  status = libspdm_key_update (spdm_context, session_id, true);
  DISABLE_N_READ(uior->fd_cycles, label);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    ERROR_PRINT ("spdm_key_update - %x\n", (uint32_t)status);
  }
  // }

  strcpy(label, "get_random_spdm");
  if (use_psk) strcat(label, "PSK"); else strcat(label, "NoPSK");
  RESET_N_ENABLE(uior->fd_cycles);
  app_fun (spdm_context, session_id);
  DISABLE_N_READ(uior->fd_cycles, label);

  strcpy(label, "end_session");
  if (use_psk) strcat(label, "PSK"); else strcat(label, "NoPSK");
  RESET_N_ENABLE(uior->fd_cycles);
  status = libspdm_stop_session (spdm_context, session_id, 0);
  DISABLE_N_READ(uior->fd_cycles, label);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    ERROR_PRINT ("spdm_stop_session - %x\n", (uint32_t)status);
    return status;
  }

  return status;
}

size_t print_measurement(spdm_measurement_block_dmtf_t *measurement_block_dmtf) {
  unsigned int i;
  size_t total_size = 0;
  total_size += printf("\tmeasurement %u:\n", measurement_block_dmtf->measurement_block_common_header.index);
  total_size += printf("\t0x%X 0x%X %u\n", measurement_block_dmtf->measurement_block_common_header.measurement_specification,
                        measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_type,
                        measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
  printf("\t");
  for (i = 0; i < measurement_block_dmtf->measurement_block_dmtf_header.dmtf_spec_measurement_value_size; i++) {
    total_size += printf("%02X ", ((uint8_t*)(measurement_block_dmtf+1))[i]);
    if ( (i+1) % 16 == 0 )
      total_size += printf("\n\t");
  }
  return total_size;
}

libspdm_return_t
spdm_uio_load_certificates (void*  spdm_context) {
  // libspdm_return_t                status;
  uint8_t                     index;
  bool                        res;
  void                        *data;
  size_t                      data_size;
  libspdm_data_parameter_t    parameter;
  uint8_t                     data8;
  uint16_t                    data16;
  uint32_t                    data32;
  void                        *hash;
  size_t                      hash_size;

  libspdm_zero_mem (&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

  data_size = sizeof(data32);
  libspdm_get_data (spdm_context, LIBSPDM_DATA_CONNECTION_STATE, &parameter, &data32, &data_size);
  LIBSPDM_ASSERT (data32 == LIBSPDM_CONNECTION_STATE_NEGOTIATED);

  data_size = sizeof(data32);
  libspdm_get_data (spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &data32, &data_size);
  m_use_measurement_hash_algo = data32;
  data_size = sizeof(data32);
  libspdm_get_data (spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, &data_size);
  m_use_asym_algo = data32;
  data_size = sizeof(data32);
  libspdm_get_data (spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, &data_size);
  m_use_hash_algo = data32;
  data_size = sizeof(data16);
  libspdm_get_data (spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, &data_size);
  m_use_req_asym_algo = data16;


  const uint8_t* cert_buffer;
  size_t cert_buffer_size;
  res = libspdm_read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
  // printf("%d %d\n", m_use_hash_algo, m_use_asym_algo);
  // DUMP_ARRAY("libspdm_read_responder_public_certificate_chain", data, data_size);

  res = libspdm_x509_get_cert_from_cert_chain(data,
                                                       data_size, -1,
                                                       &cert_buffer, &cert_buffer_size);

  if (m_use_slot_id == 0xFF) {
    if (res) {
      libspdm_zero_mem (&parameter, sizeof(parameter));
      parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
      libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_KEY /*LIBSPDM_DATA_PEER_PUBLIC_CERT_CHAIN*/, &parameter, data, data_size);
      // do not free it.
    } else {
      ERROR_PRINT("==============\t read_responder_public_certificate_chain ERROR \t==============\n");
      return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
  } else {
    res = libspdm_read_responder_root_public_certificate (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
    if (res) {
      libspdm_zero_mem (&parameter, sizeof(parameter));
      parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
      libspdm_set_data (spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT /*_HASH*/, &parameter, hash, hash_size);
      // do not free it.
    } else {
      ERROR_PRINT("==============\t read_responder_root_public_certificate ERROR \t==============\n");
      return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
  }

  res = libspdm_read_requester_public_certificate_chain (m_use_hash_algo, m_use_req_asym_algo, &data, &data_size, NULL, NULL);
  if (res) {
    libspdm_zero_mem (&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    data8 = 0;
    for (index = 0; index < m_use_slot_count; index++) {
      data8 |= (1 << index);
    }
    libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, &parameter, &data8, sizeof(data8));

    for (index = 0; index < m_use_slot_count; index++) {
      parameter.additional_data[0] = index;
      libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, data, data_size);
    }
    // do not free it
  } else {
    ERROR_PRINT("==============\t read_requester_public_certificate_chain ERROR \t==============\n");
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  return LIBSPDM_STATUS_SUCCESS;

}
