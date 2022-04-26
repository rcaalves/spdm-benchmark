#include "uio_requester_aux.h"
#include "spdm_requester_lib.h"
#include "spdm_requester_lib_internal.h"
#include "spdm_device_secret_lib_internal.h"
#include "uio_spdm_rng.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

return_status
uio_spdm_init_connection (
  IN     void                 *opaque,
  IN     char                 collect_stats
  )
{
  return_status          status;
  spdm_context_t         *spdm_context;
  struct uio_requester_t *uior;

  uior = opaque;
  spdm_context = uior->spdm_context;

  if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
  status = spdm_get_version (spdm_context);
  if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "get_version"); }
  if (RETURN_ERROR(status)) {
    return status;
  }

  if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
  status = spdm_get_capabilities (spdm_context);
  if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "get_capabilities"); }
  if (RETURN_ERROR(status)) {
    return status;
  }

  if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
  status = spdm_negotiate_algorithms (spdm_context);
  if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "negotiate_algorithms"); }
  if (RETURN_ERROR(status)) {
    return status;
  }

  return RETURN_SUCCESS;
}

return_status
uio_do_authentication_via_spdm (
  IN void *opaque,
  IN char  collect_stats
  )
{
  return_status         status;
  uint8                 slot_mask;
  uint8                 total_digest_buffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];
  uint8                 measurement_hash[MAX_HASH_SIZE];
  uintn                 cert_chain_size;
  uint8                 cert_chain[MAX_SPDM_CERT_CHAIN_SIZE];
  spdm_context_t        *spdm_context;
  struct uio_requester_t *uior;

  uior = opaque;
  spdm_context = uior->spdm_context;

  if ((spdm_context->local_context.capability.flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) != 0) {
    if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
    zero_mem (total_digest_buffer, sizeof(total_digest_buffer));
    status = spdm_get_digest (spdm_context, &slot_mask, total_digest_buffer);
    if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "get_digest"); }
    if (RETURN_ERROR(status)) {
      return status;
    }

    if (m_use_slot_id != 0xFF) {
      if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
      cert_chain_size = sizeof(cert_chain);
      zero_mem (cert_chain, sizeof(cert_chain));
      status = spdm_get_certificate (spdm_context, m_use_slot_id, &cert_chain_size, cert_chain);
      if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "get_certificate"); }
      if (RETURN_ERROR(status)) {
        return status;
      }
    }
  }

  if(collect_stats) { RESET_N_ENABLE(uior->fd_cycles); }
  zero_mem (measurement_hash, sizeof(measurement_hash));
  status = spdm_challenge (spdm_context, m_use_slot_id, m_use_measurement_summary_hash_type, measurement_hash);
  if(collect_stats) { DISABLE_N_READ(uior->fd_cycles, "challenge"); }
  if (RETURN_ERROR(status)) {
    return status;
  }

  return RETURN_SUCCESS;
}

return_status
uio_do_measurement_via_spdm (
  IN void *opaque
  )
{
  return_status                             status;
  uint8                                     number_of_blocks;
  uint8                                     number_of_block;
  uint32                                    measurement_record_length;
  uint8                                     measurement_record[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
  uint8                                     index;
  uint8                                     request_attribute;
  void *spdm_context;
  struct uio_requester_t *uior;

  uior = opaque;
  spdm_context = uior->spdm_context;

  RESET_N_ENABLE(uior->fd_cycles);
  request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
  measurement_record_length = sizeof(measurement_record);
  status = spdm_get_measurement (
             spdm_context,
             NULL,
             request_attribute,
             SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
             m_use_slot_id & 0xF,
             &number_of_block,
             &measurement_record_length,
             measurement_record
             );
  DISABLE_N_READ(uior->fd_cycles, "get_measurement_all");
  if (RETURN_ERROR(status)) {
    return status;
  }
  // } else {
  RESET_N_ENABLE(uior->fd_cycles);
  request_attribute = 0;
  //
  // 1. query the total number of measurements available.
  //
  status = spdm_get_measurement (
            spdm_context,
            NULL,
            request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
            m_use_slot_id & 0xF,
            &number_of_blocks,
            NULL,
            NULL
            );

  if (RETURN_ERROR(status)) {
    return status;
  }
  DEBUG((DEBUG_INFO, "number_of_blocks - 0x%x\n", number_of_blocks));
  for (index = 1; index <= number_of_blocks; index++) {
    DEBUG((DEBUG_INFO, "index - 0x%x\n", index));
    //
    // 2. query measurement one by one
    // get signature in last message only.
    //
    if (index == number_of_blocks) {
      request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    }
    measurement_record_length = sizeof(measurement_record);
    status = spdm_get_measurement (
              spdm_context,
              NULL,
              request_attribute,
              index,
              m_use_slot_id & 0xF,
              &number_of_block,
              &measurement_record_length,
              measurement_record
              );
    if (RETURN_ERROR(status)) {
      return status;
    }
  }
  DISABLE_N_READ(uior->fd_cycles, "get_measurement_one_by_one");

  return RETURN_SUCCESS;
}

return_status get_measurement_to_buffer(void *opaque, uint8 index, uint8 *out_buf, size_t *buf_len) {
  return_status                             status;
  uint8                                     number_of_block;
  uint32                                    measurement_record_length;
  uint8                                     measurement_record[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
  uint8                                     request_attribute;

  void *spdm_context;
  struct uio_requester_t *uior;
  int attempts = 0;

  uior = opaque;
  spdm_context = uior->spdm_context;


  request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
  measurement_record_length = sizeof(measurement_record);

  // transcript may be out of sync, so we try more than once
  do {
    status = spdm_get_measurement (
          spdm_context,
          NULL,
          request_attribute,
          index,
          m_use_slot_id & 0xF,
          &number_of_block,
          &measurement_record_length,
          measurement_record
          );
  } while(RETURN_ERROR(status) && attempts < 3);

  if (RETURN_ERROR(status)) {
    *buf_len = 0;
  } else {
    *buf_len = MIN(*buf_len, measurement_record_length);
    memcpy(out_buf, measurement_record, *buf_len);
  }

  return status;
}

typedef struct {
  spdm_data_type_t        data_type;
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
    PCI_PROTOCAL_ID_IDE_KM,
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

return_status
uio_do_app_session_via_spdm (
  IN void                            *spdm_context,
  IN uint32                          session_id
  )
{
  return_status                       status = RETURN_SUCCESS;
  spdm_vendor_defined_request_mine_t  request;
  uintn                               request_size;
  spdm_vendor_defined_response_mine_t response;
  uintn                               response_size;
  secure_session_response_mine_t      app_response;
  uintn                               app_response_size;

  if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
    copy_mem (&request, &m_vendor_defined_request, sizeof(request));

    request_size = sizeof(request);
    response_size = sizeof(response);
    status = spdm_send_receive_data (spdm_context, &session_id, FALSE, &request, request_size, &response, &response_size);
    ASSERT_RETURN_ERROR(status);

    ASSERT (response_size == sizeof(spdm_vendor_defined_response_mine_t));
    ASSERT (response.header.request_response_code == SPDM_VENDOR_DEFINED_RESPONSE);
    ASSERT (response.standard_id == SPDM_REGISTRY_ID_PCISIG);
    ASSERT (response.vendor_id == SPDM_VENDOR_ID_PCISIG);
    ASSERT (response.payload_length == sizeof(pci_protocol_header_t) + sizeof(pci_ide_km_query_resp_t));
    ASSERT (response.pci_protocol.protocol_id == PCI_PROTOCAL_ID_IDE_KM);
    ASSERT (response.pci_ide_km_query_resp.header.object_id == PCI_IDE_KM_OBJECT_ID_QUERY_RESP);
  }

  if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
    app_response_size = sizeof(app_response);
    status = spdm_send_receive_data (spdm_context, &session_id, TRUE, &m_secure_session_request, sizeof(m_secure_session_request), &app_response, &app_response_size);
    ASSERT_RETURN_ERROR(status);

    ASSERT (app_response_size == sizeof(app_response));
    ASSERT (app_response.mctp_header.message_type == MCTP_MESSAGE_TYPE_PLDM);
    ASSERT (app_response.pldm_header.pldm_type == PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY);
    ASSERT (app_response.pldm_header.pldm_command_code == PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID);
    ASSERT (app_response.pldm_response_header.pldm_completion_code == PLDM_BASE_CODE_SUCCESS);
  }

  return status;
}

return_status
uio_do_rng_app_session_via_spdm (
  IN void                            *spdm_context,
  IN uint32                          session_id
  )
{
  return_status                      status = RETURN_ERROR(RETURN_DEVICE_ERROR);
  SECURE_SESSION_RESPONSE_RNG        app_response_rng;
  uintn                              app_response_size;

  if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
    app_response_size = sizeof(app_response_rng);
    INFO_PRINT("Request random number\n");
    status = spdm_send_receive_data (spdm_context, &session_id, TRUE, &m_secure_rng_request, sizeof(m_secure_rng_request), &app_response_rng, &app_response_size);
    INFO_PRINT("Received random number is %d\n", app_response_rng.rng);
  } else {
    printf("NOT IMPLEMENTED\n");
  }

  return status;
}

return_status
uio_do_session_via_spdm (
  IN void                 *opaque,
  IN boolean              use_psk,
  // IN boolean              update_key,
  IN app_fun_t             app_fun
  )
{
  return_status                    status = RETURN_SUCCESS;
  uint32                           session_id;
  uint8                            heartbeat_period;
  uint8                            measurement_hash[MAX_HASH_SIZE];
  spdm_session_info_t              *session_info;
  uint8                            req_slot_id_param;
  void *spdm_context;
  struct uio_requester_t *uior;
  char label[100];

  uior = opaque;
  spdm_context = uior->spdm_context;

  heartbeat_period = 0;
  zero_mem(measurement_hash, sizeof(measurement_hash));

  if (!use_psk) {
    RESET_N_ENABLE(uior->fd_cycles);
    status = spdm_send_receive_key_exchange (spdm_context, m_use_measurement_summary_hash_type, m_use_slot_id, &session_id, &heartbeat_period, &req_slot_id_param, measurement_hash);
    if (RETURN_ERROR(status)) {
      DEBUG ((DEBUG_INFO, "Spdm_start_session - spdm_send_receive_key_exchange - %p\n", status));
      return status;
    }

    session_info = spdm_get_session_info_via_session_id (spdm_context, session_id);
    if (session_info == NULL) {
      ASSERT (FALSE);
      return RETURN_UNSUPPORTED;
    }

    switch (session_info->mut_auth_requested) {
    case 0:
      break;
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED:
      break;
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST:
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS:
      status = spdm_encapsulated_request (spdm_context, &session_id, session_info->mut_auth_requested, &req_slot_id_param);
      DEBUG ((DEBUG_INFO, "spdm_start_session - spdm_encapsulated_request - %p\n", status));
      if (RETURN_ERROR(status)) {
        return status;
      }
      break;
    default:
      DEBUG ((DEBUG_INFO, "spdm_start_session - unknown mut_auth_requested - 0x%x\n", session_info->mut_auth_requested));
      return RETURN_UNSUPPORTED;
    }

    DISABLE_N_READ(uior->fd_cycles, "key_exchange");

    if (req_slot_id_param == 0xF) {
      req_slot_id_param = 0xFF;
    }
    RESET_N_ENABLE(uior->fd_cycles);
    status = spdm_send_receive_finish (spdm_context, session_id, req_slot_id_param);
    DISABLE_N_READ(uior->fd_cycles, "finish");
    DEBUG ((DEBUG_INFO, "spdm_start_session - spdm_send_receive_finish - %p\n", status));
  } else {
    RESET_N_ENABLE(uior->fd_cycles);
    status = spdm_send_receive_psk_exchange (spdm_context, m_use_measurement_summary_hash_type, &session_id, &heartbeat_period, measurement_hash);
    DISABLE_N_READ(uior->fd_cycles, "key_exchangePSK");
    if (RETURN_ERROR(status)) {
      DEBUG ((DEBUG_INFO, "spdm_start_session - spdm_send_receive_psk_exchange - %p\n", status));
      return status;
    }
    if (spdm_is_capabilities_flag_supported(spdm_context, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
      RESET_N_ENABLE(uior->fd_cycles);
      status = spdm_send_receive_psk_finish (spdm_context, session_id);
      DISABLE_N_READ(uior->fd_cycles, "finishPSK");
      DEBUG ((DEBUG_INFO, "spdm_start_session - spdm_send_receive_psk_finish - %p\n", status));
    }
  }

  strcpy(label, "heartbeat");
  if (use_psk) strcat(label, "PSK"); else strcat(label, "NoPSK");
  RESET_N_ENABLE(uior->fd_cycles);
  status = spdm_heartbeat (spdm_context, session_id);
  DISABLE_N_READ(uior->fd_cycles, label);
  if (RETURN_ERROR(status)) {
    ERROR_PRINT ("spdm_heartbeat - %x\n", (uint32)status);
  }

  strcpy(label, "key_update");
  if (use_psk) strcat(label, "PSK"); else strcat(label, "NoPSK");
  RESET_N_ENABLE(uior->fd_cycles);
  status = spdm_key_update (spdm_context, session_id, TRUE);
  DISABLE_N_READ(uior->fd_cycles, label);
  if (RETURN_ERROR(status)) {
    ERROR_PRINT ("spdm_key_update - %x\n", (uint32)status);
  }

  strcpy(label, "get_random_spdm");
  if (use_psk) strcat(label, "PSK"); else strcat(label, "NoPSK");
  RESET_N_ENABLE(uior->fd_cycles);
  app_fun (spdm_context, session_id);
  DISABLE_N_READ(uior->fd_cycles, label);

  strcpy(label, "end_session");
  if (use_psk) strcat(label, "PSK"); else strcat(label, "NoPSK");
  RESET_N_ENABLE(uior->fd_cycles);
  status = spdm_stop_session (spdm_context, session_id, 0);
  DISABLE_N_READ(uior->fd_cycles, label);
  if (RETURN_ERROR(status)) {
    ERROR_PRINT ("spdm_stop_session - %x\n", (uint32)status);
    return status;
  }

  return status;
}

size_t print_measurement(spdm_measurement_block_dmtf_t *measurement_block_dmtf) {
  unsigned int i;
  size_t total_size = 0;
  total_size += printf("\tmeasurement %u:\n", measurement_block_dmtf->Measurement_block_common_header.index);
  total_size += printf("\t0x%X 0x%X %u\n", measurement_block_dmtf->Measurement_block_common_header.measurement_specification,
                        measurement_block_dmtf->Measurement_block_dmtf_header.dmtf_spec_measurement_value_type,
                        measurement_block_dmtf->Measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
  printf("\t");
  for (i = 0; i < measurement_block_dmtf->Measurement_block_dmtf_header.dmtf_spec_measurement_value_size; i++) {
    total_size += printf("%02X ", ((uint8*)(measurement_block_dmtf+1))[i]);
    if ( (i+1) % 16 == 0 )
      total_size += printf("\n\t");
  }
  return total_size;
}

return_status
spdm_uio_load_certificates (
  IN void*  spdm_context
  )
{
  uint8                        index;
  return_status                status;
  boolean                      res;
  void                         *data;
  uintn                        data_size;
  spdm_data_parameter_t          parameter;
  uint8                        data8;
  uint16                       data16;
  uint32                       data32;
  void                         *hash;
  uintn                        hash_size;

  zero_mem (&parameter, sizeof(parameter));
  parameter.location = SPDM_DATA_LOCATION_CONNECTION;

  data_size = sizeof(data32);
  spdm_get_data (spdm_context, SPDM_DATA_CONNECTION_STATE, &parameter, &data32, &data_size);
  ASSERT (data32 == SPDM_CONNECTION_STATE_NEGOTIATED);

  data_size = sizeof(data32);
  spdm_get_data (spdm_context, SPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &data32, &data_size);
  m_use_measurement_hash_algo = data32;
  data_size = sizeof(data32);
  spdm_get_data (spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, &data_size);
  m_use_asym_algo = data32;
  data_size = sizeof(data32);
  spdm_get_data (spdm_context, SPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, &data_size);
  m_use_hash_algo = data32;
  data_size = sizeof(data16);
  spdm_get_data (spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, &data_size);
  m_use_req_asym_algo = data16;

  if (m_use_slot_id == 0xFF) {
    res = read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
    if (res) {
      zero_mem (&parameter, sizeof(parameter));
      parameter.location = SPDM_DATA_LOCATION_LOCAL;
      spdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_CERT_CHAIN, &parameter, data, data_size);
      // do not free it.
    } else {
      ERROR_PRINT("==============\t read_responder_public_certificate_chain ERROR \t==============\n");
      return RETURN_DEVICE_ERROR;
    }
  } else {
    res = read_responder_root_public_certificate (m_use_hash_algo, m_use_asym_algo, &data, &data_size, &hash, &hash_size);
    if (res) {
      zero_mem (&parameter, sizeof(parameter));
      parameter.location = SPDM_DATA_LOCATION_LOCAL;
      spdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_ROOT_CERT_HASH, &parameter, hash, hash_size);
      // do not free it.
    } else {
      ERROR_PRINT("==============\t read_responder_root_public_certificate ERROR \t==============\n");
      return RETURN_DEVICE_ERROR;
    }
  }

  res = read_requester_public_certificate_chain (m_use_hash_algo, m_use_req_asym_algo, &data, &data_size, NULL, NULL);
  if (res) {
    zero_mem (&parameter, sizeof(parameter));
    parameter.location = SPDM_DATA_LOCATION_LOCAL;
    data8 = m_use_slot_count;
    spdm_set_data (spdm_context, SPDM_DATA_LOCAL_SLOT_COUNT /*spdm_data_local_slot_count*/, &parameter, &data8, sizeof(data8));

    for (index = 0; index < m_use_slot_count; index++) {
      parameter.additional_data[0] = index;
      spdm_set_data (spdm_context, SPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, data, data_size);
    }
    // do not free it
  } else {
    ERROR_PRINT("==============\t read_requester_public_certificate_chain ERROR \t==============\n");
    return RETURN_DEVICE_ERROR;
  }

  status = spdm_set_data (spdm_context, SPDM_DATA_PSK_HINT, NULL, TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  if (RETURN_ERROR(status)) {
    ERROR_PRINT ("spdm_set_data error - %x\n", (uint32)status);
    return RETURN_DEVICE_ERROR;
  }
  return RETURN_SUCCESS;

}
