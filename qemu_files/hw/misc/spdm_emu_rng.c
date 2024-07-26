/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

// #include "spdm_emu.h"
#include <library/spdm_transport_mctp_lib.h>

#define SOCKET_TRANSPORT_TYPE_MCTP 0x01
#define SOCKET_TRANSPORT_TYPE_PCI_DOE 0x02

extern uint32_t m_use_transport_layer;

extern uint8_t m_use_version;
extern uint8_t m_use_secured_message_version;
extern uint32_t m_use_requester_capability_flags;
extern uint32_t m_use_responder_capability_flags;

extern uint32_t m_use_capability_flags;
extern uint8_t m_use_basic_mut_auth;
extern uint8_t m_use_mut_auth;
extern uint8_t m_use_measurement_summary_hash_type;
extern uint8_t m_use_measurement_operation;
extern uint8_t m_use_slot_id;
extern uint8_t m_use_slot_count;

// extern spdm_key_update_action_t m_use_key_update_action;

extern uint32_t m_use_hash_algo;
extern uint32_t m_use_measurement_hash_algo;
extern uint32_t m_use_asym_algo;
extern uint16_t m_use_req_asym_algo;

/*
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
*/
extern uint8_t m_support_measurement_spec;
extern uint32_t m_support_measurement_hash_algo;
extern uint32_t m_support_hash_algo;
extern uint32_t m_support_asym_algo;
extern uint16_t m_support_req_asym_algo;
extern uint16_t m_support_dhe_algo;
extern uint16_t m_support_aead_algo;
extern uint16_t m_support_key_schedule_algo;


#define EXE_MODE_SHUTDOWN 0
#define EXE_MODE_CONTINUE 1
// extern uint32_t m_exe_mode;

#define EXE_CONNECTION_VERSION_ONLY 0x1
#define EXE_CONNECTION_DIGEST 0x2
#define EXE_CONNECTION_CERT 0x4
#define EXE_CONNECTION_CHAL 0x8
#define EXE_CONNECTION_MEAS 0x10
// extern uint32_t m_exe_connection;

#define EXE_SESSION_KEY_EX 0x1
#define EXE_SESSION_PSK 0x2
#define EXE_SESSION_NO_END 0x4
#define EXE_SESSION_KEY_UPDATE 0x8
#define EXE_SESSION_HEARTBEAT 0x10
#define EXE_SESSION_MEAS 0x20
// extern uint32_t m_exe_session;

extern uint32_t m_exe_mode;

extern uint32_t m_exe_connection;

extern uint32_t m_exe_session;

//
// Vendor message
//
#pragma pack(1)

///
/// SPDM VENDOR_DEFINED request
///
typedef struct {
  spdm_message_header_t header;
  // param1 == RSVD
  // param2 == RSVD
  uint16_t standard_id;
  uint8_t len;
  uint16_t vendor_id;
  uint16_t payload_length;
  pci_protocol_header_t pci_protocol;
  pci_ide_km_query_t pci_ide_km_query;
} spdm_vendor_defined_request_mine_t;

///
/// SPDM VENDOR_DEFINED response
///
typedef struct {
  spdm_message_header_t header;
  // param1 == RSVD
  // param2 == RSVD
  uint16_t standard_id;
  uint8_t len;
  uint16_t vendor_id;
  uint16_t payload_length;
  pci_protocol_header_t pci_protocol;
  pci_ide_km_query_resp_t pci_ide_km_query_resp;
} spdm_vendor_defined_response_mine_t;

///
/// Secure Session APP request
///
typedef struct {
  mctp_message_header_t mctp_header;
  pldm_message_header_t pldm_header;
} secure_session_request_mine_t;

///
/// Secure Session APP response
///
typedef struct {
  mctp_message_header_t mctp_header;
  pldm_message_header_t pldm_header;
  pldm_message_response_header_t pldm_response_header;
  uint8_t tid;
} secure_session_response_mine_t;

///
/// DOE Discovery request
///
typedef struct {
  pci_doe_data_object_header_t doe_header;
  pci_doe_discovery_request_t doe_discovery_request;
} doe_discovery_request_mine_t;

///
/// DOE Discovery response
///
typedef struct {
  pci_doe_data_object_header_t doe_header;
  pci_doe_discovery_response_t doe_discovery_response;
} doe_discovery_response_mine_t;

#define DUMP_ARRAY(msg, array, array_size) \
  printf("%s: %s", __func__, msg); \
  for(int __i = 0; __i < array_size; __i++) { \
    if(__i % 16 == 0) printf("\n[%03x] ", __i); \
    printf("%02x ", ((uint8_t*)array)[__i]); \
  } \
  printf("\n");

#pragma pack()