#include <library/spdm_transport_mctp_lib.h>

#define SPDM_BLK_APP_TAMPER   0x01
#define SPDM_BLK_APP_MSG      0x02

#define SOCKET_TRANSPORT_TYPE_MCTP 0x01
#define SOCKET_TRANSPORT_TYPE_PCI_DOE 0x02

extern uint32_t m_use_transport_layer;
extern uint8_t m_use_version;
extern uint8_t m_use_secured_message_version;
extern uint32_t m_use_requester_capability_flags;
extern uint32_t m_use_capability_flags;
extern uint8_t m_use_measurement_summary_hash_type;
extern uint8_t m_use_slot_id;
extern uint8_t m_use_slot_count;
extern uint32_t m_use_hash_algo;
extern uint32_t m_use_measurement_hash_algo;
extern uint32_t m_use_asym_algo;
extern uint16_t m_use_req_asym_algo;
extern uint8_t m_support_measurement_spec;
extern uint32_t m_support_hash_algo;
extern uint32_t m_support_asym_algo;
extern uint16_t m_support_req_asym_algo;
extern uint16_t m_support_dhe_algo;
extern uint16_t m_support_aead_algo;
extern uint16_t m_support_key_schedule_algo;
extern uint8_t m_session_policy;

