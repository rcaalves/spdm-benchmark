/*
 * Basic SPDM responder PCI device
 *
 * Built on top of the QEMU educational PCI device by Jiri Slaby
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h" /* iothread mutex */
#include "qemu/module.h"
#include "qapi/visitor.h"


// libspdm includes
#include "spdm_common_lib.h"
#include "spdm_responder_lib.h"
// this define avoid some annoying warnings
#define REQUESTER_PSKLIB_H
#include "spdm_device_secret_lib_internal.h"
#include <library/spdm_transport_mctp_lib.h>
#include "pci_idekm.h"
#include "pldm.h"
#include "pcidoe.h"
#include "mctp.h"
#include "internal/libspdm_common_lib.h"

#include "uio_spdm_rng.h"
#include "spdm_emu_rng.c"

// perf
// #include <sys/ioctl.h> // this include may cause compilation issues
int ioctl(int fd, unsigned long request, ...);
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>
// #include <unistd.h>

#define SPDMDEV_DEBUG 0

#define TYPE_PCI_SPDM_DEVICE "spdm"
#define SPDM(obj)        OBJECT_CHECK(spdmdev_state, obj, TYPE_PCI_SPDM_DEVICE)

#define FACT_IRQ        0x00000001
#define DMA_IRQ         0x00000100
#define SPDMIO_IRQ      0x00001000

#define DMA_START       0x40000
#define DMA_SIZE        4096


#define SPDMDEV_TXRX_CTRL_ADDR      (0xA0)
#define SPDMDEV_TXRX_DATA_SIZEADDR  (0xA4)
#define SPDMDEV_TXRX_DATA_ADDR      (0xA8)
#define SPDMDEV_MEAS_TAMPER_ADDR    (0xB0)
#define SPDMDEV_TX_TO_DEV           (0x1)
#define SPDMDEV_TX_TO_DEV_DONE      (0x2)
#define SPDMDEV_TX_TO_OS            (0x4)
#define SPDMDEV_TX_TO_OS_DONE       (0x8)
#define SPDMDEV_MAX_BUF             (4096)

// external variable that controls tampering simulation
extern uint8_t ts[10];

typedef struct {
    PCIDevice pdev;
    MemoryRegion mmio;

    // Used by the factorial example
    QemuThread thread;
    QemuMutex thr_mutex;
    QemuCond thr_cond;
    bool stopping;

    // Used by SPDM messaging
    QemuThread spdm_io_thread;
    // QemuMutex spdm_io_mutex;
    QemuCond spdm_io_cond;
    bool spdm_io_stopping;

    uint32_t addr4;
    uint32_t fact;
#define SPDM_STATUS_COMPUTING    0x01
#define SPDM_STATUS_IRQFACT      0x80
    uint32_t status;

    uint32_t irq_status;

#define SPDM_DMA_RUN             0x1
#define SPDM_DMA_DIR(cmd)        (((cmd) & 0x2) >> 1)
# define SPDM_DMA_FROM_PCI       0
# define SPDM_DMA_TO_PCI         1
#define SPDM_DMA_IRQ             0x4
    struct dma_state {
        dma_addr_t src;
        dma_addr_t dst;
        dma_addr_t cnt;
        dma_addr_t cmd;
    } dma;
    QEMUTimer dma_timer;
    char dma_buf[DMA_SIZE];
    uint64_t dma_mask;
    void* dev_spdm_context;
    // char spdm_buf[SPDMDEV_MAX_BUF];
    // uint32_t spdm_ctrl;
    // uint32_t spdm_buf_size;
    int fd_cycles;
    int fd_taskclock;
    int fd_instructions;
    FILE* out_f;
} spdmdev_state;

#define NUM_PERF_EVENTS 3
enum { CYCLES = 0, TASK_CLOCK = 1, INSTRUCTIONS = 2 };

struct read_format {
 uint64_t nr;            /* The number of events */
 // uint64_t time_enabled;  /* if PERF_FORMAT_TOTAL_TIME_ENABLED */
 uint64_t time_running;  /* if PERF_FORMAT_TOTAL_TIME_RUNNING */
 struct {
     uint64_t value;     /* The value of the event */
     // uint64_t id;        /* if PERF_FORMAT_ID */
 } values[NUM_PERF_EVENTS];
};

// Global variables used by Spdm Transmit and Receive functions
uint8_t spdm_buf[SPDMDEV_MAX_BUF];
uint32_t spdm_ctrl;
uint32_t spdm_buf_size;
QemuMutex spdm_io_mutex;
QemuMutex spdm_ctx_mutex;

// Prototypes
libspdm_return_t
spdmdev_send_message (
  void                    *spdm_context,
  size_t                   request_size,
  const void              *request,
  uint64_t                 timeout
  );

libspdm_return_t
spdmdev_receive_message (
  void                   *spdm_context,
  size_t                 *response_size,
  void                  **response,
  uint64_t                timeout
  );

libspdm_return_t
spdmdev_get_response_vendor_defined_request (
  void                    *spdm_context,
  const uint32_t          *session_id,
  bool                     is_app_message,
  size_t                   request_size,
  const void              *request,
  size_t                  *response_size,
  void                    *response
  );

libspdm_return_t
spdmdev_process_packet_callback (
  const uint32_t           *session_id,
  bool                      is_app_message,
  const void               *request,
  size_t                    request_size,
  void                     *response,
  size_t                   *response_size
  );

void spdmdev_server_callback (void *spdm_context);

libspdm_return_t spdmdev_init_perf_events(int *fd_cycles, int *fd_taskclock, int *fd_instructions);

uint32_t spdmdev_get_rand(void);

unsigned int mySeed = 12345;
uint32_t spdmdev_get_rand(void) {
    return rand_r(&mySeed);
}

spdm_vendor_defined_response_mine_t  mVendorDefinedResponse = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_VENDOR_DEFINED_RESPONSE,
    0, // Param1
    0, // Param2
  },
  SPDM_REGISTRY_ID_PCISIG, // StandardID
  2, // Len
  SPDM_VENDOR_ID_PCISIG, // VendorID
  sizeof(pci_protocol_header_t) + sizeof(pci_ide_km_query_resp_t), // PayloadLength
  {
    PCI_PROTOCOL_ID_IDE_KM,
  },
  {
    {
      PCI_IDE_KM_OBJECT_ID_QUERY_RESP,
    },
    0, // Reserved
    0, // PortIndex
    0, // DevFuncNum
    0, // BusNum
    0, // Segment
    7, // MaxPortIndex
  }
};

secure_session_response_mine_t  mSecureSessionResponse = {
  {
    MCTP_MESSAGE_TYPE_PLDM
  },
  {
    0,
    PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY,
    PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID,
  },
  {
    PLDM_BASE_CODE_SUCCESS,
  },
  1, // TID
};

rng_secure_session_response_t mSecureRngResponse = {
  {
    MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI
  },
};

const char* spdmdev_requestreponsecode_to_str(uint8_t code);

const char* spdmdev_requestreponsecode_to_str(uint8_t code) {
  // printf("%02X\n", code);
  switch (code) {
    case SPDM_DIGESTS: return "SPDM_DIGESTS";
    case SPDM_CERTIFICATE: return "SPDM_CERTIFICATE";
    case SPDM_CHALLENGE_AUTH: return "SPDM_CHALLENGE_AUTH";
    case SPDM_VERSION: return "SPDM_VERSION";
    case SPDM_MEASUREMENTS: return "SPDM_MEASUREMENTS";
    case SPDM_CAPABILITIES: return "SPDM_CAPABILITIES";
    case SPDM_ALGORITHMS: return "SPDM_ALGORITHMS";
    case SPDM_VENDOR_DEFINED_RESPONSE: return "SPDM_VENDOR_DEFINED_RESPONSE";
    case SPDM_ERROR: return "SPDM_ERROR";
    case SPDM_KEY_EXCHANGE_RSP: return "SPDM_KEY_EXCHANGE_RSP";
    case SPDM_FINISH_RSP: return "SPDM_FINISH_RSP";
    case SPDM_PSK_EXCHANGE_RSP: return "SPDM_PSK_EXCHANGE_RSP";
    case SPDM_PSK_FINISH_RSP: return "SPDM_PSK_FINISH_RSP";
    case SPDM_HEARTBEAT_ACK: return "SPDM_HEARTBEAT_ACK";
    case SPDM_KEY_UPDATE_ACK: return "SPDM_KEY_UPDATE_ACK";
    case SPDM_ENCAPSULATED_REQUEST: return "SPDM_ENCAPSULATED_REQUEST";
    case SPDM_ENCAPSULATED_RESPONSE_ACK: return "SPDM_ENCAPSULATED_RESPONSE_ACK";
    case SPDM_END_SESSION_ACK: return "SPDM_END_SESSION_ACK";

    case SPDM_GET_DIGESTS: return "get_digest"; //"SPDM_GET_DIGESTS";
    case SPDM_GET_CERTIFICATE: return "get_certificate"; //"SPDM_GET_CERTIFICATE";
    case SPDM_CHALLENGE: return "challenge"; //"SPDM_CHALLENGE";
    case SPDM_GET_VERSION: return "get_version"; //"SPDM_GET_VERSION";
    case SPDM_GET_MEASUREMENTS: return "get_measurement"; //"SPDM_GET_MEASUREMENTS";
    case SPDM_GET_CAPABILITIES: return "get_capabilities"; //"SPDM_GET_CAPABILITIES";
    case SPDM_NEGOTIATE_ALGORITHMS: return "negotiate_algorithms"; //"SPDM_NEGOTIATE_ALGORITHMS";
    case SPDM_VENDOR_DEFINED_REQUEST: return "get_random_spdm";//return "SPDM_VENDOR_DEFINED_REQUEST";
    case SPDM_RESPOND_IF_READY: return "SPDM_RESPOND_IF_READY";
    case SPDM_KEY_EXCHANGE: return "key_exchange"; //"SPDM_KEY_EXCHANGE";
    case SPDM_FINISH: return "finish"; //"SPDM_FINISH";
    case SPDM_PSK_EXCHANGE: return "key_exchangePSK"; //"SPDM_PSK_EXCHANGE";
    case SPDM_PSK_FINISH: return "finishPSK"; //"SPDM_PSK_FINISH";
    case SPDM_HEARTBEAT: return "heartbeat"; //"SPDM_HEARTBEAT";
    case SPDM_KEY_UPDATE: return "key_update"; //"SPDM_KEY_UPDATE";
    case SPDM_GET_ENCAPSULATED_REQUEST: return "SPDM_GET_ENCAPSULATED_REQUEST";
    case SPDM_DELIVER_ENCAPSULATED_RESPONSE: return "SPDM_DELIVER_ENCAPSULATED_RESPONSE"; //return "MUTUAL_AUTH";
    case SPDM_END_SESSION: return "end_session"; //"SPDM_END_SESSION";
    default: return "Unknown code";
  }
  return NULL;

}

int spdmdev_init_spdm(void **spdm_context);

/**
  Process a packet in the current SPDM session.

  @param  This                         Indicates a pointer to the calling context.
  @param  SessionId                    ID of the session.
  @param  request                      A pointer to the request data.
  @param  request_size                 Size of the request data.
  @param  response                     A pointer to the response data.
  @param  response_size                Size of the response data. On input, it means the size of Data
                                       buffer. On output, it means the size of copied Data buffer if
                                       LIBSPDM_STATUS_SUCCESS, and means the size of desired Data buffer if
                                       RETURN_BUFFER_TOO_SMALL.

  @retval LIBSPDM_STATUS_SUCCESS          The SPDM request is set successfully.
  @retval RETURN_INVALID_PARAMETER        The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_NOT_FOUND                The DataType cannot be found.
  @retval RETURN_NOT_READY                The DataType is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                          to execute.
**/

libspdm_return_t
spdmdev_process_packet_callback (
  const uint32_t           *session_id,
  bool                      is_app_message,
  const void               *request,
  size_t                    request_size,
  void                     *response,
  size_t                   *response_size
  )
{
  const spdm_vendor_defined_request_mine_t  *spdm_request;
  const secure_session_request_mine_t       *app_request;
  const rng_secure_session_request_t        *app_request_rng;

  if (!is_app_message) {
    spdm_request = request;
    LIBSPDM_ASSERT ((request_size >= sizeof(spdm_vendor_defined_request_mine_t)) && (request_size < sizeof(spdm_vendor_defined_request_mine_t) + 4));
    LIBSPDM_ASSERT (spdm_request->header.request_response_code == SPDM_VENDOR_DEFINED_REQUEST);
    LIBSPDM_ASSERT (spdm_request->standard_id == SPDM_REGISTRY_ID_PCISIG);
    LIBSPDM_ASSERT (spdm_request->vendor_id == SPDM_VENDOR_ID_PCISIG);
    LIBSPDM_ASSERT (spdm_request->payload_length == sizeof(pci_protocol_header_t) + sizeof(pci_ide_km_query_t));
    LIBSPDM_ASSERT (spdm_request->pci_protocol.protocol_id == PCI_PROTOCOL_ID_IDE_KM);
    LIBSPDM_ASSERT (spdm_request->pci_ide_km_query.header.object_id == PCI_IDE_KM_OBJECT_ID_QUERY);
    memcpy (response, &mVendorDefinedResponse, sizeof(mVendorDefinedResponse));
    *response_size = sizeof(mVendorDefinedResponse);
  } else {
    app_request = request;
    app_request_rng = request;
    // printf("app_request->mctp_header.message_type %X \n", app_request->mctp_header.message_type);
    if (app_request->mctp_header.message_type == MCTP_MESSAGE_TYPE_PLDM) {
      LIBSPDM_ASSERT (request_size == sizeof(secure_session_request_mine_t));
      LIBSPDM_ASSERT (app_request->mctp_header.message_type == MCTP_MESSAGE_TYPE_PLDM);
      LIBSPDM_ASSERT (app_request->pldm_header.pldm_type == PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY);
      LIBSPDM_ASSERT (app_request->pldm_header.pldm_command_code == PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID);

      memcpy (response, &mSecureSessionResponse, sizeof(mSecureSessionResponse));
      *response_size = sizeof(mSecureSessionResponse);
    } else if (app_request_rng->MctpHeader.message_type == MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI) {
      LIBSPDM_ASSERT (app_request_rng->Req == RNG_REQ_CODE);
      mSecureRngResponse.Rng = spdmdev_get_rand();
      // printf("Sending random number %d\n", mSecureRngResponse.Rng);
      memcpy (response, &mSecureRngResponse, sizeof(mSecureRngResponse));
      *response_size = sizeof(mSecureRngResponse);
    } else {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
  }

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t
spdmdev_get_response_vendor_defined_request (
  void                 *spdm_context,
  const uint32_t       *session_id,
  bool                  is_app_message,
  size_t                request_size,
  const void           *request,
  size_t               *response_size,
  void                 *response
  )
{
  libspdm_return_t status;

  status = spdmdev_process_packet_callback (
             session_id,
             is_app_message,
             request,
             request_size,
             response,
             response_size
             );
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    libspdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, response_size, response);
  }
  return LIBSPDM_STATUS_SUCCESS;
}


void spdmdev_server_callback (void *spdm_context) {
  bool                        res;
  void                       *data;
  size_t                      data_size;
  libspdm_data_parameter_t    parameter;
  uint8_t                     data8;
  uint16_t                    data16;
  uint32_t                    data32;
  void                       *hash;
  size_t                      hash_size;
  uint8_t                     index;
  // libspdm_return_t         status;

  // static bool                 AlgoProvisioned = false;
  // if (AlgoProvisioned) {
  //   return ;
  // }

  libspdm_zero_mem (&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

  data_size = sizeof(data32);
  libspdm_get_data (spdm_context, LIBSPDM_DATA_CONNECTION_STATE, &parameter, &data32, &data_size);
  if (data32 != LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
    return ;
  }

  // data_size = sizeof(data32);
  // libspdm_get_data (spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &data32, &data_size);
  // m_use_measurement_hash_algo = data32;
  data_size = sizeof(data32);
  libspdm_get_data (spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, &data_size);
  m_use_asym_algo = data32;
  data_size = sizeof(data32);
  libspdm_get_data (spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, &data_size);
  m_use_hash_algo = data32;
  data_size = sizeof(data16);
  libspdm_get_data (spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, &data_size);
  m_use_req_asym_algo = data16;

  res = libspdm_read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &data, &data_size, NULL, NULL);
  if (res) {
    libspdm_zero_mem (&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data8 = m_use_slot_count;
    libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, &data8, sizeof(data8));

    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
      parameter.additional_data[0] = index;
      libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, data, data_size);
    }

#if SPDMDEV_DEBUG
    printf("%s spdm_context->local_context.local_cert_chain_provision[0] (%ld)", __func__, ((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision_size[0]);
    for (int i = 0; i < MIN(((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision_size[0],64); i++) {
            if (i%16 == 0) printf("\n[%3d] ", i);
            printf("0x%02x ", ((const uint8_t*)((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision[0])[i]);
    }
    printf("\n");
#endif
    // do not free it
  }

  if (m_use_slot_id == 0xFF) {
    res = libspdm_read_requester_public_certificate_chain (m_use_hash_algo, m_use_req_asym_algo, &data, &data_size, NULL, NULL);
    if (res) {
      libspdm_zero_mem (&parameter, sizeof(parameter));
      parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
      libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, data, data_size);
      // Do not free it.
    }
  } else {
    res = libspdm_read_requester_root_public_certificate (m_use_hash_algo, m_use_req_asym_algo, &data, &data_size, &hash, &hash_size);
    if (res) {
      libspdm_zero_mem (&parameter, sizeof(parameter));
      parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
      libspdm_set_data (spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, hash, hash_size);
      // Do not free it.
    }
  }

  if (res) {
    data8 = m_use_mut_auth;
    if (data8 != 0) {
      data8 |= SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
    }
    parameter.additional_data[0] = m_use_slot_id;
    parameter.additional_data[1] = m_use_measurement_summary_hash_type;
    libspdm_set_data (spdm_context, LIBSPDM_DATA_MUT_AUTH_REQUESTED, &parameter, &data8, sizeof(data8));

    data8 = (m_use_mut_auth & 0x1);
    libspdm_set_data (spdm_context, LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED, &parameter, &data8, sizeof(data8));
  }

  libspdm_zero_mem(&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
  data8 = 0xFF;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, &parameter,
                      &data8, sizeof(data8));

  // AlgoProvisioned = true;

  return ;
}

// Functions to be used with SpdmRegisterDeviceIoFunc
libspdm_return_t
spdmdev_send_message (
  void                    *spdm_context,
  size_t                   request_size,
  const void              *request,
  uint64_t                 timeout
  )
{
    if (request_size > sizeof(spdm_buf)) {
        fprintf(stderr, "request_size too large %lu\n", request_size);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    if (! (atomic_read(&spdm_ctrl) & SPDMDEV_TX_TO_DEV_DONE)) {
        fprintf(stderr, "Wrong spdm_ctrl flags 0x%X\n", atomic_read(&spdm_ctrl));
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    // spdm_ctrl |= SPDMDEV_TX_TO_OS;
    atomic_or(&spdm_ctrl, SPDMDEV_TX_TO_OS);
    atomic_set(&spdm_buf_size, request_size);
    qemu_mutex_lock(&spdm_io_mutex);
    // DUMP_ARRAY("", request, request_size);
    memcpy(spdm_buf, request, request_size);
    qemu_mutex_unlock(&spdm_io_mutex);
    atomic_or(&spdm_ctrl, SPDMDEV_TX_TO_OS_DONE);

    // raise interrupt
    // pci_set_irq(&spdmst->pdev, 1); // Can't do it here as this function cannot access "spdmst"
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t
spdmdev_receive_message (
  void                     *spdm_context,
  size_t                   *response_size,
  void                    **response,
  uint64_t                  timeout
  )
{

    // const uint8_t GET_VERSION[] = {0x05, 0x10, 0x84, 0x00, 0x00};
    // printf("spdmdev_receive_message\n");
    if (*response_size < atomic_read(&spdm_buf_size)) {
        fprintf(stderr, "*response_size too small %lu\n", *response_size);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    // for (int i = 0; i < MIN(spdm_buf_size, 8); i++)
    //   printf("%x ", spdm_buf[i]);
    // printf("\n");
    // fflush(stdout);
    // if (!memcmp(GET_VERSION, spdm_buf, sizeof(GET_VERSION))) {
    //     libspdm_reset_context(spdm_context);
    // }
    qemu_mutex_lock(&spdm_io_mutex);
    // printf("spdmdev_receive_message memcpy\n");
    memcpy(*response, spdm_buf, spdm_buf_size);
    qemu_mutex_unlock(&spdm_io_mutex);
    *response_size = atomic_read(&spdm_buf_size);

    return LIBSPDM_STATUS_SUCCESS;
}

static long
spdmdev_perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                    group_fd, flags);
    return ret;
}

libspdm_return_t spdmdev_init_perf_events(int *fd_cycles, int *fd_taskclock, int *fd_instructions) {
  struct perf_event_attr pe;

  memset(&pe, 0, sizeof(struct perf_event_attr));
  pe.size = sizeof(struct perf_event_attr);
  pe.disabled = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;
  pe.exclude_guest = 1;
  pe.read_format = PERF_FORMAT_GROUP |
                   // PERF_FORMAT_TOTAL_TIME_ENABLED |
                   PERF_FORMAT_TOTAL_TIME_RUNNING |
                   // PERF_FORMAT_ID;
                   0;

  pe.type   = PERF_TYPE_HARDWARE;
  pe.config = PERF_COUNT_HW_CPU_CYCLES;

  *fd_cycles = spdmdev_perf_event_open(&pe, 0, -1, -1, 0);
  if (*fd_cycles == -1) {
      fprintf(stderr, "Error opening perf leader fd %llx\n", pe.config);
      return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_TASK_CLOCK;

  *fd_taskclock = spdmdev_perf_event_open(&pe, 0, -1, *fd_cycles, 0);
  if (*fd_taskclock == -1) {
      fprintf(stderr, "Error opening perf TASK_CLOCK fd %llx\n", pe.config);
      return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  pe.type = PERF_TYPE_HARDWARE;
  pe.config = PERF_COUNT_HW_INSTRUCTIONS;

  *fd_instructions = spdmdev_perf_event_open(&pe, 0, -1, *fd_cycles, 0);
  if (*fd_instructions == -1) {
      fprintf(stderr, "Error opening perf INSTRUCTIONS fd %llx\n", pe.config);
      return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  return LIBSPDM_STATUS_SUCCESS;
}

// Deice management functions
static bool spdmdev_msi_enabled(spdmdev_state *spdmst)
{
    return msi_enabled(&spdmst->pdev);
}

static void spdmdev_raise_irq(spdmdev_state *spdmst, uint32_t val)
{
    spdmst->irq_status |= val;
    if (spdmst->irq_status) {
        if (spdmdev_msi_enabled(spdmst)) {
            msi_notify(&spdmst->pdev, 0);
        } else {
            pci_set_irq(&spdmst->pdev, 1);
        }
    }
}

static void spdmdev_lower_irq(spdmdev_state *spdmst, uint32_t val)
{
    spdmst->irq_status &= ~val;

    if (!spdmst->irq_status && !spdmdev_msi_enabled(spdmst)) {
        pci_set_irq(&spdmst->pdev, 0);
    }
}

static bool within(uint64_t addr, uint64_t start, uint64_t end)
{
    return start <= addr && addr < end;
}

static void spdmdev_check_range(uint64_t addr, uint64_t size1, uint64_t start,
                uint64_t size2)
{
    uint64_t end1 = addr + size1;
    uint64_t end2 = start + size2;

    if (within(addr, start, end2) &&
            end1 > addr && within(end1, start, end2)) {
        return;
    }

    hw_error("SPDM: DMA range 0x%016"PRIx64"-0x%016"PRIx64
             " out of bounds (0x%016"PRIx64"-0x%016"PRIx64")!",
            addr, end1 - 1, start, end2 - 1);
}

static dma_addr_t spdmdev_clamp_addr(const spdmdev_state *spdmst, dma_addr_t addr)
{
    dma_addr_t res = addr & spdmst->dma_mask;

    if (addr != res) {
        printf("SPDM: clamping DMA %#.16"PRIx64" to %#.16"PRIx64"!\n", addr, res);
    }

    return res;
}

static void spdmdev_dma_timer(void *opaque)
{
    spdmdev_state *spdmst = opaque;
    bool raise_irq = false;

    if (!(spdmst->dma.cmd & SPDM_DMA_RUN)) {
        return;
    }

    if (SPDM_DMA_DIR(spdmst->dma.cmd) == SPDM_DMA_FROM_PCI) {
        uint64_t dst = spdmst->dma.dst;
        spdmdev_check_range(dst, spdmst->dma.cnt, DMA_START, DMA_SIZE);
        dst -= DMA_START;
        pci_dma_read(&spdmst->pdev, spdmdev_clamp_addr(spdmst, spdmst->dma.src),
                spdmst->dma_buf + dst, spdmst->dma.cnt);
    } else {
        uint64_t src = spdmst->dma.src;
        spdmdev_check_range(src, spdmst->dma.cnt, DMA_START, DMA_SIZE);
        src -= DMA_START;
        pci_dma_write(&spdmst->pdev, spdmdev_clamp_addr(spdmst, spdmst->dma.dst),
                spdmst->dma_buf + src, spdmst->dma.cnt);
    }

    spdmst->dma.cmd &= ~SPDM_DMA_RUN;
    if (spdmst->dma.cmd & SPDM_DMA_IRQ) {
        raise_irq = true;
    }

    if (raise_irq) {
        spdmdev_raise_irq(spdmst, DMA_IRQ);
    }
}

static void dma_rw(spdmdev_state *spdmst, bool write, dma_addr_t *val, dma_addr_t *dma,
                bool timer)
{
    if (write && (spdmst->dma.cmd & SPDM_DMA_RUN)) {
        return;
    }

    if (write) {
        *dma = *val;
    } else {
        *val = *dma;
    }

    if (timer) {
        timer_mod(&spdmst->dma_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 100);
    }
}

static uint64_t spdmdev_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    spdmdev_state *spdmst = opaque;
    uint64_t val = ~0ULL;

    // printf("Trying to read %u bytes at 0x%X\n", size, addr);

    if (addr < 0x80 && size != 4) {
        return val;
    }

    if (within(addr, SPDMDEV_TXRX_DATA_ADDR, SPDMDEV_TXRX_DATA_ADDR + SPDMDEV_MAX_BUF) && size == 1) {
        if (atomic_read(&spdm_ctrl) & SPDMDEV_TX_TO_OS_DONE) {
            qemu_mutex_lock(&spdm_io_mutex);
            val = spdm_buf[addr - SPDMDEV_TXRX_DATA_ADDR];
            qemu_mutex_unlock(&spdm_io_mutex);
        } else {
            fprintf(stderr, "Wrong flags while sending data: %X\n", spdm_ctrl);
        }
    }

    if (addr >= 0x80 && size != 4 && size != 8) {
        return val;
    }

    switch (addr) {
    case 0x00:
        val = 0x010000edu;
        break;
    case 0x04:
        val = spdmst->addr4;
        break;
    case 0x08:
        qemu_mutex_lock(&spdmst->thr_mutex);
        val = spdmst->fact;
        qemu_mutex_unlock(&spdmst->thr_mutex);
        break;
    case 0x20:
        val = atomic_read(&spdmst->status);
        break;
    case 0x24:
        val = spdmst->irq_status;
        break;
    case 0x80:
        dma_rw(spdmst, false, &val, &spdmst->dma.src, false);
        break;
    case 0x88:
        dma_rw(spdmst, false, &val, &spdmst->dma.dst, false);
        break;
    case 0x90:
        dma_rw(spdmst, false, &val, &spdmst->dma.cnt, false);
        break;
    case 0x98:
        dma_rw(spdmst, false, &val, &spdmst->dma.cmd, false);
        break;
    case SPDMDEV_TXRX_CTRL_ADDR:
        val = atomic_read(&spdm_ctrl);
        break;
    case SPDMDEV_TXRX_DATA_SIZEADDR:
        val = atomic_read(&spdm_buf_size);
        break;
    }

    return val;
}

static void spdmdev_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    spdmdev_state *spdmst = opaque;

    // printf("Trying to write %u bytes (%lX) at 0x%lX\n", size, val, addr);

    if (addr < 0x80 && size != 4) {
        return;
    }

    if (within(addr, SPDMDEV_TXRX_DATA_ADDR, SPDMDEV_TXRX_DATA_ADDR + SPDMDEV_MAX_BUF) && size == 1) {
        if ((atomic_read(&spdm_ctrl) & SPDMDEV_TX_TO_DEV) && ! (atomic_read(&spdm_ctrl) & SPDMDEV_TX_TO_OS) ) {
            qemu_mutex_lock(&spdm_io_mutex);
            spdm_buf[addr - SPDMDEV_TXRX_DATA_ADDR] = val;
            qemu_mutex_unlock(&spdm_io_mutex);
        } else {
            fprintf(stderr, "Wrong flags while receiving data: %X\n", spdm_ctrl);
        }
    }

    if (addr >= 0x80 && size != 4 && size != 8) {
        return;
    }

    switch (addr) {
    case 0x04:
        spdmst->addr4 = ~val;
        break;
    case 0x08:
        if (atomic_read(&spdmst->status) & SPDM_STATUS_COMPUTING) {
            break;
        }
        /* SPDM_STATUS_COMPUTING cannot go 0->1 concurrently, because it is only
         * set in this function and it is under the iothread mutex.
         */
        qemu_mutex_lock(&spdmst->thr_mutex);
        spdmst->fact = val;
        atomic_or(&spdmst->status, SPDM_STATUS_COMPUTING);
        qemu_cond_signal(&spdmst->thr_cond);
        qemu_mutex_unlock(&spdmst->thr_mutex);
        break;
    case 0x20:
        if (val & SPDM_STATUS_IRQFACT) {
            atomic_or(&spdmst->status, SPDM_STATUS_IRQFACT);
        } else {
            atomic_and(&spdmst->status, ~SPDM_STATUS_IRQFACT);
        }
        break;
    case 0x60:
        spdmdev_raise_irq(spdmst, val);
        break;
    case 0x64:
        spdmdev_lower_irq(spdmst, val);
        break;
    case 0x80:
        dma_rw(spdmst, true, &val, &spdmst->dma.src, false);
        break;
    case 0x88:
        dma_rw(spdmst, true, &val, &spdmst->dma.dst, false);
        break;
    case 0x90:
        dma_rw(spdmst, true, &val, &spdmst->dma.cnt, false);
        break;
    case 0x98:
        if (!(val & SPDM_DMA_RUN)) {
            break;
        }
        dma_rw(spdmst, true, &val, &spdmst->dma.cmd, true);
        break;
    case SPDMDEV_TXRX_CTRL_ADDR:
        // spdm_ctrl = val;
        atomic_set(&spdm_ctrl, val);
        // printf("0x%lx 0x%lx\n", val, val & SPDMDEV_TX_TO_DEV);
        if (val & SPDMDEV_TX_TO_DEV_DONE && ! (val & SPDMDEV_TX_TO_OS)) {

            qemu_mutex_lock(&spdm_io_mutex);
            qemu_cond_signal(&spdmst->spdm_io_cond);
            qemu_mutex_unlock(&spdm_io_mutex);

            // if (spdm_ctrl & SPDMDEV_TX_TO_OS_DONE) {
            //     // raise interrupt
            //     pci_set_irq(&spdmst->pdev, 1);
            // }
        }
        if (val == 0) {
            // printf("Lower IRQ SPDMIO_IRQ\n");
            spdmdev_lower_irq(spdmst, SPDMIO_IRQ);
        }
        break;
    case SPDMDEV_TXRX_DATA_SIZEADDR:
        atomic_set(&spdm_buf_size, val);
        break;
    case SPDMDEV_MEAS_TAMPER_ADDR:
        val = MIN(val, 9);
        ts[val] = MAX(ts[val], ts[val] + 1);
        printf("Triggering tamper of measurement %lu\n", val);
        break;
    }
}

static const MemoryRegionOps spdmdev_mmio_ops = {
    .read = spdmdev_mmio_read,
    .write = spdmdev_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },

};

static void *spdmdev_fact_thread(void *opaque) {
    spdmdev_state *spdmst = opaque;

    int local_cyc, local_clock, local_inst;
    struct read_format rf;

    spdmdev_init_perf_events(&local_cyc, &local_clock, &local_inst);

    while (1) {
        uint32_t val, ret = 1;

        qemu_mutex_lock(&spdmst->thr_mutex);
        while ((atomic_read(&spdmst->status) & SPDM_STATUS_COMPUTING) == 0 &&
                        !spdmst->stopping) {
            qemu_cond_wait(&spdmst->thr_cond, &spdmst->thr_mutex);
        }

        if (spdmst->stopping) {
            qemu_mutex_unlock(&spdmst->thr_mutex);
            break;
        }

        val = spdmst->fact;
        qemu_mutex_unlock(&spdmst->thr_mutex);

        if (val != 0) {
            mySeed = val;
            while (val > 0) {
                ret *= val--;
            }
        } else {
            ioctl(local_cyc, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
            ioctl(local_cyc, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
            ret = spdmdev_get_rand();
            ioctl(local_cyc, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
            read(local_cyc, &rf, sizeof(rf));
            if (spdmst->out_f) {
              fprintf(spdmst->out_f, "get_random_no_spdm,\t%lu cycles,\t%lu ns,\t%lu instructions\n",
              rf.values[CYCLES].value, rf.values[TASK_CLOCK].value, rf.values[INSTRUCTIONS].value);
              fflush(spdmst->out_f);
            }
        }

        /*
         * We should sleep for a random period here, so that students are
         * forced to check the status properly.
         */

        qemu_mutex_lock(&spdmst->thr_mutex);
        spdmst->fact = ret;
        qemu_mutex_unlock(&spdmst->thr_mutex);
        atomic_and(&spdmst->status, ~SPDM_STATUS_COMPUTING);

        if (atomic_read(&spdmst->status) & SPDM_STATUS_IRQFACT) {
            qemu_mutex_lock_iothread();
            spdmdev_raise_irq(spdmst, FACT_IRQ);
            qemu_mutex_unlock_iothread();
        }
    }

    close(local_cyc);
    close(local_clock);
    close(local_inst);

    return NULL;
}

int should_accumulate(uint8_t current_code, uint8_t current_param2);

int keep_accumulating(uint16_t previous_code, uint8_t current_code);

const char* get_suffix(uint8_t code, bool use_psk, int accumulating);

libspdm_return_t spdmdev_spdm_responder_dispatch_message (
  spdmdev_state *spdmst
  );

int should_accumulate(uint8_t current_code, uint8_t current_param2) {
  // accumulates GET_MEASUREMENTS, unless requester is getting all measurements at once
  if (current_code == SPDM_GET_MEASUREMENTS && current_param2 != SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
    return 1;
  }
  if (current_code == SPDM_GET_CERTIFICATE) {
    return 1;
  }
  if (current_code == SPDM_KEY_UPDATE) {
    return 1;
  }
  // accumulates requests used for mutual authentication (will be followed by encapsulated messages)
  if (current_code == SPDM_CHALLENGE || current_code == SPDM_KEY_EXCHANGE) {
    return 1;
  }
  return 0;
}

int keep_accumulating(uint16_t previous_code, uint8_t current_code) {
  if (previous_code == current_code) {
    return 1;
  }
  // Keep accumalting if a mutual authentication is taking place
  if (current_code == SPDM_GET_ENCAPSULATED_REQUEST || current_code == SPDM_DELIVER_ENCAPSULATED_RESPONSE) {
    return 1;
  }
  return 0;
}

const char* get_suffix(uint8_t code, bool use_psk, int accumulating) {
  if (code == SPDM_GET_MEASUREMENTS) {
    if (accumulating) {
      return "_one_by_one";
    } else {
      return "_all";
    }
  }
  if (code == SPDM_HEARTBEAT ||
      code == SPDM_KEY_UPDATE ||
      code == SPDM_VENDOR_DEFINED_REQUEST ||
      code == SPDM_END_SESSION) {
    if (use_psk) {
      return "PSK";
    } else {
      return "NoPSK";
    }
  }
  return "";
}

static void spdm_clearall_session_id(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;
    size_t index;

    session_info = spdm_context->session_info;
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        session_info[index].session_id = (INVALID_SESSION_ID & 0xFFFF);
    }
}

libspdm_return_t
spdmdev_spdm_responder_dispatch_message (
  spdmdev_state *spdmst
  )
{
  libspdm_return_t          status;
  libspdm_context_t        *spdm_context;
  void                     *request;
  size_t                    request_size;
  void                     *response;
  size_t                    response_size;
  uint32_t                 *session_id;
  bool                      is_app_message;
  void                     *message;
  size_t                    message_size;

  libspdm_session_info_t   *session_info = NULL;
  bool                      use_psk = false;

  struct read_format        rf;
  uint8_t                   request_response_code;

  // static variables to maintain accumation state
  static uint64_t cycle_accum = 0;
  static uint64_t clock_accum = 0;
  static uint64_t instr_accum = 0;
  static uint16_t previous_code = 0xFFFF;
  static int count_getversion = 0;
  static int accumulating = 0;

  // request = malloc(SPDMDEV_MAX_BUF);
  // response = malloc(SPDMDEV_MAX_BUF);
  // if (request == NULL || response == NULL) {
  //   return LIBSPDM_STATUS_BUFFER_FULL;
  // }

  spdm_context = spdmst->dev_spdm_context;

#if SPDMDEV_DEBUG
  printf("%s spdm_context->local_context.local_cert_chain_provision[0] (%ld)", __func__, ((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision_size[0]);
  for (int i = 0; i < MIN(((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision_size[0],64); i++) {
          if (i%16 == 0) printf("\n[%3d] ", i);
          printf("0x%02x ", ((const uint8_t*)((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision[0])[i]);
  }
  printf("\n");
#endif

  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

  status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
      return status;
  }
  request = message;
  request_size = message_size;
  #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
  /* need get real receiver buffer, because acquire receiver buffer will return scratch buffer*/
  libspdm_get_receiver_buffer (spdm_context, (void **)&request, &request_size);
  #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

  status = spdm_context->receive_message (spdm_context, &request_size, &request, 0);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    libspdm_release_receiver_buffer (spdm_context);
    return status;
  }

  // response_size = SPDMDEV_MAX_BUF;
  status = libspdm_process_request (spdm_context, &session_id, &is_app_message, request_size, request);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    libspdm_release_receiver_buffer (spdm_context);
    return status;
  }

  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
  if (session_id != NULL) {
    session_info = libspdm_get_session_info_via_session_id (spdm_context, *session_id);
    if (session_info) use_psk = session_info->use_psk;
  }
  libspdm_release_receiver_buffer (spdm_context);
  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

  /* build and send response message */
  status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
      return status;
  }

  response = message;
  response_size = message_size;
  libspdm_zero_mem(response, response_size);

  status = libspdm_build_response (spdm_context, session_id, is_app_message, &response_size, (void**)&response);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    return status;
  }

  status = spdm_context->send_message (spdm_context, response_size, response, 0);

  libspdm_release_sender_buffer (spdm_context);

  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
  read(spdmst->fd_cycles, &rf, sizeof(rf));

  if (is_app_message) {
    request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
  } else {
    request_response_code = ((spdm_message_header_t*)spdm_context->last_spdm_request)->request_response_code;
  }

  if (accumulating) {
    // fprintf(spdmst->out_f, "\taccumulating is true %02x %02x\n", previous_code, request_response_code);
    if (keep_accumulating(previous_code, request_response_code)) {
      // fprintf(spdmst->out_f, "\t\tkeep_accumulating() %02x %02x\n", previous_code, request_response_code);
      cycle_accum += rf.values[CYCLES].value;
      clock_accum += rf.values[TASK_CLOCK].value;
      instr_accum += rf.values[INSTRUCTIONS].value;
    } else {
      // fprintf(spdmst->out_f, "\t\twill not keep_accumulating()\n");
      fprintf(spdmst->out_f, "%s%s,\t%lu cycles,\t%lu ns,\t%lu instructions\n",
              spdmdev_requestreponsecode_to_str(previous_code), get_suffix(previous_code, use_psk, accumulating),
              cycle_accum, clock_accum, instr_accum);
      accumulating = 0;
      cycle_accum = instr_accum = clock_accum = 0;
    }
  }

  if (request_response_code == SPDM_GET_VERSION) {
    char filename[sizeof("uio_responder_iXXXXX.log")];
    void *dummy_ctx;
    struct read_format rf_inner;
    count_getversion++;
    spdm_clearall_session_id(spdm_context);
    if (spdmst->out_f != NULL) {
      fclose(spdmst->out_f);
      spdmst->out_f = NULL;
    }
    sprintf(filename, "uio_responder1.3_i%d.log", count_getversion);
    spdmst->out_f = fopen(filename, "w");

    ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
    ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
    spdmdev_init_spdm(&dummy_ctx);
    ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
    read(spdmst->fd_cycles, &rf_inner, sizeof(rf_inner));
    fprintf(spdmst->out_f, "init_spdm,\t%lu cycles,\t%lu ns,\t%lu instructions\n",
            rf_inner.values[CYCLES].value, rf_inner.values[TASK_CLOCK].value, rf_inner.values[INSTRUCTIONS].value);
    free(dummy_ctx);
  }

  if (!accumulating) {
    // fprintf(spdmst->out_f, "\taccumulating is false %02x %02x\n", previous_code, request_response_code);
    cycle_accum += rf.values[CYCLES].value;
    clock_accum += rf.values[TASK_CLOCK].value;
    instr_accum += rf.values[INSTRUCTIONS].value;
    if (should_accumulate(request_response_code, ((spdm_message_header_t*)spdm_context->last_spdm_request)->param2)) {
      // fprintf(spdmst->out_f, "\t\tstart accumulating now %02x %02x\n", previous_code, request_response_code);
      accumulating = 1;
    } else {
      fprintf(spdmst->out_f, "%s%s,\t%lu cycles,\t%lu ns,\t%lu instructions\n",
              spdmdev_requestreponsecode_to_str(request_response_code), get_suffix(request_response_code, use_psk, accumulating),
              cycle_accum, clock_accum, instr_accum);
      cycle_accum = instr_accum = clock_accum = 0;
    }
  }

  if (status == LIBSPDM_STATUS_SUCCESS && request_response_code == SPDM_NEGOTIATE_ALGORITHMS) {
    // load certificates and stuff
    // qemu_mutex_lock(&spdm_io_mutex);
    ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
    ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
    spdmdev_server_callback (spdmst->dev_spdm_context);
    ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
    read(spdmst->fd_cycles, &rf, sizeof(rf));
    // qemu_mutex_unlock(&spdm_io_mutex);
    fprintf(spdmst->out_f, "load_certificates,\t%lu cycles,\t%lu ns,\t%lu instructions\n",
              rf.values[CYCLES].value, rf.values[TASK_CLOCK].value, rf.values[INSTRUCTIONS].value);
  }

  if (!(request_response_code == SPDM_GET_ENCAPSULATED_REQUEST || request_response_code == SPDM_DELIVER_ENCAPSULATED_RESPONSE)) {
    previous_code = request_response_code;
  }
  fflush(spdmst->out_f);

  // free(request);
  // free(response);

  return status;
}

static void *spdmdev_io_thread(void *opaque)
{
    spdmdev_state *spdmst = opaque;
    // libspdm_return_t status;

    spdmdev_init_perf_events(&spdmst->fd_cycles, &spdmst->fd_taskclock, &spdmst->fd_instructions); // have to create it here, since cannot enable 'inherit' with PERF_FORMAT_GROUP

    while (1) {
        // printf("spdmdev_io_thread() loop\n");
        qemu_mutex_lock(&spdm_io_mutex);
        while ( !(atomic_read(&spdm_ctrl) & SPDMDEV_TX_TO_DEV_DONE) &&
                        !spdmst->stopping
                        ) {
            qemu_cond_wait(&spdmst->spdm_io_cond, &spdm_io_mutex);
        }

        qemu_mutex_unlock(&spdm_io_mutex);
        if (spdmst->stopping) {
            break;
        }

        // status =
        spdmdev_spdm_responder_dispatch_message (spdmst);

        // no need to do it every time
        // if (status == LIBSPDM_STATUS_SUCCESS) {
        //     // load certificates and stuff

        //     qemu_mutex_lock(&spdm_io_mutex);
        //     spdmdev_server_callback (spdmst->dev_spdm_context);
        //     qemu_mutex_unlock(&spdm_io_mutex);
        // }

        // printf("0x%X\n",atomic_read(&spdm_ctrl));
        atomic_and(&spdm_ctrl, ~(SPDMDEV_TX_TO_DEV | SPDMDEV_TX_TO_DEV_DONE));

        // printf("0x%X\n",atomic_read(&spdm_ctrl));
        if (atomic_read(&spdm_ctrl) & SPDMDEV_TX_TO_OS_DONE) {
            // printf("Raise SPDMIO_IRQ\n");
            qemu_mutex_lock_iothread();
            spdmdev_raise_irq(spdmst, SPDMIO_IRQ);
            qemu_mutex_unlock_iothread();
        }
    }
    fclose(spdmst->out_f);

    return NULL;
}


libspdm_return_t spdm_responder_acquire_sender_buffer (void *context, void **msg_buf_ptr);
void spdm_responder_release_sender_buffer(void *context, const void *msg_buf_ptr);
libspdm_return_t spdm_responder_acquire_receiver_buffer (void *context, void **msg_buf_ptr);
void spdm_responder_release_receiver_buffer(void *context, const void *msg_buf_ptr);

/*
 * SPDM acquire sender buffer
 * */
libspdm_return_t spdm_responder_acquire_sender_buffer (
    void *context, void **msg_buf_ptr)
{
    qemu_mutex_lock(&spdm_io_mutex);
    *msg_buf_ptr = (void *)malloc(SPDMDEV_MAX_BUF);
    if (*msg_buf_ptr == NULL)
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    qemu_mutex_unlock(&spdm_io_mutex);

    return LIBSPDM_STATUS_SUCCESS;
}

/*
 * SPDM release sender buffer
 * */
void spdm_responder_release_sender_buffer(
    void *context, const void *msg_buf_ptr)
{
    qemu_mutex_lock(&spdm_io_mutex);
    if (msg_buf_ptr != NULL)
        free((void *)msg_buf_ptr);
    qemu_mutex_unlock(&spdm_io_mutex);

    return;
}

/*
 * SPDM acquire receiver buffer
 * */
libspdm_return_t spdm_responder_acquire_receiver_buffer (
    void *context, void **msg_buf_ptr)
{
    qemu_mutex_lock(&spdm_io_mutex);
    *msg_buf_ptr = (void *)malloc(SPDMDEV_MAX_BUF);
    if (*msg_buf_ptr == NULL)
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    qemu_mutex_unlock(&spdm_io_mutex);


    return LIBSPDM_STATUS_SUCCESS;
}

/*
 * SPDM release receiver buffer
 * */
void spdm_responder_release_receiver_buffer(
    void *context, const void *msg_buf_ptr)
{
    qemu_mutex_lock(&spdm_io_mutex);
    if (msg_buf_ptr != NULL)
        free((void *)msg_buf_ptr);
    qemu_mutex_unlock(&spdm_io_mutex);

    return;
}

int spdmdev_init_spdm(void **spdm_context) {
  libspdm_data_parameter_t        parameter;
  size_t                          scratch_buffer_size;
  void *                          scratch_buffer;
  uint8_t                         data8;
  uint16_t                        data16;
  uint32_t                        data32;
  void *                          requester_cert_chain_buffer;
  spdm_version_number_t           spdm_version;

  *spdm_context = (void *)malloc (libspdm_get_context_size());
  if (*spdm_context == NULL) {
      return -1;
  }
  libspdm_init_context (*spdm_context);

  libspdm_register_device_io_func (*spdm_context, spdmdev_send_message, spdmdev_receive_message);

  libspdm_register_transport_layer_func(
          *spdm_context,
          (SPDMDEV_MAX_BUF - LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE - LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE),
          LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
          LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
          libspdm_transport_mctp_encode_message,
          libspdm_transport_mctp_decode_message);

  libspdm_register_device_buffer_func(
        *spdm_context,
        SPDMDEV_MAX_BUF,
        SPDMDEV_MAX_BUF,
        spdm_responder_acquire_sender_buffer,
        spdm_responder_release_sender_buffer,
        spdm_responder_acquire_receiver_buffer,
        spdm_responder_release_receiver_buffer);

  scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(*spdm_context);
  scratch_buffer = (void *)malloc(scratch_buffer_size);
  if (scratch_buffer == NULL) {
      printf("Failed to allocate scratch buffer.\n");
      free(*spdm_context);
      return -1;
  }
  libspdm_set_scratch_buffer(*spdm_context, scratch_buffer, scratch_buffer_size);

  requester_cert_chain_buffer = (void *)malloc(SPDM_MAX_CERTIFICATE_CHAIN_SIZE);
    if (requester_cert_chain_buffer == NULL) {
        printf("Failed to allocate requester_cert_chain_buffer.\n");
        return -1;
    }
    libspdm_register_cert_chain_buffer(*spdm_context, requester_cert_chain_buffer, SPDM_MAX_CERTIFICATE_CHAIN_SIZE);

    if (!libspdm_check_context(*spdm_context)) {
        printf("Failed SPDM context check.\n");
        return -1;
    }

    if (m_use_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        spdm_version = m_use_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_set_data(*spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                  &spdm_version, sizeof(spdm_version));
    }

    if (m_use_secured_message_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        if (m_use_secured_message_version != 0) {
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
            spdm_version = m_use_secured_message_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
            libspdm_set_data(*spdm_context,
                      LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                      &parameter, &spdm_version,
                      sizeof(spdm_version));
        } else {
            libspdm_set_data(*spdm_context,
                      LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                      &parameter, NULL, 0);
        }
    }

  data8 = 0;
  libspdm_zero_mem (&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &data8, sizeof(data8));

  data32 = m_use_responder_capability_flags;
  if (m_use_capability_flags != 0) {
      data32 = m_use_capability_flags;
  }
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &data32, sizeof(data32));

  data8 = m_support_measurement_spec;
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter, &data8, sizeof(data8));
  data32 = m_support_measurement_hash_algo;
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &data32, sizeof(data32));
  data32 = m_support_asym_algo;
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, sizeof(data32));
  data32 = m_support_hash_algo;
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, sizeof(data32));
  data16 = m_support_dhe_algo;
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter, &data16, sizeof(data16));
  data16 = m_support_aead_algo;
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &data16, sizeof(data16));
  data16 = m_support_req_asym_algo;
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, sizeof(data16));
  data16 = m_support_key_schedule_algo;
  libspdm_set_data (*spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16, sizeof(data16));
  data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
  libspdm_set_data(*spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                   &data8, sizeof(data8));
  data8 = SPDM_MEL_SPECIFICATION_DMTF;
  libspdm_set_data(*spdm_context, LIBSPDM_DATA_MEL_SPEC, &parameter,
                   &data8, sizeof(data8));

  data8 = 0xF0;
  libspdm_set_data(*spdm_context, LIBSPDM_DATA_HEARTBEAT_PERIOD, &parameter,
                   &data8, sizeof(data8));

  libspdm_register_get_response_func (*spdm_context, spdmdev_get_response_vendor_defined_request);

  return 0;
}

static void pci_spdmdev_realize(PCIDevice *pdev, Error **errp)
{
    spdmdev_state *spdmst = SPDM(pdev);
    uint8_t *pci_conf = pdev->config;
    // libspdm_return_t        status;

    pci_config_set_interrupt_pin(pci_conf, 1);

    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    timer_init_ms(&spdmst->dma_timer, QEMU_CLOCK_VIRTUAL, spdmdev_dma_timer, spdmst);

    qemu_mutex_init(&spdmst->thr_mutex);
    qemu_cond_init(&spdmst->thr_cond);

    qemu_mutex_init(&spdm_io_mutex);
    qemu_cond_init(&spdmst->spdm_io_cond);

    qemu_mutex_init(&spdm_ctx_mutex);

    if (spdmdev_init_spdm(&spdmst->dev_spdm_context)) {
      return;
    }
    // printf("SPDM context initialized\n");
    spdmst->out_f = NULL;

    spdm_ctrl = 0;
    spdm_buf_size = 0;

    qemu_thread_create(&spdmst->thread, "spdm_fact", spdmdev_fact_thread,
                       spdmst, QEMU_THREAD_JOINABLE);

    qemu_thread_create(&spdmst->spdm_io_thread, "spdm_io", spdmdev_io_thread,
                       spdmst, QEMU_THREAD_JOINABLE);

    memory_region_init_io(&spdmst->mmio, OBJECT(spdmst), &spdmdev_mmio_ops, spdmst,
                    "spdmst-mmio", 1 * MiB);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &spdmst->mmio);
}

static void pci_spdmdev_uninit(PCIDevice *pdev)
{
    spdmdev_state *spdmst = SPDM(pdev);

    qemu_mutex_lock(&spdmst->thr_mutex);
    qemu_mutex_lock(&spdm_io_mutex);
    spdmst->stopping = true;
    qemu_mutex_unlock(&spdm_io_mutex);
    qemu_mutex_unlock(&spdmst->thr_mutex);

    qemu_cond_signal(&spdmst->thr_cond);
    qemu_thread_join(&spdmst->thread);

    qemu_cond_destroy(&spdmst->thr_cond);
    qemu_mutex_destroy(&spdmst->thr_mutex);

    qemu_cond_signal(&spdmst->spdm_io_cond);
    qemu_thread_join(&spdmst->spdm_io_thread);

    qemu_cond_destroy(&spdmst->spdm_io_cond);
    qemu_mutex_destroy(&spdm_io_mutex);

    timer_del(&spdmst->dma_timer);
    msi_uninit(pdev);
}

static void spdmdev_obj_uint64(Object *obj, Visitor *v, const char *name,
                           void *opaque, Error **errp)
{
    uint64_t *val = opaque;

    visit_type_uint64(v, name, val, errp);
}

static void spdmdev_instance_init(Object *obj)
{
    spdmdev_state *spdmst = SPDM(obj);

    spdmst->dma_mask = (1UL << 28) - 1;
    object_property_add(obj, "dma_mask", "uint64", spdmdev_obj_uint64,
                    spdmdev_obj_uint64, NULL, &spdmst->dma_mask, NULL);
}

static void spdmdev_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_spdmdev_realize;
    k->exit = pci_spdmdev_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x10ff;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static void pci_spdmdev_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    static const TypeInfo spdmdev_info = {
        .name          = TYPE_PCI_SPDM_DEVICE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(spdmdev_state),
        .instance_init = spdmdev_instance_init,
        .class_init    = spdmdev_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&spdmdev_info);
}
type_init(pci_spdmdev_register_types)
