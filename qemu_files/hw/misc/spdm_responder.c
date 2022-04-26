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

// avoiding some annoying redefine warnings
#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#undef FALSE
#undef TRUE
#endif

// libspdm includes
#pragma GCC diagnostic ignored "-Wundef"
#include "spdm_common_lib.h"
#include "spdm_responder_lib.h"
#include "spdm_responder_lib_internal.h"
#include "spdm_device_secret_lib_internal.h"
#include <library/spdm_transport_mctp_lib.h>
#include "pci_idekm.h"
#include "pldm.h"
#include "pcidoe.h"
#include "mctp.h"
#pragma GCC diagnostic pop

#include "UioSpdmRng.h"
#include "spdm_emu_rng.c"

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>
#include <unistd.h>

#define TYPE_PCI_SPDM_DEVICE "spdm"
#define SPDM(obj)        OBJECT_CHECK(SpdmState, obj, TYPE_PCI_SPDM_DEVICE)

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
extern uint8 ts[10];

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
    void* oSpdmContext;
    int fd_cycles;
    int fd_taskclock;
    int fd_instructions;
    FILE* out_f;
} SpdmState;

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

// Prototypes
return_status
SpdmDevSendMessage (
  IN     void                    *SpdmContext,
  IN     uintn                   RequestSize,
  IN     void                    *Request,
  IN     uint64                  Timeout
  );

return_status
SpdmDevReceiveMessage (
  IN     void                    *SpdmContext,
  IN OUT uintn                   *ResponseSize,
  IN OUT void                    *Response,
  IN     uint64                  Timeout
  );

return_status
SpdmGetResponseVendorDefinedRequest (
  IN     void                *SpdmContext,
  IN     uint32               *SessionId,
  IN     boolean              IsAppMessage,
  IN     uintn                RequestSize,
  IN     void                 *Request,
  IN OUT uintn                *ResponseSize,
     OUT void                 *Response
  );

return_status
QemuSpdmGetResponseVendorDefinedRequest (
  IN     void                *SpdmContext,
  IN     uint32               *SessionId,
  IN     boolean              IsAppMessage,
  IN     uintn                RequestSize,
  IN     void                 *Request,
  IN OUT uintn                *ResponseSize,
     OUT void                 *Response
  );

return_status
QemuTestSpdmProcessPacketCallback (
  IN     uint32                       *SessionId,
  IN     boolean                      IsAppMessage,
  IN     void                         *Request,
  IN     uintn                        RequestSize,
     OUT void                         *Response,
  IN OUT uintn                        *ResponseSize
  );

void
QemuSpdmServerCallback (
  IN void                         *SpdmContext
  );

return_status spdmdev_init_perf_events(int *fd_cycles, int *fd_taskclock, int *fd_instructions);

uint32 myGetRand(void);

unsigned int mySeed = 12345;
uint32 myGetRand(void) {
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
    PCI_PROTOCAL_ID_IDE_KM,
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

SECURE_SESSION_RESPONSE_RNG mSecureRngResponse = {
  {
    MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI
  },
};

const char* spdmdev_requestreponsecode_to_str(uint8 code);

const char* spdmdev_requestreponsecode_to_str(uint8 code) {
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

    case SPDM_GET_DIGESTS: return "get_digest";
    case SPDM_GET_CERTIFICATE: return "get_certificate";
    case SPDM_CHALLENGE: return "challenge";
    case SPDM_GET_VERSION: return "get_version";
    case SPDM_GET_MEASUREMENTS: return "get_measurement";
    case SPDM_GET_CAPABILITIES: return "get_capabilities";
    case SPDM_NEGOTIATE_ALGORITHMS: return "negotiate_algorithms";
    case SPDM_VENDOR_DEFINED_REQUEST: return "get_random_spdm";
    case SPDM_RESPOND_IF_READY: return "SPDM_RESPOND_IF_READY";
    case SPDM_KEY_EXCHANGE: return "key_exchange";
    case SPDM_FINISH: return "finish";
    case SPDM_PSK_EXCHANGE: return "key_exchangePSK";
    case SPDM_PSK_FINISH: return "finishPSK";
    case SPDM_HEARTBEAT: return "heartbeat";
    case SPDM_KEY_UPDATE: return "key_update";
    case SPDM_GET_ENCAPSULATED_REQUEST: return "SPDM_GET_ENCAPSULATED_REQUEST";
    case SPDM_DELIVER_ENCAPSULATED_RESPONSE: return "SPDM_DELIVER_ENCAPSULATED_RESPONSE";
    case SPDM_END_SESSION: return "end_session";
    default: return "Unknown code";
  }
  return NULL;

}

int spdmdev_init_spdm(void **spdm_context);

/**
  Process a packet in the current SPDM session.

  @param  This                         Indicates a pointer to the calling context.
  @param  SessionId                    ID of the session.
  @param  Request                      A pointer to the request data.
  @param  RequestSize                  Size of the request data.
  @param  Response                     A pointer to the response data.
  @param  ResponseSize                 Size of the response data. On input, it means the size of Data
                                       buffer. On output, it means the size of copied Data buffer if
                                       RETURN_SUCCESS, and means the size of desired Data buffer if
                                       RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS                  The SPDM request is set successfully.
  @retval RETURN_INVALID_PARAMETER        The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_NOT_FOUND                The DataType cannot be found.
  @retval RETURN_NOT_READY                The DataType is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                          to execute.
**/

return_status
QemuTestSpdmProcessPacketCallback (
  IN     uint32                       *SessionId,
  IN     boolean                      IsAppMessage,
  IN     void                         *Request,
  IN     uintn                        RequestSize,
     OUT void                         *Response,
  IN OUT uintn                        *ResponseSize
  )
{
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
  spdm_vendor_defined_request_mine_t   *SpmdRequest;
#pragma GCC diagnostic pop
  secure_session_request_mine_t        *AppRequest;
  SECURE_SESSION_REQUEST_RNG         *AppRequestRng;

  if (!IsAppMessage) {
    SpmdRequest = Request;
    ASSERT ((RequestSize >= sizeof(spdm_vendor_defined_request_mine_t)) && (RequestSize < sizeof(spdm_vendor_defined_request_mine_t) + 4));
    ASSERT (SpmdRequest->header.request_response_code == SPDM_VENDOR_DEFINED_REQUEST);
    ASSERT (SpmdRequest->standard_id == SPDM_REGISTRY_ID_PCISIG);
    ASSERT (SpmdRequest->vendor_id == SPDM_VENDOR_ID_PCISIG);
    ASSERT (SpmdRequest->payload_length == sizeof(pci_protocol_header_t) + sizeof(pci_ide_km_query_t));
    ASSERT (SpmdRequest->pci_protocol.protocol_id == PCI_PROTOCAL_ID_IDE_KM);
    ASSERT (SpmdRequest->pci_ide_km_query.header.object_id == PCI_IDE_KM_OBJECT_ID_QUERY);
    copy_mem (Response, &mVendorDefinedResponse, sizeof(mVendorDefinedResponse));
    *ResponseSize = sizeof(mVendorDefinedResponse);
  } else {
    AppRequest = Request;
    AppRequestRng = Request;
    // printf("AppRequest->mctp_header.message_type %X \n", AppRequest->mctp_header.message_type);
    if (AppRequest->mctp_header.message_type == MCTP_MESSAGE_TYPE_PLDM) {
      ASSERT (RequestSize == sizeof(secure_session_request_mine_t));
      ASSERT (AppRequest->mctp_header.message_type == MCTP_MESSAGE_TYPE_PLDM);
      ASSERT (AppRequest->pldm_header.pldm_type == PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY);
      ASSERT (AppRequest->pldm_header.pldm_command_code == PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID);

      copy_mem (Response, &mSecureSessionResponse, sizeof(mSecureSessionResponse));
      *ResponseSize = sizeof(mSecureSessionResponse);
    } else if (AppRequestRng->MctpHeader.message_type == MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI) {
      ASSERT (AppRequestRng->Req == RNG_REQ_CODE);
      mSecureRngResponse.Rng = myGetRand();
      // printf("Sending random number %d\n", mSecureRngResponse.Rng);
      copy_mem (Response, &mSecureRngResponse, sizeof(mSecureRngResponse));
      *ResponseSize = sizeof(mSecureRngResponse);
    } else {
        return RETURN_DEVICE_ERROR;
    }
  }

  return RETURN_SUCCESS;
}

return_status
QemuSpdmGetResponseVendorDefinedRequest (
  IN     void                *SpdmContext,
  IN     uint32               *SessionId,
  IN     boolean              IsAppMessage,
  IN     uintn                RequestSize,
  IN     void                 *Request,
  IN OUT uintn                *ResponseSize,
     OUT void                 *Response
  )
{
  return_status  Status;

  Status = QemuTestSpdmProcessPacketCallback (
             SessionId,
             IsAppMessage,
             Request,
             RequestSize,
             Response,
             ResponseSize
             );
  if (RETURN_ERROR(Status)) {
    spdm_generate_error_response (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
  }
  return RETURN_SUCCESS;
}


void
QemuSpdmServerCallback (
  IN void                         *SpdmContext
  )
{
  boolean                      Res;
  void                         *Data;
  uintn                        DataSize;
  spdm_data_parameter_t        Parameter;
  uint8                        Data8;
  uint16                       Data16;
  uint32                       Data32;
  return_status                Status;
  void                         *Hash;
  uintn                        HashSize;
  uint8                        Index;

  zero_mem (&Parameter, sizeof(Parameter));
  Parameter.location = SPDM_DATA_LOCATION_CONNECTION;

  DataSize = sizeof(Data32);
  spdm_get_data (SpdmContext, SPDM_DATA_CONNECTION_STATE, &Parameter, &Data32, &DataSize);
  if (Data32 != SPDM_CONNECTION_STATE_NEGOTIATED) {
    return ;
  }

  DataSize = sizeof(Data32);
  spdm_get_data (SpdmContext, SPDM_DATA_MEASUREMENT_HASH_ALGO, &Parameter, &Data32, &DataSize);
  m_use_measurement_hash_algo = Data32;
  DataSize = sizeof(Data32);
  spdm_get_data (SpdmContext, SPDM_DATA_BASE_ASYM_ALGO, &Parameter, &Data32, &DataSize);
  m_use_asym_algo = Data32;
  DataSize = sizeof(Data32);
  spdm_get_data (SpdmContext, SPDM_DATA_BASE_HASH_ALGO, &Parameter, &Data32, &DataSize);
  m_use_hash_algo = Data32;
  DataSize = sizeof(Data16);
  spdm_get_data (SpdmContext, SPDM_DATA_REQ_BASE_ASYM_ALG, &Parameter, &Data16, &DataSize);
  m_use_req_asym_algo = Data16;

  Res = read_responder_public_certificate_chain (m_use_hash_algo, m_use_asym_algo, &Data, &DataSize, NULL, NULL);
  if (Res) {
    zero_mem (&Parameter, sizeof(Parameter));
    Parameter.location = SPDM_DATA_LOCATION_LOCAL;
    Data8 = m_use_slot_count;
    spdm_set_data (SpdmContext, SPDM_DATA_LOCAL_SLOT_COUNT, &Parameter, &Data8, sizeof(Data8));

    for (Index = 0; Index < m_use_slot_count; Index++) {
      Parameter.additional_data[0] = Index;
      spdm_set_data (SpdmContext, SPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &Parameter, Data, DataSize);
    }
    // do not free it
  }

  if (m_use_slot_id == 0xFF) {
    Res = read_requester_public_certificate_chain (m_use_hash_algo, m_use_req_asym_algo, &Data, &DataSize, NULL, NULL);
    if (Res) {
      zero_mem (&Parameter, sizeof(Parameter));
      Parameter.location = SPDM_DATA_LOCATION_LOCAL;
      spdm_set_data (SpdmContext, SPDM_DATA_PEER_PUBLIC_CERT_CHAIN, &Parameter, Data, DataSize);
      // Do not free it.
    }
  } else {
    Res = read_requester_root_public_certificate (m_use_hash_algo, m_use_req_asym_algo, &Data, &DataSize, &Hash, &HashSize);
    if (Res) {
      zero_mem (&Parameter, sizeof(Parameter));
      Parameter.location = SPDM_DATA_LOCATION_LOCAL;
      spdm_set_data (SpdmContext, SPDM_DATA_PEER_PUBLIC_ROOT_CERT_HASH, &Parameter, Hash, HashSize);
      // Do not free it.
    }
  }

  if (Res) {
    Data8 = m_use_mut_auth;
    if (Data8 != 0) {
      Data8 |= SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    }
    Parameter.additional_data[0] = m_use_slot_id;
    Parameter.additional_data[1] = m_use_measurement_summary_hash_type;
    spdm_set_data (SpdmContext, SPDM_DATA_MUT_AUTH_REQUESTED, &Parameter, &Data8, sizeof(Data8));

    Data8 = (m_use_mut_auth & 0x1);
    spdm_set_data (SpdmContext, SPDM_DATA_BASIC_MUT_AUTH_REQUESTED, &Parameter, &Data8, sizeof(Data8));
  }

  Status = spdm_set_data (SpdmContext, SPDM_DATA_PSK_HINT, NULL, (void *) TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  if (RETURN_ERROR(Status)) {
    fprintf (stderr, "spdm_set_data error- %x\n", (uint32_t)Status);
  }

  return ;
}

// Functions to be used with SpdmRegisterDeviceIoFunc
return_status
SpdmDevSendMessage (
  IN     void                    *SpdmContext,
  IN     uintn                   RequestSize,
  IN     void                    *Request,
  IN     uint64                  Timeout
  )
{
    if (RequestSize > sizeof(spdm_buf)) {
        fprintf(stderr, "RequestSize too large %llu\n", RequestSize);
        return RETURN_DEVICE_ERROR;
    }

    if (! (atomic_read(&spdm_ctrl) & SPDMDEV_TX_TO_DEV_DONE)) {
        fprintf(stderr, "Wrong spdm_ctrl flags 0x%X\n", atomic_read(&spdm_ctrl));
        return RETURN_DEVICE_ERROR;
    }

    atomic_or(&spdm_ctrl, SPDMDEV_TX_TO_OS);
    atomic_set(&spdm_buf_size, RequestSize);
    qemu_mutex_lock(&spdm_io_mutex);
    memcpy(spdm_buf, Request, RequestSize);
    qemu_mutex_unlock(&spdm_io_mutex);
    atomic_or(&spdm_ctrl, SPDMDEV_TX_TO_OS_DONE);

    return RETURN_SUCCESS;
}

return_status
SpdmDevReceiveMessage (
  IN     void                    *SpdmContext,
  IN OUT uintn                   *ResponseSize,
  IN OUT void                    *Response,
  IN     uint64                  Timeout
  )
{
    // printf("SpdmDevReceiveMessage\n");
    if (*ResponseSize < atomic_read(&spdm_buf_size)) {
        fprintf(stderr, "*ResponseSize too small %llu\n", *ResponseSize);
        return RETURN_DEVICE_ERROR;
    }
    // printf("SpdmDevReceiveMessage memcpy\n");
    qemu_mutex_lock(&spdm_io_mutex);
    memcpy(Response, spdm_buf, spdm_buf_size);
    qemu_mutex_unlock(&spdm_io_mutex);
    *ResponseSize = atomic_read(&spdm_buf_size);

    return RETURN_SUCCESS;
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

return_status spdmdev_init_perf_events(int *fd_cycles, int *fd_taskclock, int *fd_instructions) { //SpdmState *spdmst) {
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

  pe.type = PERF_TYPE_HARDWARE;
  pe.config = PERF_COUNT_HW_CPU_CYCLES;

  *fd_cycles = spdmdev_perf_event_open(&pe, 0, -1, -1, 0);
  if (*fd_cycles == -1) {
      fprintf(stderr, "Error opening perf leader fd %llx\n", pe.config);
      return RETURN_DEVICE_ERROR;
  }

  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_TASK_CLOCK;

  *fd_taskclock = spdmdev_perf_event_open(&pe, 0, -1, *fd_cycles, 0);
  if (*fd_taskclock == -1) {
      fprintf(stderr, "Error opening perf TASK_CLOCK fd %llx\n", pe.config);
      return RETURN_DEVICE_ERROR;
  }

  pe.type = PERF_TYPE_HARDWARE;
  pe.config = PERF_COUNT_HW_INSTRUCTIONS;

  *fd_instructions = spdmdev_perf_event_open(&pe, 0, -1, *fd_cycles, 0);
  if (*fd_instructions == -1) {
      fprintf(stderr, "Error opening perf INSTRUCTIONS fd %llx\n", pe.config);
      return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}

// Device management functions
static bool spdmdev_msi_enabled(SpdmState *spdmst)
{
    return msi_enabled(&spdmst->pdev);
}

static void spdmdev_raise_irq(SpdmState *spdmst, uint32_t val)
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

static void spdmdev_lower_irq(SpdmState *spdmst, uint32_t val)
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

static dma_addr_t spdmdev_clamp_addr(const SpdmState *spdmst, dma_addr_t addr)
{
    dma_addr_t res = addr & spdmst->dma_mask;

    if (addr != res) {
        printf("SPDM: clamping DMA %#.16"PRIx64" to %#.16"PRIx64"!\n", addr, res);
    }

    return res;
}

static void spdmdev_dma_timer(void *opaque)
{
    SpdmState *spdmst = opaque;
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

static void dma_rw(SpdmState *spdmst, bool write, dma_addr_t *val, dma_addr_t *dma,
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
    SpdmState *spdmst = opaque;
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
    SpdmState *spdmst = opaque;

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
        atomic_set(&spdm_ctrl, val);
        if (val & SPDMDEV_TX_TO_DEV_DONE && ! (val & SPDMDEV_TX_TO_OS)) {

            qemu_mutex_lock(&spdm_io_mutex);
            qemu_cond_signal(&spdmst->spdm_io_cond);
            qemu_mutex_unlock(&spdm_io_mutex);

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


static void *spdmdev_fact_thread(void *opaque)
{
    SpdmState *spdmst = opaque;

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
            ret = myGetRand();
            ioctl(local_cyc, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
            read(local_cyc, &rf, sizeof(rf));
            if (spdmst->out_f) {
              fprintf(spdmst->out_f, "get_random_no_spdm,\t%lu cycles,\t%lu ns,\t%lu instructions\n",
              rf.values[CYCLES].value, rf.values[TASK_CLOCK].value, rf.values[INSTRUCTIONS].value);
              fflush(spdmst->out_f);
            }
        }

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

int should_accumulate(uint8 current_code, uint8 current_param2);

int keep_accumulating(uint16 previous_code, uint8 current_code);

const char* get_suffix(uint8 code, boolean usePsk, int accumulating);

return_status SpdmDevSpdmResponderDispatchMessage (
  IN     SpdmState *spdmst
  );

int should_accumulate(uint8 current_code, uint8 current_param2) {
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

int keep_accumulating(uint16 previous_code, uint8 current_code) {
  if (previous_code == current_code) {
    return 1;
  }
  // Keep accumalting if a mutual authentication is taking place
  if (current_code == SPDM_GET_ENCAPSULATED_REQUEST || current_code == SPDM_DELIVER_ENCAPSULATED_RESPONSE) {
    return 1;
  }
  return 0;
}

const char* get_suffix(uint8 code, boolean usePsk, int accumulating) {
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
    if (usePsk) {
      return "PSK";
    } else {
      return "NoPSK";
    }
  }
  return "";
}

return_status
SpdmDevSpdmResponderDispatchMessage (
  IN     SpdmState *spdmst
  )
{
  return_status             Status;
  spdm_context_t           *SpdmContext;
  uint8                     Request[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  uintn                     RequestSize;
  uint8                     Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  uintn                     ResponseSize;
  uint32                    *SessionId;
  boolean                   IsAppMessage;

  spdm_session_info_t       *SessionInfo = NULL;
  boolean                   usePsk = FALSE;

  struct read_format        rf;
  uint8                     RequestResponseCode;

  // static variables to maintain accumation state
  static uint64_t cycle_accum = 0;
  static uint64_t clock_accum = 0;
  static uint64_t instr_accum = 0;
  static uint16_t previous_code = 0xFFFF;
  static int count_getversion = 0;
  static int accumulating = 0;

  SpdmContext = spdmst->oSpdmContext;

  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

  RequestSize = sizeof(Request);
  Status = SpdmContext->receive_message (SpdmContext, &RequestSize, Request, 0);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  ResponseSize = sizeof(Response);
  // Status = SpdmProcessMessage (SpdmContext, &SessionId, Request, RequestSize, Response, &ResponseSize);
  Status = spdm_process_request (SpdmContext, &SessionId, &IsAppMessage, RequestSize, Request);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
  if (SessionId != NULL) {
    SessionInfo = spdm_get_session_info_via_session_id (SpdmContext, *SessionId);
    if (SessionInfo) usePsk = SessionInfo->use_psk;
  }
  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

  Status = spdm_build_response (SpdmContext, SessionId, IsAppMessage, &ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  Status = SpdmContext->send_message (SpdmContext, ResponseSize, Response, 0);

  ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
  read(spdmst->fd_cycles, &rf, sizeof(rf));

  if (IsAppMessage) {
    RequestResponseCode = SPDM_VENDOR_DEFINED_REQUEST;
  } else {
    RequestResponseCode = ((spdm_message_header_t*)SpdmContext->last_spdm_request)->request_response_code;
  }

  if (accumulating) {
    // fprintf(spdmst->out_f, "\taccumulating is true %02x %02x\n", previous_code, RequestResponseCode);
    if (keep_accumulating(previous_code, RequestResponseCode)) {
      // fprintf(spdmst->out_f, "\t\tkeep_accumulating() %02x %02x\n", previous_code, RequestResponseCode);
      cycle_accum += rf.values[CYCLES].value;
      clock_accum += rf.values[TASK_CLOCK].value;
      instr_accum += rf.values[INSTRUCTIONS].value;
    } else {
      // fprintf(spdmst->out_f, "\t\twill not keep_accumulating()\n");
      fprintf(spdmst->out_f, "%s%s,\t%lu cycles,\t%lu ns,\t%lu instructions\n",
              spdmdev_requestreponsecode_to_str(previous_code), get_suffix(previous_code, usePsk, accumulating),
              cycle_accum, clock_accum, instr_accum);
      accumulating = 0;
      cycle_accum = instr_accum = clock_accum = 0;
    }
  }

  if (RequestResponseCode == SPDM_GET_VERSION) {
    char filename[sizeof("uio_responder_iXXXXX.log")];
    void *dummy_ctx;
    struct read_format rf_inner;
    count_getversion++;
    if (spdmst->out_f != NULL) {
      fclose(spdmst->out_f);
      spdmst->out_f = NULL;
    }
    sprintf(filename, "uio_responder_i%d.log", count_getversion);
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
    // fprintf(spdmst->out_f, "\taccumulating is false %02x %02x\n", previous_code, RequestResponseCode);
    cycle_accum += rf.values[CYCLES].value;
    clock_accum += rf.values[TASK_CLOCK].value;
    instr_accum += rf.values[INSTRUCTIONS].value;
    if (should_accumulate(RequestResponseCode, ((spdm_message_header_t*)SpdmContext->last_spdm_request)->param2)) {
      // fprintf(spdmst->out_f, "\t\tstart accumulating now %02x %02x\n", previous_code, RequestResponseCode);
      accumulating = 1;
    } else {
      fprintf(spdmst->out_f, "%s%s,\t%lu cycles,\t%lu ns,\t%lu instructions\n",
              spdmdev_requestreponsecode_to_str(RequestResponseCode), get_suffix(RequestResponseCode, usePsk, accumulating),
              cycle_accum, clock_accum, instr_accum);
      cycle_accum = instr_accum = clock_accum = 0;
    }
  }

  if (Status == RETURN_SUCCESS && RequestResponseCode == SPDM_NEGOTIATE_ALGORITHMS) {
    // load certificates and stuff
    ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
    ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
    QemuSpdmServerCallback (spdmst->oSpdmContext);
    ioctl(spdmst->fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
    read(spdmst->fd_cycles, &rf, sizeof(rf));
    fprintf(spdmst->out_f, "load_certificates,\t%lu cycles,\t%lu ns,\t%lu instructions\n",
              rf.values[CYCLES].value, rf.values[TASK_CLOCK].value, rf.values[INSTRUCTIONS].value);
  }

  if (!(RequestResponseCode == SPDM_GET_ENCAPSULATED_REQUEST || RequestResponseCode == SPDM_DELIVER_ENCAPSULATED_RESPONSE)) {
    previous_code = RequestResponseCode;
  }
  fflush(spdmst->out_f);

  return Status;
}

static void *spdmdev_io_thread(void *opaque)
{
    SpdmState *spdmst = opaque;
    return_status Status;

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

        Status =
        SpdmDevSpdmResponderDispatchMessage (spdmst);

        if (Status == RETURN_SUCCESS) {
            // load certificates and stuff
            QemuSpdmServerCallback (spdmst->oSpdmContext);
        }

        atomic_and(&spdm_ctrl, ~(SPDMDEV_TX_TO_DEV | SPDMDEV_TX_TO_DEV_DONE));

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

int spdmdev_init_spdm(void **spdm_context) {
  spdm_data_parameter_t          Parameter;
  uint8_t                        Data8;
  uint16_t                       Data16;
  uint32_t                       Data32;

  *spdm_context = (void *)malloc (spdm_get_context_size());
  if (*spdm_context == NULL) {
      return -1;
  }
  spdm_init_context (*spdm_context);

  spdm_register_device_io_func (*spdm_context, SpdmDevSendMessage, SpdmDevReceiveMessage);
  // spdm_register_transport_layer_func (*spdm_context, SpdmTransportPciDoeEncodeMessage, SpdmTransportPciDoeDecodeMessage);
  spdm_register_transport_layer_func (*spdm_context, spdm_transport_mctp_encode_message, spdm_transport_mctp_decode_message);
  Data8 = 0;
  zero_mem (&Parameter, sizeof(Parameter));
  Parameter.location = SPDM_DATA_LOCATION_LOCAL;
  spdm_set_data (*spdm_context, SPDM_DATA_CAPABILITY_CT_EXPONENT, &Parameter, &Data8, sizeof(Data8));

  Data32 = m_use_responder_capability_flags;
  if (m_use_capability_flags != 0) {
      Data32 = m_use_capability_flags;
  }
  spdm_set_data (*spdm_context, SPDM_DATA_CAPABILITY_FLAGS, &Parameter, &Data32, sizeof(Data32));

  Data8 = m_support_measurement_spec;
  spdm_set_data (*spdm_context, SPDM_DATA_MEASUREMENT_SPEC, &Parameter, &Data8, sizeof(Data8));
  Data32 = m_support_measurement_hash_algo;
  spdm_set_data (*spdm_context, SPDM_DATA_MEASUREMENT_HASH_ALGO, &Parameter, &Data32, sizeof(Data32));
  Data32 = m_support_asym_algo;
  spdm_set_data (*spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &Parameter, &Data32, sizeof(Data32));
  Data32 = m_support_hash_algo;
  spdm_set_data (*spdm_context, SPDM_DATA_BASE_HASH_ALGO, &Parameter, &Data32, sizeof(Data32));
  Data16 = m_support_dhe_algo;
  spdm_set_data (*spdm_context, SPDM_DATA_DHE_NAME_GROUP, &Parameter, &Data16, sizeof(Data16));
  Data16 = m_support_aead_algo;
  spdm_set_data (*spdm_context, SPDM_DATA_AEAD_CIPHER_SUITE, &Parameter, &Data16, sizeof(Data16));
  Data16 = m_support_req_asym_algo;
  spdm_set_data (*spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &Parameter, &Data16, sizeof(Data16));
  Data16 = m_support_key_schedule_algo;
  spdm_set_data (*spdm_context, SPDM_DATA_KEY_SCHEDULE, &Parameter, &Data16, sizeof(Data16));

  spdm_register_get_response_func (*spdm_context, QemuSpdmGetResponseVendorDefinedRequest);

  return 0;
}

static void pci_spdmdev_realize(PCIDevice *pdev, Error **errp)
{
    SpdmState *spdmst = SPDM(pdev);
    uint8_t *pci_conf = pdev->config;

    pci_config_set_interrupt_pin(pci_conf, 1);

    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    timer_init_ms(&spdmst->dma_timer, QEMU_CLOCK_VIRTUAL, spdmdev_dma_timer, spdmst);

    qemu_mutex_init(&spdmst->thr_mutex);
    qemu_cond_init(&spdmst->thr_cond);

    qemu_mutex_init(&spdm_io_mutex);
    qemu_cond_init(&spdmst->spdm_io_cond);

    if (spdmdev_init_spdm(&spdmst->oSpdmContext)) {
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
    SpdmState *spdmst = SPDM(pdev);

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
    SpdmState *spdmst = SPDM(obj);

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
        .instance_size = sizeof(SpdmState),
        .instance_init = spdmdev_instance_init,
        .class_init    = spdmdev_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&spdmdev_info);
}
type_init(pci_spdmdev_register_types)
