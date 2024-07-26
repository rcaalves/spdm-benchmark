#include "spdm_common_lib.h"
#include "spdm_requester_lib.h"
#include "memlib.h"
#include <library/spdm_transport_mctp_lib.h>
#include "uio_requester_aux.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>

#include "spdm_emu.h"

#define SPDM_IO_SIZE    0x100000
#define FACT_IRQ        0x00000001

#define SPDM_CARD_VERSION_ADDR    0x0
#define SPDM_CARD_LIVENESS_ADDR  (0x4  / sizeof(*bar0))
#define SPDM_RAISE_INT_ADDR      (0x60 / sizeof(*bar0))
#define SPDM_CLEAR_INT_ADDR      (0x64 / sizeof(*bar0))
#define SPDM_FACT_NUMBER_ADDR    (0x8  / sizeof(*bar0))
#define SPDM_FACT_STATUS_ADDR    (0x20 / sizeof(*bar0))

#define SPDM_STATUS_IRQFACT         0x80
#define SPDM_STATUS_FACTCOMPUTING   0x01

#define SPDMDEV_TXRX_CTRL_ADDR      (0xA0 / sizeof(*bar0))
#define SPDMDEV_TXRX_DATA_SIZEADDR  (0xA4 / sizeof(*bar0))
#define SPDMDEV_TXRX_DATA_ADDR      (0xA8 / sizeof(*bar0))
#define SPDMDEV_MEAS_TAMPER_ADDR    (0xB0 / sizeof(*bar0))
#define SPDMDEV_TX_TO_DEV           (0x1)
#define SPDMDEV_TX_TO_DEV_DONE      (0x2)
#define SPDMDEV_TX_TO_OS            (0x4)
#define SPDMDEV_TX_TO_OS_DONE       (0x8)
#define SPDMDEV_MAX_BUF             (4096)


int uiofd;
int configfd;
int bar0fd;
unsigned char command_high;
volatile uint32_t *bar0; // is this required to be volatile?
unsigned icount;
uint32_t status;

void uio_requester_write_to_tamper(uint32_t v) {
  bar0[SPDMDEV_MEAS_TAMPER_ADDR] = v;
}

libspdm_return_t
spdm_uio_send_message (
      void                    *spdm_context,
      size_t                   request_size,
      const void              *request,
      uint64_t                  timeout
  )
{
  volatile uint8_t *bar8bit;
  uint32_t i;
  INFO_PRINT("%s()\n", __func__);

  if (request_size > SPDMDEV_MAX_BUF) {
    bar0[SPDMDEV_TXRX_DATA_SIZEADDR] = 0;
    ERROR_PRINT("Request_size too large (%lu)\n", request_size);
    return LIBSPDM_STATUS_SEND_FAIL;
  }
  bar0[SPDMDEV_TXRX_DATA_SIZEADDR] = request_size;

  status = bar0[SPDMDEV_TXRX_CTRL_ADDR];
  if (status & SPDMDEV_TX_TO_DEV || status & SPDMDEV_TX_TO_OS) {
    ERROR_PRINT("Wrong SPDMDEV_TXRX_CTRL_ADDR flags (0x%X)\n", status);
    return LIBSPDM_STATUS_SEND_FAIL;
  }

  bar0[SPDMDEV_TXRX_CTRL_ADDR] |= SPDMDEV_TX_TO_DEV;

  bar8bit = (volatile uint8_t *) (bar0 + SPDMDEV_TXRX_DATA_ADDR);
  for(i=0; i< request_size; i++) {
    // INFO_PRINT("bar8bit[0x%X] = 0x%X\n", i, ((uint8*)request)[i]);
    bar8bit[i] = ((uint8_t*)request)[i];
  }

  bar0[SPDMDEV_TXRX_CTRL_ADDR] |= SPDMDEV_TX_TO_DEV_DONE;

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t
spdm_uio_receive_message (
  void                    *spdm_context,
  size_t                   *response_size,
  void                    **response,
  uint64_t                  timeout
  )
{
  volatile uint8_t *bar8bit;
  uint32_t i;
  int err;
  INFO_PRINT("%s()\n", __func__);

  while (1) {
    /* Wait for next interrupt. */
    INFO_PRINT("Wait for interrupt\n");
    err = read(uiofd, &icount, 4);
    if (err != 4) {
      perror("uio read:");
      break;
    }

    if (bar0[SPDMDEV_TXRX_CTRL_ADDR] & SPDMDEV_TX_TO_OS_DONE) {

      if (bar0[SPDMDEV_TXRX_DATA_SIZEADDR] > *response_size) {
        ERROR_PRINT("SPDMDEV_TXRX_DATA_SIZEADDR too large (%u)\n", bar0[SPDMDEV_TXRX_DATA_SIZEADDR]);
        return LIBSPDM_STATUS_RECEIVE_FAIL;
      }

      *response_size = bar0[SPDMDEV_TXRX_DATA_SIZEADDR];

      bar8bit = (volatile uint8_t *) (bar0 + SPDMDEV_TXRX_DATA_ADDR);
      for(i=0; i< *response_size; i++) {
        ((uint8_t*)*response)[i] = bar8bit[i];
        // INFO_PRINT("Response[0x%X] = %X\n", i, ((uint8*)response)[i]);
      }

      // DUMP_ARRAY("", *response, *response_size);

      bar0[SPDMDEV_TXRX_CTRL_ADDR] &= ~(SPDMDEV_TX_TO_OS | SPDMDEV_TX_TO_OS_DONE);
      break;
    } else {
      INFO_PRINT("Awaiting the correct IRQ 0x%x\n", status);
    }
    /* Re-enable interrupts. */
    INFO_PRINT("Re-enable interrupt\n");
    err = pwrite(configfd, &command_high, 1, 5);
    if (err != 1) {
      perror("config write:");
    }
  }

  /* Re-enable interrupts. */
  INFO_PRINT("Re-enable interrupt\n");
  err = pwrite(configfd, &command_high, 1, 5);
  if (err != 1) {
    perror("config write:");
  }

  return LIBSPDM_STATUS_SUCCESS;
}

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                    group_fd, flags);
    return ret;
}


/*
 * SPDM acquire sender buffer
 * */
libspdm_return_t spdm_device_acquire_sender_buffer (
  void *context, void **msg_buf_ptr)
{
  *msg_buf_ptr = (void *)malloc(SPDMDEV_MAX_BUF);
  if (*msg_buf_ptr == NULL)
    return LIBSPDM_STATUS_ACQUIRE_FAIL;

  return LIBSPDM_STATUS_SUCCESS;
}

/*
 * SPDM release sender buffer
 * */
void spdm_device_release_sender_buffer (
  void *context, const void *msg_buf_ptr)
{
  if (msg_buf_ptr != NULL)
    free((void *)msg_buf_ptr);

  return;
}

/*
 * SPDM acquire receiver buffer
 * */
libspdm_return_t spdm_device_acquire_receiver_buffer (
  void *context, void **msg_buf_ptr)
{
  *msg_buf_ptr = (void *)malloc(SPDMDEV_MAX_BUF);
  if (*msg_buf_ptr == NULL)
    return LIBSPDM_STATUS_ACQUIRE_FAIL;

  return LIBSPDM_STATUS_SUCCESS;
}

/*
 * SPDM release receiver buffer
 * */
void spdm_device_release_receiver_buffer (
  void *context, const void *msg_buf_ptr)
{
  if (msg_buf_ptr != NULL)
    free((void *)msg_buf_ptr);

  return;
}

libspdm_return_t uio_requester_init (struct uio_requester_t *uior) {
  int err;
  int i;
  struct perf_event_attr pe;

  uiofd = open("/dev/uio0", O_RDWR);
  if (uiofd < 0) {
    perror("uio open:");
    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
  }

  configfd = open("/sys/class/uio/uio0/device/config", O_RDWR);
  if (configfd < 0) {
    perror("config open:");
    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
  }

  /* Read and cache command value */
  err = pread(configfd, &command_high, 1, 5);
  if (err != 1) {
    perror("command config read:");
    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
  }
  command_high &= ~0x4;

  /* Map MMIO */
  bar0fd = open("/sys/class/uio/uio0/device/resource0", O_RDWR);
  if (bar0fd < 0) {
    perror("bar0fd open:");
    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
  }

  /* Mmap the device's BAR */
  bar0 = (volatile uint32_t *)mmap(NULL, SPDM_IO_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, bar0fd, 0);
  if (bar0 == MAP_FAILED) {
    perror("Error mapping bar0!");
    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
  }
  INFO_PRINT("Version = %08X\n", bar0[SPDM_CARD_VERSION_ADDR]);

  /* Test the invertor function */
  i = 0x12345678;
  bar0[SPDM_CARD_LIVENESS_ADDR] = i;
  INFO_PRINT("Inversion: %08X --> %08X\n", i, bar0[SPDM_CARD_LIVENESS_ADDR]);

  /* Clear previous interrupt */
  bar0[SPDM_CLEAR_INT_ADDR] = 0xFFFFFFFF;

  INFO_PRINT("Let us ask SPDM device to calculate 5!\n");
  bar0[SPDM_FACT_STATUS_ADDR] = bar0[SPDM_FACT_STATUS_ADDR] | SPDM_STATUS_IRQFACT;
  bar0[SPDM_FACT_NUMBER_ADDR] = 5;

  while (1) {
    /* Wait for next interrupt. */
    err = read(uiofd, &icount, 4);
    if (err != 4) {
      perror("uio read:");
      break;
    }

    status = bar0[SPDM_FACT_STATUS_ADDR];
    if (status & SPDM_STATUS_IRQFACT && !(status & SPDM_STATUS_FACTCOMPUTING)) {
      INFO_PRINT ("Calculated factorial is: %u\n", bar0[SPDM_FACT_NUMBER_ADDR]);
      bar0[SPDM_CLEAR_INT_ADDR] = FACT_IRQ;
      break;
    } else {
      INFO_PRINT("Awaiting the correct IRQ 0x%x\n", status);
    }
  }

  bar0[SPDMDEV_TXRX_CTRL_ADDR] = 0;

  /* re-enable interrupts. */
  err = pwrite(configfd, &command_high, 1, 5);
  if (err != 1) {
    perror("config write:");
    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
  }

  uior->spdm_context = NULL;
  memset(&pe, 0, sizeof(struct perf_event_attr));
  pe.size = sizeof(struct perf_event_attr);
  pe.disabled = 1;
  pe.exclude_kernel = 1;
  pe.exclude_hv = 1;
  pe.read_format = PERF_FORMAT_GROUP |
                   // PERF_FORMAT_TOTAL_TIME_ENABLED |
                   PERF_FORMAT_TOTAL_TIME_RUNNING |
                   // PERF_FORMAT_ID;
                   0;

  pe.type = PERF_TYPE_HARDWARE;
  pe.config = PERF_COUNT_HW_CPU_CYCLES;

  uior->fd_cycles = perf_event_open(&pe, 0, -1, -1, 0);
  if (uior->fd_cycles == -1) {
      ERROR_PRINT("Error opening perf leader fd %llx\n", pe.config);
      return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
  }

  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_TASK_CLOCK;

  uior->fd_taskclock = perf_event_open(&pe, 0, -1, uior->fd_cycles, 0);
  if (uior->fd_taskclock == -1) {
      ERROR_PRINT("Error opening perf TASK_CLOCK fd %llx\n", pe.config);
      return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
  }

  pe.type = PERF_TYPE_HARDWARE;
  pe.config = PERF_COUNT_HW_INSTRUCTIONS;

  uior->fd_instructions = perf_event_open(&pe, 0, -1, uior->fd_cycles, 0);
  if (uior->fd_instructions == -1) {
      ERROR_PRINT("Error opening perf INSTRUCTIONS fd %llx\n", pe.config);
      return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
  }

  return LIBSPDM_STATUS_SUCCESS;
}

void *uio_requester_init_spdm (void) {
  void *spdm_context;
  libspdm_data_parameter_t      parameter;
  spdm_version_number_t         spdm_version;
  uint8_t                       data8;
  uint16_t                      data16;
  uint32_t                      data32;
  size_t scratch_buffer_size;
  void *scratch_buffer;

  spdm_context = (void *)malloc (libspdm_get_context_size());
  if (spdm_context == NULL) {
    return NULL;
  }
  libspdm_init_context (spdm_context);

  libspdm_register_device_io_func (spdm_context, spdm_uio_send_message, spdm_uio_receive_message);

  if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
    libspdm_register_transport_layer_func(
      spdm_context,
      SPDMDEV_MAX_BUF - LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE - LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE, //LIBSPDM_MAX_SPDM_MSG_SIZE,
      LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
      LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
      libspdm_transport_mctp_encode_message,
      libspdm_transport_mctp_decode_message);
  } else {
    ERROR_PRINT("SPDM transfer type not supported.\n");
    return NULL;
  }

  libspdm_register_device_buffer_func(
    spdm_context,
    SPDMDEV_MAX_BUF,
    SPDMDEV_MAX_BUF,
    spdm_device_acquire_sender_buffer,
    spdm_device_release_sender_buffer,
    spdm_device_acquire_receiver_buffer,
    spdm_device_release_receiver_buffer
  );

  scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(spdm_context);
  scratch_buffer = (void *)malloc(scratch_buffer_size);
  if (scratch_buffer == NULL) {
    ERROR_PRINT("Could not allocate scratch_buffer.\n");
    free(spdm_context);
    spdm_context = NULL;
    return NULL;
  }
  libspdm_set_scratch_buffer(spdm_context, scratch_buffer, scratch_buffer_size);

  if (m_use_version != 0) {
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    spdm_version = m_use_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
            &spdm_version, sizeof(spdm_version));
  }

  if (m_use_secured_message_version != 0) {
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    spdm_version = m_use_secured_message_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(spdm_context,
            LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
            &parameter, &spdm_version,
            sizeof(spdm_version));
  } else {
    libspdm_set_data(spdm_context,
            LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
            &parameter, NULL, 0);
  }

  data8 = 0;
  libspdm_zero_mem (&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
  libspdm_set_data (spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &data8, sizeof(data8));

  data32 = m_use_requester_capability_flags;
  if (m_use_capability_flags != 0) {
    data32 = m_use_capability_flags;
  }
  libspdm_set_data (spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &data32, sizeof(data32));

  data8 = m_support_measurement_spec;
  libspdm_set_data (spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter, &data8, sizeof(data8));
  data32 = m_support_measurement_hash_algo;
  libspdm_set_data (spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &data32, sizeof(data32));
  data32 = m_support_asym_algo;
  libspdm_set_data (spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &data32, sizeof(data32));
  data32 = m_support_hash_algo;
  libspdm_set_data (spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &data32, sizeof(data32));
  data16 = m_support_dhe_algo;
  libspdm_set_data (spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter, &data16, sizeof(data16));
  data16 = m_support_aead_algo;
  libspdm_set_data (spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &data16, sizeof(data16));
  data16 = m_support_req_asym_algo;
  libspdm_set_data (spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &data16, sizeof(data16));
  data16 = m_support_key_schedule_algo;
  libspdm_set_data (spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16, sizeof(data16));
  data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter, &data8, sizeof(data8));
  data8 = SPDM_MEL_SPECIFICATION_DMTF;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_MEL_SPEC, &parameter, &data8, sizeof(data8));

  return spdm_context;
}

void uio_requester_get_random_no_spdm() {
  int err;
  INFO_PRINT("Let us get a random number (without SPDM)\n");
  bar0[SPDM_FACT_STATUS_ADDR] = bar0[SPDM_FACT_STATUS_ADDR] | SPDM_STATUS_IRQFACT;
  bar0[SPDM_FACT_NUMBER_ADDR] = 0;

  while (1) {
    /* Wait for next interrupt. */
    err = read(uiofd, &icount, 4);
    if (err != 4) {
      perror("uio read:");
      break;
    }

    status = bar0[SPDM_FACT_STATUS_ADDR];
    if (status & SPDM_STATUS_IRQFACT && !(status & SPDM_STATUS_FACTCOMPUTING)) {
      INFO_PRINT ("Random number is: %u\n", bar0[SPDM_FACT_NUMBER_ADDR]);
      bar0[SPDM_CLEAR_INT_ADDR] = FACT_IRQ;
      break;
    } else {
      INFO_PRINT("Awaiting the correct IRQ 0x%x\n", status);
    }
  }

  /* Re-enable interrupts. */
  err = pwrite(configfd, &command_high, 1, 5);
  if (err != 1) {
    perror("config write:");
  }
}
