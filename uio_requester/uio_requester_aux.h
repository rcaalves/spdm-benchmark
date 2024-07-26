#ifndef _UIO_REQUESTER_AUX_
#define _UIO_REQUESTER_AUX_

#include"spdm_common_lib.h"
#include <stdint.h>

#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>
#include <unistd.h>

#include "spdm_emu.h"

typedef libspdm_return_t (*app_fun_t)(void*, uint32_t);

libspdm_return_t
uio_spdm_init_connection (
      void                 *opaque,
      char                 collect_stats
  );

libspdm_return_t
uio_do_authentication_via_spdm (
  void *spdm_context,
  char collect_stats
  );

libspdm_return_t
uio_do_measurement_via_spdm (
  void *spdm_context
  );

libspdm_return_t
uio_do_session_via_spdm (
  void                *opaque,
  bool                use_psk,
  app_fun_t           app_fun
  );

libspdm_return_t
uio_do_app_session_via_spdm (
  void                            *spdm_context,
  uint32_t                         session_id
  );

libspdm_return_t
uio_do_rng_app_session_via_spdm (
  void                            *spdm_context,
  uint32_t                         session_id
  );

libspdm_return_t
spdm_uio_load_certificates (
  void *spdm_context
  );

libspdm_return_t get_measurement_to_buffer(void *opaque, uint8_t index, uint8_t *out_buf, size_t *buf_len);

size_t print_measurement(spdm_measurement_block_dmtf_t *measurement_block_dmtf);

// void print_usage(char *progname);void *

struct uio_requester_t {
  void    *spdm_context;
  int     fd_cycles, fd_taskclock, fd_instructions;
};

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

#define RESET_N_ENABLE(fd) \
    ioctl(fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP); \
    ioctl(fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

#define DISABLE_N_READ(fd, label) \
  do { \
    ioctl(fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP); \
    { \
      struct read_format rf_; \
      read(fd, &rf_, sizeof(rf_)); \
      printf("%s,\t%lu cycles,\t%lu ns,\t%lu instructions\n", \
                label, \
                rf_.values[CYCLES].value, \
                rf_.values[TASK_CLOCK].value, \
                rf_.values[INSTRUCTIONS].value); \
    } \
  } while(0)

#if UIO_DEBUG_LVL >= 2
#define INFO_PRINT(format,  ...) fprintf(stdout, format, ##__VA_ARGS__)
#else
#define INFO_PRINT(format,  ...)
#endif

#if UIO_DEBUG_LVL >= 1
#define ERROR_PRINT(format,  ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define ERROR_PRINT(format,  ...)
#endif

#define DUMP_ARRAY(msg, array, array_size) \
  printf("%s: %s (size %ld)", __func__, msg, array_size); \
  for(int __i = 0; __i < array_size; __i++) { \
    if(__i % 16 == 0) printf("\n[%03x] ", __i); \
    printf("%02x ", ((uint8_t*)array)[__i]); \
  } \
  printf("\n");

#endif //_UIO_REQUESTER_AUX_
