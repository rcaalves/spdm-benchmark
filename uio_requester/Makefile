CC?=gcc
SPDM_DIR?=/opt/libspdm
SPDM_BUILD_DIR?=$(SPDM_DIR)/build

SPDM_INCLUDE = 	\
	-I $(SPDM_DIR)/include \
	-I $(SPDM_DIR)/include/hal \
	-I $(SPDM_DIR)/include/hal/x64 \
	-I $(SPDM_DIR)/include/library \
	-I $(SPDM_DIR)/include/industry_standard \
	-I $(SPDM_DIR)/library/spdm_common_lib \
	-I $(SPDM_DIR)/library/spdm_requester_lib \
	-I $(SPDM_DIR)/os_stub/spdm_device_secret_lib

SPDM_LIBS = \
	$(SPDM_BUILD_DIR)/lib/librnglib.a \
	$(SPDM_BUILD_DIR)/lib/libmemlib.a \
	$(SPDM_BUILD_DIR)/lib/libmalloclib.a \
	$(SPDM_BUILD_DIR)/lib/libdebuglib.a \
	$(SPDM_BUILD_DIR)/lib/libcryptlib_mbedtls.a \
	$(SPDM_BUILD_DIR)/lib/libmbedtlslib.a \
	$(SPDM_BUILD_DIR)/lib/libspdm_crypt_lib.a \
	$(SPDM_BUILD_DIR)/lib/libspdm_secured_message_lib.a \
	$(SPDM_BUILD_DIR)/lib/libspdm_requester_lib.a \
	$(SPDM_BUILD_DIR)/lib/libspdm_device_secret_lib.a \
	$(SPDM_BUILD_DIR)/lib/libspdm_common_lib.a \
	$(SPDM_BUILD_DIR)/lib/libspdm_transport_mctp_lib.a \
	$(SPDM_BUILD_DIR)/lib/libspdm_transport_pcidoe_lib.a

DEBUG_LVL?=1
CFLAGS += -O0 -g -Wall -DUIO_DEBUG_LVL=$(DEBUG_LVL)

BINARY = uio_requester_bench
HEADERS = uio_requester.h uio_requester_aux.h uio_spdm_rng.h
COMMON_OBJ = uio_requester.o uio_requester_aux.o spdm_emu.o

all: $(BINARY)

uio_requester_bench: uio_requester_bench.o $(COMMON_OBJ)


uio_requester_bench.o: uio_requester_bench.c $(HEADERS)


uio_requester_aux.o: uio_requester_aux.c uio_requester_aux.h uio_spdm_rng.h

uio_requester.o: uio_requester.c $(HEADERS)

spdm_emu.o: spdm_emu.c

%.o: %.c $(HEADERS)
	${CC} -c $< $(CFLAGS) $(SPDM_INCLUDE)

%: %.o $(COMMON_OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -Wl,--start-group $(SPDM_LIBS) -Wl,--end-group


clean:
	rm -f $(BINARY) *.o
