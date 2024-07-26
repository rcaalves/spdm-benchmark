
obj-y += spdm_glue.o

SPDM_DIR?= /opt/libspdm
SPDM_BUILD_DIR?= $(SPDM_DIR)/build_buildroot
SPDM_CRYPTO?= mbedtls

SPDM_HEADERS = $(SPDM_DIR)/include

SPDM_INCLUDE := -Iinclude/spdm -Iinclude/spdm/hal

CFLAGS_spdm_glue.o = $(SPDM_INCLUDE) -DLIBSPDM_STDINT_ALT=\"linux/types.h\"


SPDM_INCLUDE_DIR =  \
        $(SPDM_HEADERS) \
        $(SPDM_HEADERS)/hal \
        $(SPDM_HEADERS)/library \
        $(SPDM_HEADERS)/industry_standard \
				$(SPDM_HEADERS)/internal \
				$(SPDM_DIR)/os_stub \
				$(SPDM_DIR)/os_stub/spdm_crypt_ext_lib \
				$(SPDM_DIR)/os_stub/spdm_device_secret_lib_sample \
        $(SPDM_DIR)/library/spdm_common_lib
#         $(SPDM_DIR)/library/spdm_requester_lib \
#         $(SPDM_DIR)/library/spdm_secured_message_lib

SPDM_HEADER_DIR_KERNEL := $(foreach incdir, $(SPDM_INCLUDE_DIR), $(addprefix include/spdm/,$(notdir $(incdir))))

$(SPDM_HEADER_DIR_KERNEL):
	mkdir -p include/spdm
	ln -s $(filter %$(notdir $@), $(SPDM_INCLUDE_DIR)) $@
	if ls $@/*.h >/dev/null 2>&1; then for i in $@/*.h; do ln -s ../../$$i include/spdm/; done; fi

SPDM_LIBS = \
        $(SPDM_BUILD_DIR)/lib/librnglib.a \
        $(SPDM_BUILD_DIR)/lib/libmemlib.a \
        $(SPDM_BUILD_DIR)/lib/libmalloclib.a \
        $(SPDM_BUILD_DIR)/lib/libdebuglib.a \
        $(SPDM_BUILD_DIR)/lib/libplatform_lib_null.a \
        $(SPDM_BUILD_DIR)/lib/libcryptlib_$(SPDM_CRYPTO).a \
        $(SPDM_BUILD_DIR)/lib/lib$(SPDM_CRYPTO).a \
        $(SPDM_BUILD_DIR)/lib/libmbedcrypto.a \
        $(SPDM_BUILD_DIR)/lib/libmbedx509.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_crypt_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_crypt_ext_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_secured_message_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_requester_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_device_secret_lib_sample.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_common_lib.a \
        $(SPDM_BUILD_DIR)/lib/libspdm_transport_mctp_lib.a\
        $(SPDM_BUILD_DIR)/lib/libspdm_transport_pcidoe_lib.a

SPDM_DIR_SUFIX = _spdmlib
SPDM_OBJ  := $(foreach libfile, $(SPDM_LIBS), $(shell ar t $(libfile) | sed s-^-$$(basename $(libfile))$(SPDM_DIR_SUFIX)/-))
SPDM_TARGETS := $(addprefix $(obj)/, $(SPDM_OBJ))

spdm_glue-objs := spdm_glue.o spdm_auth.o spdm_default_params.o $(SPDM_OBJ)

SPDM_INCLUDE := -Iinclude/spdm -Iinclude/spdm/hal -DLIBSPDM_STDINT_ALT=\"linux/types.h\"
CFLAGS_spdm_auth.o += $(SPDM_INCLUDE)
CFLAGS_spdm_default_params.o += $(SPDM_INCLUDE)

$(SPDM_TARGETS): $(SPDM_LIBS) $(SPDM_HEADER_DIR_KERNEL)
	mkdir -p $$(dirname $@)
	cd $$(dirname $@); ar x $(SPDM_BUILD_DIR)/lib/$$(basename $$(dirname $@ | sed s/$(SPDM_DIR_SUFIX)//)) $$(basename $@)
