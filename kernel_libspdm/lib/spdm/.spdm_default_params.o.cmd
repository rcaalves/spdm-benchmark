cmd_lib/spdm/spdm_default_params.o := /home/ralves/code/buildroot-2020.02.9_recomp/buildroot-2020.02.9/output/host/bin/x86_64-buildroot-linux-uclibc-gcc -Wp,-MD,lib/spdm/.spdm_default_params.o.d -nostdinc -isystem /home/ralves/code/buildroot-2020.02.9_recomp/buildroot-2020.02.9/output/host/lib/gcc/x86_64-buildroot-linux-uclibc/8.4.0/include -I./arch/x86/include -I./arch/x86/include/generated  -I./include -I./arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h -include ./include/linux/compiler_types.h -D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -Werror-implicit-function-declaration -Wno-format-security -std=gnu89 -fno-PIE -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel -funit-at-a-time -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_FXSAVEQ=1 -DCONFIG_AS_SSSE3=1 -DCONFIG_AS_CRC32=1 -DCONFIG_AS_AVX=1 -DCONFIG_AS_AVX2=1 -DCONFIG_AS_AVX512=1 -DCONFIG_AS_SHA1_NI=1 -DCONFIG_AS_SHA256_NI=1 -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -fno-jump-tables -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow -Wno-int-in-bool-context -O2 --param=allow-store-data-races=0 -Wframe-larger-than=2048 -fno-stack-protector -Wno-unused-but-set-variable -Wno-unused-const-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -g -Wdeclaration-after-statement -Wno-pointer-sign -Wno-stringop-truncation -fno-strict-overflow -fno-merge-all-constants -fmerge-constants -fno-stack-check -fconserve-stack -Werror=implicit-int -Werror=strict-prototypes -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -fmacro-prefix-map=./= -fcf-protection=none -Wno-packed-not-aligned -Wno-attribute-alias -Iinclude/spdm -Iinclude/spdm/hal -DLIBSPDM_STDINT_ALT=\"linux/types.h\"    -DKBUILD_BASENAME='"spdm_default_params"' -DKBUILD_MODNAME='"spdm_glue"' -c -o lib/spdm/spdm_default_params.o lib/spdm/spdm_default_params.c

source_lib/spdm/spdm_default_params.o := lib/spdm/spdm_default_params.c

deps_lib/spdm/spdm_default_params.o := \
  include/linux/kconfig.h \
    $(wildcard include/config/cpu/big/endian.h) \
    $(wildcard include/config/booger.h) \
    $(wildcard include/config/foo.h) \
  include/linux/compiler_types.h \
    $(wildcard include/config/have/arch/compiler/h.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/retpoline.h) \
    $(wildcard include/config/arch/use/builtin/bswap.h) \
  include/spdm/library/spdm_transport_mctp_lib.h \
  include/spdm/library/spdm_common_lib.h \
  include/spdm/internal/libspdm_lib_config.h \
  include/spdm/library/spdm_lib_config.h \
  include/spdm/hal/base.h \
  include/linux/types.h \
    $(wildcard include/config/have/uid16.h) \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  include/uapi/linux/types.h \
  arch/x86/include/uapi/asm/types.h \
  include/uapi/asm-generic/types.h \
  include/asm-generic/int-ll64.h \
  include/uapi/asm-generic/int-ll64.h \
  arch/x86/include/uapi/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/uapi/asm-generic/bitsperlong.h \
  include/uapi/linux/posix_types.h \
  include/linux/stddef.h \
  include/uapi/linux/stddef.h \
  include/linux/compiler_types.h \
  arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  arch/x86/include/uapi/asm/posix_types_64.h \
  include/uapi/asm-generic/posix_types.h \
  /home/ralves/code/buildroot-2020.02.9_recomp/buildroot-2020.02.9/output/host/lib/gcc/x86_64-buildroot-linux-uclibc/8.4.0/include/stdbool.h \
  /home/ralves/code/buildroot-2020.02.9_recomp/buildroot-2020.02.9/output/host/lib/gcc/x86_64-buildroot-linux-uclibc/8.4.0/include/stddef.h \
  include/spdm/library/spdm_secured_message_lib.h \
  include/spdm/industry_standard/spdm.h \
  include/spdm/industry_standard/spdm_secured_message.h \
  include/spdm/library/spdm_return_status.h \
  include/spdm/library/spdm_crypt_lib.h \
  include/spdm/industry_standard/mctp.h \

lib/spdm/spdm_default_params.o: $(deps_lib/spdm/spdm_default_params.o)

$(deps_lib/spdm/spdm_default_params.o):
