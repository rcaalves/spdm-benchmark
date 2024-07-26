# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 1999 - 2006 Intel Corporation.

#
# Makefile for the Intel(R) PRO/1000 ethernet driver
#

obj-$(CONFIG_E1000) += e1000.o

e1000-objs := e1000_main.o e1000_hw.o e1000_ethtool.o e1000_param.o

# SPDM
SPDM_INCLUDE := -Iinclude/spdm -Iinclude/spdm/hal -DLIBSPDM_STDINT_ALT=\"linux/types.h\"
CFLAGS_e1000_main.o += $(SPDM_INCLUDE)