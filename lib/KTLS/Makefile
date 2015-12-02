KBUILD_EXTRA_SYMBOLS=$(CURDIR)/Module.symvers
KERNEL_VERSION=$(shell uname -r)
MODULES_DIR=$(wildcard /lib/modules)
KERNEL_BUILD_DIR=$(wildcard $(MODULES_DIR)/$(KERNEL_VERSION)/build)

# If /lib/modules exists, then we are in linux, and uname -r should return the current kernel version
ifneq ($(MODULES_DIR),)
ifeq ($(KERNEL_VERSION),)
$(error Cannot find out your kernel version by running 'uname -r')
endif
endif

ifeq ($(KERNEL_BUILD_DIR),)

LEVEL = ../..
ifneq (,$(wildcard $(LEVEL)/Makefile.common))
	include $(LEVEL)/Makefile.common
endif

Echo ?= @echo

all::
ifeq ($(MODULES_DIR),)
	$(Echo) Skipping KTLS kernel module, since /lib/modules does not exist
else
	$(Echo) WARNING: Skipping KTLS kernel module, since /lib/modules exists, but not /lib/modules/$(KERNEL_VERSION)/build
endif

else

MOD_NAME=KTLS
SOURCES=ktls.c ktls_assert.c ktls_hhash.c ktls_hhash_adapter.c ktls_vector.c
BUILD_FILES=$(SOURCES) bitarray.h ktls_assert.h ktls_hhash.h ktls_hhash_adapter.h ktls_vector.h syscalls.h Makefile
MOD=$(ObjDir)/$(MOD_NAME).ko
ifeq (,$(BuildMode))
  INSTALLED_MOD=kmod/$(MOD_NAME).ko
else
  INSTALLED_MOD=$(PROJ_OBJ_ROOT)/$(BuildMode)/kmod/$(MOD_NAME).ko
endif

# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)

obj-m += $(MOD_NAME).o
$(MOD_NAME)-objs := $(SOURCES:.c=.o) syscalls.o

else

LEVEL = ../..
ifneq (,$(wildcard $(LEVEL)/Makefile.common))
	include $(LEVEL)/Makefile.common
endif

Echo ?= @echo
ifeq (1,$(VERBOSE))
	Verb ?=
else
	Verb ?= @
endif
MKDIR ?= mkdir -p
CP ?= cp
PROJ_SRC_DIR ?= $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
PROJ_SRC_ROOT ?= $(PROJ_SRC_DIR)/../..
ObjDir ?= $(PROJ_SRC_DIR)/obj


ccflags-y := -I$(PROJ_SRC_ROOT)/include -std=gnu99 -Wno-declaration-after-statement

ccflags-y += -DBUILDMODE=$(BuildMode)

ifneq ($(ENABLE_OPTIMIZED),1)
ccflags-y += -O0 -ggdb
endif
ifeq ($(DISABLE_ASSERTIONS),1)
ccflags-y += -DNDEBUG
endif

# In order to be able to build different configurations in parallel,
# we just copy the source files to the individual ObjDirs.
# Building in this directory directly would fail, and I don't know
# a way to synchronize between different parallel make processes.
# Also, the object files for the different configurations need to be
# kept in different directories.
#                                   - Clemens Hammacher, 21.6.2013

GENERATED_FILES = $(addprefix $(ObjDir)/, syscalls.S)
OBJ_FILES = $(addprefix $(ObjDir)/, $(BUILD_FILES))

all:: $(INSTALLED_MOD)

$(INSTALLED_MOD): $(MOD)
	$(Verb) $(MKDIR) $(@D)
	$(Verb) $(CP) $< $@

$(MOD): $(OBJ_FILES) $(GENERATED_FILES)
	$(Echo) Compiling $(BuildMode) KTLS kernel module for kernel $(KERNEL_VERSION)
	$(Verb) (set -o pipefail; $(MAKE) ccflags-y="$(ccflags-y)" V=$(VERBOSE) -C $(KERNEL_BUILD_DIR) M=$(ObjDir) modules 2>&1 | sed 's#$(ObjDir)#$(PROJ_SRC_DIR)#g')
	$(Verb) test -e $@ || { echo "Error: file was not created: $@"; false; }
	$(Verb) touch $@

$(OBJ_FILES): $(ObjDir)/%: $(PROJ_SRC_DIR)/%
	$(Verb) $(MKDIR) $(@D)
	$(Verb) $(CP) $< $@

$(ObjDir)/syscalls.S: $(PROJ_SRC_DIR)/build-syscalls-asm.py
	$(Echo) Generating $@
	$(Verb) $< >$@

endif
endif
