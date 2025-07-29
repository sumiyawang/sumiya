# SPDX-License-Identifier: GPL-2.0
.SUFFIXES:
CC     = $(CROSS_COMPILE)gcc
CLANG  = $(CROSS_COMPILE)clang
LD     = $(CROSS_COMPILE)ld
AS     = $(CROSS_COMPILE)as

HELPERS_PATH := src/helperC

CFLAGS += -iquote $(HELPERS_PATH)/
CFLAGS += -iquote src/headers/
CFLAGS += -iquote src/skel/
CFLAGS += -iquote ../libbpf/src/
CLANGFLAGS += -iquote ../vmlinux/5.14/
CLANGFLAGS += -DENABLE_ATOMICS_TESTS -D__KERNEL__ \
	      -D__BPF_TRACING__ -D__TARGET_ARCH_x86 \
	      -g -fno-stack-protector -Werror \
	      -Wno-compare-distinct-pointer-types \
	      -fno-asynchronous-unwind-tables \
	      -fno-stack-protector  -O2 -mlittle-endian\
	      -target bpf -mcpu=probe

comma       := ,
dot-target  = $(dir $@).$(notdir $@)
depfile     = $(subst $(comma),_,$(dot-target).d)

LIBBPF   = ../tools/libbpf.a.$(lbpf_hv)
LDLIBS  += $(LIBBPF) -lelf -lz -lrt

SOURCES         := $(filter-out %.bpf.c, $(wildcard src/ebpf/*.c))           
BPF_SOURCES     := $(wildcard src/ebpf/*.bpf.c)       
HELPER_SOURCES  := $(wildcard $(HELPERS_PATH)/*.c)

HELPER_OBJECTS  := $(patsubst %.c,%.o,$(HELPER_SOURCES))
LOADER_OBJECT   := $(patsubst %.c,%,$(SOURCES))         
USER_OBJECT     := $(patsubst %.c,%.o,$(SOURCES))
SKEL_OBJECT 	:= $(patsubst src/ebpf/%.c,src/skel/%.skel.h,$(SOURCES))
BPF_OBJECT      := $(patsubst %.c,%.o,$(BPF_SOURCES))

BIN_OBJECTS 	:= $(notdir $(wildcard bin/*))
BIN_LD_OBJECTS 	:= $(notdir $(LOADER_OBJECT))
BIN_NEED_LD 	:= $(filter-out $(BIN_OBJECTS), $(BIN_LD_OBJECTS))
BIN 		:= $(addprefix ../bin/,$(BIN_NEED_LD))

BPFTOOL = ../tools/bpftool

.PHONY: all clean
.DEFAULT_GOAL := all

lbpf_hv = v1.5.0

define mk_$(lbpf_hv)
@(cd ../libbpf && git reset --hard $(lbpf_hv) && cd -)
endef

define v0.8.0
@(cd ../libbpf && git reset --hard v0.8.0 && cd -)
endef

all: $(BIN)
	@echo "Successfully remade target file 'all'."

clean:
	rm -f $(HELPERS_PATH)/*.o $(HELPERS_PATH)/.*.o.d src/ebpf/*.o \
		src/ebpf/.*.o.d

$(LIBBPF):
	@echo "[Makefile] Building libbpf..."
	@(make -C ../libbpf/src/ && cd -)

src/helperC/%.o: src/helperC/%.c
	@echo "build helpers $(HELPER_OBJECTS)"
	$(v0.8.0)
	$(CC) -Wp,-MD,$(depfile) $(CFLAGS) -g -c -o $@ $<

src/ebpf/%.bpf.o: src/ebpf/%.bpf.c src/headers/ver.h
	@echo "[BPF] Building libbpf $(lbpf_hv) $< -> $@"
	$(mk_$(lbpf_hv))
	$(CLANG) $(CFLAGS) $(CLANGFLAGS) -c -o $@ $<

src/skel/%.skel.h: src/ebpf/%.bpf.o
	@echo "[Skeleton] Generating $@ from $<"
	$(BPFTOOL) gen skeleton $< > $@
	@(sed -i 's@#include <bpf/libbpf.h>@#include "libbpf.h"@g' $@)

$(USER_OBJECT): %.o: %.c $(SKEL_OBJECT)
	@echo "[User] $(SKEL_OBJECT)"
	$(mk_$(lbpf_hv))
	$(CC) -Wp,-MD,$(depfile) $(CFLAGS) -g -c -o $@ $<

../libbpf/src/libbpf.a:
	cd ../libbpf && git reset --hard $(lbpf_hv) && make -C src && cd -

../tools/libbpf.a.$(lbpf_hv): ../libbpf/src/libbpf.a
	@echo "Copying libbpf.a to tools/ directory"
	cp ../libbpf/src/libbpf.a ../tools/libbpf.a.$(lbpf_hv)

$(BIN): ../tools/libbpf.a.$(lbpf_hv) $(HELPER_OBJECTS) $(USER_OBJECT)
	@echo "[Link]: $(USER_OBJECT) ../tools/libbpf.a.$(lbpf_hv) $(HELPER_OBJECTS)"
	$($(lbpf_hv))
	$(CC) -static -g -o $@ $(USER_OBJECT) $(HELPER_OBJECTS) $(LDLIBS)
