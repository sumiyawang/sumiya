# SPDX-License-Identifier: GPL-2.0
.SUFFIXES:
CC     = $(CROSS_COMPILE)gcc
CLANG  = $(CROSS_COMPILE)clang
LD     = $(CROSS_COMPILE)ld
AS     = $(CROSS_COMPILE)as


CFLAGS += -iquote ./
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

TPATH := $(basename $(notdir $(PWD)))
BPF_SOURCES := $(TPATH).bpf.c
BPF_OBJECT      := $(patsubst %.c,%.o,$(BPF_SOURCES))
SKEL_OBJECT 	:= $(TPATH).skel.h
HELPER_SOURCES := $(wildcard *_helpers.c)
HELPER_OBJECTS  := $(patsubst %.c,%.o,$(HELPER_SOURCES))
SOURCES := $(TPATH).c
LOADER_OBJECT   := $(patsubst %.c,%,$(SOURCES))         
USER_OBJECT     := $(patsubst %.c,%.o,$(SOURCES))

BIN 		:= $(addprefix ../bin/,$(TPATH))

#$(info $(TPATH)/ $(BPF_SOURCES)/ $(BPF_OBJECT)/ $(SKEL_OBJECT)/ $(HELPER_SOURCES)/ $(HELPER_OBJECTS)/ $(SOURCES)/ $(LOADER_OBJECT)/ $(USER_OBJECT)/ $(BIN))
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
	@echo "[Success] build target file $(BIN)"

clean:
	rm -f ./*.o ./.*.o.d

$(LIBBPF):
	@echo "[Building libbpf]..."
	@(make -C ../libbpf/src/ && cd -)

$(HELPER_OBJECTS): %.o: %.c
	@echo "[build helpers] $(HELPER_OBJECTS)"
	$(v0.8.0)
	$(CC) -Wp,-MD,$(depfile) $(CFLAGS) -g -c -o $@ $<

$(BPF_OBJECT): $(BPF_SOURCES) $(TPATH).h
	@echo "[Building ebpf] $(lbpf_hv) $< -> $@"
	$(mk_$(lbpf_hv))
	$(CLANG) $(CFLAGS) $(CLANGFLAGS) -c -o $@ $<

$(SKEL_OBJECT): $(BPF_OBJECT)
	@echo "[Skeleton] Generating $@ from $<"
	$(BPFTOOL) gen skeleton $< > $@
	@(sed -i 's@#include <bpf/libbpf.h>@#include "libbpf.h"@g' $@)

$(USER_OBJECT): $(SOURCES) $(HELPER_OBJECTS) $(SKEL_OBJECT)
	@echo "[User] $(USER_OBJECT)"
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
