.PHONY: clean test

# WARNING: DEBUG ONLY

ROOTDIR=../../../../../
LIBDIR=$(ROOTDIR)/lib
INCLUDEDIR=$(ROOTDIR)/scheds/include

BPF_SOURCES = $(wildcard *.bpf.c) pmu.bpf.c
BPF_OBJECTS = $(notdir $(BPF_SOURCES:.bpf.c=.bpf.o))
vpath %.bpf.c $(LIBDIR)

BPFTOOL=bpftool

INCLUDES=-I$(INCLUDEDIR) -I$(INCLUDEDIR)/bpf-compat -I$(PWD)

BPF_FLAGS=--target=bpf -g -O2 -D__TARGET_ARCH_x86 -mcpu=v3 -mlittle-endian
BPF_FLAGS+=-Wall -Wno-compare-distinct-pointer-types -Wno-incompatible-pointer-types-discards-qualifiers

BPF_FLAGS+=-I$(ROOTDIR)/scheds/vmlinux -I/usr/include/bpf -I/usr/include/$(shell uname -m)-linux-gnu 
BPF_FLAGS+=$(INCLUDES)

CFLAGS=-O2 -no-pie
CFLAGS+=$(INCLUDES)
LDFLAGS=-static -lbpf -lelf -lz -lzstd

all: selftest.skel.h

selftest.skel.h: bpf.bpf.o
	$(BPFTOOL) gen skeleton $< name "skeleton" > $@

bpf.bpf.o: $(BPF_OBJECTS)
	$(BPFTOOL) gen object $@ $^

%.bpf.o: %.bpf.c
	clang $(BPF_FLAGS) -c $< -o $@
	clang $(BPF_FLAGS) -c $< -o $@
	clang $(BPF_FLAGS) -S -emit-llvm -o $(basename $@).ll $<
		
clean:
	rm -f *.skel.h *.bpf.o selftest *.ll
