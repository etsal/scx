.PHONY: all clean

CC=clang

INCLUDEDIR=../../include
LIBDIR=../../../lib

BPFTOOL=bpftool
CLANGVER := $(shell clang --version | head -n 1 | sed 's/.*version \([0-9.]*\).*/\1/' | cut -d '.' -f 1)

ARCH := $(shell uname -m | cut -d '_' -f 1)

CFLAGS = -O2 -g -Wall -pthread -D_FILE_OFFSET_BITS=64 -Winvalid-pch
CFLAGS += -I$(INCLUDEDIR)
# XXX Use the system libbpf instead.
CFLAGS += -I../../../build/libbpf/src/usr/include
LIBS = -Wl,--start-group ../../../build/libbpf/src/libbpf.a -lz -lelf -lzstd -Wl,--end-group

BPFFLAGS = -O2 -g -Wall
BPFFLAGS += -target bpf -D__TARGET_ARCH_$(ARCH) -mcpu=v3 -mlittle-endian
BPFFLAGS += -Wno-compare-distinct-pointer-types
BPFFLAGS += -idirafter /usr/lib/clang/$(CLANGVER)/include -idirafter /usr/local/include -idirafter /usr/include
BPFFLAGS += -I../../../build/libbpf/src/usr/include
BPFFLAGS += -I$(INCLUDEDIR) -I$(INCLUDEDIR)/arch/$(ARCH) -I$(INCLUDEDIR)/bpf-compat -I$(INCLUDEDIR)/lib

all: scx_ule

scx_ule: scx_ule.c scx_ule.bpf.skel.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

scx_ule.bpf.skel.h: scx_ule.bpf.o
	$(shell $(BPFTOOL) gen skeleton $^ name scx_ule > $@)

scx_ule.bpf.o: sched.bpf.o ule_runq.bpf.o cpumask.bpf.o sdt_alloc.bpf.o sdt_task.bpf.o
	$(BPFTOOL) gen object $@ $^

%.bpf.o: %.bpf.c
	$(CC) $(BPFFLAGS) $(CFLAGS) -c $^ -o $@

cpumask.bpf.o: $(LIBDIR)/cpumask.bpf.c
	$(CC) $(BPFFLAGS) $(CFLAGS) -c $^ -o $@

sdt_alloc.bpf.o: $(LIBDIR)/sdt_alloc.bpf.c
	$(CC) $(BPFFLAGS) $(CFLAGS) -c $^ -o $@

sdt_task.bpf.o: $(LIBDIR)/sdt_task.bpf.c
	$(CC) $(BPFFLAGS) $(CFLAGS) -c $^ -o $@

clean:
	rm -f *.o scx_ule *.bpf.skel.h
