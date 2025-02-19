#!/bin/sh

meson setup build --prefix ~;
cd build/bpftool/libbpf && git apply ../../../libbpf.patch && cd -
cd build/libbpf && git apply ../../libbpf.patch && cd -
meson compile -C build scx_wd40
sudo ./build/debug/scx_wd40
