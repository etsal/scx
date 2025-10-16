#!/bin/bash

sysctl kernel.panic_on_warn=1

/scx/target/debug/scx_layered --run-example 2>&1 & 
stress-ng --tlb-shootdown=40 --epoll=44 &
