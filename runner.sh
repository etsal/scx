#!/bin/bash

/scx/target/debug/scx_layered --run-example 2>&1 & 

while true;
do
	stress-ng --epoll=24 &
	sleep 1
	pkill stress-ng
	sleep 1
done
