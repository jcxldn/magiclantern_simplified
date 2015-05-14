#!/bin/bash

QEMU_PATH=${QEMU_PATH:=qemu-2.3.0}
make -C $QEMU_PATH || exit
$QEMU_PATH/arm-softmmu/qemu-system-arm -M $*
