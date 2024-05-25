#! /usr/bin/env bash

(
  cd "$(dirname "$0")/.." || exit

  clang \
    -target bpf \
    -I include/vmlinux/host \
    -I src/bpf \
    -D__TARGET_ARCH_x86 \
    -fno-stack-protector \
    -O2 \
    -g \
    -c src/bpf/watcher.bpf.c \
    -o watcher.o

  echo "$@" | grep -q -- --gcc && bpf-gcc \
    -I /usr/include \
    -I include/vmlinux/host \
    -I src/bpf \
    -D__TARGET_ARCH_x86 \
    -fno-stack-protector \
    -O2 \
    -g \
    -c src/bpf/watcher.bpf.c \
    -o watcher.o
)
