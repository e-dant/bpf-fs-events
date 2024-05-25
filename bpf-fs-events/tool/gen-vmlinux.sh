#! /usr/bin/env bash

(
  cd "$(dirname "$0")/.." || exit
  tmp=$(mktemp -d)
  trap "rm -rf '$tmp'" EXIT

  [ -d include/vmlinux ] && { echo "Exists (remove to update) 'include/vmlinux'" ; exit 0 ; }
  [ ! -f /sys/kernel/btf/vmlinux ] && { echo "Error (BTF not enabled on this host)" ; exit 1 ; }
  [ ! which bpftool ] &>/dev/null && { echo "Error (bpftool not found)" ; exit 1 ; }

  git clone https://github.com/libbpf/libbpf-bootstrap "$tmp/libbpf-bootstrap" &>/dev/null || {
    echo "Error (failed to clone) $bootstraprepo" ; exit 1
  }

  ( cd "$tmp/libbpf-bootstrap/vmlinux"
    find . -mindepth 1 -maxdepth 1 -type d
  ) | while read -r d
  do
    mkdir -p "include/vmlinux/$d"
    ls -al "$tmp/libbpf-bootstrap/vmlinux/$d"
    from=$(realpath "$tmp/libbpf-bootstrap/vmlinux/$d/vmlinux.h")
    to=$(realpath "include/vmlinux/$d")/vmlinux.h
    if mv "$from" "$to"
    then echo "Wrote '$to'"
    else echo "Error (failed to copy) '$to'" ; exit 1
    fi
  done
  mkdir -p include/vmlinux/host
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux/host/vmlinux.h
  echo "Wrote 'include/vmlinux/host/vmlinux.h'"
)
