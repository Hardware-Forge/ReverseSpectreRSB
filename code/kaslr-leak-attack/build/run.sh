#!/bin/sh

qemu-system-x86_64 \
	--enable-kvm \
	-m 128M \
	-smp 1 \
	-kernel ./bzImage \
	-initrd ./initramfs.cpio.gz \
	-cpu host \
	-append "console=ttyS0 oops=panic panic=1 kaslr" \
	-monitor /dev/null \
	-nographic \
	-no-reboot
