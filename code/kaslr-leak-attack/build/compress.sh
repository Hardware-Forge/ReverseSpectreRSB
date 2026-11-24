#!/bin/sh

set -e
cd initramfs

find . -print0 \
	| cpio --null -o --format=newc --owner=root \
	| gzip -9 > ../initramfs.cpio.gz
