#!/bin/sh

set -ev

cd module
make

cd ..
cp module/my-module-main.ko initramfs
./compress.sh
