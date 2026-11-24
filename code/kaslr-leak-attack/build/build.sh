#!/bin/bash

set -ev

cd /src
export DEBIAN_FRONTEND=noninteractive
apt update
apt install cpio bc wget libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf -y

if [[ -e ./linux-6.13.tar.xz ]]; then
	echo "Linux source already downloaded. Skipping"
else
	wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.13.tar.xz
fi
tar xf linux-6.13.tar.xz

cd linux-6.13
make ARCH=x86 x86_64_defconfig
make -j`nproc` bzImage
make -j`nproc` modules

cd ..
cp linux-6.13/arch/x86_64/boot/bzImage .

if [[ -e ./busybox-1.37.0.tar.bz2 ]]; then
	echo "Busybox source already downloaded. Skipping"
else
	wget https://www.busybox.net/downloads/busybox-1.37.0.tar.bz2
fi
tar xf busybox-1.37.0.tar.bz2

cd busybox-1.37.0
make defconfig
sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/g' .config
sed -i 's/CONFIG_TC=y/CONFIG_TC=n/g' .config
make -j`nproc`
make install

cd ..
mkdir -p initramfs
cd initramfs
mkdir -p bin sbin etc/init.d proc sys usr/bin usr/sbin root
ln -s /bin/busybox init || true

cd ..
cp -a busybox-1.37.0/_install/* initramfs
cp rcS initramfs/etc/init.d/
chmod +x rcS initramfs/etc/init.d/rcS

./build-module.sh
