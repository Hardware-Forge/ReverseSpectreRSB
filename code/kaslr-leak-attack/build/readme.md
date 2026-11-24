It is advised to build everything inside a docker container, but run the VM outside of it (in order not to mess up with kvm modules).
```bash
docker run -ti -v /path/to/build/directory:/src --name rsb-leak-builder ubuntu:24.04
# You might want to replace `/path/to/build/directory` with `$PWD`
```

Inside the docker
```bash
cd /src
./build.sh
```

Then you can run `./run.sh` to run the VM, which will execute the attack and exit.

### Getting the kernel offset

In order to get the attack working on your pc, you will have to insert one offset into the attack module ([`module/my-module.c`](https://github.com/Hardware-Forge/MT_TEA_13/blob/main/code/kaslr-leak-attack/build/module/my-module.c#L18)).

Here are the steps to get that value. Get the kernel image at `/boot/vmlinux-...` (`/boot/vmlinuz-$(uname -r)` might work depending on the used distro) and convert it to an ELF file with [vmlinxu-to-elf](https://github.com/marin-m/vmlinux-to-elf) `vmlinux-to-elf /boot/vmlinuz-... vmlinux`, then get the disassembly of the `ioctl` function by running `objdump --disassemble=__x64_sys_ioctl -Mintel vmlinux`. Search for a call to the `__x86_indirect_thunk_array` and get the address of the instruction immediately after.

```
ffffffff814826f0 <__x64_sys_ioctl>:
ffffffff814826f0:       f3 0f 1e fa             endbr64
...
ffffffff8148277f:       e8 3c 66 a7 00          call   ffffffff81ef8dc0 <__x86_indirect_thunk_array>
ffffffff81482784:       3d fd fd ff ff          cmp    eax,0xfffffdfd   <=== This one
...
```

To get the offset with respect to the kernel base, you can either get the last 6 nibbles or subtract `0xffffffff81000000`. In this example, the offset will be `0xffffffff81482784 - 0xffffffff81000000 = 0xffffffff81482784 & 0xffffff = 0x482784`.

Rebuild the module with `./build-module.sh` and run the VM (`./run.sh`) to see if it worked.

You can get the kernel base address (to check if the attack worked) with `sudo cat /proc/kallsyms | grep "_stext"`
