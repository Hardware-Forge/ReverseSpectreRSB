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

### Getting the poc addresses

In order to get the poc working on your pc, you will have to insert some addresses into the attack module ([`module/my-module.c`](https://github.com/Hardware-Forge/MT_TEA_13/blob/main/code/kaslr-rsb-leak-poc/build/module/my-module.c), in particular, the first six constants (the most important are the last two, which are for the kaslr leak, the other ones are for the kvm and kvm-amd address leak).

To get the address to put in `cheatX`, you just have to read `/proc/kallsyms`, so, for example, to get the `__x64_sys_ioctl` address, you just have to run `sudo cat /proc/kallsyms | grep -F ' __x64_sys_ioctl'`.

The `call_offsetX` are way trickier, let's start from the kernel one. Get the kernel image at `/boot/vmlinux-...` (`/boot/vmlinuz-$(uname -r)` might work depending on the used distro) and convert it to an ELF file with [vmlinxu-to-elf](https://github.com/marin-m/vmlinux-to-elf) `vmlinux-to-elf /boot/vmlinuz-... vmlinux`, then get the disassembly of the `ioctl` function by running `objdump --disassemble=__x64_sys_ioctl -Mintel vmlinux`. Search for a call to the `__x86_indirect_thunk_array` and get the offset inside the function of the instruction immediately after.

```
ffffffff814826f0 <__x64_sys_ioctl>:
ffffffff814826f0:       f3 0f 1e fa             endbr64
...
ffffffff8148277f:       e8 3c 66 a7 00          call   ffffffff81ef8dc0 <__x86_indirect_thunk_array>
ffffffff81482784:       3d fd fd ff ff          cmp    eax,0xfffffdfd
...
```

In this example, the offset will be `0xffffffff81482784 - 0xffffffff814826f0 = 0x94`.

Unfortunately, disassembling modules is not that easy, because symbols are a bit messed up and `objdump` will not handle them nicely. To get the needed offsets I used a decompiler (such as [IDA](https://hex-rays.com/ida-free) or [ghidra](https://ghidra-sre.org/)) and got the references to the called function inside of the calling function (for example, for the first constant, search the references to `_svm_vcpu_run` inside `svm_vcpu_enter_exit`). Then, as before, get the offset inside the function of the instruction after the call and place it inside the `call_offsetX` variable. The modules are in the `/lib/modules/$(uname -r)/kernel/arch/x86/kvm/` folder, if they end in `.zst`, you have to decompress them before decompiling, using `unzstd`.

Finally you can rebuild the module with `./build-module.sh` and run the VM to see if it worked.
