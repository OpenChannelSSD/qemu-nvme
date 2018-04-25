# Virtual Open-Channel SSD 2.0

This repository implements support for exposing an NVMe device that implements the Open-Channel 2.0 specification.

## Compiling & Installing

Below is a minimal example of the installation process for x86_64, kvm-enabled emulation using libaio for I/O.

    git clone https://github.com/OpenChannelSSD/qemu-nvme.git

    cd qemu-nvme
    ./configure --enable-kvm --target-list=x86_64-softmmu --enable-linux-aio --prefix=$HOME/qemu-nvme
    make
    make install

That'll install the OCSSD enabled qemu binary into $HOME/qemu-nvme.

## Configuring the virtual open-channel SSD drive

The device must have a backend file to store its data. Create a backend file by

    dd if=/dev/zero of=ocssd_backend.img bs=1M count=8096

The qemu arguments must be extended with:

    -drive file={path to ocssd backend file},id=myocssd,format=raw,if=none \
    -device nvme,drive=myocssd,lnum_lun=4,lstrict=1,meta=16,mc=3 \

The full command line could look like the following and creates an ocssd with 4 parallel units:

    sudo $HOME/qemu-nvme/bin/qemu-system-x86_64 -m 4G -smp 4 -s \
    -drive file={path to vm image},id=diskdrive,format=raw,if=none \
    -device virtio-blk-pci,drive=diskdrive,scsi=off,config-wce=off,x-data-plane=on \
    -drive file={path to ocssd backend file},id=myocssd,format=raw,if=none \
    -device nvme,drive=myocssd,lnum_lun=4,lstrict=1,meta=16,mc=3

A complete list of all options supported by the NVMe device can be found in [the source](hw/block/nvme.c) with comments on each option at the top of the file and a list of options and their default values toward the bottom of the file.

In the virtual machine, make sure to install at least Linux kernel 4.17 or latest release candidate.

## Current limitations

  - The driver does not support multiple groups. This should however be easy to implement.
