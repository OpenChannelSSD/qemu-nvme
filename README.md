# Virtual Open-Channel SSD 2.0

This repository implements support for exposing an NVMe device that implements
the Open-Channel 2.0 specification.

## Compiling & Installing

Below is a minimal example of the installation process for x86_64, kvm-enabled
emulation using libaio for I/O.

    git clone https://github.com/OpenChannelSSD/qemu-nvme.git

    cd qemu-nvme
    ./configure --target-list=x86_64-softmmu --prefix=$HOME/qemu-nvme
    make
    make install

That'll install the OCSSD enabled qemu binary into $HOME/qemu-nvme.

## Configuring the virtual open-channel SSD drive

The device must have a backend file to store its data. Create a backend file by
(e.g., 8GB)

    dd if=/dev/zero of=ocssd_backend.img bs=1M count=8096

The qemu arguments must be extended with:


    -drive file={path to ocssd backend file},id=myocssd,format=raw,if=none \
    -device nvme,drive=myocssd,serial=deadbeef,lnum_pu=4,lstrict=1,meta=16,\
    mc=3,id='lnvm',chunktable_txt=$HOME/chunktable.txt

The full command line could look like the following and creates an ocssd with 4
parallel units:

    $HOME/qemu-nvme/bin/qemu-system-x86_64 \
        -cpu host -smp 4 -m 4G \
        -drive file=boot.img,id=bootdrive,format=qcow2,if=none \
        -device virtio-blk-pci,drive=bootdrive,scsi=off,config-wce=off \
        -drive file=nvme00.img,if=none,id=nvme00,format=raw \
        -device nvme,drive=nvme00,serial=deadbeef,lnum_pu=4,lstrict=1,\
        meta=16,mc=3,id='lnvm',lchunktable_txt=chunktable.txt

A complete list of all options supported by the NVMe device can be found in
[the source](hw/block/nvme.c#L61) with comments on each option at the top of
the file and a list of options and their default values toward the bottom of
the file.

In the virtual machine, make sure to install at least Linux kernel 4.20 or
latest release candidate.

You probably want to make sure the following options are enabled in the kernel
you are going to use.

    CONFIG_BLK_DEV_INTEGRITY=y
    CONFIG_HOTPLUG_PCI_PCIE=y
    CONFIG_HOTPLUG_PCI_ACPI=y

## Current limitations

  - The driver does not support multiple groups. This should however be easy to
    implement.
