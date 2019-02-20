# Virtual Open-Channel SSD 2.0

This repository implements support for exposing an NVMe device that implements
the Open-Channel 2.0 specification.

**NOTE** This is the CNEX Labs development version of this fork. See
[OpenChannelSSD/qemu-nvme](https://github.com/OpenChannelSSD/qemu-nvme) for
upstream. This fork differs from upstream:

-  [x] Upstream QEMU master merged
-  [x] Support for multiple groups
-  [x] Support for SGLs
-  [x] Refactored I/O path (metadata and chunk info log page on backend file)
-  [x] Optional support for chunk early close (`learly_close` parameter)
-  [x] Support for no metadata (parameter `ms=0`)
-  [x] Strongly respects the OCSSD 2.0 read/write/reset access rules
-  [x] Write and reset error injection
-  [x] Additional tracing (prefixes `nvme` and `lnvm`)

It is the intention to have this merged into upstream qemu-nvme, but there are
still some rough edges.

## Compiling & Installing

Below is a minimal example of the installation process for x86_64 into
`$HOME/qemu-nvme/bin`.

    git clone https://github.com/CNEX-Labs/qemu-nvme.git

    cd qemu-nvme
    ./configure --target-list=x86_64-softmmu --prefix=$HOME/qemu-nvme
    make
    make install

**NOTE** Consider using the `--enable-trace-backends=log` configure option for
better debugging.

## Configuring the virtual open-channel SSD drive

The device must have a backend file to store its data. Create a backend file by
(e.g., 8GB)

    dd if=/dev/zero of=ocssd.img bs=1M count=8192

To add the OCSSD NVMe device, extend the QEMU arguments with something like:

    -blockdev raw,node-name=nvme01,file.driver=file,file.filename=ocssd.img \
    -device nvme,drive=nvme01,serial=deadbeef,ms=16,id=lnvm,\
      lnum_grp=2,lnum_pu=4,lclba=4096,lws_min=4,lws_opt=8

Only the number of group, parallel units per group and sectors per chunk are
configured. The number of chunks per parallel unit is inferred from those
values to fill out the backend file (with reserved space for internal and
external metadata).

A complete list of all options supported by the NVMe device can be found in
[the source](hw/block/nvme.c#L31).

You probably want to make sure the following options are enabled in the kernel
you are going to use.

    CONFIG_BLK_DEV_INTEGRITY=y
    CONFIG_HOTPLUG_PCI_PCIE=y
    CONFIG_HOTPLUG_PCI_ACPI=y
