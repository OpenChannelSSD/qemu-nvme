### Qemu NVMe Driver Fork

####About


This work is part of the OpenChannelSSD/LightNVM project, derived from work on an NVMe driver for Qemu (git://git.qemu.org/qemu).
The NVMe device emulation code has been extended to allow it to pose as a LightNVM-compatible device for testing the proposed kernel component, available from https://github.com/OpenChannelSSD/linux.

#### Compiling & Installing 
Configuration & installation follows the standard QEMU approach, consult [QEMU - Getting Started (Developers)](http://wiki.qemu.org/Documentation/GettingStartedDevelopers) for more information.

Below is a minimal example of the installation process for x86_64, kvm-enabled emulation using libaio for I/O.

    ./configure --python=/usr/bin/python2 --enable-kvm --target-list=x86_64-softmmu --enable-linux-aio --prefix=$HOME/qemu-nvme
    make -j8
    make install


#### Configuring the NVMe device driver

A complete list of all options supported by the NVMe device can be found in [the source](hw/block/nvme.c) with comments on each option at the top of the file and a list of options and their default values toward the bottom of the file.

Example:
> -drive file=/home/<myuser>/blk_nvme_device,if=none,id=lightnvme
> -device nvme,drive=lightnvme,serial=deadbeef,lver=1,ltype=0,lba_index=3,nlbaf=5,lchannels=1,namespaces=1

In this case, a single namespace (namespaces=1) with 4K blocks (nlbaf=5,lba_index=3) is created, as large as the backing file. The device is marked as LightNVM-compatible (lver=1) and block-addressable(ltype=0). Each namespace is assigned a single channel (lchannels=1).

#### Driver Limitations
The modified QEMU NVMe driver has some limitations:
  - The driver cannot support namespaces with different numbers of channels assigned to them - this is not a limitation of the LightNVM standard, but mostly one of determining an easy way of passing the configuration to the underlying driver.
  - The driver does not yet persist the per-namespace physical- to logical block mapping table - ideally this should be handled by partitioning the namespaces (done) and ensuring the data is flushed before the VM shuts down.

Patches, input and comments with respect to any of these limitations are gratefully accepted.

#### QEMU-specific documentation
Read the documentation in qemu-doc.html or on http://wiki.qemu-project.org

- QEMU team
