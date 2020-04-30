# QEMU Open-Channel SSD 2.0

This repository contains a fork of [qemu/qemu](https://github.com/qemu/qemu)
with modifications to the NVMe device to allow the device to expose itself as
an Open-Channel 2.0 device.

Also included is support for metadata, SGLs, predefined data according to
`DLFEAT`, optional error recovery through the error recovery `DULBE`-attribute
and error injection.

## Compiling & Installing

Below is a minimal example of the installation process.

    git clone https://github.com/OpenChannelSSD/qemu-nvme.git

    cd qemu-nvme
    ./configure --target-list=x86_64-softmmu --prefix=$HOME/qemu-nvme
    make
    make install

**NOTE** Consider using the `--enable-trace-backends=log` configure option for
better debugging.

## Configuring the Open-Channel 2.0 SSD device

The device must have a backing file to store its data. An initialized OCSSD
backing file must be created using `qemu-img`:

```
qemu-img create -f ocssd -o num_grp=2,num_pu=4,num_chk=60 ocssd.img
```

Besides the geometry options (`num_{grp,pu,chk,sec}`), `qemu-img` also supports
options related to write characteristics (`ws_min`, `ws_opt` and `mw_cunits`).
These options can also be overwritten as parameters to the device. Issue

```
qemu-img create -f ocssd -o help
```

to see the full list of supported options.

To add the OCSSD NVMe device, extend the QEMU arguments with something like:

```
-blockdev ocssd,node-name=nvme01,file.driver=file,file.filename=ocssd.img
-device nvme,drive=nvme01,serial=deadbeef,id=lnvm
```

To get a complete list of all options supported by the NVMe device, issue

```
qemu-system-x86_64 -device nvme,help
```

or look into [the source](hw/block/nvme/nvme.c#L31).

There are two QEMU device parameters that change the behavior of the device.
The first, `learly_reset` is enabled by default and allows `OPEN` chunks to be
reset. While the OCSSD 2.0 specification does not allow this most available
drives do. The second, `lsgl_lbal` is disabled by default and governs how the
`LBAL` field should be interpreted if `DPTR` is an SGL (`PSDT` is `0x1` or
`0x2`). By default `LBAL` will be not be interpreted as an SGL in any case.
Enabling this option may be useful for toying around with NVMe over Fabrics.

### Chunk State

The emulated device maintains a Chunk Info Log Page on the backing block
device. When the device is brought up any state will be restored. The restored
chunk states may be overwritten using the `lchunkstate` parameter. An example
chunk state file:

```
grp=0 pu=0 chk=0 state=OPEN wp=65535 type=W_RAN wi=0
grp=0 pu=0 chk=1 state=OFFLINE wp=65535 type=W_SEQ wi=0
grp=0 pu=0 chk=2 state=CLOSED wp=4096 type=W_SEQ wi=0
grp=0 pu=0 chk=3 state=OPEN wp=2048 type=W_SEQ wi=0
```

### Error Injection

The `lresetfail` and `lwritefail` QEMU parameters can be used to do
probabilistic error injection. The parameters points to text files.

Write error injection is done per sector.

```
grp=0 pu=3 chk=0 sec=53 writefail_prob=100
```

Reset error injection is done per chunk, so exclude the `sec` parameter.

```
grp=0 pu=3 chk=5 resetfail_prob=100
grp=0 pu=3 chk=6 resetfail_prob=20
```

## Guest Kernel

You probably want to make sure the following options are enabled in the kernel
you are going to use.

```
CONFIG_BLK_DEV_INTEGRITY=y
CONFIG_HOTPLUG_PCI_PCIE=y
CONFIG_HOTPLUG_PCI_ACPI=y
```
