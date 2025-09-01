ublk-btrfs-check
================

`ublk-btrfs-check` is a ublk target which runs `btrfs check` every time the
superblock is written on a btrfs volume. This is useful if you are trying to
fix a corruption issue: you will have the `btrfs check` output from as soon as
the problem starts to manifest.

Compilation
-----------

We're using C++ modules, so you will need recent versions of CMake, GCC or
Clang, and Ninja. You will also need ublksrv (a.k.a. ubdsrv), as well as
obviously btrfs-progs.

```
$ git clone https://github.com/maharmstone/ublk-btrfs-check
$ cd ublk-btrfs-check
$ mkdir build
$ cd build
$ cmake -GNinja ..
$ ninja
```

Running
-------

Make sure you have CONFIG_BLK_DEV_UBLK set in your kernel. The driver's name is
`ublk_drv`, if you're doing `modprobe`. You might have to muck about with your
udev rules if you want to run this in unprivileged mode (or just use root).

Create a backing file:
```
$ dd if=/dev/zero of=img bs=4096 count=262144
```

Run `ublk-btrfs-check`:
```
$ ./ublk-btrfs-check img
tid 31279: ublk dev 0 queue 0 started
dev id 0: nr_hw_queues 1 queue_depth 128 block size 512 dev_capacity 2097152
        max rq size 524288 daemon pid 31270 state LIVE
        flags 0x2062 [ URING_CMD_COMP_IN_TASK UNPRIVILEGED_DEV CMD_IOCTL_ENCODE ]
        ublkc: 240:0 ublkb: 259:22 owner: 1000:1004
        queue 0: tid 31279 affinity(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 )
        target {"dev_size":1073741824,"name":"ublk-btrfs-check","type":0}
```

`dev id 0` means that the block device will be called `/dev/ublkb0`.

In another console, manipulate your new block device:

```
# mkfs.btrfs /dev/ublkb0
btrfs-progs v6.16
See https://btrfs.readthedocs.io for more information.

Performing full device TRIM /dev/ublkb0 (1.00GiB) ...
Label:              (null)
UUID:               dde253f4-7654-4865-8c07-84d35c8d2813
Node size:          16384
Sector size:        4096        (CPU page size: 4096)
Filesystem size:    1.00GiB
Block group profiles:
  Data:             single            8.00MiB
  Metadata:         DUP              51.19MiB
  System:           DUP               8.00MiB
SSD detected:       yes
Zoned device:       no
Features:           extref, skinny-metadata, no-holes, free-space-tree
Checksum:           crc32c
Number of devices:  1
Devices:
   ID        SIZE  PATH
    1     1.00GiB  /dev/ublkb0

# mount /dev/ublkb0 /root/temp
# dd if=/dev/zero of=/root/temp/file bs=4096 count=1 conv=fsync
# sync
```

In your first console, you will see something like:
```
btrfs check passed (generation 8)
btrfs check passed (generation 8)
btrfs check passed (generation 9)
```

If one of the check fails, the full output of `btrfs check` will be printed.

Finally `umount` your block device and Ctrl+C to stop the program.

Changelog
=========

* 20250901 - Initial release
