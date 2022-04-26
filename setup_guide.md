# Guide to setup the system on a brand-new ubuntu 20.04 installation

## Basic packages needed
```console
$ sudo apt install git build-essential cmake # build tools
$ sudo apt install libgtk-3-0-dev nettle-dev libsdl2-dev libjemalloc-dev libcap-dev libattr1-dev linux-kvm # libraries needed for QEMU
$ sudo apt install libncurses5-dev libncursesw5-dev # to enable menuconfig
$ sudo apt install flex bison # optional packages QEMU
```

## Miscellaneous configuration

* Make sure virtualization support is enabled in your BIOS
* Access to performance counters may be disabled by default. It can be enabled as shown below:
```console
$ sudo su
# echo 1 > /proc/sys/kernel/perf_event_paranoid # configuration persists until system reboot
# echo kernel.perf_event_paranoid = 1 >> /etc/sysctl.conf # sets configuration automatically on boot (optional)
```

## Buildroot setup, part 1

* Download, extract, and compile Buildroot 2020.02.9
```console
$ wget https://buildroot.org/downloads/buildroot-2020.02.9.tar.bz2
$ tar xvvf buildroot-2020.02.9.tar.bz2
$ cd buildroot-2020.02.9
$ make qemu_x86_64_defconfig
$ make menuconfig
<Inside the Toolchain menu, check "Enable C++ support" option. Save and exit.>
$ make
```

## libspdm setup

libspdm have to be built three ways.

* Clone libspdm repository and checkout the correct commit
```console
$ git clone https://github.com/DMTF/libspdm.git
$ cd libspdm
$ git checkout dc48779a5b8c9199b01549311922e05429af2a0e
$ git submodule update --init --recursive
```

* Apply the patches from `libspdm_patches` and update mbedtls config file
```console
<in libspdm directory>
$ git am --3way --ignore-space-change --keep-cr /path/to/libspdm_patches/0*.patch
$ cp /path/to/libspdm_patches/config.h os_stub/mbedtlslib/include/mbedtls/
```

* For the purposes os performance analysis, it is recomended to remove any unecessary messages.
	1. Edit file libspdm/include/hal/library/debuglib.h and insert `#define MDEPKG_NDEBUG` after the guard defines
	1. Add `-Wno-error=unused-but-set-variable` flag to CMakeLists.txt to avoid compilation error (`CMAKE_C_FLAGS` variable in `if(TOOLCHAIN STREQUAL "GCC")` section)

* Increase `MAX_SPDM_MESSAGE_BUFFER_SIZE` in `libspdm/include/library/spdm_lib_config.h` to `0x2200`

* Build libspdm to be linked with QEMU (or any other applications at the host machine)
```console
<in libspdm directory>
$ mkdir build_x64
$ cd build_x64
$ cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls .. # could use -DTARGET=Debug
$ make copy_sample_key
$ make
```

* Build libspdm to be linked with the Buildroot Linux kernel
```console
<in libspdm directory>
$ mkdir build_buildroot
$ cd build_buildroot
$ cmake -DARCH=x64 -DTOOLCHAIN=BUILDROOT -DTARGET=Release -DCRYPTO=mbedtls .. # could use -DTARGET=Debug
$ export PATH=/path/to/buildroot-2020.02.9/output/host/bin:$PATH
$ make copy_sample_key
$ make
```

* Build libspdm to be linked with guest userspace applications
```console
<in libspdm directory>
$ mkdir build_buildroot_userspace
$ cd build_buildroot_userspace
$ cmake -DARCH=x64 -DTOOLCHAIN=BUILDROOT_USERSPACE -DTARGET=Release -DCRYPTO=mbedtls .. # could use -DTARGET=Debug
$ #if compiler not already in $PATH add: export PATH=/path/to/buildroot-2020.02.9/output/host/bin:$PATH 
$ make copy_sample_key
$ make
```

## Buildroot setup, part 2

* Enable UIO support on the Buildroot kernel
```console
<in buildroot-2020.02.9 directory>
$ make linux-menuconfig
$ # Enable the following options:
$ #	Device Drivers -> Userspace I/O drivers
$ #	Device Drivers -> Userspace I/O drivers -> Userspace I/O platform driver with generic IRQ handling (as a module)
$ #	Device Drivers -> Userspace I/O drivers -> Generic driver for PCI 2.3 and PCI Express cards (as a module)
$ # Save and exit.
```

* (**optional**) Enable 9p filesystem support (useful to trade files between guest and host)
```console
<in buildroot-2020.02.9 directory>
$ make linux-menuconfig
$ # Enable the following options:
$ #	Networking support -> Plan 9 Resource Sharing Support (9P2000)
$ #	Networking support -> Plan 9 Resource Sharing Support (9P2000) -> 9P Virtio Transport
$ #	File systems -> Network File Systems -> Plan 9 Resource Sharing Support (9P2000)
$ #	File systems -> Network File Systems -> Plan 9 Resource Sharing Support (9P2000) -> 9P POSIX Access Control Lists
$ #	File systems -> Network File Systems -> Plan 9 Resource Sharing Support (9P2000) -> 9P Security Labels
$ # Save and exit.
```

* Copy SPDM-related modifications to the kernel code tree
```console
cp -r /path/to/kernel_hd/drivers /path/to/buildroot-2020.02.9/output/build/linux-4.19.91/
cp -r /path/to/kernel_hd/include /path/to/buildroot-2020.02.9/output/build/linux-4.19.91/
```

* Rebuild Buildroot, indicating libspdm location
```console
$ SPDM_DIR=/path/to/libspdm SPDM_BUILD_DIR=/path/to/libspdm/build_buildroot make
```

## QEMU setup

* Clone the repository and switch to stable-4.1 branch
```
$ git clone https://github.com/qemu/qemu.git
$ cd qemu
$ git switch stable-4.1
```

* Copy new and modified files
```
$ cp -r /path/to/git/qemu_files /path/to/qemu
```

* Build qemu
```console
$ mkdir build
$ cd build
$ ../configure --enable-gtk --enable-libspdm --libspdm-srcdir=/path/to/libspdm --libspdm-builddir=/path/to/libspdm/build_x64 --libspdm-crypto=mbedtls --enable-system --enable-kvm --enable-virtfs --enable-sdl --enable-jemalloc --enable-nettle --disable-pie --enable-debug --target-list=x86_64-softmmu
$ make
```

## Compiling UIO requester
```console
$ cd /path/to/uio_requester/
$ CC=/path/to/buildroot-2020.02.9/output/host/bin/x86_64-buildroot-linux-uclibc-gcc SPDM_DIR=/path/to/libspdm/ SPDM_BUILD_DIR=/path/to/libspdm/build_buildroot_userspace make
```

## Running UIO requester experiments on QEMU

* Symlink (or copy) the certificates to the QEMU build directory
```console
$ cd /path/to/qemu/build 
$ ln -s /path/to/libspdm/build_x64/bin/ecp384
$ ln -s /path/to/libspdm/build_x64/bin/rsa3072
```

### Make UIO requester available inside the VM

#### If 9p filesystem was enabled in the buildroot kernel:
  * Create a directory to be shared between host and guest `mkdir qemu_shared`
  * Copy uio_requester_bench to the directory `cp /path/to/uio_requester/uio_requester_bench /path_to/qemu_shared`
  * Copy the certificates to the same directory `cp -r /path/to/libspdm/buil_buildroot_userspace/bin/{ecp384,rsa3072} /path_to/qemu_shared`
  * Run QEMU
```console
$ cd /path/to/qemu/build
$ ./x86_64-softmmu/qemu-system-x86_64 -enable-kvm -cpu qemu64,pmu=on \
	-device spdm -virtfs local,path=/path/to/qemu_shared/,mount_tag=host0,security_model=mapped,id=host0 \
	-kernel /path/to/buildroot-2020.02.9/output/images/bzImage \
	-drive file=/path/to/buildroot-2020.02.9/output/images/rootfs.ext2,if=ide,format=raw \
	-append "console=ttyS0 rootwait root=/dev/sda" \
	-m 1024 -net nic,model=virtio -net user 
```
  * Inside the vm, mount the shared directory
```console
# mkdir -p /mnt/qemu_shared
# mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/qemu_shared
# cd /mnt/qemu_shared
```
  * Copy the files to the `/root` folder

#### If 9p filesystem was **not** enabled in the buildroot kernel:
  * Mount buildroot's rootfs on the host machine `sudo mount /path/to/buildroot-2020.02.9/output/images/rootfs.ext2 /mnt/mountpoint`
  * Copy the same files mentioned before to `/mnt/mountpoint/root`
  * Umount buildroot's rootfs `sudo umount /mnt/mountpoint`
  * Run QEMU
```console
$ cd /path/to/qemu/build
$ ./x86_64-softmmu/qemu-system-x86_64 -enable-kvm -cpu qemu64,pmu=on \
	-device spdm \
	-kernel /path/to/buildroot-2020.02.9/output/images/bzImage \
	-drive file=/path/to/buildroot-2020.02.9/output/images/rootfs.ext2,if=ide,format=raw \
	-append "console=ttyS0 rootwait root=/dev/sda" \
	-m 1024 -net nic,model=virtio -net user 
```

### Registering spdm responder and running UIO requester

* Inside the vm, load uio generic module and register the spdm responder device
```console
# modprobe uio_pci_generic
# echo "1234 10ff" > /sys/bus/pci/drivers/uio_pci_generic/new_id
```

* Go to the directory where UIO requester is located and run it for que desired amount of times (e.g 10. times)
```console
# for i in $(seq 1 10); do ./uio_requester_bench > uio_requester_i${i}.log; done
```

* QEMU will generate corresponding uio_responder\_iNN.log on the directory its being run. They will be overwritten if QEMU is closed and run again.

### Extracting statistics and generating graphs

* Additional packages needed to run the scripts
```console
$ sudo apt install python3-pandas
```

* Move all `uio_responder_iNN.log` and `uio_requester_iNN.log` to the same folder for organization

* Process files into csv files (substitute N by number of runs)
```console
$ python3 /path/to/uio_requester/benchmark/data_extraction2.py uio_requester 1 N
$ python3 /path/to/uio_requester/benchmark/data_extraction2.py uio_responder 1 N
```

* The graphs in the paper are produced from a filtered version of the csv files
```console
$ grep -v  -e heartbeatPSK -e key_updatePSK -e get_random_spdmPSK -e end_sessionPSK uio_requester.csv | sed s/NoPSK// > uio_requester_filtered.csv
$ grep -v  -e heartbeatPSK -e key_updatePSK -e get_random_spdmPSK -e end_sessionPSK uio_responder.csv | sed s/NoPSK// > uio_responder_filtered.csv
```

* Plot graphs (png can be replaced by other image file formats such as eps)
```console
$ python3 /path/to/uio_requester/benchmark/data_analysis2.py uio_requester_filtered png
$ python3 /path/to/uio_requester/benchmark/data_analysis2.py uio_responder_filtered png
```

## Running HD experiments on QEMU

### Compiling additional software

* fio
```console
$ wget http://brick.kernel.dk/snaps/fio-3.23.tar.gz
$ tar xvvf fio-3.23.tar.gz
$ cd fio-3.23
$ ./configure --cc=x86_64-buildroot-linux-uclibc-gcc --disable-native # the compiler must be in your $PATH
$ make
```

* ioping
```console
$ wget https://github.com/koct9i/ioping/archive/v0.9/ioping-0.9.tar.gz
$ tar xvvf ioping-0.9.tar.gz
$ cd ioping-0.9
$ CC=x86_64-buildroot-linux-uclibc-gcc make # the compiler must be in your $PATH
```

* bonnie++
```console
$ wget http://www.coker.com.au/bonnie++/bonnie++_1.04.tgz
$ tar xvvf bonnie++_1.04.tgz
$ cd bonnie++_1.04
$ CXX=x86_64-buildroot-linux-uclibc-c++ ./configure --host --host-alias # the compiler must be in your $PATH
$ make
```

### Running QEMU

* Prepare a file to be used as an additional hard drive in the VM
```console
$ dd if=/dev/zero of=benchmarkdisk bs=1M count=5000 # creates 5GB empty file. Could be larger or smaller depending on the needs
$ cfdisk benchmarkdisk # create partition table and add a linux partition occupying the whole space. Can use any other partition tool
$ mkfs.ext4 benchmarkdisk # create ext4 filesystem
```

* Run QEMU
```console
$ cd /path/to/qemu/build
$ ./x86_64-softmmu/qemu-system-x86_64 -enable-kvm -cpu qemu64,pmu=on \
	-virtfs local,path=/path/to/qemu_shared/,mount_tag=host0,security_model=mapped,id=host0 \
	-drive file=/path/to/benchmarkdisk,if=virtio,format=raw
	-kernel /path/to/buildroot-2020.02.9/output/images/bzImage \
	-drive file=/path/to/buildroot-2020.02.9/output/images/rootfs.ext2,if=ide,format=raw \
	-append "console=ttyS0 rootwait root=/dev/sda" \
	-m 1024 -net nic,model=virtio -net user
```

* Inside the VM, mount the virtio disk `# mkdir -p /mnt/extra_hd && mount /dev/vda /mnt/extra_hd`

* Make sure fio, ioping, and bonnie++ are in the VM's $PATH (to copy files to the vm, use the methods explained for UIO requester)

* Adjust variables at the top of the script and run `hdbenchmark.sh` (found in kernel_hd/benchmark)

* To run the baseline experiments (without SPDM) set `SPDM_ENABLED` to 0 in `buildroot-2020.02.9/output/build/linux-4.19.91/drivers/block/virtio_blk.c`.
Then recompile the kernel (`make linux-rebuild`). No changes in QEMU are needed. Follow the same procedure as above to run the benchmarks.

### Extracting statistics and generating graphs

* Follow instructions in kernel_hd/benchmark/readme.md
