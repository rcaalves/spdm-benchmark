* Compiling applications to run on Buildroot-generated guest:

```Shell Session
$ CC=<path to buildroot output>/host/bin/x86_64-buildroot-linux-uclibc-gcc SPDM_DIR=/path/to/libspdm/ SPDM_BUILD_DIR=/path/to/libspdm/build/dir DEBUG_LVL=1 make
```

`SPDM_BUILD_DIR` is optional, defaults to `$SPDM_DIR/build`
`DEBUG_LVL` is optional, it defines the verbose level: 1=error only (default), 2=general info

Appropriate certificates must be in the execution directory.

Four executables are generated:

1. `uio_requester_bench`: benchmarking tool
1. `uio_tampering_test`: simple tampering test tool
1. `uio_get_measurement`: tool for retrieving measurements. Usage: `uio_get_measurement <N> <file>`, where `<N>` is the measurement index and `<file>` is a raw data file to be compared with retrieved measurement. Both arguments are optional
1. `uio_tamper_measurement`: tool for simulating the tampering of a chosen measurement. Usage: `uio_tamper_measurement <N>`, where `<N>` is the measurement index