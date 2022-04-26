* Compiling application to run on Buildroot-generated guest:
```Shell Session
$ CC=<path to buildroot output>/host/bin/x86_64-buildroot-linux-uclibc-gcc SPDM_DIR=/path/to/libspdm/ SPDM_BUILD_DIR=/path/to/libspdm/build/dir DEBUG_LVL=2 make
```

`SPDM_BUILD_DIR` is optional, defaults to `$SPDM_DIR/build`
`DEBUG_LVL` is optional, it defines the verbose level: 1=error only (default), 2=general info

Appropriate certificates must be in the execution directory.