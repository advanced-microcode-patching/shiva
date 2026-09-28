# saruman_v2

## Description

Saruman injects a dynamically linked PIE executable into a remote process image and creates
a thread of execution for it. This is an anti-forensics technique. Further improvements can be made
such as writing a custom loader to replace dlopen that specifically uses anonymous memory mappings.

## Build instructions

### Install libelfmaster

```
$ git clone git@github.com:elfmaster/libelfmaster
$ cd libelfmaster/src
$ make
$ sudo make install
```

### Build Saruman

```
$ cd saruman
$ make
```

### Usage

Specify the target pid of the process you want to inject into
Specify the path of the executable you want to run inside of the remote process
Specify the command line args of the program you are injecting
```
./saruman <target_pid> <exec_path> [args]
```

### NOTES

The executable file that you are injecting will be slightly modified.
In order for the newer glibc's dlopen() to load a PIE executable it must
have the PIE flag turned off in the DT_FLAGS_1 tag of the dynamic segment.
This won't effect the execution of the program in anyway but you must have
write access to the executable you are loading.

ptrace scope must be disabled (Set to 0) unless you call ./saruman as root.




