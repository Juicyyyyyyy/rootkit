- le pc de la victime doit etre sur un linux d'une version >= 4.0

## Attacking VM and the attacking program

### Goal
In this exercise, you are expected to produce a virtual machine and a program to communicate with
the rootkit.

### Virtual machine
The virtual machine executing the attacking program must be a Linux distribution. It can be
whatever distribution you want.
It must run on the EPITA’s laptop.

### Technology
You are free to use the technology you want to code the attacking program. As long as it run on the
attacking virtual machine

---

### Victim VM and EpiRootkit

### Goal
In this exercise, you are expected to produce a kernel object serving as a rootkit.

### Virtual machine
The virtual machine executing the rootkit must be a Linux distribution. It can be whatever distri-
bution you want.
It must run on the EPITA’s laptop.

### Module kernel creation
Your Makefile must be able to create the epirootkit module kernel and clean the repo.
You are free about your Makefile, so make whatever target you want to make whatever you want.
Just document it.
### Rootkit features
The following features can be made in the order you want. I list them in the order I think is the
easiest, but make yourself confortable if you want to make them in the reverse order.
### Compiling
This is mandatory.
Please make your code compile...
### Connection
This is mandatory.
I want a visual alert about the state of the connection between the rootkit and the attacking program.
Once loaded in the kernel, your rootkit must contact the attacking program installed on the attacking
server. Make your attacking program visually alert (stdout, stderr, in a log file displayed on real
time, whatever ...) the connection.
If your rootkit can’t contact the attacking program or get disconnected, it must continue to try to
contact the attacking program until the connection is successful. The attacking program must then
change the state of the connection.
It is for you to think about how long it goes without trying a new connection? No waiting? 1 minute?
5 minutes? You will earn the same amount of point, anyway, but make it works (and don’t make it
too long for my own test please...).
The connection must be persistent. Sending one socket to alert the attacking program and getting
disconnected just after that is not good enough.
SYS2
Wild Linux Kernel Object Module EpiRootkit 8
### Persistence
This is mandatory.
Your rootkit must stay loaded after a reboot.
### Password
This is mandatory.
Secure the access to the rootkit with a password. Don’t make it a hardcoded value in the rootkit.
### Executing commands
This is mandatory.
From your attacking program, make it possible to execute programs or scripts and getting the stdout,
stderr and exit status back to the attacking program.
