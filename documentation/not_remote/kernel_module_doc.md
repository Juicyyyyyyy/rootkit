### Install linux headers

sudo apt install linux-headers-$(uname -r)

### get info about module

modinfo hello.ko

### Get kernel logs 

sudo dmesg -T -L -W

- T: Show time in a human-readable format
- L: put color on text
- W: only display new logs, not the one generated from the boot

### Insert nodule

sudo insmod  hello.ko 

### List the modules

lsmod

lsmod | grep hello

### Unloading the module

sudo rmmod hello
