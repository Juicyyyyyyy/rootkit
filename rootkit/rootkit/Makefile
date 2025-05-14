obj-m += epirootkit.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	@echo "Building EpiRootkit module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	@echo "Cleaning EpiRootkit build..."
	rm -f *.o *.ko *.mod.c *.symvers *.order
