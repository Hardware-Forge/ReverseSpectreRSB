obj-m := my-module-main.o
my-module-main-y := my-module.o attack.o

KERNELDIR = ../linux-6.13/
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
