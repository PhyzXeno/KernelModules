KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build

obj-m += drop.o

all:
	make -C $(KERNEL_SRC) M=$(PWD) modules
	
clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean