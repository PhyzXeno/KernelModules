KERNEL_SRC = "/root/Desktop/linux-4.9.18"

obj-m += drop.o

all:
	make -C $(KERNEL_SRC) M=$(PWD) modules
	
clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean