obj-m += sort.o

LIB=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

all:
	make -C $(LIB) M=$(PWD) modules

clean:
	make -C $(LIB) M=$(PWD) clean
