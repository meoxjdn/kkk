MODULE_NAME := android-wuwa

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := main.o core_hook.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
