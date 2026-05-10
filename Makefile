MODULE_NAME := android-wuwa
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := core.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

EXTRA_CFLAGS += -O2 -Wno-declaration-after-statement

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
