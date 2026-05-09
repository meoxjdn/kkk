MODULE_NAME := android-wuwa

obj-m := $(MODULE_NAME).o
# 核心架构解耦：main 负责网关，core_hook 负责 V10 物理拦截逻辑
$(MODULE_NAME)-objs := main.o core_hook.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# 开启高版本内核下汇编指令支持与 O2 级优化
EXTRA_CFLAGS += -O2

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

