CONFIG_MODULE_SIG=n
KASAN_SANITIZE := n


# if KERNELRELEASE is defined, we've been invoked from the kernel build system and can use its language.
ifneq (${KERNELRELEASE},)
	obj-m := s2e-kprobe.o
	EXTRA_CFLAGS :="-I$(PWD)/include"
# Otherwise we were called directly from the command line.
# Invoke the kernel build system.
else
	PWD := $(shell pwd)

default:
	$(CFLAGS) $(MAKE) -C $(KERNELPATH) src=$(PWD) M=$(PWD)/s2e-$(KERNELFULL) modules
clean:
	$(MAKE) -C $(KERNELPATH) src=$(PWD) M=$(PWD)/s2e-$(KERNELFULL) clean
install:
	sudo insmod s2e-kprobe.ko
rm:
	sudo rmmod s2e-kprobe
endif

