

CFLAGS = -O3 -g -std=c99 -Wall -Wextra -pedantic
CFLAGS += -fsched-pressure
#CFLAGS += -save-temps -fverbose-asm

ARCH = $(shell arch)
KERN = $(shell uname -s)
ifeq ($(ARCH),ppc)
CFLAGS += -maltivec -mabi=altivec -mcpu=7450
ifeq ($(KERN),Linux)
	CFLAGS += -mno-vrsave
endif
endif
ifeq ($(ARCH),ppc64)
CFLAGS += -maltivec -mabi=altivec
endif

siphash-test: siphash-test.o siphash.o



clean:
	rm -f *.o

.PHONY: clean

# use gcc 4.7 if we can
ifneq ($(shell which gcc-4.7),)
CC = gcc-4.7
endif
