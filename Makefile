obj-m += labfw.o

all:
	make -C /usr/src/kernels/4.13.16-302.fc27.x86_64 M=$(PWD) modules

clean:
	make -C /usr/src/kernels/4.13.16-302.fc27.x86_64 M=$(PWD) clean