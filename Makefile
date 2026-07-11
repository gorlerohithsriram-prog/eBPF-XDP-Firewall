CLANG ?= clang
CC ?= gcc

BPF_CFLAGS = -O2 -g -target bpf
USER_CFLAGS = -O2 -g

LIBS = -lbpf -lelf -lz

all: bpf/firewall.bpf.o bpf/firewall.skel.h fw

bpf/firewall.bpf.o: bpf/firewall.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf/firewall.skel.h: bpf/firewall.bpf.o
	bpftool gen skeleton $< > $@

fw: loader/fw.c bpf/firewall.skel.h
	$(CC) $(USER_CFLAGS) loader/fw.c -o fw $(LIBS)

clean:
	rm -f fw
	rm -f bpf/firewall.bpf.o
	rm -f bpf/firewall.skel.h
