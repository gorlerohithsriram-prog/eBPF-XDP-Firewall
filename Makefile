CLANG ?= clang
CC ?= gcc

BPF_CFLAGS := -O2 -g -target bpf
USER_CFLAGS := -O2 -g

LIBS := -lbpf -lelf -lz

BPF_SRC := bpf/firewall.bpf.c
BPF_OBJ := bpf/firewall.bpf.o
SKEL := bpf/firewall.skel.h

LOADER_SRC := loader/fw.c
TARGET := fw

all: $(TARGET)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(TARGET): $(LOADER_SRC) $(SKEL)
	$(CC) $(USER_CFLAGS) $(LOADER_SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)
	rm -f $(BPF_OBJ)
	rm -f $(SKEL)

.PHONY: all clean
