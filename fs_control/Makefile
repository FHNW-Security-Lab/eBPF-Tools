CLANG ?= clang
CFLAGS ?= -g -O2 -Wall
LDFLAGS ?= -lelf -lz

# Output directories
OBJDIR = dist/obj
BINDIR = dist/bin
SKELDIR = dist/skel
INCLUDEDIR = dist/include

# Tools
BPFTOOL ?= bpftool
VMLINUX = $(INCLUDEDIR)/vmlinux.h

INCLUDES = -I$(OBJDIR) -I$(LIBBPF_HEADERS) -I./include -I$(SKELDIR) -I$(INCLUDEDIR)

# Source files
BPF_SOURCE = src/lsm_fs_control.bpf.c
USER_SOURCE = src/lsm_fs_control.c
BPF_OBJ = $(OBJDIR)/lsm_fs_control.bpf.o
SKEL_OBJ = $(SKELDIR)/lsm_fs_control.skel.h
USER_BIN = $(BINDIR)/lsm_fs_control

# libbpf
LIBBPF_SRC = $(abspath libbpf/src)
LIBBPF_OBJ = $(abspath libbpf/src/libbpf.a)
LIBBPF_DIST_OBJ = $(abspath libbpf/src/dist/lib/libbpf.a)
LIBBPF_HEADERS = $(abspath libbpf/include)

.PHONY: all
all: $(USER_BIN)

$(OBJDIR) $(BINDIR) $(SKELDIR) $(INCLUDEDIR):
	mkdir -p $@

# Generate vmlinux.h
$(VMLINUX): | $(INCLUDEDIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF program
$(BPF_OBJ): $(BPF_SOURCE) $(VMLINUX) | $(OBJDIR)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		$(INCLUDES) \
		-c $(BPF_SOURCE) -o $@

# Generate BPF skeleton
$(SKEL_OBJ): $(BPF_OBJ) | $(SKELDIR)
	$(BPFTOOL) gen skeleton $< > $@

# Build libbpf
$(LIBBPF_OBJ): | $(OBJDIR)
	$(MAKE) -C $(LIBBPF_SRC) \
		OBJDIR=$(dir $(LIBBPF_DIST_OBJ))

# Build user-space program
$(USER_BIN): $(USER_SOURCE) $(SKEL_OBJ) $(LIBBPF_OBJ) | $(BINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< \
		$(LIBBPF_DIST_OBJ) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf dist/
	rm -f $(VMLINUX)
	$(MAKE) -C $(LIBBPF_SRC) clean

.PHONY: deps
deps:
	@if [ ! -d "libbpf" ]; then \
		git clone https://github.com/libbpf/libbpf.git; \
	fi

