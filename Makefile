CAPSTONE_ARCHIVE := capstone-3.0.5-rc2.tar.gz
CAPSTONE_DIR := capstone-3.0.5-rc2
CAPSTONE_LIB := $(CAPSTONE_DIR)/libcapstone.a

DEBUG ?= 0

CC := gcc
CFLAGS := -isystem $(CAPSTONE_DIR)/include -Wall -Wextra -Wpedantic
ifeq ($(DEBUG),1)
CFLAGS += -O0 -g
else
CFLAGS += -O3
endif
#CFLAGS += -fsanitize=address
PROGRAM := gbadisasm
SOURCES := main.c disasm.c
LIBS := $(CAPSTONE_LIB)

# Compile the program
$(PROGRAM): $(SOURCES) $(CAPSTONE_LIB)
	$(CC) $(CFLAGS) $^ -o $@

# Build libcapstone
$(CAPSTONE_LIB): $(CAPSTONE_DIR)
	make -C $(CAPSTONE_DIR) CAPSTONE_STATIC=yes CAPSTONE_SHARED=no CAPSTONE_ARCHS="arm"

# Extract the archive
$(CAPSTONE_DIR): $(CAPSTONE_ARCHIVE)
	tar -xvf $(CAPSTONE_ARCHIVE)

clean:
	$(RM) $(PROGRAM) $(PROGRAM).exe

distclean: clean
	rm -rf $(CAPSTONE_DIR)
