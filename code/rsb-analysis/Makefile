# Compiler and assembler settings
CC = gcc
ASM = nasm
CFLAGS = -Wall -Wextra -O0 -masm=intel -fno-stack-protector -g3
ASMFLAGS = -f elf64
LDFLAGS = -static

# Targets
TARGET = get-rsb-entries
C_SOURCE = get-rsb-entries.c
ASM_SOURCE = attack.S
OBJECTS = $(C_SOURCE:.c=.o) $(ASM_SOURCE:.S=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(ASM) $(ASMFLAGS) $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)
