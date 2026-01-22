# Makefile for Lab E - myELF
# Compiles the ELF file analyzer with 32-bit support

# Compiler and flags
CC = gcc
# -m32: compile for 32-bit (required for this lab since we work with 32-bit ELF)
# -Wall: enable all warnings (good practice)
# -g: include debug symbols (useful for debugging with gdb)
CFLAGS = -m32 -Wall -g

# Target executable name
TARGET = myELF

# Source files
SRCS = myELF.c

# Object files (generated from source files)
OBJS = $(SRCS:.c=.o)

# Default target - build the program
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up generated files
clean:
	rm -f $(OBJS) $(TARGET) out.ro

# Run the program
run: $(TARGET)
	./$(TARGET)

# Phony targets (not actual files)
.PHONY: all clean run
