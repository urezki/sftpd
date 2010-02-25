# Mafifile

CC = gcc
CFLAGS	= -g -O0 -Wall -Werror -D_GNU_SOURCE -DMEMORY_DEBUG -DUPLOAD_SUPPORT -std=c99
INCLUDE = -I./include
LIB = -lcrypt

BINARY = sftpd
SRC = $(wildcard src/*.c)
OBJ = $(subst .c,.o, $(SRC))

all: $(OBJ)
	$(CC) -o $(BINARY) $(OBJ) $(LIB)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ -c $<

clean:
	rm -rf $(OBJ) $(BINARY)
