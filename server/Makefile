# Mafifile

CC = gcc
# CFLAGS	= -g -O0 -Wall -Werror -D_GNU_SOURCE -DUPLOAD_SUPPORT -std=c99
CFLAGS	= -g -O0 -Wall -Werror -D_GNU_SOURCE -std=c99
INCLUDE = -I./include
LIB = -lcrypt -pthread

BINARY = sftpd
SRC = $(wildcard src/*.c)
OBJ = $(subst .c,.o, $(SRC))

all: $(OBJ)
	$(CC) -o $(BINARY) $(OBJ) $(LIB)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ -c $<

clean:
	rm -rf $(OBJ) $(BINARY)
