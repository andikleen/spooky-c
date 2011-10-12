CFLAGS := -g -O2 -Wall

OBJ := spooky-c.o test.o map.o

all: test

test: ${OBJ}

clean:
	rm -f ${OBJ} test
