
PREFIX ?= /usr/local

CFLAGS := -I $(PREFIX)/include/ -Wno-unused-function -Wall
LDFLAGS := -L $(PREFIX)/lib -lcrypto -losmocore -losmogsm -ltalloc

CFLAGS += $(EXTRA_CFLAGS)

all: l2tpd test_connect

l2tpd: l2tpd.o l2tpd_fsm.o l2tpd_data.o l2tpd_packet.o l2tpd_socket.c l2tpd_lapd.c crc32.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_connect: test_connect.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f l2tpd l2tp*.o
