
PREFIX ?= /usr/local

CFLAGS := -I $(PREFIX)/include/ -Wno-unused-function -Wall
LDFLAGS := -L $(PREFIX)/lib -lcrypto -losmocore -losmogsm -ltalloc

all: l2tpd

l2tpd: l2tpd.o l2tpd_fsm.o l2tpd_data.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f l2tpd l2tp*.o
