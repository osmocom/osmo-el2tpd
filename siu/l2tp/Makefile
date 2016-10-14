
all: l2tpd

l2tpd: l2tpd.c
	$(CC) -Wall -lcrypto -losmocore -losmogsm -o $@ $<

clean:
	rm l2tpd
