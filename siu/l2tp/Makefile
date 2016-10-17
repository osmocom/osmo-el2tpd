
all: l2tpd

l2tpd: l2tpd.c l2tpd_data.c l2tpd_fsm.c
	$(CC) -Wall -lcrypto -losmocore -losmogsm -o $@ $<

clean:
	rm l2tpd
