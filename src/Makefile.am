AM_CFLAGS = -Wall -I$(top_srcdir)/include -I$(top_builddir)/include \
	    $(OSMOCORE_CFLAGS) $(CRYPTO_CFLAGS)
LDADD = $(OSMOCORE_LIBS) $(CRYPTO_LIBS)

noinst_HEADERS = \
	crc32.h \
	l2tp_protocol.h \
	l2tpd.h \
	l2tpd_data.h \
	l2tpd_fsm.h \
	l2tpd_lapd.h \
	l2tpd_logging.h \
	l2tpd_packet.h \
	l2tpd_socket.h \
	unixsocket_proto.h \
	$(NULL)


sbin_PROGRAMS = osmo-el2tpd
noinst_PROGRAMS = test_connect

osmo_el2tpd_SOURCES = \
	l2tpd.c \
	l2tpd_fsm.c \
	l2tpd_data.c \
	l2tpd_packet.c \
	l2tpd_socket.c \
	l2tpd_lapd.c \
	l2tpd_logging.c \
	crc32.c \
	$(NULL)

test_connect_SOURCES = \
	test_connect.c \
	$(NULL)
