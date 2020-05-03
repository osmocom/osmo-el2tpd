AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = src

EXTRA_DIST = .version README.md notes/notes.txt

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
