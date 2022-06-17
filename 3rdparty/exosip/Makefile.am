ACLOCAL_AMFLAGS = -I scripts
EXTRA_DIST = README autogen.sh LICENSE.OpenSSL

SUBDIRS = scripts platform src include tools help

doxygen:
	doxygen help/doxygen/DoxyFile

upload: dist
	@echo "######## Maintainer only ##########";
	@echo "building files for upload and scp libexosip2-X.X.X.tar.gz xxxxxx@dl.sv.nongnu.org:/releases/exosip";
	@echo "building: $(PACKAGE)-$(VERSION).tar.gz.sig";
	gpg -b $(PACKAGE)-$(VERSION).tar.gz

indent:
	@type clang-format --version >/dev/null 2>&1 || clang-format -i $(top_srcdir)/include/eXosip2/*.h
	@type clang-format --version >/dev/null 2>&1 || clang-format -i $(top_srcdir)/src/*.h
	@type clang-format --version >/dev/null 2>&1 || clang-format -i $(top_srcdir)/src/*.c
	@type clang-format --version >/dev/null 2>&1 || clang-format -i $(top_srcdir)/tools/*.c
	rm -rf $(top_srcdir)/*/*/*.h~
	rm -rf $(top_srcdir)/*/*.h~
	rm -rf $(top_srcdir)/*/*.c~
