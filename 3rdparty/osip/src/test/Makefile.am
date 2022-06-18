
EXTRA_DIST = tst CHECK res

if COMPILE_TESTS
noinst_PROGRAMS = torture_test turl tfrom tto tcontact tvia tcallid tcontentt trecordr troute twwwa

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/osipparser2
AM_CFLAGS = $(SIP_CFLAGS) $(SIP_PARSER_FLAGS) $(SIP_EXTRA_FLAGS)

twwwa_SOURCES =  twwwa.c
twwwa_LDADD = $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
twwwa_LDFLAGS = -no-install

tcontentt_SOURCES =  tcontentt.c
tcontentt_LDADD = $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
tcontentt_LDFLAGS = -no-install

turl_SOURCES =  turls.c
turl_LDADD = $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
turl_LDFLAGS = -no-install

tfrom_SOURCES =  tfrom.c
tfrom_LDADD =  $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
tfrom_LDFLAGS = -no-install

tto_SOURCES =  tto.c
tto_LDADD = $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
tto_LDFLAGS = -no-install

tcontact_SOURCES =  tcontact.c
tcontact_LDADD =  $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
tcontact_LDFLAGS = -no-install

trecordr_SOURCES =  trecordr.c
trecordr_LDADD =  $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
trecordr_LDFLAGS = -no-install

troute_SOURCES =  troute.c
troute_LDADD =  $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
troute_LDFLAGS = -no-install

tvia_SOURCES =  tvia.c
tvia_LDADD = $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
tvia_LDFLAGS = -no-install

tcallid_SOURCES =  tcallid.c
tcallid_LDADD = $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
tcallid_LDFLAGS = -no-install

torture_test_SOURCES =  torture.c
torture_test_LDADD = $(top_builddir)/src/osipparser2/libosipparser2.la $(PARSER_LIB) $(EXTRA_LIB)
torture_test_LDFLAGS = -no-install

valgrind:
	@echo " ****************************************"
	@echo " ****** starting valgrind tests! ********"
	@echo " ****************************************"
	@type valgrind --version >/dev/null 2>&1 || ./$(top_srcdir)/src/test/tst_valgrind ./$(top_srcdir)/src/test/res -c

	@echo ""
	@echo "In case you have a doubt, send the generated"
	@echo "log file with your comment to <amoizard@antisip.com>."

check:
	@echo " *******************************"
	@echo " ****** starting tests! ********"
	@echo " *******************************"
	@./$(top_srcdir)/src/test/tst ./$(top_srcdir)/src/test/res -c

	@echo ""
	@echo "In case you have a doubt, send the generated"
	@echo "log file with your comment to <amoizard@antisip.com>."
else
valgrind:
	@echo " ************************************"
	@echo " Please use ./configure --enable-test"
	@echo " ************************************"

check:
	@echo " ************************************"
	@echo " Please use ./configure --enable-test"
	@echo " ************************************"
endif
