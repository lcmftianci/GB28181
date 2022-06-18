
if COMPILE_TOOLS
bin_PROGRAMS = sip_reg sip_monitor sip_storm
endif

AM_CFLAGS = $(EXOSIP_FLAGS)

sip_storm_SOURCES = sip_storm.c
sip_storm_LDADD = $(top_builddir)/src/libeXosip2.la $(OSIP_LIBS)

sip_reg_SOURCES = sip_reg.c
sip_reg_LDADD = $(top_builddir)/src/libeXosip2.la $(OSIP_LIBS)

sip_monitor_SOURCES = sip_monitor.c
sip_monitor_LDADD = $(top_builddir)/src/libeXosip2.la $(OSIP_LIBS)

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include $(OSIP_CFLAGS)
