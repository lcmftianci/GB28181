/*
 * SIP Monitoring Agent -- by amoizard@gmail.com
 *
 * This program is Free Software, released under the GNU General
 * Public License v2.0 http://www.gnu.org/licenses/gpl
 *
 * This program will monitor connection to a SIP proxy.
 *
 */

#if !defined(WIN32)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#ifndef OSIP_MONOTHREAD
#include <pthread.h>
#endif
#include <string.h>
#ifdef __linux
#include <signal.h>
#endif
#endif

#include <sys/time.h>

#include <osip2/osip_mt.h>
#include <eXosip2/eXosip.h>
#include <osip2/osip.h>

#if !defined(WIN32)
#define _GNU_SOURCE
#include <getopt.h>
#endif

#define PROG_NAME "sip_monitor"
#define SYSLOG_FACILITY LOG_DAEMON

struct monitored_log {
  int log_level;
  int count;
  char log[1024];
};

static volatile int keepRunning = 2;
static int debug = 0;
static osip_list_t monitored_logs;
static char error_reason[1024] = {'\0'};
#ifdef __linux

static void intHandler(int dummy) {
  keepRunning = 0;
}
#endif

#if defined(WIN32)
static void syslog_wrapper(int a, const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  vfprintf(stdout, fmt, args);
  va_end(args);
}

#define LOG_INFO 0
#define LOG_ERR 0
#define LOG_WARNING 0
#define LOG_DEBUG 0

#elif defined(LOG_PERROR)
/* If we can, we use syslog() to emit the debugging messages to stderr. */
#define syslog_wrapper syslog
#else
#define syslog_wrapper(a, b...) \
  fprintf(stderr, b);           \
  fprintf(stderr, "\n")
#endif

static void usage(void);

static void usage(void) {
  printf(PROG_NAME
         " v%s\n"
         "\nUsage: " PROG_NAME
         " [required_options] [optional_options]\n"
         "\n[required_options]\n"
         "  -r --proxy       sip:proxyhost[:port]\n"
         "  -u --from        sip:user@host[:port]\n"
         "\n[optional_options]\n"
         "  -d --daemon                                 (fork in daemon mode)\n"
         "  -s --syslogandconsole                       (output syslog to stderr)\n"
         "  -v --verbose     number                     (show exosip logs to stdout)\n"
         "\n[optional_sip_options]\n"
         "  -U --username    username                   (authentication username)\n"
         "  -P --password    password                   (authentication password)\n"
         "  -o --outbound    sip:proxyhost[:port]       (outbound proxy)\n"
         "  -t --transport   UDP|TCP|TLS|DTLS           (default UDP)\n"
         "  -e --expiry      number                     (default 0 second - ie: fetch bindings)\n"
         "  -S --sslrootcapath /etc/path                (default /etc/ssl/certs/)\n"
         "\n[very_optional_sip_options]\n"
         "  -p --port        number                     (default 0 - random)\n"
         "  -c --contact     sip:user@host[:port]\n"
         "  -m --automasquerade                         (auto discover NAT IP:PORT)\n"
         "\n"
         "  -h --help\n",
         eXosip_get_version());
}

typedef struct regparam_t {
  int regid;
  int expiry;
  int auth;
} regparam_t;

struct eXosip_t *context_eXosip;

static void add_log(int level, char *_log) {
  osip_list_iterator_t it;
  struct monitored_log *ml;

  ml = (struct monitored_log *) osip_list_get_first(&monitored_logs, &it);

  while (ml != OSIP_SUCCESS) {
    if (ml != NULL && strcmp(ml->log, _log) == 0) {
      ml->count++;
      return;
    }

    ml = (struct monitored_log *) osip_list_get_next(&it);
  }

  ml = (struct monitored_log *) osip_malloc(sizeof(struct monitored_log));
  ml->log_level = level;
  ml->count = 1;
  snprintf(ml->log, sizeof(ml->log), "%s", _log);
  osip_list_add(&monitored_logs, ml, -1);
}

static void dump_logs() {
  while (!osip_list_eol(&monitored_logs, 0)) {
    struct monitored_log *ml = (struct monitored_log *) osip_list_get(&monitored_logs, 0);
    syslog_wrapper(ml->log_level, "[count=%i] %s", ml->count, ml->log);
    osip_list_remove(&monitored_logs, 0);
    osip_free(ml);
  }
}

#if defined(WIN32) || defined(__linux)
#define HAVE_LOCALTIME
#endif
#define MAX_LENGTH_TR 2024

static void __osip_trace_func(const char *fi, int li, osip_trace_level_t level, const char *chfr, va_list args) {
  char time_buffer[80] = {'\0'};
#if defined(HAVE_LOCALTIME)
  {
    time_t timestamp;
    struct timeval now;
    struct tm *ptm;
#ifdef __USE_POSIX
    struct tm local_tm;
#endif
    int tenths_ms;
    osip_gettimeofday(&now, NULL);

    timestamp = now.tv_sec;
    tenths_ms = now.tv_usec / (100L);
#ifdef __USE_POSIX
    ptm = localtime_r(&timestamp, &local_tm);
#else
    ptm = localtime(&timestamp);
#endif

    snprintf(time_buffer, 80, "%04d-%02d-%02d %02d:%02d:%02d.%04d", 1900 + ptm->tm_year, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec, tenths_ms);
  }
#endif

  {
    char buffer[MAX_LENGTH_TR];
    int in = 0;

    memset(buffer, 0, sizeof(buffer));

    if (level == OSIP_FATAL) {
      in = snprintf(buffer, MAX_LENGTH_TR - 1, "| FATAL | %s <%10.10s:%5i> ", time_buffer, fi, li);

    } else if (level == OSIP_BUG) {
      in = snprintf(buffer, MAX_LENGTH_TR - 1, "|  BUG  | %s <%10.10s:%5i> ", time_buffer, fi, li);

    } else if (level == OSIP_ERROR) {
      in = snprintf(buffer, MAX_LENGTH_TR - 1, "| ERROR | %s <%10.10s:%5i> ", time_buffer, fi, li);

    } else if (level == OSIP_WARNING) {
      in = snprintf(buffer, MAX_LENGTH_TR - 1, "|WARNING| %s <%10.10s:%5i> ", time_buffer, fi, li);

    } else if (level == OSIP_INFO1) {
      in = snprintf(buffer, MAX_LENGTH_TR - 1, "| INFO1 | %s <%10.10s:%5i> ", time_buffer, fi, li);

    } else if (level == OSIP_INFO2) {
      in = snprintf(buffer, MAX_LENGTH_TR - 1, "| INFO2 | %s <%10.10s:%5i> ", time_buffer, fi, li);

    } else if (level == OSIP_INFO3) {
      in = snprintf(buffer, MAX_LENGTH_TR - 1, "| INFO3 | %s <%10.10s:%5i> ", time_buffer, fi, li);

    } else if (level == OSIP_INFO4) {
      in = snprintf(buffer, MAX_LENGTH_TR - 1, "| INFO4 | %s <%10.10s:%5i> ", time_buffer, fi, li);
    }

    vsnprintf(buffer + in, MAX_LENGTH_TR - 1 - in, chfr, args);
    buffer[MAX_LENGTH_TR - 1] = '\0';

    if (debug > (int) level) {
      printf("%s", buffer);
    }

    if (strstr(buffer, "[getaddrinfo] dns") != NULL && strstr(buffer, "failure") != NULL) {
      char *tmp = strstr(buffer, "[getaddrinfo");
      add_log(LOG_ERR, tmp);

      if (error_reason[0] == '\0') {
        snprintf(error_reason, sizeof(error_reason), "%s", tmp);
      }

    } else if (strstr(buffer, "socket [") != NULL && strstr(buffer, "] connected")) {
      char *tmp = strstr(buffer, "socket [");
      add_log(LOG_ERR, tmp);

    } else if (strstr(buffer, "[ssl connect] [verification=") != NULL) {
      char *tmp = strstr(buffer, "[ssl connect] ");
      add_log(LOG_INFO, tmp);

      if (error_reason[0] == '\0') {
	if (strstr(buffer, "[ssl connect] [verification=ENABLED] [FAILURE") != NULL) {
	  snprintf(error_reason, sizeof(error_reason), "%s", tmp);
	}
      }
      
    } else if (strstr(buffer, "[TLS] invalid  depth[") != NULL) {
      char *tmp = strstr(buffer, "[TLS] invalid  depth[");
      add_log(LOG_ERR, tmp);

      if (error_reason[0] == '\0') {
        snprintf(error_reason, sizeof(error_reason), "%s", tmp);
      }

    } else if (strstr(buffer, "cannot connect socket ") != NULL && strstr(buffer, "terminated") != NULL) {
      char *tmp = strstr(buffer, "cannot connect socket ");
      add_log(LOG_ERR, tmp);

      if (error_reason[0] == '\0') {
        snprintf(error_reason, sizeof(error_reason), "%s", tmp);
      }
    }
  }
}

#ifdef TEST_NAPTR

static int _naptr_lookup(const char *sip_server, struct osip_naptr *naptr_lookup, int keep_in_cache) {
  osip_naptr_t *naptr_record;
  naptr_record = eXosip_dnsutils_naptr(context_eXosip, sip_server, "sip", "tcp", keep_in_cache);

  if (naptr_record != NULL) {
    while (1) {
      /* 1: make sure there is no pending DNS */
      eXosip_dnsutils_dns_process(naptr_record, 1);

      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS) {
        eXosip_dnsutils_dns_process(naptr_record, 1);
      }

      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_UNKNOWN) {
        /* fallback to DNS A */
        /* should never happen? */
        eXosip_dnsutils_release(naptr_record);
        return OSIP_NOTFOUND;

      } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_INPROGRESS) {
        /* 2: keep waiting (naptr answer not received) */
        osip_usleep(10000);
        continue;

      } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE) {
        /* 3: keep waiting (naptr answer received/no srv answer received) */
        osip_usleep(1000);
        continue;

      } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS) {
        /* 3: keep waiting (naptr answer received/no srv answer received) */
        osip_usleep(1000);
        continue;

      } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVDONE) {
        /* 4: check if we have the one we want... */
        if (naptr_lookup != NULL) {
          memcpy(naptr_lookup, naptr_record, sizeof(struct osip_naptr));
        }

        eXosip_dnsutils_release(naptr_record);
        return OSIP_SUCCESS;

      } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NOTSUPPORTED) {
        /* 5: fallback to DNS A */
        eXosip_dnsutils_release(naptr_record);
        return OSIP_NOTFOUND;

      } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_RETRYLATER) {
        /* 5: fallback to DNS A */
        eXosip_dnsutils_release(naptr_record);
        return OSIP_TIMEOUT;
      }
    }
  }

  return -1;
}

static int _resolv_naptr(const char *domain) {
  struct timeval time_start;
  struct timeval time_end;
  struct timeval time_sub;

  int err;
  struct osip_naptr naptr_lookup;

  osip_gettimeofday(&time_start, NULL);

  memset(&naptr_lookup, 0, sizeof(struct osip_naptr));
  err = _naptr_lookup(domain, &naptr_lookup, 1);

  if (err == OSIP_SUCCESS) {
    if (naptr_lookup.sipenum_record.name[0] != '\0') {
      /* enum resolved: */
      syslog_wrapper(LOG_INFO, "ENUM: %s -> %s", domain, naptr_lookup.sipenum_record.name);

    } else {
      struct osip_srv_record *best = NULL;

      if (naptr_lookup.sipudp_record.srventry[0].port > 0) {
        best = &naptr_lookup.sipudp_record;

      } else if (naptr_lookup.siptcp_record.srventry[0].port > 0) {
        best = &naptr_lookup.siptcp_record;

      } else if (naptr_lookup.siptls_record.srventry[0].port > 0) {
        best = &naptr_lookup.siptls_record;
      }

      if (best != NULL) {
        if (naptr_lookup.siptcp_record.srventry[0].port > 0) {
          if (naptr_lookup.siptcp_record.order <= best->order) {
            best = &naptr_lookup.siptcp_record;
          }
        }

        if (naptr_lookup.siptls_record.srventry[0].port > 0) {
          if (naptr_lookup.siptls_record.order <= best->order) {
            best = &naptr_lookup.siptls_record;
          }
        }

        osip_gettimeofday(&time_end, NULL);
        osip_timersub(&time_end, &time_start, &time_sub);
        syslog_wrapper(LOG_INFO, "NAPTR REPORT:[SUCCESS] [duration:%li,%03lis] best service for %s -> [%s] [%s:%i]", time_sub.tv_sec, time_sub.tv_usec / 1000, naptr_lookup.domain, best->protocol, best->srventry[0].srv, best->srventry[0].port);
        return 0;
      }
    }
  }

  osip_gettimeofday(&time_end, NULL);
  osip_timersub(&time_end, &time_start, &time_sub);
  syslog_wrapper(LOG_ERR, "NAPTR REPORT:[FAILURE] [duration:%li,%03lis] no NAPTR/no SRV record for %s", time_sub.tv_sec, time_sub.tv_usec / 1000, domain);
  return 0;
}

#endif

static int _am_option_route_add_lr(const char *orig_route, char *dst_route, int dst_route_size) {
  osip_route_t *route_header = NULL;
  char *new_route = NULL;
  const char *tmp;
  const char *tmp2;
  int i;

  memset(dst_route, '\0', dst_route_size);
  if (orig_route == NULL || orig_route[0] == '\0')
    return 0;

  tmp = strstr(orig_route, "sip:");
  tmp2 = strstr(orig_route, "sips:");
  if (tmp == NULL && tmp2 == NULL) {
    snprintf(dst_route, dst_route_size, "<sip:%s;lr>", orig_route);
    return 0;
  }

  i = osip_route_init(&route_header);
  if (i != 0 || route_header == NULL)
    return OSIP_NOMEM;
  i = osip_route_parse(route_header, orig_route);
  if (i != 0 || route_header->url == NULL || route_header->url->host == NULL) {
    osip_route_free(route_header);
    snprintf(dst_route, dst_route_size, "%s", orig_route);
    return i;
  }

  tmp = strstr(orig_route, ";lr");
  if (tmp == NULL)
    osip_uri_uparam_add(route_header->url, osip_strdup("lr"), NULL);

  i = osip_route_to_str(route_header, &new_route);
  osip_route_free(route_header);
  if (i != 0 || new_route == NULL) {
    return i;
  }
  snprintf(dst_route, dst_route_size, "%s", new_route);
  osip_free(new_route);
  return 0;
}

static int _prepend_route(osip_message_t *sip, const char *hvalue) {
  osip_route_t *route;
  int i;
  char outbound_route[256];

  if (hvalue == NULL || hvalue[0] == '\0')
    return OSIP_SUCCESS;

  memset(outbound_route, '\0', sizeof(outbound_route));
  i = _am_option_route_add_lr(hvalue, outbound_route, sizeof(outbound_route));
  if (i != 0)
    return i;

  i = osip_route_init(&route);

  if (i != 0)
    return i;
  i = osip_route_parse(route, outbound_route);
  if (i != 0) {
    osip_route_free(route);
    return i;
  }
  sip->message_property = 2;
  osip_list_add(&sip->routes, route, 0);
  return OSIP_SUCCESS;
}

int main(int argc, char *argv[]) {
  int exit_code = 1;
  int c;
  int port = 0;
  char *contact = NULL;
  char *fromuser = NULL;
  int automasquerade = 0;
  char *proxy = NULL;
  char *outbound = NULL;
  char transport[5];

  struct servent *service;
  char *username = NULL;
  char *password = NULL;
  char sslrootcapath[1024];
  struct regparam_t regparam = {0, -1, 0};
  int fork = 0;
  int log_perror = 0;
  int err;

  char prog_name[32];
  int optval;

  struct timeval time_start;
  struct timeval time_end;
  struct timeval time_sub;

  snprintf(prog_name, sizeof(prog_name), "%s (%s)", PROG_NAME, eXosip_get_version());

#ifdef SIGPIPE
  signal(SIGPIPE, SIG_IGN);
#endif
#ifdef __linux
  signal(SIGINT, intHandler);
#endif

  snprintf(transport, sizeof(transport), "%s", "UDP");
  snprintf(sslrootcapath, sizeof(sslrootcapath), "%s", "/etc/ssl/certs/");

  for (;;) {
#define short_options "du:r:U:P:o:S:t:p:c:e:mv:sh"
#ifdef _GNU_SOURCE
    int option_index = 0;

    static struct option long_options[] = {{"deamon", no_argument, NULL, 'd'},
                                           {"from", required_argument, NULL, 'u'},
                                           {"proxy", required_argument, NULL, 'r'},
                                           {"username", required_argument, NULL, 'U'},
                                           {"password", required_argument, NULL, 'P'},
                                           {"outbound", required_argument, NULL, 'o'},

                                           {"sslrootcapath", required_argument, NULL, 'S'},
                                           {"transport", required_argument, NULL, 't'},
                                           {"port", required_argument, NULL, 'p'},
                                           {"contact", required_argument, NULL, 'c'},
                                           {"expiry", required_argument, NULL, 'e'},
                                           {"automasquerade", no_argument, NULL, 'm'},
                                           {"syslogandconsole", no_argument, NULL, 's'},
                                           {"verbose", required_argument, NULL, 'v'},

                                           {"help", no_argument, NULL, 'h'},

                                           {NULL, 0, NULL, 0}};

    c = getopt_long(argc, argv, short_options, long_options, &option_index);
#else
    c = getopt(argc, argv, short_options);
#endif

    if (c == -1) {
      break;
    }

    switch (c) {
    case 'c':
      contact = optarg;
      break;

    case 'd':
      fork = 1;
      break;

    case 'v':
      debug = atoi(optarg);
      break;

    case 's':
#ifdef LOG_PERROR
      log_perror = LOG_PERROR;
#endif
      break;

    case 'e':
      regparam.expiry = atoi(optarg);
      break;

    case 'm':
      automasquerade = 1;
      break;

    case 'h':
      usage();
      exit(0);

    case 'p':
      service = getservbyname(optarg, "udp");

      if (service) {
        port = ntohs(service->s_port);

      } else {
        port = atoi(optarg);
      }

      break;

    case 't':
      snprintf(transport, sizeof(transport), "%s", optarg);
      break;

    case 'r':
      proxy = optarg;
      break;

    case 'u':
      fromuser = optarg;
      break;

    case 'U':
      username = optarg;
      break;

    case 'P':
      password = optarg;
      break;

    case 'o':
      outbound = optarg;
      break;

    case 'S':
      snprintf(sslrootcapath, sizeof(sslrootcapath), "%s", optarg);
      break;

    default:
      break;
    }
  }

#ifdef LOG_PERROR
  openlog(PROG_NAME, LOG_PID | log_perror, SYSLOG_FACILITY);
#endif

  syslog_wrapper(LOG_INFO, "%s up and running [testing on [%s] REGISTER [%s] From: [%s]%s%s%s %s%s%s", prog_name, transport, proxy, fromuser, (username && password) ? " Username: [" : "", (username && password) ? username : "",
                 (username && password) ? ":*****]" : "", outbound? "Route: [" : "", outbound? outbound : "", outbound ? "]" : "");

  if (!proxy || !fromuser || strlen(proxy) < 7 || strlen(fromuser) < 7) {
    syslog_wrapper(LOG_ERR, "REGISTRATION REPORT:[FAILURE] [%s][duration:0,000s] missing or broken mandatory parameter", transport);
    usage();
    exit(1);
  }

  if (osip_strcasecmp(transport, "UDP") != 0 && osip_strcasecmp(transport, "TCP") != 0 && osip_strcasecmp(transport, "TLS") != 0 && osip_strcasecmp(transport, "DTLS") != 0) {
    syslog_wrapper(LOG_ERR, "REGISTRATION REPORT:[FAILURE] [%s][duration:0,000s] wrong transport parameter", transport);
    usage();
    exit(1);
  }

  if (fork) {
    err = daemon(1, 0);
    if (err < 0) {
      syslog_wrapper(LOG_ERR, "REGISTRATION REPORT:[FAILURE] [%s][duration:0,000s] daemon mode failed", transport);
      exit(1);
    }
  }

  osip_list_init(&monitored_logs);
  osip_trace_initialize_func(TRACE_LEVEL6, __osip_trace_func);

  context_eXosip = eXosip_malloc();
  err = eXosip_init(context_eXosip);

  if (err) {
    syslog_wrapper(LOG_ERR, "REGISTRATION REPORT:[FAILURE] [%s][duration:0,000s] eXosip_init failure [%i]", transport, err);
    dump_logs();
    exit(1);
  }

  eXosip_set_user_agent(context_eXosip, prog_name);

  if (username && password) {
    err = eXosip_add_authentication_info(context_eXosip, username, username, password, NULL, NULL);

    if (err) {
      syslog_wrapper(LOG_ERR, "REGISTRATION REPORT:[FAILURE] [%s][duration:0,000s] cannot add credential [%i]", transport, err);
      eXosip_quit(context_eXosip);
      osip_free(context_eXosip);
      dump_logs();
      exit(1);
    }
  }

  optval = 1;
  eXosip_set_option(context_eXosip, EXOSIP_OPT_SET_TLS_VERIFY_CERTIFICATE, &optval);

  {
    eXosip_tls_ctx_t tls_description;
    memset(&tls_description, 0, sizeof(eXosip_tls_ctx_t));
    snprintf(tls_description.root_ca_cert, sizeof(tls_description.root_ca_cert), "%s", sslrootcapath);
    eXosip_set_option(context_eXosip, EXOSIP_OPT_SET_TLS_CERTIFICATES_INFO, &tls_description);
  }

  optval = automasquerade;
  eXosip_set_option(context_eXosip, EXOSIP_OPT_AUTO_MASQUERADE_CONTACT, &optval);

  if (automasquerade) {
    syslog_wrapper(LOG_INFO, "automasquerade enabled");
  }

#ifdef TEST_NAPTR
  if (osip_strncasecmp(proxy, "sip:", 4) == 0) {
    _resolv_naptr(proxy + 4);

  } else if (osip_strncasecmp(proxy, "sips:", 4) == 0) {
    _resolv_naptr(proxy + 4);
  }
#endif

  osip_gettimeofday(&time_start, NULL);

  err = -1;

  if (osip_strcasecmp(transport, "UDP") == 0) {
    err = eXosip_listen_addr(context_eXosip, IPPROTO_UDP, NULL, port, AF_INET, 0);

  } else if (osip_strcasecmp(transport, "TCP") == 0) {
    err = eXosip_listen_addr(context_eXosip, IPPROTO_TCP, NULL, port, AF_INET, 0);

  } else if (osip_strcasecmp(transport, "TLS") == 0) {
    err = eXosip_listen_addr(context_eXosip, IPPROTO_TCP, NULL, port, AF_INET, 1);

  } else if (osip_strcasecmp(transport, "DTLS") == 0) {
    err = eXosip_listen_addr(context_eXosip, IPPROTO_UDP, NULL, port, AF_INET, 1);
  }

  if (err) {
    syslog_wrapper(LOG_ERR, "REGISTRATION REPORT:[FAILURE] [%s][duration:0,000s] cannot prepare sip network layer [%i]", transport, err);
    eXosip_quit(context_eXosip);
    osip_free(context_eXosip);
    dump_logs();
    exit(1);
  }

  {
    osip_message_t *reg = NULL;

    if (contact != NULL && regparam.expiry == -1) {
      regparam.expiry = 300;
    }

    eXosip_lock(context_eXosip);
    if (contact == NULL && regparam.expiry == -1) {
      regparam.regid = eXosip_register_build_initial_register(context_eXosip, fromuser, proxy, contact, 0, &reg);

    } else {
      regparam.regid = eXosip_register_build_initial_register(context_eXosip, fromuser, proxy, contact, regparam.expiry, &reg);
    }

    if (regparam.regid < 1) {
      eXosip_unlock(context_eXosip);
      syslog_wrapper(LOG_ERR, "REGISTRATION REPORT:[FAILURE] [%s][duration:0,000s] cannot prepare sip REGISTER [%i]", transport, err);
      eXosip_quit(context_eXosip);
      osip_free(context_eXosip);
      dump_logs();
      exit(1);
    }

    _prepend_route(reg, outbound);
    
    if (contact == NULL && regparam.expiry == -1) {
      int pos = 0;

      while (!osip_list_eol(&reg->contacts, pos)) {
        osip_contact_t *co;

        co = (osip_contact_t *) osip_list_get(&reg->contacts, pos);
        osip_list_remove(&reg->contacts, pos);
        osip_contact_free(co);
      }
    }

    err = eXosip_register_send_register(context_eXosip, regparam.regid, reg);
    eXosip_unlock(context_eXosip);

    if (err != 0) {
      syslog_wrapper(LOG_ERR, "REGISTRATION REPORT:[FAILURE] [%s][duration:0,000s] cannot send sip REGISTER [%i]", transport, err);
      eXosip_quit(context_eXosip);
      osip_free(context_eXosip);
      dump_logs();
      exit(1);
    }
  }

  exit_code = 1;

  for (; keepRunning;) {
    eXosip_event_t *event;

    if (!(event = eXosip_event_wait(context_eXosip, 0, 1))) {
#ifdef OSIP_MONOTHREAD
      eXosip_execute(context_eXosip);
#endif
      eXosip_lock(context_eXosip);
      eXosip_automatic_action(context_eXosip);
      eXosip_unlock(context_eXosip);
      osip_usleep(10000);
      continue;
    }

#ifdef OSIP_MONOTHREAD
    eXosip_execute(context_eXosip);
#endif

    eXosip_lock(context_eXosip);
    eXosip_automatic_action(context_eXosip);

    switch (event->type) {
    case EXOSIP_REGISTRATION_SUCCESS:
      osip_gettimeofday(&time_end, NULL);
      osip_timersub(&time_end, &time_start, &time_sub);

      dump_logs();
      syslog_wrapper(LOG_INFO, "REGISTRATION REPORT:[SUCCESS] [%s][duration:%li,%03lis] REGISTER [%i][%s]", transport, time_sub.tv_sec, time_sub.tv_usec / 1000, event->response->status_code, event->response->reason_phrase);
      keepRunning = 0;
      exit_code = 0;
      break;

    case EXOSIP_REGISTRATION_FAILURE:
      osip_gettimeofday(&time_end, NULL);
      osip_timersub(&time_end, &time_start, &time_sub);

      dump_logs();

      if (event->response == NULL) {
        syslog_wrapper(LOG_INFO, "REGISTRATION REPORT:[FAILURE] [%s][duration:%li,%03lis] REGISTER [408][       ] err=%s", transport, time_sub.tv_sec, time_sub.tv_usec / 1000, error_reason[0] == '\0' ? "no answer" : error_reason);
        keepRunning = 0;

      } else {
        if (event->response->status_code == 401 || event->response->status_code == 407) {
          osip_authorization_t *auth = NULL;
          err = osip_message_get_authorization(event->request, 0, &auth);

          if (err < 0) {
            keepRunning--;

            if (keepRunning == 0) {
              syslog_wrapper(LOG_INFO, "REGISTRATION REPORT:[FAILURE] [%s][duration:%li,%03lis] REGISTER [%i][%s] err=no password or unsupported algorithm", transport, time_sub.tv_sec, time_sub.tv_usec / 1000, event->response->status_code,
                             event->response->reason_phrase);

            } else {
              syslog_wrapper(LOG_INFO, "[%s][duration:%li,%03lis] REGISTER [%i][%s]", transport, time_sub.tv_sec, time_sub.tv_usec / 1000, event->response->status_code, event->response->reason_phrase);
            }

          } else {
            syslog_wrapper(LOG_INFO, "REGISTRATION REPORT:[FAILURE] [%s][duration:%li,%03lis] REGISTER [%i][%s] - err=bad password", transport, time_sub.tv_sec, time_sub.tv_usec / 1000, event->response->status_code, event->response->reason_phrase);
            keepRunning = 0; /* most probably a bad password */
          }

        } else {
          syslog_wrapper(LOG_INFO, "REGISTRATION REPORT:[FAILURE] [%s][duration:%li,%03lis] REGISTER [%i][%s] err=%s", transport, time_sub.tv_sec, time_sub.tv_usec / 1000, event->response->status_code, event->response->reason_phrase,
                         event->response->reason_phrase);
          keepRunning = 0;
        }
      }

      break;

    case EXOSIP_CALL_INVITE: {
      osip_message_t *answer;
      int i;

      i = eXosip_call_build_answer(context_eXosip, event->tid, 405, &answer);

      if (i != 0) {
        syslog_wrapper(LOG_ERR, "failed to reject INVITE");
        break;
      }

      osip_free(answer->reason_phrase);
      answer->reason_phrase = osip_strdup("No Support for Incoming Calls");
      i = eXosip_call_send_answer(context_eXosip, event->tid, 405, answer);

      if (i != 0) {
        syslog_wrapper(LOG_ERR, "failed to reject INVITE");
        break;
      }

      syslog_wrapper(LOG_INFO, "INVITE rejected with 405");
      break;
    }

    case EXOSIP_MESSAGE_NEW: {
      osip_message_t *answer;
      int i;

      i = eXosip_message_build_answer(context_eXosip, event->tid, 405, &answer);

      if (i != 0) {
        syslog_wrapper(LOG_ERR, "failed to reject %s", event->request->sip_method);
        break;
      }

      i = eXosip_message_send_answer(context_eXosip, event->tid, 405, answer);

      if (i != 0) {
        syslog_wrapper(LOG_ERR, "failed to reject %s", event->request->sip_method);
        break;
      }

      syslog_wrapper(LOG_INFO, "%s rejected with 405", event->request->sip_method);
      break;
    }

    case EXOSIP_IN_SUBSCRIPTION_NEW: {
      osip_message_t *answer;
      int i;

      i = eXosip_insubscription_build_answer(context_eXosip, event->tid, 405, &answer);

      if (i != 0) {
        syslog_wrapper(LOG_ERR, "failed to reject %s", event->request->sip_method);
        break;
      }

      i = eXosip_insubscription_send_answer(context_eXosip, event->tid, 405, answer);

      if (i != 0) {
        syslog_wrapper(LOG_ERR, "failed to reject %s", event->request->sip_method);
        break;
      }

      syslog_wrapper(LOG_INFO, "%s rejected with 405", event->request->sip_method);
      break;
    }

    case EXOSIP_CALL_CLOSED:
    case EXOSIP_CALL_RELEASED:
      break;

    default:
      syslog_wrapper(LOG_DEBUG, "received unknown eXosip event (type, did, cid) = (%d, %d, %d)", event->type, event->did, event->cid);
    }

    eXosip_unlock(context_eXosip);
    eXosip_event_free(event);
  }

  eXosip_quit(context_eXosip);
  osip_free(context_eXosip);
  dump_logs();
  return exit_code;
}
