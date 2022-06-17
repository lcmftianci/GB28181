/*
 * SIP Registration Agent -- by ww@styx.org
 *
 * This program is Free Software, released under the GNU General
 * Public License v2.0 http://www.gnu.org/licenses/gpl
 *
 * This program will register to a SIP proxy using the contact
 * supplied on the command line. This is useful if, for some
 * reason your SIP client cannot register to the proxy itself.
 * For example, if your SIP client registers to Proxy A, but
 * you want to be able to recieve calls that arrive at Proxy B,
 * you can use this program to register the client's contact
 * information to Proxy B.
 *
 * This program requires the eXosip library. To compile,
 * assuming your eXosip installation is in /usr/local,
 * use something like:
 *
 * gcc -O2 -I/usr/local/include -L/usr/local/lib sipreg.c \
 *         -o sipreg \
 *         -leXosip2 -losip2 -losipparser2 -lpthread
 *
 * It should compile and run on any POSIX compliant system
 * that supports pthreads.
 *
 */

#if !defined(WIN32) && !defined(_WIN32_WCE)
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

#include <osip2/osip_mt.h>
#include <eXosip2/eXosip.h>

#if !defined(WIN32)
#define _GNU_SOURCE
#include <getopt.h>
#endif

#define PROG_NAME "sip_reg"
#define SYSLOG_FACILITY LOG_DAEMON

static volatile int keepRunning = 1;

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
         "  -r --proxy      sip:proxyhost[:port]\n"
         "  -u --from       sip:user@host[:port]\n"
         "\n[optional_options]\n"
         "  -d --debug                                  (log to stderr and do not fork)\n"
         "\n[optional_sip_options]\n"
         "  -U --username   xxxx                        (authentication username)\n"
         "  -P --password   yyyy                        (authentication password)\n"
         "  -t --transport  UDP|TCP|TLS|DTLS            (default UDP)\n"
         "  -e --expiry     number                      (default 3600)\n"
         "\n[very_optional_sip_options]\n"
         "  -p --port       number                      (default 5060)\n"
         "  -c --contact    sip:user@host[:port]        (default automatic)\n"
         "  -f --firewallip N.N.N.N\n"
         "  -m --automasquerade                         (auto discover contact IP:PORT)\n"
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

int main(int argc, char *argv[]) {
  int c;
  int port = 5060;
  char *contact = NULL;
  char *fromuser = NULL;
  int automasquerade = 0;
  const char *firewallip = NULL;
  char *proxy = NULL;
  char transport[5];

  struct servent *service;
  char *username = NULL;
  char *password = NULL;
  struct regparam_t regparam = {0, 3600, 0};
  int debug = 0;
  int nofork = 0;
  int err;

  char prog_name[32];
  int optval;

  snprintf(prog_name, sizeof(prog_name), "%s (%s)", PROG_NAME, eXosip_get_version());

#ifdef SIGPIPE
  signal(SIGPIPE, SIG_IGN);
#endif
#ifdef __linux
  signal(SIGINT, intHandler);
#endif

  snprintf(transport, sizeof(transport), "%s", "UDP");

  for (;;) {
#define short_options "du:r:U:P:t:p:c:e:mf:h"
#ifdef _GNU_SOURCE
    int option_index = 0;

    static struct option long_options[] = {{"debug", no_argument, NULL, 'd'},
                                           {"from", required_argument, NULL, 'u'},
                                           {"proxy", required_argument, NULL, 'r'},
                                           {"username", required_argument, NULL, 'U'},
                                           {"password", required_argument, NULL, 'P'},

                                           {"transport", required_argument, NULL, 't'},
                                           {"port", required_argument, NULL, 'p'},
                                           {"contact", required_argument, NULL, 'c'},
                                           {"expiry", required_argument, NULL, 'e'},
                                           {"automasquerade", no_argument, NULL, 'm'},
                                           {"firewallip", required_argument, NULL, 'f'},

                                           {"help", no_argument, NULL, 'h'},

                                           {NULL, 0, NULL, 0}};

    c = getopt_long(argc, argv, short_options, long_options, &option_index);
#else
    c = getopt(argc, argv, short_options);
#endif

    if (c == -1)
      break;

    switch (c) {
    case 'c':
      contact = optarg;
      break;

    case 'd':
      nofork = 1;
#ifdef LOG_PERROR
      debug = LOG_PERROR;
#endif
      break;

    case 'e':
      regparam.expiry = atoi(optarg);
      break;

    case 'm':
      automasquerade = 1;
      break;

    case 'f':
      firewallip = optarg;
      break;

    case 'h':
      usage();
      exit(0);

    case 'p':
      service = getservbyname(optarg, "udp");

      if (service)
        port = ntohs(service->s_port);

      else
        port = atoi(optarg);

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

    default:
      break;
    }
  }

  if (!proxy || !fromuser) {
    usage();
    exit(1);
  }

  if (!nofork) {
    err = daemon(1, 0);
    if (err < 0) {
      exit(1);
    }
  }

#ifdef LOG_PERROR
  openlog(PROG_NAME, LOG_PID | debug, SYSLOG_FACILITY);
#endif

  syslog_wrapper(LOG_INFO, "%s up and running [testing on [%s] REGISTER [%s] Expires [%d] From: [%s]%s%s%s]", prog_name, transport, proxy, regparam.expiry, fromuser, (username && password) ? " Username: [" : "",
                 (username && password) ? username : "", (username && password) ? ":*****]" : "");

  if (contact != NULL)
    syslog_wrapper(LOG_INFO, "contact: %s", contact);

  syslog_wrapper(LOG_INFO, "local port: %d", port);

  if (osip_strcasecmp(transport, "UDP") != 0 && osip_strcasecmp(transport, "TCP") != 0 && osip_strcasecmp(transport, "TLS") != 0 && osip_strcasecmp(transport, "DTLS") != 0) {
    syslog_wrapper(LOG_ERR, "wrong transport parameter");
    usage();
    exit(1);
  }

  if (debug > 0)
    TRACE_INITIALIZE(6, NULL);

  context_eXosip = eXosip_malloc();

  if (eXosip_init(context_eXosip)) {
    syslog_wrapper(LOG_ERR, "eXosip_init failed");
    exit(1);
  }

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
    syslog_wrapper(LOG_ERR, "eXosip_listen_addr failed");
    eXosip_quit(context_eXosip);
    osip_free(context_eXosip);
    exit(1);
  }

  if (firewallip) {
    syslog_wrapper(LOG_INFO, "firewall address: %s:%i", firewallip, port);
    eXosip_masquerade_contact(context_eXosip, firewallip, port);
  }

  optval = automasquerade;
  eXosip_set_option(context_eXosip, EXOSIP_OPT_AUTO_MASQUERADE_CONTACT, &optval);

  if (automasquerade) {
    syslog_wrapper(LOG_INFO, "automasquerade enabled");
  }

  eXosip_set_user_agent(context_eXosip, prog_name);

  if (username && password) {
    if (eXosip_add_authentication_info(context_eXosip, username, username, password, NULL, NULL)) {
      syslog_wrapper(LOG_ERR, "eXosip_add_authentication_info failed");
      eXosip_quit(context_eXosip);
      osip_free(context_eXosip);
      exit(1);
    }
  }

  {
    osip_message_t *reg = NULL;
    int i;

    eXosip_lock(context_eXosip);
    regparam.regid = eXosip_register_build_initial_register(context_eXosip, fromuser, proxy, contact, regparam.expiry * 2, &reg);

    if (regparam.regid < 1) {
      eXosip_unlock(context_eXosip);
      syslog_wrapper(LOG_ERR, "eXosip_register_build_initial_register failed");
      eXosip_quit(context_eXosip);
      osip_free(context_eXosip);
      exit(1);
    }

    i = eXosip_register_send_register(context_eXosip, regparam.regid, reg);
    eXosip_unlock(context_eXosip);

    if (i != 0) {
      syslog_wrapper(LOG_ERR, "eXosip_register_send_register failed");
      eXosip_quit(context_eXosip);
      osip_free(context_eXosip);
      exit(1);
    }
  }

  for (; keepRunning;) {
    static int counter = 0;
    eXosip_event_t *event;

    counter++;

    if (counter % 60000 == 0) {
      struct eXosip_stats stats;

      memset(&stats, 0, sizeof(struct eXosip_stats));
      eXosip_lock(context_eXosip);
      eXosip_set_option(context_eXosip, EXOSIP_OPT_GET_STATISTICS, &stats);
      eXosip_unlock(context_eXosip);
      syslog_wrapper(LOG_INFO, "eXosip stats: inmemory=(tr:%i//reg:%i) average=(tr:%f//reg:%f)", stats.allocated_transactions, stats.allocated_registrations, stats.average_transactions, stats.average_registrations);
    }

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
      syslog_wrapper(LOG_INFO, "registrered successfully");
      break;

    case EXOSIP_REGISTRATION_FAILURE:
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
  return 0;
}
