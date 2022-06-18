/*
  eXosip - This is the eXtended osip library.
  Copyright (C) 2001-2020 Aymeric MOIZARD amoizard@antisip.com

  eXosip is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  eXosip is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  In addition, as a special exception, the copyright holders give
  permission to link the code of portions of this program with the
  OpenSSL library under certain conditions as described in each
  individual source file, and distribute linked combinations
  including the two.
  You must obey the GNU General Public License in all respects
  for all of the code used other than OpenSSL.  If you modify
  file(s) with this exception, you may extend this exception to your
  version of the file(s), but you are not obligated to do so.  If you
  do not wish to do so, delete this exception statement from your
  version.  If you delete this exception statement from all source
  files in the program, then also delete it here.
*/

#include "eXosip2.h"

#if defined(HAVE_STDARG_H)
#include <stdarg.h>
#define VA_START(a, f) va_start(a, f)
#else
#if defined(HAVE_VARARGS_H)
#include <varargs.h>
#define VA_START(a, f) va_start(a)
#else
#include <stdarg.h>
#define VA_START(a, f) va_start(a, f)
#endif
#endif

#include <osipparser2/osip_port.h>

#if defined(HAVE_WINDNS_H)
#include <malloc.h>
#include <windns.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif

#ifdef HAVE_NAMESER8_COMPAT_H
#include <nameser8_compat.h>
#include <resolv8_compat.h>
#elif defined(HAVE_RESOLV_H) || defined(OpenBSD) || defined(FreeBSD) || defined(NetBSD)
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#include <resolv.h>
#endif

#include <ctype.h>

#ifdef HAVE_REGEX_H
#include <regex.h>
#elif defined(HAVE_PCRE2POSIX_H)
#define PCRE2_STATIC 1
#include "pcre2posix.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

int _eXosip_closesocket(SOCKET_TYPE sock) {
#if !defined(HAVE_WINSOCK2_H)
  return close(sock);
#else
  return closesocket(sock);
#endif
}

#if defined(WIN32) || defined(_WIN32_WCE)

char *_ex_strerror(int errnum, char *buf, size_t buflen) {
  switch (errnum) {
  case WSAEINTR:
    snprintf(buf, buflen, "[%d:Interrupted system call]", errnum);
    break;

  case WSAEBADF:
    snprintf(buf, buflen, "[%d:Bad file number]", errnum);
    break;

  case WSAEACCES:
    snprintf(buf, buflen, "[%d:Permission denied]", errnum);
    break;

  case WSAEFAULT:
    snprintf(buf, buflen, "[%d:Bad address]", errnum);
    break;

  case WSAEINVAL:
    snprintf(buf, buflen, "[%d:Invalid argument]", errnum);
    break;

  case WSAEMFILE:
    snprintf(buf, buflen, "[%d:Too many open sockets]", errnum);
    break;

  case WSAEWOULDBLOCK:
    snprintf(buf, buflen, "[%d:Operation would block]", errnum);
    break;

  case WSAEINPROGRESS:
    snprintf(buf, buflen, "[%d:Operation now in progress]", errnum);
    break;

  case WSAEALREADY:
    snprintf(buf, buflen, "[%d:Operation already in progress]", errnum);
    break;

  case WSAENOTSOCK:
    snprintf(buf, buflen, "[%d:Socket operation on non-socket]", errnum);
    break;

  case WSAEDESTADDRREQ:
    snprintf(buf, buflen, "[%d:Destination address required]", errnum);
    break;

  case WSAEMSGSIZE:
    snprintf(buf, buflen, "[%d:Message too long]", errnum);
    break;

  case WSAEPROTOTYPE:
    snprintf(buf, buflen, "[%d:Protocol wrong type for socket]", errnum);
    break;

  case WSAENOPROTOOPT:
    snprintf(buf, buflen, "[%d:Bad protocol option]", errnum);
    break;

  case WSAEPROTONOSUPPORT:
    snprintf(buf, buflen, "[%d:Protocol not supported]", errnum);
    break;

  case WSAESOCKTNOSUPPORT:
    snprintf(buf, buflen, "[%d:Socket type not supported]", errnum);
    break;

  case WSAEOPNOTSUPP:
    snprintf(buf, buflen, "[%d:Operation not supported on socket]", errnum);
    break;

  case WSAEPFNOSUPPORT:
    snprintf(buf, buflen, "[%d:Protocol family not supported]", errnum);
    break;

  case WSAEAFNOSUPPORT:
    snprintf(buf, buflen, "[%d:Address family not supported]", errnum);
    break;

  case WSAEADDRINUSE:
    snprintf(buf, buflen, "[%d:Address already in use]", errnum);
    break;

  case WSAEADDRNOTAVAIL:
    snprintf(buf, buflen, "[%d:Can't assign requested address]", errnum);
    break;

  case WSAENETDOWN:
    snprintf(buf, buflen, "[%d:Network is down]", errnum);
    break;

  case WSAENETUNREACH:
    snprintf(buf, buflen, "[%d:Network is unreachable]", errnum);
    break;

  case WSAENETRESET:
    snprintf(buf, buflen, "[%d:Net connection reset]", errnum);
    break;

  case WSAECONNABORTED:
    snprintf(buf, buflen, "[%d:Software caused connection abort]", errnum);
    break;

  case WSAECONNRESET:
    snprintf(buf, buflen, "[%d:Connection reset by peer]", errnum);
    break;

  case WSAENOBUFS:
    snprintf(buf, buflen, "[%d:No buffer space available]", errnum);
    break;

  case WSAEISCONN:
    snprintf(buf, buflen, "[%d:Socket is already connected]", errnum);
    break;

  case WSAENOTCONN:
    snprintf(buf, buflen, "[%d:Socket is not connected]", errnum);
    break;

  case WSAESHUTDOWN:
    snprintf(buf, buflen, "[%d:Can't send after socket shutdown]", errnum);
    break;

  case WSAETOOMANYREFS:
    snprintf(buf, buflen, "[%d:Too many references: can't splice]", errnum);
    break;

  case WSAETIMEDOUT:
    snprintf(buf, buflen, "[%d:Connection timed out]", errnum);
    break;

  case WSAECONNREFUSED:
    snprintf(buf, buflen, "[%d:Connection refused]", errnum);
    break;

  case WSAELOOP:
    snprintf(buf, buflen, "[%d:Too many levels of symbolic links]", errnum);
    break;

  case WSAENAMETOOLONG:
    snprintf(buf, buflen, "[%d:File name too long]", errnum);
    break;

  case WSAEHOSTDOWN:
    snprintf(buf, buflen, "[%d:Host is down]", errnum);
    break;

  case WSAEHOSTUNREACH:
    snprintf(buf, buflen, "[%d:No route to host]", errnum);
    break;

  case WSAENOTEMPTY:
    snprintf(buf, buflen, "[%d:Directory not empty]", errnum);
    break;

  case WSAEPROCLIM:
    snprintf(buf, buflen, "[%d:Too many processes]", errnum);
    break;

  case WSAEUSERS:
    snprintf(buf, buflen, "[%d:Too many users]", errnum);
    break;

  case WSAEDQUOT:
    snprintf(buf, buflen, "[%d:Disc quota exceeded]", errnum);
    break;

  case WSAESTALE:
    snprintf(buf, buflen, "[%d:Stale NFS file handle]", errnum);
    break;

  case WSAEREMOTE:
    snprintf(buf, buflen, "[%d:Too many levels of remote in path]", errnum);
    break;

  case WSASYSNOTREADY:
    snprintf(buf, buflen, "[%d:Network system is unavailable]", errnum);
    break;

  case WSAVERNOTSUPPORTED:
    snprintf(buf, buflen, "[%d:Winsock version out of range]", errnum);
    break;

  case WSANOTINITIALISED:
    snprintf(buf, buflen, "[%d:WSAStartup not yet called]", errnum);
    break;

  case WSAEDISCON:
    snprintf(buf, buflen, "[%d:Graceful shutdown in progress]", errnum);
    break;

  default:
    snprintf(buf, buflen, "[%d:unknown error]", errnum);
    break;
  }
  return buf;
}

#elif (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600 || __APPLE__ || defined(ANDROID)) && !_GNU_SOURCE

char *_ex_strerror(int errnum, char *buf, size_t buflen) {
  int in = snprintf(buf, buflen, "[%d:", errnum);
  int err = strerror_r(errnum, buf + in, buflen - in);
  if (err) {
    snprintf(buf, buflen, "[%d:invalid error]", errnum);
    return buf;
  }
  if (buflen - strlen(buf) > 1)
    snprintf(buf + strlen(buf), buflen - strlen(buf), "]");
  return buf;
}

#else

char *_ex_strerror(int errnum, char *buf, size_t buflen) {
  int in = snprintf(buf, buflen, "[%d:", errnum);
  /* fix: GNU strerror_r may return a static buffer instead of writing into buf */
  char *tmp = strerror_r(errnum, buf + in, buflen - in);
  if (tmp != buf) {
    strncat(buf + strlen(buf), tmp, buflen - strlen(buf) - 1);
  }
  if (buflen - strlen(buf) > 1)
    snprintf(buf + strlen(buf), buflen - strlen(buf), "]");
  return buf;
}


#endif

#if defined(WIN32) || defined(_WIN32_WCE)

char *_ex_gai_strerror(int errnum, char *buf, size_t buflen) {
  snprintf(buf, buflen, "[%d:%s]", errnum, gai_strerrorA(errnum));
  return buf;
}

#elif (_POSIX_C_SOURCE >= 1 || _XOPEN_SOURCE || _POSIX_SOURCE)

char *_ex_gai_strerror(int errnum, char *buf, size_t buflen) {
  snprintf(buf, buflen, "[%d:%s]", errnum, gai_strerror(errnum));
  return buf;
}

#else

char *_ex_gai_strerror(int errnum, char *buf, size_t buflen) {
  snprintf(buf, buflen, "[%d:--]", errnum);
  return buf;
}
#endif

static int naptr_enum_match_and_replace(osip_naptr_t *output_record, osip_srv_record_t *srvrecord) {
  char re_regexp[1024];

  /* srvrecord.regexp contains 3 parts : delimit ere delimit substitution delimit flag */
  char *re_delim = NULL;
  char *re_delim2 = NULL;
  char *re_delim3 = NULL;
  char *tmp_ptr;
  char *dest_ptr;

  memset(srvrecord->name, 0, sizeof(srvrecord->name));

  memset(re_regexp, 0, sizeof(re_regexp));
  memcpy(re_regexp, srvrecord->regexp, sizeof(re_regexp));

  re_delim = re_regexp;
  re_delim++;
  re_delim2 = strchr(re_delim, re_regexp[0]);

  if (re_delim2 == NULL)
    return -1;

  re_delim2[0] = '\0';
  re_delim2++;
  re_delim3 = strchr(re_delim2, re_regexp[0]);

  if (re_delim3 == NULL)
    return -1;

  re_delim3[0] = '\0';
  re_delim3++;

#if defined(HAVE_REGEX_H) || defined(HAVE_PCRE2POSIX_H)
  {
    regex_t regex;
    regmatch_t pmatch[10];
    int result;
    size_t nmatch;

    result = regcomp(&regex, re_delim, REG_EXTENDED);

    if (result) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR ENUM] [%s] -> regex compilation failure [%s]\n", output_record->domain, srvrecord->regexp));
      return -1;
    }

    nmatch = regex.re_nsub + 1;

    if (nmatch > 9) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR ENUM] [%s] -> regex too much match [%s]\n", output_record->domain, srvrecord->regexp));
      return -1;
    }

    memset(&pmatch, 0, sizeof(pmatch));
    result = regexec(&regex, output_record->AUS, nmatch, pmatch, 0);

    if (result) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR ENUM] [%s] -> regex no match [%s|aus=%s]\n", output_record->domain, srvrecord->regexp, output_record->AUS));
      return -1;
    }

    regfree(&regex);

    tmp_ptr = re_delim2;
    dest_ptr = srvrecord->name;

    while (tmp_ptr[0] != '\0') {
      if (tmp_ptr[0] == '\\' && isdigit(tmp_ptr[1])) {
        size_t idx = (tmp_ptr[1] - '0');

        if (idx >= nmatch) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR ENUM] [%s] -> regex wrong back reference index [%s|AUS=%s|%i:%i]\n", output_record->domain, srvrecord->regexp, output_record->AUS, idx, nmatch));
          return -1;
        }

        strncpy(dest_ptr, output_record->AUS + pmatch[idx].rm_so, pmatch[idx].rm_eo - pmatch[idx].rm_so);
        dest_ptr += pmatch[idx].rm_eo - pmatch[idx].rm_so;
        tmp_ptr++;
        tmp_ptr++;

      } else {
        dest_ptr[0] = tmp_ptr[0];
        dest_ptr++;
        tmp_ptr++;
      }
    }
  }
#else
  {
    char *backref = strchr(re_delim2, '\\');

    while (backref != NULL) {
      if (isdigit(backref[1]))
        break;

      backref = strchr(backref + 1, '\\');
    }

    if (re_delim[0] == '(' || (re_delim[0] == '^' && re_delim[1] == '(')) {
      size_t len = strlen(re_delim);

      if (len > 2) {
        if (re_delim[len - 1] == ')' || (re_delim[len - 2] == ')' && re_delim[len - 1] == '$')) {
          /* just replace \1 with AUS */

          tmp_ptr = re_delim2;
          dest_ptr = srvrecord->name;

          while (tmp_ptr[0] != '\0') {
            if (tmp_ptr[0] == '\\' && isdigit(tmp_ptr[1])) {
              size_t idx = (tmp_ptr[1] - '0');

              if (idx >= 2) {
                OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR ENUM] [%s] -> regex wrong back reference index [%s|AUS=%s|%i]\n", output_record->domain, srvrecord->regexp, output_record->AUS, idx));
                return -1;
              }

              snprintf(dest_ptr, sizeof(output_record->AUS), "%s", output_record->AUS);
              dest_ptr += strlen(output_record->AUS);
              tmp_ptr++;
              tmp_ptr++;

            } else {
              dest_ptr[0] = tmp_ptr[0];
              dest_ptr++;
              tmp_ptr++;
            }
          }
        }
      }

    } else if (backref == NULL) {
      /* no back reference to replace */
      snprintf(srvrecord->name, sizeof(srvrecord->name), "%s", re_delim2);
    }
  }
#endif
  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR ENUM] [%s] -> regex done [%s]\n", output_record->domain, srvrecord->name));
  return 0;
}

#if defined(USE_GETHOSTBYNAME)

void _eXosip_freeaddrinfo(struct addrinfo *ai) {
  struct addrinfo *next;

  while (ai) {
    next = ai->ai_next;
    free(ai);
    ai = next;
  }
}

struct namebuf {
  struct hostent hostentry;
  char *h_addr_list[2];
  struct in_addr addrentry;
  char h_name[16]; /* 123.123.123.123 = 15 letters is maximum */
};

static struct addrinfo *osip_he2ai(struct hostent *he, int port, int protocol) {
  struct addrinfo *ai;

  struct addrinfo *prevai = NULL;

  struct addrinfo *firstai = NULL;

  struct sockaddr_in *addr;

  int i;

  struct in_addr *curr;

  if (!he) /* no input == no output! */
    return NULL;

  for (i = 0; (curr = (struct in_addr *) he->h_addr_list[i]); i++) {
    ai = calloc(1, sizeof(struct addrinfo) + sizeof(struct sockaddr_in));

    if (!ai)
      break;

    if (!firstai) /* store the pointer we want to return from this function */
      firstai = ai;

    if (prevai) /* make the previous entry point to this */
      prevai->ai_next = ai;

    ai->ai_family = AF_INET; /* we only support this */

    if (protocol == IPPROTO_UDP)
      ai->ai_socktype = SOCK_DGRAM;

    else
      ai->ai_socktype = SOCK_STREAM;

    ai->ai_addrlen = sizeof(struct sockaddr_in);
    /* make the ai_addr point to the address immediately following this struct
       and use that area to store the address */
    ai->ai_addr = (struct sockaddr *) ((char *) ai + sizeof(struct addrinfo));

    /* leave the rest of the struct filled with zero */

    addr = (struct sockaddr_in *) ai->ai_addr; /* storage area for this info */

    memcpy((char *) &(addr->sin_addr), curr, sizeof(struct in_addr));
    addr->sin_family = he->h_addrtype;
    addr->sin_port = htons((unsigned short) port);

    prevai = ai;
  }

  return firstai;
}

/*
 * osip_ip2addr() takes a 32bit ipv4 internet address as input parameter
 * together with a pointer to the string version of the address, and it
 * returns a struct addrinfo chain filled in correctly with information for this
 * address/host.
 *
 * The input parameters ARE NOT checked for validity but they are expected
 * to have been checked already when this is called.
 */
static struct addrinfo *osip_ip2addr(in_addr_t num, const char *hostname, int port, int protocol) {
  struct addrinfo *ai;
  struct hostent *h;
  struct in_addr *addrentry;
  struct namebuf buffer;
  struct namebuf *buf = &buffer;

  h = &buf->hostentry;
  h->h_addr_list = &buf->h_addr_list[0];
  addrentry = &buf->addrentry;
  addrentry->s_addr = num;
  h->h_addr_list[0] = (char *) addrentry;
  h->h_addr_list[1] = NULL;
  h->h_addrtype = AF_INET;
  h->h_length = sizeof(*addrentry);
  h->h_name = &buf->h_name[0];
  h->h_aliases = NULL;

  /* Now store the dotted version of the address */
  snprintf((char *) h->h_name, 16, "%s", hostname);

  ai = osip_he2ai(h, port, protocol);
  return ai;
}

static int eXosip_inet_pton(int family, const char *src, void *dst) {
  if (strchr(src, ':'))          /* possible IPv6 address */
    return OSIP_UNDEFINED_ERROR; /* (inet_pton(AF_INET6, src, dst)); */
  else if (strchr(src, '.')) {   /* possible IPv4 address */
    struct in_addr *tmp = dst;

    tmp->s_addr = inet_addr(src); /* already in N. byte order */

    if (tmp->s_addr == INADDR_NONE)
      return 0;

    return 1; /* (inet_pton(AF_INET, src, dst)); */

  } else /* Impossibly a valid ip address */
    return INADDR_NONE;
}

/*
 * osip_getaddrinfo() - the ipv4 synchronous version.
 *
 * The original code to this function was from the Dancer source code, written
 * by Bjorn Reese, it has since been patched and modified considerably.
 *
 * gethostbyname_r() is the thread-safe version of the gethostbyname()
 * function. When we build for plain IPv4, we attempt to use this
 * function. There are _three_ different gethostbyname_r() versions, and we
 * detect which one this platform supports in the configure script and set up
 * the HAVE_GETHOSTBYNAME_R_3, HAVE_GETHOSTBYNAME_R_5 or
 * HAVE_GETHOSTBYNAME_R_6 defines accordingly. Note that HAVE_GETADDRBYNAME
 * has the corresponding rules. This is primarily on *nix. Note that some unix
 * flavours have thread-safe versions of the plain gethostbyname() etc.
 *
 */
int _eXosip_get_addrinfo(struct eXosip_t *excontext, struct addrinfo **addrinfo, const char *hostname, int port, int protocol) {
  struct hostent *h = NULL;

  in_addr_t in;

  struct hostent *buf = NULL;

  *addrinfo = NULL; /* default return */

  if (port < 0) /* -1 for SRV record */
    return OSIP_BADPARAMETER;

  if (1 == eXosip_inet_pton(AF_INET, hostname, &in))
  /* This is a dotted IP address 123.123.123.123-style */
  {
    *addrinfo = osip_ip2addr(in, hostname, port, protocol);
    return OSIP_SUCCESS;
  }
#if defined(HAVE_GETHOSTBYNAME_R)
  /*
   * gethostbyname_r() is the preferred resolve function for many platforms.
   * Since there are three different versions of it, the following code is
   * somewhat #ifdef-ridden.
   */
  else {
    int h_errnop;

    int res = ERANGE;

    buf = (struct hostent *) calloc(CURL_HOSTENT_SIZE, 1);

    if (!buf)
      return NULL; /* major failure */

      /*
       * The clearing of the buffer is a workaround for a gethostbyname_r bug in
       * qnx nto and it is also _required_ for some of these functions on some
       * platforms.
       */

#ifdef HAVE_GETHOSTBYNAME_R_5
    /* Solaris, IRIX and more */
    (void) res; /* prevent compiler warning */
    h = gethostbyname_r(hostname, (struct hostent *) buf, (char *) buf + sizeof(struct hostent), CURL_HOSTENT_SIZE - sizeof(struct hostent), &h_errnop);

    /* If the buffer is too small, it returns NULL and sets errno to
     * ERANGE. The errno is thread safe if this is compiled with
     * -D_REENTRANT as then the 'errno' variable is a macro defined to get
     * used properly for threads.
     */

    if (h) {
      ;

    } else
#endif /* HAVE_GETHOSTBYNAME_R_5 */
#ifdef HAVE_GETHOSTBYNAME_R_6
      /* Linux */

      res = gethostbyname_r(hostname, (struct hostent *) buf, (char *) buf + sizeof(struct hostent), CURL_HOSTENT_SIZE - sizeof(struct hostent), &h, /* DIFFERENCE */
                            &h_errnop);

    /* Redhat 8, using glibc 2.2.93 changed the behavior. Now all of a
     * sudden this function returns EAGAIN if the given buffer size is too
     * small. Previous versions are known to return ERANGE for the same
     * problem.
     *
     * This wouldn't be such a big problem if older versions wouldn't
     * sometimes return EAGAIN on a common failure case. Alas, we can't
     * assume that EAGAIN *or* ERANGE means ERANGE for any given version of
     * glibc.
     *
     * For now, we do that and thus we may call the function repeatedly and
     * fail for older glibc versions that return EAGAIN, until we run out of
     * buffer size (step_size grows beyond CURL_HOSTENT_SIZE).
     *
     * If anyone has a better fix, please tell us!
     *
     * -------------------------------------------------------------------
     *
     * On October 23rd 2003, Dan C dug up more details on the mysteries of
     * gethostbyname_r() in glibc:
     *
     * In glibc 2.2.5 the interface is different (this has also been
     * discovered in glibc 2.1.1-6 as shipped by Redhat 6). What I can't
     * explain, is that tests performed on glibc 2.2.4-34 and 2.2.4-32
     * (shipped/upgraded by Redhat 7.2) don't show this behavior!
     *
     * In this "buggy" version, the return code is -1 on error and 'errno'
     * is set to the ERANGE or EAGAIN code. Note that 'errno' is not a
     * thread-safe variable.
     */

    if (!h) /* failure */
#endif      /* HAVE_GETHOSTBYNAME_R_6 */
#ifdef HAVE_GETHOSTBYNAME_R_3

      /* AIX, Digital Unix/Tru64, HPUX 10, more? */

      /* For AIX 4.3 or later, we don't use gethostbyname_r() at all, because of
       * the plain fact that it does not return unique full buffers on each
       * call, but instead several of the pointers in the hostent structs will
       * point to the same actual data! This have the unfortunate down-side that
       * our caching system breaks down horribly. Luckily for us though, AIX 4.3
       * and more recent versions have a "completely thread-safe"[*] libc where
       * all the data is stored in thread-specific memory areas making calls to
       * the plain old gethostbyname() work fine even for multi-threaded
       * programs.
       *
       * This AIX 4.3 or later detection is all made in the configure script.
       *
       * Troels Walsted Hansen helped us work this out on March 3rd, 2003.
       *
       * [*] = much later we've found out that it isn't at all "completely
       * thread-safe", but at least the gethostbyname() function is.
       */

      if (CURL_HOSTENT_SIZE >= (sizeof(struct hostent) + sizeof(struct hostent_data))) {
        /* August 22nd, 2000: Albert Chin-A-Young brought an updated version
         * that should work! September 20: Richard Prescott worked on the buffer
         * size dilemma.
         */

        res = gethostbyname_r(hostname, (struct hostent *) buf, (struct hostent_data *) ((char *) buf + sizeof(struct hostent)));
        h_errnop = errno; /* we don't deal with this, but set it anyway */

      } else
        res = -1; /* failure, too smallish buffer size */

    if (!res) { /* success */

      h = buf; /* result expected in h */

      /* This is the worst kind of the different gethostbyname_r() interfaces.
       * Since we don't know how big buffer this particular lookup required,
       * we can't realloc down the huge alloc without doing closer analysis of
       * the returned data. Thus, we always use CURL_HOSTENT_SIZE for every
       * name lookup. Fixing this would require an extra malloc() and then
       * calling struct addrinfo_copy() that subsequent realloc()s down the new
       * memory area to the actually used amount.
       */

    } else
#endif /* HAVE_GETHOSTBYNAME_R_3 */
    {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [getaddrinfo] gethostbyname failure [%s][%d]\n", hostname, port));
      h = NULL; /* set return code to NULL */
      free(buf);
    }

#else /* HAVE_GETHOSTBYNAME_R */
  /*
   * Here is code for platforms that don't have gethostbyname_r() or for
   * which the gethostbyname() is the preferred() function.
   */
  else {
    h = NULL;
#if !defined(__arc__)
    h = gethostbyname(hostname);
#endif

    if (!h) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [getaddrinfo] gethostbyname failure [%s][%d]\n", hostname, port));
    }

#endif /*HAVE_GETHOSTBYNAME_R */
  }

  if (h) {
    *addrinfo = osip_he2ai(h, port, protocol);

    if (buf) /* used a *_r() function */
      free(buf);
  }

  return OSIP_SUCCESS;
}

#endif

int _eXosip_getport(const struct sockaddr *sa) {
  if (sa->sa_family == AF_INET)
    return ntohs(((struct sockaddr_in *) sa)->sin_port);

  return ntohs(((struct sockaddr_in6 *) sa)->sin6_port);
}

#if defined(__arc__)

int _eXosip_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags) {
  struct sockaddr_in *fromsa = (struct sockaddr_in *) sa;
  char *tmp;

  tmp = inet_ntoa(fromsa->sin_addr);

  if (tmp == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [getnameinfo] failure [?]\n"));
    snprintf(host, hostlen, "127.0.0.1");
    return OSIP_UNDEFINED_ERROR;
  }

  snprintf(host, hostlen, "%s", tmp);
  return OSIP_SUCCESS;
}

#else
int _eXosip_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags) {
  int err;

  err = getnameinfo((struct sockaddr *) sa, salen, host, hostlen, serv, servlen, flags);

  if (err != 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [getnameinfo] failure [%i]\n", err));
    snprintf(host, hostlen, "127.0.0.1");
    return OSIP_UNDEFINED_ERROR;
  }

  return OSIP_SUCCESS;
}
#endif

int _eXosip_guess_ip_for_via(struct eXosip_t *excontext, int family, char *address, int size) {
  if (family == AF_INET)
    return _eXosip_guess_ip_for_destination(excontext, family, excontext->ipv4_for_gateway, address, size);

  return _eXosip_guess_ip_for_destination(excontext, family, excontext->ipv6_for_gateway, address, size);
}

#if defined(HAVE_WINSOCK2_H)

int _eXosip_guess_ip_for_destination(struct eXosip_t *excontext, int family, char *destination, char *address, int size) {
  SOCKET sock;

  SOCKADDR_STORAGE local_addr;

  int local_addr_len;

  struct addrinfo *addrf = NULL;
  int type;

  address[0] = '\0';

  if (destination == NULL && family == AF_INET)
    destination = excontext->ipv4_for_gateway;

  if (destination == NULL && family == AF_INET6)
    destination = excontext->ipv6_for_gateway;

  type = SOCK_DGRAM;
#if defined(SOCK_CLOEXEC)
  type = SOCK_CLOEXEC | SOCK_DGRAM;
#endif
  sock = socket(family, type, 0);

  _eXosip_get_addrinfo(excontext, &addrf, destination, 0, IPPROTO_UDP);

  if (addrf == NULL) {
    if (family == AF_INET) {
      _eXosip_get_addrinfo(excontext, &addrf, "217.12.3.11", 0, IPPROTO_UDP);

    } else if (family == AF_INET6) {
      _eXosip_get_addrinfo(excontext, &addrf, "2001:638:500:101:2e0:81ff:fe24:37c6", 0, IPPROTO_UDP);
    }
  }

  if (addrf == NULL) {
    _eXosip_closesocket(sock);
    snprintf(address, size, (family == AF_INET) ? "127.0.0.1" : "::1");
    return OSIP_NO_NETWORK;
  }

  if (WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, addrf->ai_addr, (DWORD) addrf->ai_addrlen, &local_addr, sizeof(local_addr), &local_addr_len, NULL, NULL) != 0) {
    _eXosip_closesocket(sock);
    _eXosip_freeaddrinfo(addrf);
    snprintf(address, size, (family == AF_INET) ? "127.0.0.1" : "::1");
    return OSIP_NO_NETWORK;
  }

  _eXosip_closesocket(sock);
  _eXosip_freeaddrinfo(addrf);

  if (_eXosip_getnameinfo((const struct sockaddr *) &local_addr, local_addr_len, address, size, NULL, 0, NI_NUMERICHOST)) {
    snprintf(address, size, (family == AF_INET) ? "127.0.0.1" : "::1");
    return OSIP_NO_NETWORK;
  }

  return OSIP_SUCCESS;
}

int _eXosip_guess_ip_for_destinationsock(struct eXosip_t *excontext, int family, int proto, struct sockaddr_storage *udp_local_bind, int sock, char *destination, char *address, int size) {
  SOCKADDR_STORAGE local_addr;

  DWORD local_addr_len;

  struct addrinfo *addrf = NULL;

  address[0] = '\0';

  if (destination == NULL && family == AF_INET)
    destination = excontext->ipv4_for_gateway;

  if (destination == NULL && family == AF_INET6)
    destination = excontext->ipv6_for_gateway;

  _eXosip_get_addrinfo(excontext, &addrf, destination, 0, proto);

  if (addrf == NULL) {
    if (family == AF_INET) {
      _eXosip_get_addrinfo(excontext, &addrf, "217.12.3.11", 0, proto);

    } else if (family == AF_INET6) {
      _eXosip_get_addrinfo(excontext, &addrf, "2001:638:500:101:2e0:81ff:fe24:37c6", 0, proto);
    }
  }

  if (addrf == NULL) {
    snprintf(address, size, (family == AF_INET) ? "127.0.0.1" : "::1");
    return OSIP_NO_NETWORK;
  }

  if (WSAIoctl(sock, SIO_ROUTING_INTERFACE_QUERY, addrf->ai_addr, (DWORD) addrf->ai_addrlen, &local_addr, sizeof(local_addr), &local_addr_len, NULL, NULL) != 0) {
    _eXosip_freeaddrinfo(addrf);
    snprintf(address, size, (family == AF_INET) ? "127.0.0.1" : "::1");
    return OSIP_NO_NETWORK;
  }

  _eXosip_freeaddrinfo(addrf);

  if (_eXosip_getnameinfo((const struct sockaddr *) &local_addr, (socklen_t) local_addr_len, address, size, NULL, 0, NI_NUMERICHOST)) {
    snprintf(address, size, (family == AF_INET) ? "127.0.0.1" : "::1");
    return OSIP_NO_NETWORK;
  }

  return OSIP_SUCCESS;
}

#else /* sun, *BSD, linux, and other? */

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_GETIFADDRS

#include <ifaddrs.h>
#include <net/if.h>
static int _eXosip_default_gateway_with_getifaddrs(int type, char *address, int size) {
  struct ifaddrs *ifp;

  struct ifaddrs *ifpstart;

  int ret = -1;

  if (getifaddrs(&ifpstart) < 0) {
    return OSIP_NO_NETWORK;
  }

  for (ifp = ifpstart; ifp != NULL; ifp = ifp->ifa_next) {
    if (ifp->ifa_addr && ifp->ifa_addr->sa_family == type && (ifp->ifa_flags & IFF_RUNNING) && !(ifp->ifa_flags & IFF_LOOPBACK)) {
      _eXosip_getnameinfo(ifp->ifa_addr, (type == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in), address, size, NULL, 0, NI_NUMERICHOST);

      if (strchr(address, '%') == NULL) { /*avoid ipv6 link-local addresses */
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [default gateway:getifaddrs] found [%s:%s]\n", (type == AF_INET6) ? "AF_INET6" : "AF_INET", address));
        ret = 0;
        break;
      }
    }
  }

  freeifaddrs(ifpstart);
  return ret;
}
#endif

/* This is a portable way to find the default gateway.
 * The ip of the default interface is returned.
 */
static int _eXosip_default_gateway_ipv4(char *destination, char *address, int size) {
  socklen_t len;
  int sock_rt, on = 1;

  struct sockaddr_in iface_out;

  struct sockaddr_in remote;
  int type;

  memset(&remote, 0, sizeof(struct sockaddr_in));

  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = inet_addr(destination);
  remote.sin_port = htons(11111);

  memset(&iface_out, 0, sizeof(iface_out));

  type = SOCK_DGRAM;
#if defined(SOCK_CLOEXEC)
  type = SOCK_CLOEXEC | SOCK_DGRAM;
#endif
  sock_rt = socket(AF_INET, type, 0);

  if (setsockopt(sock_rt, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
    _eXosip_closesocket(sock_rt);
    snprintf(address, size, "127.0.0.1");
    return OSIP_NO_NETWORK;
  }

  if (connect(sock_rt, (struct sockaddr *) &remote, sizeof(struct sockaddr_in)) == -1) {
    _eXosip_closesocket(sock_rt);
    snprintf(address, size, "127.0.0.1");
    return OSIP_NO_NETWORK;
  }

  len = sizeof(iface_out);

  if (getsockname(sock_rt, (struct sockaddr *) &iface_out, &len) == -1) {
    _eXosip_closesocket(sock_rt);
    snprintf(address, size, "127.0.0.1");
    return OSIP_NO_NETWORK;
  }

  _eXosip_closesocket(sock_rt);

  if (iface_out.sin_addr.s_addr == 0) { /* what is this case?? */
    snprintf(address, size, "127.0.0.1");
    return OSIP_NO_NETWORK;
  }

  osip_strncpy(address, inet_ntoa(iface_out.sin_addr), size - 1);
  return OSIP_SUCCESS;
}

/* This is a portable way to find the default gateway.
 * The ip of the default interface is returned.
 */
static int _eXosip_default_gateway_ipv6(char *destination, char *address, int size) {
  socklen_t len;
  int sock_rt, on = 1;

  struct sockaddr_in6 iface_out;

  struct sockaddr_in6 remote;
  int type;

  memset(&remote, 0, sizeof(struct sockaddr_in6));

  remote.sin6_family = AF_INET6;
  inet_pton(AF_INET6, destination, &remote.sin6_addr);
  remote.sin6_port = htons(11111);

  memset(&iface_out, 0, sizeof(iface_out));
  type = SOCK_DGRAM;
#if defined(SOCK_CLOEXEC)
  type = SOCK_CLOEXEC | SOCK_DGRAM;
#endif
  sock_rt = socket(AF_INET6, type, 0);
  /*default to ipv6 local loopback in case something goes wrong: */
  snprintf(address, size, "::1");

  if (setsockopt(sock_rt, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
    _eXosip_closesocket(sock_rt);
    return OSIP_NO_NETWORK;
  }

  if (connect(sock_rt, (struct sockaddr *) &remote, sizeof(struct sockaddr_in6)) == -1) {
    _eXosip_closesocket(sock_rt);
    return OSIP_NO_NETWORK;
  }

  len = sizeof(iface_out);

  if (getsockname(sock_rt, (struct sockaddr *) &iface_out, &len) == -1) {
    _eXosip_closesocket(sock_rt);
    return OSIP_NO_NETWORK;
  }

  _eXosip_closesocket(sock_rt);

  inet_ntop(AF_INET6, (const void *) &iface_out.sin6_addr, address, size - 1);
  return OSIP_SUCCESS;
}

int _eXosip_guess_ip_for_destination(struct eXosip_t *excontext, int family, char *destination, char *address, int size) {
  int err;

  if (family == AF_INET6) {
    err = _eXosip_default_gateway_ipv6(destination, address, size);

  } else {
    err = _eXosip_default_gateway_ipv4(destination, address, size);
  }

#ifdef HAVE_GETIFADDRS

  if (err < 0)
    err = _eXosip_default_gateway_with_getifaddrs(family, address, size);

#endif
  return err;
}

/* This is a portable way to find the default gateway.
 * The ip of the default interface is returned.
 */
static int _eXosip_default_gateway_ipv4sock(int proto, struct sockaddr_storage *udp_local_bind, int sock, char *destination, char *address, int size) {
  socklen_t len;
  struct sockaddr_in iface_out;
  int type;

  snprintf(address, size, "127.0.0.1");

  if (udp_local_bind != NULL) {
    struct sockaddr_in remote;

    /* for udp, we use an independant socket with similar binding, because we can't connect the socket */

    memset(&remote, 0, sizeof(struct sockaddr_in));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(destination);
    remote.sin_port = htons(11111);

    memcpy(&iface_out, udp_local_bind, sizeof(iface_out));
    len = sizeof(iface_out);
    iface_out.sin_port = htons(0);

    type = SOCK_DGRAM;
#if defined(SOCK_CLOEXEC)
    type = SOCK_CLOEXEC | SOCK_DGRAM;
#endif
    sock = socket(AF_INET, type, proto);

    if (bind(sock, (struct sockaddr *) &iface_out, len) < 0) {
      _eXosip_closesocket(sock);
      return OSIP_NO_NETWORK;
    }

    if (connect(sock, (struct sockaddr *) &remote, sizeof(struct sockaddr_in)) == -1) {
      _eXosip_closesocket(sock);
      return OSIP_NO_NETWORK;
    }

    len = sizeof(iface_out);

    if (getsockname(sock, (struct sockaddr *) &iface_out, &len) == -1) {
      _eXosip_closesocket(sock);
      return OSIP_NO_NETWORK;
    }

    _eXosip_closesocket(sock);

    if (iface_out.sin_addr.s_addr == 0) { /* what is this case?? */
      return OSIP_NO_NETWORK;
    }

    osip_strncpy(address, inet_ntoa(iface_out.sin_addr), size - 1);
    return OSIP_SUCCESS;
  }

  memset(&iface_out, 0, sizeof(iface_out));
  len = sizeof(iface_out);

  if (getsockname(sock, (struct sockaddr *) &iface_out, &len) == -1) {
    return OSIP_NO_NETWORK;
  }

  if (iface_out.sin_addr.s_addr == 0) { /* what is this case?? */
    return OSIP_NO_NETWORK;
  }

  osip_strncpy(address, inet_ntoa(iface_out.sin_addr), size - 1);
  return OSIP_SUCCESS;
}

/* This is a portable way to find the default gateway.
 * The ip of the default interface is returned.
 */
static int _eXosip_default_gateway_ipv6sock(int proto, struct sockaddr_storage *udp_local_bind, int sock, char *destination, char *address, int size) {
  socklen_t len;
  struct sockaddr_in6 iface_out;
  int type;

  snprintf(address, size, "::1");

  if (udp_local_bind != NULL) {
    /* for udp, we use an independant socket with similar binding, because we can't connect the socket */
    struct sockaddr_in6 remote;

    memset(&remote, 0, sizeof(struct sockaddr_in6));
    remote.sin6_family = AF_INET6;
    inet_pton(AF_INET6, destination, &remote.sin6_addr);
    remote.sin6_port = htons(11111);

    memcpy(&iface_out, udp_local_bind, sizeof(iface_out));
    len = sizeof(iface_out);
    iface_out.sin6_port = htons(0);

    type = SOCK_DGRAM;
#if defined(SOCK_CLOEXEC)
    type = SOCK_CLOEXEC | SOCK_DGRAM;
#endif
    sock = socket(AF_INET6, type, proto);

    if (bind(sock, (struct sockaddr *) &iface_out, len) < 0) {
      _eXosip_closesocket(sock);
      return OSIP_NO_NETWORK;
    }

    if (connect(sock, (struct sockaddr *) &remote, sizeof(struct sockaddr_in6)) == -1) {
      _eXosip_closesocket(sock);
      return OSIP_NO_NETWORK;
    }

    len = sizeof(iface_out);

    if (getsockname(sock, (struct sockaddr *) &iface_out, &len) == -1) {
      _eXosip_closesocket(sock);
      return OSIP_NO_NETWORK;
    }

    _eXosip_closesocket(sock);

    inet_ntop(AF_INET6, (const void *) &iface_out.sin6_addr, address, size - 1);
    return OSIP_SUCCESS;
  }

  memset(&iface_out, 0, sizeof(iface_out));
  len = sizeof(iface_out);

  if (getsockname(sock, (struct sockaddr *) &iface_out, &len) == -1) {
    return OSIP_NO_NETWORK;
  }

  inet_ntop(AF_INET6, (const void *) &iface_out.sin6_addr, address, size - 1);
  return OSIP_SUCCESS;
}

int _eXosip_guess_ip_for_destinationsock(struct eXosip_t *excontext, int family, int proto, struct sockaddr_storage *udp_local_bind, int sock, char *destination, char *address, int size) {
  int err;

  if (family == AF_INET6) {
    err = _eXosip_default_gateway_ipv6sock(proto, udp_local_bind, sock, destination, address, size);

  } else {
    err = _eXosip_default_gateway_ipv4sock(proto, udp_local_bind, sock, destination, address, size);
  }

#ifdef HAVE_GETIFADDRS

  if (err < 0)
    err = _eXosip_default_gateway_with_getifaddrs(family, address, size);

#endif
  return err;
}

#endif

char *_eXosip_strdup_printf(const char *fmt, ...) {
  /* Guess we need no more than 100 bytes. */
  int n, size = 100;

  char *p;

  va_list ap;

  if ((p = osip_malloc(size)) == NULL)
    return NULL;

  while (1) {
    /* Try to print in the allocated space. */
    VA_START(ap, fmt);
#ifdef WIN32
    n = _vsnprintf(p, size, fmt, ap);
#else
    n = vsnprintf(p, size, fmt, ap);
#endif
    va_end(ap);

    /* If that worked, return the string. */
    if (n > -1 && n < size)
      return p;

    /* Else try again with more space. */
    if (n > -1)     /* glibc 2.1 */
      size = n + 1; /* precisely what is needed */
    else            /* glibc 2.0 */
      size *= 2;    /* twice the old size */

    if ((p = osip_realloc(p, size)) == NULL)
      return NULL;
  }
}

#if !defined(USE_GETHOSTBYNAME)

static int _exosip_isipv4addr(const char *ip) {
  int i;

  for (i = 0; i < 4 && *ip != '\0'; i++) {
    while (*ip != '\0' && (*ip >= '0') && (*ip <= '9'))
      ip++;

    if (*ip != '\0') {
      if (*ip == '.' && i < 3)
        ip++;

      else
        break;
    }
  }

  if (i == 4 && *ip == '\0')
    return 1;

  return 0;
}

int _eXosip_get_addrinfo(struct eXosip_t *excontext, struct addrinfo **addrinfo, const char *hostname, int service, int protocol) {
  struct addrinfo hints;
  char portbuf[10];
  int error;
  int i;

  char tmplog[512] = {'\0'};
  int size_log = 0;

  if (service == -1) { /* -1 for SRV record */
    /* obsolete code: make an SRV record? */
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [getaddrinfo] obsolete code\n"));
    return -1;
  }

  size_log = snprintf(tmplog, sizeof(tmplog), "[eXosip] [getaddrinfo]");
  if (hostname != NULL)
    size_log += snprintf(tmplog + size_log, sizeof(tmplog) - size_log, " dns [%s][%d]", hostname, service);

  if (excontext != NULL && hostname != NULL) {
    for (i = 0; i < MAX_EXOSIP_DNS_ENTRY; i++) {
      if (excontext->dns_entries[i].host[0] != '\0' && 0 == osip_strcasecmp(excontext->dns_entries[i].host, hostname)) {
        /* update entry */
        if (excontext->dns_entries[i].ip[0] != '\0') {
          hostname = excontext->dns_entries[i].ip;
          size_log += snprintf(tmplog + size_log, sizeof(tmplog) - size_log, " cached[%s]", excontext->dns_entries[i].ip);
          break;
        }
      }
    }
  }

  snprintf(portbuf, sizeof(portbuf), "%i", service);

  memset(&hints, 0, sizeof(hints));

  hints.ai_flags = 0;

  if (hostname == NULL) {
    hints.ai_flags = AI_PASSIVE;
  }

  if (excontext->ipv6_enable > 1)
    hints.ai_family = AF_UNSPEC;

  else if (excontext->ipv6_enable)
    hints.ai_family = PF_INET6;

  else
    hints.ai_family = PF_INET; /* ipv4 only support */

  if (hostname == NULL) {
  } else if (strchr(hostname, ':') != NULL) /* it's an IPv6 address... */
    hints.ai_family = PF_INET6;

  else if (_exosip_isipv4addr(hostname))
    hints.ai_family = PF_INET; /* it's an IPv4 address... */

  if (protocol == IPPROTO_UDP)
    hints.ai_socktype = SOCK_DGRAM;

  else
    hints.ai_socktype = SOCK_STREAM;

  hints.ai_protocol = protocol; /* IPPROTO_UDP or IPPROTO_TCP */
  error = getaddrinfo(hostname, portbuf, &hints, addrinfo);

  if (error || *addrinfo == NULL) {
    char eb[ERRBSIZ];
#if defined(HAVE_RESOLV_H)

    /* When a DNS server has changed after roaming to a new network. The
       new one should be automatically used. However, a few system are not
       doing this automatically so, when the DNS server is not accessible,
       we force getaddrinfo to use the new one after the first failure. */
    if (error == EAI_AGAIN)
      res_init();

#endif
    size_log += snprintf(tmplog + size_log, sizeof(tmplog) - size_log, " failure %s", _ex_gai_strerror(error, eb, ERRBSIZ));
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "%s\n", tmplog));
    return OSIP_UNKNOWN_HOST;

  } else {
    struct addrinfo *elem;

    char tmp[INET6_ADDRSTRLEN];

    char porttmp[10];

    size_log += snprintf(tmplog + size_log, sizeof(tmplog) - size_log, " = ");

    for (elem = *addrinfo; elem != NULL; elem = elem->ai_next) {
      _eXosip_getnameinfo(elem->ai_addr, (socklen_t) elem->ai_addrlen, tmp, sizeof(tmp), porttmp, sizeof(porttmp), NI_NUMERICHOST | NI_NUMERICSERV);
      size_log += snprintf(tmplog + size_log, sizeof(tmplog) - size_log, " [%s][%s]", tmp, porttmp);
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "%s\n", tmplog));
  }

  return OSIP_SUCCESS;
}
#endif

static void osip_srv_record_sort(struct osip_srv_record *rec, int n) {
  int i;
  int permuts;
  struct osip_srv_entry swap;

  do {
    struct osip_srv_entry *s1, *s2;

    permuts = 0;

    for (i = 0; i < n - 1; ++i) {
      s1 = &rec->srventry[i];
      s2 = &rec->srventry[i + 1];

      if (s1->priority > s2->priority) {
        memcpy(&swap, s1, sizeof(swap));
        memcpy(s1, s2, sizeof(swap));
        memcpy(s2, &swap, sizeof(swap));
        permuts++;
      }
    }
  } while (permuts != 0);
}

int _eXosip_srv_lookup(struct eXosip_t *excontext, osip_message_t *sip, osip_naptr_t **naptr_record) {
  int use_srv = 1;
  char *host;
  osip_via_t *via;

  via = (osip_via_t *) osip_list_get(&sip->vias, 0);

  if (via == NULL || via->protocol == NULL)
    return OSIP_BADPARAMETER;

  if (MSG_IS_REQUEST(sip)) {
    osip_route_t *route;

    if (sip->sip_method == NULL)
      return OSIP_BADPARAMETER;

    osip_message_get_route(sip, 0, &route);

    if (route != NULL) {
      osip_uri_param_t *lr_param = NULL;

      osip_uri_uparam_get_byname(route->url, "lr", &lr_param);

      if (lr_param == NULL)
        route = NULL;
    }

    if (route != NULL) {
      if (route->url->port != NULL) {
        use_srv = 0;
      }

      host = route->url->host;

    } else {
      /* search for maddr parameter */
      osip_uri_param_t *maddr_param = NULL;

      osip_uri_uparam_get_byname(sip->req_uri, "maddr", &maddr_param);
      host = NULL;

      if (maddr_param != NULL && maddr_param->gvalue != NULL)
        host = maddr_param->gvalue;

      if (sip->req_uri->port != NULL) {
        use_srv = 0;
      }

      if (host == NULL)
        host = sip->req_uri->host;
    }

  } else {
    osip_generic_param_t *maddr;

    osip_generic_param_t *received;

    osip_generic_param_t *rport;

    osip_via_param_get_byname(via, "maddr", &maddr);
    osip_via_param_get_byname(via, "received", &received);
    osip_via_param_get_byname(via, "rport", &rport);

    if (maddr != NULL)
      host = maddr->gvalue;

    else if (received != NULL)
      host = received->gvalue;

    else
      host = via->host;

    if (via->port == NULL)
      use_srv = 0;
  }

  if (host == NULL) {
    return OSIP_UNKNOWN_HOST;
  }

  /* check if we have an IPv4 or IPv6 address */
  if (strchr(host, ':') || (INADDR_NONE != inet_addr(host))) {
    return OSIP_UNDEFINED_ERROR;
  }

  if (use_srv == 1) {
    int keep_in_cache = MSG_IS_REGISTER(sip) ? 1 : 0;

    /* Section 16.6 Request Forwarding (4. Record-Route)
       The URI placed in the Record-Route header field MUST resolve to
       the element inserting it (or a suitable stand-in) when the
       server location procedures of [4] are applied to it, so that
       subsequent requests reach the same SIP element.

       Note: When the above doesn't appear to be true, check at least cache. */

    osip_generic_param_t *tag = NULL;

    if (excontext->dns_capabilities <= 0) {
      *naptr_record = NULL;
      return OSIP_SUCCESS;
    }

    osip_to_get_tag(sip->to, &tag);

    if (tag != NULL) /* check cache only */
      *naptr_record = eXosip_dnsutils_naptr(excontext, host, "sip", via->protocol, -1);

    else
      *naptr_record = eXosip_dnsutils_naptr(excontext, host, "sip", via->protocol, keep_in_cache);

    return OSIP_SUCCESS;
  }

  return OSIP_UNDEFINED_ERROR;
}

int eXosip_dnsutils_rotate_srv(osip_srv_record_t *srv_record) {
  int n;
  int prev_idx = srv_record->index;

  if (srv_record->srventry[0].srv[0] == '\0')
    return -1;

  srv_record->index++;

  if (srv_record->srventry[srv_record->index].srv[0] == '\0')
    srv_record->index = 0;

  for (n = 1; n < 10 && srv_record->srventry[n].srv[0] != '\0'; n++) {
  }

  if (prev_idx != srv_record->index) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] failover with SRV [%s][%d] -> [%s][%d]\n", srv_record->srventry[prev_idx].srv, srv_record->srventry[prev_idx].port,
                          srv_record->srventry[srv_record->index].srv, srv_record->srventry[srv_record->index].port));
  }

  return n - 1;
}

#ifdef SRV_RECORD

static osip_list_t *dnsutils_list = NULL;

#define EXOSIP_DNSUTILS_FIND_SNI_DEFINED
const char *_eXosip_dnsutils_find_sni(struct eXosip_t *excontext, const char *hostname) {
  osip_list_iterator_t it;
  struct osip_naptr *naptr_record;

  if (dnsutils_list == NULL)
    return NULL;

  naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

  while (naptr_record != NULL) {
    if (naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVDONE) {
      int idx;
      for (idx = 1; idx < 10 && naptr_record->siptls_record.srventry[idx].srv[0] != '\0'; idx++) {
        if (osip_strcasecmp(hostname, naptr_record->siptls_record.srventry[idx].srv) == 0)
          return naptr_record->domain;
      }
    }

    naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
  }

  return NULL;
}

#if !defined(EXOSIP_DNSUTILS_DEFINED) && (defined(HAVE_CARES_H) || defined(HAVE_ARES_H))
#define EXOSIP_DNSUTILS_DEFINED

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#else
#include "ares_nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#ifndef HFIXEDSZ
#define HFIXEDSZ 12
#endif
#ifndef QFIXEDSZ
#define QFIXEDSZ 4
#endif
#ifndef RRFIXEDSZ
#define RRFIXEDSZ 10
#endif

#ifndef T_A
#define T_A 1
#endif

#ifndef T_AAAA
#define T_AAAA 28
#endif

#ifndef T_SRV
#define T_SRV 33
#endif

#ifndef T_NAPTR
#define T_NAPTR 35
#endif

#ifndef C_IN
#define C_IN 1
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <ares.h>
#include <ares_dns.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(HAVE_INET_NTOP)
#include "inet_ntop.h"
#endif

#ifdef USE_WINSOCK
#define SOCKERRNO ((int) WSAGetLastError())
#define SET_SOCKERRNO(x) (WSASetLastError((int) (x)))
#else
#define SOCKERRNO (errno)
#define SET_SOCKERRNO(x) (errno = (x))
#endif

static const unsigned char *skip_question(const unsigned char *aptr, const unsigned char *abuf, int alen) {
  char *name;
  int status;
  long len;

  status = ares_expand_name(aptr, abuf, alen, &name, &len);

  if (status != ARES_SUCCESS)
    return NULL;

  aptr += len;

  ares_free_string(name);

  if (aptr + QFIXEDSZ > abuf + alen) {
    return NULL;
  }

  aptr += QFIXEDSZ;
  return aptr;
}

static const unsigned char *save_A(osip_naptr_t *output_record, const unsigned char *aptr, const unsigned char *abuf, int alen) {
  char rr_name[512];

  /* int dnsclass, ttl; */
  int type, dlen, status;
  long len;
  char addr[46];
  union {
    unsigned char *as_uchar;
    char *as_char;
  } name;

  /* Parse the RR name. */
  status = ares_expand_name(aptr, abuf, alen, &name.as_char, &len);

  if (status != ARES_SUCCESS)
    return NULL;

  aptr += len;

  if (aptr + RRFIXEDSZ > abuf + alen) {
    ares_free_string(name.as_char);
    return NULL;
  }

  type = DNS_RR_TYPE(aptr);
  /* dnsclass = DNS_RR_CLASS(aptr); */
  /* ttl = DNS_RR_TTL(aptr); */
  dlen = DNS_RR_LEN(aptr);
  aptr += RRFIXEDSZ;

  if (aptr + dlen > abuf + alen) {
    ares_free_string(name.as_char);
    return NULL;
  }

  snprintf(rr_name, sizeof(rr_name), "%s", name.as_char);
  ares_free_string(name.as_char);

  switch (type) {
  case T_A:
    /* The RR data is a four-byte Internet address. */
    {
      int n;
      osip_srv_entry_t *srventry;

      if (dlen != 4)
        return NULL;

      inet_ntop(AF_INET, aptr, addr, sizeof(addr));
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [save_A record] [%s] -> [%s]\n", rr_name, addr));

      for (n = 0; n < 10; n++) {
        if (osip_strcasecmp(rr_name, output_record->sipudp_record.srventry[n].srv) == 0) {
          srventry = &output_record->sipudp_record.srventry[n];
          snprintf(srventry->ipaddress, sizeof(srventry->ipaddress), "%s", addr);
        }

        if (osip_strcasecmp(rr_name, output_record->siptcp_record.srventry[n].srv) == 0) {
          srventry = &output_record->siptcp_record.srventry[n];
          snprintf(srventry->ipaddress, sizeof(srventry->ipaddress), "%s", addr);
        }

        if (osip_strcasecmp(rr_name, output_record->siptls_record.srventry[n].srv) == 0) {
          srventry = &output_record->siptls_record.srventry[n];
          snprintf(srventry->ipaddress, sizeof(srventry->ipaddress), "%s", addr);
        }

        if (osip_strcasecmp(rr_name, output_record->sipdtls_record.srventry[n].srv) == 0) {
          srventry = &output_record->sipdtls_record.srventry[n];
          snprintf(srventry->ipaddress, sizeof(srventry->ipaddress), "%s", addr);
        }

        if (osip_strcasecmp(rr_name, output_record->sipsctp_record.srventry[n].srv) == 0) {
          srventry = &output_record->sipsctp_record.srventry[n];
          snprintf(srventry->ipaddress, sizeof(srventry->ipaddress), "%s", addr);
        }
      }
    }

    break;

  case T_AAAA:

    /* The RR data is a 16-byte IPv6 address. */
    if (dlen != 16)
      return NULL;

    inet_ntop(AF_INET6, aptr, addr, sizeof(addr));
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [save_AAAA record] [%s] -> [%s]\n", rr_name, addr));
    break;

  default:
    break;
  }

  return aptr + dlen;
}

static const unsigned char *save_SRV(osip_naptr_t *output_record, const unsigned char *aptr, const unsigned char *abuf, int alen) {
  char rr_name[512];

  /* int dnsclass, ttl; */
  int type, dlen, status;
  long len;
  union {
    unsigned char *as_uchar;
    char *as_char;
  } name;

  status = ares_expand_name(aptr, abuf, alen, &name.as_char, &len);

  if (status != ARES_SUCCESS)
    return NULL;

  aptr += len;

  if (aptr + RRFIXEDSZ > abuf + alen) {
    ares_free_string(name.as_char);
    return NULL;
  }

  type = DNS_RR_TYPE(aptr);
  /* dnsclass = DNS_RR_CLASS(aptr); */
  /* ttl = DNS_RR_TTL(aptr); */
  dlen = DNS_RR_LEN(aptr);
  aptr += RRFIXEDSZ;

  if (aptr + dlen > abuf + alen) {
    ares_free_string(name.as_char);
    return NULL;
  }

  snprintf(rr_name, sizeof(rr_name), "%s", name.as_char);
  ares_free_string(name.as_char);

  switch (type) {
  case T_SRV:
    /* The RR data is three two-byte numbers representing the
     * priority, weight, and port, followed by a domain name.
     */
    {
      osip_srv_record_t *srvrecord = NULL;
      osip_srv_entry_t *srventry = NULL;
      int n;

      if (osip_strcasecmp(rr_name, output_record->sipudp_record.name) == 0)
        srvrecord = &output_record->sipudp_record;

      else if (osip_strcasecmp(rr_name, output_record->siptcp_record.name) == 0)
        srvrecord = &output_record->siptcp_record;

      else if (osip_strcasecmp(rr_name, output_record->siptls_record.name) == 0)
        srvrecord = &output_record->siptls_record;

      else if (osip_strcasecmp(rr_name, output_record->sipdtls_record.name) == 0)
        srvrecord = &output_record->sipdtls_record;

      else if (osip_strcasecmp(rr_name, output_record->sipsctp_record.name) == 0)
        srvrecord = &output_record->sipsctp_record;

      else
        break;

      n = 0;

      while (n < 10 && srvrecord->srventry[n].srv[0] != '\0')
        n++;

      if (n == 10)
        break; /* skip... */

      srventry = &srvrecord->srventry[n];

      srventry->priority = DNS__16BIT(aptr);
      srventry->weight = DNS__16BIT(aptr + 2);
      srventry->port = DNS__16BIT(aptr + 4);

      if (srventry->weight)
        srventry->rweight = 1 + rand() % (10000 * srventry->weight);

      else
        srventry->rweight = 0;

      status = ares_expand_name(aptr + 6, abuf, alen, &name.as_char, &len);

      if (status != ARES_SUCCESS)
        return NULL;

      snprintf(srventry->srv, sizeof(srventry->srv), "%s", name.as_char);

      srvrecord->srv_state = OSIP_SRV_STATE_COMPLETED;

      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [save_SRV record] [%s] IN SRV -> [%s][%i][%i][%i][%i]\n", rr_name, srventry->srv, srventry->port, srventry->priority, srventry->weight, srventry->rweight));

      osip_srv_record_sort(srvrecord, n + 1);
      ares_free_string(name.as_char);
    }
    break;

  default:
    break;
  }

  return aptr + dlen;
}

static const unsigned char *save_NAPTR(osip_naptr_t *output_record, const unsigned char *aptr, const unsigned char *abuf, int alen) {
  char rr_name[512];
  const unsigned char *p;

  /* int dnsclass, ttl; */
  int type, dlen, status;
  long len;
  union {
    unsigned char *as_uchar;
    char *as_char;
  } name;

  status = ares_expand_name(aptr, abuf, alen, &name.as_char, &len);

  if (status != ARES_SUCCESS)
    return NULL;

  aptr += len;

  if (aptr + RRFIXEDSZ > abuf + alen) {
    ares_free_string(name.as_char);
    return NULL;
  }

  type = DNS_RR_TYPE(aptr);
  /* dnsclass = DNS_RR_CLASS(aptr); */
  /* ttl = DNS_RR_TTL(aptr); */
  dlen = DNS_RR_LEN(aptr);
  aptr += RRFIXEDSZ;

  if (aptr + dlen > abuf + alen) {
    ares_free_string(name.as_char);
    return NULL;
  }

  snprintf(rr_name, sizeof(rr_name), "%s", name.as_char);
  ares_free_string(name.as_char);

  switch (type) {
  case T_NAPTR: {
    osip_srv_record_t srvrecord;

    memset(&srvrecord, 0, sizeof(osip_srv_record_t));

    srvrecord.order = DNS__16BIT(aptr);
    srvrecord.preference = DNS__16BIT(aptr + 2);

    p = aptr + 4;

    status = ares_expand_string(p, abuf, alen, &name.as_uchar, &len);

    if (status != ARES_SUCCESS)
      return NULL;

    snprintf(srvrecord.flag, sizeof(srvrecord.flag), "%s", name.as_char);
    ares_free_string(name.as_char);
    p += len;

    status = ares_expand_string(p, abuf, alen, &name.as_uchar, &len);

    if (status != ARES_SUCCESS)
      return NULL;

    snprintf(srvrecord.protocol, sizeof(srvrecord.protocol), "%s", name.as_char);
    ares_free_string(name.as_char);
    p += len;

    status = ares_expand_string(p, abuf, alen, &name.as_uchar, &len);

    if (status != ARES_SUCCESS)
      return NULL;

    snprintf(srvrecord.regexp, sizeof(srvrecord.regexp), "%s", name.as_uchar);
    ares_free_string(name.as_char);
    p += len;

    status = ares_expand_name(p, abuf, alen, &name.as_char, &len);

    if (status != ARES_SUCCESS)
      return NULL;

    snprintf(srvrecord.replacement, sizeof(srvrecord.replacement), "%s", name.as_char);
    ares_free_string(name.as_char);

    if (srvrecord.flag[0] == 's' || srvrecord.flag[0] == 'S') {
      snprintf(srvrecord.name, sizeof(srvrecord.name), "%s", srvrecord.replacement);
    }

    if (srvrecord.flag[0] == 'a' || srvrecord.flag[0] == 'A') {
      snprintf(srvrecord.name, sizeof(srvrecord.name), "%s", srvrecord.replacement);
    }

    if (srvrecord.flag[0] == 'u' || srvrecord.flag[0] == 'U') {
      naptr_enum_match_and_replace(output_record, &srvrecord);
    }

    srvrecord.srv_state = OSIP_SRV_STATE_UNKNOWN;

    if (osip_strncasecmp(srvrecord.name, "_sip._udp.", 10) == 0 || osip_strncasecmp(srvrecord.protocol, "SIP+D2U", 8) == 0) { /* udp */
      memcpy(&output_record->sipudp_record, &srvrecord, sizeof(osip_srv_record_t));

    } else if (osip_strncasecmp(srvrecord.name, "_sip._tcp.", 10) == 0 || osip_strncasecmp(srvrecord.protocol, "SIP+D2T", 8) == 0) { /* tcp */
      memcpy(&output_record->siptcp_record, &srvrecord, sizeof(osip_srv_record_t));

    } else if (osip_strncasecmp(srvrecord.protocol, "SIPS+D2T", 9) == 0) { /* tls */
      memcpy(&output_record->siptls_record, &srvrecord, sizeof(osip_srv_record_t));

    } else if (osip_strncasecmp(srvrecord.protocol, "SIPS+D2U", 9) == 0) { /* dtls-udp */
      memcpy(&output_record->sipdtls_record, &srvrecord, sizeof(osip_srv_record_t));

    } else if (osip_strncasecmp(srvrecord.protocol, "SIP+D2S", 8) == 0) { /* sctp */
      memcpy(&output_record->sipsctp_record, &srvrecord, sizeof(osip_srv_record_t));

    } else if (osip_strncasecmp(srvrecord.protocol, "E2U+SIP", 8) == 0 || osip_strncasecmp(srvrecord.protocol, "SIP+E2U", 8) == 0) { /* enum result // SIP+E2U is from rfc2916 and obsolete */
      srvrecord.srv_state = OSIP_SRV_STATE_COMPLETED;
      memcpy(&output_record->sipenum_record, &srvrecord, sizeof(osip_srv_record_t));
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [save_NAPTR record] [%s] -> [%i][%i][%s][%s][%s]\n", rr_name, srvrecord.order, srvrecord.preference, srvrecord.protocol, srvrecord.regexp, srvrecord.name));
  } break;

  default:
    break;
  }

  return aptr + dlen;
}

static void _store_A(void *arg, int status, int timeouts, unsigned char *abuf, int alen, int verbose) {
  osip_naptr_t *output_record = (osip_naptr_t *) arg;

#if 0
  int qr, aa, tc, rd, ra, opcode, rcode;        /* , id; */
#endif
  unsigned int qdcount, ancount, nscount, arcount, i;
  const unsigned char *aptr;

  (void) timeouts;

  if (status != ARES_SUCCESS) {
    if (verbose) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [DNS A record] [%s] [%s]\n", output_record->domain, ares_strerror(status)));
    }

    if (!abuf)
      return;
  }

  if (alen < HFIXEDSZ)
    return;

#if 0
  /* id = DNS_HEADER_QID(abuf); */
  qr = DNS_HEADER_QR(abuf);
  opcode = DNS_HEADER_OPCODE(abuf);
  aa = DNS_HEADER_AA(abuf);
  tc = DNS_HEADER_TC(abuf);
  rd = DNS_HEADER_RD(abuf);
  ra = DNS_HEADER_RA(abuf);
  rcode = DNS_HEADER_RCODE(abuf);
#endif
  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);
  nscount = DNS_HEADER_NSCOUNT(abuf);
  arcount = DNS_HEADER_ARCOUNT(abuf);

  /* the questions. */
  aptr = abuf + HFIXEDSZ;

  for (i = 0; i < qdcount; i++) {
    aptr = skip_question(aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }

  /* the answers. */
  for (i = 0; i < ancount; i++) {
    aptr = save_A(output_record, aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }

  /* the NS records. */
  for (i = 0; i < nscount; i++) {
    aptr = save_A(output_record, aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }

  /* the additional records. */
  for (i = 0; i < arcount; i++) {
    aptr = save_A(output_record, aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }
}

static void _store_srv(void *arg, int status, int timeouts, unsigned char *abuf, int alen, int verbose) {
  osip_naptr_t *output_record = (osip_naptr_t *) arg;

#if 0
  int qr, aa, tc, rd, ra, opcode, rcode;        /* , id; */
#endif
  unsigned int qdcount, ancount, nscount, arcount, i;
  const unsigned char *aptr;

  (void) timeouts;

  if (status != ARES_SUCCESS) {
    if (verbose) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [DNS SRV record] [%s] [%s]\n", output_record->domain, ares_strerror(status)));
    }

    if (!abuf)
      return;
  }

  if (alen < HFIXEDSZ)
    return;

#if 0
  /* id = DNS_HEADER_QID(abuf); */
  qr = DNS_HEADER_QR(abuf);
  opcode = DNS_HEADER_OPCODE(abuf);
  aa = DNS_HEADER_AA(abuf);
  tc = DNS_HEADER_TC(abuf);
  rd = DNS_HEADER_RD(abuf);
  ra = DNS_HEADER_RA(abuf);
  rcode = DNS_HEADER_RCODE(abuf);
#endif
  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);
  nscount = DNS_HEADER_NSCOUNT(abuf);
  arcount = DNS_HEADER_ARCOUNT(abuf);

  /* the questions. */
  aptr = abuf + HFIXEDSZ;

  for (i = 0; i < qdcount; i++) {
    aptr = skip_question(aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }

  /* the answers. */
  for (i = 0; i < ancount; i++) {
    aptr = save_SRV(output_record, aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }

  /* the NS records. */
  for (i = 0; i < nscount; i++) {
    aptr = save_SRV(output_record, aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }

  /* the additional records. */
  for (i = 0; i < arcount; i++) {
    aptr = save_SRV(output_record, aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }
}

static void _store_naptr(void *arg, int status, int timeouts, unsigned char *abuf, int alen, int verbose) {
  osip_naptr_t *output_record = (osip_naptr_t *) arg;

#if 0
  int qr, aa, tc, rd, ra, opcode, rcode;        /* , id; */
#endif
  unsigned int qdcount, ancount, nscount, arcount, i;
  const unsigned char *aptr;

  (void) timeouts;

  if (status != ARES_SUCCESS) {
    if (verbose) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [DNS NAPTR record] [%s] [%s]\n", output_record->domain, ares_strerror(status)));
    }

    if (!abuf)
      return;
  }

  if (alen < HFIXEDSZ)
    return;

#if 0
  /* id = DNS_HEADER_QID(abuf); */
  qr = DNS_HEADER_QR(abuf);
  opcode = DNS_HEADER_OPCODE(abuf);
  aa = DNS_HEADER_AA(abuf);
  tc = DNS_HEADER_TC(abuf);
  rd = DNS_HEADER_RD(abuf);
  ra = DNS_HEADER_RA(abuf);
  rcode = DNS_HEADER_RCODE(abuf);
#endif
  qdcount = DNS_HEADER_QDCOUNT(abuf);
  ancount = DNS_HEADER_ANCOUNT(abuf);
  nscount = DNS_HEADER_NSCOUNT(abuf);
  arcount = DNS_HEADER_ARCOUNT(abuf);

  /* the questions. */
  aptr = abuf + HFIXEDSZ;

  for (i = 0; i < qdcount; i++) {
    aptr = skip_question(aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }

  /* the answers. */
  for (i = 0; i < ancount; i++) {
    aptr = save_NAPTR(output_record, aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }

  /* the NS records. */
  for (i = 0; i < nscount; i++) {
    aptr = save_NAPTR(output_record, aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }

  /* the additional records. */
  for (i = 0; i < arcount; i++) {
    aptr = save_NAPTR(output_record, aptr, abuf, alen);

    if (aptr == NULL)
      return;
  }
}

static void _srv_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  _store_srv(arg, status, timeouts, abuf, alen, 1);
  _store_A(arg, status, timeouts, abuf, alen, 0);
}

static void _naptr_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
  osip_naptr_t *output_record = (osip_naptr_t *) arg;

  if (status != ARES_SUCCESS && output_record->AUS[0] != '\0') {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR callback] [%s] [%s]\n", output_record->domain, ares_strerror(status)));

    if (status == ARES_ENODATA) /* no NAPTR record for this domain */
      output_record->naptr_state = OSIP_NAPTR_STATE_NOTSUPPORTED;

    else if (status == ARES_ENOTFOUND) /* domain does not exist */
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else if (status == ARES_ETIMEOUT)
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else if (status == ARES_ESERVFAIL)
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else if (status == ARES_ENOTIMP)
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else if (status == ARES_EREFUSED)
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else /* ... */
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR callback] [%s] [%s]\n", output_record->domain, ares_strerror(status)));
    return;
  }

  if (status != ARES_SUCCESS) {
    if (status == ARES_ENODATA || status == ARES_ENOTFOUND) { /* no NAPTR record for this domain */
      osip_srv_record_t srvrecord;

      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR callback] [%s] [%s]\n", output_record->domain, ares_strerror(status)));
      /* pre-set all SRV record to unsupported? */
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

      output_record->sipudp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
      output_record->siptcp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
      output_record->siptls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
      output_record->sipdtls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
      output_record->sipsctp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
      output_record->sipenum_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;

      memset(&srvrecord, 0, sizeof(osip_srv_record_t));

      srvrecord.order = 49;
      srvrecord.preference = 49;
      srvrecord.srv_state = OSIP_SRV_STATE_UNKNOWN;

      snprintf(srvrecord.protocol, sizeof(srvrecord.protocol), "%s", "SIP+D2U");
      snprintf(srvrecord.name, sizeof(srvrecord.name), "_sip._udp.%s", output_record->domain);
      memcpy(&output_record->sipudp_record, &srvrecord, sizeof(osip_srv_record_t));

      snprintf(srvrecord.protocol, sizeof(srvrecord.protocol), "%s", "SIP+D2T");
      snprintf(srvrecord.name, sizeof(srvrecord.name), "_sip._tcp.%s", output_record->domain);
      memcpy(&output_record->siptcp_record, &srvrecord, sizeof(osip_srv_record_t));

      snprintf(srvrecord.protocol, sizeof(srvrecord.protocol), "%s", "SIPS+D2T");
      snprintf(srvrecord.name, sizeof(srvrecord.name), "_sips._tcp.%s", output_record->domain);
      memcpy(&output_record->siptls_record, &srvrecord, sizeof(osip_srv_record_t));

      snprintf(srvrecord.protocol, sizeof(srvrecord.protocol), "%s", "SIPS+D2U");
      snprintf(srvrecord.name, sizeof(srvrecord.name), "_sips._udp.%s", output_record->domain);
      memcpy(&output_record->sipdtls_record, &srvrecord, sizeof(osip_srv_record_t));

      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR callback] no NAPTR answer // SRV record created manually -> [%i][%i][%s]\n", srvrecord.order, srvrecord.preference, srvrecord.name));

      return;
    }
  }

  if (status != ARES_SUCCESS) {
    if (status == ARES_ENODATA) /* no NAPTR record for this domain */
      output_record->naptr_state = OSIP_NAPTR_STATE_NOTSUPPORTED;

    else if (status == ARES_ENOTFOUND) /* domain does not exist */
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else if (status == ARES_ETIMEOUT)
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else if (status == ARES_ESERVFAIL)
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else if (status == ARES_ENOTIMP)
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else if (status == ARES_EREFUSED)
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    else /* ... */
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR callback] [%s] [%s]\n", output_record->domain, ares_strerror(status)));
    /*if (!abuf) */
    return;
  }

  /* pre-set all SRV record to unsupported? */
  output_record->sipudp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->siptcp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->siptls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->sipdtls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->sipsctp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->sipenum_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;

  _store_naptr(arg, status, timeouts, abuf, alen, 1);
  _store_srv(arg, status, timeouts, abuf, alen, 0);
  _store_A(arg, status, timeouts, abuf, alen, 0);
  output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

  if (status == ARES_SUCCESS && output_record->sipenum_record.srv_state == OSIP_SRV_STATE_COMPLETED) {
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;
    return;
  }

  /* check if something was found? */
  if (status == ARES_SUCCESS && output_record->sipudp_record.name[0] == '\0' && output_record->siptcp_record.name[0] == '\0' && output_record->siptls_record.name[0] == '\0' && output_record->sipdtls_record.name[0] == '\0' &&
      output_record->sipsctp_record.name[0] == '\0' && output_record->sipenum_record.name[0] == '\0') {
    osip_srv_record_t srvrecord;

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR callback] [%s] [%s] [but missing NAPTR data]\n", output_record->domain, ares_strerror(status)));
    /* pre-set all SRV record to unsupported? */
    output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    output_record->sipudp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
    output_record->siptcp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
    output_record->siptls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
    output_record->sipdtls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
    output_record->sipsctp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
    output_record->sipenum_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;

    memset(&srvrecord, 0, sizeof(osip_srv_record_t));

    srvrecord.order = 49;
    srvrecord.preference = 49;
    srvrecord.srv_state = OSIP_SRV_STATE_UNKNOWN;

    snprintf(srvrecord.protocol, sizeof(srvrecord.protocol), "%s", "SIP+D2U");
    snprintf(srvrecord.name, sizeof(srvrecord.name), "_sip._udp.%s", output_record->domain);
    memcpy(&output_record->sipudp_record, &srvrecord, sizeof(osip_srv_record_t));

    snprintf(srvrecord.protocol, sizeof(srvrecord.protocol), "%s", "SIP+D2T");
    snprintf(srvrecord.name, sizeof(srvrecord.name), "_sip._tcp.%s", output_record->domain);
    memcpy(&output_record->siptcp_record, &srvrecord, sizeof(osip_srv_record_t));

    snprintf(srvrecord.protocol, sizeof(srvrecord.protocol), "%s", "SIPS+D2T");
    snprintf(srvrecord.name, sizeof(srvrecord.name), "_sips._tcp.%s", output_record->domain);
    memcpy(&output_record->siptls_record, &srvrecord, sizeof(osip_srv_record_t));

    snprintf(srvrecord.protocol, sizeof(srvrecord.protocol), "%s", "SIPS+D2U");
    snprintf(srvrecord.name, sizeof(srvrecord.name), "_sips._udp.%s", output_record->domain);
    memcpy(&output_record->sipdtls_record, &srvrecord, sizeof(osip_srv_record_t));

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR callback] no NAPTR answer // SRV record created manually -> [%i][%i][%s]\n", srvrecord.order, srvrecord.preference, srvrecord.name));
    return;
  }
}

#ifdef HAVE_SYS_EPOLL_H
#define EXOSIP_DNSUTILS_CARES_PROCESS_DEFINED

static int eXosip_dnsutils_cares_process(struct osip_naptr *output_record, ares_channel channel) {
  ares_socket_t socks[16] = {
      ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
      ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
  };

  int bitmask = ares_getsock(channel, socks, 16);

  if (bitmask != 0) {
    int num;
#if 0
    int nfds;
    int epfd;
    int n;
    struct epoll_event ep_array[16];

    epfd = epoll_create(16);

    if (epfd < 0) {
      output_record->arg = NULL;
      ares_destroy(channel);
      return OSIP_UNDEFINED_ERROR;
    }

    for (num = 0; num < ARES_GETSOCK_MAXNUM; num++) {
      struct epoll_event ev;

      memset(&ev, 0, sizeof(struct epoll_event));

      if (socks[num] == ARES_SOCKET_BAD)
        continue;

      ev.events = EPOLLIN;

      if (ARES_GETSOCK_READABLE(bitmask, num)) {
        ev.events |= EPOLLIN;

      } else if (ARES_GETSOCK_WRITABLE(bitmask, num)) {
        ev.events |= EPOLLOUT;
      }

      ev.data.fd = socks[num];
      epoll_ctl(epfd, EPOLL_CTL_ADD, socks[num], &ev);
    }

    nfds = epoll_wait(epfd, ep_array, 16, 0);

    if (nfds < 0 && SOCKERRNO != EINVAL) {
      output_record->arg = NULL;
      ares_destroy(channel);
      return OSIP_UNDEFINED_ERROR;
    }

    for (n = 0; n < nfds; ++n) {
      ares_process_fd(channel, ep_array[n].data.fd, ep_array[n].data.fd);
    }

#else

    for (num = 0; num < ARES_GETSOCK_MAXNUM; num++) {
      if (socks[num] == ARES_SOCKET_BAD)
        continue;

      ares_process_fd(channel, socks[num], socks[num]);
    }

#endif
    bitmask = ares_getsock(channel, socks, 16);
  }

  return bitmask;
}

#endif

#ifndef EXOSIP_DNSUTILS_CARES_PROCESS_DEFINED

// TODO: this method should exist when epoll mode is not selected?
#define EXOSIP_DNSUTILS_CARES_PROCESS_DEFINED
static int eXosip_dnsutils_cares_process(struct osip_naptr *output_record, ares_channel channel) {
  fd_set read_fds, write_fds;
  struct timeval *tvp, tv;
  int nfds;
  int count;

  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  nfds = ares_fds(channel, &read_fds, &write_fds);

  if (nfds != 0) {
    tvp = ares_timeout(channel, NULL, &tv);
    tvp->tv_sec = 0;
    tvp->tv_usec = 0;
    count = select(nfds, &read_fds, &write_fds, NULL, tvp);

    if (count < 0 && SOCKERRNO != EINVAL) {
      output_record->arg = NULL;
      ares_destroy(channel);
      return OSIP_UNDEFINED_ERROR;
    }

    ares_process(channel, &read_fds, &write_fds);

    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    nfds = ares_fds(channel, &read_fds, &write_fds);
  }

  return nfds;
}

#endif

#ifdef HAVE_SYS_EPOLL_H

#define EXOSIP_DNSUTILS_ADDSOCK_EPOLL_DEFINED
int _eXosip_dnsutils_addsock_epoll(struct eXosip_t *excontext, int *cares_fd_table) {
  ares_socket_t socks[16] = {
      ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
      ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
  };
  osip_list_iterator_t iterator;
  osip_transaction_t *tr;
  int pos_fd = 0;

  tr = (osip_transaction_t *) osip_list_get_first(&excontext->j_osip->osip_ict_transactions, &iterator);

  while (osip_list_iterator_has_elem(iterator)) {
    ares_channel channel = NULL;
    if (tr->naptr_record != NULL && tr->naptr_record->arg != NULL) {
      if (tr->state == ICT_CALLING) {
        channel = tr->naptr_record->arg;

        int bitmask = ares_getsock(channel, socks, 16);

        if (bitmask != 0) {
          int num;

          for (num = 0; num < ARES_GETSOCK_MAXNUM; num++) {
            struct epoll_event ev;

            memset(&ev, 0, sizeof(struct epoll_event));

            if (socks[num] == ARES_SOCKET_BAD)
              continue;

            ev.events = EPOLLIN;

            if (ARES_GETSOCK_READABLE(bitmask, num)) {
              ev.events |= EPOLLIN;

            } else if (ARES_GETSOCK_WRITABLE(bitmask, num)) {
              ev.events |= EPOLLOUT;
            }

            ev.data.fd = socks[num];
            epoll_ctl(excontext->epfd, EPOLL_CTL_ADD, socks[num], &ev);
            cares_fd_table[pos_fd] = socks[num];
            pos_fd++;
          }
        }
      }
    }
    tr = (osip_transaction_t *) osip_list_get_next(&iterator);
  }

  tr = (osip_transaction_t *) osip_list_get_first(&excontext->j_osip->osip_nict_transactions, &iterator);

  while (osip_list_iterator_has_elem(iterator)) {
    ares_channel channel = NULL;
    if (tr->naptr_record != NULL && tr->naptr_record->arg != NULL) {
      if (tr->state == NICT_TRYING) {
        channel = tr->naptr_record->arg;

        int bitmask = ares_getsock(channel, socks, 16);

        if (bitmask != 0) {
          int num;

          for (num = 0; num < ARES_GETSOCK_MAXNUM; num++) {
            struct epoll_event ev;

            memset(&ev, 0, sizeof(struct epoll_event));

            if (socks[num] == ARES_SOCKET_BAD)
              continue;

            ev.events = EPOLLIN;

            if (ARES_GETSOCK_READABLE(bitmask, num)) {
              ev.events |= EPOLLIN;

            } else if (ARES_GETSOCK_WRITABLE(bitmask, num)) {
              ev.events |= EPOLLOUT;
            }

            ev.data.fd = socks[num];
            epoll_ctl(excontext->epfd, EPOLL_CTL_ADD, socks[num], &ev);
            cares_fd_table[pos_fd] = socks[num];
            pos_fd++;
          }
        }
      }
    }
    tr = (osip_transaction_t *) osip_list_get_next(&iterator);
  }

  return OSIP_SUCCESS;
}

#define EXOSIP_DNSUTILS_CHECKSOCK_EPOLL_DEFINED
int _eXosip_dnsutils_checksock_epoll(struct eXosip_t *excontext, int nfds) {
  osip_list_iterator_t iterator;
  osip_transaction_t *tr;
  int nbtransaction = 0;

  tr = (osip_transaction_t *) osip_list_get_first(&excontext->j_osip->osip_ict_transactions, &iterator);

  while (osip_list_iterator_has_elem(iterator)) {
    ares_channel channel = NULL;
    if (tr->naptr_record != NULL && tr->naptr_record->arg != NULL) {
      if (tr->state == ICT_CALLING) {
        ares_socket_t socks[16] = {
            ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
            ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
        };
        int num;

        channel = tr->naptr_record->arg;

        int bitmask = ares_getsock(channel, socks, 16);

        if (bitmask != 0) {
          for (num = 0; num < ARES_GETSOCK_MAXNUM; num++) {
            if (ARES_GETSOCK_READABLE(bitmask, num)) {
              int n;
              for (n = 0; n < nfds; ++n) {
                if (excontext->ep_array[n].data.fd == socks[num]) {
                  if (excontext->ep_array[n].events & EPOLLIN) {
                    // proceed with timer A
                    osip_gettimeofday(&tr->ict_context->timer_a_start, NULL);
                    add_gettimeofday(&tr->ict_context->timer_a_start, 0);
                    nbtransaction++;
                  }
                }
              }
            } else if (ARES_GETSOCK_WRITABLE(bitmask, num)) {
              int n;
              for (n = 0; n < nfds; ++n) {
                if (excontext->ep_array[n].data.fd == socks[num]) {
                  if (excontext->ep_array[n].events & EPOLLOUT) {
                    // proceed with timer A
                    osip_gettimeofday(&tr->ict_context->timer_a_start, NULL);
                    add_gettimeofday(&tr->ict_context->timer_a_start, 0);
                    nbtransaction++;
                  }
                }
              }
            }
          }
        }
      }
    }
    tr = (osip_transaction_t *) osip_list_get_next(&iterator);
  }

  tr = (osip_transaction_t *) osip_list_get_first(&excontext->j_osip->osip_nict_transactions, &iterator);

  while (osip_list_iterator_has_elem(iterator)) {
    ares_channel channel = NULL;
    if (tr->naptr_record != NULL && tr->naptr_record->arg != NULL) {
      if (tr->state == NICT_TRYING) {
        ares_socket_t socks[16] = {
            ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
            ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
        };
        int num;

        channel = tr->naptr_record->arg;

        int bitmask = ares_getsock(channel, socks, 16);

        if (bitmask != 0) {
          for (num = 0; num < ARES_GETSOCK_MAXNUM; num++) {
            if (ARES_GETSOCK_READABLE(bitmask, num)) {
              int n;
              for (n = 0; n < nfds; ++n) {
                if (excontext->ep_array[n].data.fd == socks[num]) {
                  if (excontext->ep_array[n].events & EPOLLIN) {
                    // proceed with timer E
                    osip_gettimeofday(&tr->nict_context->timer_e_start, NULL);
                    add_gettimeofday(&tr->nict_context->timer_e_start, 0);
                    nbtransaction++;
                  }
                }
              }

            } else if (ARES_GETSOCK_WRITABLE(bitmask, num)) {
              int n;
              for (n = 0; n < nfds; ++n) {
                if (excontext->ep_array[n].data.fd == socks[num]) {
                  if (excontext->ep_array[n].events & EPOLLOUT) {
                    // proceed with timer E
                    osip_gettimeofday(&tr->nict_context->timer_e_start, NULL);
                    add_gettimeofday(&tr->nict_context->timer_e_start, 0);
                    nbtransaction++;
                  }
                }
              }
            }
          }
        }
      }
    }
    tr = (osip_transaction_t *) osip_list_get_next(&iterator);
  }

  return nbtransaction;
}

#define EXOSIP_DNSUTILS_DELSOCK_EPOLL_DEFINED
int _eXosip_dnsutils_delsock_epoll(struct eXosip_t *excontext, int *cares_fd_table) {
  int idx;
  int i;
  char eb[ERRBSIZ];

  for (idx = 0; idx < EXOSIP_MAX_SOCKETS; idx++) {
    if (cares_fd_table[idx] > 0) {
      struct epoll_event ev;
      memset(&ev, 0, sizeof(struct epoll_event));
      i = epoll_ctl(excontext->epfd, EPOLL_CTL_DEL, cares_fd_table[idx], &ev);
      if (i < 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [epoll] cares sock not removed %s\n", _ex_strerror(errno, eb, ERRBSIZ)));
      }
    }
  }
  return OSIP_SUCCESS;
}

#endif

#define EXOSIP_DNSUTILS_GETSOCK_DEFINED
int _eXosip_dnsutils_getsock(struct eXosip_t *excontext, fd_set *read_fds, fd_set *write_fds) {
  osip_list_iterator_t iterator;
  osip_transaction_t *tr;
  int nfds = 0;
  int max = 0;
  tr = (osip_transaction_t *) osip_list_get_first(&excontext->j_osip->osip_ict_transactions, &iterator);

  while (osip_list_iterator_has_elem(iterator)) {
    ares_channel channel = NULL;
    if (tr->naptr_record != NULL && tr->naptr_record->arg != NULL) {
      if (tr->state == ICT_CALLING) {
        channel = tr->naptr_record->arg;
        nfds = ares_fds(channel, read_fds, write_fds);
        if (nfds > max)
          max = nfds;
      }
    }
    tr = (osip_transaction_t *) osip_list_get_next(&iterator);
  }

  tr = (osip_transaction_t *) osip_list_get_first(&excontext->j_osip->osip_nict_transactions, &iterator);

  while (osip_list_iterator_has_elem(iterator)) {
    ares_channel channel = NULL;
    if (tr->naptr_record != NULL && tr->naptr_record->arg != NULL) {
      if (tr->state == NICT_TRYING) {
        channel = tr->naptr_record->arg;
        nfds = ares_fds(channel, read_fds, write_fds);
        if (nfds > max)
          max = nfds;
      }
    }
    tr = (osip_transaction_t *) osip_list_get_next(&iterator);
  }

  return max;
}

#define EXOSIP_DNSUTILS_CHECKSOCK_DEFINED
int _eXosip_dnsutils_checksock(struct eXosip_t *excontext, fd_set *read_fds, fd_set *write_fds) {
  osip_list_iterator_t iterator;
  osip_transaction_t *tr;
  int nbtransaction = 0;

  tr = (osip_transaction_t *) osip_list_get_first(&excontext->j_osip->osip_ict_transactions, &iterator);

  while (osip_list_iterator_has_elem(iterator)) {
    ares_channel channel = NULL;
    if (tr->naptr_record != NULL && tr->naptr_record->arg != NULL) {
      if (tr->state == ICT_CALLING) {
        ares_socket_t socks[16] = {
            ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
            ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
        };
        int num;

        channel = tr->naptr_record->arg;

        int bitmask = ares_getsock(channel, socks, 16);

        if (bitmask != 0) {
          for (num = 0; num < ARES_GETSOCK_MAXNUM; num++) {
            if (ARES_GETSOCK_READABLE(bitmask, num)) {
              if (FD_ISSET(socks[num], read_fds)) {
                // WAKE UP TRANSACTION
                nbtransaction++;
                osip_gettimeofday(&tr->ict_context->timer_a_start, NULL);
                add_gettimeofday(&tr->ict_context->timer_a_start, 0);
              }

            } else if (ARES_GETSOCK_WRITABLE(bitmask, num)) {
              if (FD_ISSET(socks[num], write_fds)) {
                // WAKE UP TRANSACTION
                nbtransaction++;
                osip_gettimeofday(&tr->ict_context->timer_a_start, NULL);
                add_gettimeofday(&tr->ict_context->timer_a_start, 0);
              }
            }
          }
        }
      }
    }
    tr = (osip_transaction_t *) osip_list_get_next(&iterator);
  }

  tr = (osip_transaction_t *) osip_list_get_first(&excontext->j_osip->osip_nict_transactions, &iterator);

  while (osip_list_iterator_has_elem(iterator)) {
    ares_channel channel = NULL;
    if (tr->naptr_record != NULL && tr->naptr_record->arg != NULL) {
      if (tr->state == NICT_TRYING) {
        ares_socket_t socks[16] = {
            ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
            ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD, ARES_SOCKET_BAD,
        };
        int num;

        channel = tr->naptr_record->arg;

        int bitmask = ares_getsock(channel, socks, 16);

        if (bitmask != 0) {
          for (num = 0; num < ARES_GETSOCK_MAXNUM; num++) {
            if (ARES_GETSOCK_READABLE(bitmask, num)) {
              if (FD_ISSET(socks[num], read_fds)) {
                // proceed with timer E
                osip_gettimeofday(&tr->nict_context->timer_e_start, NULL);
                add_gettimeofday(&tr->nict_context->timer_e_start, 0);
                nbtransaction++;
              }

            } else if (ARES_GETSOCK_WRITABLE(bitmask, num)) {
              if (FD_ISSET(socks[num], write_fds)) {
                // proceed with timer E
                osip_gettimeofday(&tr->nict_context->timer_e_start, NULL);
                add_gettimeofday(&tr->nict_context->timer_e_start, 0);
                nbtransaction++;
              }
            }
          }
        }
      }
    }
    tr = (osip_transaction_t *) osip_list_get_next(&iterator);
  }

  return nbtransaction;
}

static int eXosip_dnsutils_srv_lookup(struct osip_naptr *output_record, const char *dnsserver) {
  ares_channel channel = NULL;
  struct ares_options options;
  int i;

  if (output_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS) {
    /* continue searching if channel exist */
    if (output_record->arg == NULL)
      return OSIP_SUCCESS;

    channel = output_record->arg;
    {
      int nfds;

      nfds = eXosip_dnsutils_cares_process(output_record, channel);

      if (nfds < 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [SRV LOOKUP] select failed [%s SRV]\n", output_record->domain));
        output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;
        return OSIP_UNDEFINED_ERROR;
      }

      if (nfds == 0) {
        /* SRVs finished */
        if (output_record->sipudp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else if (output_record->siptcp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else if (output_record->siptls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else if (output_record->sipdtls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else if (output_record->sipsctp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else {
          if (output_record->sipudp_record.order == 49 && output_record->sipudp_record.preference == 49)
            output_record->naptr_state = OSIP_NAPTR_STATE_NOTSUPPORTED;

          else
            output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;
        }

        output_record->arg = NULL;
        ares_destroy(channel);
        return OSIP_SUCCESS;
      }
    }

    return OSIP_SUCCESS;
  }

  if (output_record->naptr_state != OSIP_NAPTR_STATE_NAPTRDONE)
    return OSIP_SUCCESS;

  if (output_record->sipudp_record.name[0] == '\0' && output_record->siptcp_record.name[0] == '\0' && output_record->siptls_record.name[0] == '\0' && output_record->sipdtls_record.name[0] == '\0' && output_record->sipsctp_record.name[0] == '\0') {
    output_record->naptr_state = OSIP_NAPTR_STATE_NOTSUPPORTED;

    if (output_record->arg != NULL) {
      output_record->arg = NULL;
      ares_destroy(channel);
    }

    return OSIP_SUCCESS;
  }

  if (output_record->arg == NULL) {
    options.timeout = 1500;
    options.tries = 2;

    if (dnsserver != NULL && dnsserver[0] != '\0' && strchr(dnsserver, ',')) {
      options.timeout = 750;
      options.tries = 2;
    }

    options.flags = ARES_FLAG_NOALIASES;
    i = ares_init_options(&channel, &options, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_FLAGS);

    if (i != ARES_SUCCESS) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [SRV LOOKUP] ares_init_options failed [%s SRV]\n", output_record->domain));
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;
      return OSIP_BADPARAMETER;
    }

    if (dnsserver != NULL && dnsserver[0] != '\0') {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [SRV LOOKUP] use dnsserver: [%s SRV]\n", dnsserver));
      i = ares_set_servers_csv(channel, dnsserver);

    } else {
#ifdef ANDROID
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [SRV LOOKUP] revert to [8.8.8.8,8.8.4.4]\n"));
      i = ares_set_servers_csv(channel, "8.8.8.8,8.8.4.4");
#endif
    }

    output_record->arg = channel;

  } else {
    channel = output_record->arg;
  }

  output_record->naptr_state = OSIP_NAPTR_STATE_SRVINPROGRESS;

  if (output_record->sipudp_record.name[0] != '\0' && output_record->sipudp_record.srv_state != OSIP_SRV_STATE_COMPLETED) {
    ares_query(channel, output_record->sipudp_record.name, C_IN, T_SRV, _srv_callback, (void *) output_record);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [SRV LOOKUP] about to ask for [%s SRV]\n", output_record->sipudp_record.name));
  }

  if (output_record->siptcp_record.name[0] != '\0' && output_record->siptcp_record.srv_state != OSIP_SRV_STATE_COMPLETED) {
    ares_query(channel, output_record->siptcp_record.name, C_IN, T_SRV, _srv_callback, (void *) output_record);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [SRV LOOKUP] about to ask for [%s SRV]\n", output_record->siptcp_record.name));
  }

  if (output_record->siptls_record.name[0] != '\0' && output_record->siptls_record.srv_state != OSIP_SRV_STATE_COMPLETED) {
    ares_query(channel, output_record->siptls_record.name, C_IN, T_SRV, _srv_callback, (void *) output_record);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [SRV LOOKUP] about to ask for [%s SRV]\n", output_record->siptls_record.name));
  }

  if (output_record->sipdtls_record.name[0] != '\0' && output_record->sipdtls_record.srv_state != OSIP_SRV_STATE_COMPLETED) {
    ares_query(channel, output_record->sipdtls_record.name, C_IN, T_SRV, _srv_callback, (void *) output_record);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [SRV LOOKUP] about to ask for [%s SRV]\n", output_record->sipdtls_record.name));
  }

  {
    int nfds;

    nfds = eXosip_dnsutils_cares_process(output_record, channel);

    if (nfds < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [SRV LOOKUP] select failed [%s SRV]\n", output_record->domain));
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;
      return OSIP_UNDEFINED_ERROR;
    }

    if (nfds == 0) {
      /* SRVs finished: we assume that one is enough */
      if (output_record->sipudp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
        output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

      else if (output_record->siptcp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
        output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

      else if (output_record->siptls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
        output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

      else if (output_record->sipdtls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
        output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

      else if (output_record->sipsctp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
        output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

      else {
        if (output_record->sipudp_record.order == 49 && output_record->sipudp_record.preference == 49)
          output_record->naptr_state = OSIP_NAPTR_STATE_NOTSUPPORTED;

        else
          output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;
      }

      output_record->arg = NULL;
      ares_destroy(channel);
      return OSIP_SUCCESS;
    }
  }

  return OSIP_SUCCESS;
}

static int eXosip_dnsutils_naptr_lookup(osip_naptr_t *output_record, const char *domain, const char *dnsserver) {
  ares_channel channel = NULL;
  struct ares_options options;
  int i;

  if (output_record->arg != NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] wrong code path [%s NAPTR]\n", domain));
    return OSIP_UNDEFINED_ERROR;
  }

  output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

  if (domain == NULL)
    return OSIP_BADPARAMETER;

  if (strlen(domain) > 512)
    return OSIP_BADPARAMETER;

  snprintf(output_record->domain, sizeof(output_record->domain), "%s", domain);

  options.timeout = 1500;
  options.tries = 2;

  if (dnsserver != NULL && dnsserver[0] != '\0' && strchr(dnsserver, ',')) {
    options.timeout = 750;
    options.tries = 2;
  }

  options.flags = ARES_FLAG_NOALIASES;
  i = ares_init_options(&channel, &options, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_FLAGS);

  if (i != ARES_SUCCESS) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] ares_init_options failed [%s NAPTR]\n", domain));
    return OSIP_BADPARAMETER;
  }

  if (dnsserver != NULL && dnsserver[0] != '\0') {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [NAPTR LOOKUP] use dnsserver: [%s NAPTR]\n", dnsserver));
    i = ares_set_servers_csv(channel, dnsserver);

  } else {
#ifdef ANDROID
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [NAPTR LOOKUP] revert to 8.8.8.8,8.8.4.4\n"));
    i = ares_set_servers_csv(channel, "8.8.8.8,8.8.4.4");
#endif
  }

  output_record->arg = channel;
  output_record->naptr_state = OSIP_NAPTR_STATE_INPROGRESS;
  ares_query(channel, domain, C_IN, T_NAPTR, _naptr_callback, (void *) output_record);

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] about to ask for [%s NAPTR]\n", domain));

  {
    int nfds;

    nfds = eXosip_dnsutils_cares_process(output_record, channel);

    if (nfds < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] select failed [%s NAPTR]\n", domain));
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;
      return OSIP_UNDEFINED_ERROR;
    }

    if (nfds == 0) {
      if (output_record->naptr_state != OSIP_NAPTR_STATE_NAPTRDONE) {
        /* don't need channel any more */
        ares_destroy(channel);
        output_record->arg = NULL;
      }

      return OSIP_SUCCESS;
    }
  }

  return OSIP_SUCCESS;
}

struct osip_naptr *eXosip_dnsutils_naptr(struct eXosip_t *excontext, const char *_domain, const char *protocol, const char *transport, int keep_in_cache) {
  osip_list_iterator_t it;
  struct osip_naptr *naptr_record;
  int i;

#if defined(HAVE_WINDNS_H)
  DNS_STATUS err;
  DWORD buf_length = 0;
  IP4_ARRAY *dns_servers;
#endif
  int not_in_list = 0;

  char domain[NI_MAXHOST * 2];
  char AUS[64]; /* number with + prefix and only digits */
  char dnsserver[NI_MAXHOST];
  char *delim_aus;
  char *delim_dnsserver;

  if (_domain == NULL)
    return NULL;

  memset(domain, 0, sizeof(domain));
  memset(AUS, 0, sizeof(AUS));
  memset(dnsserver, 0, sizeof(dnsserver));
  delim_aus = strchr(_domain, '!');

  if (delim_aus != NULL && delim_aus[1] != '\0') {
    /* this is an enum NAPTR with AUS after '!' */
    /* example: enum.enumer.org!+123456789 */
    size_t idx;
    size_t idx_domain = 0;
    size_t idx_AUS = 0;
    size_t aus_length;

    delim_aus++;
    delim_dnsserver = strchr(delim_aus, '!');
    aus_length = strlen(delim_aus);

    if (delim_dnsserver != NULL)
      aus_length = delim_dnsserver - delim_aus;

    if (delim_dnsserver != NULL && delim_dnsserver[1] != '\0') {
      delim_dnsserver++;
      snprintf(dnsserver, sizeof(dnsserver), "%s", delim_dnsserver);
    }

    for (idx = 0; idx + 1 <= aus_length; idx++) {
      if (delim_aus[idx] == '+' || isdigit(delim_aus[idx])) {
        AUS[idx_AUS] = delim_aus[idx];
        idx_AUS++;
      }
    }

    AUS[idx_AUS] = '\0';

    for (idx = 0; idx + 1 <= aus_length; idx++) {
      if (isdigit(delim_aus[aus_length - idx - 1])) {
        domain[idx_domain] = delim_aus[aus_length - idx - 1];
        idx_domain++;
        domain[idx_domain] = '.';
        idx_domain++;
      }
    }

    domain[idx_domain] = '\0';
    snprintf(domain + idx_domain, delim_aus - _domain, "%s", _domain);

  } else if (delim_aus != NULL && delim_aus[1] == '\0') {
    snprintf(domain, delim_aus - _domain + 1, "%s", _domain);

  } else {
    delim_aus = NULL;
    snprintf(domain, sizeof(domain), "%s", _domain);
  }

  if (dnsutils_list == NULL) {
    dnsutils_list = (osip_list_t *) osip_malloc(sizeof(osip_list_t));
    osip_list_init(dnsutils_list);

    i = ares_library_init(ARES_LIB_INIT_ALL);

    if (i != ARES_SUCCESS) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] ares cannot be initialized\n"));
      return NULL;
    }
  }

  if (keep_in_cache < 0) {
    naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

    while (naptr_record != NULL) {
      if (osip_strcasecmp(domain, naptr_record->domain) == 0) {
        if (naptr_record->naptr_state == OSIP_NAPTR_STATE_RETRYLATER)
          break;

        if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NOTSUPPORTED)
          break;

        return naptr_record;
      }

      naptr_record = NULL;

      if (it.pos == 9)
        break;

      naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
    }

    return NULL;
  }

#if defined(HAVE_WINDNS_H)
  err = DnsQueryConfig(DnsConfigDnsServerList, 0, NULL, NULL, NULL, &buf_length);

  if (err == DNS_ERROR_NO_DNS_SERVERS) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] no dns server configured\n"));
    return NULL;
  }

  if (err != ERROR_MORE_DATA && err != 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] error with DnsQueryConfig / DnsConfigDnsServerList\n"));
    return NULL;
  }

  dns_servers = osip_malloc(buf_length);
  err = DnsQueryConfig(DnsConfigDnsServerList, 0, NULL, NULL, dns_servers, &buf_length);

  if (err != 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] error with DnsQueryConfig / DnsConfigDnsServerList\n"));
    osip_free(dns_servers);
    return NULL;
  }

  if (dns_servers->AddrCount == 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] no dns server configured\n"));
    osip_free(dns_servers);
    return NULL;
  }

  for (i = 0; (DWORD) i < dns_servers->AddrCount; i++) {
    char ipaddress[512];
    DWORD val = dns_servers->AddrArray[i];

    snprintf(ipaddress, sizeof(ipaddress), "%d.%d.%d.%d", (val >> 0) & 0x000000FF, (val >> 8) & 0x000000FF, (val >> 16) & 0x000000FF, (val >> 24) & 0x000000FF);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] dns server [%i] [%s]\n", i, ipaddress));
  }

  osip_free(dns_servers);
#endif

  naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

  while (naptr_record != NULL) {
    /* process all */
    if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
      eXosip_dnsutils_srv_lookup(naptr_record, dnsserver);

    naptr_record = NULL;

    if (it.pos == 9)
      break;

    naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
  }

  it.pos = 0;
  naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

  while (naptr_record != NULL) {
    if (osip_strcasecmp(domain, naptr_record->domain) == 0) {
      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_RETRYLATER)
        break;

      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
        eXosip_dnsutils_srv_lookup(naptr_record, dnsserver);

      return naptr_record;
    }

    naptr_record = NULL;

    if (it.pos == 9)
      break;

    naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
  }

  if (it.pos == 9 && keep_in_cache > 0) {
    /* no NAPTR found within the last 10 NAPTR : refuse to keep in cache... */
    /* If we were adding unlimited NAPTR record into the cache, the program
       would infinitly increase memory usage. If you reach there, then you
       most probably don't use the API correctly: Only NAPTR related to
       registration will end up in the cache. So in theory, 10 NAPTR will be
       cached for 10 accounts, which seems enough for a softphone. Then all
       SIP message should go through the same proxy by using a pre-route set.
       Correctly using the API will definitly send out-of-dialog SIP message
       to the same proxy as the REGISTER. If you have issue with in-dialog
       Request or Response and NAPTR, that means your proxy is not following
       guidelines from the rfc3261 and rfc3263 where proxy should specify
       port numbers when they want you to resolve the host as a A record
       -and then avoid NAPTR-.
     */
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] time will tell how much you go there [%s] - it's wrong code path, fix it\n", domain));

    keep_in_cache = 0;

    naptr_record = (osip_naptr_t *) osip_malloc(sizeof(osip_naptr_t));
    memset(naptr_record, 0, sizeof(osip_naptr_t));
    naptr_record->keep_in_cache = keep_in_cache;
    snprintf(naptr_record->AUS, sizeof(naptr_record->AUS), "%s", AUS);

  } else if (naptr_record == NULL) {
    naptr_record = (osip_naptr_t *) osip_malloc(sizeof(osip_naptr_t));
    memset(naptr_record, 0, sizeof(osip_naptr_t));
    naptr_record->keep_in_cache = keep_in_cache;
    not_in_list = 1;
    snprintf(naptr_record->AUS, sizeof(naptr_record->AUS), "%s", AUS);

  } else {
    /* it was found, so it WAS in cache before, but we were in "retry" state */
    memset(naptr_record, 0, sizeof(osip_naptr_t));
    naptr_record->keep_in_cache = 1;
    snprintf(naptr_record->AUS, sizeof(naptr_record->AUS), "%s", AUS);
  }

  i = eXosip_dnsutils_naptr_lookup(naptr_record, domain, dnsserver);

  if (i < 0) {
    if (keep_in_cache <= 0) {
      return naptr_record;
    }

    if (not_in_list == 1) {
      osip_list_add(dnsutils_list, naptr_record, -1);
    }

    return naptr_record;
  }

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
    eXosip_dnsutils_srv_lookup(naptr_record, dnsserver);

  if (keep_in_cache <= 0) {
    return naptr_record;
  }

  if (not_in_list == 1)
    osip_list_add(dnsutils_list, naptr_record, -1);

  return naptr_record;
}

#define EXOSIP_DNSUTILS_DNS_PROCESS
int eXosip_dnsutils_dns_process(osip_naptr_t *naptr_record, int force) {
  ares_channel channel = NULL;

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
    eXosip_dnsutils_srv_lookup(naptr_record, NULL);

  if (naptr_record->arg != NULL)
    channel = naptr_record->arg;

  if (channel == NULL)
    return OSIP_SUCCESS;

  /* in "keep_in_cache" use-case (REGISTER), we delayed completion. */
  for (;;) {
    int nfds;

    nfds = eXosip_dnsutils_cares_process(naptr_record, channel);

    if (nfds < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [SRV LOOKUP] select failed ('%s')\n", naptr_record->domain));
      return OSIP_UNDEFINED_ERROR;
    }

    if (nfds == 0) {
      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS) {
        /* missing SRV */
        eXosip_dnsutils_srv_lookup(naptr_record, NULL);

        if (naptr_record->arg == NULL) /* FIX: success: eXosip_dnsutils_srv_lookup has destroyed channel already. */
          return OSIP_SUCCESS;

      } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_INPROGRESS) {
        if (naptr_record->sipudp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          naptr_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else if (naptr_record->siptcp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          naptr_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else if (naptr_record->siptls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          naptr_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else if (naptr_record->sipdtls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          naptr_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else if (naptr_record->sipsctp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
          naptr_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

        else
          naptr_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

        /* no need any more */
        naptr_record->arg = NULL;
        ares_destroy(channel);
        return OSIP_SUCCESS;

      } else {
        /* no need any more */
        naptr_record->arg = NULL;
        ares_destroy(channel);
        return OSIP_SUCCESS;
      }
    }

    if (force <= 0)
      break;
  }

  return OSIP_SUCCESS;
}

#define EXOSIP_DNSUTILS_RELEASE
void eXosip_dnsutils_release(struct osip_naptr *naptr_record) {
  ares_channel channel;

  if (naptr_record == NULL)
    return;

  if (naptr_record->keep_in_cache > 0)
    return;

  if (naptr_record->arg != NULL) {
    channel = naptr_record->arg;
    ares_destroy(channel);
    naptr_record->arg = NULL;
  }

  osip_free(naptr_record);
}

#endif

#if !defined(EXOSIP_DNSUTILS_DEFINED) && (defined(WIN32) && !defined(_WIN32_WCE))
#define EXOSIP_DNSUTILS_DEFINED

static int _eXosip_dnsutils_srv_lookup(struct osip_srv_record *output_srv) {
  PDNS_RECORD answer; /* answer buffer from nameserver */
  PDNS_RECORDA tmp;   /* even in UNICODE, DnsQuery_UTF8 returns in UT8, not unicode */
  int n;

  if (output_srv->name[0] == '\0') {
    return OSIP_SUCCESS;
  }

  if (output_srv->srventry[0].srv[0] != '\0') {
    /* if we received the SRV inside the NAPTR answer, are we sure we received
       all SRV entries? */
    return OSIP_SUCCESS;
  }

  if (DnsQuery_UTF8(output_srv->name, DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL, &answer, NULL) != 0) {
    return OSIP_UNKNOWN_HOST;
  }

  n = 0;

  for (tmp = (PDNS_RECORDA) answer; tmp != NULL; tmp = tmp->pNext) {
    struct osip_srv_entry *srventry;

    DNS_SRV_DATAA *data;

    if (tmp->wType != DNS_TYPE_SRV)
      continue;

    srventry = &output_srv->srventry[n];
    data = &tmp->Data.SRV;
    snprintf(srventry->srv, sizeof(srventry->srv), "%s", data->pNameTarget);

    srventry->priority = data->wPriority;
    srventry->weight = data->wWeight;

    if (srventry->weight)
      srventry->rweight = 1 + rand() % (10000 * srventry->weight);

    else
      srventry->rweight = 0;

    srventry->port = data->wPort;

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [save_SRV record] [%s] IN SRV -> [%s/%i/%i/%i/%i]\n", output_srv->name, srventry->srv, srventry->port, srventry->priority, srventry->weight, srventry->rweight));

    output_srv->srv_state = OSIP_SRV_STATE_COMPLETED;

    n++;

    if (n == 10)
      break;
  }

  DnsRecordListFree(answer, DnsFreeRecordList);

  if (n == 0)
    return OSIP_UNKNOWN_HOST;

  osip_srv_record_sort(output_srv, n);
  return OSIP_SUCCESS;
}

int eXosip_dnsutils_srv_lookup(struct osip_naptr *output_record, const char *dnsserver) {
  if (output_record->naptr_state == OSIP_NAPTR_STATE_SRVDONE)
    return OSIP_SUCCESS;

  output_record->sipudp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->siptcp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->siptls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->sipdtls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->sipsctp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;

  _eXosip_dnsutils_srv_lookup(&output_record->sipudp_record);
  _eXosip_dnsutils_srv_lookup(&output_record->siptcp_record);
  _eXosip_dnsutils_srv_lookup(&output_record->siptls_record);
  _eXosip_dnsutils_srv_lookup(&output_record->sipdtls_record);
  /* _eXosip_dnsutils_srv_lookup(&output_record->sipsctp_record); */

  if (output_record->sipudp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else if (output_record->siptcp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else if (output_record->siptls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else if (output_record->sipdtls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else if (output_record->sipsctp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else
    output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

  return 0;
}

int _eX_dn_expand(unsigned char *msg, unsigned char *eomorig, unsigned char *comp_dn, unsigned char *exp_dn, int length) {
  unsigned char *cp;
  unsigned char *dest;
  unsigned char *eom;
  int len = -1;
  int len_copied = 0;

  dest = exp_dn;
  cp = comp_dn;
  eom = exp_dn + length;

  while (*cp != '\0') {
    int w = *cp;
    int comp = w & 0xc0;

    cp++;

    if (comp == 0) {
      if (dest != exp_dn) {
        if (dest >= eom)
          return -1;

        *dest = '.';
        dest++;
      }

      if (dest + w >= eom)
        return -1;

      len_copied++;
      len_copied = len_copied + w;
      w--;

      for (; w >= 0; w--, cp++) {
        if ((*cp == '.') || (*cp == '\\')) {
          if (dest + w + 2 >= eom)
            return -1;

          *dest = '\\';
          dest++;
        }

        *dest = *cp;
        dest++;

        if (cp >= eomorig)
          return -1;
      }

    } else if (comp == 0xc0) {
      if (len < 0)
        len = cp - comp_dn + 1;

      cp = msg + (((w & 0x3f) << 8) | (*cp & 0xff));

      if (cp < msg || cp >= eomorig)
        return -1;

      len_copied = len_copied + 2;

      if (len_copied >= eomorig - msg)
        return -1;

    } else
      return -1;
  }

  *dest = '\0';

  if (len < 0)
    len = cp - comp_dn;

  return len;
}

static int eXosip_dnsutils_naptr_lookup(osip_naptr_t *output_record, const char *domain, const char *dnsserver) {
  PDNS_RECORD answer; /* answer buffer from nameserver */
  PDNS_RECORDA tmp;   /* even in UNICODE, DnsQuery_UTF8 returns in UT8, not unicode */
  DNS_STATUS ret;

  if (domain == NULL)
    return OSIP_BADPARAMETER;

  if (strlen(domain) > 512)
    return OSIP_BADPARAMETER;

  snprintf(output_record->domain, sizeof(output_record->domain), "%s", domain);

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] about to ask for [%s NAPTR]\n", domain));

  ret = DnsQuery_UTF8(domain, DNS_TYPE_NAPTR, DNS_QUERY_STANDARD, NULL, &answer, NULL);

  if (ret == DNS_ERROR_NO_DNS_SERVERS)
    return OSIP_NO_NETWORK;

  if (ret == ERROR_TIMEOUT)
    return OSIP_TIMEOUT;

  if (ret == DNS_INFO_NO_RECORDS)
    return OSIP_UNKNOWN_HOST;

  if (ret == DNS_ERROR_RCODE_SERVER_FAILURE)
    return OSIP_NOTFOUND; /* no such domain? */

  if (ret != 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] DnsQuery failed for [%s NAPTR] [%d]\n", domain, ret));
    return OSIP_UNDEFINED_ERROR;
  }

  for (tmp = (PDNS_RECORDA) answer; tmp != NULL; tmp = tmp->pNext) {
    char *buf = (char *) &tmp->Data;

    int len;
    OSVERSIONINFOEX ovi;
    osip_srv_record_t srvrecord;

    if (tmp->wType != DNS_TYPE_NAPTR)
      continue;

    memset(&srvrecord, 0, sizeof(osip_srv_record_t));
    memset(&ovi, 0, sizeof(ovi));
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    GetVersionEx((LPOSVERSIONINFO) &ovi);

    /* Minimum: client: Windows 2000 Professional */
    /* Minimum: server: Windows 2000 Server */
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] check OS support for NAPTR [v=%i.%i.%i]\n", ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber));

    if (ovi.dwMajorVersion > 5) {
#if (_WIN32_WINNT >= 0x0600)
      /* RUN only on Vista? */
      /* compile starting from SDK 6.0A? even on XP... */
      srvrecord.order = tmp->Data.NAPTR.wOrder;
      srvrecord.preference = tmp->Data.NAPTR.wPreference;
      strncpy(srvrecord.protocol, tmp->Data.NAPTR.pService, sizeof(srvrecord.protocol) - 1);
      strncpy(srvrecord.regexp, tmp->Data.NAPTR.pRegularExpression, sizeof(srvrecord.regexp) - 1);
      strncpy(srvrecord.replacement, tmp->Data.NAPTR.pReplacement, sizeof(srvrecord.replacement) - 1);
      strncpy(srvrecord.flag, tmp->Data.NAPTR.pFlags, sizeof(srvrecord.flag) - 1);
#endif

    } else {
      memcpy((void *) &srvrecord.order, buf, 2);
      srvrecord.order = ntohs(srvrecord.order); /* ((unsigned short)buf[0] << 8) | ((unsigned short)buf[1]); */
      buf += sizeof(unsigned short);
      memcpy((void *) &srvrecord.preference, buf, 2);
      srvrecord.preference = ntohs(srvrecord.preference); /* ((unsigned short)buf[0] << 8) | ((unsigned short)buf[1]); */
      buf += sizeof(unsigned short);

      len = *buf;

      if (len < 0 || len > 255)
        break;

      buf++;
      strncpy(srvrecord.flag, buf, len);
      srvrecord.flag[len] = '\0';
      buf += len;

      len = *buf;

      if (len < 0 || len > 1023)
        break;

      buf++;
      strncpy(srvrecord.protocol, buf, len);
      srvrecord.protocol[len] = '\0';
      buf += len;

      len = *buf;

      if (len < 0 || len > 1023)
        break;

      buf++;
      strncpy(srvrecord.regexp, buf, len);
      srvrecord.regexp[len] = '\0';
      buf += len;

      len = _eX_dn_expand((char *) &tmp->Data, ((char *) &tmp->Data) + tmp->wDataLength, buf, srvrecord.replacement, 1024 - 1);

      if (len < 0)
        break;

      buf += len;
    }

    if (srvrecord.flag[0] == 's' || srvrecord.flag[0] == 'S') {
      snprintf(srvrecord.name, sizeof(srvrecord.name), "%s", srvrecord.replacement);
    }

    if (srvrecord.flag[0] == 'a' || srvrecord.flag[0] == 'A') {
      snprintf(srvrecord.name, sizeof(srvrecord.name), "%s", srvrecord.replacement);
    }

    if (srvrecord.flag[0] == 'u' || srvrecord.flag[0] == 'U') {
      naptr_enum_match_and_replace(output_record, &srvrecord);
    }

    srvrecord.srv_state = OSIP_SRV_STATE_UNKNOWN;

    if (osip_strncasecmp(srvrecord.name, "_sip._udp.", 10) == 0 || osip_strncasecmp(srvrecord.protocol, "SIP+D2U", 8) == 0) { /* udp */
      memcpy(&output_record->sipudp_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.name, "_sip._tcp.", 10) == 0 || osip_strncasecmp(srvrecord.protocol, "SIP+D2T", 8) == 0) { /* tcp */
      memcpy(&output_record->siptcp_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.protocol, "SIPS+D2T", 9) == 0) { /* tls */
      memcpy(&output_record->siptls_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.protocol, "SIPS+D2U", 9) == 0) { /* dtls-udp */
      memcpy(&output_record->sipdtls_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.protocol, "SIP+D2S", 8) == 0) { /* sctp */
      memcpy(&output_record->sipsctp_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.protocol, "E2U+SIP", 8) == 0 || osip_strncasecmp(srvrecord.protocol, "SIP+E2U", 8) == 0) { /* enum result // SIP+E2U is from rfc2916 and obsolete */
      srvrecord.srv_state = OSIP_SRV_STATE_COMPLETED;
      memcpy(&output_record->sipenum_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [save_NAPTR record] [%s] -> [%i][%i][%s][%s][%s]\n", output_record->domain, srvrecord.order, srvrecord.preference, srvrecord.protocol, srvrecord.regexp, srvrecord.name));
  }

  for (tmp = (PDNS_RECORDA) answer; tmp != NULL; tmp = tmp->pNext) {
    struct osip_srv_entry *srventry;
    struct osip_srv_record *srvrecord;
    DNS_SRV_DATAA *data;
    int n;

    if (tmp->wType != DNS_TYPE_SRV)
      continue;

    if (osip_strcasecmp(tmp->pName, output_record->sipudp_record.name) == 0)
      srvrecord = &output_record->sipudp_record;

    else if (osip_strcasecmp(tmp->pName, output_record->siptcp_record.name) == 0)
      srvrecord = &output_record->siptcp_record;

    else if (osip_strcasecmp(tmp->pName, output_record->siptls_record.name) == 0)
      srvrecord = &output_record->siptls_record;

    else if (osip_strcasecmp(tmp->pName, output_record->sipdtls_record.name) == 0)
      srvrecord = &output_record->sipdtls_record;

    else if (osip_strcasecmp(tmp->pName, output_record->sipsctp_record.name) == 0)
      srvrecord = &output_record->sipsctp_record;

    else
      continue;

    n = 0;

    while (n < 10 && srvrecord->srventry[n].srv[0] != '\0')
      n++;

    if (n == 10)
      continue; /* skip... */

    srventry = &srvrecord->srventry[n];

    data = &tmp->Data.SRV;
    snprintf(srventry->srv, sizeof(srventry->srv), "%s", data->pNameTarget);

    srventry->priority = data->wPriority;
    srventry->weight = data->wWeight;

    if (srventry->weight)
      srventry->rweight = 1 + rand() % (10000 * srventry->weight);

    else
      srventry->rweight = 0;

    srventry->port = data->wPort;

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [save_SRV record] [%s] IN SRV -> [%s/%i/%i/%i/%i]\n", tmp->pName, srventry->srv, srventry->port, srventry->priority, srventry->weight, srventry->rweight));
    osip_srv_record_sort(srvrecord, n + 1);

    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;
  }

  for (tmp = (PDNS_RECORDA) answer; tmp != NULL; tmp = tmp->pNext) {
    struct osip_srv_entry *srventry;
    DNS_A_DATA *data;
    DWORD val;
    int n;

    if (tmp->wType != DNS_TYPE_A)
      continue;

    data = &tmp->Data.A;

    val = data->IpAddress;

    /* update all SRV bound to this A record. */
    for (n = 0; n < 10; n++) {
      if (osip_strcasecmp(tmp->pName, output_record->sipudp_record.srventry[n].srv) == 0)
        srventry = &output_record->sipudp_record.srventry[n];

      else if (osip_strcasecmp(tmp->pName, output_record->siptcp_record.srventry[n].srv) == 0)
        srventry = &output_record->siptcp_record.srventry[n];

      else if (osip_strcasecmp(tmp->pName, output_record->siptls_record.srventry[n].srv) == 0)
        srventry = &output_record->siptls_record.srventry[n];

      else if (osip_strcasecmp(tmp->pName, output_record->sipdtls_record.srventry[n].srv) == 0)
        srventry = &output_record->sipdtls_record.srventry[n];

      else if (osip_strcasecmp(tmp->pName, output_record->sipsctp_record.srventry[n].srv) == 0)
        srventry = &output_record->sipsctp_record.srventry[n];

      else
        continue;

      snprintf(srventry->ipaddress, sizeof(srventry->ipaddress), "%d.%d.%d.%d", (val >> 0) & 0x000000FF, (val >> 8) & 0x000000FF, (val >> 16) & 0x000000FF, (val >> 24) & 0x000000FF);
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] A record [%s] -> [%d.%d.%d.%d]\n", tmp->pName, (val >> 0) & 0x000000FF, (val >> 8) & 0x000000FF, (val >> 16) & 0x000000FF, (val >> 24) & 0x000000FF));
  }

  DnsRecordListFree(answer, DnsFreeRecordList);

  return OSIP_SUCCESS;
}

struct osip_naptr *eXosip_dnsutils_naptr(struct eXosip_t *excontext, const char *_domain, const char *protocol, const char *transport, int keep_in_cache) {
  osip_list_iterator_t it;
  struct osip_naptr *naptr_record;
  int i;
  DNS_STATUS err;
  DWORD buf_length = 0;
  IP4_ARRAY *dns_servers;
  int not_in_list = 0;

  char domain[NI_MAXHOST * 2];
  char AUS[64]; /* number with + prefix and only digits */
  char dnsserver[NI_MAXHOST];
  char *delim_aus;
  char *delim_dnsserver;

  if (_domain == NULL)
    return NULL;

  memset(domain, 0, sizeof(domain));
  memset(AUS, 0, sizeof(AUS));
  memset(dnsserver, 0, sizeof(dnsserver));
  delim_aus = strchr(_domain, '!');

  if (delim_aus != NULL && delim_aus[1] != '\0') {
    /* this is an enum NAPTR with AUS after '!' */
    /* example: enum.enumer.org!+123456789 */
    size_t idx;
    size_t idx_domain = 0;
    size_t idx_AUS = 0;
    size_t aus_length;

    delim_aus++;
    delim_dnsserver = strchr(delim_aus, '!');
    aus_length = strlen(delim_aus);

    if (delim_dnsserver != NULL)
      aus_length = delim_dnsserver - delim_aus;

    if (delim_dnsserver != NULL && delim_dnsserver[1] != '\0') {
      delim_dnsserver++;
      snprintf(dnsserver, sizeof(dnsserver), "%s", delim_dnsserver);
    }

    for (idx = 0; idx + 1 <= aus_length; idx++) {
      if (delim_aus[idx] == '+' || isdigit(delim_aus[idx])) {
        AUS[idx_AUS] = delim_aus[idx];
        idx_AUS++;
      }
    }

    AUS[idx_AUS] = '\0';

    for (idx = 0; idx + 1 <= aus_length; idx++) {
      if (isdigit(delim_aus[aus_length - idx - 1])) {
        domain[idx_domain] = delim_aus[aus_length - idx - 1];
        idx_domain++;
        domain[idx_domain] = '.';
        idx_domain++;
      }
    }

    domain[idx_domain] = '\0';
    snprintf(domain + idx_domain, delim_aus - _domain, "%s", _domain);

  } else if (delim_aus != NULL && delim_aus[1] == '\0') {
    snprintf(domain, delim_aus - _domain + 1, "%s", _domain);

  } else {
    snprintf(domain, sizeof(domain), "%s", _domain);
  }

  if (dnsutils_list == NULL) {
    dnsutils_list = (osip_list_t *) osip_malloc(sizeof(osip_list_t));
    osip_list_init(dnsutils_list);
  }

  if (keep_in_cache < 0) {
    naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

    while (naptr_record != NULL) {
      if (osip_strcasecmp(domain, naptr_record->domain) == 0) {
        if (naptr_record->naptr_state == OSIP_NAPTR_STATE_RETRYLATER)
          break;

        if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NOTSUPPORTED)
          break;

        return naptr_record;
      }

      naptr_record = NULL;

      if (it.pos == 9)
        break;

      naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
    }

    return NULL;
  }

  err = DnsQueryConfig(DnsConfigDnsServerList, 0, NULL, NULL, NULL, &buf_length);

  if (err == DNS_ERROR_NO_DNS_SERVERS) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] no dns server configured\n"));
    return NULL;
  }

  if (err != ERROR_MORE_DATA && err != 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] error with DnsQueryConfig / DnsConfigDnsServerList\n"));
    return NULL;
  }

  dns_servers = osip_malloc(buf_length);
  err = DnsQueryConfig(DnsConfigDnsServerList, 0, NULL, NULL, dns_servers, &buf_length);

  if (err != 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] error with DnsQueryConfig / DnsConfigDnsServerList\n"));
    osip_free(dns_servers);
    return NULL;
  }

  if (dns_servers->AddrCount == 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] no dns server configured\n"));
    osip_free(dns_servers);
    return NULL;
  }

  for (i = 0; (DWORD) i < dns_servers->AddrCount; i++) {
    char ipaddress[512];
    DWORD val = dns_servers->AddrArray[i];

    snprintf(ipaddress, sizeof(ipaddress), "%d.%d.%d.%d", (val >> 0) & 0x000000FF, (val >> 8) & 0x000000FF, (val >> 16) & 0x000000FF, (val >> 24) & 0x000000FF);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] dns server [%i] [%s]\n", i, ipaddress));
  }

  naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

  while (naptr_record != NULL) {
    /* process all */
    if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
      eXosip_dnsutils_srv_lookup(naptr_record, dnsserver);

    naptr_record = NULL;

    if (it.pos == 9)
      break;

    naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
  }

  it.pos = 0;
  naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

  while (naptr_record != NULL) {
    if (osip_strcasecmp(domain, naptr_record->domain) == 0) {
      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_RETRYLATER)
        break;

      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
        eXosip_dnsutils_srv_lookup(naptr_record, dnsserver);

      return naptr_record;
    }

    naptr_record = NULL;

    if (it.pos == 9)
      break;

    naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
  }

  if (it.pos == 9 && keep_in_cache > 0) {
    /* no NAPTR found within the last 10 NAPTR : refuse to keep in cache... */
    /* If we were adding unlimited NAPTR record into the cache, the program
       would infinitly increase memory usage. If you reach there, then you
       most probably don't use the API correctly: Only NAPTR related to
       registration will end up in the cache. So in theory, 10 NAPTR will be
       cached for 10 accounts, which seems enough for a softphone. Then all
       SIP message should go through the same proxy by using a pre-route set.
       Correctly using the API will definitly send out-of-dialog SIP message
       to the same proxy as the REGISTER. If you have issue with in-dialog
       Request or Response and NAPTR, that means your proxy is not following
       guidelines from the rfc3261 and rfc3263 where proxy should specify
       port numbers when they want you to resolve the host as a A record
       -and then avoid NAPTR-.
     */
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] time will tell how much you go there [%s] - it's wrong code path, fix it\n", domain));

    keep_in_cache = 0;

    naptr_record = (osip_naptr_t *) osip_malloc(sizeof(osip_naptr_t));
    memset(naptr_record, 0, sizeof(osip_naptr_t));
    naptr_record->keep_in_cache = keep_in_cache;
    snprintf(naptr_record->AUS, sizeof(naptr_record->AUS), "%s", AUS);

  } else if (naptr_record == NULL) {
    naptr_record = (osip_naptr_t *) osip_malloc(sizeof(osip_naptr_t));
    memset(naptr_record, 0, sizeof(osip_naptr_t));
    naptr_record->keep_in_cache = keep_in_cache;
    not_in_list = 1;
    snprintf(naptr_record->AUS, sizeof(naptr_record->AUS), "%s", AUS);

  } else {
    /* it was found, so it WAS in cache before, but we were in "retry" state */
    memset(naptr_record, 0, sizeof(osip_naptr_t));
    naptr_record->keep_in_cache = 1;
    snprintf(naptr_record->AUS, sizeof(naptr_record->AUS), "%s", AUS);
  }

  i = eXosip_dnsutils_naptr_lookup(naptr_record, domain, dnsserver);

  if (i < 0) {
    if (keep_in_cache <= 0) {
      return naptr_record;
    }

    if (not_in_list == 1) {
      osip_list_add(dnsutils_list, naptr_record, -1);
    }

    return naptr_record;
  }

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
    eXosip_dnsutils_srv_lookup(naptr_record, dnsserver);

  if (keep_in_cache <= 0) {
    return naptr_record;
  }

  if (not_in_list == 1)
    osip_list_add(dnsutils_list, naptr_record, -1);

  return naptr_record;
}

#endif

#if !defined(EXOSIP_DNSUTILS_DEFINED) && (defined(__linux) || defined(__APPLE_CC__))
#define EXOSIP_DNSUTILS_DEFINED

/* the biggest packet we'll send and receive */
#if PACKETSZ > 1024
#define MAXPACKET PACKETSZ
#else
#define MAXPACKET 1024
#endif

/* and what we send and receive */
typedef union {
  HEADER hdr;
  u_char buf[MAXPACKET];
} querybuf;

#ifndef T_SRV
#define T_SRV 33
#endif

#ifndef T_NAPTR
#define T_NAPTR 35
#endif

static int _eXosip_dnsutils_srv_lookup(struct osip_srv_record *output_srv) {
  querybuf answer; /* answer buffer from nameserver */
  int n;
  int ancount, qdcount; /* answer count and query count */
  HEADER *hp;           /* answer buffer header */
  char hostbuf[256];
  unsigned char *msg, *eom, *cp; /* answer buffer positions */
  int dlen, type, aclass, pref, weight, port;
  long ttl;
  int answerno;

  if (output_srv->name[0] == '\0') {
    return OSIP_SUCCESS;
  }

  if (output_srv->srventry[0].srv[0] != '\0') {
    /* if we received the SRV inside the NAPTR answer, are we sure we received
       all SRV entries? */
    return OSIP_SUCCESS;
  }

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] about to ask for [%s SRV]\n", output_srv->name));

  n = res_query(output_srv->name, C_IN, T_SRV, (unsigned char *) &answer, sizeof(answer));

  if (n < (int) sizeof(HEADER)) {
    return OSIP_UNKNOWN_HOST;
  }

  /* browse message and search for DNS answers part */
  hp = (HEADER *) &answer;
  qdcount = ntohs(hp->qdcount);
  ancount = ntohs(hp->ancount);

  msg = (unsigned char *) (&answer);
  eom = (unsigned char *) (&answer) + n;
  cp = (unsigned char *) (&answer) + sizeof(HEADER);

  while (qdcount-- > 0 && cp < eom) {
    n = dn_expand(msg, eom, cp, (char *) hostbuf, 256);

    if (n < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] invalid SRV record answer for [%s SRV] [bad format]\n", output_srv->name));
      return OSIP_UNDEFINED_ERROR;
    }

    cp += n + QFIXEDSZ;
  }

  /* browse DNS answers */
  answerno = 0;

  /* loop through the answer buffer and extract SRV records */
  while (ancount-- > 0 && cp < eom) {
    struct osip_srv_entry *srventry;

    n = dn_expand(msg, eom, cp, (char *) hostbuf, 256);

    if (n < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] invalid SRV record answer for [%s SRV] [bad format]\n", output_srv->name));
      return OSIP_UNDEFINED_ERROR;
    }

    cp += n;

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    type = _get_short(cp);
    cp += sizeof(u_short);
#elif defined(__APPLE_CC__)
    GETSHORT(type, cp);
#else
    NS_GET16(type, cp);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    aclass = _get_short(cp);
    cp += sizeof(u_short);
#elif defined(__APPLE_CC__)
    aclass++; /* get rid of compiler warning... who cares */
    GETSHORT(aclass, cp);
#else
    aclass++; /* get rid of compiler warning... who cares */
    NS_GET16(aclass, cp);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    ttl = _get_long(cp);
    cp += sizeof(u_long);
#elif defined(__APPLE_CC__)
    ttl++; /* get rid of compiler warning... who cares */
    GETLONG(ttl, cp);
#else
    ttl++; /* get rid of compiler warning... who cares */
    NS_GET32(ttl, cp);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    dlen = _get_short(cp);
    cp += sizeof(u_short);
#elif defined(__APPLE_CC__)
    GETSHORT(dlen, cp);
#else
    NS_GET16(dlen, cp);
#endif

    if (type != T_SRV) {
      cp += dlen;
      continue;
    }

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    pref = _get_short(cp);
    cp += sizeof(u_short);
#elif defined(__APPLE_CC__)
    GETSHORT(pref, cp);
#else
    NS_GET16(pref, cp);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    weight = _get_short(cp);
    cp += sizeof(u_short);
#elif defined(__APPLE_CC__)
    GETSHORT(weight, cp);
#else
    NS_GET16(weight, cp);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    port = _get_short(cp);
    cp += sizeof(u_short);
#elif defined(__APPLE_CC__)
    GETSHORT(port, cp);
#else
    NS_GET16(port, cp);
#endif

    n = dn_expand(msg, eom, cp, (char *) hostbuf, 256);

    if (n < 0)
      break;

    cp += n;

    srventry = &output_srv->srventry[answerno];
    snprintf(srventry->srv, sizeof(srventry->srv), "%s", hostbuf);

    srventry->priority = pref;
    srventry->weight = weight;

    if (weight)
      srventry->rweight = (int) (1 + random() % (10000 * srventry->weight));

    else
      srventry->rweight = 0;

    srventry->port = port;

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [save_SRV record] [%s] IN SRV -> [%s/%i/%i/%i/%i]\n", output_srv->name, srventry->srv, srventry->port, srventry->priority, srventry->weight, srventry->rweight));

    output_srv->srv_state = OSIP_SRV_STATE_COMPLETED;

    answerno++;

    if (answerno == 10)
      break;
  }

  if (answerno == 0)
    return OSIP_UNKNOWN_HOST;

  osip_srv_record_sort(output_srv, answerno);
  return OSIP_SUCCESS;
}

static int eXosip_dnsutils_srv_lookup(struct osip_naptr *output_record, const char *dnsserver) {
  if (output_record->naptr_state == OSIP_NAPTR_STATE_SRVDONE)
    return OSIP_SUCCESS;

  output_record->sipudp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->siptcp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->siptls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->sipdtls_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;
  output_record->sipsctp_record.srv_state = OSIP_SRV_STATE_NOTSUPPORTED;

  _eXosip_dnsutils_srv_lookup(&output_record->sipudp_record);
  _eXosip_dnsutils_srv_lookup(&output_record->siptcp_record);
  _eXosip_dnsutils_srv_lookup(&output_record->siptls_record);
  _eXosip_dnsutils_srv_lookup(&output_record->sipdtls_record);
  /* _eXosip_dnsutils_srv_lookup(&output_record->sipsctp_record); */

  if (output_record->sipudp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else if (output_record->siptcp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else if (output_record->siptls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else if (output_record->sipdtls_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else if (output_record->sipsctp_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  else
    output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

  return 0;
}

static int eXosip_dnsutils_naptr_lookup(osip_naptr_t *output_record, const char *domain, const char *dnsserver) {
  querybuf answer; /* answer buffer from nameserver */
  int n;
  int ancount, qdcount; /* answer count and query count */

  /* int nscount, arcount;         ns count and ar count */
  HEADER *hp; /* answer buffer header */
  char rr_name[512];
  unsigned char *msg, *eom, *cp; /* answer buffer positions */
  int dlen, type, aclass;
  long ttl;
  int answerno;

  output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

  if (domain == NULL)
    return OSIP_BADPARAMETER;

  if (strlen(domain) > 512)
    return OSIP_BADPARAMETER;

  snprintf(output_record->domain, sizeof(output_record->domain), "%s", domain);

  output_record->naptr_state = OSIP_NAPTR_STATE_INPROGRESS;

  n = res_query(domain, C_IN, T_NAPTR, (unsigned char *) &answer, sizeof(answer));

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] about to ask for [%s NAPTR]\n", domain));

  if (n < (int) sizeof(HEADER)) {
    int hstatus = h_errno;

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] res_query failed [%s NAPTR]\n", domain));

    if (hstatus == NO_DATA)
      output_record->naptr_state = OSIP_NAPTR_STATE_NOTSUPPORTED;

    else if (hstatus == HOST_NOT_FOUND)
      output_record->naptr_state = OSIP_NAPTR_STATE_NOTSUPPORTED;

    else
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;

    return OSIP_UNDEFINED_ERROR;
  }

  /* browse message and search for DNS answers part */
  hp = (HEADER *) &answer;
  qdcount = ntohs(hp->qdcount);
  ancount = ntohs(hp->ancount);
  /* nscount = ntohs (hp->ancount); */
  /* arcount = ntohs (hp->arcount); */

  msg = (unsigned char *) (&answer);
  eom = (unsigned char *) (&answer) + n;
  cp = (unsigned char *) (&answer) + sizeof(HEADER);

  while (qdcount-- > 0 && cp < eom) {
    n = dn_expand(msg, eom, cp, (char *) rr_name, 512);

    if (n < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] invalid SRV record answer for [%s NAPTR] [bad format]\n", domain));
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;
      return OSIP_UNDEFINED_ERROR;
    }

    cp += n + QFIXEDSZ;
  }

  /* browse DNS answers */
  answerno = 0;

  /* loop through the answer buffer and extract SRV records */
  while (ancount-- > 0 && cp < eom) {
    int len;
    osip_srv_record_t srvrecord;

    n = dn_expand(msg, eom, cp, (char *) rr_name, 512);

    if (n < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [NAPTR LOOKUP] invalid NAPTR answer for [%s NAPTR] [bad format]\n", domain));
      output_record->naptr_state = OSIP_NAPTR_STATE_RETRYLATER;
      return OSIP_UNDEFINED_ERROR;
    }

    cp += n;

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    type = _get_short(cp);
    cp += sizeof(u_short);
#elif defined(__APPLE_CC__)
    GETSHORT(type, cp);
#else
    NS_GET16(type, cp);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    aclass = _get_short(cp);
    cp += sizeof(u_short);
#elif defined(__APPLE_CC__)
    aclass++; /* get rid of compiler warning... who cares */
    GETSHORT(aclass, cp);
#else
    aclass++; /* get rid of compiler warning... who cares */
    NS_GET16(aclass, cp);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    ttl = _get_long(cp);
    cp += sizeof(u_long);
#elif defined(__APPLE_CC__)
    ttl++; /* get rid of compiler warning... who cares */
    GETLONG(ttl, cp);
#else
    ttl++; /* get rid of compiler warning... who cares */
    NS_GET32(ttl, cp);
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(OLD_NAMESER) || defined(__FreeBSD__)
    dlen = _get_short(cp);
    cp += sizeof(u_short);
#elif defined(__APPLE_CC__)
    GETSHORT(dlen, cp);
#else
    NS_GET16(dlen, cp);
#endif

    if (type != T_NAPTR) {
      cp += dlen;
      continue;
    }

    memset(&srvrecord, 0, sizeof(osip_srv_record_t));

    memcpy((void *) &srvrecord.order, cp, 2);
    srvrecord.order = ntohs(srvrecord.order); /*((unsigned short)cp[0] << 8) | ((unsigned short)cp[1]); */
    cp += sizeof(unsigned short);
    memcpy((void *) &srvrecord.preference, cp, 2);
    srvrecord.preference = ntohs(srvrecord.preference); /* ((unsigned short)cp[0] << 8) | ((unsigned short)cp[1]); */
    cp += sizeof(unsigned short);

    len = *cp;
    cp++;
    strncpy(srvrecord.flag, (char *) cp, len);
    srvrecord.flag[len] = '\0';
    cp += len;

    len = *cp;
    cp++;
    strncpy(srvrecord.protocol, (char *) cp, len);
    srvrecord.protocol[len] = '\0';
    cp += len;

    len = *cp;
    cp++;
    strncpy(srvrecord.regexp, (char *) cp, len);
    srvrecord.regexp[len] = '\0';
    cp += len;

    n = dn_expand(msg, eom, cp, srvrecord.replacement, 1024 - 1);

    if (n < 0)
      break;

    cp += n;

    if (srvrecord.flag[0] == 's' || srvrecord.flag[0] == 'S') {
      snprintf(srvrecord.name, sizeof(srvrecord.name), "%s", srvrecord.replacement);
    }

    if (srvrecord.flag[0] == 'a' || srvrecord.flag[0] == 'A') {
      snprintf(srvrecord.name, sizeof(srvrecord.name), "%s", srvrecord.replacement);
    }

    if (srvrecord.flag[0] == 'u' || srvrecord.flag[0] == 'U') {
      naptr_enum_match_and_replace(output_record, &srvrecord);
    }

    srvrecord.srv_state = OSIP_SRV_STATE_UNKNOWN;

    if (osip_strncasecmp(srvrecord.name, "_sip._udp.", 10) == 0 || osip_strncasecmp(srvrecord.protocol, "SIP+D2U", 8) == 0) { /* udp */
      memcpy(&output_record->sipudp_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.name, "_sip._tcp.", 10) == 0 || osip_strncasecmp(srvrecord.protocol, "SIP+D2T", 8) == 0) { /* tcp */
      memcpy(&output_record->siptcp_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.protocol, "SIPS+D2T", 9) == 0) { /* tls */
      memcpy(&output_record->siptls_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.protocol, "SIPS+D2U", 9) == 0) { /* dtls-udp */
      memcpy(&output_record->sipdtls_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.protocol, "SIP+D2S", 8) == 0) { /* sctp */
      memcpy(&output_record->sipsctp_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;

    } else if (osip_strncasecmp(srvrecord.protocol, "E2U+SIP", 8) == 0 || osip_strncasecmp(srvrecord.protocol, "SIP+E2U", 8) == 0) { /* enum result // SIP+E2U is from rfc2916 and obsolete */
      srvrecord.srv_state = OSIP_SRV_STATE_COMPLETED;
      memcpy(&output_record->sipenum_record, &srvrecord, sizeof(osip_srv_record_t));
      output_record->naptr_state = OSIP_NAPTR_STATE_NAPTRDONE;
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [save_NAPTR record] [%s] -> [%i][%i][%s][%s][%s]\n", rr_name, srvrecord.order, srvrecord.preference, srvrecord.protocol, srvrecord.regexp, srvrecord.name));

    answerno++;
  }

  if (answerno == 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] no NAPTR for SIP for domain [%s]\n", domain));
    output_record->naptr_state = OSIP_NAPTR_STATE_NOTSUPPORTED;
    return OSIP_SUCCESS;
  }

  if (output_record->naptr_state != OSIP_NAPTR_STATE_NAPTRDONE)
    output_record->naptr_state = OSIP_NAPTR_STATE_NOTSUPPORTED;

  if (output_record->sipenum_record.srv_state == OSIP_SRV_STATE_COMPLETED)
    output_record->naptr_state = OSIP_NAPTR_STATE_SRVDONE;

  return OSIP_SUCCESS;
}

struct osip_naptr *eXosip_dnsutils_naptr(struct eXosip_t *excontext, const char *_domain, const char *protocol, const char *transport, int keep_in_cache) {
  osip_list_iterator_t it;
  struct osip_naptr *naptr_record;
  int i;
  int not_in_list = 0;

  char domain[NI_MAXHOST * 2];
  char AUS[64]; /* number with + prefix and only digits */
  char dnsserver[NI_MAXHOST];
  char *delim_aus;
  char *delim_dnsserver;

  if (_domain == NULL)
    return NULL;

  memset(domain, 0, sizeof(domain));
  memset(AUS, 0, sizeof(AUS));
  memset(dnsserver, 0, sizeof(dnsserver));
  delim_aus = strchr(_domain, '!');

  if (delim_aus != NULL && delim_aus[1] != '\0') {
    /* this is an enum NAPTR with AUS after '!' */
    /* example: enum.enumer.org!+123456789 */
    size_t idx;
    size_t idx_domain = 0;
    size_t idx_AUS = 0;
    size_t aus_length;

    delim_aus++;
    delim_dnsserver = strchr(delim_aus, '!');
    aus_length = strlen(delim_aus);

    if (delim_dnsserver != NULL)
      aus_length = delim_dnsserver - delim_aus;

    if (delim_dnsserver != NULL && delim_dnsserver[1] != '\0') {
      delim_dnsserver++;
      snprintf(dnsserver, sizeof(dnsserver), "%s", delim_dnsserver);
    }

    for (idx = 0; idx + 1 <= aus_length; idx++) {
      if (delim_aus[idx] == '+' || isdigit(delim_aus[idx])) {
        AUS[idx_AUS] = delim_aus[idx];
        idx_AUS++;
      }
    }

    AUS[idx_AUS] = '\0';

    for (idx = 0; idx + 1 <= aus_length; idx++) {
      if (isdigit(delim_aus[aus_length - idx - 1])) {
        domain[idx_domain] = delim_aus[aus_length - idx - 1];
        idx_domain++;
        domain[idx_domain] = '.';
        idx_domain++;
      }
    }

    domain[idx_domain] = '\0';
    snprintf(domain + idx_domain, delim_aus - _domain, "%s", _domain);

  } else if (delim_aus != NULL && delim_aus[1] == '\0') {
    snprintf(domain, delim_aus - _domain + 1, "%s", _domain);

  } else {
    delim_aus = NULL;
    snprintf(domain, sizeof(domain), "%s", _domain);
  }

  if (dnsutils_list == NULL) {
    dnsutils_list = (osip_list_t *) osip_malloc(sizeof(osip_list_t));
    osip_list_init(dnsutils_list);
  }

  if (keep_in_cache < 0) {
    naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

    while (naptr_record != NULL) {
      if (osip_strcasecmp(domain, naptr_record->domain) == 0) {
        if (naptr_record->naptr_state == OSIP_NAPTR_STATE_RETRYLATER)
          break;

        if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NOTSUPPORTED)
          break;

        return naptr_record;
      }

      naptr_record = NULL;

      if (it.pos == 9)
        break;

      naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
    }

    return NULL;
  }

  naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

  while (naptr_record != NULL) {
    /* process all */
    if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
      eXosip_dnsutils_srv_lookup(naptr_record, dnsserver);

    naptr_record = NULL;

    if (it.pos == 9)
      break;

    naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
  }

  it.pos = 0;
  naptr_record = (osip_naptr_t *) osip_list_get_first(dnsutils_list, &it);

  while (naptr_record != NULL) {
    if (osip_strcasecmp(domain, naptr_record->domain) == 0) {
      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_RETRYLATER)
        break;

      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
        eXosip_dnsutils_srv_lookup(naptr_record, dnsserver);

      return naptr_record;
    }

    naptr_record = NULL;

    if (it.pos == 9)
      break;

    naptr_record = (osip_naptr_t *) osip_list_get_next(&it);
  }

  if (it.pos == 9 && keep_in_cache > 0) {
    /* no NAPTR found within the last 10 NAPTR : refuse to keep in cache... */
    /* If we were adding unlimited NAPTR record into the cache, the program
       would infinitly increase memory usage. If you reach there, then you
       most probably don't use the API correctly: Only NAPTR related to
       registration will end up in the cache. So in theory, 10 NAPTR will be
       cached for 10 accounts, which seems enough for a softphone. Then all
       SIP message should go through the same proxy by using a pre-route set.
       Correctly using the API will definitly send out-of-dialog SIP message
       to the same proxy as the REGISTER. If you have issue with in-dialog
       Request or Response and NAPTR, that means your proxy is not following
       guidelines from the rfc3261 and rfc3263 where proxy should specify
       port numbers when they want you to resolve the host as a A record
       -and then avoid NAPTR-.
     */
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [NAPTR LOOKUP] time will tell how much you go there [%s] - it's wrong code path, fix it\n", domain));

    keep_in_cache = 0;

    naptr_record = (osip_naptr_t *) osip_malloc(sizeof(osip_naptr_t));
    memset(naptr_record, 0, sizeof(osip_naptr_t));
    naptr_record->keep_in_cache = keep_in_cache;
    snprintf(naptr_record->AUS, sizeof(naptr_record->AUS), "%s", AUS);

  } else if (naptr_record == NULL) {
    naptr_record = (osip_naptr_t *) osip_malloc(sizeof(osip_naptr_t));
    memset(naptr_record, 0, sizeof(osip_naptr_t));
    naptr_record->keep_in_cache = keep_in_cache;
    not_in_list = 1;
    snprintf(naptr_record->AUS, sizeof(naptr_record->AUS), "%s", AUS);

  } else {
    /* it was found, so it WAS in cache before, but we were in "retry" state */
    memset(naptr_record, 0, sizeof(osip_naptr_t));
    naptr_record->keep_in_cache = 1;
    snprintf(naptr_record->AUS, sizeof(naptr_record->AUS), "%s", AUS);
  }

  i = eXosip_dnsutils_naptr_lookup(naptr_record, domain, dnsserver);

  if (i < 0) {
    if (keep_in_cache <= 0) {
      return naptr_record;
    }

    if (not_in_list == 1) {
      osip_list_add(dnsutils_list, naptr_record, -1);
    }

    return naptr_record;
  }

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
    eXosip_dnsutils_srv_lookup(naptr_record, dnsserver);

  if (keep_in_cache <= 0) {
    return naptr_record;
  }

  if (not_in_list == 1)
    osip_list_add(dnsutils_list, naptr_record, -1);

  return naptr_record;
}

#endif

#endif

#if defined(EXOSIP_DNSUTILS_DEFINED) && !defined(EXOSIP_DNSUTILS_RELEASE)
#define EXOSIP_DNSUTILS_RELEASE
void eXosip_dnsutils_release(struct osip_naptr *naptr_record) {
  if (naptr_record == NULL)
    return;

  if (naptr_record->keep_in_cache > 0)
    return;

  osip_free(naptr_record);
}

#endif

#if !defined(EXOSIP_DNSUTILS_DEFINED)

struct osip_naptr *eXosip_dnsutils_naptr(struct eXosip_t *excontext, const char *domain, const char *protocol, const char *transport, int keep_in_cache) {
  return NULL;
}

#endif

#if !defined(EXOSIP_DNSUTILS_DNS_PROCESS)
int eXosip_dnsutils_dns_process(osip_naptr_t *naptr_record, int force) {
  return OSIP_UNDEFINED_ERROR;
}
#endif

#if !defined(EXOSIP_DNSUTILS_RELEASE)
void eXosip_dnsutils_release(struct osip_naptr *naptr_record) {
  return;
}
#endif

#if !defined(EXOSIP_DNSUTILS_FIND_SNI_DEFINED)
const char *_eXosip_dnsutils_find_sni(struct eXosip_t *excontext, const char *hostname) {
  return NULL;
}
#endif

#if !defined(EXOSIP_DNSUTILS_GETSOCK_DEFINED)
int _eXosip_dnsutils_getsock(struct eXosip_t *excontext, fd_set *read_fds, fd_set *write_fds) {
  return 0;
}
#endif

#if !defined(EXOSIP_DNSUTILS_CHECKSOCK_DEFINED)
int _eXosip_dnsutils_checksock(struct eXosip_t *excontext, fd_set *read_fds, fd_set *write_fds) {
  return 0;
}
#endif

#if !defined(EXOSIP_DNSUTILS_ADDSOCK_EPOLL_DEFINED)
int _eXosip_dnsutils_addsock_epoll(struct eXosip_t *excontext, int *cares_fd_table) {
  return 0;
}
#endif

#if !defined(EXOSIP_DNSUTILS_CHECKSOCK_EPOLL_DEFINED)
int _eXosip_dnsutils_checksock_epoll(struct eXosip_t *excontext, int nfds) {
  return 0;
}
#endif

#if !defined(EXOSIP_DNSUTILS_DELSOCK_EPOLL_DEFINED)
int _eXosip_dnsutils_delsock_epoll(struct eXosip_t *excontext, int *cares_fd_table) {
  return 0;
}
#endif
