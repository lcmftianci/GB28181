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
#include "eXtransport.h"

#ifdef HAVE_MSTCPIP_H
#include <Mstcpip.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if !defined(_WIN32_WCE)
#include <errno.h>
#endif

#if defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif

#if defined(HAVE_WINSOCK2_H)
#define ex_errno WSAGetLastError()
#define is_wouldblock_error(r) ((r) == WSAEINTR || (r) == WSAEWOULDBLOCK)
#define is_connreset_error(r) ((r) == WSAECONNRESET || (r) == WSAECONNABORTED || (r) == WSAETIMEDOUT || (r) == WSAENETRESET || (r) == WSAENOTCONN)
#else
#define ex_errno errno
#endif
#ifndef is_wouldblock_error
#define is_wouldblock_error(r) ((r) == EINTR || (r) == EWOULDBLOCK || (r) == EAGAIN)
#define is_connreset_error(r) ((r) == ECONNRESET || (r) == ECONNABORTED || (r) == ETIMEDOUT || (r) == ENETRESET || (r) == ENOTCONN)
#endif

#ifdef __APPLE_CC__
#include "TargetConditionals.h"
#endif

#if TARGET_OS_IPHONE
#include <CFNetwork/CFSocketStream.h>
#include <CoreFoundation/CFStream.h>
#define MULTITASKING_ENABLED
#endif

/* persistent connection */
struct _tcp_stream {
  int socket;
  struct sockaddr ai_addr;
  socklen_t ai_addrlen;
  char remote_ip[65];
  int remote_port;
  char *buf;      /* recv buffer */
  size_t bufsize; /* allocated size of buf */
  size_t buflen;  /* current length of buf */
  char *sendbuf;  /* send buffer */
  size_t sendbufsize;
  size_t sendbuflen;
#ifdef MULTITASKING_ENABLED
  CFReadStreamRef readStream;
  CFWriteStreamRef writeStream;
#endif
  char natted_ip[65];
  int natted_port;
  int ephemeral_port;
  int invalid;
  int is_server;
  time_t tcp_max_timeout;
  time_t tcp_inprogress_max_timeout;
  char reg_call_id[64];
  time_t ping_rfc5626;
  int pong_supported;
};

#ifndef SOCKET_TIMEOUT
/* when stream has sequence error: */
/* having SOCKET_TIMEOUT > 0 helps the system to recover */
#define SOCKET_TIMEOUT 0
#endif

static int _tcp_tl_send_sockinfo(struct eXosip_t *excontext, struct _tcp_stream *sockinfo, const char *msg, int msglen);

struct eXtltcp {
  int tcp_socket;
  struct sockaddr_storage ai_addr;
  int ai_addr_len;

  struct _tcp_stream socket_tab[EXOSIP_MAX_SOCKETS];
};

static int tcp_tl_init(struct eXosip_t *excontext) {
  struct eXtltcp *reserved = (struct eXtltcp *) osip_malloc(sizeof(struct eXtltcp));

  if (reserved == NULL)
    return OSIP_NOMEM;

  reserved->tcp_socket = 0;
  memset(&reserved->ai_addr, 0, sizeof(struct sockaddr_storage));
  reserved->ai_addr_len = 0;
  memset(&reserved->socket_tab, 0, sizeof(struct _tcp_stream) * EXOSIP_MAX_SOCKETS);

  excontext->eXtltcp_reserved = reserved;
  return OSIP_SUCCESS;
}

static void _tcp_tl_close_sockinfo(struct eXosip_t *excontext, struct _tcp_stream *sockinfo) {

  _eXosip_mark_all_transaction_transport_error(excontext, sockinfo->socket);

  _eXosip_closesocket(sockinfo->socket);

  if (sockinfo->buf != NULL)
    osip_free(sockinfo->buf);

  if (sockinfo->sendbuf != NULL)
    osip_free(sockinfo->sendbuf);

#ifdef MULTITASKING_ENABLED

  if (sockinfo->readStream != NULL) {
    CFReadStreamClose(sockinfo->readStream);
    CFRelease(sockinfo->readStream);
  }

  if (sockinfo->writeStream != NULL) {
    CFWriteStreamClose(sockinfo->writeStream);
    CFRelease(sockinfo->writeStream);
  }

#endif
  memset(sockinfo, 0, sizeof(*sockinfo));
}

static int tcp_tl_free(struct eXosip_t *excontext) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos;

  if (reserved == NULL)
    return OSIP_SUCCESS;

  memset(&reserved->ai_addr, 0, sizeof(struct sockaddr_storage));
  reserved->ai_addr_len = 0;

  if (reserved->tcp_socket > 0)
    _eXosip_closesocket(reserved->tcp_socket);

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket > 0) {
      _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
    }
  }

  osip_free(reserved);
  excontext->eXtltcp_reserved = NULL;
  return OSIP_SUCCESS;
}

static int tcp_tl_open(struct eXosip_t *excontext) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int res;
  struct addrinfo *addrinfo = NULL;
  struct addrinfo *curinfo;
  int sock = -1;
  char *node = NULL;
  char eb[ERRBSIZ];

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  excontext->eXtl_transport.proto_local_port = excontext->eXtl_transport.proto_port;

  if (excontext->eXtl_transport.proto_local_port < 0)
    excontext->eXtl_transport.proto_local_port = 5060;

  if (osip_strcasecmp(excontext->eXtl_transport.proto_ifs, "0.0.0.0") != 0 && osip_strcasecmp(excontext->eXtl_transport.proto_ifs, "::") != 0)
    node = excontext->eXtl_transport.proto_ifs;

  res = _eXosip_get_addrinfo(excontext, &addrinfo, node, excontext->eXtl_transport.proto_local_port, excontext->eXtl_transport.proto_num);

  if (res)
    return -1;

  for (curinfo = addrinfo; curinfo; curinfo = curinfo->ai_next) {
#ifdef ENABLE_MAIN_SOCKET
    socklen_t len;
#endif
    int type;

    if (curinfo->ai_protocol && curinfo->ai_protocol != excontext->eXtl_transport.proto_num) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [TCP] skipping protocol [%d]\n", curinfo->ai_protocol));
      continue;
    }

    type = curinfo->ai_socktype;
#if defined(SOCK_CLOEXEC)
    type = SOCK_CLOEXEC | type;
#endif
    sock = (int) socket(curinfo->ai_family, type, curinfo->ai_protocol);

    if (sock < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] cannot create socket %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      continue;
    }

    if (curinfo->ai_family == AF_INET6) {
#ifdef IPV6_V6ONLY

      if (setsockopt_ipv6only(sock)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] cannot set socket option %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
        _eXosip_closesocket(sock);
        sock = -1;
        continue;
      }

#endif /* IPV6_V6ONLY */
    }

    {
      int valopt = 1;

      setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &valopt, sizeof(valopt));
    }

#ifdef ENABLE_MAIN_SOCKET
    res = bind(sock, curinfo->ai_addr, (socklen_t) curinfo->ai_addrlen);

    if (res < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] cannot bind socket [%s][%s] %s\n", excontext->eXtl_transport.proto_ifs, (curinfo->ai_family == AF_INET) ? "AF_INET" : "AF_INET6", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      _eXosip_closesocket(sock);
      sock = -1;
      continue;
    }

    len = sizeof(reserved->ai_addr);
    res = getsockname(sock, (struct sockaddr *) &reserved->ai_addr, &len);

    if (res != 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] cannot get socket name %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      memcpy(&reserved->ai_addr, curinfo->ai_addr, curinfo->ai_addrlen);
    }

    reserved->ai_addr_len = len;

    if (excontext->eXtl_transport.proto_num == IPPROTO_TCP) {
      res = listen(sock, SOMAXCONN);

      if (res < 0) {
        OSIP_TRACE(
            osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] cannot bind socket [%s][%s] %s\n", excontext->eXtl_transport.proto_ifs, (curinfo->ai_family == AF_INET) ? "AF_INET" : "AF_INET6", _ex_strerror(ex_errno, eb, ERRBSIZ)));
        _eXosip_closesocket(sock);
        sock = -1;
        continue;
      }
    }

#endif

    break;
  }

  _eXosip_freeaddrinfo(addrinfo);

  if (sock < 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] cannot bind on port [%i]\n", excontext->eXtl_transport.proto_local_port));
    return -1;
  }

  reserved->tcp_socket = sock;

  if (excontext->eXtl_transport.proto_local_port == 0) {
    /* get port number from socket */
    if (reserved->ai_addr.ss_family == AF_INET)
      excontext->eXtl_transport.proto_local_port = ntohs(((struct sockaddr_in *) &reserved->ai_addr)->sin_port);

    else
      excontext->eXtl_transport.proto_local_port = ntohs(((struct sockaddr_in6 *) &reserved->ai_addr)->sin6_port);

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] binding on port [%i]\n", excontext->eXtl_transport.proto_local_port));
  }

#ifdef ENABLE_MAIN_SOCKET
#ifdef HAVE_SYS_EPOLL_H

  if (excontext->poll_method == EXOSIP_USE_EPOLL_LT) {
    struct epoll_event ev;

    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    res = epoll_ctl(excontext->epfd, EPOLL_CTL_ADD, sock, &ev);

    if (res < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] cannot poll on main tcp socket [%i]\n", excontext->eXtl_transport.proto_local_port));
      _eXosip_closesocket(sock);
      reserved->tcp_socket = -1;
      return -1;
    }
  }

#endif
#endif

  return OSIP_SUCCESS;
}

static int tcp_tl_reset(struct eXosip_t *excontext) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket > 0)
      reserved->socket_tab[pos].invalid = 1;
  }

  return OSIP_SUCCESS;
}

static int tcp_tl_set_fdset(struct eXosip_t *excontext, fd_set *osip_fdset, fd_set *osip_wrset, fd_set *osip_exceptset, int *fd_max, int *osip_fd_table) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos;
  int pos_fd = 0;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

#ifdef ENABLE_MAIN_SOCKET

  if (reserved->tcp_socket <= 0)
    return -1;

  if (osip_fdset != NULL)
    eXFD_SET(reserved->tcp_socket, osip_fdset);

  if (reserved->tcp_socket > *fd_max)
    *fd_max = reserved->tcp_socket;

#endif


  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {

    if (reserved->socket_tab[pos].invalid > 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] [fdset] socket info:[%s][%d] [sock=%d] [pos=%d] manual reset\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port, reserved->socket_tab[pos].socket, pos));
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
      _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
      continue;
    }

    if (reserved->socket_tab[pos].socket > 0) {
      if (osip_fdset != NULL)
        eXFD_SET(reserved->socket_tab[pos].socket, osip_fdset);
      osip_fd_table[pos_fd] = reserved->socket_tab[pos].socket;
      pos_fd++;

      if (reserved->socket_tab[pos].socket > *fd_max)
        *fd_max = reserved->socket_tab[pos].socket;

      if (osip_wrset != NULL && reserved->socket_tab[pos].sendbuflen > 0)
        eXFD_SET(reserved->socket_tab[pos].socket, osip_wrset);

      if (osip_wrset != NULL && reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) /* wait for establishment */
        eXFD_SET(reserved->socket_tab[pos].socket, osip_wrset);
      if (osip_exceptset != NULL && reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) /* wait for establishment */
        eXFD_SET(reserved->socket_tab[pos].socket, osip_exceptset);
    }
  }

  return OSIP_SUCCESS;
}

/* Like strstr, but works for haystack that may contain binary data and is
 not NUL-terminated. */
static char *buffer_find(const char *haystack, size_t haystack_len, const char *needle) {
  const char *search = haystack, *end = haystack + haystack_len;
  char *p;
  size_t len = strlen(needle);

  while (search < end && (p = memchr(search, *needle, end - search)) != NULL) {
    if (p + len > end)
      break;

    if (memcmp(p, needle, len) == 0)
      return (p);

    search = p + 1;
  }

  return (NULL);
}

#define END_HEADERS_STR "\r\n\r\n"
#define CLEN_HEADER_STR "\r\ncontent-length:"
#define CLEN_HEADER_COMPACT_STR "\r\nl:"
#define CLEN_HEADER_STR2 "\r\ncontent-length "
#define CLEN_HEADER_COMPACT_STR2 "\r\nl "
#define const_strlen(x) (sizeof((x)) - 1)

/* consume any complete messages in sockinfo->buf and
 return the total number of bytes consumed */
static size_t handle_messages(struct eXosip_t *excontext, struct _tcp_stream *sockinfo) {
  size_t consumed = 0;
  char *buf = sockinfo->buf;
  size_t buflen = sockinfo->buflen;
  char *end_headers;

  while (buflen > 0 && (end_headers = buffer_find(buf, buflen, END_HEADERS_STR)) != NULL) {
    int clen;
    size_t msglen;
    char *clen_header;

    if (buf == end_headers) {
      /* skip tcp standard keep-alive */
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] socket [%s][%d] rfc5626 [double]pong received [CRLFCRLF]\n", sockinfo->remote_ip, sockinfo->remote_port));
      consumed += 4;
      buflen -= 4;
      buf += 4;
      sockinfo->ping_rfc5626 = 0;
      continue;
    }

    /* stuff a nul in so we can use osip_strcasestr */
    *end_headers = '\0';

    /* ok we have complete headers, find content-length: or l: */
    clen_header = osip_strcasestr(buf, CLEN_HEADER_STR);

    if (!clen_header)
      clen_header = osip_strcasestr(buf, CLEN_HEADER_STR2);

    if (!clen_header)
      clen_header = osip_strcasestr(buf, CLEN_HEADER_COMPACT_STR);

    if (!clen_header)
      clen_header = osip_strcasestr(buf, CLEN_HEADER_COMPACT_STR2);

    if (clen_header != NULL) {
      clen_header = strchr(clen_header, ':');
      clen_header++;
    }

    if (!clen_header) {
      /* Oops, no content-length header.      Presume 0 (below) so we
         consume the headers and make forward progress.  This permits
         server-side keepalive of "\r\n\r\n". */
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] socket [%s][%d] message has no content-length: <%s>\n", sockinfo->remote_ip, sockinfo->remote_port, buf));
    }

    clen = clen_header ? atoi(clen_header) : 0;

    if (clen < 0)
      return sockinfo->buflen; /* discard data */

    /* undo our overwrite and advance end_headers */
    *end_headers = END_HEADERS_STR[0];
    end_headers += const_strlen(END_HEADERS_STR);

    /* do we have the whole message? */
    msglen = (end_headers - buf + clen);

    if (msglen > buflen) {
      /* nope */
      return consumed;
    }

    /* yep; handle the message */
    _eXosip_handle_incoming_message(excontext, buf, msglen, sockinfo->socket, sockinfo->remote_ip, sockinfo->remote_port, sockinfo->natted_ip, &sockinfo->natted_port);
    consumed += msglen;
    buflen -= msglen;
    buf += msglen;
  }

  if (buflen == 2 && buf[0] == '\r' && buf[1] == '\n') {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] socket [%s][%d] rfc5626 pong received [CRLF]\n", sockinfo->remote_ip, sockinfo->remote_port, buf));
    consumed += 2;
    buflen -= 2;
    buf += 2;
    sockinfo->ping_rfc5626 = 0;
    sockinfo->pong_supported = 1;
  }

  return consumed;
}

static int _tcp_tl_recv(struct eXosip_t *excontext, struct _tcp_stream *sockinfo) {
  int r;
  char eb[ERRBSIZ];

  if (!sockinfo->buf) {
    sockinfo->buf = (char *) osip_malloc(SIP_MESSAGE_MAX_LENGTH);

    if (sockinfo->buf == NULL)
      return OSIP_NOMEM;

    sockinfo->bufsize = SIP_MESSAGE_MAX_LENGTH;
    sockinfo->buflen = 0;
  }

  /* buffer is 100% full -> realloc with more size */
  if (sockinfo->bufsize - sockinfo->buflen <= 0) {
    sockinfo->buf = (char *) osip_realloc(sockinfo->buf, sockinfo->bufsize + 1000);

    if (sockinfo->buf == NULL)
      return OSIP_NOMEM;

    sockinfo->bufsize = sockinfo->bufsize + 1000;
  }

  /* buffer is 100% empty-> realloc with initial size */
  if (sockinfo->buflen == 0 && sockinfo->bufsize > SIP_MESSAGE_MAX_LENGTH) {
    osip_free(sockinfo->buf);
    sockinfo->buf = (char *) osip_malloc(SIP_MESSAGE_MAX_LENGTH);

    if (sockinfo->buf == NULL)
      return OSIP_NOMEM;

    sockinfo->bufsize = SIP_MESSAGE_MAX_LENGTH;
  }

  r = (int) recv(sockinfo->socket, sockinfo->buf + sockinfo->buflen, (int) (sockinfo->bufsize - sockinfo->buflen), 0);

  if (r == 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] socket [%s][%d] eof\n", sockinfo->remote_ip, sockinfo->remote_port));
    _eXosip_mark_registration_expired(excontext, sockinfo->reg_call_id);
    _tcp_tl_close_sockinfo(excontext, sockinfo);
    return OSIP_UNDEFINED_ERROR;

  } else if (r < 0) {
    int valopt = ex_errno;

    if (is_wouldblock_error(valopt))
      return OSIP_SUCCESS;

    /* Do we need next line ? */
    /* else if (is_connreset_error(valopt)) */
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] socket [%s][%d] error %s\n", sockinfo->remote_ip, sockinfo->remote_port, _ex_strerror(valopt, eb, ERRBSIZ)));
    _eXosip_mark_registration_expired(excontext, sockinfo->reg_call_id);
    _tcp_tl_close_sockinfo(excontext, sockinfo);
    return OSIP_UNDEFINED_ERROR;

  } else {
    size_t consumed;

    sockinfo->tcp_max_timeout = 0;
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] socket [%s][%d] read %d bytes\n", sockinfo->remote_ip, sockinfo->remote_port, r));
    sockinfo->buflen += r;
    consumed = handle_messages(excontext, sockinfo);

    if (consumed == 0) {
      return OSIP_SUCCESS;

    } else {
      if (sockinfo->buflen > consumed) {
        memmove(sockinfo->buf, sockinfo->buf + consumed, sockinfo->buflen - consumed);
        sockinfo->buflen -= consumed;

      } else {
        sockinfo->buflen = 0;
      }

      return OSIP_SUCCESS;
    }
  }
}

static int _tcp_read_tcp_main_socket(struct eXosip_t *excontext) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;

  /* accept incoming connection */
  char src6host[NI_MAXHOST];
  int recvport = 0;
  struct sockaddr_storage sa;
  int sock;
  int i;

  socklen_t slen;
  int pos;
  int valopt;

  if (reserved->ai_addr.ss_family == AF_INET)
    slen = sizeof(struct sockaddr_in);

  else
    slen = sizeof(struct sockaddr_in6);

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket == 0)
      break;
  }

  if (pos == EXOSIP_MAX_SOCKETS) {
    /* delete an old one! */
    pos = 0;

    if (reserved->socket_tab[pos].socket > 0) {
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
      _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
    }

    memset(&reserved->socket_tab[pos], 0, sizeof(reserved->socket_tab[pos]));
  }

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [TCP] creating TCP socket at index [%i]\n", pos));

  sock = (int) accept(reserved->tcp_socket, (struct sockaddr *) &sa, (socklen_t *) &slen);

  if (sock < 0) {
#if defined(EBADF)
    int valopt = ex_errno;
#endif
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] error accepting TCP socket\n"));
#if defined(EBADF)

    if (valopt == EBADF) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] error accepting TCP socket [EBADF]\n"));
      memset(&reserved->ai_addr, 0, sizeof(struct sockaddr_storage));

      if (reserved->tcp_socket > 0) {
        _eXosip_closesocket(reserved->tcp_socket);

        for (i = 0; i < EXOSIP_MAX_SOCKETS; i++) {
          if (reserved->socket_tab[i].socket > 0 && reserved->socket_tab[i].is_server > 0) {
            _eXosip_mark_registration_expired(excontext, reserved->socket_tab[i].reg_call_id);
            _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[i]);
          }
        }
      }

      tcp_tl_open(excontext);
    }

#endif

  } else {
    reserved->socket_tab[pos].socket = sock;
    reserved->socket_tab[pos].is_server = 1;
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] incoming TCP connection accepted\n"));

    valopt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &valopt, sizeof(valopt));

    memset(src6host, 0, NI_MAXHOST);
    recvport = _eXosip_getport((struct sockaddr *) &sa);
    _eXosip_getnameinfo((struct sockaddr *) &sa, slen, src6host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

    _eXosip_transport_set_dscp(excontext, sa.ss_family, sock);

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] message received from [%s][%d]\n", src6host, recvport));
    osip_strncpy(reserved->socket_tab[pos].remote_ip, src6host, sizeof(reserved->socket_tab[pos].remote_ip) - 1);
    reserved->socket_tab[pos].remote_port = recvport;

#ifdef HAVE_SYS_EPOLL_H

    if (excontext->poll_method == EXOSIP_USE_EPOLL_LT) {
      struct epoll_event ev;
      int res;

      memset(&ev, 0, sizeof(struct epoll_event));
      ev.events = EPOLLIN;
      ev.data.fd = sock;
      res = epoll_ctl(excontext->epfd, EPOLL_CTL_ADD, sock, &ev);

      if (res < 0) {
        _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        return -1;
      }
    }

#endif
  }

  return OSIP_SUCCESS;
}

#ifdef HAVE_SYS_EPOLL_H

static int tcp_tl_epoll_read_message(struct eXosip_t *excontext, int nfds, struct epoll_event *ep_array) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos = 0;
  int n;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  for (n = 0; n < nfds; ++n) {
    if (ep_array[n].data.fd == reserved->tcp_socket) {
      _tcp_read_tcp_main_socket(excontext);
      continue;
    }

    for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
      if (reserved->socket_tab[pos].socket > 0) {
        if (ep_array[n].data.fd == reserved->socket_tab[pos].socket) {
          if ((ep_array[n].events & EPOLLOUT) && reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) {
            _eXosip_mark_all_transaction_force_send(excontext, reserved->socket_tab[pos].socket);
          } else if ((ep_array[n].events & EPOLLOUT) && reserved->socket_tab[pos].sendbuflen > 0) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [tid=-1] message sent [len=%d] to [%s][%d]\n%s\n", reserved->socket_tab[pos].sendbuflen, reserved->socket_tab[pos].remote_ip,
                                  reserved->socket_tab[pos].remote_port, reserved->socket_tab[pos].sendbuf));
            _tcp_tl_send_sockinfo(excontext, &reserved->socket_tab[pos], (const char *) reserved->socket_tab[pos].sendbuf, (int) reserved->socket_tab[pos].sendbuflen);
            reserved->socket_tab[pos].sendbuflen = 0;
          }

          if (reserved->socket_tab[pos].tcp_inprogress_max_timeout == 0 && (ep_array[n].events & EPOLLIN)) {
            static int test = 0;
            test++;

            _tcp_tl_recv(excontext, &reserved->socket_tab[pos]);
            // if (test == 8) _tcp_tl_close_sockinfo(&reserved->socket_tab[pos]);
          }
          break;
        }
      }
    }
  }

  return OSIP_SUCCESS;
}

#endif

static int tcp_tl_read_message(struct eXosip_t *excontext, fd_set *osip_fdset, fd_set *osip_wrset, fd_set *osip_exceptset) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos = 0;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (FD_ISSET(reserved->tcp_socket, osip_fdset)) {
    _tcp_read_tcp_main_socket(excontext);
  }

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket > 0) {
      if (FD_ISSET(reserved->socket_tab[pos].socket, osip_exceptset)) {
        int res = _tcptls_tl_is_connected(excontext->poll_method, reserved->socket_tab[pos].socket);
        if (res < 0) {
          _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
          _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
          continue;
        } else {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [tid=-1] socket [%s][%d] except descriptor without error\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port));
        }
      } else if (FD_ISSET(reserved->socket_tab[pos].socket, osip_wrset) && reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) {
        _eXosip_mark_all_transaction_force_send(excontext, reserved->socket_tab[pos].socket);
      } else if (FD_ISSET(reserved->socket_tab[pos].socket, osip_wrset) && reserved->socket_tab[pos].sendbuflen > 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [tid=-1] message sent [len=%d] to [%s][%d]\n%s\n", reserved->socket_tab[pos].sendbuflen, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].sendbuf));
        _tcp_tl_send_sockinfo(excontext, &reserved->socket_tab[pos], (const char *) reserved->socket_tab[pos].sendbuf, (int) reserved->socket_tab[pos].sendbuflen);
        reserved->socket_tab[pos].sendbuflen = 0;
      }

      if (reserved->socket_tab[pos].tcp_inprogress_max_timeout == 0 && FD_ISSET(reserved->socket_tab[pos].socket, osip_fdset)) {
        _tcp_tl_recv(excontext, &reserved->socket_tab[pos]);
      }
    }
  }

  return OSIP_SUCCESS;
}

static struct _tcp_stream *_tcp_tl_find_sockinfo(struct eXosip_t *excontext, int sock) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos;

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket == sock) {
      return &reserved->socket_tab[pos];
    }
  }

  return NULL;
}

static int _tcp_tl_find_socket(struct eXosip_t *excontext, char *host, int port) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos;

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket != 0) {
      if (0 == osip_strcasecmp(reserved->socket_tab[pos].remote_ip, host) && port == reserved->socket_tab[pos].remote_port)
        return pos;
    }
  }

  return -1;
}

#ifdef HAVE_SYS_EPOLL_H

static int _tcptls_tl_is_connected_epoll(int sock) {
  int res;
  int valopt;
  socklen_t sock_len;
  int nfds;
  struct epoll_event ep_array;
  int epfd;
  struct epoll_event ev;
  char eb[ERRBSIZ];

  epfd = epoll_create(1);

  if (epfd < 0) {
    return -1;
  }

  memset(&ev, 0, sizeof(struct epoll_event));
  ev.events = EPOLLOUT;
  ev.data.fd = sock;
  res = epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

  if (res < 0) {
    _eXosip_closesocket(epfd);
    return -1;
  }

  nfds = epoll_wait(epfd, &ep_array, 1, SOCKET_TIMEOUT);

  if (nfds > 0) {
    sock_len = sizeof(int);

    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (void *) (&valopt), &sock_len) == 0) {
      if (valopt == 0) {
        _eXosip_closesocket(epfd);
        return 0;
      }

      if (valopt == EINPROGRESS || valopt == EALREADY) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TXX] [epoll] cannot connect socket [%i] / %s\n", sock, _ex_strerror(valopt, eb, ERRBSIZ)));
        _eXosip_closesocket(epfd);
        return 1;
      }

      if (is_wouldblock_error(valopt)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TXX] [epoll] cannot connect socket [%i] would block / %s\n", sock, _ex_strerror(valopt, eb, ERRBSIZ)));
        _eXosip_closesocket(epfd);
        return 1;
      }

      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TXX] [epoll] cannot connect socket [%i] / terminated %s\n", sock, _ex_strerror(valopt, eb, ERRBSIZ)));

      _eXosip_closesocket(epfd);
      return -1;

    } else {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TXX] [epoll] cannot connect socket / error in getsockopt %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      _eXosip_closesocket(epfd);
      return -1;
    }

  } else if (res < 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TXX] [epoll] cannot connect socket [%i] / error in epoll %s\n", sock, _ex_strerror(ex_errno, eb, ERRBSIZ)));
    _eXosip_closesocket(epfd);
    return -1;
  }

  _eXosip_closesocket(epfd);
  return 1;
}

#endif

int _tcptls_tl_is_connected(int epoll_method, int sock) {
  int res;
  struct timeval tv;
  fd_set wrset;
  fd_set exceptset;
  int valopt;
  socklen_t sock_len;
  char eb[ERRBSIZ];

#ifdef HAVE_SYS_EPOLL_H

  if (epoll_method == EXOSIP_USE_EPOLL_LT) {
    return _tcptls_tl_is_connected_epoll(sock);
  }

#endif

  tv.tv_sec = SOCKET_TIMEOUT / 1000;
  tv.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000;

  FD_ZERO(&wrset);
  FD_ZERO(&exceptset);
  eXFD_SET(sock, &wrset);
  eXFD_SET(sock, &exceptset);

  res = select(sock + 1, NULL, &wrset, &exceptset, &tv);

  if (res > 0) {
    sock_len = sizeof(int);

    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (void *) (&valopt), &sock_len) == 0) {
      if (valopt == 0)
        return 0;

#if !defined(HAVE_WINSOCK2_H)
      if (valopt == EINPROGRESS || valopt == EALREADY) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TXX] [select] cannot connect socket [%i] / %s\n", sock, _ex_strerror(valopt, eb, ERRBSIZ)));
        return 1;
      }
#endif

      if (is_wouldblock_error(valopt)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TXX] [select] cannot connect socket [%i] would block / %s\n", sock, _ex_strerror(valopt, eb, ERRBSIZ)));
        return 1;
      }

      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TXX] [select] cannot connect socket [%i] / terminated %s\n", sock, _ex_strerror(valopt, eb, ERRBSIZ)));
      return -1;
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TXX] [select] cannot connect socket / error in getsockopt %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
    return -1;

  } else if (res < 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TXX] [select] cannot connect socket [%i] / error in select %s\n", sock, _ex_strerror(ex_errno, eb, ERRBSIZ)));
    return -1;
  }

  return 1;
}

static int _tcp_tl_new_socket(struct eXosip_t *excontext, char *host, int port) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos;
  int res;
  struct addrinfo *addrinfo = NULL;
  struct addrinfo *curinfo;
  int sock = -1;
  struct sockaddr selected_ai_addr;
  socklen_t selected_ai_addrlen;

  char src6host[NI_MAXHOST];
  char eb[ERRBSIZ];

  memset(src6host, 0, sizeof(src6host));

  selected_ai_addrlen = 0;
  memset(&selected_ai_addr, 0, sizeof(struct sockaddr));

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket == 0) {
      break;
    }
  }

  if (pos == EXOSIP_MAX_SOCKETS) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] [new] reserved->socket_tab is full - cannot create new socket\n"));
#ifdef DELETE_OLD_SOCKETS
    /* delete an old one! */
    pos = 0;

    if (reserved->socket_tab[pos].socket > 0) {
      _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
    }

    memset(&reserved->socket_tab[pos], 0, sizeof(reserved->socket_tab[pos]));
#else
    return -1;
#endif
  }

  res = _eXosip_get_addrinfo(excontext, &addrinfo, host, port, IPPROTO_TCP);

  if (res)
    return -1;

  for (curinfo = addrinfo; curinfo; curinfo = curinfo->ai_next) {
    int i;

    if (curinfo->ai_protocol && curinfo->ai_protocol != IPPROTO_TCP)
      continue;

    res = _eXosip_getnameinfo((struct sockaddr *) curinfo->ai_addr, (socklen_t) curinfo->ai_addrlen, src6host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

    if (res != 0)
      continue;

    i = _tcp_tl_find_socket(excontext, src6host, port);

    if (i >= 0) {
      _eXosip_freeaddrinfo(addrinfo);
      return i;
    }
  }

  for (curinfo = addrinfo; curinfo; curinfo = curinfo->ai_next) {
    int type;

    if (curinfo->ai_protocol && curinfo->ai_protocol != IPPROTO_TCP) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] skipping protocol [%d]\n", curinfo->ai_protocol));
      continue;
    }

    res = _eXosip_getnameinfo((struct sockaddr *) curinfo->ai_addr, (socklen_t) curinfo->ai_addrlen, src6host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

    if (res == 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [new] new binding with [%s][%d]\n", src6host, port));
    }

    type = curinfo->ai_socktype;
#if defined(SOCK_CLOEXEC)
    type = SOCK_CLOEXEC | type;
#endif
    sock = (int) socket(curinfo->ai_family, type, curinfo->ai_protocol);

    if (sock < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] cannot create socket %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      continue;
    }

    if (curinfo->ai_family == AF_INET6) {
#ifdef IPV6_V6ONLY

      if (setsockopt_ipv6only(sock)) {
        _eXosip_closesocket(sock);
        sock = -1;
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] cannot set socket option %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
        continue;
      }

#endif /* IPV6_V6ONLY */
    }

    if (reserved->ai_addr_len > 0) {
      if (excontext->reuse_tcp_port > 0) {
        struct sockaddr_storage ai_addr;
        int valopt = 1;

        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &valopt, sizeof(valopt));

        memcpy(&ai_addr, &reserved->ai_addr, reserved->ai_addr_len);

        if (ai_addr.ss_family == AF_INET)
          ((struct sockaddr_in *) &ai_addr)->sin_port = htons(excontext->eXtl_transport.proto_local_port);

        else
          ((struct sockaddr_in6 *) &ai_addr)->sin6_port = htons(excontext->eXtl_transport.proto_local_port);

        res = bind(sock, (const struct sockaddr *) &ai_addr, reserved->ai_addr_len);

        if (res < 0) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [new] cannot bind socket [%s][%s] %s\n", excontext->eXtl_transport.proto_ifs, (ai_addr.ss_family == AF_INET) ? "AF_INET" : "AF_INET6",
                                _ex_strerror(ex_errno, eb, ERRBSIZ)));
        }

      } else if (excontext->oc_local_address[0] == '\0') {
        if (reserved->ai_addr.ss_family == curinfo->ai_family) {
          struct sockaddr_storage ai_addr;
          int count = 0;

          memcpy(&ai_addr, &reserved->ai_addr, reserved->ai_addr_len);

          while (count < 100) {
            if (excontext->oc_local_port_range[0] < 1024) {
              if (ai_addr.ss_family == AF_INET)
                ((struct sockaddr_in *) &ai_addr)->sin_port = htons(0);

              else
                ((struct sockaddr_in6 *) &ai_addr)->sin6_port = htons(0);

            } else {
              if (excontext->oc_local_port_current == 0)
                excontext->oc_local_port_current = excontext->oc_local_port_range[0];

              /* reset value */
              if (excontext->oc_local_port_current >= excontext->oc_local_port_range[1])
                excontext->oc_local_port_current = excontext->oc_local_port_range[0];

              if (ai_addr.ss_family == AF_INET)
                ((struct sockaddr_in *) &ai_addr)->sin_port = htons(excontext->oc_local_port_current);

              else
                ((struct sockaddr_in6 *) &ai_addr)->sin6_port = htons(excontext->oc_local_port_current);
            }

            res = bind(sock, (const struct sockaddr *) &ai_addr, reserved->ai_addr_len);

            if (res < 0) {
              OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [new] cannot bind socket [%s][%s] (port=%i) %s\n", excontext->eXtl_transport.proto_ifs, (ai_addr.ss_family == AF_INET) ? "AF_INET" : "AF_INET6",
                                    excontext->oc_local_port_current, _ex_strerror(ex_errno, eb, ERRBSIZ)));
              count++;

              if (excontext->oc_local_port_range[0] >= 1024)
                excontext->oc_local_port_current++;

              continue;
            }

            if (excontext->oc_local_port_range[0] >= 1024)
              excontext->oc_local_port_current++;

            break;
          }
        }

      } else {
        int count = 0;

        if (excontext->oc_local_port_range[0] < 1024)
          excontext->oc_local_port_range[0] = 0;

        while (count < 100) {
          struct addrinfo *oc_addrinfo = NULL;
          struct addrinfo *oc_curinfo;

          if (excontext->oc_local_port_current == 0)
            excontext->oc_local_port_current = excontext->oc_local_port_range[0];

          if (excontext->oc_local_port_current >= excontext->oc_local_port_range[1])
            excontext->oc_local_port_current = excontext->oc_local_port_range[0];

          _eXosip_get_addrinfo(excontext, &oc_addrinfo, excontext->oc_local_address, excontext->oc_local_port_current, IPPROTO_TCP);

          for (oc_curinfo = oc_addrinfo; oc_curinfo; oc_curinfo = oc_curinfo->ai_next) {
            if (oc_curinfo->ai_protocol && oc_curinfo->ai_protocol != IPPROTO_TCP) {
              OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] skipping protocol [%d]\n", oc_curinfo->ai_protocol));
              continue;
            }

            break;
          }

          if (oc_curinfo == NULL) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] not able to find any address to bind\n"));
            _eXosip_freeaddrinfo(oc_addrinfo);
            break;
          }

          res = bind(sock, (const struct sockaddr *) oc_curinfo->ai_addr, (socklen_t) oc_curinfo->ai_addrlen);

          if (res < 0) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [new] cannot bind socket [%s][%s] (port=%i) %s\n", excontext->oc_local_address, (oc_curinfo->ai_addr->sa_family == AF_INET) ? "AF_INET" : "AF_INET6",
                                  excontext->oc_local_port_current, _ex_strerror(ex_errno, eb, ERRBSIZ)));
            _eXosip_freeaddrinfo(oc_addrinfo);
            count++;

            if (excontext->oc_local_port_range[0] != 0)
              excontext->oc_local_port_current++;

            continue;
          }

          _eXosip_freeaddrinfo(oc_addrinfo);

          if (excontext->oc_local_port_range[0] != 0)
            excontext->oc_local_port_current++;

          break;
        }
      }
    }

    /* set NON-BLOCKING MODE */
#if defined(HAVE_WINSOCK2_H)
    {
      unsigned long nonBlock = 1;
      int val;
      int timeout = 5000;
      ioctlsocket(sock, FIONBIO, &nonBlock);

      val = 1;

      if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *) &val, sizeof(val)) == -1) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [new] cannot set socket SO_KEEPALIVE\n"));
      }

      if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(timeout))) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [new] cannot set socket SO_RCVTIMEO\n"));
      }
      if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *) &timeout, sizeof(timeout))) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [new] cannot set socket SO_SNDTIMEO\n"));
      }
    }
#ifdef HAVE_MSTCPIP_H
    {
      DWORD err = 0L;
      DWORD dwBytes = 0L;
      struct tcp_keepalive kalive = {0};
      struct tcp_keepalive kaliveOut = {0};
      kalive.onoff = 1;
      kalive.keepalivetime = 30000;    /* Keep Alive every 30 seconds */
      kalive.keepaliveinterval = 3000; /* Resend if No-Reply */
      err = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &kalive, sizeof(kalive), &kaliveOut, sizeof(kaliveOut), &dwBytes, NULL, NULL);

      if (err != 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [new] cannot set keepalive interval\n"));
      }
    }
#endif
#else
    {
      int val;

      val = fcntl(sock, F_GETFL);

      if (val < 0) {
        _eXosip_closesocket(sock);
        sock = -1;
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] [new] cannot get socket flag\n"));
        continue;
      }

      val |= O_NONBLOCK;

      if (fcntl(sock, F_SETFL, val) < 0) {
        _eXosip_closesocket(sock);
        sock = -1;
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] [new] cannot set socket flag\n"));
        continue;
      }

#if SO_KEEPALIVE
      val = 1;

      if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) == -1) {
      }

#endif
#if 0
      val = 30;                 /* 30 sec before starting probes */
      setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val));
      val = 2;                  /* 2 probes max */
      setsockopt(sock, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val));
      val = 10;                 /* 10 seconds between each probe */
      setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val));
#endif
#if SO_NOSIGPIPE
      val = 1;
      setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *) &val, sizeof(int));
#endif
    }
#endif

#if TCP_NODELAY
    {
      int val;

      val = 1;

      if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &val, sizeof(int)) != 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] cannot set socket flag (TCP_NODELAY)\n"));
      }
    }
#endif
#if TCP_USER_TIMEOUT
    {
      int val = 9000;
      if (setsockopt(sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &val, sizeof(val)) != 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] cannot set socket flag (TCP_USER_TIMEOUT)\n"));
      }
    }
#endif

    _eXosip_transport_set_dscp(excontext, curinfo->ai_family, sock);

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] socket [%s] [sock=%d] family:%d\n", host, sock, curinfo->ai_family));
    res = connect(sock, curinfo->ai_addr, (socklen_t) curinfo->ai_addrlen);

    if (res < 0) {
      int valopt = ex_errno;

#if defined(HAVE_WINSOCK2_H)

      if (valopt != WSAEWOULDBLOCK) {
#else

      if (valopt != EINPROGRESS) {
#endif
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] cannot connect socket [%s] family:%d %s\n", host, curinfo->ai_family, _ex_strerror(valopt, eb, ERRBSIZ)));
        _eXosip_closesocket(sock);
        sock = -1;
        continue;

      } else {
        res = _tcptls_tl_is_connected(excontext->poll_method, sock);

        if (res > 0) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] socket [%s] [sock=%d] [pos=%d] family:%d, in progress\n", host, sock, pos, curinfo->ai_family));
          selected_ai_addrlen = (socklen_t) curinfo->ai_addrlen;
          memcpy(&selected_ai_addr, curinfo->ai_addr, sizeof(struct sockaddr));
          break;

        } else if (res == 0) {
#ifdef MULTITASKING_ENABLED
          reserved->socket_tab[pos].readStream = NULL;
          reserved->socket_tab[pos].writeStream = NULL;
          CFStreamCreatePairWithSocket(kCFAllocatorDefault, sock, &reserved->socket_tab[pos].readStream, &reserved->socket_tab[pos].writeStream);

          if (reserved->socket_tab[pos].readStream != NULL)
            CFReadStreamSetProperty(reserved->socket_tab[pos].readStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);

          if (reserved->socket_tab[pos].writeStream != NULL)
            CFWriteStreamSetProperty(reserved->socket_tab[pos].writeStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);

          if (CFReadStreamOpen(reserved->socket_tab[pos].readStream)) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [new] CFReadStreamOpen Succeeded\n"));
          }

          CFWriteStreamOpen(reserved->socket_tab[pos].writeStream);
#endif
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [new] socket [%s] [sock=%d] [pos=%d] family:%d, connected\n", host, sock, pos, curinfo->ai_family));
          selected_ai_addrlen = 0;
          memcpy(&selected_ai_addr, curinfo->ai_addr, sizeof(struct sockaddr));
          reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0;
          break;

        } else {
          _eXosip_closesocket(sock);
          sock = -1;
          continue;
        }
      }
    }

    break;
  }

  _eXosip_freeaddrinfo(addrinfo);

  if (sock > 0) {
    reserved->socket_tab[pos].socket = sock;

    reserved->socket_tab[pos].ai_addrlen = selected_ai_addrlen;
    memset(&reserved->socket_tab[pos].ai_addr, 0, sizeof(struct sockaddr));

    if (selected_ai_addrlen > 0)
      memcpy(&reserved->socket_tab[pos].ai_addr, &selected_ai_addr, selected_ai_addrlen);

    if (src6host[0] == '\0')
      osip_strncpy(reserved->socket_tab[pos].remote_ip, host, sizeof(reserved->socket_tab[pos].remote_ip) - 1);

    else
      osip_strncpy(reserved->socket_tab[pos].remote_ip, src6host, sizeof(reserved->socket_tab[pos].remote_ip) - 1);

    reserved->socket_tab[pos].remote_port = port;

    {
      struct sockaddr_storage local_ai_addr;
      socklen_t selected_ai_addrlen;

      memset(&local_ai_addr, 0, sizeof(struct sockaddr_storage));
      selected_ai_addrlen = sizeof(struct sockaddr_storage);
      res = getsockname(sock, (struct sockaddr *) &local_ai_addr, &selected_ai_addrlen);

      if (res == 0) {
        if (local_ai_addr.ss_family == AF_INET)
          reserved->socket_tab[pos].ephemeral_port = ntohs(((struct sockaddr_in *) &local_ai_addr)->sin_port);

        else
          reserved->socket_tab[pos].ephemeral_port = ntohs(((struct sockaddr_in6 *) &local_ai_addr)->sin6_port);

        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [new] outgoing socket created on port [%i]\n", reserved->socket_tab[pos].ephemeral_port));
      }
    }

    reserved->socket_tab[pos].tcp_inprogress_max_timeout = osip_getsystemtime(NULL) + 32;

#ifdef HAVE_SYS_EPOLL_H

    if (excontext->poll_method == EXOSIP_USE_EPOLL_LT) {
      struct epoll_event ev;

      memset(&ev, 0, sizeof(struct epoll_event));
      ev.events = EPOLLIN | EPOLLOUT;
      ev.data.fd = sock;
      res = epoll_ctl(excontext->epfd, EPOLL_CTL_ADD, sock, &ev);

      if (res < 0) {
        _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        return -1;
      }
    }

#endif

    return pos;
  }

  return -1;
}

static int _tcp_tl_send_sockinfo(struct eXosip_t *excontext, struct _tcp_stream *sockinfo, const char *msg, int msglen) {
  char eb[ERRBSIZ];
  int i;

  while (1) {
    i = (int) send(sockinfo->socket, (const void *) msg, msglen, 0);

    if (i < 0) {
      int valopt = ex_errno;

      if (is_wouldblock_error(valopt)) {
        struct timeval tv;
        fd_set wrset;

#ifdef HAVE_SYS_EPOLL_H

        if (excontext->poll_method == EXOSIP_USE_EPOLL_LT) {
          int nfds;
          struct epoll_event ep_array;
          int epfd;
          struct epoll_event ev;

          epfd = epoll_create(1);

          if (epfd < 0) {
            return -1;
          }

          memset(&ev, 0, sizeof(struct epoll_event));
          ev.events = EPOLLOUT;
          ev.data.fd = sockinfo->socket;
          i = epoll_ctl(epfd, EPOLL_CTL_ADD, sockinfo->socket, &ev);

          if (i < 0) {
            _eXosip_closesocket(epfd);
            return -1;
          }

          nfds = epoll_wait(epfd, &ep_array, 1, SOCKET_TIMEOUT);

          if (nfds > 0) {
            _eXosip_closesocket(epfd);
            continue;

          } else if (nfds < 0) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] TCP epoll error: %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
            _eXosip_closesocket(epfd);
            return -1;
          }

          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] TCP timeout: %d ms\n", SOCKET_TIMEOUT));
          _eXosip_closesocket(epfd);
          continue;
        }

#endif

        tv.tv_sec = SOCKET_TIMEOUT / 1000;
        tv.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000;

        if (tv.tv_usec == 0)
          tv.tv_usec += 10000;

        FD_ZERO(&wrset);
        FD_SET(sockinfo->socket, &wrset);

        i = select(sockinfo->socket + 1, NULL, &wrset, NULL, &tv);

        if (i > 0) {
          continue;

        } else if (i < 0) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] TCP select error: %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
          return -1;
        }

        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] TCP timeout: %d ms\n", SOCKET_TIMEOUT));
        continue;
      }

      /* SIP_NETWORK_ERROR; */
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] TCP error: %s\n", _ex_strerror(valopt, eb, ERRBSIZ)));
      return -1;

    } else if (i == 0) {
      break; /* what's the meaning here? */

    } else if (i < msglen) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] TCP partial write: wrote [%i] instead of [%i]\n", i, msglen));
      msglen -= i;
      msg += i;
      continue;
    }

    break;
  }

  return OSIP_SUCCESS;
}

static int _tcp_tl_send(struct eXosip_t *excontext, int sock, const char *msg, int msglen) {
  struct _tcp_stream *sockinfo = _tcp_tl_find_sockinfo(excontext, sock);
  int i;
  if (sockinfo == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] cannot find sockinfo for socket [%d] [dropping message]\n", sock));
    return -1;
  }

  i = _tcp_tl_send_sockinfo(excontext, sockinfo, msg, msglen);
  return i;
}

static int _tcp_tl_update_contact(struct eXosip_t *excontext, osip_message_t *req, char *natted_ip, int natted_port) {
  if (req->application_data != (void *) 0x1)
    return OSIP_SUCCESS;

  if ((natted_ip != NULL && natted_ip[0] != '\0') || natted_port > 0) {
    osip_list_iterator_t it;
    osip_contact_t *co = (osip_contact_t *) osip_list_get_first(&req->contacts, &it);

    while (co != NULL) {
      if (co != NULL && co->url != NULL && co->url->host != NULL) {
        if (natted_port > 0) {
          if (co->url->port)
            osip_free(co->url->port);

          co->url->port = (char *) osip_malloc(10);
          snprintf(co->url->port, 9, "%i", natted_port);
          osip_message_force_update(req);
        }

        if (natted_ip != NULL && natted_ip[0] != '\0') {
          osip_free(co->url->host);
          co->url->host = osip_strdup(natted_ip);
          osip_message_force_update(req);
        }
      }

      co = (osip_contact_t *) osip_list_get_next(&it);
    }
  }

  return OSIP_SUCCESS;
}

int _tl_resolv_naptr_destination(struct eXosip_t *excontext, osip_transaction_t *tr, osip_message_t *sip, char **out_host, int *out_port, osip_naptr_t **out_naptr_record) {
  char *host = *out_host;
  int port = *out_port;
  int tid = (tr == NULL) ? -1 : tr->transactionid;
  int force_waiting = (tr == NULL) ? 1 : 0;
  osip_naptr_t *naptr_record = (tr == NULL) ? NULL : tr->naptr_record;

  *out_naptr_record = NULL;
  if (tr == NULL) {
    _eXosip_srv_lookup(excontext, sip, &naptr_record);
  }

  if (naptr_record == NULL) {
    /* no naptr ? */
    return OSIP_SUCCESS;
  }

  eXosip_dnsutils_dns_process(naptr_record, force_waiting);

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
    eXosip_dnsutils_dns_process(naptr_record, force_waiting);

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVDONE) {
    /* 4: check if we have the one we want... */
    struct osip_srv_record *record = NULL;

    if (osip_strcasecmp(excontext->eXtl_transport.proto_name, "UDP") == 0)
      record = &naptr_record->sipudp_record;
    else if (osip_strcasecmp(excontext->eXtl_transport.proto_name, "TCP") == 0)
      record = &naptr_record->siptcp_record;
    else if (osip_strcasecmp(excontext->eXtl_transport.proto_name, "TLS") == 0)
      record = &naptr_record->siptls_record;
    else if (osip_strcasecmp(excontext->eXtl_transport.proto_name, "DTLS-UDP") == 0)
      record = &naptr_record->sipdtls_record;
    else {
      if (tr == NULL && naptr_record->keep_in_cache == 0) {
        osip_free(naptr_record);
      }
      return OSIP_UNDEFINED_ERROR; /* unsuported transport? */
    }

    if (record->name[0] != '\0' && record->srventry[record->index].srv[0] != '\0') {
      /* always choose the first here. if a network error occur, remove first entry and replace with next entries. */
      osip_srv_entry_t *srv;

      if (MSG_IS_REGISTER(sip) || MSG_IS_OPTIONS(sip)) {
        /* activate the failover capability: for no answer OR 503 */
        if (record->srventry[record->index].srv_is_broken.tv_sec > 0) {
          record->srventry[record->index].srv_is_broken.tv_sec = 0;
          record->srventry[record->index].srv_is_broken.tv_usec = 0;

          if (eXosip_dnsutils_rotate_srv(record) > 0) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [XXX] [tid=%i] doing XXX failover [%s][%d] -> [%s][%d]\n", tid, host, port, record->srventry[record->index].srv, record->srventry[record->index].port));
          }
        }
      }

      srv = &record->srventry[record->index];

      if (srv->ipaddress[0]) {
        *out_host = srv->ipaddress;
        *out_port = srv->port;

      } else {
        *out_host = srv->srv;
        *out_port = srv->port;
      }
    }
  }

  if (tr == NULL) {
    /* handle only success use-case, otherwise skip NAPTR and continue */
    if (naptr_record->keep_in_cache == 0)
      osip_free(naptr_record);

    *out_naptr_record = NULL;
    return OSIP_SUCCESS;
  }

  *out_naptr_record = naptr_record;

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVDONE) {
    return OSIP_SUCCESS;
  }

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_INPROGRESS) {
    /* 2: keep waiting (naptr answer not received) */
    return OSIP_SUCCESS + 1;
  }

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE) {
    /* 3: keep waiting (naptr answer received/no srv answer received) */
    return OSIP_SUCCESS + 1;
  }

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS) {
    /* 3: keep waiting (naptr answer received/no srv answer received) */
    return OSIP_SUCCESS + 1;
  }

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NOTSUPPORTED || naptr_record->naptr_state == OSIP_NAPTR_STATE_RETRYLATER) {
    /* 5: fallback to DNS A */
    if (naptr_record->keep_in_cache == 0)
      osip_free(naptr_record);

    *out_naptr_record = NULL;
    tr->naptr_record = NULL;

    return OSIP_SUCCESS;
  }

  if (naptr_record->naptr_state == OSIP_NAPTR_STATE_UNKNOWN) {
    /* fallback to DNS A */
    if (naptr_record->keep_in_cache == 0)
      osip_free(naptr_record);

    *out_naptr_record = NULL;
    tr->naptr_record = NULL;

    /* must never happen? */
    return OSIP_SUCCESS;
  }

  return OSIP_SUCCESS;
}

static int _tcp_tl_build_message(struct eXosip_t *excontext, osip_message_t *sip, int pos, char *host, char **message, size_t *length) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int i;
  _eXosip_request_viamanager(excontext, sip, reserved->socket_tab[pos].ai_addr.sa_family, IPPROTO_TCP, NULL, reserved->socket_tab[pos].ephemeral_port, reserved->socket_tab[pos].socket, host);

  if (excontext->use_ephemeral_port == 1)
    _eXosip_message_contactmanager(excontext, sip, reserved->socket_tab[pos].ai_addr.sa_family, IPPROTO_TCP, NULL, reserved->socket_tab[pos].ephemeral_port, reserved->socket_tab[pos].socket, host);

  else
    _eXosip_message_contactmanager(excontext, sip, reserved->socket_tab[pos].ai_addr.sa_family, IPPROTO_TCP, NULL, excontext->eXtl_transport.proto_local_port, reserved->socket_tab[pos].socket, host);

  if (excontext->tcp_firewall_ip[0] != '\0' || excontext->auto_masquerade_contact > 0)
    _tcp_tl_update_contact(excontext, sip, reserved->socket_tab[pos].natted_ip, reserved->socket_tab[pos].natted_port);

  /* remove preloaded route if there is no tag in the To header
   */
  {
    osip_route_t *route = NULL;
    osip_generic_param_t *tag = NULL;

    if (excontext->remove_prerouteset > 0) {
      osip_message_get_route(sip, 0, &route);
      osip_to_get_tag(sip->to, &tag);

      if (tag == NULL && route != NULL && route->url != NULL) {
        osip_list_remove(&sip->routes, 0);
        osip_message_force_update(sip);
      }
    }

    i = osip_message_to_str(sip, message, length);

    if (tag == NULL && route != NULL && route->url != NULL) {
      osip_list_add(&sip->routes, route, 0);
    }
  }
  return i;
}

static int tcp_tl_send_message(struct eXosip_t *excontext, osip_transaction_t *tr, osip_message_t *sip, char *host, int port, int out_socket) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  size_t length = 0;
  char *message = NULL;
  int i;
  int pos = -1;
  osip_naptr_t *naptr_record = NULL;
  int tid = -1;

  if (tr != NULL)
    tid = tr->transactionid;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] [tid=%i] wrong state: create transport layer first\n", tid));
    return OSIP_WRONG_STATE;
  }

  if (host == NULL) {
    host = sip->req_uri->host;

    if (sip->req_uri->port != NULL)
      port = osip_atoi(sip->req_uri->port);

    else
      port = 5060;
  }

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].invalid > 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] [send] socket info:[%s][%d] [sock=%d] [pos=%d] manual reset\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                            reserved->socket_tab[pos].socket, pos));
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
      _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
      continue;
    }
  }

  i = _tl_resolv_naptr_destination(excontext, tr, sip, &host, &port, &naptr_record);
  if (i == OSIP_SUCCESS + 1)
    return i;
  if (i < OSIP_SUCCESS)
    return i;

  if (out_socket > 0) {
    for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
      if (reserved->socket_tab[pos].socket != 0) {
        if (reserved->socket_tab[pos].socket == out_socket) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [tid=%i] reusing REQUEST connection to [%s][%d]\n", tid, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port));
          break;
        }
      }
    }

    if (pos == EXOSIP_MAX_SOCKETS) {
      out_socket = 0;
      if (tr != NULL)
        osip_transaction_set_out_socket(tr, 0);
    }

    if (out_socket > 0) {
      int pos2;

      /* If we have SEVERAL sockets to same destination with different port
         number, we search for the one with "SAME port" number.
         The specification is not clear about re-using the existing transaction
         in that use-case...
         Such test, will help mainly with server having 2 sockets: one for
         incoming transaction and one for outgoing transaction?
       */
      pos2 = _tcp_tl_find_socket(excontext, host, port);

      if (pos2 >= 0) {
        out_socket = reserved->socket_tab[pos2].socket;
        pos = pos2;
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [tid=%i] reusing connection --with exact port-- to [%s][%d]\n", tid, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port));
        if (tr != NULL)
          osip_transaction_set_out_socket(tr, out_socket);
      }
    }
  }

  /* Step 1: find existing socket to send message */
  if (out_socket <= 0) {
    pos = _tcp_tl_find_socket(excontext, host, port);

    if (pos >= 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [tid=%i] reusing connection to [%s][%d]\n", tid, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port));
    }

    /* Step 2: create new socket with host:port */
    if (pos < 0) {
      pos = _tcp_tl_new_socket(excontext, host, port);
    }

    if (pos >= 0) {
      out_socket = reserved->socket_tab[pos].socket;
      if (tr != NULL)
        osip_transaction_set_out_socket(tr, out_socket);
    }
  }

  if (out_socket <= 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [tid=%i] no socket can be found or created\n", tid));

    if (MSG_IS_REGISTER(sip) || MSG_IS_OPTIONS(sip)) {
      _eXosip_mark_registration_expired(excontext, sip->call_id->number);
    }

    if (tr != NULL)
      osip_transaction_set_out_socket(tr, 0);
    return -1;
  }

  if (MSG_IS_REGISTER(sip)) {
    /* this value is saved: when a connection breaks, we will ask to retry the registration */
    snprintf(reserved->socket_tab[pos].reg_call_id, sizeof(reserved->socket_tab[pos].reg_call_id), "%s", sip->call_id->number);
  }

  i = _tcptls_tl_is_connected(excontext->poll_method, out_socket);

  if (i > 0) {
    time_t now;

    if (tr != NULL) {
      now = osip_getsystemtime(NULL);

      if (tr != NULL && now - tr->birth_time > 10) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [tid=%i] socket [%s] [sock=%d] [pos=%d] timeout\n", tid, host, out_socket, pos));
        _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
        if (naptr_record != NULL && (MSG_IS_REGISTER(sip) || MSG_IS_OPTIONS(sip))) {
          if (pos >= 0) {
            _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
          }
        }

        if (tr != NULL)
          osip_transaction_set_out_socket(tr, 0);
        return -1;
      }
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [tid=%i] socket [%s] [sock=%d] [pos=%d] in progress\n", tid, host, out_socket, pos));
    }

    if (tr == NULL) {
      /* a connection was probably broken: we tried to send a message without transaction, but it failed */
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [tid=%i] a connection is missing for to [%s][%d]\n", tid, host, port));
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);

      i = _tcp_tl_build_message(excontext, sip, pos, host, &message, &length);

      if (i != 0 || length <= 0) {
        osip_free(message);
        return -1;
      }
      if (reserved->socket_tab[pos].sendbuflen + length + 1 > reserved->socket_tab[pos].sendbufsize) {
        reserved->socket_tab[pos].sendbuf = osip_realloc(reserved->socket_tab[pos].sendbuf, reserved->socket_tab[pos].sendbuflen + length + 1);
        reserved->socket_tab[pos].sendbufsize = reserved->socket_tab[pos].sendbuflen + length + 1;
      }
      memcpy(reserved->socket_tab[pos].sendbuf + reserved->socket_tab[pos].sendbuflen, message, length + 1); /* also memcpy extra \0 */
      reserved->socket_tab[pos].sendbuflen = reserved->socket_tab[pos].sendbuflen + length;

      osip_free(message);
    }
    return 1;

  } else if (i == 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [tid=%i] socket [%s] [sock=%d] [pos=%d] connected\n", tid, host, out_socket, pos));

#ifdef HAVE_SYS_EPOLL_H
    if (excontext->poll_method == EXOSIP_USE_EPOLL_LT && reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) {
      struct epoll_event ev;
      /* no need for EPOLLOUT anymore */
      memset(&ev, 0, sizeof(struct epoll_event));
      ev.events = EPOLLIN;
      ev.data.fd = reserved->socket_tab[pos].socket;
      epoll_ctl(excontext->epfd, EPOLL_CTL_MOD, reserved->socket_tab[pos].socket, &ev);
    }
#endif

    reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0;

  } else {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] [tid=%i] socket [%s] [sock=%d] [pos=%d] error\n", tid, host, out_socket, pos));
    _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
    _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
    if (tr != NULL)
      osip_transaction_set_out_socket(tr, 0);
    return -1;
  }

#ifdef MULTITASKING_ENABLED

  if (pos >= 0 && reserved->socket_tab[pos].readStream == NULL) {
    reserved->socket_tab[pos].readStream = NULL;
    reserved->socket_tab[pos].writeStream = NULL;
    CFStreamCreatePairWithSocket(kCFAllocatorDefault, out_socket, &reserved->socket_tab[pos].readStream, &reserved->socket_tab[pos].writeStream);

    if (reserved->socket_tab[pos].readStream != NULL)
      CFReadStreamSetProperty(reserved->socket_tab[pos].readStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);

    if (reserved->socket_tab[pos].writeStream != NULL)
      CFWriteStreamSetProperty(reserved->socket_tab[pos].writeStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);

    if (CFReadStreamOpen(reserved->socket_tab[pos].readStream)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [tid=%i] CFReadStreamOpen Succeeded\n", tid));
    }

    CFWriteStreamOpen(reserved->socket_tab[pos].writeStream);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [tid=%i] socket info:[%s][%d] [sock=%d] [pos=%d] family:?, connected\n", tid, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                          reserved->socket_tab[pos].socket, pos));
  }

#endif

  i = _tcp_tl_build_message(excontext, sip, pos, host, &message, &length);

  if (i != 0 || length <= 0) {
    if (tr != NULL)
      osip_transaction_set_out_socket(tr, 0);
    return -1;
  }

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [tid=%i] message sent [len=%d] to [%s][%d]\n%s\n", tid, length, host, port, message));

  if (pos >= 0 && excontext->enable_dns_cache == 1 && osip_strcasecmp(host, reserved->socket_tab[pos].remote_ip) != 0 && MSG_IS_REQUEST(sip)) {
    if (MSG_IS_REGISTER(sip)) {
      struct eXosip_dns_cache entry;

      memset(&entry, 0, sizeof(struct eXosip_dns_cache));
      snprintf(entry.host, sizeof(entry.host), "%s", host);
      snprintf(entry.ip, sizeof(entry.ip), "%s", reserved->socket_tab[pos].remote_ip);
      eXosip_set_option(excontext, EXOSIP_OPT_ADD_DNS_CACHE, (void *) &entry);
    }
  }

  i = _tcp_tl_send(excontext, out_socket, (const char *) message, (int) length);

  if (i < 0) {
    if (pos >= 0) {
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
      _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
    }
    if (tr != NULL)
      osip_transaction_set_out_socket(tr, 0);
  }

  if (i == 0 && tr != NULL && MSG_IS_REGISTER(sip) && pos >= 0) {
    /* start a timeout to destroy connection if no answer */
    reserved->socket_tab[pos].tcp_max_timeout = osip_getsystemtime(NULL) + 32;
  }

  osip_free(message);
  return i;
}

#ifdef ENABLE_KEEP_ALIVE_OPTIONS_METHOD
static int _tcp_tl_get_socket_info(int socket, char *host, int hostsize, int *port) {
  struct sockaddr addr;
  int nameLen = sizeof(addr);
  int ret;

  if (socket <= 0 || host == NULL || hostsize <= 0 || port == NULL)
    return OSIP_BADPARAMETER;

  ret = getsockname(socket, &addr, &nameLen);

  if (ret != 0) {
    /* ret = ex_errno; */
    return OSIP_UNDEFINED_ERROR;

  } else {
    ret = _eXosip_getnameinfo((struct sockaddr *) &addr, nameLen, host, hostsize, NULL, 0, NI_NUMERICHOST);

    if (ret != 0)
      return OSIP_UNDEFINED_ERROR;

    if (addr.sa_family == AF_INET)
      (*port) = ntohs(((struct sockaddr_in *) &addr)->sin_port);

    else
      (*port) = ntohs(((struct sockaddr_in6 *) &addr)->sin6_port);
  }

  return OSIP_SUCCESS;
}
#endif

static int tcp_tl_keepalive(struct eXosip_t *excontext) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  char buf[5] = "\r\n\r\n";
  int pos;
  int i;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->tcp_socket <= 0)
    return OSIP_UNDEFINED_ERROR;

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket > 0) {
      i = _tcptls_tl_is_connected(excontext->poll_method, reserved->socket_tab[pos].socket);

      if (i > 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [keepalive] socket info:[%s][%d] [sock=%d] [pos=%d] in progress\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].socket, pos));
        continue;

      } else if (i == 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [keepalive] socket info:[%s][%d] [sock=%d] [pos=%d] connected\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].socket, pos));

#ifdef HAVE_SYS_EPOLL_H
        if (excontext->poll_method == EXOSIP_USE_EPOLL_LT && reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) {
          struct epoll_event ev;
          /* no need for EPOLLOUT anymore */
          memset(&ev, 0, sizeof(struct epoll_event));
          ev.events = EPOLLIN;
          ev.data.fd = reserved->socket_tab[pos].socket;
          epoll_ctl(excontext->epfd, EPOLL_CTL_MOD, reserved->socket_tab[pos].socket, &ev);
        }
#endif

        reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0;

      } else {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] [keepalive] socket info:[%s][%d] [sock=%d] [pos=%d] error\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].socket, pos));
        _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
        _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        continue;
      }

      if (excontext->ka_interval > 0) {
#ifdef ENABLE_KEEP_ALIVE_OPTIONS_METHOD

        if (excontext->ka_options != 0) {
          osip_message_t *options;
          char from[NI_MAXHOST];
          char to[NI_MAXHOST];
          char locip[NI_MAXHOST];
          int locport;
          char *message;
          size_t length;

          options = NULL;
          memset(to, '\0', sizeof(to));
          memset(from, '\0', sizeof(from));
          memset(locip, '\0', sizeof(locip));
          locport = 0;

          snprintf(to, sizeof(to), "<sip:%s:%d>", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port);
          _tcp_tl_get_socket_info(reserved->socket_tab[pos].socket, locip, sizeof(locip), &locport);

          if (locip[0] == '\0') {
            OSIP_TRACE(
                osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [keepalive] socket [%s] [sock=%d] [pos=%d] failed to create sip options message\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].socket, pos));
            continue;
          }

          snprintf(from, sizeof(from), "<sip:%s:%d>", locip, locport);

          /* Generate an options message */
          if (eXosip_options_build_request(excontext, &options, to, from, NULL) == OSIP_SUCCESS) {
            message = NULL;
            length = 0;

            /* Convert message to str for direct sending over correct socket */
            if (osip_message_to_str(options, &message, &length) == OSIP_SUCCESS) {
              OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [keepalive] socket [%s] [sock=%d] [pos=%d] sending sip options\n%s", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].socket, pos, message));
              i = (int) send(reserved->socket_tab[pos].socket, (const void *) message, length, 0);
              osip_free(message);

              if (i > 0) {
                OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TCP] [keepalive] keep alive sent on TCP\n"));
              }

            } else {
              OSIP_TRACE(
                  osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [keepalive] socket [%s] [sock=%d] [pos=%d] failed to convert sip options message\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].socket, pos));
            }

          } else {
            OSIP_TRACE(
                osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [keepalive] socket [%s] [sock=%d] [pos=%d] failed to create sip options message\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].socket, pos));
          }

          continue;
        }

#endif
        i = (int) send(reserved->socket_tab[pos].socket, (const void *) buf, 4, 0);
        reserved->socket_tab[pos].ping_rfc5626 = osip_getsystemtime(NULL) + 9;
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TCP] [keepalive] [ret=%i] socket [%s] [sock=%d] [pos=%d]\n", i, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].socket, pos));
      }
    }
  }

  return OSIP_SUCCESS;
}

static int tcp_tl_set_socket(struct eXosip_t *excontext, int socket) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  reserved->tcp_socket = socket;

  return OSIP_SUCCESS;
}

static int tcp_tl_masquerade_contact(struct eXosip_t *excontext, const char *public_address, int port) {
  if (public_address == NULL || public_address[0] == '\0') {
    memset(excontext->tcp_firewall_ip, '\0', sizeof(excontext->tcp_firewall_ip));
    memset(excontext->tcp_firewall_port, '\0', sizeof(excontext->tcp_firewall_port));
    return OSIP_SUCCESS;
  }

  snprintf(excontext->tcp_firewall_ip, sizeof(excontext->tcp_firewall_ip), "%s", public_address);

  if (port > 0) {
    snprintf(excontext->tcp_firewall_port, sizeof(excontext->tcp_firewall_port), "%i", port);
  }

  return OSIP_SUCCESS;
}

static int tcp_tl_get_masquerade_contact(struct eXosip_t *excontext, char *ip, int ip_size, char *port, int port_size) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;

  memset(ip, 0, ip_size);
  memset(port, 0, port_size);

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (excontext->tcp_firewall_ip[0] != '\0')
    snprintf(ip, ip_size, "%s", excontext->tcp_firewall_ip);

  if (excontext->tcp_firewall_port[0] != '\0')
    snprintf(port, port_size, "%s", excontext->tcp_firewall_port);

  return OSIP_SUCCESS;
}

static int tcp_tl_update_contact(struct eXosip_t *excontext, osip_message_t *req) {
  req->application_data = (void *) 0x1; /* request for masquerading */
  return OSIP_SUCCESS;
}

static int tcp_tl_check_all_connection(struct eXosip_t *excontext) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->tcp_socket <= 0)
    return OSIP_UNDEFINED_ERROR;

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [checkall] checking all connection\n"));
  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket > 0) {
      if (reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) {
        time_t now = osip_getsystemtime(NULL);

        if (now > reserved->socket_tab[pos].tcp_inprogress_max_timeout) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [checkall] socket is in progress since 32 seconds / close socket\n"));
          reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0;
          _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
          _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
          continue;
        }

        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [checkall] socket info:[%s][%d] [sock=%d] [pos=%d] in progress\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].socket, pos));
        continue;
      } else if (reserved->socket_tab[pos].ping_rfc5626 > 0 && reserved->socket_tab[pos].pong_supported > 0) {
        time_t now = osip_getsystemtime(NULL);

        if (now > reserved->socket_tab[pos].ping_rfc5626) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [checkall] no pong[CRLF] for ping[CRLFCRLF]\n"));
          reserved->socket_tab[pos].tcp_max_timeout = 0;
          _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
          _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
          continue;
        }

      } else if (reserved->socket_tab[pos].tcp_inprogress_max_timeout == 0 && reserved->socket_tab[pos].tcp_max_timeout > 0) {
        time_t now = osip_getsystemtime(NULL);

        if (now > reserved->socket_tab[pos].tcp_max_timeout) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [checkall] we expected a reply on established sockets / close socket\n"));
          reserved->socket_tab[pos].tcp_max_timeout = 0;
          _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
          _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
          continue;
        }
      }
    }
  }

  return OSIP_SUCCESS;
}

static int tcp_tl_check_connection(struct eXosip_t *excontext, int socket) {
  struct eXtltcp *reserved = (struct eXtltcp *) excontext->eXtltcp_reserved;
  int pos;
  int i;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (socket == -1) {
    return tcp_tl_check_all_connection(excontext);
  }

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket == socket)
      break;
  }
  if (pos == EXOSIP_MAX_SOCKETS)
    return OSIP_NOTFOUND;

  i = _tcptls_tl_is_connected(excontext->poll_method, reserved->socket_tab[pos].socket);

  if (i > 0) {
    if (reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) {
      time_t now = osip_getsystemtime(NULL);

      if (now > reserved->socket_tab[pos].tcp_inprogress_max_timeout) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [check] socket is in progress since 32 seconds / close socket\n"));
        reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0;
        _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
        _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        return OSIP_SUCCESS;
      }
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [check] socket info:[%s][%d] [sock=%d] [pos=%d] in progress\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                          reserved->socket_tab[pos].socket, pos));
    return OSIP_SUCCESS;

  } else if (i == 0) {
#ifdef HAVE_SYS_EPOLL_H
    if (excontext->poll_method == EXOSIP_USE_EPOLL_LT && reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) {
      struct epoll_event ev;
      /* no need for EPOLLOUT anymore */
      memset(&ev, 0, sizeof(struct epoll_event));
      ev.events = EPOLLIN;
      ev.data.fd = reserved->socket_tab[pos].socket;
      epoll_ctl(excontext->epfd, EPOLL_CTL_MOD, reserved->socket_tab[pos].socket, &ev);
    }
#endif

    reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0;

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [check] socket info:[%s][%d] [sock=%d] [pos=%d] connected\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                          reserved->socket_tab[pos].socket, pos));

    if (reserved->socket_tab[pos].tcp_max_timeout > 0) {
      time_t now = osip_getsystemtime(NULL);

      if (now > reserved->socket_tab[pos].tcp_max_timeout) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [check] we excepted a reply on established sockets / close socket\n"));
        reserved->socket_tab[pos].tcp_max_timeout = 0;
        _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
        _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        return OSIP_SUCCESS;
      }
    }

    return OSIP_SUCCESS;
  } else {
    OSIP_TRACE(
        osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TCP] [check] socket info:[%s][%d] [sock=%d] [pos=%d] error\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port, reserved->socket_tab[pos].socket, pos));
    _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
    _tcp_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
    return OSIP_SUCCESS;
  }

  return OSIP_SUCCESS;
}

static struct eXtl_protocol eXtl_tcp = {1,
                                        5060,
                                        "TCP",
                                        "0.0.0.0",
                                        IPPROTO_TCP,
                                        AF_INET,
                                        0,
                                        0,
                                        0,

                                        &tcp_tl_init,
                                        &tcp_tl_free,
                                        &tcp_tl_open,
                                        &tcp_tl_set_fdset,
                                        &tcp_tl_read_message,
#ifdef HAVE_SYS_EPOLL_H
                                        &tcp_tl_epoll_read_message,
#endif
                                        &tcp_tl_send_message,
                                        &tcp_tl_keepalive,
                                        &tcp_tl_set_socket,
                                        &tcp_tl_masquerade_contact,
                                        &tcp_tl_get_masquerade_contact,
                                        &tcp_tl_update_contact,
                                        &tcp_tl_reset,
                                        &tcp_tl_check_connection};

void eXosip_transport_tcp_init(struct eXosip_t *excontext) {
  memcpy(&excontext->eXtl_transport, &eXtl_tcp, sizeof(struct eXtl_protocol));
}
