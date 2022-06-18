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

#if !defined(HAVE_INET_NTOP)
#include "inet_ntop.h"
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_MSTCPIP_H
#include <Mstcpip.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_WINCRYPT_H
#include <wincrypt.h>
#endif

#if !defined(_WIN32_WCE)
#include <errno.h>
#endif

#if defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
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

#ifdef HAVE_OPENSSL_SSL_H

#include <openssl/ssl.h>

#if !(OPENSSL_VERSION_NUMBER < 0x00908000L)

#define SPROTO_TLS 500
#define SPROTO_DTLS 501
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#define SSLDEBUG 1

#define PASSWORD "password"
#define CLIENT_KEYFILE "ckey.pem"
#define CLIENT_CERTFILE "c.pem"
#define SERVER_KEYFILE "skey.pem"
#define SERVER_CERTFILE "s.pem"
#define CA_LIST "cacert.pem"
#define RANDOM "random.pem"
#define DHFILE "dh1024.pem"

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

static void SSL_set0_rbio(SSL *s, BIO *rbio) {
  BIO_free_all(s->rbio);
  s->rbio = rbio;
}

#endif

SSL_CTX *initialize_client_ctx(struct eXosip_t *excontext, eXosip_tls_ctx_t *client_ctx, int transport);
SSL_CTX *initialize_server_ctx(struct eXosip_t *excontext, eXosip_tls_ctx_t *srv_ctx, int transport);

/* persistent connection */
struct _dtls_stream {
  char remote_ip[65];
  int remote_port;
  SSL *ssl_conn;
  int ssl_state;
  int ssl_type;
};

struct eXtldtls {
  eXosip_tls_ctx_t eXosip_dtls_ctx_params;

  int dtls_socket;
  struct sockaddr_storage ai_addr;

  SSL_CTX *server_ctx;
  SSL_CTX *client_ctx;
  struct _dtls_stream socket_tab[EXOSIP_MAX_SOCKETS];
};

static int dtls_tl_init(struct eXosip_t *excontext) {
  struct eXtldtls *reserved = (struct eXtldtls *) osip_malloc(sizeof(struct eXtldtls));

  if (reserved == NULL)
    return OSIP_NOMEM;

  reserved->dtls_socket = 0;
  reserved->server_ctx = NULL;
  reserved->client_ctx = NULL;
  memset(&reserved->ai_addr, 0, sizeof(struct sockaddr_storage));
  memset(&reserved->socket_tab, 0, sizeof(struct _dtls_stream) * EXOSIP_MAX_SOCKETS);

  memset(&reserved->eXosip_dtls_ctx_params, 0, sizeof(eXosip_tls_ctx_t));

  /* TODO: make it configurable (as for TLS) */
  osip_strncpy(reserved->eXosip_dtls_ctx_params.client.priv_key, CLIENT_KEYFILE, sizeof(reserved->eXosip_dtls_ctx_params.client.priv_key) - 1);
  osip_strncpy(reserved->eXosip_dtls_ctx_params.client.priv_key, CLIENT_CERTFILE, sizeof(reserved->eXosip_dtls_ctx_params.client.priv_key) - 1);
  osip_strncpy(reserved->eXosip_dtls_ctx_params.client.priv_key_pw, PASSWORD, sizeof(reserved->eXosip_dtls_ctx_params.client.priv_key_pw) - 1);

  osip_strncpy(reserved->eXosip_dtls_ctx_params.server.priv_key, SERVER_KEYFILE, sizeof(reserved->eXosip_dtls_ctx_params.server.priv_key) - 1);
  osip_strncpy(reserved->eXosip_dtls_ctx_params.server.priv_key, SERVER_CERTFILE, sizeof(reserved->eXosip_dtls_ctx_params.server.priv_key) - 1);
  osip_strncpy(reserved->eXosip_dtls_ctx_params.server.priv_key_pw, PASSWORD, sizeof(reserved->eXosip_dtls_ctx_params.server.priv_key_pw) - 1);

  excontext->eXtldtls_reserved = reserved;
  return OSIP_SUCCESS;
}

static int _dtls_print_ssl_error(int err) {
  switch (err) {
  case SSL_ERROR_NONE:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] SSL ERROR NONE - OK\n"));
    break;

  case SSL_ERROR_ZERO_RETURN:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] SSL ERROR ZERO RETURN - SHUTDOWN\n"));
    break;

  case SSL_ERROR_WANT_READ:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] SSL want read\n"));
    break;

  case SSL_ERROR_WANT_WRITE:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] SSL want write\n"));
    break;

  case SSL_ERROR_SSL:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] SSL ERROR\n"));
    break;

  case SSL_ERROR_SYSCALL:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] SSL ERROR SYSCALL\n"));
    break;

  default:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] SSL problem\n"));
  }

  return OSIP_SUCCESS;
}

static int shutdown_free_server_dtls(struct eXosip_t *excontext, int pos) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;
  int i, err;

  if (reserved->socket_tab[pos].ssl_type == 1) {
    if (reserved->socket_tab[pos].ssl_conn != NULL) {
#ifdef SSLDEBUG
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [DTLS] DTLS-UDP server SSL_shutdown\n"));
#endif

      i = SSL_shutdown(reserved->socket_tab[pos].ssl_conn);

      if (i <= 0) {
        err = SSL_get_error(reserved->socket_tab[pos].ssl_conn, i);
        _dtls_print_ssl_error(err);
#ifdef SSLDEBUG

        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] DTLS-UDP server shutdown <= 0\n"));
#endif

      } else {
#ifdef SSLDEBUG
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [DTLS] DTLS-UDP server shutdown > 0\n"));
#endif
      }

      SSL_free(reserved->socket_tab[pos].ssl_conn);

#if 0

      if (reserved->socket_tab[pos].ssl_ctx != NULL)
        SSL_CTX_free(reserved->socket_tab[pos].ssl_ctx);

#endif

      memset(&(reserved->socket_tab[pos]), 0, sizeof(struct _dtls_stream));

      return OSIP_SUCCESS;

    } else {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] DTLS-UDP server shutdown: invalid SSL object\n"));
      return -1;
    }
  }

  return -1;
}

static int shutdown_free_client_dtls(struct eXosip_t *excontext, int pos) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;
  int i, err;
  BIO *rbio;

  struct addrinfo *addrinfo;
  struct __eXosip_sockaddr addr;

  if (reserved->socket_tab[pos].ssl_type == 2) {
    if (reserved->socket_tab[pos].ssl_conn != NULL) {
      i = _eXosip_get_addrinfo(excontext, &addrinfo, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port, IPPROTO_UDP);

      if (i != 0) {
        return -1;
      }

      memcpy(&addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
      _eXosip_freeaddrinfo(addrinfo);

      rbio = BIO_new_dgram(reserved->dtls_socket, BIO_NOCLOSE);

      BIO_ctrl(rbio, BIO_CTRL_DGRAM_SET_PEER, 0, (char *) &addr);

      SSL_set0_rbio(reserved->socket_tab[pos].ssl_conn, rbio);

      i = SSL_shutdown(reserved->socket_tab[pos].ssl_conn);

      if (i <= 0) {
        err = SSL_get_error(reserved->socket_tab[pos].ssl_conn, i);
#ifdef SSLDEBUG

        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] DTLS-UDP client shutdown error [%d] <= 0\n", i));
#endif

        _dtls_print_ssl_error(err);

      } else {
#ifdef SSLDEBUG
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [DTLS] DTLS-UDP client shutdown > 0\n"));
#endif
      }

      SSL_free(reserved->socket_tab[pos].ssl_conn);

#if 0

      if (reserved->socket_tab[pos].ssl_ctx != NULL)
        SSL_CTX_free(reserved->socket_tab[pos].ssl_ctx);

#endif

      memset(&(reserved->socket_tab[pos]), 0, sizeof(struct _dtls_stream));

      return OSIP_SUCCESS;

    } else {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] DTLS-UDP client shutdown: invalid SSL object\n"));
      return -1;
    }
  }

  return -1;
}

static int dtls_tl_free(struct eXosip_t *excontext) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;
  int pos;

  if (reserved == NULL)
    return OSIP_SUCCESS;

  if (reserved->server_ctx != NULL)
    SSL_CTX_free(reserved->server_ctx);

  if (reserved->client_ctx != NULL)
    SSL_CTX_free(reserved->client_ctx);

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].ssl_conn != NULL) {
      shutdown_free_client_dtls(excontext, pos);
      shutdown_free_server_dtls(excontext, pos);
    }
  }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
  ERR_remove_thread_state(NULL);
#else
  ERR_remove_state(0);
#endif
#endif

  memset(&reserved->socket_tab, 0, sizeof(struct _dtls_stream) * EXOSIP_MAX_SOCKETS);

  memset(&reserved->ai_addr, 0, sizeof(struct sockaddr_storage));

  if (reserved->dtls_socket > 0)
    _eXosip_closesocket(reserved->dtls_socket);

  reserved->dtls_socket = 0;

  osip_free(reserved);
  excontext->eXtldtls_reserved = NULL;
  return OSIP_SUCCESS;
}

static int dtls_tl_open(struct eXosip_t *excontext) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;
  int res;
  struct addrinfo *addrinfo = NULL;
  struct addrinfo *curinfo;
  int sock = -1;
  char eb[ERRBSIZ];

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  excontext->eXtl_transport.proto_local_port = excontext->eXtl_transport.proto_port;

  if (excontext->eXtl_transport.proto_local_port < 0)
    excontext->eXtl_transport.proto_local_port = 5061;

  /* TODO: allow parameters for DTLS */
  reserved->server_ctx = initialize_server_ctx(excontext , & reserved->eXosip_dtls_ctx_params, IPPROTO_UDP);
  reserved->client_ctx = initialize_client_ctx(excontext, &reserved->eXosip_dtls_ctx_params, IPPROTO_UDP);

  res = _eXosip_get_addrinfo(excontext, &addrinfo, excontext->eXtl_transport.proto_ifs, excontext->eXtl_transport.proto_local_port, excontext->eXtl_transport.proto_num);

  if (res)
    return -1;

  for (curinfo = addrinfo; curinfo; curinfo = curinfo->ai_next) {
    socklen_t len;
    int type;

    if (curinfo->ai_protocol && curinfo->ai_protocol != excontext->eXtl_transport.proto_num) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [DTLS] skipping protocol [%d]\n", curinfo->ai_protocol));
      continue;
    }

    type = curinfo->ai_socktype;
#if defined(SOCK_CLOEXEC)
    type = SOCK_CLOEXEC | type;
#endif
    sock = (int) socket(curinfo->ai_family, type, curinfo->ai_protocol);

    if (sock < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] cannot create socket %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      continue;
    }

    if (curinfo->ai_family == AF_INET6) {
#ifdef IPV6_V6ONLY

      if (setsockopt_ipv6only(sock)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] cannot set socket option %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
        _eXosip_closesocket(sock);
        sock = -1;
        continue;
      }

#endif /* IPV6_V6ONLY */
    }

    res = bind(sock, curinfo->ai_addr, (socklen_t) curinfo->ai_addrlen);

    if (res < 0) {
      OSIP_TRACE(
          osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] cannot bind socket [%s][%s] %s\n", excontext->eXtl_transport.proto_ifs, (curinfo->ai_family == AF_INET) ? "AF_INET" : "AF_INET6", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      _eXosip_closesocket(sock);
      sock = -1;
      continue;
    }

    len = sizeof(reserved->ai_addr);
    res = getsockname(sock, (struct sockaddr *) &reserved->ai_addr, &len);

    if (res != 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] cannot get socket name %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      memcpy(&reserved->ai_addr, curinfo->ai_addr, curinfo->ai_addrlen);
    }

    if (excontext->eXtl_transport.proto_num == IPPROTO_TCP) {
      res = listen(sock, SOMAXCONN);

      if (res < 0) {
        OSIP_TRACE(
            osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] cannot bind socket [%s][%s] %s\n", excontext->eXtl_transport.proto_ifs, (curinfo->ai_family == AF_INET) ? "AF_INET" : "AF_INET6", _ex_strerror(ex_errno, eb, ERRBSIZ)));
        _eXosip_closesocket(sock);
        sock = -1;
        continue;
      }
    }

    break;
  }

  _eXosip_freeaddrinfo(addrinfo);

  if (sock < 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] cannot bind on port [%i]\n", excontext->eXtl_transport.proto_local_port));
    return -1;
  }

  reserved->dtls_socket = sock;

  if (excontext->eXtl_transport.proto_local_port == 0) {
    /* get port number from socket */
    if (reserved->ai_addr.ss_family == AF_INET)
      excontext->eXtl_transport.proto_local_port = ntohs(((struct sockaddr_in *) &reserved->ai_addr)->sin_port);

    else
      excontext->eXtl_transport.proto_local_port = ntohs(((struct sockaddr_in6 *) &reserved->ai_addr)->sin6_port);

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [DTLS] binding on port [%i]\n", excontext->eXtl_transport.proto_local_port));
  }

  return OSIP_SUCCESS;
}

#define EXOSIP_AS_A_SERVER 1
#define EXOSIP_AS_A_CLIENT 2

static int dtls_tl_set_fdset(struct eXosip_t *excontext, fd_set *osip_fdset, fd_set *osip_wrset, fd_set *osip_exceptset, int *fd_max, int *osip_fd_table) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;
  int pos_fd = 0;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->dtls_socket <= 0)
    return -1;

  if (osip_fdset != NULL)
    eXFD_SET(reserved->dtls_socket, osip_fdset);
  osip_fd_table[pos_fd] = reserved->dtls_socket;
  pos_fd++;

  if (reserved->dtls_socket > *fd_max)
    *fd_max = reserved->dtls_socket;

  return OSIP_SUCCESS;
}

static int _dtls_read_udp_main_socket(struct eXosip_t *excontext) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;
  struct sockaddr_storage sa;
  socklen_t slen;
  char *enc_buf;
  char *dec_buf;
  int i;
  int enc_buf_len;

  if (reserved->ai_addr.ss_family == AF_INET)
    slen = sizeof(struct sockaddr_in);

  else
    slen = sizeof(struct sockaddr_in6);

  enc_buf = (char *) osip_malloc(SIP_MESSAGE_MAX_LENGTH * sizeof(char) + 1);

  if (enc_buf == NULL)
    return OSIP_NOMEM;

  enc_buf_len = (int) recvfrom(reserved->dtls_socket, enc_buf, SIP_MESSAGE_MAX_LENGTH, 0, (struct sockaddr *) &sa, &slen);

  if (enc_buf_len > 5) {
    char src6host[NI_MAXHOST];
    int recvport = 0;
    int err;

    BIO *rbio;
    struct _dtls_stream *_dtls_stream_used = NULL;
    int pos;

    enc_buf[enc_buf_len] = '\0';

    memset(src6host, 0, NI_MAXHOST);
    recvport = _eXosip_getport((struct sockaddr *) &sa);
    _eXosip_getnameinfo((struct sockaddr *) &sa, slen, src6host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [DTLS] message received from [%s][%d]\n", src6host, recvport));

    for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
      if (reserved->socket_tab[pos].ssl_conn != NULL) {
        if (reserved->socket_tab[pos].remote_port == recvport && (strcmp(reserved->socket_tab[pos].remote_ip, src6host) == 0)) {
          _dtls_stream_used = &reserved->socket_tab[pos];
          break;
        }
      }
    }

    if (_dtls_stream_used == NULL) {
      for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
        if (reserved->socket_tab[pos].ssl_conn == NULL) {
          /* should accept this connection? */
          break;
        }
      }

      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [DTLS] creating DTLS-UDP socket at index %i\n", pos));

      if (pos < 0) {
        /* delete an old one! */
        pos = 0;

        if (reserved->socket_tab[pos].ssl_conn != NULL) {
          shutdown_free_client_dtls(excontext, pos);
          shutdown_free_server_dtls(excontext, pos);
        }

        memset(&reserved->socket_tab[pos], 0, sizeof(struct _dtls_stream));
      }
    }

    if (reserved->socket_tab[pos].ssl_conn == NULL) {
      BIO *wbio;

      if (!SSL_CTX_check_private_key(reserved->server_ctx)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] SSL CTX private key check error\n"));
        osip_free(enc_buf);
        return -1;
      }

      /* behave as a server: */
      reserved->socket_tab[pos].ssl_conn = SSL_new(reserved->server_ctx);

      if (reserved->socket_tab[pos].ssl_conn == NULL) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] SSL_new error\n"));
        osip_free(enc_buf);
        return -1;
      }

      /* No MTU query */
#ifdef SSL_OP_NO_QUERY_MTU
      SSL_set_options(reserved->socket_tab[pos].ssl_conn, SSL_OP_NO_QUERY_MTU);
      SSL_set_mtu(reserved->socket_tab[pos].ssl_conn, 1200);
#endif
      /* MTU query */
      /* BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL); */
#ifdef SSL_OP_COOKIE_EXCHANGE
      SSL_set_options(reserved->socket_tab[pos].ssl_conn, SSL_OP_COOKIE_EXCHANGE);
#endif
      wbio = BIO_new_dgram(reserved->dtls_socket, BIO_NOCLOSE);
      BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_PEER, 0, (char *) &sa);
      SSL_set_bio(reserved->socket_tab[pos].ssl_conn, NULL, wbio);

      SSL_set_accept_state(reserved->socket_tab[pos].ssl_conn);

      reserved->socket_tab[pos].ssl_state = 0;
      reserved->socket_tab[pos].ssl_type = EXOSIP_AS_A_SERVER;

      osip_strncpy(reserved->socket_tab[pos].remote_ip, src6host, sizeof(reserved->socket_tab[pos].remote_ip) - 1);
      reserved->socket_tab[pos].remote_port = recvport;

      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [DTLS] incoming DTLS-UDP connection accepted\n"));
    }

    dec_buf = (char *) osip_malloc(SIP_MESSAGE_MAX_LENGTH * sizeof(char) + 1);

    if (dec_buf == NULL) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] allocation error\n"));
      osip_free(enc_buf);
      return OSIP_NOMEM;
    }

    rbio = BIO_new_mem_buf(enc_buf, enc_buf_len);
    BIO_set_mem_eof_return(rbio, -1);

    SSL_set0_rbio(reserved->socket_tab[pos].ssl_conn, rbio);

    i = SSL_read(reserved->socket_tab[pos].ssl_conn, dec_buf, SIP_MESSAGE_MAX_LENGTH);
    /* done with the rbio */
    rbio = BIO_new(BIO_s_mem());
    SSL_set0_rbio(reserved->socket_tab[pos].ssl_conn, rbio);

    if (i > 5) {
      dec_buf[i] = '\0';

      _eXosip_handle_incoming_message(excontext, dec_buf, i, reserved->dtls_socket, src6host, recvport, NULL, NULL);

    } else if (i <= 0) {
      err = SSL_get_error(reserved->socket_tab[pos].ssl_conn, i);
      _dtls_print_ssl_error(err);

      if (err == SSL_ERROR_SYSCALL) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [DTLS] DTLS-UDP SYSCALL on SSL_read\n"));

      } else if (err == SSL_ERROR_SSL || err == SSL_ERROR_ZERO_RETURN) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [DTLS] DTLS-UDP closed\n"));

        shutdown_free_client_dtls(excontext, pos);
        shutdown_free_server_dtls(excontext, pos);

        memset(&(reserved->socket_tab[pos]), 0, sizeof(reserved->socket_tab[pos]));
      }

    } else {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [DTLS] dummy SIP message received\n"));
    }

    osip_free(dec_buf);
    osip_free(enc_buf);
  }

  return OSIP_SUCCESS;
}

static int dtls_tl_read_message(struct eXosip_t *excontext, fd_set *osip_fdset, fd_set *osip_wrset, fd_set *osip_exceptset) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->dtls_socket <= 0)
    return -1;

  if (FD_ISSET(reserved->dtls_socket, osip_fdset)) {
    _dtls_read_udp_main_socket(excontext);
  }

  return OSIP_SUCCESS;
}

static int dtls_tl_update_contact(struct eXosip_t *excontext, osip_message_t *req) {
  req->application_data = (void *) 0x1; /* request for masquerading */
  return OSIP_SUCCESS;
}

static int _dtls_tl_update_contact(struct eXosip_t *excontext, osip_message_t *req) {
  struct eXosip_account_info *ainfo = NULL;
  char *proxy = NULL;
  int i;
  osip_via_t *via = NULL;

  if (req->application_data != (void *) 0x1)
    return OSIP_SUCCESS;

  req->application_data = (void *) 0x0; /* avoid doing twice */

  if (MSG_IS_REQUEST(req)) {
    if (req->from != NULL && req->from->url != NULL && req->from->url->host != NULL)
      proxy = req->from->url->host;

    osip_message_get_via(req, 0, &via);

  } else {
    if (req->to != NULL && req->to->url != NULL && req->to->url->host != NULL)
      proxy = req->to->url->host;
  }

  if (proxy != NULL) {
    for (i = 0; i < MAX_EXOSIP_ACCOUNT_INFO; i++) {
      if (excontext->account_entries[i].proxy[0] != '\0') {
        if (strstr(excontext->account_entries[i].proxy, proxy) != NULL || strstr(proxy, excontext->account_entries[i].proxy) != NULL) {
          /* use ainfo */
          if (excontext->account_entries[i].nat_ip[0] != '\0') {
            ainfo = &excontext->account_entries[i];
            break;
          }
        }
      }
    }
  }

  if (excontext->dtls_firewall_ip[0] != '\0' || excontext->auto_masquerade_contact > 0) {
    osip_list_iterator_t it;
    osip_contact_t *co = (osip_contact_t *) osip_list_get_first(&req->contacts, &it);

    while (co != NULL) {
      if (co != NULL && co->url != NULL && co->url->host != NULL) {
        if (ainfo == NULL) {
          if (excontext->dtls_firewall_port[0] == '\0') {
          } else if (co->url->port == NULL && 0 != osip_strcasecmp(excontext->dtls_firewall_port, "5061")) {
            co->url->port = osip_strdup(excontext->dtls_firewall_port);
            osip_message_force_update(req);

          } else if (co->url->port != NULL && 0 != osip_strcasecmp(excontext->dtls_firewall_port, co->url->port)) {
            osip_free(co->url->port);
            co->url->port = osip_strdup(excontext->dtls_firewall_port);
            osip_message_force_update(req);
          }

        } else {
          if (co->url->port == NULL && ainfo->nat_port != 5060) {
            co->url->port = osip_malloc(10);

            if (co->url->port == NULL)
              return OSIP_NOMEM;

            snprintf(co->url->port, 9, "%i", ainfo->nat_port);
            osip_message_force_update(req);

          } else if (co->url->port != NULL && ainfo->nat_port != atoi(co->url->port)) {
            osip_free(co->url->port);
            co->url->port = osip_malloc(10);

            if (co->url->port == NULL)
              return OSIP_NOMEM;

            snprintf(co->url->port, 9, "%i", ainfo->nat_port);
            osip_message_force_update(req);
          }

#if 1

          if (ainfo->nat_ip[0] != '\0') {
            osip_free(co->url->host);
            co->url->host = osip_strdup(ainfo->nat_ip);
            osip_message_force_update(req);
          }

#endif
        }
      }

      co = (osip_contact_t *) osip_list_get_next(&it);
    }
  }

  if (excontext->masquerade_via)
    if (via != NULL) {
      if (ainfo == NULL) {
        if (excontext->dtls_firewall_port[0] == '\0') {
        } else if (via->port == NULL && 0 != osip_strcasecmp(excontext->dtls_firewall_port, "5060")) {
          via->port = osip_strdup(excontext->dtls_firewall_port);
          osip_message_force_update(req);

        } else if (via->port != NULL && 0 != osip_strcasecmp(excontext->dtls_firewall_port, via->port)) {
          osip_free(via->port);
          via->port = osip_strdup(excontext->dtls_firewall_port);
          osip_message_force_update(req);
        }

      } else {
        if (via->port == NULL && ainfo->nat_port != 5060) {
          via->port = osip_malloc(10);

          if (via->port == NULL)
            return OSIP_NOMEM;

          snprintf(via->port, 9, "%i", ainfo->nat_port);
          osip_message_force_update(req);

        } else if (via->port != NULL && ainfo->nat_port != atoi(via->port)) {
          osip_free(via->port);
          via->port = osip_malloc(10);

          if (via->port == NULL)
            return OSIP_NOMEM;

          snprintf(via->port, 9, "%i", ainfo->nat_port);
          osip_message_force_update(req);
        }

#if 1

        if (ainfo->nat_ip[0] != '\0') {
          osip_free(via->host);
          via->host = osip_strdup(ainfo->nat_ip);
          osip_message_force_update(req);
        }

#endif
      }
    }

  return OSIP_SUCCESS;
}

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 65
#endif

static int dtls_tl_send_message(struct eXosip_t *excontext, osip_transaction_t *tr, osip_message_t *sip, char *host, int port, int out_socket) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;
  socklen_t len = 0;
  size_t length = 0;
  struct addrinfo *addrinfo;
  struct __eXosip_sockaddr addr;
  char *message;

  char ipbuf[INET6_ADDRSTRLEN];
  int i;
  osip_naptr_t *naptr_record = NULL;

  int pos;
  struct _dtls_stream *_dtls_stream_used = NULL;
  BIO *sbio = NULL;
  int tid = -1;

  if (tr != NULL)
    tid = tr->transactionid;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] [tid=%i] wrong state: create transport layer first\n", tid));
    return OSIP_WRONG_STATE;
  }

  if (reserved->dtls_socket <= 0)
    return -1;

  if (host == NULL) {
    host = sip->req_uri->host;

    if (sip->req_uri->port != NULL)
      port = osip_atoi(sip->req_uri->port);

    else
      port = 5061;
  }

  if (port == 5060)
    port = 5061;

  i = -1;

  if (tr == NULL) {
    _eXosip_srv_lookup(excontext, sip, &naptr_record);

    if (naptr_record != NULL) {
      eXosip_dnsutils_dns_process(naptr_record, 1);

      if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
        eXosip_dnsutils_dns_process(naptr_record, 1);
    }

    if (naptr_record != NULL && naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVDONE) {
      /* 4: check if we have the one we want... */
      if (naptr_record->sipdtls_record.name[0] != '\0' && naptr_record->sipdtls_record.srventry[naptr_record->sipdtls_record.index].srv[0] != '\0') {
        /* always choose the first here.
           if a network error occur, remove first entry and
           replace with next entries.
         */
        osip_srv_entry_t *srv;
        int n = 0;

        for (srv = &naptr_record->sipdtls_record.srventry[naptr_record->sipdtls_record.index]; n < 10 && naptr_record->sipdtls_record.srventry[naptr_record->sipdtls_record.index].srv[0];
             srv = &naptr_record->sipdtls_record.srventry[naptr_record->sipdtls_record.index]) {
          if (srv->ipaddress[0])
            i = _eXosip_get_addrinfo(excontext, &addrinfo, srv->ipaddress, srv->port, IPPROTO_UDP);

          else
            i = _eXosip_get_addrinfo(excontext, &addrinfo, srv->srv, srv->port, IPPROTO_UDP);

          if (i == 0) {
            host = srv->srv;
            port = srv->port;
            break;
          }

          i = eXosip_dnsutils_rotate_srv(&naptr_record->sipdtls_record);

          if (i <= 0) {
            return -1;
          }

          if (i >= n) {
            return -1;
          }

          i = -1;
          /* copy next element */
          n++;
        }
      }
    }

    if (naptr_record != NULL && naptr_record->keep_in_cache == 0)
      osip_free(naptr_record);

    naptr_record = NULL;

  } else {
    naptr_record = tr->naptr_record;
  }

  if (naptr_record != NULL) {
    /* 1: make sure there is no pending DNS */
    eXosip_dnsutils_dns_process(naptr_record, 0);

    if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE || naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS)
      eXosip_dnsutils_dns_process(naptr_record, 0);

    if (naptr_record->naptr_state == OSIP_NAPTR_STATE_UNKNOWN) {
      /* fallback to DNS A */
      if (naptr_record->keep_in_cache == 0)
        osip_free(naptr_record);

      naptr_record = NULL;

      if (tr != NULL)
        tr->naptr_record = NULL;

      /* must never happen? */

    } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_INPROGRESS) {
      /* 2: keep waiting (naptr answer not received) */
      return OSIP_SUCCESS + 1;

    } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NAPTRDONE) {
      /* 3: keep waiting (naptr answer received/no srv answer received) */
      return OSIP_SUCCESS + 1;

    } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVINPROGRESS) {
      /* 3: keep waiting (naptr answer received/no srv answer received) */
      return OSIP_SUCCESS + 1;

    } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_SRVDONE) {
      /* 4: check if we have the one we want... */
      if (naptr_record->sipdtls_record.name[0] != '\0' && naptr_record->sipdtls_record.srventry[naptr_record->sipdtls_record.index].srv[0] != '\0') {
        /* always choose the first here.
           if a network error occur, remove first entry and
           replace with next entries.
         */
        osip_srv_entry_t *srv;
        int n = 0;

        for (srv = &naptr_record->sipdtls_record.srventry[naptr_record->sipdtls_record.index]; n < 10 && naptr_record->sipdtls_record.srventry[naptr_record->sipdtls_record.index].srv[0];
             srv = &naptr_record->sipdtls_record.srventry[naptr_record->sipdtls_record.index]) {
          if (srv->ipaddress[0])
            i = _eXosip_get_addrinfo(excontext, &addrinfo, srv->ipaddress, srv->port, IPPROTO_UDP);

          else
            i = _eXosip_get_addrinfo(excontext, &addrinfo, srv->srv, srv->port, IPPROTO_UDP);

          if (i == 0) {
            host = srv->srv;
            port = srv->port;
            break;
          }

          i = eXosip_dnsutils_rotate_srv(&naptr_record->sipdtls_record);

          if (i <= 0) {
            return -1;
          }

          if (i >= n) {
            return -1;
          }

          i = -1;
          /* copy next element */
          n++;
        }
      }

    } else if (naptr_record->naptr_state == OSIP_NAPTR_STATE_NOTSUPPORTED || naptr_record->naptr_state == OSIP_NAPTR_STATE_RETRYLATER) {
      /* 5: fallback to DNS A */
      if (naptr_record->keep_in_cache == 0)
        osip_free(naptr_record);

      naptr_record = NULL;

      if (tr != NULL)
        tr->naptr_record = NULL;
    }
  }

  /* if SRV was used, destination may be already found */
  if (i != 0) {
    i = _eXosip_get_addrinfo(excontext, &addrinfo, host, port, IPPROTO_UDP);
  }

  if (i != 0) {
    return -1;
  }

  memcpy(&addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
  len = (socklen_t) addrinfo->ai_addrlen;

  _eXosip_freeaddrinfo(addrinfo);

  switch (((struct sockaddr *) &addr)->sa_family) {
  case AF_INET:
    inet_ntop(((struct sockaddr *) &addr)->sa_family, &(((struct sockaddr_in *) &addr)->sin_addr), ipbuf, sizeof(ipbuf));
    break;

  case AF_INET6:
    inet_ntop(((struct sockaddr *) &addr)->sa_family, &(((struct sockaddr_in6 *) &addr)->sin6_addr), ipbuf, sizeof(ipbuf));
    break;

  default:
    strncpy(ipbuf, "(unknown)", sizeof(ipbuf));
    break;
  }

  if (osip_strcasecmp(host, ipbuf) != 0 && MSG_IS_REQUEST(sip)) {
    if (MSG_IS_REGISTER(sip)) {
      struct eXosip_dns_cache entry;

      memset(&entry, 0, sizeof(struct eXosip_dns_cache));
      snprintf(entry.host, sizeof(entry.host), "%s", host);
      snprintf(entry.ip, sizeof(entry.ip), "%s", ipbuf);
      eXosip_set_option(excontext, EXOSIP_OPT_ADD_DNS_CACHE, (void *) &entry);
    }
  }

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].ssl_conn != NULL && reserved->socket_tab[pos].ssl_type == EXOSIP_AS_A_SERVER) {
      if (reserved->socket_tab[pos].remote_port == port && (strcmp(reserved->socket_tab[pos].remote_ip, ipbuf) == 0)) {
        BIO *rbio;

        _dtls_stream_used = &reserved->socket_tab[pos];
        rbio = BIO_new_dgram(reserved->dtls_socket, BIO_NOCLOSE);
        BIO_ctrl(rbio, BIO_CTRL_DGRAM_SET_PEER, 0, (char *) &addr);
        SSL_set0_rbio(reserved->socket_tab[pos].ssl_conn, rbio);
        break;
      }
    }
  }

  if (_dtls_stream_used == NULL) {
    for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
      if (reserved->socket_tab[pos].ssl_conn != NULL && reserved->socket_tab[pos].ssl_type == EXOSIP_AS_A_CLIENT) {
        if (reserved->socket_tab[pos].remote_port == port && (strcmp(reserved->socket_tab[pos].remote_ip, ipbuf) == 0)) {
          BIO *rbio;

          _dtls_stream_used = &reserved->socket_tab[pos];
          rbio = BIO_new_dgram(reserved->dtls_socket, BIO_NOCLOSE);
          BIO_ctrl(rbio, BIO_CTRL_DGRAM_SET_PEER, 0, (char *) &addr);
          SSL_set0_rbio(reserved->socket_tab[pos].ssl_conn, rbio);
          break;
        }
      }
    }
  }

  if (_dtls_stream_used == NULL) {
    /* delete an old one! */
    pos = 0;

    if (reserved->socket_tab[pos].ssl_conn != NULL) {
      shutdown_free_client_dtls(excontext, pos);
      shutdown_free_server_dtls(excontext, pos);
    }

    memset(&reserved->socket_tab[pos], 0, sizeof(struct _dtls_stream));
  }

  if (reserved->socket_tab[pos].ssl_conn == NULL) {
    /* create a new one */
    SSL_CTX_set_read_ahead(reserved->client_ctx, 1);
    reserved->socket_tab[pos].ssl_conn = SSL_new(reserved->client_ctx);

    if (reserved->socket_tab[pos].ssl_conn == NULL) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] [tid=%i] DTLS-UDP SSL_new error\n", tid));

      if (reserved->socket_tab[pos].ssl_conn != NULL) {
        shutdown_free_client_dtls(excontext, pos);
        shutdown_free_server_dtls(excontext, pos);
      }

      memset(&reserved->socket_tab[pos], 0, sizeof(struct _dtls_stream));

      return -1;
    }

    if (connect(reserved->dtls_socket, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] [tid=%i] DTLS-UDP connect error\n", tid));

      if (reserved->socket_tab[pos].ssl_conn != NULL) {
        shutdown_free_client_dtls(excontext, pos);
        shutdown_free_server_dtls(excontext, pos);
      }

      memset(&reserved->socket_tab[pos], 0, sizeof(struct _dtls_stream));

      return -1;
    }

    SSL_set_options(reserved->socket_tab[pos].ssl_conn, SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(reserved->socket_tab[pos].ssl_conn, 1200);
    SSL_set_connect_state(reserved->socket_tab[pos].ssl_conn);
    sbio = BIO_new_dgram(reserved->dtls_socket, BIO_NOCLOSE);
    BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_CONNECTED, 1, (char *) &addr);
    SSL_set_bio(reserved->socket_tab[pos].ssl_conn, sbio, sbio);

    reserved->socket_tab[pos].ssl_type = 2;
    reserved->socket_tab[pos].ssl_state = 2;

    osip_strncpy(reserved->socket_tab[pos].remote_ip, ipbuf, sizeof(reserved->socket_tab[pos].remote_ip) - 1);
    reserved->socket_tab[pos].remote_port = port;
  }

  _eXosip_request_viamanager(excontext, sip, addr.ss_family, IPPROTO_UDP, &reserved->ai_addr, excontext->eXtl_transport.proto_local_port, reserved->dtls_socket, host);
  _eXosip_message_contactmanager(excontext, sip, addr.ss_family, IPPROTO_UDP, &reserved->ai_addr, excontext->eXtl_transport.proto_local_port, reserved->dtls_socket, host);
  _dtls_tl_update_contact(excontext, sip);

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

    i = osip_message_to_str(sip, &message, &length);

    if (tag == NULL && route != NULL && route->url != NULL) {
      osip_list_add(&sip->routes, route, 0);
    }
  }

  if (i != 0 || length <= 0) {
    return -1;
  }

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [DTLS] [tid=%i] message sent [len=%d] to [%s][%d]\n%s\n", tid, length, ipbuf, port, message));

  i = SSL_write(reserved->socket_tab[pos].ssl_conn, message, (int) length);

  if (i < 0) {
    i = SSL_get_error(reserved->socket_tab[pos].ssl_conn, i);
    _dtls_print_ssl_error(i);

    if (i == SSL_ERROR_SSL || i == SSL_ERROR_SYSCALL) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] [tid=%i] DTLS-UDP SSL_write error\n", tid));

      if (reserved->socket_tab[pos].ssl_conn != NULL) {
        shutdown_free_client_dtls(excontext, pos);
        shutdown_free_server_dtls(excontext, pos);
      }

      memset(&reserved->socket_tab[pos], 0, sizeof(struct _dtls_stream));
    }

    if (naptr_record != NULL) {
      /* rotate on failure! */
      if (eXosip_dnsutils_rotate_srv(&naptr_record->sipdtls_record) > 0) {
        osip_free(message);
        return OSIP_SUCCESS; /* retry for next retransmission! */
      }
    }

    /* SIP_NETWORK_ERROR; */
    osip_free(message);
    return -1;
  }

  if (excontext->ka_interval > 0) {
    if (MSG_IS_REGISTER(sip)) {
      eXosip_reg_t *reg = NULL;

      if (_eXosip_reg_find(excontext, &reg, tr) == 0) {
        memcpy(&(reg->stun_addr), &addr, len);
        reg->stun_len = len;
      }
    }
  }

  osip_free(message);
  return OSIP_SUCCESS;
}

static int dtls_tl_keepalive(struct eXosip_t *excontext) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;
  eXosip_reg_t *jr;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (excontext->ka_interval <= 0) {
    return 0;
  }

  if (reserved->dtls_socket <= 0)
    return OSIP_UNDEFINED_ERROR;

  for (jr = excontext->j_reg; jr != NULL; jr = jr->next) {
    if (jr->stun_len > 0) {
      if (sendto(reserved->dtls_socket, (const void *) excontext->ka_crlf, 4, 0, (struct sockaddr *) &(jr->stun_addr), jr->stun_len) > 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [DTLS] [keepalive] keep alive sent on DTLS-UDP\n"));
      }
    }
  }

  return OSIP_SUCCESS;
}

static int dtls_tl_set_socket(struct eXosip_t *excontext, int socket) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  reserved->dtls_socket = socket;

  return OSIP_SUCCESS;
}

static int dtls_tl_masquerade_contact(struct eXosip_t *excontext, const char *public_address, int port) {
  if (public_address == NULL || public_address[0] == '\0') {
    memset(excontext->dtls_firewall_ip, '\0', sizeof(excontext->dtls_firewall_ip));
    memset(excontext->dtls_firewall_port, '\0', sizeof(excontext->dtls_firewall_port));
    return OSIP_SUCCESS;
  }

  snprintf(excontext->dtls_firewall_ip, sizeof(excontext->dtls_firewall_ip), "%s", public_address);

  if (port > 0) {
    snprintf(excontext->dtls_firewall_port, sizeof(excontext->dtls_firewall_port), "%i", port);
  }

  return OSIP_SUCCESS;
}

static int dtls_tl_get_masquerade_contact(struct eXosip_t *excontext, char *ip, int ip_size, char *port, int port_size) {
  struct eXtldtls *reserved = (struct eXtldtls *) excontext->eXtldtls_reserved;

  memset(ip, 0, ip_size);
  memset(port, 0, port_size);

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [DTLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (excontext->dtls_firewall_ip[0] != '\0')
    snprintf(ip, ip_size, "%s", excontext->dtls_firewall_ip);

  if (excontext->dtls_firewall_port[0] != '\0')
    snprintf(port, port_size, "%s", excontext->dtls_firewall_port);

  return OSIP_SUCCESS;
}

static struct eXtl_protocol eXtl_dtls = {1,
                                         5061,
                                         "DTLS-UDP",
                                         "0.0.0.0",
                                         IPPROTO_UDP,
                                         AF_INET,
                                         0,
                                         0,
                                         0,

                                         &dtls_tl_init,
                                         &dtls_tl_free,
                                         &dtls_tl_open,
                                         &dtls_tl_set_fdset,
                                         &dtls_tl_read_message,
#ifdef HAVE_SYS_EPOLL_H
                                         NULL,
#endif
                                         &dtls_tl_send_message,
                                         &dtls_tl_keepalive,
                                         &dtls_tl_set_socket,
                                         &dtls_tl_masquerade_contact,
                                         &dtls_tl_get_masquerade_contact,
                                         &dtls_tl_update_contact,
                                         NULL,
                                         NULL};

void eXosip_transport_dtls_init(struct eXosip_t *excontext) {
  memcpy(&excontext->eXtl_transport, &eXtl_dtls, sizeof(struct eXtl_protocol));
}

#endif

#endif
