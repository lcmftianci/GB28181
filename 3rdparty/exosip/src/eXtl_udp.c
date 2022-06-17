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

#if !defined(_WIN32_WCE)
#include <errno.h>
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

#ifdef ENABLE_SIP_QOS
#include <delayimp.h>
#undef ExternC
#include <QOS2.h>
#endif

struct _udp_stream {
  char remote_host[256];
  char remote_ip[64];
  int remote_port;
  int out_socket;
};

/* recv on long message returns -1 with errno=0 */
#if !defined(HAVE_WINSOCK2_H)
#define SOCKET_OPTION_VALUE void *
static size_t udp_message_max_length = SIP_MESSAGE_MAX_LENGTH;
#else
static int udp_message_max_length = SIP_MESSAGE_MAX_LENGTH;

#define SOCKET_OPTION_VALUE char *
#endif

struct eXtludp {
  int udp_socket;
  struct sockaddr_storage ai_addr;
  int udp_socket_family;
  char *buf;
  void *QoSHandle;
  unsigned long QoSFlowID;

  int udp_socket_oc;
  struct sockaddr_storage ai_addr_oc;
  int udp_socket_oc_family;

  struct _udp_stream socket_tab[EXOSIP_MAX_SOCKETS];
};

static int udp_tl_init(struct eXosip_t *excontext) {
  struct eXtludp *reserved = (struct eXtludp *) osip_malloc(sizeof(struct eXtludp));

  if (reserved == NULL)
    return OSIP_NOMEM;

  memset(reserved, 0, sizeof(struct eXtludp));
  reserved->udp_socket = -1;
  reserved->udp_socket_oc = -1;

  excontext->eXtludp_reserved = reserved;
  return OSIP_SUCCESS;
}

static int udp_tl_free(struct eXosip_t *excontext) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;

  if (reserved == NULL)
    return OSIP_SUCCESS;

#ifdef ENABLE_SIP_QOS

  if (reserved->QoSFlowID != 0) {
    OSVERSIONINFOEX ovi;

    memset(&ovi, 0, sizeof(ovi));
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    GetVersionEx((LPOSVERSIONINFO) &ovi);

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [UDP] [qos] check OS support for qwave.lib: [v%i.%i.%i]\n", ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber));

    if (ovi.dwMajorVersion > 5) {
      HRESULT hr = E_FAIL;

      __try {
        hr = __HrLoadAllImportsForDll("qwave.dll");

      } __except (EXCEPTION_EXECUTE_HANDLER) {
        hr = E_FAIL;
      }

      if (!SUCCEEDED(hr)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [UDP] [qos] failed to load qwave.dll: no QoS available\n"));

      } else {
        BOOL QoSResult;

        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [UDP] [qos] QoS API detected\n"));
        QoSResult = QOSRemoveSocketFromFlow(reserved->QoSHandle, 0, reserved->QoSFlowID, 0);

        if (QoSResult != TRUE) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] [qos] QOSRemoveSocketFromFlow failed to end a flow with error\n"));
        }

        reserved->QoSFlowID = 0;
      }
    }
  }

  if (reserved->QoSHandle != NULL) {
    QOSCloseHandle(reserved->QoSHandle);
    reserved->QoSHandle = NULL;
  }

#endif

  memset(&reserved->ai_addr, 0, sizeof(struct sockaddr_storage));

  if (reserved->udp_socket >= 0)
    _eXosip_closesocket(reserved->udp_socket);

  if (reserved->udp_socket_oc >= 0)
    _eXosip_closesocket(reserved->udp_socket_oc);

  if (reserved->buf != NULL)
    osip_free(reserved->buf);

  osip_free(reserved);
  excontext->eXtludp_reserved = NULL;
  return OSIP_SUCCESS;
}

#ifdef ENABLE_SIP_QOS
static int _udp_tl_transport_set_dscp_qos(struct eXosip_t *excontext, struct sockaddr *rem_addr, int rem_addrlen) {
  int res = 0;
  QOS_TRAFFIC_TYPE tos;
  OSVERSIONINFOEX ovi;

  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] [qos] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (excontext->dscp <= 0)
    return 0;

  memset(&ovi, 0, sizeof(ovi));
  ovi.dwOSVersionInfoSize = sizeof(ovi);
  GetVersionEx((LPOSVERSIONINFO) &ovi);

  if (ovi.dwMajorVersion > 5) {
    HRESULT hr = E_FAIL;

    if (excontext->dscp <= 0x8)
      tos = QOSTrafficTypeBackground;

    else if (excontext->dscp <= 0x28)
      tos = QOSTrafficTypeAudioVideo;

    else if (excontext->dscp <= 0x38)
      tos = QOSTrafficTypeVoice;

    else
      tos = QOSTrafficTypeExcellentEffort; /* 0x28 */

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [UDP] [qos] check OS support for qwave.lib: [v%i.%i.%i]\n", ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber));

    __try {
      hr = __HrLoadAllImportsForDll("qwave.dll");

    } __except (EXCEPTION_EXECUTE_HANDLER) {
      hr = E_FAIL;
    }

    if (!SUCCEEDED(hr)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [UDP] [qos] failed to load qwave.dll: no QoS available\n"));

    } else {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [UDP] QoS API detected\n"));

      if (excontext->dscp == 0)
        tos = QOSTrafficTypeBestEffort;

      else if (excontext->dscp <= 0x8)
        tos = QOSTrafficTypeBackground;

      else if (excontext->dscp <= 0x28)
        tos = QOSTrafficTypeAudioVideo;

      else if (excontext->dscp <= 0x38)
        tos = QOSTrafficTypeVoice;

      else
        tos = QOSTrafficTypeExcellentEffort; /* 0x28 */

      if (reserved->QoSHandle == NULL) {
        QOS_VERSION version;
        BOOL QoSResult;

        version.MajorVersion = 1;
        version.MinorVersion = 0;

        QoSResult = QOSCreateHandle(&version, &reserved->QoSHandle);

        if (QoSResult != TRUE) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] [qos] QOSCreateHandle failed to create handle with error\n"));
          res = -1;
        }
      }

      if (reserved->QoSHandle != NULL && rem_addrlen > 0) {
        BOOL QoSResult;

        QoSResult = QOSAddSocketToFlow(reserved->QoSHandle, reserved->udp_socket, rem_addr, tos, QOS_NON_ADAPTIVE_FLOW, &reserved->QoSFlowID);

        if (QoSResult != TRUE) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] [qos] QOSAddSocketToFlow failed to add a flow with error\n"));
          res = -1;
        }
      }
    }

    if (res < 0)
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] [qos] failed to set DSCP value on socket\n"));

    return res;
  }

  return OSIP_SUCCESS;
}
#endif

int _eXosip_transport_set_dscp(struct eXosip_t *excontext, int family, int sock) {
#ifdef IPPROTO_IP
  int res;

  if (family == AF_INET) {
    int tos = (excontext->dscp << 2) & 0xFC;

    res = setsockopt(sock, IPPROTO_IP, IP_TOS, (SOCKET_OPTION_VALUE) &tos, sizeof(tos));

  } else {
    int tos = (excontext->dscp << 2) & 0xFC;

#ifdef IPV6_TCLASS
    res = setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, (SOCKET_OPTION_VALUE) &tos, sizeof(tos));
#else
    res = setsockopt(sock, IPPROTO_IPV6, IP_TOS, (SOCKET_OPTION_VALUE) &tos, sizeof(tos));
#endif
  }

  return res;
#else
  return 0;
#endif
}

static int _udp_tl_open(struct eXosip_t *excontext, int force_family) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;
  int res;
  struct addrinfo *addrinfo = NULL;
  struct addrinfo *curinfo;
  int sock = -1;
  char *node = NULL;
  char eb[ERRBSIZ];

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] wrong state: create transport layer first\n"));
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
    socklen_t len;
    int type;

    if (curinfo->ai_protocol && curinfo->ai_protocol != excontext->eXtl_transport.proto_num) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [UDP] skipping protocol [%d]\n", curinfo->ai_protocol));
      continue;
    }

    if (force_family > 0 && force_family != curinfo->ai_family)
      continue;

    type = curinfo->ai_socktype;
#if defined(SOCK_CLOEXEC)
    type = SOCK_CLOEXEC | type;
#endif

    sock = (int) socket(curinfo->ai_family, type, curinfo->ai_protocol);

    if (sock < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot create socket %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      continue;
    }

    if (curinfo->ai_family == AF_INET6) {
#ifdef IPV6_V6ONLY

      if (setsockopt_ipv6only(sock)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot set socket option %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
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

#if SO_NOSIGPIPE
    {
      int val;

      val = 1;
      setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *) &val, sizeof(int));
    }
#endif

    res = bind(sock, curinfo->ai_addr, (socklen_t) curinfo->ai_addrlen);

    if (res < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot bind socket [%s][%s] %s\n", excontext->eXtl_transport.proto_ifs, (curinfo->ai_family == AF_INET) ? "AF_INET" : "AF_INET6", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      _eXosip_closesocket(sock);
      sock = -1;
      continue;
    }

    len = sizeof(reserved->ai_addr);
    res = getsockname(sock, (struct sockaddr *) &reserved->ai_addr, &len);

    if (res != 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot get socket name %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      memcpy(&reserved->ai_addr, curinfo->ai_addr, curinfo->ai_addrlen);
    }

    reserved->udp_socket_family = curinfo->ai_family;
    break;
  }

  _eXosip_freeaddrinfo(addrinfo);

  if (sock < 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot bind on port [%i]\n", excontext->eXtl_transport.proto_local_port));
    return -1;
  }

  reserved->udp_socket = sock;

  _eXosip_transport_set_dscp(excontext, reserved->udp_socket_family, sock);

  if (excontext->eXtl_transport.proto_local_port == 0) {
    /* get port number from socket */
    if (reserved->udp_socket_family == AF_INET)
      excontext->eXtl_transport.proto_local_port = ntohs(((struct sockaddr_in *) &reserved->ai_addr)->sin_port);

    else
      excontext->eXtl_transport.proto_local_port = ntohs(((struct sockaddr_in6 *) &reserved->ai_addr)->sin6_port);

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] binding on port [%i]\n", excontext->eXtl_transport.proto_local_port));
  }

#ifdef HAVE_SYS_EPOLL_H

  if (excontext->poll_method == EXOSIP_USE_EPOLL_LT) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    res = epoll_ctl(excontext->epfd, EPOLL_CTL_ADD, sock, &ev);

    if (res < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot poll on main udp socket [%i]\n", excontext->eXtl_transport.proto_local_port));
      _eXosip_closesocket(sock);
      reserved->udp_socket = -1;
      return -1;
    }
  }

#endif

  return OSIP_SUCCESS;
}

static int _udp_tl_open_oc(struct eXosip_t *excontext, int force_family) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;
  int res;
  struct addrinfo *addrinfo = NULL;
  struct addrinfo *curinfo;
  int sock = -1;
  char eb[ERRBSIZ];

  if (excontext->oc_local_address[0] == '\0')
    return OSIP_SUCCESS;

  res = _eXosip_get_addrinfo(excontext, &addrinfo, excontext->oc_local_address, excontext->oc_local_port_range[0], excontext->eXtl_transport.proto_num);

  if (res)
    return -1;

  for (curinfo = addrinfo; curinfo; curinfo = curinfo->ai_next) {
    socklen_t len;
    int type;

    if (curinfo->ai_protocol && curinfo->ai_protocol != excontext->eXtl_transport.proto_num) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [UDP] skipping protocol %d\n", curinfo->ai_protocol));
      continue;
    }

    if (force_family > 0 && force_family == curinfo->ai_family)
      continue;

    type = curinfo->ai_socktype;
#if defined(SOCK_CLOEXEC)
    type = SOCK_CLOEXEC | type;
#endif
    sock = (int) socket(curinfo->ai_family, type, curinfo->ai_protocol);

    if (sock < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot create socket %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      continue;
    }

    if (curinfo->ai_family == AF_INET6) {
#ifdef IPV6_V6ONLY

      if (setsockopt_ipv6only(sock)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot set socket option %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
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

#if SO_NOSIGPIPE
    {
      int val;

      val = 1;
      setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *) &val, sizeof(int));
    }
#endif

    res = bind(sock, curinfo->ai_addr, (socklen_t) curinfo->ai_addrlen);

    if (res < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot bind socket [%s][%s] %s\n", excontext->eXtl_transport.proto_ifs, (curinfo->ai_family == AF_INET) ? "AF_INET" : "AF_INET6", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      _eXosip_closesocket(sock);
      sock = -1;
      continue;
    }

    len = sizeof(reserved->ai_addr_oc);
    res = getsockname(sock, (struct sockaddr *) &reserved->ai_addr_oc, &len);

    if (res != 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot get socket name %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      memcpy(&reserved->ai_addr_oc, curinfo->ai_addr, curinfo->ai_addrlen);
    }

    reserved->udp_socket_oc_family = curinfo->ai_family;
    break;
  }

  _eXosip_freeaddrinfo(addrinfo);

  if (sock < 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot bind on oc port [%i]\n", excontext->oc_local_port_range[0]));
    return -1;
  }

  reserved->udp_socket_oc = sock;

  _eXosip_transport_set_dscp(excontext, reserved->udp_socket_oc_family, sock);

#ifdef HAVE_SYS_EPOLL_H

  if (excontext->poll_method == EXOSIP_USE_EPOLL_LT) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    res = epoll_ctl(excontext->epfd, EPOLL_CTL_ADD, sock, &ev);

    if (res < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot poll on oc udp socket [%i]\n", excontext->eXtl_transport.proto_local_port));
      _eXosip_closesocket(sock);
      reserved->udp_socket_oc = -1;
      return -1;
    }
  }

#endif

  return OSIP_SUCCESS;
}

static int udp_tl_open(struct eXosip_t *excontext) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;
  int res;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  res = _udp_tl_open(excontext, 0);
  _udp_tl_open_oc(excontext, 0);
  return res;
}

static int _udp_tl_reset(struct eXosip_t *excontext, int af_family) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;

  if (reserved->udp_socket >= 0)
    _eXosip_closesocket(reserved->udp_socket);

  reserved->udp_socket = -1;
  return _udp_tl_open(excontext, af_family);
}

static int _udp_tl_reset_oc(struct eXosip_t *excontext, int af_family) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;

  if (reserved->udp_socket_oc >= 0)
    _eXosip_closesocket(reserved->udp_socket_oc);

  reserved->udp_socket_oc = -1;
  return _udp_tl_open_oc(excontext, af_family);
}

static int udp_tl_set_fdset(struct eXosip_t *excontext, fd_set *osip_fdset, fd_set *osip_wrset, fd_set *osip_exceptset, int *fd_max, int *osip_fd_table) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;
  int pos_fd = 0;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->udp_socket < 0)
    return -1;

  if (osip_fdset != NULL)
    eXFD_SET(reserved->udp_socket, osip_fdset);
  osip_fd_table[pos_fd] = reserved->udp_socket;
  pos_fd++;

  if (reserved->udp_socket > *fd_max)
    *fd_max = reserved->udp_socket;

  if (reserved->udp_socket_oc >= 0) {
    if (osip_fdset != NULL)
      eXFD_SET(reserved->udp_socket_oc, osip_fdset);
    osip_fd_table[pos_fd] = reserved->udp_socket_oc;
    pos_fd++;

    if (reserved->udp_socket_oc > *fd_max)
      *fd_max = reserved->udp_socket_oc;
  }

  return OSIP_SUCCESS;
}

static void _stun_decode_xor_address_ipv4(const unsigned char *tr_id, uint16_t *xor_port, uint32_t *xor_addr) {
  uint32_t cookie = 0x2112A442;
  uint16_t cookie16 = 0x2112A442 >> 16;
  *xor_port = (*xor_port) ^ cookie16;
  *xor_addr = (*xor_addr) ^ cookie;
}

static void _stun_decode_xor_address_ipv6(const unsigned char *tr_id, uint16_t *xor_port, uint8_t *xor_addr) {
  uint16_t cookie16 = 0x2112A442 >> 16;
  uint8_t xorId[16];
  xorId[0] = 0x21;
  xorId[1] = 0x12;
  xorId[2] = 0xA4;
  xorId[3] = 0x42;
  memcpy(xorId + 4, tr_id, 12);

  *xor_port = (*xor_port) ^ cookie16;

  xor_addr[0] = xor_addr[0] ^ xorId[0];
  xor_addr[1] = xor_addr[1] ^ xorId[1];
  xor_addr[2] = xor_addr[2] ^ xorId[2];
  xor_addr[3] = xor_addr[3] ^ xorId[3];
  xor_addr[4] = xor_addr[4] ^ xorId[4];
  xor_addr[5] = xor_addr[5] ^ xorId[5];
  xor_addr[6] = xor_addr[6] ^ xorId[6];
  xor_addr[7] = xor_addr[7] ^ xorId[7];
  xor_addr[8] = xor_addr[8] ^ xorId[8];
  xor_addr[9] = xor_addr[9] ^ xorId[9];
  xor_addr[10] = xor_addr[10] ^ xorId[10];
  xor_addr[11] = xor_addr[11] ^ xorId[11];
  xor_addr[12] = xor_addr[12] ^ xorId[12];
  xor_addr[13] = xor_addr[13] ^ xorId[13];
  xor_addr[14] = xor_addr[14] ^ xorId[14];
  xor_addr[15] = xor_addr[15] ^ xorId[15];
}

static int _udp_read_udp_main_socket(struct eXosip_t *excontext) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;
  socklen_t slen;
  struct sockaddr_storage sa;
  int i;
  char eb[ERRBSIZ];

  if (reserved->udp_socket_family == AF_INET)
    slen = sizeof(struct sockaddr_in);

  else
    slen = sizeof(struct sockaddr_in6);

  if (reserved->buf == NULL)
    reserved->buf = (char *) osip_malloc(udp_message_max_length * sizeof(char) + 1);

  if (reserved->buf == NULL)
    return OSIP_NOMEM;

  i = (int) recvfrom(reserved->udp_socket, reserved->buf, udp_message_max_length, 0, (struct sockaddr *) &sa, &slen);

  if (i >= 32) {
    char src6host[64];
    int recvport = 0;

    reserved->buf[i] = '\0';

    memset(src6host, 0, 64);
    recvport = _eXosip_getport((struct sockaddr *) &sa);
    _eXosip_getnameinfo((struct sockaddr *) &sa, slen, src6host, 64, NULL, 0, NI_NUMERICHOST);

    if ((reserved->buf[0] == 0 || reserved->buf[0] == 1)) {
      eXosip_reg_t *jr;
      struct osip_stun *data = (struct osip_stun *) reserved->buf;
      if (ntohs(data->length) + 20 != i) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [UDP] data rejected - received from [%s][%d] [wrong stun length] [length=%i]\n", src6host, recvport, i));
        return OSIP_SUCCESS;
      }

      for (jr = excontext->j_reg; jr != NULL; jr = jr->next) {
        if (memcmp(reserved->buf + sizeof(uint32_t), jr->stun_binding.tr_id, 12)) {
          struct osip_stun_atr {
            uint16_t atr_typ;
            uint16_t atr_len;
            uint8_t atr_reserved;
            uint8_t atr_family;
          };
          struct osip_stun_atr *atr = (struct osip_stun_atr *) (reserved->buf + 20);
          uint16_t atr_len = ntohs(atr->atr_len);
          uint16_t atr_typ = ntohs(atr->atr_typ);
          if ((atr_typ == 0x0020 || atr_typ == 0x8020) && (atr_len == 8 || atr_len == 20)) {
            /* 0x8020 is non standard from an old draft */
            char ipbuf[INET6_ADDRSTRLEN];

            uint16_t nport;
            if (atr->atr_family != 0x01 && atr->atr_family != 0x02)
              break;

            memcpy(&nport, reserved->buf + 26, 2);
            nport = ntohs(nport);

            if (atr_len == 8) {
              uint32_t naddr;
              memcpy(&naddr, reserved->buf + 28, 4);
              naddr = ntohl(naddr);
              _stun_decode_xor_address_ipv4(jr->stun_binding.tr_id, &nport, &naddr);
              naddr = htonl(naddr);
              inet_ntop(AF_INET, &naddr, ipbuf, sizeof(ipbuf));
            } else {
              uint8_t naddr[16];
              memcpy(naddr, reserved->buf + 28, sizeof(naddr));
              _stun_decode_xor_address_ipv6(jr->stun_binding.tr_id, &nport, naddr);
              inet_ntop(AF_INET6, &naddr, ipbuf, sizeof(ipbuf));
            }
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] [STUN answer] received from [%s][%d] [length=%i] [XOR=%s %i]\n", src6host, recvport, i, ipbuf, nport));
            jr->ping_rfc5626 = 0;
            if (jr->stun_nport == 0) {
              jr->stun_nport = nport;
              memcpy(jr->stun_ipbuf, ipbuf, sizeof(jr->stun_ipbuf));
              jr->pong_supported = 1;
            } else if (jr->stun_nport != nport || osip_strcasecmp(jr->stun_ipbuf, ipbuf) != 0) {
              OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] [STUN answer] received from [%s][%d] [length=%i] [NEW XOR=%s %i]\n", src6host, recvport, i, ipbuf, nport));
              jr->stun_nport = nport;
              memcpy(jr->stun_ipbuf, ipbuf, sizeof(jr->stun_ipbuf));
              if (jr->r_last_tr->orig_request == NULL || jr->r_last_tr->orig_request->call_id == NULL || jr->r_last_tr->orig_request->call_id->number == NULL)
                break;
              _eXosip_mark_registration_expired(excontext, jr->r_last_tr->orig_request->call_id->number);
            }
            return OSIP_SUCCESS;
          }
          break;
        }
      }
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [UDP] data rejected - received from [%s][%d] [bad stun] [length=%i]\n", src6host, recvport, i));
      return OSIP_SUCCESS;
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] message received from [%s][%d]\n", src6host, recvport));

    _eXosip_handle_incoming_message(excontext, reserved->buf, i, reserved->udp_socket, src6host, recvport, NULL, NULL);

    /* if we have a second socket for outbound connection, save information about inbound traffic initiated by receiving data on udp_socket */
    if (reserved->udp_socket_oc >= 0) {
      int pos;

      for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
        /* does the entry already exist? */
        if (reserved->socket_tab[pos].remote_port == recvport && osip_strcasecmp(reserved->socket_tab[pos].remote_ip, src6host) == 0) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] inbound traffic/connection already in table\n"));
          break;
        }
      }

      if (pos == EXOSIP_MAX_SOCKETS) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] inbound traffic/new connection detected [%s][%d]\n", src6host, recvport));

        for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
          if (reserved->socket_tab[pos].out_socket == -1) {
            reserved->socket_tab[pos].out_socket = reserved->udp_socket;
            snprintf(reserved->socket_tab[pos].remote_ip, sizeof(reserved->socket_tab[pos].remote_ip), "%s", src6host);
            reserved->socket_tab[pos].remote_port = recvport;
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] inbound traffic/new connection added in table\n"));
            break;
          }
        }
      }
    }

  } else if (i < 0) {
    int valopt = ex_errno;
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot read socket [%i] %s\n", i, _ex_strerror(valopt, eb, ERRBSIZ)));

    if (valopt == 0 || valopt == 34 || valopt == 10040 /* WSAEMSGSIZE */ ) {
      if (udp_message_max_length < 65536) {
        udp_message_max_length = udp_message_max_length * 2;

        if (udp_message_max_length > 65536)
          udp_message_max_length = 65536;

        osip_free(reserved->buf);
        reserved->buf = (char *) osip_malloc(udp_message_max_length * sizeof(char) + 1);
      }
    }

    if (valopt == 57) {
      _udp_tl_reset(excontext, reserved->udp_socket_family);
    }

  } else {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] dummy SIP message received\n"));
  }

  return OSIP_SUCCESS;
}

static int _udp_read_udp_oc_socket(struct eXosip_t *excontext) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;
  socklen_t slen;
  struct sockaddr_storage sa;
  int i;
  char eb[ERRBSIZ];

  if (reserved->buf == NULL)
    reserved->buf = (char *) osip_malloc(udp_message_max_length * sizeof(char) + 1);

  if (reserved->buf == NULL)
    return OSIP_NOMEM;

  if (reserved->udp_socket_oc_family == AF_INET)
    slen = sizeof(struct sockaddr_in);

  else
    slen = sizeof(struct sockaddr_in6);

  i = (int) recvfrom(reserved->udp_socket_oc, reserved->buf, udp_message_max_length, 0, (struct sockaddr *) &sa, &slen);

  if (i > 32) {
    char src6host[NI_MAXHOST];
    int recvport = 0;

    reserved->buf[i] = '\0';

    memset(src6host, 0, NI_MAXHOST);
    recvport = _eXosip_getport((struct sockaddr *) &sa);
    _eXosip_getnameinfo((struct sockaddr *) &sa, slen, src6host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] message received from: [%s][%d]\n", src6host, recvport));

    _eXosip_handle_incoming_message(excontext, reserved->buf, i, reserved->udp_socket_oc, src6host, recvport, NULL, NULL);

  } else if (i < 0) {
    int valopt = ex_errno;
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] cannot read socket [%i] %s\n", i, _ex_strerror(valopt, eb, ERRBSIZ)));

    if (valopt == 0 || valopt == 34) {
      if (udp_message_max_length < 65536) {
        udp_message_max_length = udp_message_max_length * 2;

        if (udp_message_max_length > 65536)
          udp_message_max_length = 65536;

        osip_free(reserved->buf);
        reserved->buf = (char *) osip_malloc(udp_message_max_length * sizeof(char) + 1);
      }
    }

    if (valopt == 57) {
      _udp_tl_reset_oc(excontext, reserved->udp_socket_oc_family);
    }

  } else {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] dummy SIP message received\n"));
  }

  return OSIP_SUCCESS;
}

#ifdef HAVE_SYS_EPOLL_H

static int udp_tl_epoll_read_message(struct eXosip_t *excontext, int nfds, struct epoll_event *ep_array) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;
  int n;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->udp_socket < 0)
    return -1;

  for (n = 0; n < nfds; ++n) {
    if (ep_array[n].data.fd == reserved->udp_socket) {
      _udp_read_udp_main_socket(excontext);
    }

    if (reserved->udp_socket_oc >= 0 && ep_array[n].data.fd == reserved->udp_socket_oc) {
      _udp_read_udp_oc_socket(excontext);
    }
  }

  return OSIP_SUCCESS;
}

#endif

static int udp_tl_read_message(struct eXosip_t *excontext, fd_set *osip_fdset, fd_set *osip_wrset, fd_set *osip_exceptset) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->udp_socket < 0)
    return -1;

  if (FD_ISSET(reserved->udp_socket, osip_fdset)) {
    _udp_read_udp_main_socket(excontext);
  }

  if (reserved->udp_socket_oc >= 0 && FD_ISSET(reserved->udp_socket_oc, osip_fdset)) {
    _udp_read_udp_oc_socket(excontext);
  }

  return OSIP_SUCCESS;
}

static int udp_tl_update_contact(struct eXosip_t *excontext, osip_message_t *req) {
  req->application_data = (void *) 0x1; /* request for masquerading */
  return OSIP_SUCCESS;
}

static int _udp_tl_update_contact(struct eXosip_t *excontext, osip_message_t *req) {
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

  if (excontext->udp_firewall_ip[0] != '\0' || excontext->auto_masquerade_contact > 0) {
    osip_list_iterator_t it;
    osip_contact_t *co = (osip_contact_t *) osip_list_get_first(&req->contacts, &it);

    while (co != NULL) {
      if (co != NULL && co->url != NULL && co->url->host != NULL) {
        if (ainfo == NULL) {
          if (excontext->udp_firewall_port[0] == '\0') {
          } else if (co->url->port == NULL && 0 != osip_strcasecmp(excontext->udp_firewall_port, "5060")) {
            co->url->port = osip_strdup(excontext->udp_firewall_port);
            osip_message_force_update(req);

          } else if (co->url->port != NULL && 0 != osip_strcasecmp(excontext->udp_firewall_port, co->url->port)) {
            osip_free(co->url->port);
            co->url->port = osip_strdup(excontext->udp_firewall_port);
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
        if (excontext->udp_firewall_port[0] == '\0') {
        } else if (via->port == NULL && 0 != osip_strcasecmp(excontext->udp_firewall_port, "5060")) {
          via->port = osip_strdup(excontext->udp_firewall_port);
          osip_message_force_update(req);

        } else if (via->port != NULL && 0 != osip_strcasecmp(excontext->udp_firewall_port, via->port)) {
          osip_free(via->port);
          via->port = osip_strdup(excontext->udp_firewall_port);
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

static int udp_tl_send_message(struct eXosip_t *excontext, osip_transaction_t *tr, osip_message_t *sip, char *host, int port, int out_socket) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;
  socklen_t len = 0;
  size_t length = 0;
  struct addrinfo *addrinfo;
  struct __eXosip_sockaddr addr;
  char *message = NULL;

  char ipbuf[INET6_ADDRSTRLEN];
  int i;
  osip_naptr_t *naptr_record = NULL;
  int sock;
  struct sockaddr_storage *local_ai_addr;
  int local_port;
  int tid = -1;

  if (tr != NULL)
    tid = tr->transactionid;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] [tid=%i] wrong state: create transport layer first\n", tid));
    return OSIP_WRONG_STATE;
  }

  if (reserved->udp_socket < 0)
    return -1;

  if (host == NULL) {
    host = sip->req_uri->host;

    if (sip->req_uri->port != NULL)
      port = osip_atoi(sip->req_uri->port);

    else
      port = 5060;
  }

  i = _tl_resolv_naptr_destination(excontext, tr, sip, &host, &port, &naptr_record);
  if (i == OSIP_SUCCESS + 1)
    return i;
  if (i < OSIP_SUCCESS)
    return i;

  i = _eXosip_get_addrinfo(excontext, &addrinfo, host, port, IPPROTO_UDP);

  if (i != 0) {
    if (MSG_IS_REGISTER(sip)) {
      _eXosip_mark_registration_expired(excontext, sip->call_id->number);
    }

    return -1;
  }

  /* search for an IP similar to reserved->udp_socket_family */
  {
    struct addrinfo *curinfo = NULL;

    for (curinfo = addrinfo; curinfo; curinfo = curinfo->ai_next) {
      if (curinfo->ai_family == reserved->udp_socket_family) {
        break;
      }
    }

    if (excontext->ipv6_enable > 1 && curinfo == NULL) {
      /* search for an IP similar to reserved->udp_socket_family */
      curinfo = addrinfo;
      
      if (curinfo) {
        if (curinfo->ai_family == AF_INET && reserved->udp_socket_family == AF_INET6) {
          /* switch to another family */
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [UDP] [tid=%i] switching to IPv4\n", tid));
          _udp_tl_reset(excontext, curinfo->ai_family);
          return OSIP_SUCCESS;
        }

        if (curinfo->ai_family == AF_INET6 && reserved->udp_socket_family == AF_INET) {
          /* switch to another family */
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [UDP] [tid=%i] switching to IPv6\n", tid));
          _udp_tl_reset(excontext, curinfo->ai_family);
          return OSIP_SUCCESS;
        }
      }
    }

    if (curinfo == NULL) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_BUG, NULL, "[eXosip] [UDP] [tid=%i] missing matching family\n", tid));
      return -1;
    }

    memcpy(&addr, curinfo->ai_addr, curinfo->ai_addrlen);
    len = (socklen_t) curinfo->ai_addrlen;
  }

  _eXosip_freeaddrinfo(addrinfo);

  /* default socket used */
  sock = reserved->udp_socket;
  local_port = excontext->eXtl_transport.proto_local_port;
  local_ai_addr = &reserved->ai_addr;

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

  /* if we have a second socket for outbound connection, re-use the incoming socket (udp_socket) for any message sent there */
  if (reserved->udp_socket_oc >= 0) {
    int pos;

    sock = reserved->udp_socket_oc;
    local_port = excontext->oc_local_port_range[0];
    local_ai_addr = &reserved->ai_addr_oc;

    for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
      if (reserved->socket_tab[pos].out_socket == -1)
        continue;

      /* we insert in table ONLY incoming transaction that we want to remember: so any entry in the table refer to incoming udp_socket */
      if (reserved->socket_tab[pos].remote_port == port && osip_strcasecmp(reserved->socket_tab[pos].remote_ip, ipbuf) == 0) {
        sock = reserved->socket_tab[pos].out_socket;
        local_port = excontext->eXtl_transport.proto_local_port;
        local_ai_addr = &reserved->ai_addr;
        break;
      }
    }
  }

  _eXosip_request_viamanager(excontext, sip, addr.ss_family, IPPROTO_UDP, local_ai_addr, local_port, sock, ipbuf);
  _eXosip_message_contactmanager(excontext, sip, addr.ss_family, IPPROTO_UDP, local_ai_addr, local_port, sock, ipbuf);
  _udp_tl_update_contact(excontext, sip);

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
    osip_free(message);
    return -1;
  }

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] [tid=%i] message sent [len=%d] to [%s][%d]\n%s\n", tid, length, ipbuf, port, message));

  if (excontext->enable_dns_cache == 1 && osip_strcasecmp(host, ipbuf) != 0 && MSG_IS_REQUEST(sip)) {
    if (MSG_IS_REGISTER(sip)) {
      struct eXosip_dns_cache entry;

      memset(&entry, 0, sizeof(struct eXosip_dns_cache));
      snprintf(entry.host, sizeof(entry.host), "%s", host);
      snprintf(entry.ip, sizeof(entry.ip), "%s", ipbuf);
      eXosip_set_option(excontext, EXOSIP_OPT_ADD_DNS_CACHE, (void *) &entry);
    }
  }

  if (tr != NULL) {
    if (tr->ict_context != NULL)
      osip_ict_set_destination(tr->ict_context, osip_strdup(ipbuf), port);

    if (tr->nict_context != NULL)
      osip_nict_set_destination(tr->nict_context, osip_strdup(ipbuf), port);
  }

#ifdef ENABLE_SIP_QOS
  _udp_tl_transport_set_dscp_qos(excontext, (struct sockaddr *) &addr, len);
#endif

#ifdef HAVE_WINSOCK2_H
#define CAST_RECV_LEN(L) ((int) (L))
#else
#define CAST_RECV_LEN(L) L
#endif

  i = (int) sendto(sock, (const void *) message, CAST_RECV_LEN(length), 0, (struct sockaddr *) &addr, len);

  if (i < 0) {
    char eb[ERRBSIZ];
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] [tid=%i] [%s][%d] failure %s\n", tid, host, port, _ex_strerror(ex_errno, eb, ERRBSIZ)));
    if (MSG_IS_REGISTER(sip)) {
      _eXosip_mark_registration_expired(excontext, sip->call_id->number);
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
        reg->stun_nport = 0; /* reset detection to avoid new registration */
        reg->ping_rfc5626 = 0;
      }
    }
  }

  if (naptr_record != NULL) {
    if (tr != NULL && MSG_IS_REGISTER(sip) && tr->last_response == NULL) {
      /* failover for outgoing transaction */
      time_t now;

      now = osip_getsystemtime(NULL);

      if (tr != NULL && now - tr->birth_time > 10) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [UDP] [tid=%i] [%s][%d] timeout\n", tid, host, port));
        _eXosip_mark_registration_expired(excontext, sip->call_id->number);
        osip_free(message);
        return -1;
      }
    }
  }

  osip_free(message);
  return OSIP_SUCCESS;
}

static int udp_tl_keepalive(struct eXosip_t *excontext) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;
  eXosip_reg_t *jr;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (excontext->ka_interval <= 0) {
    return 0;
  }

  if (reserved->udp_socket < 0)
    return OSIP_UNDEFINED_ERROR;

  for (jr = excontext->j_reg; jr != NULL; jr = jr->next) {
    if (jr->stun_len > 0) {
      int idx;

      jr->stun_binding.type = htons(0x0001);  // STUN_METHOD_BINDING|STUN_REQUEST
      jr->stun_binding.length = htons(0);
      jr->stun_binding.magic_cookie = htonl(0x2112A442);

      for (idx = 0; idx < 12; idx = idx + 4) {
        /* assert(i+3<16); */
        int r = osip_build_random_number();
        jr->stun_binding.tr_id[idx + 0] = r >> 0;
        jr->stun_binding.tr_id[idx + 1] = r >> 8;
        jr->stun_binding.tr_id[idx + 2] = r >> 16;
        jr->stun_binding.tr_id[idx + 3] = r >> 24;
      }

      if (sendto(reserved->udp_socket, (const void *) &jr->stun_binding, sizeof(jr->stun_binding), 0, (struct sockaddr *) &(jr->stun_addr), jr->stun_len) > 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] [keepalive] STUN sent on UDP\n"));
        jr->ping_rfc5626 = osip_getsystemtime(NULL) + 9;
      } else {
        char eb[ERRBSIZ];
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [UDP] [keepalive] failure %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      }
    }
  }

  return OSIP_SUCCESS;
}

static int udp_tl_set_socket(struct eXosip_t *excontext, int socket) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  reserved->udp_socket = socket;

  return OSIP_SUCCESS;
}

static int udp_tl_masquerade_contact(struct eXosip_t *excontext, const char *public_address, int port) {
  if (public_address == NULL || public_address[0] == '\0') {
    memset(excontext->udp_firewall_ip, '\0', sizeof(excontext->udp_firewall_ip));
    memset(excontext->udp_firewall_port, '\0', sizeof(excontext->udp_firewall_port));
    return OSIP_SUCCESS;
  }

  snprintf(excontext->udp_firewall_ip, sizeof(excontext->udp_firewall_ip), "%s", public_address);

  if (port > 0) {
    snprintf(excontext->udp_firewall_port, sizeof(excontext->udp_firewall_port), "%i", port);
  }

  return OSIP_SUCCESS;
}

static int udp_tl_get_masquerade_contact(struct eXosip_t *excontext, char *ip, int ip_size, char *port, int port_size) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;

  memset(ip, 0, ip_size);
  memset(port, 0, port_size);

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (excontext->udp_firewall_ip[0] != '\0')
    snprintf(ip, ip_size, "%s", excontext->udp_firewall_ip);

  if (excontext->udp_firewall_port[0] != '\0')
    snprintf(port, port_size, "%s", excontext->udp_firewall_port);

  return OSIP_SUCCESS;
}

static int udp_tl_check_connection(struct eXosip_t *excontext, int socket) {
  struct eXtludp *reserved = (struct eXtludp *) excontext->eXtludp_reserved;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [UDP] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (socket == -1) {
    eXosip_reg_t *jr;

    time_t now = osip_getsystemtime(NULL);

    for (jr = excontext->j_reg; jr != NULL; jr = jr->next) {
      if (jr->ping_rfc5626 > 0 && now > jr->ping_rfc5626 && jr->pong_supported > 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [UDP] [checkall] no pong[STUN] for ping[STUN]\n"));

        if (jr->r_last_tr->orig_request == NULL || jr->r_last_tr->orig_request->call_id == NULL || jr->r_last_tr->orig_request->call_id->number == NULL)
          continue;

        jr->ping_rfc5626 = 0;
        jr->stun_nport = 0;
        _eXosip_mark_registration_expired(excontext, jr->r_last_tr->orig_request->call_id->number);

        continue;
      }
    }
    return OSIP_SUCCESS;
  }

  return OSIP_SUCCESS;
}

static struct eXtl_protocol eXtl_udp = {1,
                                        5060,
                                        "UDP",
                                        "0.0.0.0",
                                        IPPROTO_UDP,
                                        AF_INET,
                                        0,
                                        0,
                                        0,

                                        &udp_tl_init,
                                        &udp_tl_free,
                                        &udp_tl_open,
                                        &udp_tl_set_fdset,
                                        &udp_tl_read_message,
#ifdef HAVE_SYS_EPOLL_H
                                        &udp_tl_epoll_read_message,
#endif
                                        &udp_tl_send_message,
                                        &udp_tl_keepalive,
                                        &udp_tl_set_socket,
                                        &udp_tl_masquerade_contact,
                                        &udp_tl_get_masquerade_contact,
                                        &udp_tl_update_contact,
                                        NULL,
                                        &udp_tl_check_connection};

void eXosip_transport_udp_init(struct eXosip_t *excontext) {
  memcpy(&excontext->eXtl_transport, &eXtl_udp, sizeof(struct eXtl_protocol));
}
