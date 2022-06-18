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

#ifdef WIN32
#ifndef UNICODE
#define UNICODE
#endif
#endif

#include "eXosip2.h"
#include "eXtransport.h"

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

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

#define ex_verify_depth 10
#include <openssl/bn.h>
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#include <openssl/tls1.h>
#include <openssl/x509.h>
#if !(OPENSSL_VERSION_NUMBER < 0x10002000L)
#include <openssl/x509v3.h>
#endif

#define SSLDEBUG 1
/*#define PATH "D:/conf/"

#define PASSWORD "23-+Wert"
#define CLIENT_KEYFILE PATH"ckey.pem"
#define CLIENT_CERTFILE PATH"c.pem"
#define SERVER_KEYFILE PATH"skey.pem"
#define SERVER_CERTFILE PATH"s.pem"
#define CA_LIST PATH"cacert.pem"
#define RANDOM  PATH"random.pem"
#define DHFILE PATH"dh1024.pem"*/

#ifdef __APPLE_CC__
#include "TargetConditionals.h"
#endif

#if defined(__APPLE__) && (TARGET_OS_IPHONE == 0)
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>
#endif

#if TARGET_OS_IPHONE
#include <CFNetwork/CFSocketStream.h>
#include <CoreFoundation/CFStream.h>
#define MULTITASKING_ENABLED
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_STORE_get0_param(store) (store->param)
#endif

SSL_CTX *initialize_client_ctx(struct eXosip_t *excontext, eXosip_tls_ctx_t *client_ctx, int transport, const char *sni_servernameindication);

SSL_CTX *initialize_server_ctx(struct eXosip_t *excontext, eXosip_tls_ctx_t *srv_ctx, int transport);

int verify_cb(int preverify_ok, X509_STORE_CTX *store);

/* persistent connection */
struct _tls_stream {
  int socket;
  struct sockaddr ai_addr;
  socklen_t ai_addrlen;
  char sni_servernameindication[256];
  char remote_ip[65];
  int remote_port;
  char *previous_content;
  int previous_content_len;
  SSL *ssl_conn;
  SSL_CTX *ssl_ctx;
  int ssl_state;
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

static int _tls_tl_send(struct eXosip_t *excontext, SSL *ssl, const char *message, int length);

struct eXtltls {
  int tls_socket;
  struct sockaddr_storage ai_addr;
  int ai_addr_len;

  SSL_CTX *server_ctx;
  SSL_CTX *client_ctx;

  struct _tls_stream socket_tab[EXOSIP_MAX_SOCKETS];
};

static int tls_tl_init(struct eXosip_t *excontext) {
  struct eXtltls *reserved = (struct eXtltls *) osip_malloc(sizeof(struct eXtltls));

  if (reserved == NULL)
    return OSIP_NOMEM;

  reserved->tls_socket = 0;
  reserved->server_ctx = NULL;
  reserved->client_ctx = NULL;
  memset(&reserved->ai_addr, 0, sizeof(struct sockaddr_storage));
  reserved->ai_addr_len = 0;
  memset(&reserved->socket_tab, 0, sizeof(struct _tls_stream) * EXOSIP_MAX_SOCKETS);

  excontext->eXtltls_reserved = reserved;
  return OSIP_SUCCESS;
}

static void _tls_tl_close_sockinfo(struct eXosip_t *excontext, struct _tls_stream *sockinfo) {

  _eXosip_mark_all_transaction_transport_error(excontext, sockinfo->socket);

  if (sockinfo->socket > 0) {
    if (sockinfo->ssl_conn != NULL) {
      SSL_shutdown(sockinfo->ssl_conn);
      SSL_shutdown(sockinfo->ssl_conn);
      SSL_free(sockinfo->ssl_conn);
    }

    if (sockinfo->ssl_ctx != NULL)
      SSL_CTX_free(sockinfo->ssl_ctx);

    _eXosip_closesocket(sockinfo->socket);
  }

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

static int tls_tl_free(struct eXosip_t *excontext) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int pos;

  if (reserved == NULL)
    return OSIP_SUCCESS;

  if (reserved->server_ctx != NULL)
    SSL_CTX_free(reserved->server_ctx);

  reserved->server_ctx = NULL;

  if (reserved->client_ctx != NULL)
    SSL_CTX_free(reserved->client_ctx);

  reserved->client_ctx = NULL;

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
  }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
  ERR_remove_thread_state(NULL);
#else
  ERR_remove_state(0);
#endif
#endif

  memset(&reserved->socket_tab, 0, sizeof(struct _tls_stream) * EXOSIP_MAX_SOCKETS);

  memset(&reserved->ai_addr, 0, sizeof(struct sockaddr_storage));
  reserved->ai_addr_len = 0;

  if (reserved->tls_socket > 0)
    _eXosip_closesocket(reserved->tls_socket);

  reserved->tls_socket = 0;

  osip_free(reserved);
  excontext->eXtltls_reserved = NULL;
  return OSIP_SUCCESS;
}

static int tls_tl_reset(struct eXosip_t *excontext) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int pos;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket > 0)
      reserved->socket_tab[pos].invalid = 1;
  }

  return OSIP_SUCCESS;
}

static int _tls_add_certificates(struct eXosip_t *excontext, SSL_CTX *ctx) {
  int count = 0;

  if (excontext->tls_verify_client_certificate & 0x04) {
    return 0;
  }

#ifdef HAVE_WINCRYPT_H
  PCCERT_CONTEXT pCertCtx;
  X509 *cert = NULL;
  HCERTSTORE hStore = CertOpenSystemStore(0, L"CA");
  X509_STORE *x509_store;

  for (pCertCtx = CertEnumCertificatesInStore(hStore, NULL); pCertCtx != NULL; pCertCtx = CertEnumCertificatesInStore(hStore, pCertCtx)) {
    cert = d2i_X509(NULL, (const unsigned char **) &pCertCtx->pbCertEncoded, pCertCtx->cbCertEncoded);

    if (cert == NULL) {
      continue;
    }

    x509_store = SSL_CTX_get_cert_store(ctx);

    if (x509_store == NULL) {
      X509_free(cert);
      continue;
    }

    if (!X509_STORE_add_cert(x509_store, cert)) {
      X509_free(cert);
      continue;
    }

    count++;
    X509_free(cert);
  }

  CertCloseStore(hStore, 0);

  hStore = CertOpenSystemStore(0, L"ROOT");

  for (pCertCtx = CertEnumCertificatesInStore(hStore, NULL); pCertCtx != NULL; pCertCtx = CertEnumCertificatesInStore(hStore, pCertCtx)) {
    cert = d2i_X509(NULL, (const unsigned char **) &pCertCtx->pbCertEncoded, pCertCtx->cbCertEncoded);

    if (cert == NULL) {
      continue;
    }

    x509_store = SSL_CTX_get_cert_store(ctx);

    if (x509_store == NULL) {
      X509_free(cert);
      continue;
    }

    if (!X509_STORE_add_cert(x509_store, cert)) {
      X509_free(cert);
      continue;
    }

    count++;
    X509_free(cert);
  }

  CertCloseStore(hStore, 0);

  hStore = CertOpenSystemStore(0, L"MY");

  for (pCertCtx = CertEnumCertificatesInStore(hStore, NULL); pCertCtx != NULL; pCertCtx = CertEnumCertificatesInStore(hStore, pCertCtx)) {
    cert = d2i_X509(NULL, (const unsigned char **) &pCertCtx->pbCertEncoded, pCertCtx->cbCertEncoded);

    if (cert == NULL) {
      continue;
    }

    x509_store = SSL_CTX_get_cert_store(ctx);

    if (x509_store == NULL) {
      X509_free(cert);
      continue;
    }

    if (!X509_STORE_add_cert(x509_store, cert)) {
      X509_free(cert);
      continue;
    }

    count++;
    X509_free(cert);
  }

  CertCloseStore(hStore, 0);

  hStore = CertOpenSystemStore(0, L"Trustedpublisher");

  for (pCertCtx = CertEnumCertificatesInStore(hStore, NULL); pCertCtx != NULL; pCertCtx = CertEnumCertificatesInStore(hStore, pCertCtx)) {
    cert = d2i_X509(NULL, (const unsigned char **) &pCertCtx->pbCertEncoded, pCertCtx->cbCertEncoded);

    if (cert == NULL) {
      continue;
    }

    x509_store = SSL_CTX_get_cert_store(ctx);

    if (x509_store == NULL) {
      X509_free(cert);
      continue;
    }

    if (!X509_STORE_add_cert(x509_store, cert)) {
      X509_free(cert);
      continue;
    }

    count++;
    X509_free(cert);
  }

  CertCloseStore(hStore, 0);
#elif defined(__APPLE__) && (TARGET_OS_IPHONE == 0)
  SecKeychainSearchRef pSecKeychainSearch = NULL;
  SecKeychainRef pSecKeychain;
  OSStatus status = noErr;
  X509 *cert = NULL;
  SInt32 osx_version = 0;
  X509_STORE *x509_store;

  if (Gestalt(gestaltSystemVersion, &osx_version) != noErr) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] macosx certificate store: can't get osx version"));
    return 0;
  }

  if (osx_version >= 0x1050) {
    /* Leopard store location */
    status = SecKeychainOpen("/System/Library/Keychains/SystemRootCertificates.keychain", &pSecKeychain);

  } else {
    /* Tiger and below store location */
    status = SecKeychainOpen("/System/Library/Keychains/X509Anchors", &pSecKeychain);
  }

  if (status != noErr) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] macosx certificate store: can't get osx version"));
    return 0;
  }

  status = SecKeychainSearchCreateFromAttributes(pSecKeychain, kSecCertificateItemClass, NULL, &pSecKeychainSearch);

  for (;;) {
    SecKeychainItemRef pSecKeychainItem = nil;

    status = SecKeychainSearchCopyNext(pSecKeychainSearch, &pSecKeychainItem);

    if (status == errSecItemNotFound) {
      break;
    }

    if (status == noErr) {
      void *_pCertData;
      UInt32 _pCertLength;

      status = SecKeychainItemCopyAttributesAndData(pSecKeychainItem, NULL, NULL, NULL, &_pCertLength, &_pCertData);

      if (status == noErr && _pCertData != NULL) {
        unsigned char *ptr;

        ptr = _pCertData; /*required because d2i_X509 is modifying pointer */
        cert = d2i_X509(NULL, (const unsigned char **) &ptr, _pCertLength);

        if (cert == NULL) {
          continue;
        }

        x509_store = SSL_CTX_get_cert_store(ctx);

        if (x509_store == NULL) {
          X509_free(cert);
          continue;
        }

        if (!X509_STORE_add_cert(x509_store, cert)) {
          X509_free(cert);
          continue;
        }

        count++;
        X509_free(cert);

        status = SecKeychainItemFreeAttributesAndData(NULL, _pCertData);
      }
    }

    if (pSecKeychainItem != NULL)
      CFRelease(pSecKeychainItem);

    if (status != noErr) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] macosx certificate store: can't add certificate [%i]", status));
    }
  }

  CFRelease(pSecKeychainSearch);
  CFRelease(pSecKeychain);

#endif
  return count;
}

int verify_cb(int preverify_ok, X509_STORE_CTX *store) {
  char buf[256];
  X509 *err_cert;
  int err, depth;

  err_cert = X509_STORE_CTX_get_current_cert(store);
  err = X509_STORE_CTX_get_error(store);
  depth = X509_STORE_CTX_get_error_depth(store);

  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

  if (depth > ex_verify_depth /* depth -1 */) {
    preverify_ok = 0;
    err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
    X509_STORE_CTX_set_error(store, err);
  }

  if (!preverify_ok) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] invalid  depth[%d] [%s] [%d:%s]\n", depth, buf, err, X509_verify_cert_error_string(err)));

  } else {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] verified depth[%d] [%s]\n", depth, buf));
  }

  /*
   * At this point, err contains the last verification error. We can use
   * it for something special
   */
  if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
    X509 *current_cert = X509_STORE_CTX_get_current_cert(store);

    X509_NAME_oneline(X509_get_issuer_name(current_cert), buf, 256);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] issuer [%s]\n", buf));
  }

  return 1;
  // return preverify_ok;

#if 0

  if (!preverify_ok && (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)) {
    X509_NAME_oneline(X509_get_issuer_name(store->current_cert), buf, 256);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] issuer [%s]\n", buf));
    preverify_ok = 1;
    X509_STORE_CTX_set_error(store, X509_V_OK);
  }

  if (!preverify_ok && (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)) {
    X509_NAME_oneline(X509_get_issuer_name(store->current_cert), buf, 256);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] issuer [%s]\n", buf));
    preverify_ok = 1;
    X509_STORE_CTX_set_error(store, X509_V_OK);
  }

  if (!preverify_ok && (err == X509_V_ERR_CERT_HAS_EXPIRED)) {
    X509_NAME_oneline(X509_get_issuer_name(store->current_cert), buf, 256);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] issuer [%s]\n", buf));
    preverify_ok = 1;
    X509_STORE_CTX_set_error(store, X509_V_OK);
  }

  if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)) {
    X509_NAME_oneline(X509_get_issuer_name(store->current_cert), buf, 256);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] issuer [%s]\n", buf));
    preverify_ok = 1;
    X509_STORE_CTX_set_error(store, X509_V_OK);
  }

  if (!preverify_ok && (err == X509_V_ERR_CERT_UNTRUSTED)) {
    X509_NAME_oneline(X509_get_issuer_name(store->current_cert), buf, 256);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] issuer [%s]\n", buf));
    preverify_ok = 1;
    X509_STORE_CTX_set_error(store, X509_V_OK);
  }

  if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)) {
    X509_NAME_oneline(X509_get_issuer_name(store->current_cert), buf, 256);
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] issuer [%s]\n", buf));
    preverify_ok = 1;
    X509_STORE_CTX_set_error(store, X509_V_OK);
  }

  preverify_ok = 1;             /* configured to accept anyway! */
  return preverify_ok;
#endif
}

static int password_cb(char *buf, int num, int rwflag, void *userdata) {
  char *passwd = (char *) userdata;

  if (passwd == NULL || passwd[0] == '\0') {
    /* Suppress blocking read from stdin if password is missing or empty */
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] password required but missing\n"));
    return 0;
  }

  strncpy(buf, passwd, num);
  buf[num - 1] = '\0';
  return (int) strlen(buf);
}

static void load_dh_params(SSL_CTX *ctx, char *file) {
#ifndef OPENSSL_NO_DH
  DH *ret = 0;
  BIO *bio;

  if ((bio = BIO_new_file(file, "r")) == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot open DH file\n"));

  } else {
    ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (SSL_CTX_set_tmp_dh(ctx, ret) < 0)
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot set DH param\n"));
  }

#endif
}

/* RFC 5114, 2.3. 2048-bit MODP Group with 256-bit Prime Order Subgroup */
static const unsigned char dh2048_prime[] = {0x87, 0xA8, 0xE6, 0x1D, 0xB4, 0xB6, 0x66, 0x3C, 0xFF, 0xBB, 0xD1, 0x9C, 0x65, 0x19, 0x59, 0x99, 0x8C, 0xEE, 0xF6, 0x08, 0x66, 0x0D, 0xD0, 0xF2, 0x5D, 0x2C, 0xEE, 0xD4, 0x43, 0x5E, 0x3B, 0x00,
                                             0xE0, 0x0D, 0xF8, 0xF1, 0xD6, 0x19, 0x57, 0xD4, 0xFA, 0xF7, 0xDF, 0x45, 0x61, 0xB2, 0xAA, 0x30, 0x16, 0xC3, 0xD9, 0x11, 0x34, 0x09, 0x6F, 0xAA, 0x3B, 0xF4, 0x29, 0x6D, 0x83, 0x0E, 0x9A, 0x7C,
                                             0x20, 0x9E, 0x0C, 0x64, 0x97, 0x51, 0x7A, 0xBD, 0x5A, 0x8A, 0x9D, 0x30, 0x6B, 0xCF, 0x67, 0xED, 0x91, 0xF9, 0xE6, 0x72, 0x5B, 0x47, 0x58, 0xC0, 0x22, 0xE0, 0xB1, 0xEF, 0x42, 0x75, 0xBF, 0x7B,
                                             0x6C, 0x5B, 0xFC, 0x11, 0xD4, 0x5F, 0x90, 0x88, 0xB9, 0x41, 0xF5, 0x4E, 0xB1, 0xE5, 0x9B, 0xB8, 0xBC, 0x39, 0xA0, 0xBF, 0x12, 0x30, 0x7F, 0x5C, 0x4F, 0xDB, 0x70, 0xC5, 0x81, 0xB2, 0x3F, 0x76,
                                             0xB6, 0x3A, 0xCA, 0xE1, 0xCA, 0xA6, 0xB7, 0x90, 0x2D, 0x52, 0x52, 0x67, 0x35, 0x48, 0x8A, 0x0E, 0xF1, 0x3C, 0x6D, 0x9A, 0x51, 0xBF, 0xA4, 0xAB, 0x3A, 0xD8, 0x34, 0x77, 0x96, 0x52, 0x4D, 0x8E,
                                             0xF6, 0xA1, 0x67, 0xB5, 0xA4, 0x18, 0x25, 0xD9, 0x67, 0xE1, 0x44, 0xE5, 0x14, 0x05, 0x64, 0x25, 0x1C, 0xCA, 0xCB, 0x83, 0xE6, 0xB4, 0x86, 0xF6, 0xB3, 0xCA, 0x3F, 0x79, 0x71, 0x50, 0x60, 0x26,
                                             0xC0, 0xB8, 0x57, 0xF6, 0x89, 0x96, 0x28, 0x56, 0xDE, 0xD4, 0x01, 0x0A, 0xBD, 0x0B, 0xE6, 0x21, 0xC3, 0xA3, 0x96, 0x0A, 0x54, 0xE7, 0x10, 0xC3, 0x75, 0xF2, 0x63, 0x75, 0xD7, 0x01, 0x41, 0x03,
                                             0xA4, 0xB5, 0x43, 0x30, 0xC1, 0x98, 0xAF, 0x12, 0x61, 0x16, 0xD2, 0x27, 0x6E, 0x11, 0x71, 0x5F, 0x69, 0x38, 0x77, 0xFA, 0xD7, 0xEF, 0x09, 0xCA, 0xDB, 0x09, 0x4A, 0xE9, 0x1E, 0x1A, 0x15, 0x97};

static const unsigned char dh2048_generator[] = {0x3F, 0xB3, 0x2C, 0x9B, 0x73, 0x13, 0x4D, 0x0B, 0x2E, 0x77, 0x50, 0x66, 0x60, 0xED, 0xBD, 0x48, 0x4C, 0xA7, 0xB1, 0x8F, 0x21, 0xEF, 0x20, 0x54, 0x07, 0xF4, 0x79, 0x3A, 0x1A, 0x0B, 0xA1, 0x25,
                                                 0x10, 0xDB, 0xC1, 0x50, 0x77, 0xBE, 0x46, 0x3F, 0xFF, 0x4F, 0xED, 0x4A, 0xAC, 0x0B, 0xB5, 0x55, 0xBE, 0x3A, 0x6C, 0x1B, 0x0C, 0x6B, 0x47, 0xB1, 0xBC, 0x37, 0x73, 0xBF, 0x7E, 0x8C, 0x6F, 0x62,
                                                 0x90, 0x12, 0x28, 0xF8, 0xC2, 0x8C, 0xBB, 0x18, 0xA5, 0x5A, 0xE3, 0x13, 0x41, 0x00, 0x0A, 0x65, 0x01, 0x96, 0xF9, 0x31, 0xC7, 0x7A, 0x57, 0xF2, 0xDD, 0xF4, 0x63, 0xE5, 0xE9, 0xEC, 0x14, 0x4B,
                                                 0x77, 0x7D, 0xE6, 0x2A, 0xAA, 0xB8, 0xA8, 0x62, 0x8A, 0xC3, 0x76, 0xD2, 0x82, 0xD6, 0xED, 0x38, 0x64, 0xE6, 0x79, 0x82, 0x42, 0x8E, 0xBC, 0x83, 0x1D, 0x14, 0x34, 0x8F, 0x6F, 0x2F, 0x91, 0x93,
                                                 0xB5, 0x04, 0x5A, 0xF2, 0x76, 0x71, 0x64, 0xE1, 0xDF, 0xC9, 0x67, 0xC1, 0xFB, 0x3F, 0x2E, 0x55, 0xA4, 0xBD, 0x1B, 0xFF, 0xE8, 0x3B, 0x9C, 0x80, 0xD0, 0x52, 0xB9, 0x85, 0xD1, 0x82, 0xEA, 0x0A,
                                                 0xDB, 0x2A, 0x3B, 0x73, 0x13, 0xD3, 0xFE, 0x14, 0xC8, 0x48, 0x4B, 0x1E, 0x05, 0x25, 0x88, 0xB9, 0xB7, 0xD2, 0xBB, 0xD2, 0xDF, 0x01, 0x61, 0x99, 0xEC, 0xD0, 0x6E, 0x15, 0x57, 0xCD, 0x09, 0x15,
                                                 0xB3, 0x35, 0x3B, 0xBB, 0x64, 0xE0, 0xEC, 0x37, 0x7F, 0xD0, 0x28, 0x37, 0x0D, 0xF9, 0x2B, 0x52, 0xC7, 0x89, 0x14, 0x28, 0xCD, 0xC6, 0x7E, 0xB6, 0x18, 0x4B, 0x52, 0x3D, 0x1D, 0xB2, 0x46, 0xC3,
                                                 0x2F, 0x63, 0x07, 0x84, 0x90, 0xF0, 0x0E, 0xF8, 0xD6, 0x47, 0xD1, 0x48, 0xD4, 0x79, 0x54, 0x51, 0x5E, 0x23, 0x27, 0xCF, 0xEF, 0x98, 0xC5, 0x82, 0x66, 0x4B, 0x4C, 0x0F, 0x6C, 0xC4, 0x16, 0x59};

static void build_dh_params(SSL_CTX *ctx) {
#ifndef OPENSSL_NO_DH
  DH *dh = DH_new();
  BIGNUM *p;
  BIGNUM *g;

  if (!dh) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] DH_new failed\n"));
    return;
  }

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [TLS] building DH params\n"));

  p = BN_bin2bn(dh2048_prime, sizeof(dh2048_prime), NULL);
  g = BN_bin2bn(dh2048_generator, sizeof(dh2048_generator), NULL);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  dh->p = p;
  dh->g = g;
  dh->length = 256;
  if (dh->p == NULL || dh->g == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] DH set p g failed\n"));
    return;
  }
#else
  if (!DH_set0_pqg(dh, p, NULL, g)) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] DH_set0_pqg failed\n"));
    return;
  }
#endif

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [TLS] DH params built\n"));

  SSL_CTX_set_tmp_dh(ctx, dh);
  SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

  DH_free(dh);

  return;
#endif
}

#ifndef OPENSSL_NO_RSA
static RSA *__RSA_generate_key(int bits, unsigned long e_value, void (*callback)(int, int, void *), void *cb_arg) {
  int i;
  RSA *rsa = RSA_new();
  BIGNUM *e = BN_new();

  if (!rsa || !e)
    goto err;

  i = BN_set_word(e, e_value);

  if (i != 1)
    goto err;

  if (RSA_generate_key_ex(rsa, bits, e, NULL)) {
    BN_free(e);
    return rsa;
  }

err:

  if (e)
    BN_free(e);

  if (rsa)
    RSA_free(rsa);

  return 0;
}

static void generate_eph_rsa_key(SSL_CTX *ctx) {
  RSA *rsa;

  rsa = __RSA_generate_key(2048, RSA_F4, NULL, NULL);

  if (rsa != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L

    if (!SSL_CTX_set_tmp_rsa(ctx, rsa))
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot set RSA key\n"));

#endif

    RSA_free(rsa);
  }
}
#endif

eXosip_tls_ctx_error eXosip_set_tls_ctx(struct eXosip_t *excontext, eXosip_tls_ctx_t *ctx) {
  eXosip_tls_credentials_t *ownClient = &excontext->eXosip_tls_ctx_params.client;
  eXosip_tls_credentials_t *ownServer = &excontext->eXosip_tls_ctx_params.server;

  eXosip_tls_credentials_t *client = &ctx->client;
  eXosip_tls_credentials_t *server = &ctx->server;

  /* check if public AND private keys are valid */
  if (client->cert[0] == '\0' && client->priv_key[0] != '\0') {
    /* no, one is missing */
    return TLS_ERR_MISSING_AUTH_PART;
  }

  if (client->cert[0] != '\0' && client->priv_key[0] == '\0') {
    /* no, one is missing */
    return TLS_ERR_MISSING_AUTH_PART;
  }

  /* check if public AND private keys are valid */
  if (server->cert[0] == '\0' && server->priv_key[0] != '\0') {
    /* no, one is missing */
    return TLS_ERR_MISSING_AUTH_PART;
  }

  if (server->cert[0] != '\0' && server->priv_key[0] == '\0') {
    /* no, one is missing */
    return TLS_ERR_MISSING_AUTH_PART;
  }

  /* clean up configuration */
  memset(&excontext->eXosip_tls_ctx_params, 0, sizeof(eXosip_tls_ctx_t));

  if (client->public_key_pinned[0] != '\0') {
    snprintf(ownClient->public_key_pinned, sizeof(ownClient->public_key_pinned), "%s", client->public_key_pinned);
  }

  /* check if client has own certificate */
  if (client->cert[0] != '\0') {
    snprintf(ownClient->cert, sizeof(ownClient->cert), "%s", client->cert);
    snprintf(ownClient->priv_key, sizeof(ownClient->priv_key), "%s", client->priv_key);
    snprintf(ownClient->priv_key_pw, sizeof(ownClient->priv_key_pw), "%s", client->priv_key_pw);
  }

  /* check if server has own certificate */
  if (server->cert[0] != '\0') {
    snprintf(ownServer->cert, sizeof(ownServer->cert), "%s", server->cert);
    snprintf(ownServer->priv_key, sizeof(ownServer->priv_key), "%s", server->priv_key);
    snprintf(ownServer->priv_key_pw, sizeof(ownServer->priv_key_pw), "%s", server->priv_key_pw);
  }

  snprintf(excontext->eXosip_tls_ctx_params.dh_param, sizeof(ctx->dh_param), "%s", ctx->dh_param);
  snprintf(excontext->eXosip_tls_ctx_params.random_file, sizeof(ctx->random_file), "%s", ctx->random_file);
  snprintf(excontext->eXosip_tls_ctx_params.root_ca_cert, sizeof(ctx->root_ca_cert), "%s", ctx->root_ca_cert);
  snprintf(excontext->eXosip_tls_ctx_params.cipher_list, sizeof(ctx->cipher_list), "%s", ctx->cipher_list);
  excontext->eXosip_tls_ctx_params.tls_flags = ctx->tls_flags;
  excontext->eXosip_tls_ctx_params.dtls_flags = ctx->dtls_flags;

  return TLS_OK;
}

eXosip_tls_ctx_error eXosip_tls_verify_certificate(struct eXosip_t *excontext, int _tls_verify_client_certificate) {
  excontext->tls_verify_client_certificate = _tls_verify_client_certificate;
  return TLS_OK;
}

static void _tls_load_trusted_certificates(struct eXosip_t *excontext, eXosip_tls_ctx_t *exosip_tls_cfg, SSL_CTX *ctx) {
  char *caFile = 0, *caFolder = 0;

  if (_tls_add_certificates(excontext, ctx) <= 0) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] no system certificate loaded\n"));
  }

  if (exosip_tls_cfg->root_ca_cert[0] == '\0')
    return;

  {
#ifdef WIN32
    WIN32_FIND_DATA FileData;
    HANDLE hSearch;
    char szDirPath[1024];
    WCHAR wUnicodeDirPath[2048];

    snprintf(szDirPath, sizeof(szDirPath), "%s", exosip_tls_cfg->root_ca_cert);

    MultiByteToWideChar(CP_UTF8, 0, szDirPath, -1, wUnicodeDirPath, 2048);
    hSearch = FindFirstFileEx(wUnicodeDirPath, FindExInfoStandard, &FileData, FindExSearchNameMatch, NULL, 0);

    if (hSearch != INVALID_HANDLE_VALUE) {
      if ((FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
        caFolder = exosip_tls_cfg->root_ca_cert;

      else
        caFile = exosip_tls_cfg->root_ca_cert;
      FindClose(hSearch);
    } else {
      caFile = exosip_tls_cfg->root_ca_cert;
    }

#else
    int fd = open(exosip_tls_cfg->root_ca_cert, O_RDONLY);

    if (fd >= 0) {
      struct stat fileStat;

      if (fstat(fd, &fileStat) < 0) {
      } else {
        if (S_ISDIR(fileStat.st_mode)) {
          caFolder = exosip_tls_cfg->root_ca_cert;

        } else {
          caFile = exosip_tls_cfg->root_ca_cert;
        }
      }

      close(fd);
    }

#endif
  }

  if (exosip_tls_cfg->root_ca_cert[0] == '\0') {
  } else {
    if (SSL_CTX_load_verify_locations(ctx, caFile, caFolder)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] trusted CA PEM file loaded [%s]\n", exosip_tls_cfg->root_ca_cert));

    } else {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot read trusted CA list [%s]\n", exosip_tls_cfg->root_ca_cert));
    }
  }
}

static void _tls_use_certificate_private_key(const char *log, eXosip_tls_credentials_t *xtc, SSL_CTX *ctx) {
  /* load from file name in PEM files */
  if (xtc->cert[0] != '\0' && xtc->priv_key[0] != '\0') {
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *) xtc->priv_key_pw);
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);

    /* Load our keys and certificates */
    if (SSL_CTX_use_certificate_file(ctx, xtc->cert, SSL_FILETYPE_ASN1)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [%s] certificate ASN1 file loaded [%s]\n", log, xtc->cert));

    } else if (SSL_CTX_use_certificate_file(ctx, xtc->cert, SSL_FILETYPE_PEM)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [%s] certificate PEM file loaded [%s]\n", log, xtc->cert));

    } else {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] [%s] cannot read certificate file [%s]\n", log, xtc->cert));
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, xtc->priv_key, SSL_FILETYPE_ASN1)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [%s] private key ASN1 file loaded [%s]\n", log, xtc->priv_key));

    } else if (SSL_CTX_use_PrivateKey_file(ctx, xtc->priv_key, SSL_FILETYPE_PEM)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [%s] private key PEM file loaded [%s]\n", log, xtc->priv_key));

    } else {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] [%s] cannot read private key file [%s]\n", log, xtc->priv_key));
    }

    if (!SSL_CTX_check_private_key(ctx)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] [%s] private key does not match the public key of your certificate\n", log));
    }
  }
}

static void _tls_common_setup(eXosip_tls_ctx_t *exosip_tls_cfg, SSL_CTX *ctx) {
#ifndef SSL_CTRL_SET_ECDH_AUTO
#define SSL_CTRL_SET_ECDH_AUTO 94
#endif

  if (exosip_tls_cfg->dh_param[0] == '\0')
    build_dh_params(ctx);

  else
    load_dh_params(ctx, exosip_tls_cfg->dh_param);

  /* SSL_CTX_set_ecdh_auto (ctx, on) requires OpenSSL 1.0.2 which wraps: */
  if (SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, 1, NULL)) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] ctrl_set_ecdh_auto: faster PFS ciphers enabled\n"));
#if !defined(OPENSSL_NO_ECDH) && !(OPENSSL_VERSION_NUMBER < 0x10000000L) && (OPENSSL_VERSION_NUMBER < 0x10100000L)

  } else {
    /* enables AES-128 ciphers, to get AES-256 use NID_secp384r1 */
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    if (ecdh != NULL) {
      if (SSL_CTX_set_tmp_ecdh(ctx, ecdh)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] set_tmp_ecdh: faster PFS ciphers enabled (secp256r1)\n"));
      }

      EC_KEY_free(ecdh);
    }

#endif
  }
}

SSL_CTX *initialize_client_ctx(struct eXosip_t *excontext, eXosip_tls_ctx_t *client_ctx, int transport, const char *sni_servernameindication) {
  const SSL_METHOD *meth = NULL;
  SSL_CTX *ctx;
  int err;

  if (transport == IPPROTO_UDP) {
#if !(OPENSSL_VERSION_NUMBER < 0x10002000L)
    meth = DTLS_client_method();
#elif !(OPENSSL_VERSION_NUMBER < 0x00908000L)
    meth = DTLSv1_client_method();
#endif

  } else if (transport == IPPROTO_TCP) {
    meth = SSLv23_client_method();

  } else {
    return NULL;
  }

  ctx = SSL_CTX_new(meth);

  if (ctx == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot create SSL_CTX\n"));
    return NULL;
  }

  _tls_use_certificate_private_key("client", &client_ctx->client, ctx);

  /* Load the CAs we trust */
  _tls_load_trusted_certificates(excontext, client_ctx, ctx);

  {
    int verify_mode = SSL_VERIFY_NONE;

#if !(OPENSSL_VERSION_NUMBER < 0x10002000L)

    if (excontext->tls_verify_client_certificate > 0 && sni_servernameindication != NULL) {
      X509_STORE *pkix_validation_store = SSL_CTX_get_cert_store(ctx);
      const X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_lookup("ssl_server");

      if (param != NULL) { /* const value, we have to copy (inherit) */
        X509_VERIFY_PARAM *param_to = X509_STORE_get0_param(pkix_validation_store);

        if (X509_VERIFY_PARAM_inherit(param_to, param)) {
          X509_STORE_set_flags(pkix_validation_store, X509_V_FLAG_TRUSTED_FIRST);
          X509_STORE_set_flags(pkix_validation_store, X509_V_FLAG_PARTIAL_CHAIN);

        } else {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] PARAM_inherit: failed for ssl_server\n"));
        }

        if (X509_VERIFY_PARAM_set1_host(param_to, sni_servernameindication, 0)) {
          if (excontext->tls_verify_client_certificate & 0x02) {
            X509_VERIFY_PARAM_set_hostflags(param_to, X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS);
          } else {
            X509_VERIFY_PARAM_set_hostflags(param_to, X509_CHECK_FLAG_NO_WILDCARDS);
          }

        } else {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] PARAM_set1_host: [%s] failed\n", sni_servernameindication));
        }

      } else {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] PARAM_lookup: failed for ssl_server\n"));
      }
    }

#endif

    verify_mode = SSL_VERIFY_PEER;

    SSL_CTX_set_verify(ctx, verify_mode, &verify_cb);
    SSL_CTX_set_verify_depth(ctx, ex_verify_depth + 1);
  }

  {
    unsigned long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_ECDH_USE | SSL_OP_SINGLE_DH_USE;

#ifdef SSL_OP_NO_COMPRESSION
    flags |= SSL_OP_NO_COMPRESSION;
#endif

#ifdef SSL_OP_NO_TICKET
    flags |= SSL_OP_NO_TICKET;
#endif

    if (transport == IPPROTO_UDP) {
      flags |= client_ctx->dtls_flags;
    } else {
      flags |= client_ctx->tls_flags;
    }
    SSL_CTX_set_options(ctx, flags);
  }

  if (client_ctx->cipher_list[0] != '\0') {
    err = SSL_CTX_set_cipher_list(ctx, client_ctx->cipher_list);
    if (!err) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] error with cipher list\n"));
    }
  } else {
    err = SSL_CTX_set_cipher_list(ctx, "HIGH:!COMPLEMENTOFDEFAULT:!kRSA:!PSK:!SRP");
    if (!err) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] error with standard cipher list\n"));
    }
  }

  _tls_common_setup(client_ctx, ctx);

  return ctx;
}

SSL_CTX *initialize_server_ctx(struct eXosip_t *excontext, eXosip_tls_ctx_t *srv_ctx, int transport) {
  const SSL_METHOD *meth = NULL;
  SSL_CTX *ctx;
  int err;

  int s_server_session_id_context = 1;

  if (transport == IPPROTO_UDP) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [TLS] DTLS-UDP server method\n"));
#if !(OPENSSL_VERSION_NUMBER < 0x10002000L)
    meth = DTLS_server_method();
#elif !(OPENSSL_VERSION_NUMBER < 0x00908000L)
    meth = DTLSv1_server_method();
#endif

  } else if (transport == IPPROTO_TCP) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [TLS] TLS server method\n"));
    meth = SSLv23_server_method();

  } else {
    return NULL;
  }

  ctx = SSL_CTX_new(meth);

  if (ctx == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot create SSL_CTX\n"));
    SSL_CTX_free(ctx);
    return NULL;
  }

  if (transport == IPPROTO_UDP) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [TLS] DTLS-UDP read ahead\n"));
    SSL_CTX_set_read_ahead(ctx, 1);
  }

  _tls_use_certificate_private_key("server", &srv_ctx->server, ctx);

  /* Load the CAs we trust */
  _tls_load_trusted_certificates(excontext, srv_ctx, ctx);

  if (!SSL_CTX_check_private_key(ctx)) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] check_private_key: either no match or no cert/key: disable incoming TLS connection\n"));
    SSL_CTX_free(ctx);
    return NULL;
  }

  {
    int verify_mode = SSL_VERIFY_NONE;

    /*verify_mode = SSL_VERIFY_PEER; */

    SSL_CTX_set_verify(ctx, verify_mode, &verify_cb);
    SSL_CTX_set_verify_depth(ctx, ex_verify_depth + 1);
  }

  {
    unsigned long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | SSL_OP_SINGLE_ECDH_USE | SSL_OP_SINGLE_DH_USE | SSL_OP_CIPHER_SERVER_PREFERENCE;

#ifdef SSL_OP_NO_COMPRESSION
    flags |= SSL_OP_NO_COMPRESSION;
#endif

#ifdef SSL_OP_NO_TICKET
    flags |= SSL_OP_NO_TICKET;
#endif

    if (transport == IPPROTO_UDP) {
      flags |= srv_ctx->dtls_flags;
    } else {
      flags |= srv_ctx->tls_flags;
    }

    SSL_CTX_set_options(ctx, flags);
  }

  if (srv_ctx->cipher_list[0] != '\0') {
    err = SSL_CTX_set_cipher_list(ctx, srv_ctx->cipher_list);
    if (!err) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] error with cipher list\n"));
    }
  } else {
    err = SSL_CTX_set_cipher_list(ctx, "HIGH:!COMPLEMENTOFDEFAULT:!kRSA:!PSK:!SRP");
    if (!err) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] error with standard cipher list\n"));
    }
  }

  _tls_common_setup(srv_ctx, ctx);

#ifndef OPENSSL_NO_RSA
  generate_eph_rsa_key(ctx);
#endif

  SSL_CTX_set_session_id_context(ctx, (void *) &s_server_session_id_context, sizeof s_server_session_id_context);

  return ctx;
}

/**
 * @brief Initializes the OpenSSL lib and the client/server contexts.
 * Depending on the previously initialized eXosip TLS context (see eXosip_set_tls_ctx() ), only the necessary contexts will be initialized.
 * The client context will be ALWAYS initialized, the server context only if certificates are available. The following chart should illustrate
 * the behaviour.
 *
 * possible certificates  | Client initialized       | Server initialized
 * -------------------------------------------------------------------------------------
 * no certificate     | yes, no cert used        | not initialized
 * only client cert     | yes, own cert (client) used    | yes, client cert used
 * only server cert     | yes, server cert used      | yes, own cert (server) used
 * server and client cert | yes, own cert (client) used    | yes, own cert (server) used
 *
 * The file for seeding the PRNG is only needed on Windows machines. If you compile under a Windows environment, please set W32 oder _WINDOWS as
 * Preprocessor directives.
 *@return < 0 if an error occured
 **/
static int tls_tl_open(struct eXosip_t *excontext) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int res;
  struct addrinfo *addrinfo = NULL;
  struct addrinfo *curinfo;
  int sock = -1;
  char *node = NULL;
  char eb[ERRBSIZ];

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  excontext->eXtl_transport.proto_local_port = excontext->eXtl_transport.proto_port;

  if (excontext->eXtl_transport.proto_local_port < 0)
    excontext->eXtl_transport.proto_local_port = 5061;

    /* initialization (outside initialize_server_ctx) */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_library_init();
  SSL_load_error_strings();
#else
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif

  reserved->server_ctx = initialize_server_ctx(excontext, & excontext->eXosip_tls_ctx_params, IPPROTO_TCP);

  /* always initialize the client */
  reserved->client_ctx = initialize_client_ctx(excontext, &excontext->eXosip_tls_ctx_params, IPPROTO_TCP, NULL);

  /*only necessary under Windows-based OS, unix-like systems use /dev/random or /dev/urandom */
#if defined(HAVE_WINSOCK2_H)

#if 0

  /* check if a file with random data is present --> will be verified when random file is needed */
  if (reserved->eXosip_tls_ctx_params.random_file[0] == '\0') {
    return TLS_ERR_NO_RAND;
  }

#endif

  /* Load randomness */
  if (!(RAND_load_file(excontext->eXosip_tls_ctx_params.random_file, 1024 * 1024)))
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] cannot load randomness\n"));

#endif

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
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [TLS] skipping protocol [%d]\n", curinfo->ai_protocol));
      continue;
    }

    type = curinfo->ai_socktype;
#if defined(SOCK_CLOEXEC)
    type = SOCK_CLOEXEC | type;
#endif
    sock = (int) socket(curinfo->ai_family, type, curinfo->ai_protocol);

    if (sock < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot create socket %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      continue;
    }

    if (curinfo->ai_family == AF_INET6) {
#ifdef IPV6_V6ONLY

      if (setsockopt_ipv6only(sock)) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot set socket option %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
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
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot bind socket [%s][%s] %s\n", excontext->eXtl_transport.proto_ifs, (curinfo->ai_family == AF_INET) ? "AF_INET" : "AF_INET6", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      _eXosip_closesocket(sock);
      sock = -1;
      continue;
    }

    len = sizeof(reserved->ai_addr);
    res = getsockname(sock, (struct sockaddr *) &reserved->ai_addr, &len);

    if (res != 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot get socket name %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      memcpy(&reserved->ai_addr, curinfo->ai_addr, curinfo->ai_addrlen);
    }

    reserved->ai_addr_len = len;

    if (excontext->eXtl_transport.proto_num == IPPROTO_TCP) {
      res = listen(sock, SOMAXCONN);

      if (res < 0) {
        OSIP_TRACE(
            osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot bind socket [%s][%s] %s\n", excontext->eXtl_transport.proto_ifs, (curinfo->ai_family == AF_INET) ? "AF_INET" : "AF_INET6", _ex_strerror(ex_errno, eb, ERRBSIZ)));
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
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot bind on port [%i]\n", excontext->eXtl_transport.proto_local_port));
    return -1;
  }

  reserved->tls_socket = sock;

  if (excontext->eXtl_transport.proto_local_port == 0) {
    /* get port number from socket */
    if (reserved->ai_addr.ss_family == AF_INET)
      excontext->eXtl_transport.proto_local_port = ntohs(((struct sockaddr_in *) &reserved->ai_addr)->sin_port);

    else
      excontext->eXtl_transport.proto_local_port = ntohs(((struct sockaddr_in6 *) &reserved->ai_addr)->sin6_port);

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] binding on port [%i]\n", excontext->eXtl_transport.proto_local_port));
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
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot poll on main tls socket [%i]\n", excontext->eXtl_transport.proto_local_port));
      _eXosip_closesocket(sock);
      reserved->tls_socket = -1;
      return -1;
    }
  }

#endif
#endif

  return OSIP_SUCCESS;
}

static int tls_tl_set_fdset(struct eXosip_t *excontext, fd_set *osip_fdset, fd_set *osip_wrset, fd_set *osip_exceptset, int *fd_max, int *osip_fd_table) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int pos;
  int pos_fd = 0;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

#ifdef ENABLE_MAIN_SOCKET

  if (reserved->tls_socket <= 0)
    return -1;

  if (osip_fdset != NULL)
    eXFD_SET(reserved->tls_socket, osip_fdset);

  if (reserved->tls_socket > *fd_max)
    *fd_max = reserved->tls_socket;

#endif

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].invalid > 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] [fdset] socket info:[%s][%d] [sock=%d] [pos=%d] manual reset\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                            reserved->socket_tab[pos].socket, pos));
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
      _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
      continue;
    }

    if (reserved->socket_tab[pos].socket > 0) {
      if (osip_fdset != NULL)
        eXFD_SET(reserved->socket_tab[pos].socket, osip_fdset);
      osip_fd_table[pos_fd] = reserved->socket_tab[pos].socket;
      pos_fd++;

      if (reserved->socket_tab[pos].socket > *fd_max)
        *fd_max = reserved->socket_tab[pos].socket;

      if (osip_wrset != NULL && (reserved->socket_tab[pos].sendbuflen > 0 && reserved->socket_tab[pos].ssl_state == 3))
        eXFD_SET(reserved->socket_tab[pos].socket, osip_wrset);

      //if (osip_wrset != NULL && (reserved->socket_tab[pos].ssl_state == 0 || reserved->socket_tab[pos].ssl_state == 2)) /* wait for establishment OR do handshake with incoming connection */
      if (osip_wrset != NULL && reserved->socket_tab[pos].ssl_state == 0) /* wait for establishment */
        eXFD_SET(reserved->socket_tab[pos].socket, osip_wrset);

      if (osip_exceptset != NULL && reserved->socket_tab[pos].ssl_state == 0) /* wait for establishment */
        eXFD_SET(reserved->socket_tab[pos].socket, osip_exceptset);
    }
  }

  return OSIP_SUCCESS;
}

static int _tls_print_ssl_error(int err) {
  switch (err) {
  case SSL_ERROR_NONE:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL ERROR NONE - OK\n"));
    break;

  case SSL_ERROR_ZERO_RETURN:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL ERROR ZERO RETURN - SHUTDOWN\n"));
    break;

  case SSL_ERROR_WANT_READ:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL want read\n"));
    break;

  case SSL_ERROR_WANT_WRITE:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL want write\n"));
    break;

  case SSL_ERROR_SSL:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL ERROR\n"));
    break;

  case SSL_ERROR_SYSCALL:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL ERROR SYSCALL\n"));
    break;

  default:
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL problem\n"));
  }

  return OSIP_SUCCESS;
}

static void tls_dump_verification_failure(long verification_result, char *reason, size_t reason_len) {
  switch (verification_result) {
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    snprintf(reason, reason_len, "unable to get issuer certificate");
    break;

  case X509_V_ERR_UNABLE_TO_GET_CRL:
    snprintf(reason, reason_len, "unable to get certificate CRL");
    break;

  case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    snprintf(reason, reason_len, "unable to decrypt certificate's signature");
    break;

  case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
    snprintf(reason, reason_len, "unable to decrypt CRL's signature");
    break;

  case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    snprintf(reason, reason_len, "unable to decode issuer public key");
    break;

  case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    snprintf(reason, reason_len, "certificate signature failure");
    break;

  case X509_V_ERR_CRL_SIGNATURE_FAILURE:
    snprintf(reason, reason_len, "CRL signature failure");
    break;

  case X509_V_ERR_CERT_NOT_YET_VALID:
    snprintf(reason, reason_len, "certificate is not yet valid");
    break;

  case X509_V_ERR_CERT_HAS_EXPIRED:
    snprintf(reason, reason_len, "certificate has expired");
    break;

  case X509_V_ERR_CRL_NOT_YET_VALID:
    snprintf(reason, reason_len, "CRL is not yet valid");
    break;

  case X509_V_ERR_CRL_HAS_EXPIRED:
    snprintf(reason, reason_len, "CRL has expired");
    break;

  case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    snprintf(reason, reason_len, "format error in certificate's notBefore field");
    break;

  case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    snprintf(reason, reason_len, "format error in certificate's notAfter field");
    break;

  case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    snprintf(reason, reason_len, "format error in CRL's lastUpdate field");
    break;

  case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
    snprintf(reason, reason_len, "format error in CRL's nextUpdate field");
    break;

  case X509_V_ERR_OUT_OF_MEM:
    snprintf(reason, reason_len, "out of memory");
    break;

  case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    snprintf(reason, reason_len, "self signed certificate");
    break;

  case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    snprintf(reason, reason_len, "self signed certificate in certificate chain");
    break;

  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    snprintf(reason, reason_len, "unable to get local issuer certificate");
    break;

  case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    snprintf(reason, reason_len, "unable to verify the first certificate");
    break;

  case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    snprintf(reason, reason_len, "certificate chain too long");
    break;

  case X509_V_ERR_CERT_REVOKED:
    snprintf(reason, reason_len, "certificate revoked");
    break;

  case X509_V_ERR_INVALID_CA:
    snprintf(reason, reason_len, "invalid CA certificate");
    break;

  case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    snprintf(reason, reason_len, "path length constraint exceeded");
    break;

  case X509_V_ERR_INVALID_PURPOSE:
    snprintf(reason, reason_len, "unsupported certificate purpose");
    break;

  case X509_V_ERR_CERT_UNTRUSTED:
    snprintf(reason, reason_len, "certificate not trusted");
    break;

  case X509_V_ERR_CERT_REJECTED:
    snprintf(reason, reason_len, "certificate rejected");
    break;

  case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
    snprintf(reason, reason_len, "subject issuer mismatch");
    break;

  case X509_V_ERR_AKID_SKID_MISMATCH:
    snprintf(reason, reason_len, "authority and subject key identifier mismatch");
    break;

  case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
    snprintf(reason, reason_len, "authority and issuer serial number mismatch");
    break;

  case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
    snprintf(reason, reason_len, "key usage does not include certificate signing");
    break;

  case X509_V_ERR_APPLICATION_VERIFICATION:
    snprintf(reason, reason_len, "application verification failure");
    break;

  default:
    snprintf(reason, reason_len, "unknown error");
    break;
  }

  // OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] verification failure [%s]\n", tmp));
}

static int pkp_pin_peer_pubkey(struct eXosip_t *excontext, SSL *ssl) {
  X509 *cert = NULL;
  FILE *fp = NULL;

  int len1 = 0, len2 = 0;
  unsigned char *buff1 = NULL, *buff2 = NULL;

  int ret = 0, result = -1;

  if (NULL == ssl)
    return -1;

  if (excontext->eXosip_tls_ctx_params.client.public_key_pinned[0] == '\0')
    return 0;

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] checking pinned public key for certificate [%s]\n", excontext->eXosip_tls_ctx_params.client.public_key_pinned));

  do {
    unsigned char *temp = NULL;
    long size;

    cert = SSL_get_peer_certificate(ssl);

    if (!(cert != NULL))
      break; /* failed */

    /* Begin Gyrations to get the subjectPublicKeyInfo       */
    /* Thanks to Viktor Dukhovni on the OpenSSL mailing list */

    len1 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);

    if (!(len1 > 0))
      break; /* failed */

    buff1 = temp = OPENSSL_malloc(len1);

    if (!(buff1 != NULL))
      break; /* failed */

    len2 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &temp);

    if (!((len1 == len2) && (temp != NULL) && ((temp - buff1) == len1)))
      break; /* failed */

    /* in order to get your public key file in DER format: */
    /* openssl x509 -in your-base64-certificate.pem -pubkey -noout | openssl enc -base64 -d > publickey.der */
    fp = fopen(excontext->eXosip_tls_ctx_params.client.public_key_pinned, "rb");

    if (NULL == fp)
      fp = fopen(excontext->eXosip_tls_ctx_params.client.public_key_pinned, "r");

    if (!(NULL != fp))
      break; /* failed */

    ret = fseek(fp, 0, SEEK_END);

    if (!(0 == ret))
      break; /* failed */

    size = ftell(fp);

    if (!(size != -1 && size > 0 && size < 4096))
      break; /* failed */

    ret = fseek(fp, 0, SEEK_SET);

    if (!(0 == ret))
      break; /* failed */

    buff2 = NULL;
    len2 = (int) size;

    buff2 = OPENSSL_malloc(len2);

    if (!(buff2 != NULL))
      break; /* failed */

    ret = (int) fread(buff2, (size_t) len2, 1, fp);

    if (!(ret == 1))
      break; /* failed */

    size = len1 < len2 ? len1 : len2;

    if (len1 != (int) size || len2 != (int) size || 0 != memcmp(buff1, buff2, (size_t) size))
      break; /* failed */

    result = 0;

  } while (0);

  if (fp != NULL)
    fclose(fp);

  if (NULL != buff2)
    OPENSSL_free(buff2);

  if (NULL != buff1)
    OPENSSL_free(buff1);

  if (NULL != cert)
    X509_free(cert);

  return result;
}

static const char *get_sigtype(int nid) {
  switch (nid) {
  case EVP_PKEY_RSA:
    return "RSA";

  case EVP_PKEY_DSA:
    return "DSA";

  case EVP_PKEY_EC:
    return "ECDSA";

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  case EVP_PKEY_RSA_PSS:
    return "RSA-PSS";

#if defined(NID_Ed25519)
#define NID_ED25519 NID_Ed25519
#endif
#if defined(NID_Ed448)
#define NID_ED448 NID_Ed448
#endif

  case NID_ED25519:
    return "Ed25519";

  case NID_ED448:
    return "Ed448";
#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090809fL
  case NID_id_GostR3410_2001:
    return "gost2001";
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
  case NID_id_GostR3410_2012_256:
    return "gost2012_256";

  case NID_id_GostR3410_2012_512:
    return "gost2012_512";
#endif

  default:
    return NULL;
  }
}

static void tls_dump_info(struct eXosip_t *excontext, struct _tls_stream *sockinfo) {
  char tmp_info[2048];
  size_t len_info = 0;

  X509 *peer = NULL;
  const SSL_CIPHER *c;
  long verify_err;
  int nid;

  if (excontext->tls_verify_client_certificate > 0) {
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [verification=ENABLED]");
  } else {
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [verification=DISABLED]");
  }

  peer = SSL_get_peer_certificate(sockinfo->ssl_conn);

  verify_err = SSL_get_verify_result(sockinfo->ssl_conn);
  if (peer != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
    if (verify_err == X509_V_OK) {
      const char *peername = SSL_get0_peername(sockinfo->ssl_conn);

      len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [SUCCESS");
      if (peername != NULL)
        len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " peername=%s", peername);
      len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, "]");
    } else {
      const char *reason = X509_verify_cert_error_string(verify_err);

      len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [FAILURE %s]", reason);
    }
#else
    if (verify_err == X509_V_OK) {
      len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [SUCCESS]");
    } else {
      char reason[64];
      tls_dump_verification_failure(verify_err, reason, sizeof(reason));

      len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [FAILURE %s]", reason);
    }
#endif
  } else {
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [FAILURE no peer certificate]");
  }

  len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [%s]", SSL_get_version(sockinfo->ssl_conn));

  len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [peer certificate");
  if (peer != NULL) {
    char tmp_buffer[128];

    X509_NAME_oneline(X509_get_subject_name(peer), tmp_buffer, sizeof(tmp_buffer));
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " sub=%s", tmp_buffer);
    X509_NAME_oneline(X509_get_issuer_name(peer), tmp_buffer, sizeof(tmp_buffer));
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " issuer=%s]", tmp_buffer);

  } else {
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " NONE]");
  }

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
  len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [peer");
  if (SSL_get_peer_signature_nid(sockinfo->ssl_conn, &nid) && nid != NID_undef)
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " signing digest=%s", OBJ_nid2sn(nid));
  if (SSL_get_peer_signature_type_nid(sockinfo->ssl_conn, &nid))
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " signature type=%s", get_sigtype(nid));

  {
    EVP_PKEY *key;

    if (SSL_get_peer_tmp_key(sockinfo->ssl_conn, &key)) {
      len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " temp key=");
      switch (EVP_PKEY_id(key)) {
      case EVP_PKEY_RSA:
        len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, "RSA, %dbits", EVP_PKEY_bits(key));
        break;

      case EVP_PKEY_DH:
        len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, "DH, %dbits", EVP_PKEY_bits(key));
        break;
#ifndef OPENSSL_NO_EC
      case EVP_PKEY_EC: {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
        int nid;
        const char *cname;
        nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
        EC_KEY_free(ec);
        cname = EC_curve_nid2nist(nid);
        if (cname == NULL)
          cname = OBJ_nid2sn(nid);
        len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, "ECDH, %s, %dbits", cname, EVP_PKEY_bits(key));
      } break;
#endif
      default:
        len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, "%s, %dbits", OBJ_nid2sn(EVP_PKEY_id(key)), EVP_PKEY_bits(key));
      }
      EVP_PKEY_free(key);
    }
  }
  len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, "]");
#endif

  c = SSL_get_current_cipher(sockinfo->ssl_conn);
  len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [cipher %s:%s", SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));

  if (peer != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_PKEY *pktmp;

    pktmp = X509_get0_pubkey(peer);
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " peer pub.key=%ubit", EVP_PKEY_bits(pktmp));
#endif
    X509_free(peer);
  }

#ifndef OPENSSL_NO_COMP
  {
    const COMP_METHOD *comp, *expansion;
    comp = SSL_get_current_compression(sockinfo->ssl_conn);
    expansion = SSL_get_current_expansion(sockinfo->ssl_conn);
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " Compression: %s", comp ? SSL_COMP_get_name(comp) : "NONE");
    len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " Expansion: %s", expansion ? SSL_COMP_get_name(expansion) : "NONE");
  }
#endif
  len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, "]");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  len_info += snprintf(tmp_info + len_info, sizeof(tmp_info) - len_info, " [handshake read=%ju write=%ju bytes]", BIO_number_read(SSL_get_rbio(sockinfo->ssl_conn)), BIO_number_written(SSL_get_wbio(sockinfo->ssl_conn)));
#endif

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [ssl connect]%s\n", tmp_info));
}

static int _tls_tl_ssl_connect_socket(struct eXosip_t *excontext, struct _tls_stream *sockinfo) {
  X509 *peer;
  BIO *sbio;
  int res;
  long cert_err;

  if (sockinfo->ssl_ctx == NULL) {
    sockinfo->ssl_ctx = initialize_client_ctx(excontext, &excontext->eXosip_tls_ctx_params, IPPROTO_TCP, sockinfo->sni_servernameindication);

    /* FIXME: changed parameter from ctx to client_ctx -> works now */
    sockinfo->ssl_conn = SSL_new(sockinfo->ssl_ctx);

    if (sockinfo->ssl_conn == NULL) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL_new error\n"));
      return -1;
    }

    sbio = BIO_new_socket(sockinfo->socket, BIO_NOCLOSE);

    if (sbio == NULL) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] BIO_new_socket error\n"));
      return -1;
    }

    SSL_set_bio(sockinfo->ssl_conn, sbio, sbio);

#ifndef OPENSSL_NO_TLSEXT

    if (!SSL_set_tlsext_host_name(sockinfo->ssl_conn, sockinfo->sni_servernameindication /* "host.name.before.dns.srv.com" */)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] set_tlsext_host_name (SNI): no servername gets indicated\n"));
    }

#endif
  }

  res = SSL_connect(sockinfo->ssl_conn);
  res = SSL_get_error(sockinfo->ssl_conn, res);

  if (res != SSL_ERROR_NONE && res != SSL_ERROR_WANT_READ && res != SSL_ERROR_WANT_WRITE) {
    tls_dump_info(excontext, sockinfo);
    _tls_print_ssl_error(res);
    return -1;
  }

  if (!SSL_is_init_finished(sockinfo->ssl_conn)) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [ssl connect] handshake in progress\n"));
    return 1;
  }

  tls_dump_info(excontext, sockinfo);

  cert_err = SSL_get_verify_result(sockinfo->ssl_conn);

  if (excontext->tls_verify_client_certificate > 0 && cert_err != X509_V_OK) {
    return -1;
  }

  peer = SSL_get_peer_certificate(sockinfo->ssl_conn);
  if (peer == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] no certificate received\n"));
    return -1;
  }
  X509_free(peer);

  if (pkp_pin_peer_pubkey(excontext, sockinfo->ssl_conn)) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] failed to verify public key for certificate\n"));
    return -1;
  }

  SSL_set_mode(sockinfo->ssl_conn, SSL_MODE_AUTO_RETRY);

  sockinfo->ssl_state = 3;
  _eXosip_mark_all_transaction_force_send(excontext, sockinfo->socket);
  return 0;
}

/* Like strstr, but works for haystack that may contain binary data and is
   not NUL-terminated. */
static char *_tls_buffer_find(const char *haystack, size_t haystack_len, const char *needle) {
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
static size_t _tls_handle_messages(struct eXosip_t *excontext, struct _tls_stream *sockinfo) {
  size_t consumed = 0;
  char *buf = sockinfo->buf;
  size_t buflen = sockinfo->buflen;
  char *end_headers;

  while (buflen > 0 && (end_headers = _tls_buffer_find(buf, buflen, END_HEADERS_STR)) != NULL) {
    int clen;
    size_t msglen;
    char *clen_header;

    if (buf == end_headers) {
      /* skip tcp standard keep-alive */
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] socket [%s][%d] rfc5626 [double]pong received [CRLFCRLF]\n", sockinfo->remote_ip, sockinfo->remote_port));
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
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] socket [%s][%d] message has no content-length: <%s>\n", sockinfo->remote_ip, sockinfo->remote_port, buf));
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
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] socket [%s][%d] rfc5626 pong received [CRLF]\n", sockinfo->remote_ip, sockinfo->remote_port, buf));
    consumed += 2;
    buflen -= 2;
    buf += 2;
    sockinfo->ping_rfc5626 = 0;
    sockinfo->pong_supported = 1;
  }

  return consumed;
}

static int _tls_tl_recv(struct eXosip_t *excontext, struct _tls_stream *sockinfo) {
  int rlen, err;
  size_t consumed;

  if (!sockinfo->buf) {
    sockinfo->buf = (char *) osip_malloc(SIP_MESSAGE_MAX_LENGTH);

    if (sockinfo->buf == NULL)
      return OSIP_NOMEM;

    sockinfo->bufsize = SIP_MESSAGE_MAX_LENGTH;
    sockinfo->buflen = 0;
  }

  /* buffer is 100% full -> realloc with more size */
  if (sockinfo->bufsize - sockinfo->buflen <= 0) {
    sockinfo->buf = (char *) osip_realloc(sockinfo->buf, sockinfo->bufsize + 5000);

    if (sockinfo->buf == NULL)
      return OSIP_NOMEM;

    sockinfo->bufsize = sockinfo->bufsize + 5000;
  }

  /* buffer is 100% empty-> realloc with initial size */
  if (sockinfo->buflen == 0 && sockinfo->bufsize > SIP_MESSAGE_MAX_LENGTH) {
    osip_free(sockinfo->buf);
    sockinfo->buf = (char *) osip_malloc(SIP_MESSAGE_MAX_LENGTH);

    if (sockinfo->buf == NULL)
      return OSIP_NOMEM;

    sockinfo->bufsize = SIP_MESSAGE_MAX_LENGTH;
  }

  if (sockinfo->ssl_state != 3)
    return OSIP_SUCCESS;

  rlen = SSL_read(sockinfo->ssl_conn, sockinfo->buf + sockinfo->buflen, (int) (sockinfo->bufsize - sockinfo->buflen));

  if (rlen <= 0) {
    err = SSL_get_error(sockinfo->ssl_conn, rlen);

    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      _tls_print_ssl_error(err);
      /*
         The TLS/SSL connection has been closed.  If the protocol version
         is SSL 3.0 or TLS 1.0, this result code is returned only if a
         closure alert has occurred in the protocol, i.e. if the
         connection has been closed cleanly. Note that in this case
         SSL_ERROR_ZERO_RETURN does not necessarily indicate that the
         underlying transport has been closed. */
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] [recv] TLS closed\n"));

      _eXosip_mark_registration_expired(excontext, sockinfo->reg_call_id);
      _tls_tl_close_sockinfo(excontext, sockinfo);
    }
    return OSIP_UNDEFINED_ERROR;
  }

  err = OSIP_SUCCESS;

  if (SSL_pending(sockinfo->ssl_conn))
    err = -999;

  sockinfo->tcp_max_timeout = 0;
  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] [recv] socket [%s][%d] read %d bytes\n", sockinfo->remote_ip, sockinfo->remote_port, rlen));
  sockinfo->buflen += rlen;
  consumed = _tls_handle_messages(excontext, sockinfo);

  if (consumed != 0) {
    if (sockinfo->buflen > consumed) {
      memmove(sockinfo->buf, sockinfo->buf + consumed, sockinfo->buflen - consumed);
      sockinfo->buflen -= consumed;

    } else {
      sockinfo->buflen = 0;
    }
  }

  return err; /* if -999 is returned, internal buffer of SSL still contains some data */
}

static int _tls_read_tls_main_socket(struct eXosip_t *excontext) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;

  /* accept incoming connection */
  char src6host[NI_MAXHOST];
  int recvport = 0;
  struct sockaddr_storage sa;
  int sock;
  int i;

  socklen_t slen;
  int pos;

  SSL *ssl = NULL;
  BIO *sbio;

  if (reserved->ai_addr.ss_family == AF_INET)
    slen = sizeof(struct sockaddr_in);

  else
    slen = sizeof(struct sockaddr_in6);

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket <= 0)
      break;
  }

  if (pos == EXOSIP_MAX_SOCKETS) {
    /* delete an old one! */
    pos = 0;

    if (reserved->socket_tab[pos].socket > 0) {
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
      _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
    }

    memset(&reserved->socket_tab[pos], 0, sizeof(struct _tls_stream));
  }

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO3, NULL, "[eXosip] [TLS] creating TLS socket at index [%i]\n", pos));

  sock = (int) accept(reserved->tls_socket, (struct sockaddr *) &sa, (socklen_t *) &slen);

  if (sock < 0) {
#if defined(EBADF)
    int valopt = ex_errno;
#endif
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] error accepting TLS socket\n"));
#if defined(EBADF)

    if (valopt == EBADF) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] error accepting TLS socket [EBADF]\n"));
      memset(&reserved->ai_addr, 0, sizeof(struct sockaddr_storage));

      if (reserved->tls_socket > 0) {
        _eXosip_closesocket(reserved->tls_socket);

        for (i = 0; i < EXOSIP_MAX_SOCKETS; i++) {
          if (reserved->socket_tab[i].socket > 0 && reserved->socket_tab[i].is_server > 0) {
            _eXosip_mark_registration_expired(excontext, reserved->socket_tab[i].reg_call_id);
            _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[i]);
          }
        }
      }

      tls_tl_open(excontext);
    }

#endif

  } else {
    if (reserved->server_ctx == NULL) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] TLS connection rejected\n"));
      _eXosip_closesocket(sock);
      return -1;
    }

    if (!SSL_CTX_check_private_key(reserved->server_ctx)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL CTX private key check error\n"));
    }

    ssl = SSL_new(reserved->server_ctx);

    if (ssl == NULL) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] cannot create ssl connection context\n"));
      return -1;
    }

    if (!SSL_check_private_key(ssl)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL private key check error\n"));
    }

    sbio = BIO_new_socket(sock, BIO_NOCLOSE);

    if (sbio == NULL) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] BIO_new_socket error\n"));
    }

    SSL_set_bio(ssl, sbio, sbio); /* cannot fail */

    i = SSL_accept(ssl);

    if (i <= 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] SSL_accept error: %s\n", ERR_error_string(ERR_get_error(), NULL)));
      i = SSL_get_error(ssl, i);
      _tls_print_ssl_error(i);

      SSL_shutdown(ssl);
      _eXosip_closesocket(sock);
      SSL_free(ssl);
      return -1;
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] incoming TLS connection accepted\n"));

    reserved->socket_tab[pos].socket = sock;
    reserved->socket_tab[pos].is_server = 1;
    reserved->socket_tab[pos].ssl_conn = ssl;
    reserved->socket_tab[pos].ssl_state = 2;

    {
      int valopt = 1;

      setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &valopt, sizeof(valopt));
    }

    memset(src6host, 0, NI_MAXHOST);
    recvport = _eXosip_getport((struct sockaddr *) &sa);
    _eXosip_getnameinfo((struct sockaddr *) &sa, slen, src6host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

    _eXosip_transport_set_dscp(excontext, sa.ss_family, sock);

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] message received from [%s][%d]\n", src6host, recvport));
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
        _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        return -1;
      }
    }

#endif
  }

  return OSIP_SUCCESS;
}

#ifdef HAVE_SYS_EPOLL_H

static int tls_tl_epoll_read_message(struct eXosip_t *excontext, int nfds, struct epoll_event *ep_array) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int pos = 0;
  int n;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  for (n = 0; n < nfds; ++n) {
    if (ep_array[n].data.fd == reserved->tls_socket) {
      _tls_read_tls_main_socket(excontext);
      continue;
    }

    for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
      if (reserved->socket_tab[pos].socket > 0) {
        if (ep_array[n].data.fd == reserved->socket_tab[pos].socket) {
          if ((ep_array[n].events & EPOLLIN) && reserved->socket_tab[pos].ssl_state == 2 && reserved->socket_tab[pos].is_server > 0) {
            int r = SSL_do_handshake(reserved->socket_tab[pos].ssl_conn);
            int err = SSL_get_error(reserved->socket_tab[pos].ssl_conn, r);

            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
              continue;

            if (r <= 0) {
              _tls_print_ssl_error(err);
              _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
              _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
              continue;
            }

            SSL_set_mode(reserved->socket_tab[pos].ssl_conn, SSL_MODE_AUTO_RETRY);
            reserved->socket_tab[pos].ssl_state = 3;
            continue;
          }

          if ((ep_array[n].events & EPOLLIN) || ep_array[n].events & EPOLLOUT) {
            int err = -999;
            int max = 5;

            while (err == -999 && max > 0) {
              err = _tls_tl_recv(excontext, &reserved->socket_tab[pos]);
              max--;
            }
          }
        }
      }
    }
  }

  return OSIP_SUCCESS;
}

#endif

static int tls_tl_read_message(struct eXosip_t *excontext, fd_set *osip_fdset, fd_set *osip_wrset, fd_set *osip_exceptset) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int pos = 0;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (FD_ISSET(reserved->tls_socket, osip_fdset)) {
    _tls_read_tls_main_socket(excontext);
  }

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket > 0) {
      if (FD_ISSET(reserved->socket_tab[pos].socket, osip_exceptset)) {
        int res = _tcptls_tl_is_connected(excontext->poll_method, reserved->socket_tab[pos].socket);
        if (res < 0) {
          _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
          _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
          continue;
        } else {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] [tid=-1] socket [%s][%d] except descriptor without error\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port));
        }
      } else if (FD_ISSET(reserved->socket_tab[pos].socket, osip_wrset) && reserved->socket_tab[pos].ssl_state < 2) {
      } else if (FD_ISSET(reserved->socket_tab[pos].socket, osip_wrset) && reserved->socket_tab[pos].ssl_state == 2) {
        /* this should be dead code */
        int r = SSL_do_handshake(reserved->socket_tab[pos].ssl_conn);

        if (r <= 0) {
          r = SSL_get_error(reserved->socket_tab[pos].ssl_conn, r);
          _tls_print_ssl_error(r);

          _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
          _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
          continue;
        }

        SSL_set_mode(reserved->socket_tab[pos].ssl_conn, SSL_MODE_AUTO_RETRY);
        reserved->socket_tab[pos].ssl_state = 3;
      } else if (FD_ISSET(reserved->socket_tab[pos].socket, osip_wrset) && reserved->socket_tab[pos].sendbuflen > 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] [tid=-1] message sent [len=%d] to [%s][%d]\n%s\n", reserved->socket_tab[pos].sendbuflen, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].sendbuf));
        _tls_tl_send(excontext, reserved->socket_tab[pos].ssl_conn, (const char *) reserved->socket_tab[pos].sendbuf, (int) reserved->socket_tab[pos].sendbuflen);
        reserved->socket_tab[pos].sendbuflen = 0;
      }

      if (FD_ISSET(reserved->socket_tab[pos].socket, osip_fdset)) {
        int err = -999;
        int max = 5;

        while (err == -999 && max > 0) {
          err = _tls_tl_recv(excontext, &reserved->socket_tab[pos]);
          max--;
        }
      }
    }
  }

  return OSIP_SUCCESS;
}

static int _tls_tl_find_socket(struct eXosip_t *excontext, char *host, int port) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int pos;

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket != 0) {
      if (0 == osip_strcasecmp(reserved->socket_tab[pos].remote_ip, host) && port == reserved->socket_tab[pos].remote_port)
        return pos;
    }
  }

  return -1;
}

static int _tls_tl_new_socket(struct eXosip_t *excontext, char *host, int port, int retry, const char *sni_servernameindication) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int pos;
  int res;
  struct addrinfo *addrinfo = NULL;
  struct addrinfo *curinfo;
  int sock = -1;
  int ssl_state = 0;
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
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] [new] reserved->socket_tab is full - cannot create new socket\n"));
    return -1;
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

    i = _tls_tl_find_socket(excontext, src6host, port);

    if (i >= 0) {
      _eXosip_freeaddrinfo(addrinfo);
      return i;
    }
  }

  if (retry > 0)
    return -1;

  for (curinfo = addrinfo; curinfo; curinfo = curinfo->ai_next) {
    int type;

    if (curinfo->ai_protocol && curinfo->ai_protocol != IPPROTO_TCP) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] skipping protocol [%d]\n", curinfo->ai_protocol));
      continue;
    }

    res = _eXosip_getnameinfo((struct sockaddr *) curinfo->ai_addr, (socklen_t) curinfo->ai_addrlen, src6host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

    if (res == 0) {
      int i = _tls_tl_find_socket(excontext, src6host, port);

      if (i >= 0) {
        _eXosip_freeaddrinfo(addrinfo);
        return i;
      }

      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] [new] new binding with [%s][%d]\n", src6host, port));
    }

    type = curinfo->ai_socktype;
#if defined(SOCK_CLOEXEC)
    type = SOCK_CLOEXEC | type;
#endif
    sock = (int) socket(curinfo->ai_family, type, curinfo->ai_protocol);

    if (sock < 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] cannot create socket %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
      continue;
    }

    if (curinfo->ai_family == AF_INET6) {
#ifdef IPV6_V6ONLY

      if (setsockopt_ipv6only(sock)) {
        _eXosip_closesocket(sock);
        sock = -1;
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] cannot set socket option %s\n", _ex_strerror(ex_errno, eb, ERRBSIZ)));
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
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] [new] cannot bind socket [%s] family:%d %s\n", excontext->eXtl_transport.proto_ifs, ai_addr.ss_family, _ex_strerror(ex_errno, eb, ERRBSIZ)));
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
              OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] [new] cannot bind socket [%s] family:%d (port=%i) %s\n", excontext->eXtl_transport.proto_ifs, ai_addr.ss_family, excontext->oc_local_port_current,
                                    _ex_strerror(ex_errno, eb, ERRBSIZ)));
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
              OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] skipping protocol [%d]\n", oc_curinfo->ai_protocol));
              continue;
            }

            break;
          }

          if (oc_curinfo == NULL) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] not able to find any address to bind\n"));
            _eXosip_freeaddrinfo(oc_addrinfo);
            break;
          }

          res = bind(sock, (const struct sockaddr *) oc_curinfo->ai_addr, (socklen_t) oc_curinfo->ai_addrlen);

          if (res < 0) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] [new] cannot bind socket [%s] family:%d (port=%i) %s\n", excontext->oc_local_address, curinfo->ai_addr->sa_family, excontext->oc_local_port_current,
                                  _ex_strerror(ex_errno, eb, ERRBSIZ)));
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

#if defined(HAVE_WINSOCK2_H)
    {
      unsigned long nonBlock = 1;
      int val;

      ioctlsocket(sock, FIONBIO, &nonBlock);

      val = 1;

      if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *) &val, sizeof(val)) == -1) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] cannot set socket SO_KEEPALIVE\n"));
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
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] [new] cannot set keepalive interval\n"));
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
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] cannot get socket flag\n"));
        continue;
      }

      val |= O_NONBLOCK;

      if (fcntl(sock, F_SETFL, val) < 0) {
        _eXosip_closesocket(sock);
        sock = -1;
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] cannot set socket flag\n"));
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

#if TCP_NODELAY
      val = 1;

      if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &val, sizeof(int)) != 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] cannot set socket flag (TCP_NODELAY)\n"));
      }

#endif
    }
#endif
#if TCP_USER_TIMEOUT
    {
      int val = 9000;
      if (setsockopt(sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &val, sizeof(val)) != 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] cannot set socket flag (TCP_USER_TIMEOUT)\n"));
      }
    }
#endif

    _eXosip_transport_set_dscp(excontext, curinfo->ai_family, sock);

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] socket [%s] [sock=%d] family:%d\n", host, sock, curinfo->ai_family));
    res = connect(sock, curinfo->ai_addr, (socklen_t) curinfo->ai_addrlen);

    if (res < 0) {
      int valopt = ex_errno;

#if defined(HAVE_WINSOCK2_H)

      if (valopt != WSAEWOULDBLOCK) {
#else

      if (valopt != EINPROGRESS) {
#endif
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] cannot connect socket [%s] family:%d %s\n", host, curinfo->ai_family, _ex_strerror(valopt, eb, ERRBSIZ)));

        _eXosip_closesocket(sock);
        sock = -1;
        continue;

      } else {
        res = _tcptls_tl_is_connected(excontext->poll_method, sock);

        if (res > 0) {
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] socket [%s] [sock=%d] [pos=%d] family:%d, in progress\n", host, sock, pos, curinfo->ai_family));
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
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] CFReadStreamOpen Succeeded\n"));
          }

          CFWriteStreamOpen(reserved->socket_tab[pos].writeStream);
#endif
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] socket [%s] [sock=%d] [pos=%d] family:%d, connected\n", host, sock, pos, curinfo->ai_family));
          selected_ai_addrlen = 0;
          memcpy(&selected_ai_addr, curinfo->ai_addr, sizeof(struct sockaddr));
          ssl_state = 1;
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
    reserved->socket_tab[pos].ssl_conn = NULL;
    reserved->socket_tab[pos].ssl_state = ssl_state;
    reserved->socket_tab[pos].ssl_ctx = NULL;

    /* sni should be set to the domain portion of the "Application Unique String (AUS)" */
    /* Usually, this should end up being the domain of the "From" header (but if a Route is set in exosip, it will be the domain from the Route) */
    /* this code prevents Man-In-The-Middle Attack where the attacker is modifying the NAPTR result to route the request somewhere else */
    if (sni_servernameindication != NULL)
      osip_strncpy(reserved->socket_tab[pos].sni_servernameindication, sni_servernameindication, sizeof(reserved->socket_tab[pos].sni_servernameindication) - 1);

    else
      osip_strncpy(reserved->socket_tab[pos].sni_servernameindication, host, sizeof(reserved->socket_tab[pos].sni_servernameindication) - 1);

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

        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [new] outgoing socket created on port [%i]\n", reserved->socket_tab[pos].ephemeral_port));
      }
    }

    reserved->socket_tab[pos].tcp_inprogress_max_timeout = osip_getsystemtime(NULL) + 32;

#ifdef HAVE_SYS_EPOLL_H

    if (excontext->poll_method == EXOSIP_USE_EPOLL_LT) {
      struct epoll_event ev;

      memset(&ev, 0, sizeof(struct epoll_event));

      if (reserved->socket_tab[pos].ssl_state == 1)
        ev.events = EPOLLIN;

      else
        ev.events = EPOLLIN | EPOLLOUT;

      ev.data.fd = sock;
      res = epoll_ctl(excontext->epfd, EPOLL_CTL_ADD, sock, &ev);

      if (res < 0) {
        _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        return -1;
      }
    }

#endif

    return pos;
  }

  return -1;
}

static int _tls_tl_send(struct eXosip_t *excontext, SSL *ssl, const char *message, int length) {
  int i = 0;

  while (length > 0) {
    i = SSL_write(ssl, (const void *) message, (int) length);

    if (i <= 0) {
      i = SSL_get_error(ssl, i);

      if (i == SSL_ERROR_WANT_READ || i == SSL_ERROR_WANT_WRITE)
        continue;

      _tls_print_ssl_error(i);

      return -1;
    }

    length = length - i;
    message += i;
  }

  return OSIP_SUCCESS;
}

static int _tls_tl_update_contact(struct eXosip_t *excontext, osip_message_t *req, char *natted_ip, int natted_port) {
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

static int _tls_tl_build_message(struct eXosip_t *excontext, osip_message_t *sip, int pos, char *host, char **message, size_t *length) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int i;

  _eXosip_request_viamanager(excontext, sip, reserved->socket_tab[pos].ai_addr.sa_family, IPPROTO_TCP, NULL, reserved->socket_tab[pos].ephemeral_port, reserved->socket_tab[pos].socket, host);

  if (excontext->use_ephemeral_port == 1)
    _eXosip_message_contactmanager(excontext, sip, reserved->socket_tab[pos].ai_addr.sa_family, IPPROTO_TCP, NULL, reserved->socket_tab[pos].ephemeral_port, reserved->socket_tab[pos].socket, host);

  else
    _eXosip_message_contactmanager(excontext, sip, reserved->socket_tab[pos].ai_addr.sa_family, IPPROTO_TCP, NULL, excontext->eXtl_transport.proto_local_port, reserved->socket_tab[pos].socket, host);

  if (excontext->tls_firewall_ip[0] != '\0' || excontext->auto_masquerade_contact > 0)
    _tls_tl_update_contact(excontext, sip, reserved->socket_tab[pos].natted_ip, reserved->socket_tab[pos].natted_port);

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

static int tls_tl_send_message(struct eXosip_t *excontext, osip_transaction_t *tr, osip_message_t *sip, char *host, int port, int out_socket) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  size_t length = 0;
  char *message;
  int i;

  int pos;
  osip_naptr_t *naptr_record = NULL;

  SSL *ssl = NULL;
  int tid = -1;

  if (tr != NULL)
    tid = tr->transactionid;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] [tid=%i] wrong state: create transport layer first\n", tid));
    return OSIP_WRONG_STATE;
  }

  if (host == NULL) {
    host = sip->req_uri->host;

    if (sip->req_uri->port != NULL)
      port = osip_atoi(sip->req_uri->port);

    else
      port = 5061;
  }

  if (port == 5060)
    port = 5061;

  i = _tl_resolv_naptr_destination(excontext, tr, sip, &host, &port, &naptr_record);
  if (i == OSIP_SUCCESS + 1)
    return i;
  if (i < OSIP_SUCCESS)
    return i;

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].invalid > 0) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] [send] socket info:[%s][%d] [sock=%d] [pos=%d] manual reset\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                            reserved->socket_tab[pos].socket, pos));
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
      _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
      continue;
    }
  }

  if (out_socket > 0) {
    for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
      if (reserved->socket_tab[pos].socket != 0) {
        if (reserved->socket_tab[pos].socket == out_socket) {
          out_socket = reserved->socket_tab[pos].socket;
          ssl = reserved->socket_tab[pos].ssl_conn;
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] [tid=%i] reusing REQUEST connection to [%s][%d]\n", tid, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port));
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
      pos2 = _tls_tl_find_socket(excontext, host, port);

      if (pos2 >= 0) {
        out_socket = reserved->socket_tab[pos2].socket;
        pos = pos2;
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] [tid=%i] reusing connection --with exact port-- to [%s][%d]\n", tid, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port));
        if (tr != NULL)
          osip_transaction_set_out_socket(tr, out_socket);
      }
    }
  }

  /* Step 1: find existing socket to send message */
  if (out_socket <= 0) {
    pos = _tls_tl_find_socket(excontext, host, port);

    /* Step 2: create new socket with host:port */
    if (pos < 0) {
      const char *sni = NULL;

      if (naptr_record != NULL) {
        sni = naptr_record->domain;
      }
      if (sni == NULL) {
        /* when connection is failing, there are some messages that are routed with IP instead of the DNS name */
        /* for example: ACK out of transaction, message in-dialog (BYE, re-INVITE...), or answers. */
        /* in order to establish a TLS connection, we REQUIRE the SNI verification, and thus, require the domain name */
        /* unfortunatly, there is still some issue with selecting the "domain name" or the "sip server domain name" (before/after NAPTR) */

        /* first lookup for a DNS name for our IP target in the cache */
        for (i = 0; i < MAX_EXOSIP_DNS_ENTRY; i++) {
          if (excontext->dns_entries[i].host[0] != '\0' && 0 == osip_strcasecmp(excontext->dns_entries[i].ip, host)) {
            /* update entry */
            sni = excontext->dns_entries[i].host;
            break;
          }
        }

        /* then, lookup for a "domain" in an NAPTR cache result */
        if (sni != NULL) {
          const char *domain = _eXosip_dnsutils_find_sni(excontext, sni);
          if (domain != NULL)
            sni = domain;
        }
      }

      if (tr == NULL) {
        pos = _tls_tl_new_socket(excontext, host, port, 0, sni);
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] [tid=%i] message out of transaction: trying to send to [%s][%d]\n", tid, host, port));

        if (pos < 0) {
          return -1;
        }

      } else {
        pos = _tls_tl_new_socket(excontext, host, port, 0, sni);

        if (pos < 0) {
          if (MSG_IS_REGISTER(sip) || MSG_IS_OPTIONS(sip)) {
            /* reg_call_id is not set! */
            _eXosip_mark_registration_expired(excontext, sip->call_id->number);
          }

          if (tr != NULL)
            osip_transaction_set_out_socket(tr, 0);
          return -1;
        }
      }
    }

    if (pos >= 0) {
      out_socket = reserved->socket_tab[pos].socket;
      ssl = reserved->socket_tab[pos].ssl_conn;
      if (tr != NULL)
        osip_transaction_set_out_socket(tr, out_socket);
    }
  }

  if (out_socket <= 0) {
    if (naptr_record != NULL && MSG_IS_REGISTER(sip)) {
      /* reg_call_id is not set! */
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

  if (reserved->socket_tab[pos].ssl_state < 3) {
    time_t now;

    if (tr != NULL) {
      now = osip_getsystemtime(NULL);

      if (tr != NULL && now - tr->birth_time > 10) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [tid=%i] socket [%s] [sock=%d] [pos=%d] timeout\n", tid, host, out_socket, pos));
        _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
        if (naptr_record != NULL && (MSG_IS_REGISTER(sip) || MSG_IS_OPTIONS(sip))) {
          if (pos >= 0)
            _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        }

        if (tr != NULL)
          osip_transaction_set_out_socket(tr, 0);
        return -1;
      }
    }
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [tid=%i] socket [%s] [sock=%d] [pos=%d] not yet ready\n", tid, host, out_socket, pos));

    if (tr == NULL) {
      /* a connection was probably broken: we tried to send a message without transaction, but it failed */
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] [tid=%i] a connection is missing for to [%s][%d]\n", tid, host, port));
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);

      i = _tls_tl_build_message(excontext, sip, pos, host, &message, &length);

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
  }

  ssl = reserved->socket_tab[pos].ssl_conn;

  if (ssl == NULL) {
    if (tr != NULL)
      osip_transaction_set_out_socket(tr, 0);
    return -1;
  }

#ifdef MULTITASKING_ENABLED

  if (reserved->socket_tab[pos].readStream == NULL) {
    reserved->socket_tab[pos].readStream = NULL;
    reserved->socket_tab[pos].writeStream = NULL;
    CFStreamCreatePairWithSocket(kCFAllocatorDefault, reserved->socket_tab[pos].socket, &reserved->socket_tab[pos].readStream, &reserved->socket_tab[pos].writeStream);

    if (reserved->socket_tab[pos].readStream != NULL)
      CFReadStreamSetProperty(reserved->socket_tab[pos].readStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);

    if (reserved->socket_tab[pos].writeStream != NULL)
      CFWriteStreamSetProperty(reserved->socket_tab[pos].writeStream, kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP);

    if (CFReadStreamOpen(reserved->socket_tab[pos].readStream)) {
      OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [tid=%i] CFReadStreamOpen Succeeded\n", tid));
    }

    CFWriteStreamOpen(reserved->socket_tab[pos].writeStream);
  }

#endif

  i = _tls_tl_build_message(excontext, sip, pos, host, &message, &length);

  if (i != 0 || length <= 0) {
    if (tr != NULL)
      osip_transaction_set_out_socket(tr, 0);
    return -1;
  }

  OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO1, NULL, "[eXosip] [TLS] [tid=%i] message sent [len=%d] to [%s][%d]\n%s\n", tid, length, host, port, message));

  if (pos >= 0 && excontext->enable_dns_cache == 1 && osip_strcasecmp(host, reserved->socket_tab[pos].remote_ip) != 0 && MSG_IS_REQUEST(sip)) {
    if (MSG_IS_REGISTER(sip)) {
      struct eXosip_dns_cache entry;

      memset(&entry, 0, sizeof(struct eXosip_dns_cache));
      snprintf(entry.host, sizeof(entry.host), "%s", host);
      snprintf(entry.ip, sizeof(entry.ip), "%s", reserved->socket_tab[pos].remote_ip);
      eXosip_set_option(excontext, EXOSIP_OPT_ADD_DNS_CACHE, (void *) &entry);
    }
  }

  i = _tls_tl_send(excontext, ssl, (const char *) message, (int) length);

  if (i < 0) {
    if (pos >= 0) {
      _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
      _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
    }
    if (tr != NULL)
      osip_transaction_set_out_socket(tr, 0);
  }

  if (i == 0 && tr != NULL && MSG_IS_REGISTER(sip) && pos >= 0) {
    /* start a timeout to destroy connection if no answer */
    reserved->socket_tab[pos].tcp_max_timeout = osip_getsystemtime(NULL) + 32;
  }

  osip_free(message);
  return OSIP_SUCCESS;
}

static int tls_tl_keepalive(struct eXosip_t *excontext) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  char buf[5] = "\r\n\r\n";
  int pos;
  int i;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->tls_socket <= 0)
    return OSIP_UNDEFINED_ERROR;

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (excontext->ka_interval > 0) {
      if (reserved->socket_tab[pos].socket > 0 && reserved->socket_tab[pos].ssl_state > 2) {
        // SSL_set_mode(reserved->socket_tab[pos].ssl_conn, SSL_MODE_AUTO_RETRY);

        while (1) {
          i = SSL_write(reserved->socket_tab[pos].ssl_conn, (const void *) buf, 4);

          if (i <= 0) {
            i = SSL_get_error(reserved->socket_tab[pos].ssl_conn, i);

            if (i == SSL_ERROR_WANT_READ || i == SSL_ERROR_WANT_WRITE)
              continue;

            _tls_print_ssl_error(i);
          }

          reserved->socket_tab[pos].ping_rfc5626 = osip_getsystemtime(NULL) + 9;
          OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_WARNING, NULL, "[eXosip] [TLS] [keepalive] [ret=%i] socket [%s] [sock=%d] [pos=%d]\n", i, reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].socket, pos));
          break;
        }
      }
    }
  }

  return OSIP_SUCCESS;
}

static int tls_tl_set_socket(struct eXosip_t *excontext, int socket) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  reserved->tls_socket = socket;

  return OSIP_SUCCESS;
}

static int tls_tl_masquerade_contact(struct eXosip_t *excontext, const char *public_address, int port) {
  if (public_address == NULL || public_address[0] == '\0') {
    memset(excontext->tls_firewall_ip, '\0', sizeof(excontext->tls_firewall_ip));
    memset(excontext->tls_firewall_port, '\0', sizeof(excontext->tls_firewall_port));
    return OSIP_SUCCESS;
  }

  snprintf(excontext->tls_firewall_ip, sizeof(excontext->tls_firewall_ip), "%s", public_address);

  if (port > 0) {
    snprintf(excontext->tls_firewall_port, sizeof(excontext->tls_firewall_port), "%i", port);
  }

  return OSIP_SUCCESS;
}

static int tls_tl_get_masquerade_contact(struct eXosip_t *excontext, char *ip, int ip_size, char *port, int port_size) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;

  memset(ip, 0, ip_size);
  memset(port, 0, port_size);

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (excontext->tls_firewall_ip[0] != '\0')
    snprintf(ip, ip_size, "%s", excontext->tls_firewall_ip);

  if (excontext->tls_firewall_port[0] != '\0')
    snprintf(port, port_size, "%s", excontext->tls_firewall_port);

  return OSIP_SUCCESS;
}

static int tls_tl_update_contact(struct eXosip_t *excontext, osip_message_t *req) {
  req->application_data = (void *) 0x1; /* request for masquerading */
  return OSIP_SUCCESS;
}

static int tls_tl_check_all_connection(struct eXosip_t *excontext) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int pos;
  int i;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->tls_socket <= 0)
    return OSIP_UNDEFINED_ERROR;

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket > 0) {
      i = _tcptls_tl_is_connected(excontext->poll_method, reserved->socket_tab[pos].socket);

      if (i > 0) {
        if (reserved->socket_tab[pos].socket > 0 && reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) {
          time_t now = osip_getsystemtime(NULL);

          if (now > reserved->socket_tab[pos].tcp_inprogress_max_timeout) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [checkall] socket is in progress since 32 seconds / close socket\n"));
            reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0;
            _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
            _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
            continue;
          }
        }

        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [checkall] socket info:[%s][%d] [sock=%d] [pos=%d] in progress\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].socket, pos));
        continue;

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

        reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0; /* reset value */

        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [checkall] socket info:[%s][%d] [sock=%d] [pos=%d] connected\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].socket, pos));

        if (reserved->socket_tab[pos].socket > 0 && reserved->socket_tab[pos].ssl_state > 2 && reserved->socket_tab[pos].tcp_max_timeout > 0) {
          time_t now = osip_getsystemtime(NULL);

          if (now > reserved->socket_tab[pos].tcp_max_timeout) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [checkall] we expected a reply on established sockets / close socket\n"));
            reserved->socket_tab[pos].tcp_max_timeout = 0;
            _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
            _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
            continue;
          }
        }

        if (reserved->socket_tab[pos].ssl_state == 0 || reserved->socket_tab[pos].ssl_state == 1) { /* TCP connected but not TLS connected */
          reserved->socket_tab[pos].ssl_state = 1;
          i = _tls_tl_ssl_connect_socket(excontext, &reserved->socket_tab[pos]);

          if (i < 0) {
            _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
            _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
            continue;

          } else if (i > 0) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [checkall] socket info:[%s][%d] [sock=%d] [pos=%d] connected (ssl in progress)\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                                  reserved->socket_tab[pos].socket, pos));
            continue;
          }
        }

        if (reserved->socket_tab[pos].ping_rfc5626 > 0 && reserved->socket_tab[pos].pong_supported > 0) {
          time_t now = osip_getsystemtime(NULL);

          if (now > reserved->socket_tab[pos].ping_rfc5626) {
            OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TCP] [checkall] no pong[CRLF] for ping[CRLFCRLF]\n"));
            reserved->socket_tab[pos].tcp_max_timeout = 0;
            _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
            _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
            continue;
          }
        }

        continue;

      } else {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] [checkall] socket info:[%s][%d] [sock=%d] [pos=%d] error\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].socket, pos));
        _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
        _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        continue;
      }
    }
  }

  return OSIP_SUCCESS;
}

static int tls_tl_check_connection(struct eXosip_t *excontext, int socket) {
  struct eXtltls *reserved = (struct eXtltls *) excontext->eXtltls_reserved;
  int pos;
  int i;

  if (reserved == NULL) {
    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] wrong state: create transport layer first\n"));
    return OSIP_WRONG_STATE;
  }

  if (reserved->tls_socket <= 0)
    return OSIP_UNDEFINED_ERROR;

  if (socket == -1) {
    return tls_tl_check_all_connection(excontext);
  }

  for (pos = 0; pos < EXOSIP_MAX_SOCKETS; pos++) {
    if (reserved->socket_tab[pos].socket == socket)
      break;
  }

  if (pos == EXOSIP_MAX_SOCKETS)
    return OSIP_NOTFOUND;

  i = _tcptls_tl_is_connected(excontext->poll_method, reserved->socket_tab[pos].socket);

  if (i > 0) {
    if (reserved->socket_tab[pos].socket > 0 && reserved->socket_tab[pos].tcp_inprogress_max_timeout > 0) {
      time_t now = osip_getsystemtime(NULL);

      if (now > reserved->socket_tab[pos].tcp_inprogress_max_timeout) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [check] socket is in progress since 32 seconds / close socket\n"));
        reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0;
        _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
        _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        return OSIP_SUCCESS;
      }
    }

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [check] socket info:[%s][%d] [sock=%d] [pos=%d] in progress\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
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

    reserved->socket_tab[pos].tcp_inprogress_max_timeout = 0; /* reset value */

    OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [check] socket info:[%s][%d] [sock=%d] [pos=%d] connected\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                          reserved->socket_tab[pos].socket, pos));

    if (reserved->socket_tab[pos].socket > 0 && reserved->socket_tab[pos].ssl_state > 2 && reserved->socket_tab[pos].tcp_max_timeout > 0) {
      time_t now = osip_getsystemtime(NULL);

      if (now > reserved->socket_tab[pos].tcp_max_timeout) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [check] we expected a reply on established sockets / close socket\n"));
        reserved->socket_tab[pos].tcp_max_timeout = 0;
        _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
        _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        return OSIP_SUCCESS;
      }
    }

    if (reserved->socket_tab[pos].ssl_state == 0 || reserved->socket_tab[pos].ssl_state == 1) { /* TCP connected but not TLS connected */
      reserved->socket_tab[pos].ssl_state = 1;
      i = _tls_tl_ssl_connect_socket(excontext, &reserved->socket_tab[pos]);

      if (i < 0) {
        _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
        _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
        return -1;

      } else if (i > 0) {
        OSIP_TRACE(osip_trace(__FILE__, __LINE__, OSIP_INFO2, NULL, "[eXosip] [TLS] [check] socket info:[%s][%d] [sock=%d] [pos=%d] connected (ssl in progress)\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port,
                              reserved->socket_tab[pos].socket, pos));
        return 1;
      }
    }

    return OSIP_SUCCESS;

  } else {
    OSIP_TRACE(
        osip_trace(__FILE__, __LINE__, OSIP_ERROR, NULL, "[eXosip] [TLS] [check] socket info:[%s][%d] [sock=%d] [pos=%d] error\n", reserved->socket_tab[pos].remote_ip, reserved->socket_tab[pos].remote_port, reserved->socket_tab[pos].socket, pos));
    _eXosip_mark_registration_expired(excontext, reserved->socket_tab[pos].reg_call_id);
    _tls_tl_close_sockinfo(excontext, &reserved->socket_tab[pos]);
    return OSIP_SUCCESS;
  }

  return OSIP_SUCCESS;
}

static struct eXtl_protocol eXtl_tls = {1,
                                        5061,
                                        "TLS",
                                        "0.0.0.0",
                                        IPPROTO_TCP,
                                        AF_INET,
                                        0,
                                        0,
                                        0,

                                        &tls_tl_init,
                                        &tls_tl_free,
                                        &tls_tl_open,
                                        &tls_tl_set_fdset,
                                        &tls_tl_read_message,
#ifdef HAVE_SYS_EPOLL_H
                                        &tls_tl_epoll_read_message,
#endif
                                        &tls_tl_send_message,
                                        &tls_tl_keepalive,
                                        &tls_tl_set_socket,
                                        &tls_tl_masquerade_contact,
                                        &tls_tl_get_masquerade_contact,
                                        &tls_tl_update_contact,
                                        &tls_tl_reset,
                                        &tls_tl_check_connection};

void eXosip_transport_tls_init(struct eXosip_t *excontext) {
  memcpy(&excontext->eXtl_transport, &eXtl_tls, sizeof(struct eXtl_protocol));
}

#else

eXosip_tls_ctx_error eXosip_tls_verify_certificate(struct eXosip_t* excontext, int _tls_verify_client_certificate) {
  return -1; /* NOT IMPLEMENTED */
}

eXosip_tls_ctx_error eXosip_set_tls_ctx(struct eXosip_t* excontext, eXosip_tls_ctx_t* ctx) {
  return -1; /* NOT IMPLEMENTED */
}

#endif

/**
  Various explanation on using openssl with eXosip2. (Written on June 26, 2018)

  First, you should understand that it is unlikely that you need to configure
  the "server" side of eXosip. eXosip2 is a User-Agent and will receive in 99%
  of use-case incoming message on "client initiated connection". It should even
  be in 100% of use-case. Thus, I advise you to compile eXosip2 without
  #define ENABLE_MAIN_SOCKET. This will prevent people connecting to your User-Agent
  via unsecured TLS connection. I also don't maintain this server side socket code
  security, so if you want to use it, you should really make sure you do things
  correctly. (may be with code modifications?)

  CAUTIOUS: Please understand that if you use an old version of openssl, we will get unsecure
  cipher, vulnerabilities, etc...
  Configuration of client side sockets:

1/ default configuration.
   By default, eXosip2 will load certificates from WINDOWS STORE on WINDOWS ONLY.
   By default, eXosip2 will load certificates from MACOSX STORE on MACOSX ONLY.
   By default, eXosip2 won't verify certificates

2/ on WINDOWS and MACOSX, to enable certificate verification:
   int optval = 1;
   eXosip_set_option (exosip_context, EXOSIP_OPT_SET_TLS_VERIFY_CERTIFICATE, &optval);

3/ on OTHER platforms, you need to add either ONE or a full list of ROOT CERTIFICATES
   and configure to require certificate verification:

   Google is providing a file containing a list of known trusted root certificates. This
   is the easiest way you can retreive an up-to-date file.
   https://pki.google.com/roots.pem
   SIDENOTE: you need to download this file REGULARLY. Because some of the root certificates may
   be revoked.

   eXosip_tls_ctx_t _tls_description;
   memset(&_tls_description, 0, sizeof(eXosip_tls_ctx_t));
   snprintf(_tls_description.root_ca_cert, sizeof(_tls_description.root_ca_cert), "%s", "roots.pem");
   eXosip_set_option(exosip_context, EXOSIP_OPT_SET_TLS_CERTIFICATES_INFO, (void*)&_tls_description);

   int optval = 1;
   eXosip_set_option (exosip_context, EXOSIP_OPT_SET_TLS_VERIFY_CERTIFICATE, &optval);

4/ If your service(server) request a client certificate from you, you will need to configure one
   by configuring your certificate, private key and password.

   eXosip_tls_ctx_t _tls_description;
   memset(&_tls_description, 0, sizeof(eXosip_tls_ctx_t));
   snprintf(_tls_description.root_ca_cert, sizeof(_tls_description.root_ca_cert), "%s", "roots.pem");

   snprintf(_tls_description.client.priv_key_pw, sizeof(_tls_description.client.priv_key_pw), "%s", "hello");
   snprintf(_tls_description.client.priv_key, sizeof(_tls_description.client.priv_key), "%s", "selfsigned-key.pem");
   snprintf(_tls_description.client.cert, sizeof(_tls_description.client.cert), "%s", "selfsigned-cert.pem");

   eXosip_set_option(exosip_context, EXOSIP_OPT_SET_TLS_CERTIFICATES_INFO, (void*)&_tls_description);

5/ Today, I have removed the ability to use a client certificate from windows store: the feature was limited
   to RSA with SHA1 which is never negociated if you wish to have correct security. This makes the feature obsolete
   and mostly not working. So... just removed. EXOSIP_OPT_SET_TLS_CLIENT_CERTIFICATE_NAME
   and EXOSIP_OPT_SET_TLS_SERVER_CERTIFICATE_NAME have been kept, but returns -1 only.

6/ A recent feature has been introduced: Certificate pinning.

   In order to get your public key file in DER format, which is required for eXosip2 code, you
   can use the following command line to retreive the publickey from your certificate and encode
   it into base64:

   $> openssl x509 -in your-base64-certificate.pem -pubkey -noout | openssl enc -base64 -d > publickey.der

   In order to activate the check, you need to configure the "public_key_pinned" parameter:

   eXosip_tls_ctx_t _tls_description;
   memset(&_tls_description, 0, sizeof(eXosip_tls_ctx_t));
   snprintf(_tls_description.root_ca_cert, sizeof(_tls_description.root_ca_cert), "%s", "roots.pem");

   snprintf(_tls_description.client.priv_key_pw, sizeof(_tls_description.client.priv_key_pw), "%s", "hello");
   snprintf(_tls_description.client.priv_key, sizeof(_tls_description.client.priv_key), "%s", "selfsigned-key.pem");
   snprintf(_tls_description.client.cert, sizeof(_tls_description.client.cert), "%s", "selfsigned-cert.pem");

   snprintf(_tls_description.client.cert, sizeof(_tls_description.client.public_key_pinned), "%s", "pub_key.der");

   eXosip_set_option(exosip_context, EXOSIP_OPT_SET_TLS_CERTIFICATES_INFO, (void*)&_tls_description);

7/ Depending on the openssl version you use, you will NOT have the same behavior and features.
   I advise you to use the LATEST openssl version. This is for security purpose (openssl vulnerabilities)
   as well as to use the latest secured cipher list.

   There are other features only enabled or disabled with recent versions of openssl. Among them:
   * SNI server verification: v1.0.2 -> OPENSSL_VERSION_NUMBER >= 0x10002000L
   * RSA is removed since v1.1.0 OPENSSL_VERSION_NUMBER < 0x10100000L
   * ECDHE based cipher suites faster than DHE since 1.0.0 OPENSSL_VERSION_NUMBER > 0x10000000L
   * ...

   If your app accept old/deprecated/unsecure ciphers, please: update your openssl version. If you
   have no choice, you can update the internal code to specify, or remove ciphers. The default in
   eXosip is always the "HIGH:-COMPLEMENTOFDEFAULT" which is expected to be the most secure configuration
   known by openssl upon releasing the openssl version.

     SSL_CTX_set_cipher_list (ctx, "HIGH:-COMPLEMENTOFDEFAULT")

  SIDEINFO for testing purpose: If you wish to test client certifiate with
  kamailio, here is a possible configuration on a specific port number. The
  ca_list contains the selfsigned certificate that is configured on client
  side in eXosip2. (server-key and server-certificate are the server side info)

  [server:91.121.30.149:29091]
  method = TLSv1+
  verify_certificate = no
  require_certificate = yes
  private_key = /etc/kamailio/server-key.key
  certificate = /etc/kamailio/server-certificate.pem
  ca_list = /etc/kamailio/client-selfsigned-cert-aymeric.pem
  cipher_list = HIGH:-COMPLEMENTOFDEFAULT

  */
