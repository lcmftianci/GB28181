#include "rtpconfig.h"

#ifdef RTP_SOCKETTYPE_WINSOCK
	#include <winsock2.h>	
	#include <ws2tcpip.h>
#ifndef _WIN32_WCE
	#include <sys/types.h>
#endif // _WIN32_WCE
#endif // RTP_SOCKETTYPE_WINSOCK

#include <stdint.h>
#include <sys/types.h>
