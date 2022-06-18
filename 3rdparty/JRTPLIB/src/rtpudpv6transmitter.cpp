/*

  This file is a part of JRTPLIB
  Copyright (c) 1999-2017 Jori Liesenborgs

  Contact: jori.liesenborgs@gmail.com

  This library was developed at the Expertise Centre for Digital Media
  (http://www.edm.uhasselt.be), a research center of the Hasselt University
  (http://www.uhasselt.be). The library is based upon work done for 
  my thesis at the School for Knowledge Technology (Belgium/The Netherlands).

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the "Software"),
  to deal in the Software without restriction, including without limitation
  the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom the
  Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
  IN THE SOFTWARE.

*/

// This is for getaddrinfo when using mingw
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include "rtpudpv6transmitter.h"

#ifdef RTP_SUPPORT_IPV6

#include "rtprawpacket.h"
#include "rtpipv6address.h"
#include "rtptimeutilities.h"
#include "rtpdefines.h"
#include "rtpsocketutilinternal.h"
#include "rtpinternalutils.h"
#include "rtpselect.h"
#include <stdio.h>

#include "rtpdebug.h"

#define RTPUDPV6TRANS_MAXPACKSIZE							65535
#define RTPUDPV6TRANS_IFREQBUFSIZE							8192

#define RTPUDPV6TRANS_IS_MCASTADDR(x)							(x.s6_addr[0] == 0xFF)

#define RTPUDPV6TRANS_MCASTMEMBERSHIP(socket,type,mcastip,status)	{\
										struct ipv6_mreq mreq;\
										\
										mreq.ipv6mr_multiaddr = mcastip;\
										mreq.ipv6mr_interface = mcastifidx;\
										status = setsockopt(socket,IPPROTO_IPV6,type,(const char *)&mreq,sizeof(struct ipv6_mreq));\
									}
#ifdef RTP_SUPPORT_THREAD
	#define MAINMUTEX_LOCK 		{ if (threadsafe) mainmutex.Lock(); }
	#define MAINMUTEX_UNLOCK	{ if (threadsafe) mainmutex.Unlock(); }
	#define WAITMUTEX_LOCK		{ if (threadsafe) waitmutex.Lock(); }
	#define WAITMUTEX_UNLOCK	{ if (threadsafe) waitmutex.Unlock(); }
#else
	#define MAINMUTEX_LOCK
	#define MAINMUTEX_UNLOCK
	#define WAITMUTEX_LOCK
	#define WAITMUTEX_UNLOCK
#endif // RTP_SUPPORT_THREAD
	
inline bool operator==(const in6_addr &ip1,const in6_addr &ip2)
{
	if (memcmp(&ip1,&ip2,sizeof(in6_addr)) == 0)
		return true;
	return false;
}

namespace jrtplib
{

RTPUDPv6Transmitter::RTPUDPv6Transmitter(RTPMemoryManager *mgr) : RTPTransmitter(mgr),
								  destinations(GetMemoryManager(),RTPMEM_TYPE_CLASS_DESTINATIONLISTHASHELEMENT),
								  multicastgroups(GetMemoryManager(),RTPMEM_TYPE_CLASS_MULTICASTHASHELEMENT),
								  acceptignoreinfo(GetMemoryManager(),RTPMEM_TYPE_CLASS_ACCEPTIGNOREHASHELEMENT)
{
	created = false;
	init = false;
}

RTPUDPv6Transmitter::~RTPUDPv6Transmitter()
{
	Destroy();
}

int RTPUDPv6Transmitter::Init(bool tsafe)
{
	if (init)
		return ERR_RTP_UDPV6TRANS_ALREADYINIT;
	
#ifdef RTP_SUPPORT_THREAD
	threadsafe = tsafe;
	if (threadsafe)
	{
		int status;
		
		status = mainmutex.Init();
		if (status < 0)
			return ERR_RTP_UDPV6TRANS_CANTINITMUTEX;
		status = waitmutex.Init();
		if (status < 0)
			return ERR_RTP_UDPV6TRANS_CANTINITMUTEX;
	}
#else
	if (tsafe)
		return ERR_RTP_NOTHREADSUPPORT;
#endif // RTP_SUPPORT_THREAD

	init = true;
	return 0;
}

int RTPUDPv6Transmitter::Create(size_t maximumpacketsize,const RTPTransmissionParams *transparams)
{
	const RTPUDPv6TransmissionParams *params,defaultparams;
	struct sockaddr_in6 addr;
	RTPSOCKLENTYPE size;
	int status;

	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK

	if (created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_ALREADYCREATED;
	}
	
	// Obtain transmission parameters
	
	if (transparams == 0)
		params = &defaultparams;
	else
	{
		if (transparams->GetTransmissionProtocol() != RTPTransmitter::IPv6UDPProto)
		{
			MAINMUTEX_UNLOCK
			return ERR_RTP_UDPV6TRANS_ILLEGALPARAMETERS;
		}
		params = (const RTPUDPv6TransmissionParams *)transparams;
	}

	// Check if portbase is even
	if (params->GetPortbase()%2 != 0)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_PORTBASENOTEVEN;
	}

	// create sockets
	
	rtpsock = socket(PF_INET6,SOCK_DGRAM,0);
	if (rtpsock == RTPSOCKERR)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_CANTCREATESOCKET;
	}
	rtcpsock = socket(PF_INET6,SOCK_DGRAM,0);
	if (rtcpsock == RTPSOCKERR)
	{
		RTPCLOSE(rtpsock);
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_CANTCREATESOCKET;
	}
	
	// set socket buffer sizes
	
	size = params->GetRTPReceiveBuffer();
	if (setsockopt(rtpsock,SOL_SOCKET,SO_RCVBUF,(const char *)&size,sizeof(int)) != 0)
	{
		RTPCLOSE(rtpsock);
		RTPCLOSE(rtcpsock);
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_CANTSETRTPRECEIVEBUF;
	}
	size = params->GetRTPSendBuffer();
	if (setsockopt(rtpsock,SOL_SOCKET,SO_SNDBUF,(const char *)&size,sizeof(int)) != 0)
	{
		RTPCLOSE(rtpsock);
		RTPCLOSE(rtcpsock);
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_CANTSETRTPTRANSMITBUF;
	}
	size = params->GetRTCPReceiveBuffer();
	if (setsockopt(rtcpsock,SOL_SOCKET,SO_RCVBUF,(const char *)&size,sizeof(int)) != 0)
	{
		RTPCLOSE(rtpsock);
		RTPCLOSE(rtcpsock);
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_CANTSETRTCPRECEIVEBUF;
	}
	size = params->GetRTCPSendBuffer();
	if (setsockopt(rtcpsock,SOL_SOCKET,SO_SNDBUF,(const char *)&size,sizeof(int)) != 0)
	{
		RTPCLOSE(rtpsock);
		RTPCLOSE(rtcpsock);
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_CANTSETRTCPTRANSMITBUF;
	}
	
	// bind sockets

	bindIP = params->GetBindIP();
	mcastifidx = params->GetMulticastInterfaceIndex();
	
	memset(&addr,0,sizeof(struct sockaddr_in6));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(params->GetPortbase());
	addr.sin6_addr = bindIP;
	if (bind(rtpsock,(struct sockaddr *)&addr,sizeof(struct sockaddr_in6)) != 0)
	{
		RTPCLOSE(rtpsock);
		RTPCLOSE(rtcpsock);
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_CANTBINDRTPSOCKET;
	}
	memset(&addr,0,sizeof(struct sockaddr_in6));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(params->GetPortbase()+1);
	addr.sin6_addr = bindIP;
	if (bind(rtcpsock,(struct sockaddr *)&addr,sizeof(struct sockaddr_in6)) != 0)
	{
		RTPCLOSE(rtpsock);
		RTPCLOSE(rtcpsock);
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_CANTBINDRTCPSOCKET;
	}

	// Try to obtain local IP addresses

	localIPs = params->GetLocalIPList();
	if (localIPs.empty()) // User did not provide list of local IP addresses, calculate them
	{
		int status;
		
		if ((status = CreateLocalIPList()) < 0)
		{
			RTPCLOSE(rtpsock);
			RTPCLOSE(rtcpsock);
			MAINMUTEX_UNLOCK
			return status;
		}

#ifdef RTPDEBUG
		std::cout << "Found these local IP addresses:" << std::endl;
		
		std::list<in6_addr>::const_iterator it;

		for (it = localIPs.begin() ; it != localIPs.end() ; it++)
		{
			RTPIPv6Address a(*it);

			std::cout << a.GetAddressString() << std::endl;
		}
#endif // RTPDEBUG
	}

#ifdef RTP_SUPPORT_IPV6MULTICAST
	if (SetMulticastTTL(params->GetMulticastTTL()))
		supportsmulticasting = true;
	else
		supportsmulticasting = false;
#else // no multicast support enabled
	supportsmulticasting = false;
#endif // RTP_SUPPORT_IPV6MULTICAST

	if (maximumpacketsize > RTPUDPV6TRANS_MAXPACKSIZE)
	{
		RTPCLOSE(rtpsock);
		RTPCLOSE(rtcpsock);
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_SPECIFIEDSIZETOOBIG;
	}
	
	if (!params->GetCreatedAbortDescriptors())
	{
		if ((status = m_abortDesc.Init()) < 0)
		{
			RTPCLOSE(rtpsock);
			RTPCLOSE(rtcpsock);
			MAINMUTEX_UNLOCK
			return status;
		}
		m_pAbortDesc = &m_abortDesc;
	}
	else
	{
		m_pAbortDesc = params->GetCreatedAbortDescriptors();
		if (!m_pAbortDesc->IsInitialized())
		{
			RTPCLOSE(rtpsock);
			RTPCLOSE(rtcpsock);
			MAINMUTEX_UNLOCK
			return ERR_RTP_ABORTDESC_NOTINIT;
		}
	}

	maxpacksize = maximumpacketsize;
	portbase = params->GetPortbase();
	multicastTTL = params->GetMulticastTTL();
	receivemode = RTPTransmitter::AcceptAll;

	localhostname = 0;
	localhostnamelength = 0;

	waitingfordata = false;
	created = true;
	MAINMUTEX_UNLOCK
	return 0;
}

void RTPUDPv6Transmitter::Destroy()
{
	if (!init)
		return;

	MAINMUTEX_LOCK
	if (!created)
	{
		MAINMUTEX_UNLOCK;
		return;
	}

	if (localhostname)
	{
		RTPDeleteByteArray(localhostname,GetMemoryManager());
		localhostname = 0;
		localhostnamelength = 0;
	}
	
	RTPCLOSE(rtpsock);
	RTPCLOSE(rtcpsock);
	destinations.Clear();
#ifdef RTP_SUPPORT_IPV6MULTICAST
	multicastgroups.Clear();
#endif // RTP_SUPPORT_IPV6MULTICAST
	FlushPackets();
	ClearAcceptIgnoreInfo();
	localIPs.clear();
	created = false;
	
	if (waitingfordata)
	{
		m_pAbortDesc->SendAbortSignal();
		m_abortDesc.Destroy(); // Doesn't do anything if not initialized
		MAINMUTEX_UNLOCK
		WAITMUTEX_LOCK // to make sure that the WaitForIncomingData function ended
		WAITMUTEX_UNLOCK
	}
	else
		m_abortDesc.Destroy(); // Doesn't do anything if not initialized

	MAINMUTEX_UNLOCK
}

RTPTransmissionInfo *RTPUDPv6Transmitter::GetTransmissionInfo()
{
	if (!init)
		return 0;

	MAINMUTEX_LOCK
	RTPTransmissionInfo *tinf = RTPNew(GetMemoryManager(),RTPMEM_TYPE_CLASS_RTPTRANSMISSIONINFO) RTPUDPv6TransmissionInfo(localIPs,rtpsock,rtcpsock,portbase,portbase+1);
	MAINMUTEX_UNLOCK
	return tinf;
}

void RTPUDPv6Transmitter::DeleteTransmissionInfo(RTPTransmissionInfo *i)
{
	if (!init)
		return;

	RTPDelete(i, GetMemoryManager());
}

int RTPUDPv6Transmitter::GetLocalHostName(uint8_t *buffer,size_t *bufferlength)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;

	MAINMUTEX_LOCK
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}

	if (localhostname == 0)
	{
		if (localIPs.empty())
		{
			MAINMUTEX_UNLOCK
			return ERR_RTP_UDPV6TRANS_NOLOCALIPS;
		}
		
		std::list<in6_addr>::const_iterator it;
		std::list<std::string> hostnames;
	
		for (it = localIPs.begin() ; it != localIPs.end() ; it++)
		{
			bool founddouble = false;
			bool foundentry = true;

			while (!founddouble && foundentry)
			{
				struct hostent *he;
				in6_addr ip = (*it);	
			
				he = gethostbyaddr((char *)&ip,sizeof(in6_addr),AF_INET6);
				if (he != 0)
				{
					std::string hname = std::string(he->h_name);
					std::list<std::string>::const_iterator it;

					for (it = hostnames.begin() ; !founddouble && it != hostnames.end() ; it++)
						if ((*it) == hname)
							founddouble = true;

					if (!founddouble)
						hostnames.push_back(hname);

					int i = 0;
					while (!founddouble && he->h_aliases[i] != 0)
					{
						std::string hname = std::string(he->h_aliases[i]);
						
						for (it = hostnames.begin() ; !founddouble && it != hostnames.end() ; it++)
							if ((*it) == hname)
								founddouble = true;

						if (!founddouble)
						{
							hostnames.push_back(hname);
							i++;
						}
					}
				}
				else
					foundentry = false;
			}
		}
	
		bool found  = false;
		
		if (!hostnames.empty())	// try to select the most appropriate hostname
		{
			std::list<std::string>::const_iterator it;
			
			hostnames.sort();
			for (it = hostnames.begin() ; !found && it != hostnames.end() ; it++)
			{
				if ((*it).find('.') != std::string::npos)
				{
					found = true;
					localhostnamelength = (*it).length();
					localhostname = RTPNew(GetMemoryManager(),RTPMEM_TYPE_OTHER) uint8_t [localhostnamelength+1];
					if (localhostname == 0)
					{
						MAINMUTEX_UNLOCK
						return ERR_RTP_OUTOFMEM;
					}
					memcpy(localhostname,(*it).c_str(),localhostnamelength);
					localhostname[localhostnamelength] = 0;
				}
			}
		}
	
		if (!found) // use an IP address
		{
			in6_addr ip;
			int len;
			char str[48];
			uint16_t ip16[8];
			int i,j;
				
			it = localIPs.begin();
			ip = (*it);
			
			for (i = 0,j = 0 ; j < 8 ; j++,i += 2)
			{
				ip16[j] = (((uint16_t)ip.s6_addr[i])<<8);
				ip16[j] |= ((uint16_t)ip.s6_addr[i+1]);
			}			
			
			RTP_SNPRINTF(str,48,"%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",(int)ip16[0],(int)ip16[1],(int)ip16[2],(int)ip16[3],(int)ip16[4],(int)ip16[5],(int)ip16[6],(int)ip16[7]);
			len = strlen(str);
	
			localhostnamelength = len;
			localhostname = RTPNew(GetMemoryManager(),RTPMEM_TYPE_OTHER) uint8_t [localhostnamelength+1];
			if (localhostname == 0)
			{
				MAINMUTEX_UNLOCK
				return ERR_RTP_OUTOFMEM;
			}
			memcpy(localhostname,str,localhostnamelength);
			localhostname[localhostnamelength] = 0;
		}
	}
	
	if ((*bufferlength) < localhostnamelength)
	{
		*bufferlength = localhostnamelength; // tell the application the required size of the buffer
		MAINMUTEX_UNLOCK
		return ERR_RTP_TRANS_BUFFERLENGTHTOOSMALL;
	}

	memcpy(buffer,localhostname,localhostnamelength);
	*bufferlength = localhostnamelength;
	
	MAINMUTEX_UNLOCK
	return 0;
}

bool RTPUDPv6Transmitter::ComesFromThisTransmitter(const RTPAddress *addr)
{
	if (!init)
		return false;

	if (addr == 0)
		return false;
	
	MAINMUTEX_LOCK
	
	bool v;
		
	if (created && addr->GetAddressType() == RTPAddress::IPv6Address)
	{	
		const RTPIPv6Address *addr2 = (const RTPIPv6Address *)addr;
		bool found = false;
		std::list<in6_addr>::const_iterator it;
	
		it = localIPs.begin();
		while (!found && it != localIPs.end())
		{
			in6_addr itip = *it;
			in6_addr addrip = addr2->GetIP();
			if (memcmp(&addrip,&itip,sizeof(in6_addr)) == 0)
				found = true;
			else
				++it;
		}
	
		if (!found)
			v = false;
		else
		{
			if (addr2->GetPort() == portbase) // check for RTP port
				v = true;
			else if (addr2->GetPort() == (portbase+1)) // check for RTCP port
				v = true;
			else 
				v = false;
		}
	}
	else
		v = false;

	MAINMUTEX_UNLOCK
	return v;
}

int RTPUDPv6Transmitter::Poll()
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;

	int status;
	
	MAINMUTEX_LOCK
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	status = PollSocket(true); // poll RTP socket
	if (status >= 0)
		status = PollSocket(false); // poll RTCP socket
	MAINMUTEX_UNLOCK
	return status;
}

int RTPUDPv6Transmitter::WaitForIncomingData(const RTPTime &delay,bool *dataavailable)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK
		
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (waitingfordata)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_ALREADYWAITING;
	}
	
	SocketType abortSocket = m_pAbortDesc->GetAbortSocket();
	SocketType socks[3] = { rtpsock, rtcpsock, abortSocket };
	int8_t readflags[3] = { 0, 0, 0 };
	const int idxRTP = 0;
	const int idxRTCP = 1;
	const int idxAbort = 2;

	waitingfordata = true;
	
	WAITMUTEX_LOCK
	MAINMUTEX_UNLOCK

	int status = RTPSelect(socks, readflags, 3, delay);
	if (status < 0)
	{
		MAINMUTEX_LOCK
		waitingfordata = false;
		MAINMUTEX_UNLOCK
		WAITMUTEX_UNLOCK
		return status;
	}
	
	MAINMUTEX_LOCK
	waitingfordata = false;
	if (!created) // destroy called
	{
		MAINMUTEX_UNLOCK;
		WAITMUTEX_UNLOCK
		return 0;
	}
		
	// if aborted, read from abort buffer
	if (readflags[idxAbort])
		m_pAbortDesc->ReadSignallingByte();
	
	if (dataavailable != 0)
	{
		if (readflags[idxRTP] || readflags[idxRTCP])
			*dataavailable = true;
		else
			*dataavailable = false;
	}	

	MAINMUTEX_UNLOCK
	WAITMUTEX_UNLOCK
	return 0;
}

int RTPUDPv6Transmitter::AbortWait()
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (!waitingfordata)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTWAITING;
	}

	m_pAbortDesc->SendAbortSignal();
	
	MAINMUTEX_UNLOCK
	return 0;
}

int RTPUDPv6Transmitter::SendRTPData(const void *data,size_t len)	
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;

	MAINMUTEX_LOCK
	
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (len > maxpacksize)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_SPECIFIEDSIZETOOBIG;
	}
	
	destinations.GotoFirstElement();
	while (destinations.HasCurrentElement())
	{
		sendto(rtpsock,(const char *)data,len,0,(const struct sockaddr *)destinations.GetCurrentElement().GetRTPSockAddr(),sizeof(struct sockaddr_in6));
		destinations.GotoNextElement();
	}
	
	MAINMUTEX_UNLOCK
	return 0;
}

int RTPUDPv6Transmitter::SendRTCPData(const void *data,size_t len)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;

	MAINMUTEX_LOCK
	
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (len > maxpacksize)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_SPECIFIEDSIZETOOBIG;
	}
	
	destinations.GotoFirstElement();
	while (destinations.HasCurrentElement())
	{
		sendto(rtcpsock,(const char *)data,len,0,(const struct sockaddr *)destinations.GetCurrentElement().GetRTCPSockAddr(),sizeof(struct sockaddr_in6));
		destinations.GotoNextElement();
	}
	
	MAINMUTEX_UNLOCK
	return 0;
}

int RTPUDPv6Transmitter::AddDestination(const RTPAddress &addr)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK

	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (addr.GetAddressType() != RTPAddress::IPv6Address)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_INVALIDADDRESSTYPE;
	}
	
	RTPIPv6Address &address = (RTPIPv6Address &)addr;
	RTPIPv6Destination dest(address.GetIP(),address.GetPort());
	int status = destinations.AddElement(dest);

	MAINMUTEX_UNLOCK
	return status;
}

int RTPUDPv6Transmitter::DeleteDestination(const RTPAddress &addr)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK
	
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (addr.GetAddressType() != RTPAddress::IPv6Address)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_INVALIDADDRESSTYPE;
	}
	
	RTPIPv6Address &address = (RTPIPv6Address &)addr;	
	RTPIPv6Destination dest(address.GetIP(),address.GetPort());
	int status = destinations.DeleteElement(dest);
	
	MAINMUTEX_UNLOCK
	return status;
}

void RTPUDPv6Transmitter::ClearDestinations()
{
	if (!init)
		return;
	
	MAINMUTEX_LOCK
	if (created)
		destinations.Clear();
	MAINMUTEX_UNLOCK
}

bool RTPUDPv6Transmitter::SupportsMulticasting()
{
	if (!init)
		return false;
	
	MAINMUTEX_LOCK
	
	bool v;
		
	if (!created)
		v = false;
	else
		v = supportsmulticasting;

	MAINMUTEX_UNLOCK
	return v;
}

#ifdef RTP_SUPPORT_IPV6MULTICAST

int RTPUDPv6Transmitter::JoinMulticastGroup(const RTPAddress &addr)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;

	MAINMUTEX_LOCK
	
	int status;
	
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (addr.GetAddressType() != RTPAddress::IPv6Address)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_INVALIDADDRESSTYPE;
	}
	
	const RTPIPv6Address &address = (const RTPIPv6Address &)addr;
	in6_addr mcastIP = address.GetIP();
	
	if (!RTPUDPV6TRANS_IS_MCASTADDR(mcastIP))
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTAMULTICASTADDRESS;
	}
	
	status = multicastgroups.AddElement(mcastIP);
	if (status >= 0)
	{
		RTPUDPV6TRANS_MCASTMEMBERSHIP(rtpsock,IPV6_JOIN_GROUP,mcastIP,status);
		if (status != 0)
		{
			multicastgroups.DeleteElement(mcastIP);
			MAINMUTEX_UNLOCK
			return ERR_RTP_UDPV6TRANS_COULDNTJOINMULTICASTGROUP;
		}
		RTPUDPV6TRANS_MCASTMEMBERSHIP(rtcpsock,IPV6_JOIN_GROUP,mcastIP,status);
		if (status != 0)
		{
			RTPUDPV6TRANS_MCASTMEMBERSHIP(rtpsock,IPV6_LEAVE_GROUP,mcastIP,status);
			multicastgroups.DeleteElement(mcastIP);
			MAINMUTEX_UNLOCK
			return ERR_RTP_UDPV6TRANS_COULDNTJOINMULTICASTGROUP;
		}
	}
	MAINMUTEX_UNLOCK	
	return status;
}

int RTPUDPv6Transmitter::LeaveMulticastGroup(const RTPAddress &addr)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;

	MAINMUTEX_LOCK
	
	int status;
	
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (addr.GetAddressType() != RTPAddress::IPv6Address)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_INVALIDADDRESSTYPE;
	}
	
	const RTPIPv6Address &address = (const RTPIPv6Address &)addr;
	in6_addr mcastIP = address.GetIP();
	
	if (!RTPUDPV6TRANS_IS_MCASTADDR(mcastIP))
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTAMULTICASTADDRESS;
	}
	
	status = multicastgroups.DeleteElement(mcastIP);
	if (status >= 0)
	{	
		RTPUDPV6TRANS_MCASTMEMBERSHIP(rtpsock,IPV6_LEAVE_GROUP,mcastIP,status);
		RTPUDPV6TRANS_MCASTMEMBERSHIP(rtcpsock,IPV6_LEAVE_GROUP,mcastIP,status);
		status = 0;
	}
	
	MAINMUTEX_UNLOCK
	return status;
}

void RTPUDPv6Transmitter::LeaveAllMulticastGroups()
{
	if (!init)
		return;
	
	MAINMUTEX_LOCK
	if (created)
	{
		multicastgroups.GotoFirstElement();
		while (multicastgroups.HasCurrentElement())
		{
			in6_addr mcastIP;
			int status = 0;

			mcastIP = multicastgroups.GetCurrentElement();
			RTPUDPV6TRANS_MCASTMEMBERSHIP(rtpsock,IPV6_LEAVE_GROUP,mcastIP,status);
			RTPUDPV6TRANS_MCASTMEMBERSHIP(rtcpsock,IPV6_LEAVE_GROUP,mcastIP,status);
			multicastgroups.GotoNextElement();
			JRTPLIB_UNUSED(status);
		}
		multicastgroups.Clear();
	}
	MAINMUTEX_UNLOCK
}

#else // no multicast support

int RTPUDPv6Transmitter::JoinMulticastGroup(const RTPAddress &addr)
{
	return ERR_RTP_UDPV6TRANS_NOMULTICASTSUPPORT;
}

int RTPUDPv6Transmitter::LeaveMulticastGroup(const RTPAddress &addr)
{
	return ERR_RTP_UDPV6TRANS_NOMULTICASTSUPPORT;
}

void RTPUDPv6Transmitter::LeaveAllMulticastGroups()
{
}

#endif // RTP_SUPPORT_IPV6MULTICAST

int RTPUDPv6Transmitter::SetReceiveMode(RTPTransmitter::ReceiveMode m)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (m != receivemode)
	{
		receivemode = m;
		acceptignoreinfo.Clear();
	}
	MAINMUTEX_UNLOCK
	return 0;
}

int RTPUDPv6Transmitter::AddToIgnoreList(const RTPAddress &addr)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;

	MAINMUTEX_LOCK
	
	int status;

	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (addr.GetAddressType() != RTPAddress::IPv6Address)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_INVALIDADDRESSTYPE;
	}
	if (receivemode != RTPTransmitter::IgnoreSome)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_DIFFERENTRECEIVEMODE;
	}
	
	const RTPIPv6Address &address = (const RTPIPv6Address &)addr;
	status = ProcessAddAcceptIgnoreEntry(address.GetIP(),address.GetPort());
	
	MAINMUTEX_UNLOCK
	return status;
}

int RTPUDPv6Transmitter::DeleteFromIgnoreList(const RTPAddress &addr)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK
	
	int status;
	
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (addr.GetAddressType() != RTPAddress::IPv6Address)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_INVALIDADDRESSTYPE;
	}
	if (receivemode != RTPTransmitter::IgnoreSome)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_DIFFERENTRECEIVEMODE;
	}
	
	const RTPIPv6Address &address = (const RTPIPv6Address &)addr;	
	status = ProcessDeleteAcceptIgnoreEntry(address.GetIP(),address.GetPort());

	MAINMUTEX_UNLOCK
	return status;
}

void RTPUDPv6Transmitter::ClearIgnoreList()
{
	if (!init)
		return;
	
	MAINMUTEX_LOCK
	if (created && receivemode == RTPTransmitter::IgnoreSome)
		ClearAcceptIgnoreInfo();
	MAINMUTEX_UNLOCK
}

int RTPUDPv6Transmitter::AddToAcceptList(const RTPAddress &addr)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK
	
	int status;
	
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (addr.GetAddressType() != RTPAddress::IPv6Address)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_INVALIDADDRESSTYPE;
	}
	if (receivemode != RTPTransmitter::AcceptSome)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_DIFFERENTRECEIVEMODE;
	}
	
	const RTPIPv6Address &address = (const RTPIPv6Address &)addr;
	status = ProcessAddAcceptIgnoreEntry(address.GetIP(),address.GetPort());

	MAINMUTEX_UNLOCK
	return status;
}

int RTPUDPv6Transmitter::DeleteFromAcceptList(const RTPAddress &addr)
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK
	
	int status;
	
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (addr.GetAddressType() != RTPAddress::IPv6Address)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_INVALIDADDRESSTYPE;
	}
	if (receivemode != RTPTransmitter::AcceptSome)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_DIFFERENTRECEIVEMODE;
	}
	
	const RTPIPv6Address &address = (const RTPIPv6Address &)addr;
	status = ProcessDeleteAcceptIgnoreEntry(address.GetIP(),address.GetPort());

	MAINMUTEX_UNLOCK
	return status;
}

void RTPUDPv6Transmitter::ClearAcceptList()
{
	if (!init)
		return;
	
	MAINMUTEX_LOCK
	if (created && receivemode == RTPTransmitter::AcceptSome)
		ClearAcceptIgnoreInfo();
	MAINMUTEX_UNLOCK
}

int RTPUDPv6Transmitter::SetMaximumPacketSize(size_t s)	
{
	if (!init)
		return ERR_RTP_UDPV6TRANS_NOTINIT;
	
	MAINMUTEX_LOCK
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_NOTCREATED;
	}
	if (s > RTPUDPV6TRANS_MAXPACKSIZE)
	{
		MAINMUTEX_UNLOCK
		return ERR_RTP_UDPV6TRANS_SPECIFIEDSIZETOOBIG;
	}
	maxpacksize = s;
	MAINMUTEX_UNLOCK
	return 0;
}

bool RTPUDPv6Transmitter::NewDataAvailable()
{
	if (!init)
		return false;
	
	MAINMUTEX_LOCK
	
	bool v;
		
	if (!created)
		v = false;
	else
	{
		if (rawpacketlist.empty())
			v = false;
		else
			v = true;
	}
	
	MAINMUTEX_UNLOCK
	return v;
}

RTPRawPacket *RTPUDPv6Transmitter::GetNextPacket()
{
	if (!init)
		return 0;
	
	MAINMUTEX_LOCK
	
	RTPRawPacket *p;
	
	if (!created)
	{
		MAINMUTEX_UNLOCK
		return 0;
	}
	if (rawpacketlist.empty())
	{
		MAINMUTEX_UNLOCK
		return 0;
	}

	p = *(rawpacketlist.begin());
	rawpacketlist.pop_front();

	MAINMUTEX_UNLOCK
	return p;
}

// Here the private functions start...


#ifdef RTP_SUPPORT_IPV6MULTICAST
bool RTPUDPv6Transmitter::SetMulticastTTL(uint8_t ttl)
{
	int ttl2,status;

	ttl2 = (int)ttl;
	status = setsockopt(rtpsock,IPPROTO_IPV6,IPV6_MULTICAST_HOPS,(const char *)&ttl2,sizeof(int));
	if (status != 0)
		return false;
	status = setsockopt(rtcpsock,IPPROTO_IPV6,IPV6_MULTICAST_HOPS,(const char *)&ttl2,sizeof(int));
	if (status != 0)
		return false;
	return true;
}
#endif // RTP_SUPPORT_IPV6MULTICAST


void RTPUDPv6Transmitter::FlushPackets()
{
	std::list<RTPRawPacket*>::const_iterator it;

	for (it = rawpacketlist.begin() ; it != rawpacketlist.end() ; ++it)
		RTPDelete(*it,GetMemoryManager());
	rawpacketlist.clear();
}

int RTPUDPv6Transmitter::PollSocket(bool rtp)
{
	RTPSOCKLENTYPE fromlen;
	int recvlen;
	char packetbuffer[RTPUDPV6TRANS_MAXPACKSIZE];
#ifdef RTP_SOCKETTYPE_WINSOCK
	SOCKET sock;
	unsigned long len;
#else 
	size_t len;
	int sock;
#endif // RTP_SOCKETTYPE_WINSOCK
	struct sockaddr_in6 srcaddr;
	bool dataavailable;
	
	if (rtp)
		sock = rtpsock;
	else
		sock = rtcpsock;
	
	len = 0;
	RTPIOCTL(sock,FIONREAD,&len);

	if (len <= 0) // make sure a packet of length zero is not queued
	{
		int8_t isset = 0;
		int status = RTPSelect(&sock, &isset, 1, RTPTime(0));
		if (status < 0)
			return status;

		if (isset)
			dataavailable = true;
		else
			dataavailable = false;
	}
	else
		dataavailable = true;

	while (dataavailable)
	{
		RTPTime curtime = RTPTime::CurrentTime();
		fromlen = sizeof(struct sockaddr_in6);
		recvlen = recvfrom(sock,packetbuffer,RTPUDPV6TRANS_MAXPACKSIZE,0,(struct sockaddr *)&srcaddr,&fromlen);
		if (recvlen > 0)
		{
			bool acceptdata;

			// got data, process it
			if (receivemode == RTPTransmitter::AcceptAll)
				acceptdata = true;
			else
				acceptdata = ShouldAcceptData(srcaddr.sin6_addr,ntohs(srcaddr.sin6_port));
			
			if (acceptdata)
			{
				RTPRawPacket *pack;
				RTPIPv6Address *addr;
				uint8_t *datacopy;

				addr = RTPNew(GetMemoryManager(),RTPMEM_TYPE_CLASS_RTPADDRESS) RTPIPv6Address(srcaddr.sin6_addr,ntohs(srcaddr.sin6_port));
				if (addr == 0)
					return ERR_RTP_OUTOFMEM;
				datacopy = RTPNew(GetMemoryManager(),(rtp)?RTPMEM_TYPE_BUFFER_RECEIVEDRTPPACKET:RTPMEM_TYPE_BUFFER_RECEIVEDRTCPPACKET) uint8_t[recvlen];
				if (datacopy == 0)
				{
					RTPDelete(addr,GetMemoryManager());
					return ERR_RTP_OUTOFMEM;
				}
				memcpy(datacopy,packetbuffer,recvlen);
				
				pack = RTPNew(GetMemoryManager(),RTPMEM_TYPE_CLASS_RTPRAWPACKET) RTPRawPacket(datacopy,recvlen,addr,curtime,rtp,GetMemoryManager());
				if (pack == 0)
				{
					RTPDelete(addr,GetMemoryManager());
					RTPDeleteByteArray(datacopy,GetMemoryManager());
					return ERR_RTP_OUTOFMEM;
				}
				rawpacketlist.push_back(pack);	
			}
		}
		len = 0;
		RTPIOCTL(sock,FIONREAD,&len);

		if (len <= 0) // make sure a packet of length zero is not queued
		{
			int8_t isset = 0;
			int status = RTPSelect(&sock, &isset, 1, RTPTime(0));
			if (status < 0)
				return status;

			if (isset)
				dataavailable = true;
			else
				dataavailable = false;
		}
		else
			dataavailable = true;
	}
	return 0;
}

int RTPUDPv6Transmitter::ProcessAddAcceptIgnoreEntry(in6_addr ip,uint16_t port)
{
	acceptignoreinfo.GotoElement(ip);
	if (acceptignoreinfo.HasCurrentElement()) // An entry for this IP address already exists
	{
		PortInfo *portinf = acceptignoreinfo.GetCurrentElement();
		
		if (port == 0) // select all ports
		{
			portinf->all = true;
			portinf->portlist.clear();
		}
		else if (!portinf->all)
		{
			std::list<uint16_t>::const_iterator it,begin,end;

			begin = portinf->portlist.begin();
			end = portinf->portlist.end();
			for (it = begin ; it != end ; it++)
			{
				if (*it == port) // already in list
					return 0;
			}
			portinf->portlist.push_front(port);
		}
	}
	else // got to create an entry for this IP address
	{
		PortInfo *portinf;
		int status;
		
		portinf = RTPNew(GetMemoryManager(),RTPMEM_TYPE_CLASS_ACCEPTIGNOREPORTINFO) PortInfo();
		if (port == 0) // select all ports
			portinf->all = true;
		else
			portinf->portlist.push_front(port);
		
		status = acceptignoreinfo.AddElement(ip,portinf);
		if (status < 0)
		{
			RTPDelete(portinf,GetMemoryManager());
			return status;
		}
	}
	return 0;
}

void RTPUDPv6Transmitter::ClearAcceptIgnoreInfo()
{
	acceptignoreinfo.GotoFirstElement();
	while (acceptignoreinfo.HasCurrentElement())
	{
		PortInfo *inf;

		inf = acceptignoreinfo.GetCurrentElement();
		RTPDelete(inf,GetMemoryManager());
		acceptignoreinfo.GotoNextElement();
	}
	acceptignoreinfo.Clear();
}
	
int RTPUDPv6Transmitter::ProcessDeleteAcceptIgnoreEntry(in6_addr ip,uint16_t port)
{
	acceptignoreinfo.GotoElement(ip);
	if (!acceptignoreinfo.HasCurrentElement())
		return ERR_RTP_UDPV6TRANS_NOSUCHENTRY;
	
	PortInfo *inf;

	inf = acceptignoreinfo.GetCurrentElement();
	if (port == 0) // delete all entries
	{
		inf->all = false;
		inf->portlist.clear();
	}
	else // a specific port was selected
	{
		if (inf->all) // currently, all ports are selected. Add the one to remove to the list
		{
			// we have to check if the list doesn't contain the port already
			std::list<uint16_t>::const_iterator it,begin,end;

			begin = inf->portlist.begin();
			end = inf->portlist.end();
			for (it = begin ; it != end ; it++)
			{
				if (*it == port) // already in list: this means we already deleted the entry
					return ERR_RTP_UDPV6TRANS_NOSUCHENTRY;
			}
			inf->portlist.push_front(port);
		}
		else // check if we can find the port in the list
		{
			std::list<uint16_t>::iterator it,begin,end;
			
			begin = inf->portlist.begin();
			end = inf->portlist.end();
			for (it = begin ; it != end ; ++it)
			{
				if (*it == port) // found it!
				{
					inf->portlist.erase(it);
					return 0;
				}
			}
			// didn't find it
			return ERR_RTP_UDPV6TRANS_NOSUCHENTRY;			
		}
	}
	return 0;
}

bool RTPUDPv6Transmitter::ShouldAcceptData(in6_addr srcip,uint16_t srcport)
{
	if (receivemode == RTPTransmitter::AcceptSome)
	{
		PortInfo *inf;

		acceptignoreinfo.GotoElement(srcip);
		if (!acceptignoreinfo.HasCurrentElement())
			return false;
		
		inf = acceptignoreinfo.GetCurrentElement();
		if (!inf->all) // only accept the ones in the list
		{
			std::list<uint16_t>::const_iterator it,begin,end;

			begin = inf->portlist.begin();
			end = inf->portlist.end();
			for (it = begin ; it != end ; it++)
			{
				if (*it == srcport)
					return true;
			}
			return false;
		}
		else // accept all, except the ones in the list
		{
			std::list<uint16_t>::const_iterator it,begin,end;

			begin = inf->portlist.begin();
			end = inf->portlist.end();
			for (it = begin ; it != end ; it++)
			{
				if (*it == srcport)
					return false;
			}
			return true;
		}
	}
	else // IgnoreSome
	{
		PortInfo *inf;

		acceptignoreinfo.GotoElement(srcip);
		if (!acceptignoreinfo.HasCurrentElement())
			return true;
		
		inf = acceptignoreinfo.GetCurrentElement();
		if (!inf->all) // ignore the ports in the list
		{
			std::list<uint16_t>::const_iterator it,begin,end;

			begin = inf->portlist.begin();
			end = inf->portlist.end();
			for (it = begin ; it != end ; it++)
			{
				if (*it == srcport)
					return false;
			}
			return true;
		}
		else // ignore all, except the ones in the list
		{
			std::list<uint16_t>::const_iterator it,begin,end;

			begin = inf->portlist.begin();
			end = inf->portlist.end();
			for (it = begin ; it != end ; it++)
			{
				if (*it == srcport)
					return true;
			}
			return false;
		}
	}
	return true;
}

int RTPUDPv6Transmitter::CreateLocalIPList()
{
	 // first try to obtain the list from the network interface info

	if (!GetLocalIPList_Interfaces())
	{
		// If this fails, we'll have to depend on DNS info
		GetLocalIPList_DNS();
	}
	AddLoopbackAddress();
	return 0;
}

#ifdef RTP_SOCKETTYPE_WINSOCK

bool RTPUDPv6Transmitter::GetLocalIPList_Interfaces()
{
	unsigned char buffer[RTPUDPV6TRANS_IFREQBUFSIZE];
	DWORD outputsize;
	DWORD numaddresses,i;
	SOCKET_ADDRESS_LIST *addrlist;

	if (WSAIoctl(rtpsock,SIO_ADDRESS_LIST_QUERY,NULL,0,&buffer,RTPUDPV6TRANS_IFREQBUFSIZE,&outputsize,NULL,NULL))
		return false;
	
	addrlist = (SOCKET_ADDRESS_LIST *)buffer;
	numaddresses = addrlist->iAddressCount;
	for (i = 0 ; i < numaddresses ; i++)
	{
		SOCKET_ADDRESS *sockaddr = &(addrlist->Address[i]);
		if (sockaddr->iSockaddrLength == sizeof(struct sockaddr_in6)) // IPv6 address
		{
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)sockaddr->lpSockaddr;

			localIPs.push_back(addr->sin6_addr);
		}
	}

	if (localIPs.empty())
		return false;
	return true;
}

#else

#ifdef RTP_SUPPORT_IFADDRS

bool RTPUDPv6Transmitter::GetLocalIPList_Interfaces()
{
	struct ifaddrs *addrs,*tmp;
	
	getifaddrs(&addrs);
	tmp = addrs;
	
	while (tmp != 0)
	{
		if (tmp->ifa_addr != 0 && tmp->ifa_addr->sa_family == AF_INET6)
		{
			struct sockaddr_in6 *inaddr = (struct sockaddr_in6 *)tmp->ifa_addr;
			localIPs.push_back(inaddr->sin6_addr);
		}
		tmp = tmp->ifa_next;
	}
	
	freeifaddrs(addrs);
	
	if (localIPs.empty())
		return false;
	return true;
}

#else

bool RTPUDPv6Transmitter::GetLocalIPList_Interfaces()
{
	return false;
}

#endif // RTP_SUPPORT_IFADDRS

#endif // RTP_SOCKETTYPE_WINSOCK

void RTPUDPv6Transmitter::GetLocalIPList_DNS()
{
	int status;
	char name[1024];

	gethostname(name,1023);
	name[1023] = 0;

	struct addrinfo hints;
	struct addrinfo *res,*tmp;
	
	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = 0;
	hints.ai_protocol = 0;

	if ((status = getaddrinfo(name,0,&hints,&res)) != 0)
		return;

	tmp = res;
	while (tmp != 0)
	{
		if (tmp->ai_family == AF_INET6)
		{
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)(tmp->ai_addr);
			localIPs.push_back(addr->sin6_addr);
		}
		tmp = tmp->ai_next;
	}
	
	freeaddrinfo(res);	
}

void RTPUDPv6Transmitter::AddLoopbackAddress()
{
	std::list<in6_addr>::const_iterator it;
	bool found = false;

	for (it = localIPs.begin() ; !found && it != localIPs.end() ; it++)
	{
		if ((*it) == in6addr_loopback)
			found = true;
	}

	if (!found)
		localIPs.push_back(in6addr_loopback);
}

#ifdef RTPDEBUG
void RTPUDPv6Transmitter::Dump()
{
	if (!init)
		std::cout << "Not initialized" << std::endl;
	else
	{
		MAINMUTEX_LOCK
	
		if (!created)
			std::cout << "Not created" << std::endl;
		else
		{
			char str[48];
			in6_addr ip;
			uint16_t ip16[8];
			std::list<in6_addr>::const_iterator it;
			int i,j;
			
			std::cout << "Portbase:                       " << portbase << std::endl;
			std::cout << "RTP socket descriptor:          " << rtpsock << std::endl;
			std::cout << "RTCP socket descriptor:         " << rtcpsock << std::endl;
			ip = bindIP;
			for (i = 0,j = 0 ; j < 8 ; j++,i += 2)	{ ip16[j] = (((uint16_t)ip.s6_addr[i])<<8); ip16[j] |= ((uint16_t)ip.s6_addr[i+1]); }
			RTP_SNPRINTF(str,48,"%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",(int)ip16[0],(int)ip16[1],(int)ip16[2],(int)ip16[3],(int)ip16[4],(int)ip16[5],(int)ip16[6],(int)ip16[7]);
			std::cout << "Bind IP address:                " << str << std::endl;
			std::cout << "Multicast interface index:      " << mcastifidx << std::endl;
			std::cout << "Local IP addresses:" << std::endl;
			for (it = localIPs.begin() ; it != localIPs.end() ; it++)
			{
				ip = (*it);
				for (i = 0,j = 0 ; j < 8 ; j++,i += 2)	{ ip16[j] = (((uint16_t)ip.s6_addr[i])<<8); ip16[j] |= ((uint16_t)ip.s6_addr[i+1]); }
				RTP_SNPRINTF(str,48,"%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",(int)ip16[0],(int)ip16[1],(int)ip16[2],(int)ip16[3],(int)ip16[4],(int)ip16[5],(int)ip16[6],(int)ip16[7]);
				std::cout << "    " << str << std::endl;
			}
			std::cout << "Multicast TTL:                  " << (int)multicastTTL << std::endl;
			std::cout << "Receive mode:                   ";
			switch (receivemode)
			{
			case RTPTransmitter::AcceptAll:
				std::cout << "Accept all";
				break;
			case RTPTransmitter::AcceptSome:
				std::cout << "Accept some";
				break;
			case RTPTransmitter::IgnoreSome:
				std::cout << "Ignore some";
			}
			std::cout << std::endl;
			if (receivemode != RTPTransmitter::AcceptAll)
			{
				acceptignoreinfo.GotoFirstElement();
				while(acceptignoreinfo.HasCurrentElement())
				{
					ip = acceptignoreinfo.GetCurrentKey();
					for (i = 0,j = 0 ; j < 8 ; j++,i += 2)	{ ip16[j] = (((uint16_t)ip.s6_addr[i])<<8); ip16[j] |= ((uint16_t)ip.s6_addr[i+1]); }
					RTP_SNPRINTF(str,48,"%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",(int)ip16[0],(int)ip16[1],(int)ip16[2],(int)ip16[3],(int)ip16[4],(int)ip16[5],(int)ip16[6],(int)ip16[7]);
					PortInfo *pinfo = acceptignoreinfo.GetCurrentElement();
					std::cout << "    " << str << ": ";
					if (pinfo->all)
					{
						std::cout << "All ports";
						if (!pinfo->portlist.empty())
							std::cout << ", except ";
					}
					
					std::list<uint16_t>::const_iterator it;
					
					for (it = pinfo->portlist.begin() ; it != pinfo->portlist.end() ; )
					{
						std::cout << (*it);
						it++;
						if (it != pinfo->portlist.end())
							std::cout << ", ";
					}
					std::cout << std::endl;
				}
			}
			
			std::cout << "Local host name:                ";
			if (localhostname == 0)
				std::cout << "Not set";
			else
				std::cout << localhostname;
			std::cout << std::endl;

			std::cout << "List of destinations:           ";
			destinations.GotoFirstElement();
			if (destinations.HasCurrentElement())
			{
				std::cout << std::endl;
				do
				{
					std::cout << "    " << destinations.GetCurrentElement().GetDestinationString() << std::endl;
					destinations.GotoNextElement();
				} while (destinations.HasCurrentElement());
			}
			else
				std::cout << "Empty" << std::endl;
		
			std::cout << "Supports multicasting:          " << ((supportsmulticasting)?"Yes":"No") << std::endl;
#ifdef RTP_SUPPORT_IPV6MULTICAST
			std::cout << "List of multicast groups:       ";
			multicastgroups.GotoFirstElement();
			if (multicastgroups.HasCurrentElement())
			{
				std::cout << std::endl;
				do
				{
					ip = multicastgroups.GetCurrentElement();
					for (i = 0,j = 0 ; j < 8 ; j++,i += 2)	{ ip16[j] = (((uint16_t)ip.s6_addr[i])<<8); ip16[j] |= ((uint16_t)ip.s6_addr[i+1]); }
					RTP_SNPRINTF(str,48,"%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",(int)ip16[0],(int)ip16[1],(int)ip16[2],(int)ip16[3],(int)ip16[4],(int)ip16[5],(int)ip16[6],(int)ip16[7]);
					std::cout << "    " << str << std::endl;
					multicastgroups.GotoNextElement();
				} while (multicastgroups.HasCurrentElement());
			}
			else
				std::cout << "Empty" << std::endl;
#endif // RTP_SUPPORT_IPV6MULTICAST
			
			std::cout << "Number of raw packets in queue: " << rawpacketlist.size() << std::endl;
			std::cout << "Maximum allowed packet size:    " << maxpacksize << std::endl;
		}
		
		MAINMUTEX_UNLOCK
	}

}
#endif // RTPDEBUG

} // end namespace

#endif // RTP_SUPPORT_IPV6

