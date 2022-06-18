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

/**
 * \file rtpsessionsources.h
 */

#ifndef RTPSESSIONSOURCES_H

#define RTPSESSIONSOURCES_H

#include "rtpconfig.h"
#include "rtpsources.h"

namespace jrtplib
{

class RTPSession;

class JRTPLIB_IMPORTEXPORT RTPSessionSources : public RTPSources
{
public:
	RTPSessionSources(RTPSession &sess,RTPMemoryManager *mgr) : RTPSources(RTPSources::ProbationStore,mgr),rtpsession(sess)
													{ owncollision = false; }
	~RTPSessionSources()										{ }
	void ClearOwnCollisionFlag()									{ owncollision = false; }
	bool DetectedOwnCollision() const								{ return owncollision; }
private:
	void OnRTPPacket(RTPPacket *pack,const RTPTime &receivetime,
	                 const RTPAddress *senderaddress);
	void OnRTCPCompoundPacket(RTCPCompoundPacket *pack,const RTPTime &receivetime,
	                          const RTPAddress *senderaddress);
	void OnSSRCCollision(RTPSourceData *srcdat,const RTPAddress *senderaddress,bool isrtp);
	void OnCNAMECollision(RTPSourceData *srcdat,const RTPAddress *senderaddress,
	                              const uint8_t *cname,size_t cnamelength);
	void OnNewSource(RTPSourceData *srcdat);
	void OnRemoveSource(RTPSourceData *srcdat);
	void OnTimeout(RTPSourceData *srcdat);
	void OnBYETimeout(RTPSourceData *srcdat);
	void OnBYEPacket(RTPSourceData *srcdat);
	void OnAPPPacket(RTCPAPPPacket *apppacket,const RTPTime &receivetime,
	                 const RTPAddress *senderaddress);
	void OnUnknownPacketType(RTCPPacket *rtcppack,const RTPTime &receivetime,
	                         const RTPAddress *senderaddress);
	void OnUnknownPacketFormat(RTCPPacket *rtcppack,const RTPTime &receivetime,
	                           const RTPAddress *senderaddress);
	void OnNoteTimeout(RTPSourceData *srcdat);
	void OnValidatedRTPPacket(RTPSourceData *srcdat, RTPPacket *rtppack, bool isonprobation, bool *ispackethandled);
	void OnRTCPSenderReport(RTPSourceData *srcdat);
	void OnRTCPReceiverReport(RTPSourceData *srcdat);
	void OnRTCPSDESItem(RTPSourceData *srcdat, RTCPSDESPacket::ItemType t,
	                            const void *itemdata, size_t itemlength);
#ifdef RTP_SUPPORT_SDESPRIV
	void OnRTCPSDESPrivateItem(RTPSourceData *srcdat, const void *prefixdata, size_t prefixlen,
	                                   const void *valuedata, size_t valuelen);
#endif // RTP_SUPPORT_SDESPRIV
	
	RTPSession &rtpsession;
	bool owncollision;
};

} // end namespace

#endif // RTPSESSIONSOURCES_H
