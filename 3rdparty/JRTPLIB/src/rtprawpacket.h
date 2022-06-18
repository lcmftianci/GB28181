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
 * \file rtprawpacket.h
 */

#ifndef RTPRAWPACKET_H

#define RTPRAWPACKET_H

#include "rtpconfig.h"
#include "rtptimeutilities.h"
#include "rtpaddress.h"
#include "rtptypes.h"
#include "rtpmemoryobject.h"
#include "rtpstructs.h"

namespace jrtplib
{

/** This class is used by the transmission component to store the incoming RTP and RTCP data in. */
class JRTPLIB_IMPORTEXPORT RTPRawPacket : public RTPMemoryObject
{
	JRTPLIB_NO_COPY(RTPRawPacket)
public:	
    /** Creates an instance which stores data from \c data with length \c datalen.
	 *  Creates an instance which stores data from \c data with length \c datalen. Only the pointer 
	 *  to the data is stored, no actual copy is made! The address from which this packet originated 
	 *  is set to \c address and the time at which the packet was received is set to \c recvtime. 
	 *  The flag which indicates whether this data is RTP or RTCP data is set to \c rtp.
	 *  If you don't know if it's an RTP or RTCP packet, you can use the other constructor which
	 *  tries to determine the type based on the header. A memory manager can be installed as well.
	 */
	RTPRawPacket(uint8_t *data,size_t datalen,RTPAddress *address,RTPTime &recvtime,bool rtp,RTPMemoryManager *mgr = 0);

    /** Creates an instance which stores data from \c data with length \c datalen.
	 *  Creates an instance which stores data from \c data with length \c datalen. Only the pointer 
	 *  to the data is stored, no actual copy is made! The address from which this packet originated 
	 *  is set to \c address and the time at which the packet was received is set to \c recvtime. 
	 *  A memory manager can be installed as well. This is similar to the other constructor where
	 *  you have to specify yourself if the packet is supposed to contain RTP or RTCP data. In this version,
	 *  based on the header information the packet type will be determined.
	 */
	RTPRawPacket(uint8_t *data,size_t datalen,RTPAddress *address,RTPTime &recvtime,RTPMemoryManager *mgr = 0);
	~RTPRawPacket();
	
	/** Returns the pointer to the data which is contained in this packet. */
	uint8_t *GetData()														{ return packetdata; }

	/** Returns the length of the packet described by this instance. */
	size_t GetDataLength() const											{ return packetdatalength; }

	/** Returns the time at which this packet was received. */
	RTPTime GetReceiveTime() const											{ return receivetime; }

	/** Returns the address stored in this packet. */
	const RTPAddress *GetSenderAddress() const								{ return senderaddress; }

	/** Returns \c true if this data is RTP data, \c false if it is RTCP data. */
	bool IsRTP() const														{ return isrtp; }

	/** Sets the pointer to the data stored in this packet to zero.
	 *  Sets the pointer to the data stored in this packet to zero. This will prevent 
	 *  a \c delete call for the actual data when the destructor of RTPRawPacket is called. 
	 *  This function is used by the RTPPacket and RTCPCompoundPacket classes to obtain 
	 *  the packet data (without having to copy it)	and to make sure the data isn't deleted 
	 *  when the destructor of RTPRawPacket is called.
	 */
	void ZeroData()															{ packetdata = 0; packetdatalength = 0; }

	/** Allocates a number of bytes for RTP or RTCP data using the memory manager that
	 *  was used for this raw packet instance, can be useful if the RTPRawPacket::SetData
	 *  function will be used. */
	uint8_t *AllocateBytes(bool isrtp, int recvlen) const;

	/** Deallocates the previously stored data and replaces it with the data that's
	 *  specified, can be useful when e.g. decrypting data in RTPSession::OnChangeIncomingData */
	void SetData(uint8_t *data, size_t datalen);

	/** Deallocates the currently stored RTPAddress instance and replaces it
	 *  with the one that's specified (you probably don't need this function). */
	void SetSenderAddress(RTPAddress *address);
private:
	void DeleteData();

	uint8_t *packetdata;
	size_t packetdatalength;
	RTPTime receivetime;
	RTPAddress *senderaddress;
	bool isrtp;
};

inline RTPRawPacket::RTPRawPacket(uint8_t *data,size_t datalen,RTPAddress *address,RTPTime &recvtime,bool rtp,RTPMemoryManager *mgr):RTPMemoryObject(mgr),receivetime(recvtime)
{
	packetdata = data;
	packetdatalength = datalen;
	senderaddress = address;
	isrtp = rtp;
}

inline RTPRawPacket::RTPRawPacket(uint8_t *data,size_t datalen,RTPAddress *address,RTPTime &recvtime,RTPMemoryManager *mgr):RTPMemoryObject(mgr),receivetime(recvtime)
{
	packetdata = data;
	packetdatalength = datalen;
	senderaddress = address;

	isrtp = true;
	if (datalen >= sizeof(RTCPCommonHeader))
	{
		RTCPCommonHeader *rtcpheader = (RTCPCommonHeader *)data;
		uint8_t packettype = rtcpheader->packettype;

		if (packettype >= 200 && packettype <= 204)
			isrtp = false;
	}
}

inline RTPRawPacket::~RTPRawPacket()
{
	DeleteData();
}

inline void RTPRawPacket::DeleteData()
{
	if (packetdata)
		RTPDeleteByteArray(packetdata,GetMemoryManager());
	if (senderaddress)
		RTPDelete(senderaddress,GetMemoryManager());

	packetdata = 0;
	senderaddress = 0;
}

inline uint8_t *RTPRawPacket::AllocateBytes(bool isrtp, int recvlen) const
{
	JRTPLIB_UNUSED(isrtp); // possibly unused
	return RTPNew(GetMemoryManager(),(isrtp)?RTPMEM_TYPE_BUFFER_RECEIVEDRTPPACKET:RTPMEM_TYPE_BUFFER_RECEIVEDRTCPPACKET) uint8_t[recvlen];
}

inline void RTPRawPacket::SetData(uint8_t *data, size_t datalen)
{
	if (packetdata)
		RTPDeleteByteArray(packetdata,GetMemoryManager());

	packetdata = data;
	packetdatalength = datalen;
}

inline void RTPRawPacket::SetSenderAddress(RTPAddress *address)
{
	if (senderaddress)
		RTPDelete(senderaddress, GetMemoryManager());

	senderaddress = address;
}

} // end namespace

#endif // RTPRAWPACKET_H

