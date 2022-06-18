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
 * \file rtptcpaddress.h
 */

#ifndef RTPTCPADDRESS_H

#define RTPTCPADDRESS_H

#include "rtpconfig.h"
#include "rtpaddress.h"
#include "rtptypes.h"
#include "rtpsocketutil.h"

namespace jrtplib
{

class RTPMemoryManager;

/** Represents a TCP 'address' and port.
 *  This class is used by the TCP transmission component, to specify which sockets
 *  should be used to send/receive data, and to know on which socket incoming data
 *  was received.
 */
class JRTPLIB_IMPORTEXPORT RTPTCPAddress : public RTPAddress
{
public:
	/** Creates an instance with which you can use a specific socket
	 *  in the TCP transmitter (must be connected). */
	RTPTCPAddress(SocketType sock):RTPAddress(TCPAddress)	
	{ 
		m_socket = sock;
	}

	~RTPTCPAddress()																				{ }

	/** Returns the socket that was specified in the constructor. */
	SocketType GetSocket() const																	{ return m_socket; }

	RTPAddress *CreateCopy(RTPMemoryManager *mgr) const;

	// Note that these functions are only used for received packets
	bool IsSameAddress(const RTPAddress *addr) const;
	bool IsFromSameHost(const RTPAddress *addr) const;
#ifdef RTPDEBUG
	std::string GetAddressString() const;
#endif // RTPDEBUG
private:
	SocketType m_socket;
};

} // end namespace

#endif // RTPTCPADDRESS_H

