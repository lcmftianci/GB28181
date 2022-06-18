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

#include "rtpconfig.h"
#include "rtpsessionparams.h"
#include "rtpdefines.h"
#include "rtperrors.h"

#include "rtpdebug.h"

namespace jrtplib
{

RTPSessionParams::RTPSessionParams() : mininterval(0,0)
{
#ifdef RTP_SUPPORT_THREAD
	usepollthread = true;
	m_needThreadSafety = true;
#else
	usepollthread = false;
	m_needThreadSafety = false;
#endif // RTP_SUPPORT_THREAD
	maxpacksize = RTP_DEFAULTPACKETSIZE;
	receivemode = RTPTransmitter::AcceptAll;
	acceptown = false;
	owntsunit = -1; // The user will have to set it to the correct value himself
	resolvehostname = false;
#ifdef RTP_SUPPORT_PROBATION
	probationtype = RTPSources::ProbationStore;
#endif // RTP_SUPPORT_PROBATION

	mininterval = RTPTime(RTCP_DEFAULTMININTERVAL);
	sessionbandwidth = RTP_DEFAULTSESSIONBANDWIDTH;
	controlfrac = RTCP_DEFAULTBANDWIDTHFRACTION;
	senderfrac = RTCP_DEFAULTSENDERFRACTION;
	usehalfatstartup = RTCP_DEFAULTHALFATSTARTUP;
	immediatebye = RTCP_DEFAULTIMMEDIATEBYE;
	SR_BYE = RTCP_DEFAULTSRBYE;

	sendermultiplier = RTP_SENDERTIMEOUTMULTIPLIER;
	generaltimeoutmultiplier = RTP_MEMBERTIMEOUTMULTIPLIER;
	byetimeoutmultiplier = RTP_BYETIMEOUTMULTIPLIER;
	collisionmultiplier = RTP_COLLISIONTIMEOUTMULTIPLIER;
	notemultiplier = RTP_NOTETTIMEOUTMULTIPLIER;
	
	usepredefinedssrc = false;
	predefinedssrc = 0;
}

int RTPSessionParams::SetUsePollThread(bool usethread)
{
#ifndef RTP_SUPPORT_THREAD
	JRTPLIB_UNUSED(usethread);
	return ERR_RTP_NOTHREADSUPPORT;
#else
	usepollthread = usethread;
	return 0;
#endif // RTP_SUPPORT_THREAD
}

int RTPSessionParams::SetNeedThreadSafety(bool s)
{
#ifndef RTP_SUPPORT_THREAD
	JRTPLIB_UNUSED(s);
	return ERR_RTP_NOTHREADSUPPORT;
#else
	m_needThreadSafety = s;
	return 0;
#endif // RTP_SUPPORT_THREAD
}

} // end namespace

