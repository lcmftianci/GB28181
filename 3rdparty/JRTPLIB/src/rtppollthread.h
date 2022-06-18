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
 * \file rtppollthread.h
 */

#ifndef RTPPOLLTHREAD_H

#define RTPPOLLTHREAD_H

#include "rtpconfig.h"

#ifdef RTP_SUPPORT_THREAD

#include "rtptransmitter.h"

#include <jthread/jthread.h>
#include <jthread/jmutex.h>
#include <list>

namespace jrtplib
{

class RTPSession;
class RTCPScheduler;

class JRTPLIB_IMPORTEXPORT RTPPollThread : private jthread::JThread
{
	JRTPLIB_NO_COPY(RTPPollThread)
public:
	RTPPollThread(RTPSession &session,RTCPScheduler &rtcpsched);
	~RTPPollThread();
	int Start(RTPTransmitter *trans);
	void Stop();
private:
	void *Thread();
	
	bool stop;
	jthread::JMutex stopmutex;
	RTPTransmitter *transmitter;
	
	RTPSession &rtpsession;
	RTCPScheduler &rtcpsched;
};

} // end namespace

#endif // RTP_SUPPORT_THREAD

#endif // RTPPOLLTHREAD_H
