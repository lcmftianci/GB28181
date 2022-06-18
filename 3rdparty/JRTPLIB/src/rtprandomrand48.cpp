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

#include "rtprandomrand48.h"

namespace jrtplib
{

RTPRandomRand48::RTPRandomRand48()
{
	SetSeed(PickSeed());
}

RTPRandomRand48::RTPRandomRand48(uint32_t seed)
{
	SetSeed(seed);
}

RTPRandomRand48::~RTPRandomRand48()
{
}

void RTPRandomRand48::SetSeed(uint32_t seed)
{
#ifdef RTP_SUPPORT_THREAD
	mutex.Init(); // TODO: check error!
#endif // RTP_SUPPORT_THREAD

#ifdef RTP_HAVE_VSUINT64SUFFIX
	state = ((uint64_t)seed) << 16 | 0x330Eui64;
#else
	state = ((uint64_t)seed) << 16 | 0x330EULL;
#endif // RTP_HAVE_VSUINT64SUFFIX
}

uint8_t RTPRandomRand48::GetRandom8()
{
	uint32_t x =  ((GetRandom32() >> 24)&0xff);

	return (uint8_t)x;
}

uint16_t RTPRandomRand48::GetRandom16()
{
	uint32_t x =  ((GetRandom32() >> 16)&0xffff);

	return (uint16_t)x;
}

uint32_t RTPRandomRand48::GetRandom32()
{
#ifdef RTP_SUPPORT_THREAD
	mutex.Lock();
#endif // RTP_SUPPORT_THREAD

#ifdef RTP_HAVE_VSUINT64SUFFIX
	state = ((0x5DEECE66Dui64*state) + 0xBui64)&0x0000ffffffffffffui64;

	uint32_t x = (uint32_t)((state>>16)&0xffffffffui64);
#else
	state = ((0x5DEECE66DULL*state) + 0xBULL)&0x0000ffffffffffffULL;

	uint32_t x = (uint32_t)((state>>16)&0xffffffffULL);
#endif // RTP_HAVE_VSUINT64SUFFIX

#ifdef RTP_SUPPORT_THREAD
	mutex.Unlock();
#endif // RTP_SUPPORT_THREAD
	return x;
}

double RTPRandomRand48::GetRandomDouble()
{
#ifdef RTP_SUPPORT_THREAD
	mutex.Lock();
#endif // RTP_SUPPORT_THREAD

#ifdef RTP_HAVE_VSUINT64SUFFIX
	state = ((0x5DEECE66Dui64*state) + 0xBui64)&0x0000ffffffffffffui64;

	int64_t x = (int64_t)state;
#else
	state = ((0x5DEECE66DULL*state) + 0xBULL)&0x0000ffffffffffffULL;

	int64_t x = (int64_t)state;
#endif // RTP_HAVE_VSUINT64SUFFIX

#ifdef RTP_SUPPORT_THREAD
	mutex.Unlock();
#endif // RTP_SUPPORT_THREAD
	double y = 3.552713678800500929355621337890625e-15 * (double)x;
	return y;
}

} // end namespace

