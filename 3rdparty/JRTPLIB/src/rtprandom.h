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
 * \file rtprandom.h
 */

#ifndef RTPRANDOM_H

#define RTPRANDOM_H

#include "rtpconfig.h"
#include "rtptypes.h"
#include <stdlib.h>

#define RTPRANDOM_2POWMIN63										1.08420217248550443400745280086994171142578125e-19

namespace jrtplib
{

/** Interface for generating random numbers. */
class JRTPLIB_IMPORTEXPORT RTPRandom
{
public:
	RTPRandom()											{ }
	virtual ~RTPRandom()										{ }

	/** Returns a random eight bit value. */
	virtual uint8_t GetRandom8() = 0;

	/** Returns a random sixteen bit value. */
	virtual uint16_t GetRandom16() = 0;

	/** Returns a random thirty-two bit value. */
	virtual uint32_t GetRandom32() = 0;

	/** Returns a random number between $0.0$ and $1.0$. */
	virtual double GetRandomDouble() = 0;

	/** Can be used by subclasses to generate a seed for a random number generator. */
	uint32_t PickSeed();

	/** Allocate a default random number generator based on your platform. */
	static RTPRandom *CreateDefaultRandomNumberGenerator();
};

} // end namespace

#endif // RTPRANDOM_H

