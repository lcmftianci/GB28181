/*

    This file is a part of the JThread package, which contains some object-
    oriented thread wrappers for different thread implementations.

    Copyright (c) 2000-2017  Jori Liesenborgs (jori.liesenborgs@gmail.com)

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*/

#include "jmutex.h"

namespace jthread
{

JMutex::JMutex()
{
	initialized = false;
}

JMutex::~JMutex()
{
	if (initialized)
#ifdef JTHREAD_CONFIG_JMUTEXCRITICALSECTION
		DeleteCriticalSection(&mutex);
#else
		CloseHandle(mutex);
#endif // JTHREAD_CONFIG_JMUTEXCRITICALSECTION
}

int JMutex::Init()
{
	if (initialized)
		return ERR_JMUTEX_ALREADYINIT;
#ifdef JTHREAD_CONFIG_JMUTEXCRITICALSECTION
	InitializeCriticalSection(&mutex);
#else
	mutex = CreateMutex(NULL,FALSE,NULL);
	if (mutex == NULL)
		return ERR_JMUTEX_CANTCREATEMUTEX;
#endif // JTHREAD_CONFIG_JMUTEXCRITICALSECTION
	initialized = true;
	return 0;
}

int JMutex::Lock()
{
	if (!initialized)
		return ERR_JMUTEX_NOTINIT;
#ifdef JTHREAD_CONFIG_JMUTEXCRITICALSECTION
	EnterCriticalSection(&mutex);
#else
	WaitForSingleObject(mutex,INFINITE);
#endif // JTHREAD_CONFIG_JMUTEXCRITICALSECTION
	return 0;
}

int JMutex::Unlock()
{
	if (!initialized)
		return ERR_JMUTEX_NOTINIT;
#ifdef JTHREAD_CONFIG_JMUTEXCRITICALSECTION
	LeaveCriticalSection(&mutex);
#else
	ReleaseMutex(mutex);
#endif // JTHREAD_CONFIG_JMUTEXCRITICALSECTION
	return 0;
}

} // end namespace
