namespace jrtplib // So that links are created automatically
{

/**

\htmlonly
<style type="text/css">
body {
    counter-reset: section;
}

h2 {
    counter-increment: section;
    counter-reset: subsection;
}

h3 {
    counter-increment: subsection;
    counter-reset: subsubsection;
}

h4 {
    counter-increment: subsubsection;
}

h2:before {
    content: counter(section) ". ";
}

h3:before {
    content: counter(section) "." counter(subsection) " ";
}

h4:before {
    content: counter(section) "." counter(subsection) "." counter(subsubsection) " ";
}
</style>
\endhtmlonly

\mainpage JRTPLIB

\author Jori Liesenborgs
\author Developed at the the [Expertise Centre for Digital Media (EDM)](http://www.edm.uhasselt.be), 
a research institute of the [Hasselt University](http://www.uhasselt.be)

Introduction
------------
    
This document describes JRTPLIB, an object-oriented
library written in C++ which aims to help developers in using the 
Real-time Transport Protocol (RTP) as described in [RFC 3550](https://www.ietf.org/rfc/rfc3550.txt).

The library makes it possible for the user to send and receive data
using RTP, without worrying about SSRC collisions, scheduling and
transmitting RTCP data etc. The user only needs to provide the library
with the payload data to be sent and the library gives the user access
to incoming RTP and RTCP data.

### Design idea ###
        
The library provides several classes which can be helpful in
creating RTP applications. Most users will probably only need the
RTPSession class for building an application, or derive a class
from RTPSecureSession for SRTP support. These classes
provide the necessary functions for sending RTP data and handle
the RTCP part internally.

### Changes from version 2.x ###

One of the most important changes is probably the fact that this
version is based on RFC 3550 and the 2.x versions were based upon
RFC 1889 which is now obsolete.

Also, the 2.x series was created with the idea that the user would
only need to use the RTPSession class which meant that the
other classes were not very useful by themselves. This version on
the other hand, aims to provide many useful components to aid the
user in building RTP capable applications.

In this version, the code which is specific for the underlying
protocol by which RTP packets are transported, is bundled in
a class which inherits its interface from a class called
RTPTransmitter. This makes it easy for different underlying
protocols to be supported. Currently there is support for UDP over
IPv4 and UDP over IPv6.

For applications such as a mixer or translator using the
RTPSession class will not be a good solution. Other components can
be used for this purpose: a transmission component, an SSRC table,
an RTCP scheduler etc. Using these, it should be much easier to
build all kinds of applications.

Copyright license
-----------------
    
The library code uses the following copyright license:

~~~{.c}
    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation files
    (the "Software"), to deal in the Software without restriction,
    including without limitation the rights to use, copy, modify, merge,
    publish, distribute, sublicense, and/or sell copies of the Software,
    and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
    KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
    BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
    ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
~~~

There are two reasons for using this license. First, since this is the
license of the 2.x series, it only seemed natural that this rewrite
would contain the same license. Second, since the RTP protocol is
deliberately incomplete RTP profiles can, for example, define additional
header fields. The best way to deal with this is to adapt the library
code itself and that's why I like to keep the license as free as
possible.

Getting started with the RTPSession class
-----------------------------------------
    
All classes and functions are part of the `jrtplib` namespace, so to
simplify the code a bit, we'll declare that we're using this namespace:

~~~{.cpp}
    using namespace jrtplib;
~~~
    
To use RTP, you'll have to create an RTPSession object. The constructor
accepts two parameter, an instance of an RTPRandom object, and an instance 
of an RTPMemoryManager object. For now, we'll keep it simple and use the
default settings, so this is our code so far:

~~~{.cpp}
    RTPSession session; 
~~~

To actually create the session, you'll have to call the Create member 
function which takes three arguments: the first one is of type RTPSessionParams 
and specifies the general options for the session. One parameter of this class 
must be set explicitly, otherwise the session will not be created successfully. 
This parameter is the timestamp unit of the data you intend to send and
can be calculated by dividing a certain time interval (in seconds) by the 
number of samples in that interval. So, assuming that we'll send 8000 Hz 
voice data, we can use this code:

~~~{.cpp}
    RTPSessionParams sessionparams;

    sessionparams.SetOwnTimestampUnit(1.0/8000.0);
~~~

The other session parameters will probably depend on the actual RTP profile
you intend to work with. 

The second argument of the Create function is a pointer to an RTPTransmissionParams 
instance and describes the parameters for the transmission component. The third
parameter selects the type of transmission component which will be used. By default,
an UDP over IPv4 transmitter is used, and for this particular transmitter, the
transmission parameters should be of type RTPUDPv4TransmissionParams. Assuming 
that we want our RTP portbase to be 8000, we can do the following:

~~~{.cpp}
    RTPUDPv4TransmissionParams transparams;

    transparams.SetPortbase(8000);
~~~

Now, we're ready to call the Create member function of RTPSession. The return 
value is stored in the integer `status` so we can check if something went 
wrong. If this value is negative, it indicates that some error occurred. 
A description of what this error code means can be retrieved by calling
RTPGetErrorString:

~~~{.cpp}
    int status = session.Create(sessionparams,&transparams);
    if (status < 0)
    {
        std::cerr << RTPGetErrorString(status) << std::endl;
        exit(-1);
    }
~~~

If the session was created with success, this is probably a good point 
to specify to which destinations RTP and RTCP data should be sent. This is 
done by a call to the RTPSession member function AddDestination. This 
function takes an argument of type RTPAddress. This is an abstract 
class and for the UDP over IPv4 transmitter the actual class to be 
used is RTPIPv4Address. Suppose that we want to send our data to a 
process running on the same host at port 9000, we can do the following:
    
~~~{.cpp}
    uint8_t localip[]={127,0,0,1};
    RTPIPv4Address addr(localip,9000);

    status = session.AddDestination(addr);
    if (status < 0)
    {
        std::cerr << RTPGetErrorString(status) << std::endl;
        exit(-1);
    }
~~~

If the library was compiled with JThread support, incoming data is
processed in the background. If JThread support was not enabled at
compile time or if you specified in the session parameters that no
poll thread should be used, you'll have to call the RTPSession
member function Poll regularly to process incoming data and to send 
RTCP data when necessary. For now, let's assume that we're working 
with the poll thread enabled.

Lets suppose that for a duration of one minute, we want to send
packets containing 20 ms (or 160 samples) of silence and we want
to indicate when a packet from someone else has been received. Also
suppose we have L8 data as defined in RFC 3551 and want to use
payload type 96. First, we'll set some default values:
    
~~~{.cpp}
    session.SetDefaultPayloadType(96);
    session.SetDefaultMark(false);
    session.SetDefaultTimestampIncrement(160);
~~~

Next, we'll create the buffer which contains 160 silence samples
and create an RTPTime instance which indicates 20 ms or 0.020 seconds.
We'll also store the current time so we'll know    when one minute has 
passed.
    
~~~{.cpp}
    uint8_t silencebuffer[160];

    for (int i = 0 ; i < 160 ; i++)
        silencebuffer[i] = 128;

    RTPTime delay(0.020);
    RTPTime starttime = RTPTime::CurrentTime();
~~~

Next, the main loop will be shown. In this loop, a packet containing
160 bytes of payload data will be sent. Then, data handling can
take place but this part is described later in the text. Finally,
we'll wait 20 ms and check if sixty seconds have passed:
    
~~~{.cpp}
    bool done = false;
    while (!done)
    {
        status = session.SendPacket(silencebuffer,160);
        if (status < 0)
        {
            std::cerr << RTPGetErrorString(status) << std::endl;
            exit(-1);
        }
        
        //
        // Inspect incoming data here
        //
        
        RTPTime::Wait(delay);
        
        RTPTime t = RTPTime::CurrentTime();
        t -= starttime;
        if (t > RTPTime(60.0))
            done = true;
    }
~~~

Information about participants in the session, packet retrieval
etc, can be done between calls to the RTPSession member
functions RTPSession::BeginDataAccess and RTPSession::EndDataAccess. 
This ensures that the background thread doesn't try to change the same 
data you're trying 
to access. We'll iterate over the participants using the 
RTPSession::GotoFirstSource and RTPSession::GotoNextSource member functions. 
Packets from 
the currently selected participant can be retrieved using the 
RTPSession::GetNextPacket member function which returns a pointer to an 
instance of the RTPPacket class. When you don't need the packet 
anymore, it has to be deleted. The processing of incoming data will 
then be as follows:
    
~~~{.cpp}
    session.BeginDataAccess();
    if (session.GotoFirstSource())
    {
        do
        {
            RTPPacket *packet;
            while ((packet = session.GetNextPacket()) != 0)
            {
                std::cout << "Got packet with extended sequence number " 
                          << packet->GetExtendedSequenceNumber() 
                          << " from SSRC " << packet->GetSSRC() 
                          << std::endl;
                session.DeletePacket(packet);
            }
        } while (session.GotoNextSource());
    }
    session.EndDataAccess();
~~~

Information about the currently selected source can be obtained
by using the GetCurrentSourceInfo member function of the RTPSession class. 
This function returns a pointer to an instance of  RTPSourceData which 
contains all information about that source: sender reports from that 
source, receiver reports, SDES info etc. 

Alternatively, packets can also be handled directly, without iterating
over the sources, by overriding the RTPSession::OnValidatedRTPPacket
member function. The example code in `example6.cpp` illustrates this
approach.

When the main loop is finished, we'll send a BYE packet to inform other 
participants of our departure and clean up the RTPSession class. Also, 
we want to wait at most 10 seconds for the BYE packet to be sent, 
otherwise we'll just leave the session without sending a BYE packet.
    
~~~{.cpp}
    delay = RTPTime(10.0);
    session.BYEDestroy(delay,"Time's up",9);
~~~
    
The complete code of the program is given in `example2.cpp`.

SRTP support
------------

Support for Secure RTP (SRTP) is provided through the RTPSecureSession
class, which used [libsrtp](https://github.com/cisco/libsrtp) for
encryption/decryption of the data. This class itself is not meant to provide 
a complete ready-to-use solution, since there's a wide variety of options
that can be configured in `libsrtp`.

Instead, the class provides a means to initialize a `libsrtp`-context,
which you can then obtain and configure further for your needs. Incoming
and outgoing packets will be decrypted and encrypted respectively, using
the context that was constructed and completed this way.

The example code in `example7.cpp` illustrates the use of this class, where
a single key for sender and receiver is used, together with the default
encryption algorithm.

Error codes
-----------

Unless specified otherwise, functions with a return type `int`
will return a negative value when an error occurred and zero or a
positive value upon success. A description of the error code can
be obtained by using the RTPGetErrorString function, declared 
in rtperrors.h                                            

Memory management
-----------------

You can write you own memory manager by deriving a class from RTPMemoryManager.
The following example shows a very basic implementation.
    
~~~{.cpp}
    class MyMemoryManager : public RTPMemoryManager
    {
    public:
        MyMemoryManager() { }
        ~MyMemoryManager() { }
        
        void *AllocateBuffer(size_t numbytes, int memtype)
        {
            return malloc(numbytes);
        }

        void FreeBuffer(void *p)
        {
            free(p);
        }
    };
~~~

In the constructor of RTPSession, you can specify that you would like to use
this memory manager:
    
~~~{.cpp}
    MyMemoryManager mgr;
    RTPSession session(0, &mgr);
~~~

Now, all memory allocation and deallocation will be done using the `AllocateBuffer`
and `FreeBuffer` implementations of `mgr`.

The second parameter of the RTPMemoryManager::AllocateBuffer member function
indicates what the purpose is of this memory block. This allows you to handle
different kinds of data in different ways.

With the introduction of the memory management system, the RTPSession class was
extended with member function RTPSession::DeletePacket and RTPSession::DeleteTransmissionInfo.
These functions should be used to deallocate RTPPacket instances and RTPTransmissionInfo
instances respectively.

Acknowledgment
--------------

I would like thank the people at the Expertise Centre for Digital Media
for giving me the opportunity to create this rewrite of the library.
Special thanks go to Wim Lamotte for getting me started on the RTP
journey many years ago.

Contact
-------

If you have any questions, remarks or requests about the library or
if you think you've discovered a bug, you can contact me at
`jori(dot)liesenborgs(at)gmail(dot)com`

The home page of the library is
http://research.edm.uhasselt.be/jori/jrtplib/jrtplib.html

*/

}
