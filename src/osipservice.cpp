#include "rtpsession.h"
#include "rtppacket.h"
#include "rtpudpv4transmitter.h"
#include "rtpipv4address.h"
#include "rtpsessionparams.h"
#include "rtperrors.h"
#include "rtpsourcedata.h"

#ifndef WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif // WIN32
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <mxml.h>
#include <time.h>
#include <process.h>
#include <eXosip2/eXosip.h>
#include "filenameio.h"

using namespace jrtplib;

#if 0
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mxml1.lib")
#pragma comment(lib, "eXosip.lib")
#pragma comment(lib, "libcares.lib")
#pragma comment(lib, "osip2.lib")
#pragma comment(lib, "osipparser2.lib")
#endif

#ifdef _WIN32
//Dnsapi.lib;Iphlpapi.lib;ws2_32.lib;eXosip.lib;osip2.lib;osipparser2.lib;Qwave.lib;libcares.lib;delayimp.lib;
//ignore libcmt.lib
#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Qwave.lib")
#pragma comment(lib,"WS2_32.lib")
#pragma comment(lib, "delayimp.lib")
#endif

#if 0
#ifdef DEBUG
#pragma comment(lib, "jrtplib_d.lib") 
#pragma comment(lib,"jthread_d.lib")
#pragma comment(lib,"WS2_32.lib")
#else
#pragma comment(lib, "jrtplib.lib") 
#pragma comment(lib,"jthread.lib")
#endif
#endif 

#define APREFIX_NONE   "\033[0m"
#define APREFIX_RED    "\033[0;31m"
#define APREFIX_GREEN  "\033[0;32m"
#define APREFIX_YELLOW "\033[1;33m"

#define APP_DEBUG(format, args) printf(APREFIX_GREEN"DEBUG : FILE -> %s, %s, LINE -> %d :"  format APREFIX_NONE"\n", __FILE__, __FUNCTION__, __LINE__, ## args)
#define APP_WARRING(format, args) printf(APREFIX_YELLOW"WARRING : FILE -> %s, %s, LINE -> %d :"  format APREFIX_NONE"\n", __FILE__, __FUNCTION__, __LINE__, ## args)
#define APP_ERR(format, args) printf(APREFIX_RED"ERR : FILE -> %s, %s, LINE -> %d :"  format APREFIX_NONE"\n", __FILE__, __FUNCTION__, __LINE__, ## args)

#define CAMERA_SUPPORT_MAX      500
#define RTP_MAXBUF          4096
#define PS_BUF_SIZE         (1024*1024*4)
#define H264_FRAME_SIZE_MAX (1024*1024*2)

typedef struct _gb28181Params{
	char platformSipId[MAX_PATH];
	char platformIpAddr[MAX_PATH];
	int platformSipPort;
	char localSipId[MAX_PATH];
	char localIpAddr[MAX_PATH];
	int localSipPort;
	int SN;
	struct eXosip_t *eCtx;
	int call_id;
	int dialog_id;
	int registerOk;
	int running;
} gb28181Params;

typedef struct {
	char sipId[MAX_PATH];
	char UserName[MAX_PATH];
	char UserPwd[MAX_PATH];
	int recvPort;
	int status;
	int statusErrCnt;
	FILE *fpH264;
	int running;
} CameraParams;

typedef struct _liveVideoStreamParams{
	int cameraNum;
	CameraParams *pCameraParams;
	gb28181Params gb28181Param;
	int stream_input_type;
	int running;
} liveVideoStreamParams;

#if 1
#ifndef uint16_t
typedef unsigned short uint16_t;
#endif
#ifndef uint32_t
typedef unsigned int uint32_t;
#endif
//#ifndef uint64_t
//typedef unsigned int uint64_t;
//#endif

typedef struct RTP_HEADER
{
	uint16_t cc : 4;
	uint16_t extbit : 1;
	uint16_t padbit : 1;
	uint16_t version : 2;
	uint16_t paytype : 7;  //payload type
	uint16_t markbit : 1;  //1 decode unit,0 not end
	uint16_t seq_number;  //sirial number
	uint32_t timestamp; //
	uint32_t ssrc;  //ssrc
	//uint32_t csrc[16];
} RTP_header_t;
#elif

typedef struct PTR_HEADER
{
	unsigned int cc : 4;
	unsigned int extbit : 1;
	unsigned int padbit : 1;
	unsigned int version : 2;
	unsigned int paytype : 7;  //负载类型
	unsigned int markbit : 1;  //1表示前面的包为一个解码单元,0表示当前解码单元未结束
	unsigned int seq_number;  //序号
	unsigned int timestamp; //时间戳
	unsigned int ssrc;  //循环校验码
}RTP_header_t;

#endif

#pragma pack (1)
typedef union littel_endian_size_s {
	unsigned short int	length;
	unsigned char		byte[2];
} littel_endian_size;

typedef struct pack_start_code_s {
	unsigned char start_code[3];
	unsigned char stream_id[1];
} pack_start_code;

typedef struct program_stream_pack_header_s {
	pack_start_code PackStart;// 4
	unsigned char Buf[9];
	unsigned char stuffinglen;
} program_stream_pack_header;

typedef struct program_stream_map_s {
	pack_start_code PackStart;
	littel_endian_size PackLength;//we mast do exchange
} program_stream_map;

typedef struct program_stream_e_s {
	pack_start_code		PackStart;
	littel_endian_size	PackLength;//we mast do exchange
	char				PackInfo1[2];
	unsigned char		stuffing_length;
} program_stream_e;


//camera info stream info
liveVideoStreamParams g_liveVideoParams;

FILE *g_fp;


static void RegisterSuccess(struct eXosip_t * peCtx, eXosip_event_t *je)
{
	int iReturnCode = 0;
	osip_message_t * pSRegister = NULL;
	iReturnCode = eXosip_message_build_answer(peCtx, je->tid, 200, &pSRegister);
	if (iReturnCode == 0 && pSRegister != NULL)
	{
		eXosip_lock(peCtx);
		eXosip_message_send_answer(peCtx, je->tid, 200, pSRegister);
		eXosip_unlock(peCtx);
		//osip_message_free(pSRegister);
	}
}

void RegisterFailed(struct eXosip_t * peCtx, eXosip_event_t *je)
{
	int iReturnCode = 0;
	osip_message_t * pSRegister = NULL;
	iReturnCode = eXosip_message_build_answer(peCtx, je->tid, 401, &pSRegister);
	if (iReturnCode == 0 && pSRegister != NULL)
	{
		eXosip_lock(peCtx);
		eXosip_message_send_answer(peCtx, je->tid, 401, pSRegister);
		eXosip_unlock(peCtx);
	}
}


//config
static int ParserIniFile()
{
	std::string strIniPath = GetMoudlePath();
	strIniPath += "GB28181.ini";
	::GetPrivateProfileString("GB28181", "platform_id", "error", g_liveVideoParams.gb28181Param.platformSipId, MAX_PATH, strIniPath.c_str());	//platform id
	g_liveVideoParams.gb28181Param.platformSipPort = GetPrivateProfileInt("GB28181", "platform_port", 0, strIniPath.c_str());					//platform port
	::GetPrivateProfileString("GB28181", "platform_ip", "error", g_liveVideoParams.gb28181Param.platformIpAddr, MAX_PATH, strIniPath.c_str());	//platform ip
	::GetPrivateProfileString("GB28181", "local_id", "error", g_liveVideoParams.gb28181Param.localSipId, MAX_PATH, strIniPath.c_str());		//local id
	g_liveVideoParams.gb28181Param.localSipPort = GetPrivateProfileInt("GB28181", "local_port", 0, strIniPath.c_str());						//local post
	::GetPrivateProfileString("GB28181", "local_ip", "error", g_liveVideoParams.gb28181Param.localIpAddr, MAX_PATH, strIniPath.c_str());		//platform id
	g_liveVideoParams.cameraNum = GetPrivateProfileInt("GB28181", "camera_num", 0, strIniPath.c_str());										//camera number

	if (g_liveVideoParams.cameraNum > 0 && g_liveVideoParams.cameraNum < CAMERA_SUPPORT_MAX) {
		g_liveVideoParams.pCameraParams = (CameraParams *)malloc(sizeof(CameraParams)*g_liveVideoParams.cameraNum);
		if (g_liveVideoParams.pCameraParams == NULL) {
			fprintf(g_fp, "malloc, failed");
			return -1;
		}
		memset(g_liveVideoParams.pCameraParams, 0, sizeof(CameraParams)*g_liveVideoParams.cameraNum);
		CameraParams *p;

		p = g_liveVideoParams.pCameraParams;

		GetPrivateProfileString("GB28181", "camera1_sip_id", "", p->sipId, MAX_PATH, strIniPath.c_str());
		p->recvPort = GetPrivateProfileInt("GB28181", "camera1_recv_port", 0, strIniPath.c_str());

		//camera name id pwd
		GetPrivateProfileString("GB28181", "UserPwd", "", p->UserPwd, MAX_PATH, strIniPath.c_str());
		GetPrivateProfileString("GB28181", "UserName", "", p->UserName, MAX_PATH, strIniPath.c_str());
	}

	g_liveVideoParams.gb28181Param.SN = 1;
	g_liveVideoParams.gb28181Param.call_id = -1;
	g_liveVideoParams.gb28181Param.dialog_id = -1;
	g_liveVideoParams.gb28181Param.registerOk = 0;

	fprintf(g_fp, "load config ok");

	printf("==>>platform sipid:%s\n", g_liveVideoParams.gb28181Param.platformSipId);
	printf("==>>platform addr:%s\n", g_liveVideoParams.gb28181Param.platformIpAddr);
	printf("==>>local sipid:%s\n", g_liveVideoParams.gb28181Param.localSipId);
	printf("==>>local adddr:%s\n", g_liveVideoParams.gb28181Param.localIpAddr);

	return 0;
}

//transfer msg with camera
static void *MsgProcess(gb28181Params *p28181Params, void * pvSClientGB)
{
	char *p;
	int keepAliveFlag = 0;
	struct eXosip_t * peCtx = (struct eXosip_t *)pvSClientGB;

	//listen camera message and reply
	while (p28181Params->running)
	{
		eXosip_event_t *je = NULL;
		//process event
		je = eXosip_event_wait(peCtx, 0, 4);
		if (je == NULL)
		{
			osip_usleep(100000);
			continue;
		}

		switch (je->type)
		{
			case EXOSIP_MESSAGE_NEW:				//new message
			{
				fprintf(g_fp, "new msg method:%s\n", je->request->sip_method);
				if (MSG_IS_REGISTER(je->request))
				{
					//APP_DEBUG("recv Register");
					fprintf(g_fp, "recv Register");
					g_liveVideoParams.gb28181Param.registerOk = 1;
				}
				else if (MSG_IS_MESSAGE(je->request))
				{
					osip_body_t *body = NULL;
					osip_message_get_body(je->request, 0, &body);
					if (body != NULL)
					{
						p = strstr(body->body, "Keepalive");
						if (p != NULL)
						{
							if (keepAliveFlag == 0)
							{
								fprintf(g_fp, "msg body:%s\n", body->body);
								keepAliveFlag = 1;
								g_liveVideoParams.gb28181Param.registerOk = 1;
							}
						}
						else
						{
							fprintf(g_fp, "msg body:%s\n", body->body);
						}
					}
					else
					{
						// APP_ERR("get body failed");
						fprintf(g_fp, "get body failed");
					}
				}
				else if (strncmp(je->request->sip_method, "BYE", 4) != 0)
				{
					fprintf(g_fp, "unsupport new msg method : %s", je->request->sip_method);
				}
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_MESSAGE_ANSWERED:				//query
			{
				fprintf(g_fp, "answered method:%s\n", je->request->sip_method);
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_ANSWERED:
			{
				osip_message_t *ack = NULL;
				p28181Params->call_id = je->cid;
				p28181Params->dialog_id = je->did;
				fprintf(g_fp, "call answered method:%s, call_id:%d, dialog_id:%d\n", je->request->sip_method, p28181Params->call_id, p28181Params->dialog_id);
				eXosip_call_build_ack(peCtx, je->did, &ack);
				eXosip_lock(peCtx);
				eXosip_call_send_ack(peCtx, je->did, ack);
				eXosip_unlock(peCtx);
				break;
			}
			case EXOSIP_CALL_PROCEEDING:
			{
				fprintf(g_fp, "recv EXOSIP_CALL_PROCEEDING\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_REQUESTFAILURE:
			{
				printf("recv EXOSIP_CALL_REQUESTFAILURE\n");
				fprintf(g_fp, "recv EXOSIP_CALL_REQUESTFAILURE\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_MESSAGE_ANSWERED:
			{
				printf("recv EXOSIP_CALL_MESSAGE_ANSWERED\n");
				//fprintf(g_fp, "recv EXOSIP_CALL_MESSAGE_ANSWERED\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_RELEASED:         //camera reply ok
			{
				printf("recv EXOSIP_CALL_RELEASED\n");
				RegisterSuccess(peCtx, je);
				break;
			}
			case EXOSIP_CALL_CLOSED:
				printf("recv EXOSIP_CALL_CLOSED\n");
				RegisterSuccess(peCtx, je);
				break;
			case EXOSIP_CALL_MESSAGE_NEW:
				printf("recv EXOSIP_CALL_MESSAGE_NEW\n");
				RegisterSuccess(peCtx, je);
				break;
			default:
				printf("##test,%s:%d, unsupport type:%d\n", __FILE__, __LINE__, je->type);
				RegisterSuccess(peCtx, je);
				break;
		}
		eXosip_event_free(je);
	}

	return NULL;
}

//init udp socket
int init_udpsocket(int port, struct sockaddr_in *servaddr, char *mcast_addr)
{
	int err = -1;
	int socket_fd;

	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0)
	{
		APP_ERR("socket failed, port:%d", port);
		return -1;
	}

	memset(servaddr, 0, sizeof(struct sockaddr_in));
	servaddr->sin_family = AF_INET;
	servaddr->sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr->sin_port = htons(port);

	err = bind(socket_fd, (struct sockaddr*)servaddr, sizeof(struct sockaddr_in));
	if (err < 0)
	{
		APP_ERR("bind failed, port:%d", port);
		return -2;
	}

	/*set enable MULTICAST LOOP */
	int loop = 4*1024*1024;
	err = setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, (const char*)&loop, sizeof(loop));
	//err = setsockopt(socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	if (err < 0)
	{
		APP_ERR("setsockopt IP_MULTICAST_LOOP failed, port:%d", port);
		return -3;
	}

	return socket_fd;
}

//close socket
void release_udpsocket(int socket_fd, char *mcast_addr)
{
	closesocket(socket_fd);
}

int inline ProgramStreamPackHeader(char* Pack, int length, char **NextPack, int *leftlength)
{
	//printf("[%s]%x %x %x %x\n", __FUNCTION__, Pack[0], Pack[1], Pack[2], Pack[3]);
	//00 00 01 ba
	program_stream_pack_header *PsHead = (program_stream_pack_header *)Pack;
	unsigned char pack_stuffing_length = PsHead->stuffinglen & '\x07';

	*leftlength = length - sizeof(program_stream_pack_header)-pack_stuffing_length;//remove head
	*NextPack = Pack + sizeof(program_stream_pack_header)+pack_stuffing_length;
	if (*leftlength<4)
		return 0;

	return *leftlength;
}


inline int ProgramStreamMap(char* Pack, int length, char **NextPack, int *leftlength, char **PayloadData, int *PayloadDataLen)
{
	program_stream_map* PSMPack = (program_stream_map*)Pack;

	//no payload
	*PayloadData = 0;
	*PayloadDataLen = 0;

	if ((unsigned int)length < sizeof(program_stream_map)) return 0;

	littel_endian_size psm_length;
	psm_length.byte[0] = PSMPack->PackLength.byte[1];
	psm_length.byte[1] = PSMPack->PackLength.byte[0];

	*leftlength = length - psm_length.length - sizeof(program_stream_map);
	if (*leftlength <= 0) return 0;

	*NextPack = Pack + psm_length.length + sizeof(program_stream_map);

	return *leftlength;
}

inline int ProgramShHead(char* Pack, int length, char **NextPack, int *leftlength, char **PayloadData, int *PayloadDataLen)
{
	program_stream_map* PSMPack = (program_stream_map*)Pack;

	//no payload
	*PayloadData = 0;
	*PayloadDataLen = 0;

	if ((unsigned int)length < sizeof(program_stream_map)) return 0;

	littel_endian_size psm_length;
	psm_length.byte[0] = PSMPack->PackLength.byte[1];
	psm_length.byte[1] = PSMPack->PackLength.byte[0];

	*leftlength = length - psm_length.length - sizeof(program_stream_map);
	if (*leftlength <= 0)
		return 0;

	*NextPack = Pack + psm_length.length + sizeof(program_stream_map);

	return *leftlength;
}

//ps stream parse
inline int Pes(char* Pack, int length, char **NextPack, int *leftlength, char **PayloadData, int *PayloadDataLen)
{
	program_stream_e* PSEPack = (program_stream_e*)Pack;

	*PayloadData = 0;
	*PayloadDataLen = 0;

	if ((unsigned int)length < sizeof(program_stream_e)) return 0;

	littel_endian_size pse_length;
	pse_length.byte[0] = PSEPack->PackLength.byte[1];
	pse_length.byte[1] = PSEPack->PackLength.byte[0];

	*PayloadDataLen = pse_length.length - 2 - 1 - PSEPack->stuffing_length;
	if (*PayloadDataLen>0)
		*PayloadData = Pack + sizeof(program_stream_e)+PSEPack->stuffing_length;

	*leftlength = length - pse_length.length - sizeof(pack_start_code)-sizeof(littel_endian_size);
	if (*leftlength <= 0) return 0;

	*NextPack = Pack + sizeof(pack_start_code)+sizeof(littel_endian_size)+pse_length.length;

	return *leftlength;
}

//parse h264
int inline GetH246FromPs(char* buffer, int length, char *h264Buffer, int *h264length, char *sipId)
{
	int leftlength = 0;
	char *NextPack = 0;

	*h264length = 0;

	if (ProgramStreamPackHeader(buffer, length, &NextPack, &leftlength) == 0)
		return 0;

	char *PayloadData = NULL;
	int PayloadDataLen = 0;

	while ((unsigned int)leftlength >= sizeof(pack_start_code))
	{
		PayloadData = NULL;
		PayloadDataLen = 0;

		if (NextPack
			&& NextPack[0] == '\x00'
			&& NextPack[1] == '\x00'
			&& NextPack[2] == '\x01'
			&& NextPack[3] == '\xE0')
		{
			if (Pes(NextPack, leftlength, &NextPack, &leftlength, &PayloadData, &PayloadDataLen))
			{
				if (PayloadDataLen)
				{
					if (PayloadDataLen + *h264length < H264_FRAME_SIZE_MAX)
					{
						memcpy(h264Buffer, PayloadData, PayloadDataLen);
						h264Buffer += PayloadDataLen;
						*h264length += PayloadDataLen;
					}
					else
					{
						APP_WARRING("h264 frame size exception!! %d:%d", PayloadDataLen, *h264length);
					}
				}
			}
			else
			{
				if (PayloadDataLen)
				{
					if (PayloadDataLen + *h264length < H264_FRAME_SIZE_MAX)
					{
						memcpy(h264Buffer, PayloadData, PayloadDataLen);
						h264Buffer += PayloadDataLen;
						*h264length += PayloadDataLen;
					}
					else
					{
						APP_WARRING("h264 frame size exception!! %d:%d", PayloadDataLen, *h264length);
					}
				}
				break;
			}
		}
		else if (NextPack
			&& NextPack[0] == '\x00'
			&& NextPack[1] == '\x00'
			&& NextPack[2] == '\x01'
			&& NextPack[3] == '\xBB')
		{
			if (ProgramShHead(NextPack, leftlength, &NextPack, &leftlength, &PayloadData, &PayloadDataLen) == 0)
				break;
		}
		else if (NextPack
			&& NextPack[0] == '\x00'
			&& NextPack[1] == '\x00'
			&& NextPack[2] == '\x01'
			&& NextPack[3] == '\xBC')
		{
			if (ProgramStreamMap(NextPack, leftlength, &NextPack, &leftlength, &PayloadData, &PayloadDataLen) == 0)
				break;
		}
		else if (NextPack
			&& NextPack[0] == '\x00'
			&& NextPack[1] == '\x00'
			&& NextPack[2] == '\x01'
			&& (NextPack[3] == '\xC0' || NextPack[3] == '\xBD'))
		{
			printf("audio ps frame, skip it\n");
			break;
		}
		else
		{
			printf("[%s]no know %x %x %x %x\n", sipId, NextPack[0], NextPack[1], NextPack[2], NextPack[3]);
			break;
		}
	}

	return *h264length;
}

void checkerror(int rtperr)
{
	if (rtperr < 0)
	{
		std::cout << "ERROR: " << RTPGetErrorString(rtperr) << std::endl;
		exit(-1);
	}
}

class MyRTPSession : public RTPSession
{
protected:
	void OnNewSource(RTPSourceData *dat)
	{
		if (dat->IsOwnSSRC())
			return;

		uint32_t ip;
		uint16_t port;

		if (dat->GetRTPDataAddress() != 0)
		{
			const RTPIPv4Address *addr = (const RTPIPv4Address *)(dat->GetRTPDataAddress());
			ip = addr->GetIP();
			port = addr->GetPort();
		}
		else if (dat->GetRTCPDataAddress() != 0)
		{
			const RTPIPv4Address *addr = (const RTPIPv4Address *)(dat->GetRTCPDataAddress());
			ip = addr->GetIP();
			port = addr->GetPort() - 1;
		}
		else
			return;

		RTPIPv4Address dest(ip, port);
		AddDestination(dest);

		struct in_addr inaddr;
		inaddr.s_addr = htonl(ip);
		std::cout << "Adding destination " << std::string(inet_ntoa(inaddr)) << ":" << port << std::endl;
	}

	void OnBYEPacket(RTPSourceData *dat)
	{
		if (dat->IsOwnSSRC())
			return;

		uint32_t ip;
		uint16_t port;

		if (dat->GetRTPDataAddress() != 0)
		{
			const RTPIPv4Address *addr = (const RTPIPv4Address *)(dat->GetRTPDataAddress());
			ip = addr->GetIP();
			port = addr->GetPort();
		}
		else if (dat->GetRTCPDataAddress() != 0)
		{
			const RTPIPv4Address *addr = (const RTPIPv4Address *)(dat->GetRTCPDataAddress());
			ip = addr->GetIP();
			port = addr->GetPort() - 1;
		}
		else
			return;

		RTPIPv4Address dest(ip, port);
		DeleteDestination(dest);

		struct in_addr inaddr;
		inaddr.s_addr = htonl(ip);
		std::cout << "Deleting destination " << std::string(inet_ntoa(inaddr)) << ":" << port << std::endl;
	}

	void OnRemoveSource(RTPSourceData *dat)
	{
		if (dat->IsOwnSSRC())
			return;
		if (dat->ReceivedBYE())
			return;

		uint32_t ip;
		uint16_t port;

		if (dat->GetRTPDataAddress() != 0)
		{
			const RTPIPv4Address *addr = (const RTPIPv4Address *)(dat->GetRTPDataAddress());
			ip = addr->GetIP();
			port = addr->GetPort();
		}
		else if (dat->GetRTCPDataAddress() != 0)
		{
			const RTPIPv4Address *addr = (const RTPIPv4Address *)(dat->GetRTCPDataAddress());
			ip = addr->GetIP();
			port = addr->GetPort() - 1;
		}
		else
			return;

		RTPIPv4Address dest(ip, port);
		DeleteDestination(dest);

		struct in_addr inaddr;
		inaddr.s_addr = htonl(ip);
		std::cout << "Deleting destination " << std::string(inet_ntoa(inaddr)) << ":" << port << std::endl;
	}
};


//recv stream by jrtp
static unsigned __stdcall jrtplib_rtp_recv_thread(void* arg)
{
	CameraParams *p = (CameraParams *)arg;

#ifdef WIN32
	WSADATA dat;
	WSAStartup(MAKEWORD(2, 2), &dat);
#endif // WIN32

	RTPSession sess;
	uint16_t portbase;
	std::string ipstr;
	int status, i, num;

	RTPUDPv4TransmissionParams transparams;
	RTPSessionParams sessparams;

	sessparams.SetOwnTimestampUnit(1.0 / 9000.0);

	portbase = p->recvPort;

	sessparams.SetAcceptOwnPackets(true);
	transparams.SetPortbase(portbase);
	status = sess.Create(sessparams, &transparams);
	checkerror(status);

	std::string strPath = GetMoudlePath();
	char filename[MAX_PATH];
	strPath += p->sipId;
	_snprintf(filename, 128, "%s1234.264", strPath.c_str());
	p->fpH264 = fopen(filename, "wb");
	if (p->fpH264 == NULL)
	{
		APP_ERR("fopen %s failed", filename);
		return NULL;
	}

	while (p->running)
	{
		sess.BeginDataAccess();

		// check incoming packets
		if (sess.GotoFirstSourceWithData())
		{
			do
			{
				RTPPacket *pack;

				while ((pack = sess.GetNextPacket()) != NULL)
				{
					// You can examine the data here
					fprintf(g_fp, "Got packet !\n");
					printf("Got packet!\n");

					//std::cout << pack->GetPayloadData() << std::endl;

					fwrite(pack->GetPayloadData(), 1, pack->GetPayloadLength(), p->fpH264);
					// we don't longer need the packet, so
					// we'll delete it
					sess.DeletePacket(pack);
				}
			} while (sess.GotoNextSourceWithData());
		}

		sess.EndDataAccess();

#ifndef RTP_SUPPORT_THREAD
		status = sess.Poll();
		checkerror(status);
#endif // RTP_SUPPORT_THREAD

		//RTPTime::Wait(RTPTime(0, 0));
	}

	sess.BYEDestroy(RTPTime(10, 0), 0, 0);

#ifdef WIN32
	WSACleanup();
#endif // WIN32

	fclose(p->fpH264);
	p->fpH264 == NULL;

	return 0;
}

static unsigned __stdcall rtp_recv_thread(void *arg)
{
	int socket_fd;
	CameraParams *p = (CameraParams *)arg;
	int rtp_port = p->recvPort;
	struct sockaddr_in servaddr;

	socket_fd = init_udpsocket(rtp_port, &servaddr, NULL);
	if (socket_fd >= 0)
	{
		printf("start socket port %d success\n", rtp_port);
	}

	char *buf = (char *)malloc(RTP_MAXBUF);
	if (buf == NULL)
	{
		fprintf(g_fp, "malloc failed buf");
		printf("malloc failed buf");
		return NULL;
	}
	char *psBuf = (char *)malloc(PS_BUF_SIZE);
	if (psBuf == NULL)
	{
		//APP_ERR("malloc failed");
		printf("malloc failed");
		return NULL;
	}
	memset(psBuf, '\0', PS_BUF_SIZE);
	char *h264buf = (char *)malloc(H264_FRAME_SIZE_MAX);
	if (h264buf == NULL)
	{
		//APP_ERR("malloc failed");
		printf("malloc failed");
		return NULL;
	}
	int recvLen;
	int addr_len = sizeof(struct sockaddr_in);
	int rtpHeadLen = sizeof(RTP_header_t);

	std::string strPath = GetMoudlePath();
	char filename[MAX_PATH];
	strPath += p->sipId;
	_snprintf(filename, 128, "%s1234.264", strPath.c_str());
	p->fpH264 = fopen(filename, "wb");
	if (p->fpH264 == NULL)
	{
		APP_ERR("fopen %s failed", filename);
		return NULL;
	}

	APP_DEBUG("%s:%d starting ...", p->sipId, p->recvPort);

	int cnt = 0;
	int rtpPsLen, h264length, psLen = 0;
	char *ptr;
	memset(buf, 0, RTP_MAXBUF);

	ptr = (char*)malloc(PS_BUF_SIZE);
	memset(ptr, 0, PS_BUF_SIZE);
	int ntotal = 0;
	while (p->running)
	{
		recvLen = recvfrom(socket_fd, buf, RTP_MAXBUF, 0, (struct sockaddr*)&servaddr, (int*)&addr_len);

		if (recvLen > rtpHeadLen)
		{
			unsigned char *buffer = (unsigned char *)buf;

			fprintf(g_fp, "==>> ---------------------%x,,%x,,%x,,%x\n", buffer[0], buffer[1], buffer[2], buffer[3]);
			ptr = psBuf + psLen;
			rtpPsLen = recvLen - rtpHeadLen;
#if 1
			if (psLen + rtpPsLen < PS_BUF_SIZE)
			{
				memcpy(ptr, buf + rtpHeadLen, rtpPsLen);
			}
			else
			{
				APP_WARRING("psBuf memory overflow, %d\n", psLen + rtpPsLen);
				psLen = 0;
				continue;
			}
#endif
			fprintf(g_fp, "==>> %x,,%x,,%x,,%x\n", ptr[0], ptr[1], ptr[2], ptr[3]);
			if (/*(*//*(*/ptr[0] == 0x00 && ptr[1] == 0x00 && ptr[2] == 0x01 && ptr[3] == 0xffffffBA/*) *//*|| (ptr[0] == 0x00 && ptr[1] == 0x00 && ptr[2] == 0x01 && ptr[3] == 0xBA)*//*) */ && psLen > 0)
			{
				if (cnt % 10000 == 0)
				{
					printf("rtpRecvPort:%d, cnt:%d, pssize:%d\n", rtp_port, cnt++, psLen);
				}
				if (cnt % 25 == 0)
				{
					p->status = 1;
				}
				GetH246FromPs((char *)psBuf, psLen, h264buf, &h264length, p->sipId);
				if (h264length > 0)
				{
					fwrite(h264buf, 1, h264length, p->fpH264);
				}
				memcpy(psBuf, ptr, rtpPsLen);
				psLen = 0;
				cnt++;
			}
			/*else if (psLen > 0)
			{
			memcpy(psBuf + psLen, ptr, rtpPsLen);
			}*/
			psLen += rtpPsLen;
		}
		else
		{
			perror("recvfrom() long");
		}

		if (recvLen > 1500)
		{
			printf("udp frame exception, %d\n", recvLen);
		}
	}

	release_udpsocket(socket_fd, NULL);
	if (buf != NULL)
	{
		free(buf);
	}
	if (psBuf != NULL)
	{
		free(psBuf);
	}
	if (h264buf != NULL)
	{
		free(h264buf);
	}
	if (p->fpH264 != NULL)
	{
		fclose(p->fpH264);
		p->fpH264 = NULL;
		fclose(g_fp);
		g_fp = NULL;
	}

	APP_DEBUG("%s:%d run over", p->sipId, p->recvPort);

	return NULL;
}

static unsigned __stdcall stream_keep_alive_thread(void *arg)
{
	int socket_fd;
	CameraParams *p = (CameraParams *)arg;
	int rtcp_port = p->recvPort + 1;
	struct sockaddr_in servaddr;

	SYSTEMTIME st;

	socket_fd = init_udpsocket(rtcp_port, &servaddr, NULL);
	if (socket_fd >= 0)
	{
		printf("start socket port %d success\n", rtcp_port);
	}

	char *buf = (char *)malloc(1024);
	if (buf == NULL)
	{
		printf("malloc failed buf");
		return NULL;
	}
	int recvLen;
	int addr_len = sizeof(struct sockaddr_in);

	APP_DEBUG("%s:%d starting ...", p->sipId, rtcp_port);

	memset(buf, 0, 1024);
	while (p->running)
	{
		recvLen = recvfrom(socket_fd, buf, 1024, 0, (struct sockaddr*)&servaddr, (int*)&addr_len);
		if (recvLen > 0)
		{
			printf("stream_keep_alive_thread, rtcp_port %d, recv %d bytes\n", rtcp_port, recvLen);
			recvLen = sendto(socket_fd, buf, recvLen, 0, (struct sockaddr*)&servaddr, sizeof(struct sockaddr_in));
			if (recvLen <= 0)
			{
				APP_ERR("sendto %d failed", rtcp_port);
			}
		}
		else
		{
			perror("recvfrom() alive");
		}
		//gettimeofday(&tv, NULL);
		GetLocalTime(&st);
	}

	release_udpsocket(socket_fd, NULL);
	if (buf != NULL)
	{
		free(buf);
	}

	APP_DEBUG("%s:%d run over", p->sipId, rtcp_port);

	return NULL;
}

static int startStreamRecv(liveVideoStreamParams *pliveVideoParams)
{
	int i;
	HANDLE hHandle;
	HANDLE hHandleAlive;
	//pthread_t pid;
	CameraParams *p;
	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		p = pliveVideoParams->pCameraParams + i;
		p->statusErrCnt = 0;
		p->running = 1;
		if ((hHandle = (HANDLE)_beginthreadex(NULL, 0, rtp_recv_thread, (void*)p, 0, NULL)) == INVALID_HANDLE_VALUE)
		{
			APP_ERR("pthread_create rtp_recv_thread err, %s:%d", p->sipId, p->recvPort);
		}
		else
		{
			CloseHandle(hHandle);
		}
		/*	if ((hHandleAlive = (HANDLE)_beginthreadex(NULL, 0, stream_keep_alive_thread, (void*)p, 0, NULL)) == INVALID_HANDLE_VALUE) {
		APP_ERR("pthread_create stream_keep_alive_thread err, %s:%d", p->sipId, p->recvPort + 1);
		}
		else
		{
		CloseHandle(hHandleAlive);
		}*/
	}

	return 0;
}

static unsigned __stdcall gb28181ServerThread(void *arg)
{
	int iReturnCode = 0;
	struct eXosip_t *eCtx;
	gb28181Params *p28181Params = (gb28181Params *)(arg);

	TRACE_INITIALIZE(6, NULL);

	eCtx = eXosip_malloc();
	iReturnCode = eXosip_init(eCtx);
	if (iReturnCode != OSIP_SUCCESS)
	{
		printf("Can,t initialize, eXosip!");
		return NULL;
	}
	else
	{
		printf("eXosip_init successfully!\n");
	}

	iReturnCode = eXosip_listen_addr(eCtx, IPPROTO_UDP, NULL, p28181Params->localSipPort, AF_INET, 0);
	if (iReturnCode != OSIP_SUCCESS)
	{
		printf("eXosip_listen_addr error!");
		return NULL;
	}

	p28181Params->eCtx = eCtx;
	MsgProcess(p28181Params, eCtx);

	eXosip_quit(eCtx);
	osip_free(eCtx);
	eCtx = NULL;
	p28181Params->eCtx = NULL;

	fprintf(g_fp, "%s run over", __FUNCTION__);

	return 0;
}

#if 1

//query video
static int sendInvitePlay(char *playSipId, int rtp_recv_port, gb28181Params *p28181Params)
{
	char dest_call[256], source_call[256], subject[128];
	osip_message_t *invite = NULL;
	int ret;
	struct eXosip_t *peCtx = p28181Params->eCtx;

	_snprintf(dest_call, 256, "sip:%s@%s:%d", playSipId, p28181Params->platformIpAddr, p28181Params->platformSipPort);
	_snprintf(source_call, 256, "sip:%s@%s", p28181Params->localSipId, p28181Params->localIpAddr);
	_snprintf(subject, 128, "%s:0,%s:0", playSipId, p28181Params->localSipId);
	ret = eXosip_call_build_initial_invite(peCtx, &invite, dest_call, source_call, NULL, subject);
	if (ret != 0)
	{
		fprintf(g_fp, "eXosip_call_build_initial_invite failed, %s,%s,%s", dest_call, source_call, subject);
		return -1;
	}

	//sdp
	char body[500];
	int bodyLen = _snprintf(body, 500,
		"v=0\r\n"
		"o=%s 0 0 IN IP4 %s\r\n"
		"s=Play\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=video %d RTP/AVP 96 97 98\r\n"
		"a=rtpmap:96 PS/90000\r\n"
		"a=rtpmap:97 MPEG4/90000\r\n"
		"a=rtpmap:98 H264/90000\r\n"
		"a=recvonly\r\n"
		"y=0100000001\n", playSipId, p28181Params->localIpAddr,
		p28181Params->localIpAddr, rtp_recv_port);
	osip_message_set_body(invite, body, bodyLen);
	osip_message_set_content_type(invite, "APPLICATION/SDP");
	eXosip_lock(peCtx);
	eXosip_call_send_initial_invite(peCtx, invite);
	eXosip_unlock(peCtx);

	return 0;
}

#else

//query video
static int sendInvitePlay(char *playSipId, int rtp_recv_port, gb28181Params *p28181Params)
{
	char dest_call[256], source_call[256], subject[128];
	osip_message_t *invite = NULL;
	int ret;
	struct eXosip_t *peCtx = p28181Params->eCtx;

	_snprintf(dest_call, 256, "sip:%s@%s:%d", playSipId, p28181Params->platformIpAddr, p28181Params->platformSipPort);
	_snprintf(source_call, 256, "sip:%s@%s", p28181Params->localSipId, p28181Params->localIpAddr);
	_snprintf(subject, 128, "%s:0,%s:0", playSipId, p28181Params->localSipId);
	ret = eXosip_call_build_initial_invite(peCtx, &invite, dest_call, source_call, NULL, subject);
	if (ret != 0)
	{
		//APP_ERR("eXosip_call_build_initial_invite failed, %s,%s,%s", dest_call, source_call, subject);
		return -1;
	}

	//sdp
	char body[500];
	/*int bodyLen = _snprintf(body, 500,
	"v=0\r\n"
	"o=%s 0 0 IN IP4 %s\r\n"
	"s=Play\r\n"
	"c=IN IP4 %s\r\n"
	"t=0 0\r\n"
	"m=video %d RTP/AVP 96 97 98\r\n"
	"a=rtpmap:96 PS/90000\r\n"
	"a=rtpmap:97 MPEG4/90000\r\n"
	"a=rtpmap:98 H264/90000\r\n"
	"a=recvonly\r\n"
	"y=0100000001\n", playSipId, p28181Params->localIpAddr,
	p28181Params->localIpAddr, rtp_recv_port);*/

	int bodyLen = _snprintf(body, 500, "v=0\n"
		"o=%s 0 0 IN IP4 %s\n"
		"s=Play\n"
		"c=IN IP4 %s\n"
		"t=0 0\n"
		"m=video %d RTP/AVP 96 98 97\n"
		"a=recvonly\n"
		"a=rtpmap:96 PS/90000\n"
		"a=rtpmap:98 H264/90000\n"
		"a=rtpmap:97 MPEG4/90000\n"
		"y=0100000001\n",
		playSipId,
		p28181Params->localIpAddr,
		p28181Params->localIpAddr,
		rtp_recv_port);

	osip_message_set_body(invite, body, bodyLen);
	osip_message_set_content_type(invite, "APPLICATION/SDP");
	eXosip_lock(peCtx);
	eXosip_call_send_initial_invite(peCtx, invite);
	eXosip_unlock(peCtx);

	return 0;
}

#endif

//stop video
static int sendPlayBye(gb28181Params *p28181Params)
{
	struct eXosip_t *peCtx = p28181Params->eCtx;

	eXosip_lock(peCtx);
	eXosip_call_terminate(peCtx, p28181Params->call_id, p28181Params->dialog_id);
	eXosip_unlock(peCtx);
	return 0;
}

//query realtime video
static int startCameraRealStream(liveVideoStreamParams *pliveVideoParams)
{
	int i;
	CameraParams *p;

	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		p = pliveVideoParams->pCameraParams + i;
		sendInvitePlay(p->sipId, p->recvPort, &(pliveVideoParams->gb28181Param));
	}

	return 0;
}

//stop realtime stream
static int stopCameraRealStream(liveVideoStreamParams *pliveVideoParams)
{
	int i, tryCnt;
	CameraParams *p;
	gb28181Params *p28181Params = &(pliveVideoParams->gb28181Param);

	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		p = pliveVideoParams->pCameraParams + i;
		p28181Params->call_id = -1;
		sendInvitePlay(p->sipId, p->recvPort, p28181Params);
		tryCnt = 10;
		while (tryCnt-- > 0)
		{
			if (p28181Params->call_id != -1)
			{
				break;
			}
			Sleep(1000);
		}
		if (p28181Params->call_id == -1)
		{
			APP_WARRING("exception wait call_id:%d, %s", p28181Params->call_id, p->sipId);
		}
		sendPlayBye(p28181Params);

		p->running = 0;
	}

	return 0;
}

//check camera status
static int checkCameraStatus(liveVideoStreamParams *pliveVideoParams)
{
	int i;
	CameraParams *p;
	gb28181Params *p28181Params = &(pliveVideoParams->gb28181Param);

	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		p = pliveVideoParams->pCameraParams + i;
		if (p->status == 0)
		{
			p->statusErrCnt++;
			if (p->statusErrCnt % 10 == 0)
			{
				APP_WARRING("camera %s is exception, restart it", p->sipId);
				p28181Params->call_id = -1;
				sendInvitePlay(p->sipId, p->recvPort, p28181Params);
				p->statusErrCnt = 0;

			}
		}
		else
		{
			p->statusErrCnt = 0;
			p->status = 0;
		}
	}

	return 0;
}

//stop stream
static int stopStreamRecv(liveVideoStreamParams *pliveVideoParams)
{
	int i;
	CameraParams *p;

	for (i = 0; i < pliveVideoParams->cameraNum; i++)
	{
		p = pliveVideoParams->pCameraParams + i;
		p->running = 0;
	}

	return 0;
}

const char *whitespace_cb(mxml_node_t *node, int where)
{
	return NULL;
}

//query catalog
static int sendQueryCatalog(gb28181Params *p28181Params)
{
	char sn[32];
	int ret;
	mxml_node_t *tree, *query, *node;
	struct eXosip_t *peCtx = p28181Params->eCtx;
	char *deviceId = p28181Params->localSipId;

	tree = mxmlNewXML("1.0");
	if (tree != NULL)
	{
		query = mxmlNewElement(tree, "Query");
		if (query != NULL)
		{
			char buf[256] = { 0 };
			char dest_call[256], source_call[256];
			node = mxmlNewElement(query, "CmdType");
			mxmlNewText(node, 0, "Catalog");
			node = mxmlNewElement(query, "SN");
			_snprintf(sn, 32, "%d", p28181Params->SN++);
			mxmlNewText(node, 0, sn);
			node = mxmlNewElement(query, "DeviceID");
			mxmlNewText(node, 0, deviceId);
			mxmlSaveString(tree, buf, 256, whitespace_cb);
			//printf("send query catalog:%s\n", buf);
			osip_message_t *message = NULL;
			_snprintf(dest_call, 256, "sip:%s@%s:%d", p28181Params->platformSipId,
				p28181Params->platformIpAddr, p28181Params->platformSipPort);
			_snprintf(source_call, 256, "sip:%s@%s", p28181Params->localSipId, p28181Params->localIpAddr);
			ret = eXosip_message_build_request(peCtx, &message, "MESSAGE", dest_call, source_call, NULL);
			if (ret == 0 && message != NULL)
			{
				osip_message_set_body(message, buf, strlen(buf));
				osip_message_set_content_type(message, "Application/MANSCDP+xml");
				eXosip_lock(peCtx);
				eXosip_message_send_request(peCtx, message);
				eXosip_unlock(peCtx);
				APP_DEBUG("xml:%s, dest_call:%s, source_call:%s, ok", buf, dest_call, source_call);
				fprintf(g_fp, "xml:%s, dest_call:%s, source_call:%s, ok", buf, dest_call, source_call);
			}
			else
			{
				printf("eXosip_message_build_request failed");
				fprintf(g_fp, "eXosip_message_build_request failed");
			}
		}
		else
		{
			printf("mxmlNewElement Query failed");
			fprintf(g_fp, "mxmlNewElement Query failed");
		}
		mxmlDelete(tree);
	}
	else
	{
		fprintf(g_fp, "mxmlNewXML failed");
	}

	return 0;
}

int main(int argc, char *argv[])
{

	HANDLE hHandle;

	std::string strLogPath = GetMoudlePath();
	strLogPath += "log.txt";
	g_fp = fopen(strLogPath.c_str(), "wt");
	if (g_fp == NULL)
		return 0;


	//parse config
	ParserIniFile();

	g_liveVideoParams.running = 1;
	g_liveVideoParams.gb28181Param.running = 1;

	//start sip client server
	if ((hHandle = (HANDLE)_beginthreadex(NULL, 0, gb28181ServerThread, (void*)&(g_liveVideoParams.gb28181Param), 0, NULL)) == INVALID_HANDLE_VALUE)
	{
		printf("error pthread_create gb28181ServerThread err");
		fprintf(g_fp, "error, pthread_create gb28181ServerThread err");
	}
	else
	{
		CloseHandle(hHandle);
	}

	int tmpCnt = 20;
	while ((!g_liveVideoParams.gb28181Param.registerOk) && (tmpCnt > 0))
	{
		printf("waiting register %d...\n", tmpCnt);
		fprintf(g_fp, "waiting register %d...\n", tmpCnt--);
		Sleep(1000);
		if (tmpCnt == 0)
			exit(-1);
	}


	sendQueryCatalog(&(g_liveVideoParams.gb28181Param));


	startStreamRecv(&g_liveVideoParams);
	Sleep(1000);

	int i = 0;

	startCameraRealStream(&g_liveVideoParams);
	while (g_liveVideoParams.running)
	{
		i++;
		checkCameraStatus(&g_liveVideoParams);
		Sleep(2000);
		if (i == 20)
			break;
	}

	g_liveVideoParams.running = 0;
	stopCameraRealStream(&g_liveVideoParams);
	Sleep(300);
	stopStreamRecv(&g_liveVideoParams);
	g_liveVideoParams.gb28181Param.running = 0;
	Sleep(1000);
	printf("LiveVideoStream run over");

	return 0;
}