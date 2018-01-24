#ifndef _TIME_STRAMP_H_
#define _TIME_STRAMP_H_


#include <windows.h>
#include <stdio.h>
#include <atlstr.h>

extern FILE* g_fp;

class timestramp{
private:
	LARGE_INTEGER m_litmp;
	_int64 QPart2;
	_int64 QPart1;
	double dfMinus, dfFreq, dfTim;
public:
	timestramp(){ 
		QueryPerformanceFrequency(&m_litmp);
		dfFreq = (double)m_litmp.QuadPart;
		QueryPerformanceCounter(&m_litmp);
		QPart1 = m_litmp.QuadPart;
	}

	~timestramp(){
		QueryPerformanceCounter(&m_litmp);
		QPart2 = m_litmp.QuadPart;
		dfMinus = (double)(QPart2 - QPart1);
		dfTim = dfMinus / dfFreq * 1000;

		//显示时间
		CString msg4 = "时间：", msg3, msg5 = "毫秒";
		msg3.Format("%10.9f", dfTim);
		CString st = msg4 + msg3 + msg5;

		fprintf(g_fp, "%s\n", st);
	}
};

#endif