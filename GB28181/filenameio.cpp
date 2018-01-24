#include "filenameio.h"
#include <windows.h>

/*获取执行程序路径*/
std::string GetMoudlePath()
{
	char chFullFileName[MAX_PATH];
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	GetModuleFileName(NULL, chFullFileName, MAX_PATH);
	//获取文件路径
	_splitpath(chFullFileName, chDrive, chDir, chFileName, chFileExt);

	//合并文件路径
	std::string strPath = chDrive;
	//strPath += "\\";
	strPath += chDir;
	//strPath += "\\";
	return strPath;
}

/*获取执行文件文件名*/
std::string GetMoudleName()
{
	char chFullFileName[MAX_PATH];
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	GetModuleFileName(NULL, chFullFileName, MAX_PATH);
	//获取文件路径
	_splitpath(chFullFileName, chDrive, chDir, chFileName, chFileExt);

	//合并文件路径
	std::string strPath = chFileName;
	strPath += ".";
	strPath += chFileExt;
	return strPath;
}

/*获取文件名*/
std::string GetFileNameNoExt(std::string strFilePath)
{
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	//获取文件路径
	_splitpath(strFilePath.c_str(), chDrive, chDir, chFileName, chFileExt);

	//合并文件路径
	return std::string(chFileName);
}

/*获取文件后缀名*/
std::string GetFileExt(std::string strFileName)
{
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	//获取文件路径
	_splitpath(strFileName.c_str(), chDrive, chDir, chFileName, chFileExt);

	//合并文件路径
	return std::string(chFileExt);
}

/*获取文件名（包括后缀）*/
std::string GetFileName(std::string strFilePath)
{
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	//获取文件路径
	_splitpath(strFilePath.c_str(), chDrive, chDir, chFileName, chFileExt);

	//合并文件路径
	//合并文件路径
	std::string strPath = chFileName;
	strPath += ".";
	strPath += chFileExt;
	return strPath;
}

/*获取文件路径*/
std::string GetFilePath(std::string strFilePath)
{
	char chDrive[MAX_PATH];
	char chDir[MAX_PATH];
	char chFileName[MAX_PATH];
	char chFileExt[MAX_PATH];
	//获取文件路径
	_splitpath(strFilePath.c_str(), chDrive, chDir, chFileName, chFileExt);

	//合并文件路径
	//合并文件路径
	std::string strPath = chDrive;
	strPath += "\\";
	strPath += chDir;
	strPath += "\\";
	return strPath;
}