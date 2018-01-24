#ifndef _FILE_NAME_IO_H_
#define _FILE_NAME_IO_H_

#include <iostream>

/*获取执行程序路径*/
std::string GetMoudlePath();

/*获取执行文件文件名*/
std::string GetMoudleName();

/*获取文件名*/
std::string GetFileNameNoExt(std::string strFilePath);

/*获取文件后缀名*/
std::string GetFileExt(std::string strFileName);

/*获取文件名（包括后缀）*/
std::string GetFileName(std::string strFilePath);

/*获取文件路径*/
std::string GetFilePath(std::string strFilePath);

#endif