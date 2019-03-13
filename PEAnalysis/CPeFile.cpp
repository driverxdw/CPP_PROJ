// PEAnalysis.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "pch.h"
#include <iostream>
#include <windows.h>
#include <ImageHlp.h>
#include <Commctrl.h>
#include "CPeFile.h"
#include <assert.h>
#include <new>
using namespace std;


//读取标志m_dwReadFlag取值（仅在类中使用）
#define PE_READ_FLAG_EXPORT				0x00000001UL
#define PE_READ_FLAG_IMPORT				0x00000002UL
#define PE_READ_FLAG_RESOURCE			0x00000004UL
#define PE_READ_FLAG_EXCEPTION			0x00000008UL
#define PE_READ_FLAG_SECURITY			0x00000010UL
#define PE_READ_FLAG_BASERELOCATION		0x00000020UL
#define PE_READ_FLAG_DEBUG				0x00000040UL
#define PE_READ_FLAG_TLS				0x00000080UL
#define PE_READ_FLAG_LOADCONFIG			0x00000100UL
#define PE_READ_FLAG_BOUNDIMPORT		0x00000200UL
#define PE_READ_FLAG_DELAYIMPORT		0x00000400UL
#define PE_READ_FLAG_ALL				(PE_READ_FLAG_EXPORT | PE_READ_FLAG_IMPORT | PE_READ_FLAG_RESOURCE | PE_READ_FLAG_EXCEPTION | \
										PE_READ_FLAG_SECURITY | PE_READ_FLAG_BASERELOCATION | PE_READ_FLAG_DEBUG | PE_READ_FLAG_TLS | \
										PE_READ_FLAG_LOADCONFIG | PE_READ_FLAG_BOUNDIMPORT | PE_READ_FLAG_DELAYIMPORT)

CPeFile::CPeFile()
	: m_dwType(0UL)
	, m_dwReadFlag(0UL)
	, m_lpExportManager(NULL)
	, m_lpImportManager(NULL)
	, m_lpResourceManager(NULL)
	, m_lpExceptionManager(NULL)
	, m_lpSecurityManager(NULL)
	, m_lpBaseRelocationManager(NULL)
	, m_lpDebugManager(NULL)
	, m_lpTLSManager(NULL)
	, m_lpLoadConfigManager(NULL)
	, m_lpBoundImportManager(NULL)
	, m_lpDelayImportManager(NULL)
{
}

CPeFile::~CPeFile()
{
	Detach();
}

DWORD CPeFile::Attach(LPCSTR lpszFilePath)
{
	assert(!m_dwType);
	assert(lpszFilePath);
	int ret = OpenPeFile(lpszFilePath);
	if (ret == -1)
		return 0UL; //ul代表无符号长整形
	else if (ret == 0)
		return 1UL;
	__try
	{
		m_dwType = CheckHeaders();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		CloseFile();
		return 2UL;
	}
	if (!m_dwType) {
		CloseFile();
	}
	return m_dwType;
}

void CPeFile::Detach() {
	if (m_dwType == IMAGE_NT_SIGNATURE) //pe标识符
		ClearAll();
	if (m_dwType) {
		CloseFile();
		m_dwType = 0UL;
	}
}

int CPeFile::OpenPeFile(LPCSTR lpszFilePath) {
	m_hFile = ::CreateFileA(lpszFilePath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);//创建文件对象
	if (m_hFile != INVALID_HANDLE_VALUE) {
		LARGE_INTEGER liFileSize;
		if (::GetFileSizeEx(m_hFile, &liFileSize) && liFileSize.QuadPart == 0LL) {
			::CloseHandle(m_hFile);
			return -1; 
		}
		m_hFileMap = ::CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0UL, 0UL, NULL);//创建内存映射
		if (m_hFileMap) {
			m_lpMemory = ::MapViewOfFile(m_hFileMap,FILE_MAP_READ, 0UL, 0UL, 0U); //映射文件对象到内存，返回指向内存的指针
			if (m_lpMemory)
			{
				//cout << "valid";
				return 1;
			}
			::CloseHandle(m_hFileMap);
	}
		::CloseHandle(m_hFile);
	}
	return 0;
}

void CPeFile::CloseFile()
{
	::UnmapViewOfFile(m_lpMemory);
	::CloseHandle(m_hFileMap);
	::CloseHandle(m_hFile);
}

void CPeFile::ClearAll() 
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (m_dwReadFlag)
	{
		m_dwReadFlag = 0UL;
	}
}

DWORD CPeFile::CheckHeaders()//checkheaders函数是关键，实例化内存句柄
{
	m_lpDosHeader = (IMAGE_DOS_HEADER*)m_lpMemory; //IMAGE_DOS_HEADER类型winnt.h有定义(结构体),m_lpMemory是指针，所以*;
	if (m_lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE) //IMAGE_DOS_SIGNATURE同样在winnt.h中有定义，直接比较;
		return 0UL;
	if (!m_lpDosHeader->e_lfanew)
		return (DWORD)IMAGE_DOS_SIGNATURE;
	m_lpNtHeader = MakePtr(IMAGE_NT_HEADERS32*, m_lpMemory, m_lpDosHeader->e_lfanew);
	if(LOWORD(m_lpNtHeader->Signature)==IMAGE_OS2_SIGNATURE || LOWORD(m_lpNtHeader->Signature==IMAGE_OS2_SIGNATURE_LE))
		return (DWORD)LOWORD(m_lpNtHeader->Signature);
	if (m_lpNtHeader->Signature != IMAGE_NT_SIGNATURE) //0x50450000
		return 0UL;
	switch (m_lpNtHeader->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		m_b64Bit = FALSE;
		break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		m_b64Bit = TRUE;
		break;
	default:
		return 0UL;
	}
	m_lpSectionHeader = (IMAGE_SECTION_HEADER*)IMAGE_FIRST_SECTION(m_lpNtHeader);
	return (DWORD)IMAGE_NT_SIGNATURE;
}

const IMAGE_DOS_HEADER* CPeFile::GetDosHeader() const
{
	assert(m_dwType);
	return m_lpDosHeader;
}

const IMAGE_NT_HEADERS32* CPeFile::GetNtHeader() const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE || m_dwType == IMAGE_OS2_SIGNATURE || m_dwType == IMAGE_OS2_SIGNATURE_LE);
	return m_lpNtHeader;
}

BOOL CPeFile::Is64Bit() const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	return  m_b64Bit;
}



const IMAGE_SECTION_HEADER* CPeFile::GetSectionHeader(LPWORD lpSectionNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (lpSectionNum)
		*lpSectionNum = m_lpNtHeader->FileHeader.NumberOfSections;
	return m_lpSectionHeader;
}

const  IMAGE_IMPORT_DESCRIPTOR* CPeFile::GetImportDescriptor(LPDWORD lpImportDescriptorNum) const
{
	assert(m_dwType == IMAGE_NT_SIGNATURE);
	if (!m_lpImportManager) //如果没有获取到importManager句柄
	{
		if (lpImportDescriptorNum)
			*lpImportDescriptorNum = 0UL;
		return NULL;
	}
	if (lpImportDescriptorNum)
		*lpImportDescriptorNum = m_lpImportManager->m_dwImportDescriptorNum;
	return m_lpImportManager->m_lpImportDescriptor;
}