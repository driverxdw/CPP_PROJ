#include "pch.h"
#include "CPeFile.h"
#include <iostream>

using namespace std;
int main()
{
	const char* lpszPath = "D:\\C++_PROJ\\PEAnalysis\\crackme2019D7.exe";
	CPeFile PE;
	if (PE.Attach(lpszPath) != IMAGE_NT_SIGNATURE)
		//cout << hex<<PE.Attach(lpszPath) << endl;
		return -1;
	//HANDLE m_hFile = ::CreateFileA(lpszPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	//获取dos头指针(结构体类型)
	const IMAGE_DOS_HEADER*  lpDosHeader = PE.GetDosHeader();
	//lpDosHeader->e_xxx
	/*
	typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
	} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
	*/
	cout << "*************************IMAGE_DOS_HEADER**************************" << endl;
	cout <<hex<< lpDosHeader->e_magic << endl; //魔术数字0x4d5a
	cout << hex << lpDosHeader->e_cblp << endl; //文件最后页的字节数
	cout << hex << lpDosHeader->e_cp << endl; //文件页数
	cout << hex << lpDosHeader->e_crlc << endl;//重定位元素个数
	cout << hex << lpDosHeader->e_cparhdr << endl;//头部尺寸
	cout << hex << lpDosHeader->e_minalloc << endl;//所需的最小附加段
	cout << hex << lpDosHeader->e_maxalloc << endl;//所需的最大附加段
	cout << hex << lpDosHeader->e_ss << endl;//初始ss值（栈段 偏移）
	cout << hex << lpDosHeader->e_sp << endl;//初始sp值
	cout << hex << lpDosHeader->e_csum << endl;//校验和
	cout << hex << lpDosHeader->e_ip << endl;//初始ip值
	cout << hex << lpDosHeader->e_cs << endl;//初始cs值（代码段 偏移）
	cout << hex << lpDosHeader->e_lfarlc << endl;//重定位表的文件内偏移
	cout << hex << lpDosHeader->e_ovno << endl;//覆盖号
	//cout << hex << lpDosHeader->e_res << endl;//保留字
	cout << hex << lpDosHeader->e_oemid << endl;//OEM标识符
	//cout << hex << lpDosHeader->e_res2[0]<< endl;//保留字
	cout << hex << lpDosHeader->e_lfanew << endl;//新exe头部地址

	cout << "**********************IAMGE_NT_HEADER**************************" << endl;
	const IMAGE_NT_HEADERS32* lpNtHeader32 = PE.GetNtHeader();
	const IMAGE_NT_HEADERS64* lpNtHeader64 = (IMAGE_NT_HEADERS64*)lpNtHeader32;
	BOOL b64Bit =PE.Is64Bit();
	if (b64Bit == 0)
	{
		cout << "32位程序" << endl;
		cout << hex << lpNtHeader32->Signature << endl; //IMAGE_NT_SIGNATURE魔数

		//以下输出IMAGE_FILE_HEADER的各个元素
		/*
		typedef struct _IMAGE_FILE_HEADER {
		WORD    Machine;
		WORD    NumberOfSections;
		DWORD   TimeDateStamp;
		DWORD   PointerToSymbolTable;
		DWORD   NumberOfSymbols;
		WORD    SizeOfOptionalHeader;
		WORD    Characteristics;
		} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
		*/
		cout << hex << lpNtHeader32->FileHeader.Machine << endl;//运行平台
		/*
		#define IMAGE_FILE_MACHINE_UNKNOWN           0
		#define IMAGE_FILE_MACHINE_TARGET_HOST       0x0001  // Useful for indicating we want to interact with the host and not a WoW guest.
		#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
		#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
		*/
		cout << hex << lpNtHeader32->FileHeader.NumberOfSections << endl;//文件区块数目 
		cout << hex << lpNtHeader32->FileHeader.TimeDateStamp << endl;//文件创建日期和时间
		cout << hex << lpNtHeader32->FileHeader.PointerToSymbolTable << endl;//指向符号表(用于调试）
		cout << hex << lpNtHeader32->FileHeader.NumberOfSymbols << endl;//符号表中符号个数(用于调试)
		cout << hex << lpNtHeader32->FileHeader.SizeOfOptionalHeader << endl;//IMAGE_OPTIONAL_HEADER32结构大小
		cout << hex << lpNtHeader32->FileHeader.Characteristics << endl;//文件属性
		

		cout << "**********************IMAGE_OPTIONAL_HEADER**************************" << endl;
		//IMAGE_FILE_HEADER不足以定义pe文件属性，所以这里使用了IMAGE_OPTIONAL_HEADER
		//最后128个字节为数据目录(IMAGE_DATA_DIRECTORY)
		/*
		WORD    Magic;
		BYTE    MajorLinkerVersion;
		BYTE    MinorLinkerVersion;
		DWORD   SizeOfCode;
		DWORD   SizeOfInitializedData;
		DWORD   SizeOfUninitializedData;
		DWORD   AddressOfEntryPoint;
		DWORD   BaseOfCode;
		DWORD   BaseOfData;
		//
		// NT additional fields. NT结构增加的领域
		//
		DWORD   ImageBase;
		DWORD   SectionAlignment;
		DWORD   FileAlignment;
		WORD    MajorOperatingSystemVersion;
		WORD    MinorOperatingSystemVersion;
		WORD    MajorImageVersion;
		WORD    MinorImageVersion;
		WORD    MajorSubsystemVersion;
		WORD    MinorSubsystemVersion;
		DWORD   Win32VersionValue;
		DWORD   SizeOfImage;
		DWORD   SizeOfHeaders;
		DWORD   CheckSum;
		WORD    Subsystem;
		WORD    DllCharacteristics;
		DWORD   SizeOfStackReserve;
		DWORD   SizeOfStackCommit;
		DWORD   SizeOfHeapReserve;
		DWORD   SizeOfHeapCommit;
		DWORD   LoaderFlags;
		DWORD   NumberOfRvaAndSizes;
		*/

		//标志字，ROM映像(107h),普通可执行文件(10bh)
		cout << hex << lpNtHeader32->OptionalHeader.Magic << endl;
		//链接程序的主版本号
		cout << hex << lpNtHeader32->OptionalHeader.MajorLinkerVersion << endl;
		//链接程序次版本号
		cout << hex << lpNtHeader32->OptionalHeader.MinorImageVersion << endl;
		//代码段大小
		cout << hex << lpNtHeader32->OptionalHeader.SizeOfCode << endl;
		//已初始化数据大小
		cout << hex << lpNtHeader32->OptionalHeader.SizeOfInitializedData << endl;
		//未初始化数据大小(bass)
		cout << hex << lpNtHeader32->OptionalHeader.SizeOfUninitializedData << endl;
		//入口点地址(RVA)
		cout << hex << lpNtHeader32->OptionalHeader.AddressOfEntryPoint << endl;
		//代码段起始地址（RVA）
		cout << hex << lpNtHeader32->OptionalHeader.BaseOfCode << endl;
		//数据段起始地址（RVA）
		cout << hex << lpNtHeader32->OptionalHeader.BaseOfData << endl;
		
		//程序的首选装载地址
		cout << hex << lpNtHeader32->OptionalHeader.ImageBase << endl;
		//内存中区块对齐大小
		cout << hex << lpNtHeader32->OptionalHeader.SectionAlignment << endl;
		//文件中区块对齐大小
		cout << hex << lpNtHeader32->OptionalHeader.FileAlignment << endl;
		//要求操作系统最低版本号的主版本号
		cout << hex << lpNtHeader32->OptionalHeader.MajorOperatingSystemVersion << endl;
		//要求操作系统最低版本号的副版本号
		cout << hex << lpNtHeader32->OptionalHeader.MinorOperatingSystemVersion << endl;
		/*
		.
		.
		.
		*/
		//映像装入内存后的总尺寸
		cout << hex << lpNtHeader32->OptionalHeader.SizeOfImage << endl;
		//所有头+区块表的尺寸大小
		cout << hex << lpNtHeader32->OptionalHeader.SizeOfHeaders << endl;
		//映像的校验和
		cout << hex << lpNtHeader32->OptionalHeader.CheckSum << endl;
		//可执行文件期待的子系统
		cout << hex << lpNtHeader32->OptionalHeader.Subsystem << endl;
		//初始化时栈大小
		cout << hex << lpNtHeader32->OptionalHeader.SizeOfStackReserve << endl;
		//初始化时实际提交的栈大小
		cout << hex << lpNtHeader32->OptionalHeader.SizeOfStackCommit << endl;
		//初始化时保留的堆大小
		cout << hex << lpNtHeader32->OptionalHeader.SizeOfHeapReserve << endl;
		//初始化时实际提交的堆大小
		cout << hex << lpNtHeader32->OptionalHeader.SizeOfHeapCommit << endl;
		//与调试有关，默认为0
		cout << hex << lpNtHeader32->OptionalHeader.LoaderFlags << endl;
		//下一个结构体（数据目录）的项数(默认16)
		cout << hex << lpNtHeader32->OptionalHeader.NumberOfRvaAndSizes << endl;

	}
	if (b64Bit == -1)
		cout << "64位程序" << endl;
	//cout << hex << lpNtHeader32->Signature << endl;
	//cout << b64Bit << hex << endl;

	cout << "*************************IMAGE_Section_Header***********************" << endl;
	/*
	typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
			DWORD   PhysicalAddress;
			DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

	*/
	WORD wSectionNum;
	const IMAGE_SECTION_HEADER* lpSectionHeader = PE.GetSectionHeader(&wSectionNum);
	for (WORD i = 0; i < wSectionNum; i++) {
		cout << "第" << i+1 << "个节区:" << endl;
		cout << lpSectionHeader[i].Name<< endl; //各个节区名
		cout << hex<<lpSectionHeader[i].Misc.PhysicalAddress<<endl;//物理地址
		cout << hex<<lpSectionHeader[i].Misc.VirtualSize<<endl;//节区对其前的大小（实际大小）
		cout << hex << lpSectionHeader->VirtualAddress << endl;//该块装载到内存中的RVA
		cout << hex << lpSectionHeader->SizeOfRawData << endl;//物理长度（文件中对齐后的大小）
		cout << hex << lpSectionHeader->PointerToRawData << endl;//节基于文件的偏移量
		cout << hex << lpSectionHeader->PointerToRelocations << endl;//重定位的偏移
		cout << hex << lpSectionHeader->PointerToLinenumbers << endl;//行号表偏移
		cout << hex << lpSectionHeader->NumberOfRelocations << endl;//重定位项的数目
		cout << hex << lpSectionHeader->NumberOfLinenumbers << endl;//行号表的书目
		cout << hex << lpSectionHeader->Characteristics << endl;//节属性
	}


	//导入表
	DWORD nImport;
	




	return 0;
}