#pragma once

#ifndef _GETPEFILEINFO__H__H__H
#define _GETPEFILEINFO__H__H__H

#include <Windows.h>
#include <wintrust.h>

//通过数学运算计算指针偏移（而不是通过指针运算）
#define MakePtr(cast, ptr, addValue) ((cast)((DWORD_PTR)(ptr) + (DWORD_PTR)(addValue)))


//用于记录资源的ID标识
#ifndef _WIN64
typedef DWORD IDTYPE;
typedef LPDWORD PIDTYPE;
#else
typedef ULONGLONG IDTYPE;
typedef PULONGLONG PIDTYPE;
#endif

class CPeFile
{
public:
	CPeFile();
	~CPeFile();
public:
	//将pe文件附加到对象，成功返回IMAGE_DOS_SIGNATURE、IMAGE_OS2_SIGNATURE、IMAGE_OS2_SIGNATURE_LE、IMAGE_NT_SIGNATURE之一；
	//失败返回0UL（未知类型），1UL（文件操作失败），2（其他错误），【仅在没有PE文件附加到类对象时可用】
	DWORD Attach(LPCSTR lpszFilePath);
	//若有pe文件附加到对象则释放关联
	void Detach();
	//获取Attach信息，成功返回IMAGE_DOS_SIGNATURE、IMAGE_OS2_SIGNATURE、IMAGE_OS2_SIGNATURE_LE、IMAGE_NT_SIGNATURE之一；未成功返回0UL
	DWORD GetAttachInfo() const;

	//以下函数无特殊说明Attach成功后均可用
public:
	//获取文件句柄
	HANDLE GetFileHandle() const;
	//获取内存映射文件头部地址
	DWORD_PTR GetMappedFileStart() const;
	//获取内存映射文件头部指定偏移地址
	DWORD_PTR GetMappedFileOffset(DWORD dwFoa) const;
	//获取dos头
	const IMAGE_DOS_HEADER* GetDosHeader() const;
	//获取dos的入口地址
	DWORD GetDosEntryPoint() const;
	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE
public:
	//获取pe文件头
	const IMAGE_NT_HEADERS32* GetNtHeader() const;
	//返回文件是否为64位
	BOOL Is64Bit() const;
	//获取pe文件头的加载基址ImageBase(64位返回ULONGLONG类型，32位返回DWORD类型，需要进行转换)
	ULONGLONG GetImageBase() const;
	//获取pe文件头中的DataDirectory
	const IMAGE_DATA_DIRECTORY* GetDataDirectory() const;
	//获取DataDirectory入口的RVA
	DWORD GetDataDirectoryEntryRva(DWORD dwIndex) const;
	//获取节表
	const IMAGE_SECTION_HEADER* GetSectionHeader(LPWORD lpSectionNum = NULL) const;
	//将RVA转换为FOA
	BOOL RvaToFoa(DWORD dwRva, LPDWORD lpFoa = NULL, LPWORD lpSection = NULL) const;
	//将FOA转化为RVA
	BOOL FoaToRva(DWORD dwFoa, LPDWORD lpRva = NULL, LPWORD lpSection = NULL) const;
	//VA转为RVA
	DWORD VaToRva(DWORD dwVa) const; //32位
	DWORD VaToRva(ULONGLONG ullVa) const; //64位
	//RVA转VA
	ULONGLONG RvaToVa(DWORD dwRva) const;

	//以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE
public:
	//读取pe中的导出表
	BOOL ReadExport();
	//读取pe中的导入表
	BOOL ReadImport();
	//读取pe中的资源表
	BOOL ReadResource();
	//读取pe中的异常表
	BOOL ReadException();
	//读取pe中的属性证书表
	BOOL ReadSecurity();
	//读取pe中的基址重定位表
	BOOL ReadBaseRelocation();
	//读取pe中的调试数据
	BOOL ReadDebug();
	//读取pe中线程局部存储表
	BOOL ReadTLS();
	//读取pe中加载配置表
	BOOL ReadLoadConfig();
	//读取pe中绑定导入表
	BOOL ReadBoundImport();
	//读取pe中延迟加载导入表
	BOOL ReadDelayImport();
	//清理pe中导入表
	void ClearExport();
	void ClearImport();
	void ClearResource();
	void ClearException();
	void ClearSecurity();
	void ClearBaseRelocation();
	void ClearDebug();
	void ClearTLS();
	void ClearLoadConfig();
	void ClearBoundImport();
	void ClearDelayImport();
	//清理所有
	void ClearAll();

	//返回是否读取了pe中的的导出表
	BOOL IsReadExport() const;
	BOOL IsReadImport() const;
	BOOL IsReadResource() const;
	BOOL IsReadException() const;
	BOOL IsReadSecurity() const;
	BOOL IsReadBaseRelocation() const;
	BOOL IsReadDebug() const;
	BOOL IsReadTLS() const;
	BOOL IsReadLoadConfig() const;
	BOOL IsReadBoundImport() const;
	BOOL IsReadDelayImport() const;

	//以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadExport成功
public:
	//获取导入表
	const IMAGE_EXPORT_DIRECTORY* GetExportDirectory() const;
	//获取导出表各导出函数地址数组
	const DWORD* GetExportFunction(LPDWORD lpFuncNum = NULL) const;
	//获取导出表中被定义了名称的各导出函数名称地址数组
	const DWORD* GetExportName(LPDWORD lpNameNum = NULL) const;
	//获取导出表中被定义了名称的各导出函数的索引（数量可由lpNameNum传出）
	const WORD* GetExportNameOrdinal(LPDWORD lpNameNum = NULL) const;
	//解析导出函数地址数组中dwIndex项，返回值小于NumberOfNames为按名称导出（数值为序号），返回值等于NumberOfNames则为按序号导出
	DWORD ParseExportFunction(DWORD dwIndex) const;

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadImport成功
public:
	//获取各导入表（导入表数量可由lpImportDescriptorNum传出）
	const IMAGE_IMPORT_DESCRIPTOR* GetImportDescriptor(LPDWORD lpImportDescriptorNum = NULL) const;
	//获取第iImpoert个导入表中的IMAGE_THUNK_DATA32结构（64位程序实际是IMAGE_THUNK_DATA64）（数量可由lpCount传出）
	const IMAGE_THUNK_DATA32* GetImportThunkData(DWORD iImport, LPDWORD lpCount = NULL) const;
	//解析某个IMAGE_THUNK_DATA32结构（64位程序实际是IMAGE_THUNK_DATA64），返回结果：1表示按序号导入（lpParam可传出序号）；2表示按名称导入（lpParam可传出对应IMAGE_IMPORT_BY_NAME的FOA）；0失败【只需要IMAGE_NT_SIGNATURE即可用】
	int ParseThunkData(const IMAGE_THUNK_DATA32* lpThunk, LPDWORD lpParam = NULL) const;

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadResource成功
public:
	//获取第一层资源的ID，返回1表示第一层是目录，返回2表示第一层是数据，返回0表示无资源
	int GetFirstResourceId(PIDTYPE lpFirstID) const;
	//获取下一层资源的ID，返回1表示下一层是目录，返回2表示下一层是数据，返回0表示无下一层
	int GetNextResourceId(IDTYPE Id, DWORD iRes, PIDTYPE NextID) const;
	//解析Id对应的目录层，lpEntryNum可传出数组数量，lpLevel可传出第几级目录，lpResourceEntry传出本层对应的IMAGE_RESOURCE_DIRECTORY_ENTRY数组
	const IMAGE_RESOURCE_DIRECTORY* ParseResourceDirectory(IDTYPE Id, LPDWORD lpEntryNum = NULL, LPDWORD lpLevel = NULL, IMAGE_RESOURCE_DIRECTORY_ENTRY** lpResourceEntry = NULL) const;
	//解析dwId对应的数据层
	const IMAGE_RESOURCE_DATA_ENTRY* ParseResourceData(IDTYPE Id) const;
	//解析某个IMAGE_RESOURCE_DIRECTORY_ENTRY结构中Name成员，返回结果：1（dwParam为ID）；2（dwParam为对应IMAGE_RESOURCE_DIR_STRING_U的FOA）【只需要IMAGE_NT_SIGNATURE即可用】
	int ParseResourceDirectoryEntry(const IMAGE_RESOURCE_DIRECTORY_ENTRY* lpEntry, LPDWORD dwParam) const;

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadException成功
public:
	//获取异常表（数量可由lpRuntimeFunctionNum传出）
	const IMAGE_RUNTIME_FUNCTION_ENTRY* GetRuntimeFunction(LPDWORD lpRuntimeFunctionNum = NULL) const;

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadSecurity成功
public:
	//获取属性证书表（数量可由lpCertificateNum传出）
	const WIN_CERTIFICATE* const* GetCertificate(LPDWORD lpCertificateNum = NULL) const;

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadBaseRelocation成功
public:
	//获取各基址重定位表（数量可由lpBaseRelocationNum传出）
	const IMAGE_BASE_RELOCATION* const* GetBaseRelocation(LPDWORD lpBaseRelocationNum = NULL) const;
	//获得某个基址重定位表中的重定位块（数量可由lpCount传出，包括对齐用的）
	const WORD* GetBaseRelocationBlock(const IMAGE_BASE_RELOCATION* lpBaseRelocation, LPDWORD lpCount = NULL) const;
	//解析某个基址重定位表后的某一项，返回的是高4位的值，低12位的值可由lpParam传出【任何时候均后可用】
	static WORD ParseBaseRelocationBlock(WORD wBaseRelocationBlock, LPWORD lpParam = NULL);

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadDebug成功
public:
	//获取调试数据（数量可由lpDebugDirectoryNum传出）
	const IMAGE_DEBUG_DIRECTORY* GetDebugDirectory(LPDWORD lpDebugDirectoryNum = NULL) const;
	//获取第dwIndex项调试信息起始地址，未获取到返回NULL
	LPCVOID GetDebugInfoStart(DWORD dwIndex);

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadTLS成功
public:
	//获取线程局部存储表（如果是64位程序，返回的实际是const IMAGE_TLS_DIRECTORY64*）
	const IMAGE_TLS_DIRECTORY32* GetTLSDirectory() const;
	//获取线程局部存储表回调函数数组的指针（如果是64位程序，返回的实际是const ULONGLONG*）（数量可由lpCallbackNum传出）
	const DWORD* GetTLSCallback(LPDWORD lpCallbackNum = NULL) const;

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadLoadConfig成功

public:
	//获取加载配置表（如果是64位程序，返回的实际是const IMAGE_LOAD_CONFIG_DIRECTORY64*）
	const IMAGE_LOAD_CONFIG_DIRECTORY32* GetLoadConfigDirectory() const;

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadBoundImport成功

public:
	//获取绑定导入表（数量可由lpBoundImportNum传出）
	const IMAGE_BOUND_IMPORT_DESCRIPTOR* const* GetBoundImportDescriptor(LPDWORD lpBoundImportNum = NULL) const;
	//获取第iBoundImpoert个绑定导入表（数量可由lpRefNum传出）
	const IMAGE_BOUND_FORWARDER_REF* GetBoundImportForwarderRef(DWORD iBoundImport, LPDWORD lpRefNum = NULL) const;

	// 以下函数无特殊说明仅用于IMAGE_NT_SIGNATURE且ReadDelayImport成功

public:
	//获取延迟加载导入表（数量可由lpDelayImportNum传出）
	const IMAGE_DELAYLOAD_DESCRIPTOR* GetDelayImportDescriptor(LPDWORD lpDelayImportNum = NULL) const;


	//禁止拷贝、移动、赋值
private:
	CPeFile(const CPeFile&);
	CPeFile(const CPeFile&&);
	CPeFile& operator=(const CPeFile&);
	CPeFile& operator=(const CPeFile&&);

protected:
	class CPeExportManager
	{
	public:
		CPeExportManager();
		BOOL Initialize(IMAGE_EXPORT_DIRECTORY* lpExportStart, const CPeFile* lpPe);
	public:
		IMAGE_EXPORT_DIRECTORY* m_lpExportDirectory;
		DWORD* m_lpExportFunction;
		DWORD* m_lpExportName;
		WORD* m_lpExportNameOrdinal;
	};
	class CPeImportManager
	{
	public:
		CPeImportManager();
		~CPeImportManager();
		BOOL Initialize(IMAGE_IMPORT_DESCRIPTOR* lpImportStart, const CPeFile* lpPe);
	public:
		DWORD m_dwImportDescriptorNum;
		IMAGE_IMPORT_DESCRIPTOR* m_lpImportDescriptor;
		DWORD* m_lpThunkDataCount;
		IMAGE_THUNK_DATA32** m_lpThunkData;
	};
	class CPeResourceManager
	{
	public:
		CPeResourceManager(IMAGE_RESOURCE_DIRECTORY* lpResourceStart);
		~CPeResourceManager();
	protected:
		CPeResourceManager();
		void SearchResource(IMAGE_RESOURCE_DIRECTORY* lpResourceDirectory, DWORD dwLevel, IMAGE_RESOURCE_DIRECTORY* lpResourceStart);
	public:
		DWORD m_dwLevel;
		IMAGE_RESOURCE_DIRECTORY* m_lpResourceDirectory;
		DWORD m_dwResourceDirectoryEntryNum;
		CPeResourceManager* m_lpNext;
	};
	class CPeExceptionManager
	{
	public:
		CPeExceptionManager(IMAGE_RUNTIME_FUNCTION_ENTRY* lpRuntimeFunctionStart, const CPeFile* lpPe);
	public:
		DWORD m_dwRuntimeFunctionNum;
		IMAGE_RUNTIME_FUNCTION_ENTRY* m_lpRuntimeFunctionStart;
	};
	class CPeSecurityManager
	{
	public:
		CPeSecurityManager(WIN_CERTIFICATE* lpSecurityStart, DWORD dwSize);
		~CPeSecurityManager();
	public:
		DWORD m_dwSecuritNum;
		WIN_CERTIFICATE** m_lpSecurity;
	};
	class CPeBaseRelocationManager
	{
	public:
		CPeBaseRelocationManager(IMAGE_BASE_RELOCATION* lpBaseRelocationStart);
		~CPeBaseRelocationManager();
	public:
		DWORD m_dwBaseRelocationNum;
		IMAGE_BASE_RELOCATION** m_lpBaseRelocation;
	};
	class CPeDebugManager
	{
	public:
		CPeDebugManager(IMAGE_DEBUG_DIRECTORY* lpDebugStart, const CPeFile* lpPe);
	public:
		DWORD m_dwDebugDirectoryNum;
		IMAGE_DEBUG_DIRECTORY* m_lpDebugDirectory;
	};
	class CPeTLSManager
	{
	public:
		BOOL Initialize(IMAGE_TLS_DIRECTORY32* lpTLSStart, const CPeFile* lpPe);
	public:
		IMAGE_TLS_DIRECTORY32* m_lpTLSDirectory;
		DWORD* m_lpTLSCallback;
		DWORD m_dwTLSCallbackNum;
	};
	class CPeLoadConfigManager
	{
	public:
		CPeLoadConfigManager(IMAGE_LOAD_CONFIG_DIRECTORY32* lpLoadConfigStart);
	public:
		IMAGE_LOAD_CONFIG_DIRECTORY32* m_lpLoadConfigDirectory;
	};
	class CPeBoundImportManager
	{
	public:
		CPeBoundImportManager(IMAGE_BOUND_IMPORT_DESCRIPTOR* lpBoundImportStart);
		~CPeBoundImportManager();
	public:
		DWORD m_dwBoundImportDescriptorNum;
		IMAGE_BOUND_IMPORT_DESCRIPTOR** m_lpBoundImportDescriptor;
	};
	class CPeDelayImportManager
	{
	public:
		CPeDelayImportManager(IMAGE_DELAYLOAD_DESCRIPTOR* lpDelayImportStart);
	public:
		DWORD m_dwDelayImportDescriptorNum;
		IMAGE_DELAYLOAD_DESCRIPTOR* m_lpDelayImportDescriptor;
	};

protected:
	int OpenPeFile(LPCSTR lpszFilePath);
	void CloseFile();
	DWORD CheckHeaders();
	BOOL ReadExportAux();
	BOOL ReadImportAux();
	BOOL ReadResourceAux();
	BOOL ReadExceptionAux();
	BOOL ReadSecurityAux();
	BOOL ReadBaseRelocationAux();
	BOOL ReadDebugAux();
	BOOL ReadTLSAux();
	BOOL ReadLoadConfigAux();
	BOOL ReadBoundImportAux();
	BOOL ReadDelayImportAux();
	void ClearExportAux();
	void ClearImportAux();
	void ClearResourceAux();
	void ClearExceptionAux();
	void ClearSecurityAux();
	void ClearBaseRelocationAux();
	void ClearDebugAux();
	void ClearTLSAux();
	void ClearLoadConfigAux();
	void ClearBoundImportAux();
	void ClearDelayImportAux();

protected:
	HANDLE m_hFile;
	HANDLE m_hFileMap;
	LPVOID m_lpMemory;
	DWORD m_dwType;
	BOOL m_b64Bit;
	IMAGE_DOS_HEADER* m_lpDosHeader;
	IMAGE_NT_HEADERS32* m_lpNtHeader;
	IMAGE_SECTION_HEADER* m_lpSectionHeader;
	DWORD m_dwReadFlag;
	CPeExportManager* m_lpExportManager;
	CPeImportManager* m_lpImportManager;
	CPeResourceManager* m_lpResourceManager;
	CPeExceptionManager* m_lpExceptionManager;
	CPeSecurityManager* m_lpSecurityManager;
	CPeBaseRelocationManager* m_lpBaseRelocationManager;
	CPeDebugManager* m_lpDebugManager;
	CPeTLSManager* m_lpTLSManager;
	CPeLoadConfigManager* m_lpLoadConfigManager;
	CPeBoundImportManager* m_lpBoundImportManager;
	CPeDelayImportManager* m_lpDelayImportManager;

};
#endif