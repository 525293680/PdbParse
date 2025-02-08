#include "Dia2Dump.h"
#include <oleauto.h>
#include <cstdint>
#include <windows.h>
#include <DbgHelp.h>
#include <urlmon.h>
#include <shlobj.h>

// 链接库
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "urlmon.lib")
#pragma warning (disable : 4100)

IDiaDataSource* gDiaDataSource;
IDiaSession* gDiaSession;
IDiaSymbol* gGlobalSymbol;

uint32_t ComputeCrc32(const void* data, size_t length)
{
	static uint32_t crcTable[256];
	static bool tableInitialized = false;
	const uint32_t polynomial = 0xEDB88320;

	if (!tableInitialized)
	{
		for (uint32_t i = 0; i < 256; ++i)
		{
			uint32_t crc = i;
			for (int j = 0; j < 8; ++j)
			{
				crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
			}
			crcTable[i] = crc;
		}
		tableInitialized = true;
	}

	uint32_t crc = 0xFFFFFFFF;
	const uint8_t* byteData = reinterpret_cast<const uint8_t*>(data);
	while (length--)
	{
		crc = (crc >> 8) ^ crcTable[(crc ^ *byteData++) & 0xFF];
	}
	return ~crc;
}

uint64_t ComputeCrc64(const void* data, size_t length)
{
	static uint64_t crcTable[256];
	static bool tableInitialized = false;
	const uint64_t polynomial = 0xC96C5795D7870F42; // ECMA-182多项式

	if (!tableInitialized)
	{
		for (uint64_t i = 0; i < 256; ++i)
		{
			uint64_t crc = i;
			for (int j = 0; j < 8; ++j)
			{
				crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
			}
			crcTable[i] = crc;
		}
		tableInitialized = true;
	}

	uint64_t crc = 0xFFFFFFFFFFFFFFFF;
	const uint8_t* byteData = reinterpret_cast<const uint8_t*>(data);
	while (length--)
	{
		crc = (crc >> 8) ^ crcTable[(crc ^ *byteData++) & 0xFF];
	}
	return ~crc;
}

void DumpPublicSymbols(IDiaSymbol* globalSymbol, const char* symbolFilePath)
{
	IDiaEnumSymbols* enumSymbols = nullptr;
	IDiaSymbol* symbol = nullptr;
	ULONG fetchedCount = 1;
	BSTR symbolName = nullptr;

	FILE* filePtr = nullptr;
	// 使用 "ab+" 模式打开文件
	errno_t err = fopen_s(&filePtr, symbolFilePath, "ab+");
	if (err != 0)
		return;

	HRESULT hr = globalSymbol->findChildren(SymTagPublicSymbol, nullptr, nsNone, &enumSymbols);
	if (FAILED(hr))
	{
		fclose(filePtr);
		return;
	}

	while (SUCCEEDED(enumSymbols->Next(1, &symbol, &fetchedCount)) && (fetchedCount == 1))
	{
		hr = symbol->get_name(&symbolName);
		if (FAILED(hr))
		{
			hr = symbol->get_undecoratedName(&symbolName);
			if (FAILED(hr))
			{
				symbol->Release();
				continue;
			}
		}
		if (wcsstr(symbolName, L"_"))
		{
			SysFreeString(symbolName);
			symbol->Release();
			continue;
		}

		DWORD RetVal = 0;
		hr = symbol->get_relativeVirtualAddress(&RetVal);
		if (FAILED(hr))
		{
			SysFreeString(symbolName);
			symbol->Release();
			continue;
		}

		size_t nameByteLength = wcslen(symbolName) * sizeof(wchar_t);
		uint32_t checksum = ComputeCrc32(symbolName, nameByteLength);

		fwrite(&checksum, sizeof(checksum), 1, filePtr);
		fwrite(&RetVal, sizeof(RetVal), 1, filePtr);

		SysFreeString(symbolName);
		symbol->Release();
	}

	enumSymbols->Release();
	fclose(filePtr);
}

bool GetPdbInfo(PCV_INFO_PDB70 pdbInfo)
{
	memset(pdbInfo, 0, sizeof(CV_INFO_PDB70));

	// 获取系统目录路径
	wchar_t ntoskrnlPath[MAX_PATH];
	GetSystemDirectoryW(ntoskrnlPath, MAX_PATH);
	// 构建 ntoskrnl.exe 完整路径
	wcscat_s(ntoskrnlPath, MAX_PATH, L"\\ntoskrnl.exe");

	HANDLE fileHandle = CreateFileW(ntoskrnlPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	// 创建文件映射
	HANDLE mappingHandle = CreateFileMappingW(fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!mappingHandle)
	{
		CloseHandle(fileHandle);
		return false;
	}

	// 将整个文件映射到内存
	LPVOID baseAddress = MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0);
	if (!baseAddress)
	{
		CloseHandle(mappingHandle);
		CloseHandle(fileHandle);
		return false;
	}

	// 使用 ImageDirectoryEntryToData 获取调试目录
	ULONG debugDataSize = 0;
	PIMAGE_DEBUG_DIRECTORY debugDirectory = (PIMAGE_DEBUG_DIRECTORY)
		ImageDirectoryEntryToData(baseAddress, FALSE, IMAGE_DIRECTORY_ENTRY_DEBUG, &debugDataSize);
	if (!debugDirectory)
	{
		UnmapViewOfFile(baseAddress);
		CloseHandle(mappingHandle);
		CloseHandle(fileHandle);
		return false;
	}

	DWORD debugCount = debugDataSize / sizeof(IMAGE_DEBUG_DIRECTORY);
	for (DWORD i = 0; i < debugCount; i++)
	{
		if (debugDirectory[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW)
		{
			memcpy(pdbInfo, (BYTE*)baseAddress + debugDirectory[i].PointerToRawData, sizeof(CV_INFO_PDB70));
			break;
		}
	}

	UnmapViewOfFile(baseAddress);
	CloseHandle(mappingHandle);
	CloseHandle(fileHandle);

	if (pdbInfo->CvSignature != 0x53445352)
	{
		return false;
	}
	return true;
}

int RemoveDirectoryRecursive(const char* path)
{
	char delPath[MAX_PATH] = { 0 };
	sprintf_s(delPath, "%s*", path);
	SHFILEOPSTRUCTA fileOp = { 0 };
	fileOp.hwnd = nullptr;
	fileOp.wFunc = FO_DELETE;
	fileOp.pFrom = delPath;
	fileOp.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
	return SHFileOperationA(&fileOp);
}

bool FetchPdbFile(char pdbSaveName[MAX_PATH], bool updateExisting)
{
	memset(pdbSaveName, 0, MAX_PATH);

	char windowsDir[MAX_PATH];
	DWORD pathLen = GetWindowsDirectoryA(windowsDir, MAX_PATH);
	if (pathLen == 0 || pathLen > MAX_PATH)
		return false;

	char pdbSavePath[MAX_PATH] = { 0 };
	sprintf_s(pdbSavePath, MAX_PATH, "%s\\Temp\\Symbol\\", windowsDir);

	CV_INFO_PDB70 pdbInfo{};
	if (!GetPdbInfo(&pdbInfo))
	{
		RemoveDirectoryRecursive(pdbSavePath);
		return false;
	}

	char signatureStr[64] = { 0 };
	sprintf_s(signatureStr, 64,
			  "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
			  pdbInfo.Signature.Data1,
			  pdbInfo.Signature.Data2,
			  pdbInfo.Signature.Data3,
			  pdbInfo.Signature.Data4[0],
			  pdbInfo.Signature.Data4[1],
			  pdbInfo.Signature.Data4[2],
			  pdbInfo.Signature.Data4[3],
			  pdbInfo.Signature.Data4[4],
			  pdbInfo.Signature.Data4[5],
			  pdbInfo.Signature.Data4[6],
			  pdbInfo.Signature.Data4[7],
			  pdbInfo.Age);

	int dirRet = SHCreateDirectoryExA(nullptr, pdbSavePath, nullptr);
	if (dirRet == ERROR_ALREADY_EXISTS)
	{
		// 构造带后缀过滤的路径，用于删除目录下所有特定后缀的文件，例如只删除.sdat文件
		char delPath[MAX_PATH] = { 0 };
		if (updateExisting)
			sprintf_s(delPath, "%s*", pdbSavePath);
		else
			sprintf_s(delPath, "%s*SDAT", pdbSavePath);
		SHFILEOPSTRUCTA fileOp = { 0 };
		fileOp.hwnd = nullptr;
		fileOp.wFunc = FO_DELETE;
		fileOp.pFrom = delPath;
		fileOp.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
		SHFileOperationA(&fileOp);
	}
	else if (dirRet != ERROR_SUCCESS)
		return false;

	// 构造保存路径和文件名
	sprintf_s(pdbSaveName, MAX_PATH, "%s%s%s", pdbSavePath, signatureStr, ".PDAT");
	if (!updateExisting)
	{
		// 检查文件是否存在
		if (GetFileAttributesA(pdbSaveName) != INVALID_FILE_ATTRIBUTES)
			return true;
	}

	// 构造URL字符串
	// 微软源: https://msdl.microsoft.com/download/symbols/PdbFileName/GUIDAGE/PdbFileName
	// 国内源: http://msdl.blackint3.com:88/download/symbols/PdbFileName/GUIDAGE/PdbFileName
	char msUrl[MAX_PATH] = { 0 };
	char cnUrl[MAX_PATH] = { 0 };

	sprintf_s(cnUrl, MAX_PATH,
			  "http://msdl.blackint3.com:88/download/symbols/%s/%s/%s",
			  pdbInfo.PdbFileName,
			  signatureStr,
			  pdbInfo.PdbFileName);

	sprintf_s(msUrl, MAX_PATH,
			  "http://msdl.microsoft.com/download/symbols/%s/%s/%s",
			  pdbInfo.PdbFileName,
			  signatureStr,
			  pdbInfo.PdbFileName);

	// 下载PDB文件
	HRESULT hr = URLDownloadToFileA(nullptr, cnUrl, pdbSaveName, 0, nullptr);
	if (FAILED(hr))
	{
		hr = URLDownloadToFileA(nullptr, msUrl, pdbSaveName, 0, nullptr);
		if (FAILED(hr))
		{
			memset(pdbSavePath, 0, MAX_PATH);
			memset(pdbSaveName, 0, MAX_PATH);
			return false;
		}
	}
	// 设置属性为隐藏和系统 (如有需要可启用)
	//  SetFileAttributesA(pdbSaveName, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
	return true;
}

////////////////////////////////////////////////////////////
int wmain(int argc, wchar_t* argv[])
{
	char pdbSaveName[MAX_PATH] = { 0 };
	wchar_t pdbSaveNameW[MAX_PATH] = { 0 };

	if (!FetchPdbFile(pdbSaveName, false))
		return -1;

	// 将 pdbSaveName 转换为宽字符
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, pdbSaveNameW, pdbSaveName, strlen(pdbSaveName));

	// 去掉 pdbSaveName 扩展名
	char* dotPos = strrchr(pdbSaveName, '.');
	if (dotPos)
		*dotPos = '\0';

	// 追加 .sdat 扩展名
	strcat_s(pdbSaveName, MAX_PATH, ".SDAT");

	if (!LoadDataFromPdb(pdbSaveNameW, &gDiaDataSource, &gDiaSession, &gGlobalSymbol))
	{
		DeleteFileA(pdbSaveName);
		DeleteFile(pdbSaveNameW);
		return -1;
	}

	DumpPublicSymbols(gGlobalSymbol, pdbSaveName);

	Cleanup();

	return 0;
}

////////////////////////////////////////////////////////////
bool LoadDataFromPdb(const wchar_t* pdbFileName,
					 IDiaDataSource** ppDataSource,
					 IDiaSession** ppSession,
					 IDiaSymbol** ppGlobalSymbol)
{
	HRESULT hr = NoRegCoCreate(L"msdia140.dll", // 直接使用 DLL 名
							   __uuidof(DiaSource),
							   __uuidof(IDiaDataSource),
							   (void**)ppDataSource);

	if (FAILED(hr))
	{
		wprintf(L"NoRegCoCreate failed - HRESULT = %08X\n", hr);
		return false;
	}

	hr = (*ppDataSource)->loadDataFromPdb(pdbFileName);
	if (FAILED(hr))
	{
		wprintf(L"loadDataFromPdb failed - HRESULT = %08X\n", hr);
		return false;
	}

	// Open a session for querying symbols
	hr = (*ppDataSource)->openSession(ppSession);
	if (FAILED(hr))
	{
		wprintf(L"openSession failed - HRESULT = %08X\n", hr);
		return false;
	}

	// Retrieve a reference to the global scope
	hr = (*ppSession)->get_globalScope(ppGlobalSymbol);
	if (hr != S_OK)
	{
		wprintf(L"get_globalScope failed\n");
		return false;
	}

	return true;
}

////////////////////////////////////////////////////////////
void Cleanup()
{
	if (gGlobalSymbol)
	{
		gGlobalSymbol->Release();
		gGlobalSymbol = nullptr;
	}

	if (gDiaSession)
	{
		gDiaSession->Release();
		gDiaSession = nullptr;
	}
}