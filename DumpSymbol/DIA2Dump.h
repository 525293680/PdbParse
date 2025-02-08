#pragma once

#include <dia2.h>
#include <diacreate.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>


extern IDiaDataSource* g_pDiaDataSource;
extern IDiaSession* g_pDiaSession;
extern IDiaSymbol* g_pGlobalSymbol;

bool LoadDataFromPdb(const wchar_t*, IDiaDataSource**, IDiaSession**, IDiaSymbol**);

void Cleanup();

// 定义 CodeView PDB 7.0 结构
#pragma pack(push,1)
typedef struct _CV_INFO_PDB70 {
	DWORD CvSignature; // 应该为 "RSDS"（即 0x53445352）
	GUID Signature;
	DWORD Age;
	CHAR PdbFileName[MAX_PATH]; // 后跟以 NULL 结束的 PDB 文件名字符串
} CV_INFO_PDB70, * PCV_INFO_PDB70;
#pragma pack(pop)