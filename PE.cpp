// Test.cpp : 定义控制台应用程序的入口点。
//

_CRT_SECURE_NO_WARNINGS

#include "stdafx.h"

PVOID FileToMem(IN PCHAR szFilePath, long *dwFileSize)
{

	FILE* pFile = fopen(szFilePath, "rb");
	if (!pFile)
	{
		printf("Cannot open file!\n");
		return NULL;
	}
	fseek(pFile,0,SEEK_END);
	*dwFileSize =ftell(pFile);
	fseek(pFile,0,SEEK_SET);

	PCHAR pFileBuffer = (PCHAR)malloc(*dwFileSize);
	if (!pFileBuffer)
	{
		printf("cannot malloc filebuffer!\n");
		return NULL;
	}

	fread(pFileBuffer,*dwFileSize,1,pFile);
	
	if (*(PSHORT)pFileBuffer!= IMAGE_DOS_SIGNATURE)
	{
		printf("PE not read!\n");
		free(pFileBuffer);
	}

	fclose(pFile);
	return pFileBuffer;

}

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PUCHAR)pFileBuffer+pDos->e_lfanew);
	PIMAGE_FILE_HEADER pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth+4);
	PIMAGE_OPTIONAL_HEADER pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil+IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo+pFil->SizeOfOptionalHeader);

	//分配拉伸后的内存
	DWORD dwImageSize = pOpo->SizeOfImage;
	PUCHAR pTemp = (PUCHAR)malloc(dwImageSize);
	if (!pTemp)
	{
		printf("Memory malloc error!\n");
		return 0;
	}
	memset(pTemp,0,dwImageSize);
	//1.copy header 
	memcpy(pTemp,pFileBuffer,pOpo->SizeOfHeaders);

	//2.copy section
	for (size_t i=0;i<pFil->NumberOfSections;i++)
	{
		memcpy(pTemp+pSec[i].VirtualAddress, (PUCHAR)pFileBuffer+pSec[i].PointerToRawData,pSec[i].SizeOfRawData);
	
	}
	return 0;
	
}

DWORD foaToRva(IN PCHAR szFilePath, IN DWORD foa)
{

	FILE* pFileBuffer = fopen(szFilePath, "rb");
	if (!pFileBuffer)
	{
		printf("Cannot open file!\n");
		return NULL;
	}
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PUCHAR)pFileBuffer+pDos->e_lfanew);
	PIMAGE_FILE_HEADER pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth+4);
	PIMAGE_OPTIONAL_HEADER pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil+IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo+pFil->SizeOfOptionalHeader);
	printf("Export Table RVA: %x \n",pOpo->DataDirectory[0].VirtualAddress);
	printf("Export Table Size: %x \n",pOpo->DataDirectory[0].Size);

	//1.foa<optionalheader 或 sectionalignment = filealignment 直接返回
	if (foa<pFil->SizeOfOptionalHeader || (pOpo->SectionAlignment==pOpo->FileAlignment))
	{
		free(pFileBuffer);
		return foa;
	}

	//2.foa>option
	if (foa<pOpo->SizeOfImage)
	{
		for (size_t i=0; i<pFil->NumberOfSections; i++)
		{
			
			if (foa>(pSec[i].PointerToRawData) && foa<(pSec[i].PointerToRawData+pSec->SizeOfRawData))
			{
				// RVA = foa - PointerToRawData + VirtualAddress
				free(pFileBuffer);
				return foa - pSec[i].PointerToRawData + pSec->VirtualAddress;
			}
		}

	} else 
	{
		printf("无法转换地址.\n");
		free(pFileBuffer);
		return 0;
	}



}

int _tmain(int argc, _TCHAR* argv[])
{

	CHAR targetFilePath[20] = "C:\\vmmreg32.dll";

	long dwFileSize =0;
	PVOID pFileBuffer;
	pFileBuffer=FileToMem(targetFilePath,&dwFileSize);
	printf("filesize is %d.\n",dwFileSize);

	
	getchar();
	return 0;
}

