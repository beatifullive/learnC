// Test.cpp : 定义控制台应用程序的入口点。
//

_CRT_SECURE_NO_WARNINGS

#include "stdafx.h"


/** 
* @brief 函数简要说明-read PE file to Buffer 
* @param filePath    参数1 LPCSTR filePath
* @param fileBuffer  参数2 LPSTR fileBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed return size of file
*/
DWORD readPeFile(IN FILE* pfile, OUT LPVOID pFileBuffer)
{
	DWORD sizeOfFile;

	fseek(pfile, 0, SEEK_END);
	sizeOfFile = ftell(pfile);
	fseek(pfile, 0, SEEK_SET);

	//2.read file to malloc buffer, and return lp to buffer
	pFileBuffer = malloc(sizeOfFile);
	memset(pFileBuffer, 0, sizeOfFile);
	//memcpy(pFileBuffer, pfile, sizeOfFile);
	fread(pFileBuffer, sizeOfFile, 1, pfile);

	return sizeOfFile;
}


/** 
* @brief 函数简要说明-read PE file to FileBuffer
* @param filePath    参数1 LPCSTR filePath
* @param fileBuffer  参数2 LPSTR fileBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed return size of file
*/
PVOID FileToMem(IN PCHAR szFilePath, long *FileSize)
{

	FILE* pFile = fopen(szFilePath, "rb");
	if (!pFile)
	{
		printf("Cannot open file!\n");
		return NULL;
	}
	fseek(pFile,0,SEEK_END);
	*FileSize =ftell(pFile);
	fseek(pFile,0,SEEK_SET);

	PCHAR pFileBuffer = (PCHAR)malloc(*FileSize);
	if (!pFileBuffer)
	{
		printf("cannot malloc filebuffer!\n");
		return NULL;
	}

	fread(pFileBuffer,*FileSize,1,pFile);

	if (*(PSHORT)pFileBuffer!= IMAGE_DOS_SIGNATURE)
	{
		printf("PE not read!\n");
		free(pFileBuffer);
	}

	fclose(pFile);
	return pFileBuffer;

}

//2.copy filebuffer to imagebuffer
/** 
* @brief 函数简要说明-read PE file
* @param filePath    参数1 LPCSTR filePath
* @param fileBuffer  参数2 LPSTR fileBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed return size of file
*/
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


//tools:foa To Rva
/** 
* @brief 函数简要说明-read PE file
* @param filePath    参数1 LPCSTR filePath
* @param fileBuffer  参数2 LPSTR fileBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed return size of file
*/
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

//tools:Rva To foa
/** 
* @brief 函数简要说明-read PE file
* @param filePath    参数1 LPCSTR filePath
* @param fileBuffer  参数2 LPSTR fileBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed return size of file
*/
DWORD RvaTofoa(IN LPSTR filebuffer, IN DWORD RVA)
{
	return 0;
}


int _tmain(int argc, _TCHAR* argv[])
{

	//outside function:openfile, get &file and pass to function

	LPSTR filePath = "C:\\Documents and Settings\\Administrator\\My Documents\\Visual Studio 2008\\Projects\\test1\\NOTEPAD.EXE";
	FILE* pFile = NULL;
	LPVOID pFileBuffer =NULL;
	pFile = fopen(filePath, "rb");
	if (!pFile)
	{
		printf("Open File Failed!\n");
		return 0;
	}
	printf("file size is %d.\n",readPeFile(pFile, pFileBuffer));

	return 0;
}
