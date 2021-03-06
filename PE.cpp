// 实现任意节区添加shellcode
// todo: 
// 1.新增节区添加shellcode
// 2.扩大、合并节区

_CRT_SECURE_NO_WARNINGS

#include "stdafx.h"

BYTE shellcode[] = 
{
	0x6a,00,0x6a,00,0x6a,00,0x6a,00,
	0xe8,00,00,00,00,
	0xe9,00,00,00,00
};

#define messageboxAddr 0x77d5050b


/** 
* @brief 函数简要说明-read PE file to Buffer 
* @param filePath    参数1 LPCSTR filePath
* @param fileBuffer  参数2 LPSTR fileBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed return size of file
*/
DWORD readPeFile(IN FILE* pfile, OUT LPVOID* pFileBuffer)
{
	DWORD sizeOfFile;

	fseek(pfile, 0, SEEK_END);
	sizeOfFile = ftell(pfile);
	fseek(pfile, 0, SEEK_SET);

	//2.read file to malloc buffer, and return lp to buffer
	*pFileBuffer = malloc(sizeOfFile);
	memset(*pFileBuffer, 0, sizeOfFile);
	//memcpy(*pFileBuffer, pfile, sizeOfFile);
	fread(*pFileBuffer, sizeOfFile, 1, pfile);

	return sizeOfFile;
}


//2.copy file Buffer extend to image Buffer
/** 
* @brief 函数简要说明-read PE file
* @param filePath    参数1 LPCSTR pFileBuffer
* @param fileBuffer  参数2 LPSTR pImageBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed return size of file
*/
DWORD fileBufferToImageBuffer(IN LPVOID* pFileBuffer,OUT LPVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)*pFileBuffer;
	PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PUCHAR)*pFileBuffer+pDos->e_lfanew);
	PIMAGE_FILE_HEADER pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth+4);
	PIMAGE_OPTIONAL_HEADER pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil+IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo+pFil->SizeOfOptionalHeader);

	//分配拉伸后的内存
	DWORD dwImageSize = pOpo->SizeOfImage;
	*pImageBuffer = (PUCHAR)malloc(dwImageSize);
	if (!*pImageBuffer)
	{
		printf("Image Buffer malloc error!\n");
		return 0;
	}
	memset(*pImageBuffer,0,dwImageSize);
	//1.copy header 
	memcpy(*pImageBuffer,*pFileBuffer,pOpo->SizeOfHeaders);

	//2.copy section
	for (size_t i=0;i<pFil->NumberOfSections;i++)
	{
		memcpy(
			LPVOID((DWORD)*pImageBuffer+pSec[i].VirtualAddress), 
			LPVOID((DWORD)*pFileBuffer+pSec[i].PointerToRawData),
			pSec[i].SizeOfRawData
			);

	}
	return 0;

}

//3.copy image Buffer to file Buffer
/** 
* @brief 函数简要说明-read PE file
* @param filePath    参数1  LPVOID pImageBuffer
* @param fileBuffer  参数2  LPVOID pFileBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed 
*/
DWORD imageBufferToFileBuffer(IN LPVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)*pImageBuffer;
	PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PUCHAR)*pImageBuffer+pDos->e_lfanew);
	PIMAGE_FILE_HEADER pImage = (PIMAGE_FILE_HEADER)((PUCHAR)pNth+4);
	PIMAGE_OPTIONAL_HEADER pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pImage+IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo+pImage->SizeOfOptionalHeader);

	//分配拉伸后的内存
	int numOfSections = pImage->NumberOfSections - 1;
	DWORD dwFileSize = pSec[numOfSections].PointerToRawData + pSec[numOfSections].SizeOfRawData;
	PUCHAR pTemp = (PUCHAR)malloc(dwFileSize);
	if (!pTemp)
	{
		printf("Image Buffer malloc error!\n");
		free(pImageBuffer);
		return 0;
	}
	memset(pTemp,0,dwFileSize);
	//1.copy header 
	memcpy(pTemp,*pImageBuffer,pOpo->SizeOfHeaders);

	//2.copy section
	for (size_t i=0;i<pImage->NumberOfSections;i++)
	{
		memcpy(pTemp+pSec[i].PointerToRawData, LPVOID((DWORD)*pImageBuffer+pSec[i].VirtualAddress),pSec[i].Misc.VirtualSize);

	}

	//3.write to new file and save
	FILE* tempFile;
	tempFile = fopen("c:\\notepad11.exe","wb+");
	if (!tempFile)
	{
		printf("Create new file failed!\n");

		return 0;
	}
	fwrite(pTemp, dwFileSize, 1, tempFile);
	fclose(tempFile);

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

			if (foa>(pSec[i].PointerToRawData) && foa<(pSec[i].PointerToRawData+pSec[i].SizeOfRawData))
			{
				// RVA = foa - PointerToRawData + VirtualAddress
				free(pFileBuffer);
				return foa - pSec[i].PointerToRawData + pSec[i].VirtualAddress;
			}
		}

	} else 
	{
		printf("无法转换地址.\n");
		fclose(pFileBuffer);
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
DWORD RvaTofoa(IN PCHAR szFilePath, IN DWORD RVA)
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
	if (RVA<pFil->SizeOfOptionalHeader || (pOpo->SectionAlignment==pOpo->FileAlignment))
	{
		free(pFileBuffer);
		return RVA;
	}

	//2.foa>option
	if (RVA<pOpo->SizeOfImage)
	{
		for (size_t i=0; i<pFil->NumberOfSections; i++)
		{

			if (RVA>(pSec[i].VirtualAddress) && RVA<(pSec[i].VirtualAddress+pSec[i].Misc.VirtualSize))
			{
				// foa = RVA + PointerToRawData - VirtualAddress
				free(pFileBuffer);
				return RVA + pSec[i].PointerToRawData - pSec[i].VirtualAddress;
			}
		}

	} else 
	{
		printf("无法转换地址.\n");
		fclose(pFileBuffer);
		return 0;
	}
}


//3.copy code to image buffer to file Buffer
/** 
* @brief 函数简要说明-read PE file
* @param filePath    参数1  LPVOID* pImageBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed 
*/
VOID copyCodeToImagebuffer(IN LPVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)*pImageBuffer;
	PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PUCHAR)*pImageBuffer+pDos->e_lfanew);
	PIMAGE_FILE_HEADER pImage = (PIMAGE_FILE_HEADER)((PUCHAR)pNth+4);
	PIMAGE_OPTIONAL_HEADER pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pImage+IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo+pImage->SizeOfOptionalHeader);
	PBYTE pcodeBegin = NULL;
	PBYTE pjmpAddr = NULL;
	PBYTE pcallAddr = NULL;



	//分配拉伸后的内存
	int numOfSections = pImage->NumberOfSections - 1;
	DWORD dwFileSize = pSec[numOfSections].PointerToRawData + pSec[numOfSections].SizeOfRawData;
	PUCHAR pTemp = (PUCHAR)malloc(dwFileSize);
	if (!pTemp)
	{
		printf("Image Buffer malloc error!\n");
		free(pImageBuffer);
		return ;
	}
	memset(pTemp,0,dwFileSize);


	//1.write code to image buffer
	//decide the space is enough for shellcode
	if ( sizeof(shellcode) > pSec[0].SizeOfRawData - pSec[0].Misc.VirtualSize)
	{
		printf("the space is not enough!\n");
		free(*pImageBuffer);
		return ;
	}

	pcodeBegin = (PBYTE)((DWORD)*pImageBuffer + pSec[0].VirtualAddress + pSec[0].Misc.VirtualSize);
	pcallAddr = (PBYTE)(messageboxAddr - ((DWORD)pcodeBegin + 0xd - (DWORD)*pImageBuffer + pOpo->ImageBase));
	pjmpAddr = (PBYTE)(((DWORD)pOpo->AddressOfEntryPoint + pOpo->ImageBase) - ((DWORD)pcodeBegin + 0xd + 0x5 - (DWORD)*pImageBuffer + pOpo->ImageBase));
	pOpo->AddressOfEntryPoint = (DWORD)pcodeBegin - (DWORD)pImageBuffer;

	memcpy(pcodeBegin, (VOID*)shellcode, sizeof(shellcode));
	*(PDWORD)(pcodeBegin + 0x9) = (DWORD)pcallAddr;
	*(PDWORD)(pcodeBegin + 0x9 + 0x5) = (DWORD)pjmpAddr;
	pOpo->AddressOfEntryPoint = (DWORD)pcodeBegin-(DWORD)*pImageBuffer;

	//2.copy header 
		memcpy(pTemp,*pImageBuffer,pOpo->SizeOfHeaders);

	//3.copy section
	for (size_t i=0;i<pImage->NumberOfSections;i++)
	{
		memcpy((void*)((DWORD)pTemp+pSec[i].PointerToRawData), LPVOID((DWORD)*pImageBuffer+pSec[i].VirtualAddress),pSec[i].SizeOfRawData);

	}


	//4.write to new file and save
	FILE* tempFile;
	tempFile = fopen("c:\\notepad11.exe","wb+");
	if (!tempFile)
	{
		printf("Create new file failed!\n");
		return ;
	}
	fwrite(pTemp, dwFileSize, 1, tempFile);
	fclose(tempFile);

	return ;

}

//4.copy code to any section image buffer to file Buffer
/** 
* @brief 函数简要说明-read PE file
* @param filePath    参数1  LPVOID* pImageBuffer
*
* @return 返回说明
*     -<em>false</em> fail
*     -<em>true</em> succeed 
*/
VOID copyCodeToSectionToImagebuffer(IN LPVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)*pImageBuffer;
	PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PUCHAR)*pImageBuffer+pDos->e_lfanew);
	PIMAGE_FILE_HEADER pImage = (PIMAGE_FILE_HEADER)((PUCHAR)pNth+4);
	PIMAGE_OPTIONAL_HEADER pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pImage+IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo+pImage->SizeOfOptionalHeader);
	PBYTE pcodeBegin = NULL;
	PBYTE pjmpAddr = NULL;
	PBYTE pcallAddr = NULL;



	//分配拉伸后的内存
	int numOfSections = pImage->NumberOfSections - 1;
	DWORD dwFileSize = pSec[numOfSections].PointerToRawData + pSec[numOfSections].SizeOfRawData;
	PUCHAR pTemp = (PUCHAR)malloc(dwFileSize);
	if (!pTemp)
	{
		printf("Image Buffer malloc error!\n");
		free(pImageBuffer);
		return ;
	}
	memset(pTemp,0,dwFileSize);

	//第一个区域0,第二个区域1...
	int numSection = 2;
	//1.write code to image buffer
	//decide the space is enough for shellcode
	if ( sizeof(shellcode) > (pSec[numSection].SizeOfRawData - pSec[numSection].Misc.VirtualSize) || (pSec[numSection].SizeOfRawData < pSec[numSection].Misc.VirtualSize))
	{
		printf("the section %d space is not enough!\n", numSection);
		free(*pImageBuffer);
		return ;
	}

	pcodeBegin = (PBYTE)((DWORD)*pImageBuffer + pSec[numSection].VirtualAddress + pSec[numSection].Misc.VirtualSize);
	pcallAddr = (PBYTE)(messageboxAddr - ((DWORD)pcodeBegin + 0xd - (DWORD)*pImageBuffer + pOpo->ImageBase));
	pjmpAddr = (PBYTE)(((DWORD)pOpo->AddressOfEntryPoint + pOpo->ImageBase) - ((DWORD)pcodeBegin + 0xd + 0x5 - (DWORD)*pImageBuffer + pOpo->ImageBase));
	pOpo->AddressOfEntryPoint = (DWORD)pcodeBegin - (DWORD)pImageBuffer;

	memcpy(pcodeBegin, (VOID*)shellcode, sizeof(shellcode));
	*(PDWORD)(pcodeBegin + 0x9) = (DWORD)pcallAddr;
	*(PDWORD)(pcodeBegin + 0x9 + 0x5) = (DWORD)pjmpAddr;
	pOpo->AddressOfEntryPoint = (DWORD)pcodeBegin-(DWORD)*pImageBuffer;
	pSec[numSection].Characteristics = pSec[0].Characteristics | pSec[numSection].Characteristics;

	//2.copy header 
	memcpy(pTemp,*pImageBuffer,pOpo->SizeOfHeaders);

	//3.copy section
	for (size_t i=0;i<pImage->NumberOfSections;i++)
	{
		memcpy((void*)((DWORD)pTemp+pSec[i].PointerToRawData), LPVOID((DWORD)*pImageBuffer+pSec[i].VirtualAddress),pSec[i].SizeOfRawData);

	}


	//4.write to new file and save
	FILE* tempFile;
	tempFile = fopen("c:\\notepad11.exe","wb+");
	if (!tempFile)
	{
		printf("Create new file failed!\n");
		return ;
	}
	fwrite(pTemp, dwFileSize, 1, tempFile);
	printf("write notepad11.exe success!\n");
	fclose(tempFile);

	return ;

}
int _tmain(int argc, _TCHAR* argv[])
{

	//outside function:openfile, get &file and pass to function

	LPSTR filePath = "C:\\NOTEPAD.EXE";
	FILE* pFile = NULL;
	LPVOID pFileBuffer =NULL;
	LPVOID pImageBuffer =NULL;


	pFile = fopen(filePath, "rb");
	if (!pFile)
	{
		printf("Open File Failed!\n");
		return 0;
	}
	printf("file size is %d.\n",readPeFile(pFile, &pFileBuffer));

	fileBufferToImageBuffer(&pFileBuffer, &pImageBuffer);
	//	imageBufferToFileBuffer(&pImageBuffer);
	//copyCodeToImagebuffer(&pImageBuffer);
	copyCodeToSectionToImagebuffer(&pImageBuffer);

	return 0;
}
