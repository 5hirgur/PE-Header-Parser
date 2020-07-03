#include<Windows.h>
#include <iostream>



int main() {

	HANDLE hmodule;
	hmodule = GetModuleHandleA(NULL);
	
	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hmodule;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 112);
	std::cout << "---------[ DOS HEADER ]---------" << std::endl;
	
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);

	std::cout << "\ne_magic     | " << std::hex << pDosHeader->e_magic << std::endl;
	std::cout << "e_cblp      | " << pDosHeader->e_cblp << std::endl;
	std::cout << "e_cp        | " << pDosHeader->e_cp << std::endl;
	std::cout << "e_crlc      | " << pDosHeader->e_crlc << std::endl;
	std::cout << "e_cparhdr   | " << pDosHeader->e_cparhdr << std::endl;
	std::cout << "e_minalloc  | " << pDosHeader->e_minalloc << std::endl;
	std::cout << "e_maxalloc  | " << pDosHeader->e_maxalloc << std::endl;
	std::cout << "e_ss        | " << pDosHeader->e_ss << std::endl;
	std::cout << "e_sp        | " << pDosHeader->e_sp << std::endl;
	std::cout << "e_csum      | " << pDosHeader->e_csum << std::endl;
	std::cout << "e_ip        | " << pDosHeader->e_ip << std::endl;
	std::cout << "e_cs        | " << pDosHeader->e_cs << std::endl;
	std::cout << "e_lfarlc    | " << pDosHeader->e_lfarlc << std::endl;
	std::cout << "e_ovno      | " << pDosHeader->e_ovno << std::endl;
	std::cout << "e_oemid     | " << pDosHeader->e_oemid << std::endl;
	std::cout << "e_oeminfo   | " << pDosHeader->e_oeminfo << std::endl;
	std::cout << "e_lfanew    | " << pDosHeader->e_lfanew << std::endl; printf("\n");
	

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 30);
	char* buffer;
	std::memcpy(&buffer, &pDosHeader, sizeof(buffer));
	buffer = buffer + pDosHeader->e_lfanew;
	if (buffer[0] == 'P' && buffer[1] == 'E') { std::cout << "PE file signature confirmed."; }
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7); printf("\n\n");
	
	
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 112);
	std::cout << "---------[ COFF HEADER/FILE HEADER ]---------";
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
	printf("\n\n");
	
	PIMAGE_NT_HEADERS pFileHeader = PIMAGE_NT_HEADERS(buffer);
	std::cout << "File Signature           | " << pFileHeader->Signature << std::endl;
	std::cout << "Number Of Sections       | " << pFileHeader->FileHeader.NumberOfSections << std::endl;
	std::cout << "Machine                  | " << pFileHeader->FileHeader.Machine << std::endl;
	std::cout << "Time Date Stamp          | " << pFileHeader->FileHeader.TimeDateStamp << std::endl;
	std::cout << "Pointer To Symbol Table  | " << pFileHeader->FileHeader.PointerToSymbolTable << std::endl;
	std::cout << "Number Of Symbols        | " << pFileHeader->FileHeader.NumberOfSymbols << std::endl;
	std::cout << "SizeOf Optional Header   | " << pFileHeader->FileHeader.SizeOfOptionalHeader << std::endl;
	std::cout << "Characteristics          | " << pFileHeader->FileHeader.Characteristics << std::endl; printf("\n\n");

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 112);
	std::cout << "---------[ OPTIONAL HEADER ]---------";
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 13);
	printf("\n\n");
	 
	std::cout << "STANDARD FIELDS - \n";
	std::cout << "---------------\n";
	
	std::cout << "Magic                       | " << pFileHeader->OptionalHeader.Magic << std::endl;
	printf("Major Linker Version        | %x\n", pFileHeader->OptionalHeader.MajorLinkerVersion);
	printf("Minor Linker Version        | %x\n", pFileHeader->OptionalHeader.MinorLinkerVersion);
	std::cout << "Size Of Code                | " << pFileHeader->OptionalHeader.SizeOfCode << std::endl;
	std::cout << "Size Of Initialized Data    | " << pFileHeader->OptionalHeader.SizeOfInitializedData << std::endl;
	std::cout << "Size Of Uninitialized Data  | " << pFileHeader->OptionalHeader.SizeOfUninitializedData << std::endl;
	std::cout << "Address Of Entry Point      | " << pFileHeader->OptionalHeader.AddressOfEntryPoint << std::endl;
	std::cout << "Base Of Code                | " << pFileHeader->OptionalHeader.BaseOfCode << std::endl;
	std::cout << "Base Of Data                | " << pFileHeader->OptionalHeader.BaseOfData << std::endl; printf("\n");
	
	
	std::cout << "NT ADDTIONAL FIELDS -\n";
	std::cout << "-------------------\n";

	std::cout << "Image Base                      | " << pFileHeader->OptionalHeader.ImageBase << std::endl;
	std::cout << "Section Alignment               | " << pFileHeader->OptionalHeader.SectionAlignment << std::endl;
	std::cout << "File Alignment                  | " << pFileHeader->OptionalHeader.FileAlignment << std::endl;
	std::cout << "Major Operating System Version  | " << pFileHeader->OptionalHeader.MajorOperatingSystemVersion << std::endl;
	std::cout << "Minor Operating System Version  | "<< pFileHeader->OptionalHeader.MinorOperatingSystemVersion << std::endl;
	std::cout << "Major Image Version             | " << pFileHeader->OptionalHeader.MajorImageVersion << std::endl;
	std::cout << "Minor Image Version             | "<< pFileHeader->OptionalHeader.MinorImageVersion << std::endl;
	std::cout << "Major Subsystem Version         | " << pFileHeader->OptionalHeader.MajorSubsystemVersion << std::endl;
	std::cout << "Minor Subsystem Version         | " << pFileHeader->OptionalHeader.MinorSubsystemVersion << std::endl;
	std::cout << "Win32 Version Value             | " << pFileHeader->OptionalHeader.Win32VersionValue << std::endl;
	std::cout << "Size Of Image                   | " << pFileHeader->OptionalHeader.SizeOfImage << std::endl;
	std::cout << "Size Of Headers                 | " << pFileHeader->OptionalHeader.SizeOfHeaders << std::endl;
	std::cout << "CheckSum                        | " << pFileHeader->OptionalHeader.CheckSum << std::endl;
	std::cout << "Subsystem                       | " << pFileHeader->OptionalHeader.Subsystem << std::endl;
	std::cout << "Dll Characteristics             | " << pFileHeader->OptionalHeader.DllCharacteristics << std::endl;
	std::cout << "Size Of Stack Reserve           | " << pFileHeader->OptionalHeader.SizeOfStackReserve << std::endl;
	std::cout << "Size Of Stack Commit            | " << pFileHeader->OptionalHeader.SizeOfStackCommit << std::endl;
	std::cout << "Size Of Heap Reserve            | " << pFileHeader->OptionalHeader.SizeOfHeapReserve << std::endl;
	std::cout << "Size Of Heap Commit             | " << pFileHeader->OptionalHeader.SizeOfHeapCommit << std::endl;
	std::cout << "Loader Flags                    | " << pFileHeader->OptionalHeader.LoaderFlags << std::endl;
	std::cout << "Number Of Rva And Sizes         | " << pFileHeader->OptionalHeader.NumberOfRvaAndSizes << std::endl; printf("\n\n");


	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 112);
	std::cout << "---------[ DATA DIRECTORIES ]---------";
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
	printf("\n\n");

	

	printf("Export Directory Address | %x\n", pFileHeader->OptionalHeader.DataDirectory[0]);
	printf("Import Directory Address | %x\n", pFileHeader->OptionalHeader.DataDirectory[1]);
	
}
