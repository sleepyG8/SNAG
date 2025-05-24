#include <Windows.h>
#include <winnt.h>
#include <stdio.h>

//written by Sleepy (https://github.com/sleepyG8)

#pragma comment(lib, "DbgHelp.lib")

#pragma comment(lib, "Psapi.lib")

IMAGE_THUNK_DATA thunkData;

// I found this RVA function on stack overflow, this was not needed but cool to me to add
UINT RvaToFileOffset(HANDLE hProcess, BYTE* baseAddress, UINT rva) {
    IMAGE_DOS_HEADER dh;
    if (!ReadProcessMemory(hProcess, baseAddress, &dh, sizeof(IMAGE_DOS_HEADER), NULL)) {
        printf("Error reading DOS header\n");
        return -1;
    }

    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProcess, baseAddress + dh.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL)) {
        printf("Error reading NT headers\n");
        return -1;
    }

    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections);
    if (!sections) {
        printf("Memory allocation failed\n");
        return -1;
    }

    DWORD sectionOffset = dh.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

    if (!ReadProcessMemory(hProcess, baseAddress + sectionOffset, sections,
                           sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections, NULL)) {
        printf("Error reading section headers\n");
        free(sections);
        return -1;
    }

    
    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section = sections[i];
        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize) {
            free(sections);
            return section.PointerToRawData + (rva - section.VirtualAddress);
        }
    }

    free(sections);
    return -1; 
}

//same with this one, used from stack overflow for future use its unused right now becuase I moved a lot around before posting
DWORD getLocalRVA(char* dll, char* functionName) {
    HMODULE hMod = LoadLibraryEx(dll, NULL, 0);
    if (!hMod) {
        printf("Error loading DLL: %s\n", dll);
        return -1;
    }

    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)hMod;
    if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid PE file format\n");
        return -1;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT Headers\n");
        return -1;
    }

    PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

    DWORD importRVA = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRVA) {
        printf("No imports available\n");
        return -1;
    }

    PIMAGE_IMPORT_DESCRIPTOR id = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)dh + importRVA);
    while (id->Name != 0) {
        char* importName = (char*)dh + id->Name;
        
        if (strcmp(importName, functionName) == 0) {
            printf("Found Import: %s\n", importName);
            return id->FirstThunk;  
        }

        id++;  
    }

    return -1; 
}

BOOL logo() {
        printf("\x1B[2J");
    
        printf("\x1B[2;20H");
        printf("\x1B[37;44m");
        printf("Snag: A hooking detection engine\n");

    
        
    
    
        printf("\x1B[4;1H");
        //char *buff = "+";
        for (int i = 0; i < 100; i++) {
            printf("+");
        }
        printf("\x1B[0m");
        return TRUE;
}

//This list all exports on disk it takes in the dll name and function name inside the main()
char* getLocalExports(char* dll, char* function) {

printf("\nLocal Exports:\n");

HMODULE hMod = LoadLibraryEx(dll, NULL, 0);
if (!hMod) {
    printf("error 1\n");
    return NULL;
}

PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)hMod;
if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("error 3\n");
    return NULL;
}


PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
if (nt->Signature != IMAGE_NT_SIGNATURE) {
    printf("error 2\n");
    return NULL;
}


PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

PIMAGE_DATA_DIRECTORY exportDataDir = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)oh->ImageBase + exportDataDir->VirtualAddress);

char *retAddress;
int functionNum = 0;
DWORD* nameRVAs = (DWORD*)((BYTE*)oh->ImageBase + exportDir->AddressOfNames);
for (size_t i = 0; i < exportDir->NumberOfNames; i++) {
    char* functionName = (char*)oh->ImageBase + nameRVAs[i];
    if (strcmp(functionName, function) == 0) {
    printf("Function: %s\n", (char*)oh->ImageBase + nameRVAs[i]);
    printf("address: 0x%p\n", (char*)oh->ImageBase + nameRVAs[i]);
    retAddress = (char*)oh->ImageBase + nameRVAs[i];
    }
}
return retAddress;
}


char* getRemoteImports(char* dll, DWORD procId, char* function) {

printf("Remote Imports:\n");

BYTE *baseAddress = (BYTE*)malloc(100 * sizeof(BYTE));

HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);
if (!hProcess) {
    printf("error opening process\n");
    return NULL;
}

//getting base address
HMODULE hMods[1024];
DWORD cbNeeded;
if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
    baseAddress = (BYTE*)hMods[0]; 
} else {
    printf("error enumerating base address\n");
    return NULL;
}


//reading dos header
IMAGE_DOS_HEADER dh;

if (!ReadProcessMemory(hProcess, baseAddress, &dh, sizeof(IMAGE_DOS_HEADER), NULL)) {
    printf("error reading memory of process ID\n");
   return NULL;
}

//checks for a valid PE file
if (dh.e_magic != IMAGE_DOS_SIGNATURE) {
    printf("error 3 %lu\n", GetLastError());
    return NULL;
} else {
    printf("Valdid PE file: YES-%x\n", dh.e_magic);
}


//getting nt headers
IMAGE_NT_HEADERS nt;
if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + dh.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL)) {
    printf("error reading NT headers from remote process\n");
    return NULL;
}

//optional headers
IMAGE_OPTIONAL_HEADER oh;
if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + dh.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader), 
                       &oh, sizeof(IMAGE_OPTIONAL_HEADER), NULL)) {
    printf("Error reading Optional Header\n");
    return NULL;
}

//some dlls like ntdll dont have imports
if (oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
    printf("Does not have any imports.\n");
    return NULL;
} 

IMAGE_IMPORT_DESCRIPTOR id;
if (!ReadProcessMemory(hProcess, (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)baseAddress + oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), &id, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL)) {
    printf("error reading the import descriptor\n");
    return NULL;
}

char *returnOffset = (char*)malloc(100 * sizeof(char));

while (id.Name != 0) {

DWORD importNameRVA = id.Name;
char importName[256];  

if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + importNameRVA, 
                       importName, sizeof(importName), NULL)) {
    printf("Error reading import name\n");
    return NULL;
}

if (importName == NULL) {
    printf("error with import name\n");
}

    if (strcmp(importName, function) == 0) {
   DWORD rOffset = RvaToFileOffset(hProcess, baseAddress, importNameRVA); //dont ask lol, this is how you find the true offset I found online
   printf("RVA: 0x%x\n", rOffset);

   
    //time to get the offset of the import
    DWORD firstThunkRVA = id.FirstThunk;
    

    if (!ReadProcessMemory(hProcess, (BYTE*)baseAddress + id.FirstThunk, &thunkData, sizeof(IMAGE_THUNK_DATA), NULL)) {
        printf("error reading memory\n");
    }

    BYTE hookedBytes[5];
    ReadProcessMemory(hProcess, (void*)thunkData.u1.Function, hookedBytes, 5, NULL); //reading only 5 bytes

    returnOffset = (void*)thunkData.u1.Function;
    printf("Offset Value: 0x%p\n", (void*)returnOffset);

if (hookedBytes[0] == 0xE9) {  // using 0xE9 to detect a jmp (likely a hook)
    printf("Inline Hook Detected: Redirected function.\n");
} else {
    printf("\x1B[37;44m+++++++++++++++++++++++++++++++++\x1B[0m\nAny Hooks?:\n");

    printf("Inline-hook: \x1b[0;92mSAFE\x1b[0m\n");
}  

    break;
    }
    
    id.Name++;
}
return returnOffset;
}

int main(int argc, char* argv[]) {

if (argc < 2) {
    printf("Usage: <DLL to scan> <function to get> <process ID>\n");
    return 1;
}

if (!logo()) {
    printf("error running snag :(\n");
    return 1;
} 

char* localImports = (char*)getLocalExports(argv[1], argv[2]);
if (localImports == NULL) {
    printf("error reading local exports\n");
}

DWORD procID = (DWORD)atoi(argv[3]);

printf("\x1B[37;44m+++++++++++++++++++++++++++++++++\x1B[0m\n");

char* remoteImports = getRemoteImports(argv[1], procID, argv[2]);
if (remoteImports == NULL) {
    printf("error reading remote imports\n");
    return 1;
}

//if this weird looking string confuses you research ansi escape codes
printf("\x1B[37;44m+++++++++++++++++++++++++++++++++\x1B[0m\n");



return 0;
}
