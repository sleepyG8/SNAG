#include <Windows.h>

//This is a DLL! I compiled with cl /LD hook_detection.c
//Load into a program either with LoadLibrary() or manually
//or inject into a process to monitor it

#pragma comment(lib, "user32.lib")  
#pragma comment(lib, "Dbghelp.lib") 
BYTE baseAddress = 0;
BOOL getLocalImports() {

BYTE* baseAddress = (BYTE*)GetModuleHandle(NULL);


    // Read DOS header
    PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)baseAddress;
    if (dh->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid PE file\n");
        return FALSE;
    }

    // Read NT headers
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dh + dh->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT headers\n");
        return FALSE;
    }

    // Get Optional Header
    PIMAGE_OPTIONAL_HEADER oh = &nt->OptionalHeader;

    // Check for Import Table
    if (oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0) {
        printf("No imports found\n");
        return FALSE;
    }

    // Locate Import Table
    PIMAGE_IMPORT_DESCRIPTOR id = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddress + oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    while (id->Name != NULL) {
        char* importName = (char*)((BYTE*)baseAddress + id->Name);
        printf("%s\n", importName);
        
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + id->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + id->FirstThunk);
            
            while (origThunk->u1.AddressOfData != NULL) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)baseAddress + origThunk->u1.AddressOfData);

                if (importByName) {
                FARPROC funcAddr = (FARPROC)thunkData->u1.Function;
                //If you want more information uncomment this section right now it only list when hooks are found
                  
                //printf("+ %s", importByName->Name);
                //printf("Function Address: %p\n", funcAddr);
                
                //reading the first 10 bytes
                //BYTE* funcBytes = (BYTE*)funcAddr;
                //for (int i=0; i < 10; i++) {
                  //  printf("%02X ", funcBytes[i]);
                //}
               // printf("\n");
                BYTE hookedBytes[5];
                memcpy(hookedBytes, (void*)funcAddr, sizeof(hookedBytes));

                if (hookedBytes[0] == 0xE9) {
                    printf("+ %s", importByName->Name);
                    printf("Function Address: %p\n", funcAddr);
                    printf("Hook detected! %02X\n", funcAddr);
                }

            }
                origThunk++;
                thunkData++;
            
        }
        printf("+++++++++++++++++++++++++++++++++++++++\n");
        id++;
    }

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    
    if (!getLocalImports()) {
        return FALSE;
    }
       
    return TRUE;
    }
}
