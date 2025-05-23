#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <time.h>
#include "include/engineboot_kafl.h"
#include "include/openscan_kafl.h"
#include "include/scanreply_kafl.h"
#include "include/streambuffer_kafl.h"
#define RSIG_BOOTENGINE                       0x4036
#define RSIG_SCAN_STREAMBUFFER                0x403D
#define PE_CODE_SECTION_NAME ".text"

//x86_64-w64-mingw32-gcc mpclient_defender_harness_withoutHypercalls.c -o bin/mpclient_defender_harness_withoutHypercalls.exe 

static BYTE* fileContent = NULL;
static size_t fileSize = 0;

typedef DWORD(*__rsignal)(DWORD Code, PVOID Params, DWORD Size);


LONG CALLBACK exception_handle(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
    DWORD exception_code = ExceptionInfo->ExceptionRecord->ExceptionCode;

    printf("exception %x\n",exception_code);
    if((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
       (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
        (exception_code == 0xc0000374) ||
       (exception_code == EXCEPTION_STACK_OVERFLOW) ||
       (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
       (exception_code == STATUS_FATAL_APP_EXIT) ||
       (exception_code == 0xC0000421))
        
    {
        ExitProcess(0);        
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD EngineScanCallback(PSCANSTRUCT Scan)
{
    return 0;
}


static size_t ReadStream(PVOID this, size_t offset, BYTE* buffer, size_t size, size_t* nsize)
{  
    if (offset >= fileSize) {
        *nsize = 0;
        return TRUE;
    }

    size_t remainingSize = fileSize - offset;
    size_t bytesToRead = (size < remainingSize) ? size : remainingSize;

    memcpy(buffer, fileContent + offset, bytesToRead);
    *nsize = bytesToRead;
    printf("    ReadStream offset-d=%x size-d=%x\n", offset,size);
    printf("    read nsize=%x\n", *nsize);

    return TRUE;
}

static size_t GetStreamSize(PVOID this, size_t* size)
{    
    *size = fileSize;    
    printf("    GetStreamSize size=%x\n", fileSize);    
    return 0;
}

void printLastError() {
    DWORD errorMessageID = GetLastError();
    if(errorMessageID == 0) {
        printf("No error occurred.\n");
        return;
    }

    LPSTR messageBuffer = NULL;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
    if(size == 0) {
        printf("Failed to get error message string.\n");
        return;
    }

    printf("Error: %s\n", messageBuffer);

    LocalFree(messageBuffer);
}

static const wchar_t* GetStreamName(PSTREAMBUFFER_DESCRIPTOR self)
{
    wchar_t test[] = L"engine";
    return test;
}
__rsignal prsignal;
HMODULE hModule;


void loadfile(char filename[]) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("error opening file");
        return;
    }

    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    rewind(file);

    fileContent = (BYTE*)malloc(fileSize);
    if (fileContent == NULL) {
        printf("Handle memory allocation error");
        fclose(file);
        return;
    }

    fread(fileContent, 1, fileSize, file);

    /*if (!VirtualLock(fileContent, fileSize)){
        printf("[+] WARNING: Virtuallock failed to lock payload buffer\n");
        DWORD err = GetLastError();
        printf("VirtualLock failed with error: %lu\n", err);
    }else{
        printf("locked paylaod buffer\n");
    }*/


    fclose(file);
}

void scanFile(char filename[]){
    SCANSTREAM_PARAMS ScanParams;
    STREAMBUFFER_DESCRIPTOR ScanDescriptor;
    SCAN_REPLY ScanReply;
    ZeroMemory(&ScanParams, sizeof ScanParams);
    ZeroMemory(&ScanDescriptor, sizeof ScanDescriptor);
    ZeroMemory(&ScanReply, sizeof ScanReply);

    ScanParams.Descriptor = &ScanDescriptor;
    ScanParams.ScanReply = &ScanReply;
    ScanReply.EngineScanCallback = EngineScanCallback;
    ScanReply.field_C = 0x7fffffff;
    ScanDescriptor.Read = ReadStream;
    ScanDescriptor.GetSize = GetStreamSize;
    ScanDescriptor.GetName = GetStreamName;    
    ScanDescriptor.UserPtr = fopen(filename, "rb");    
    if (ScanDescriptor.UserPtr == NULL) {
        printf("open failed\n");
        return 1;
    }
        
    printf("start scan\n");

    clock_t startc, endc;
    struct timeval startt, endt;
    double cpu_time_used, time_taken;
    
    //load file
    loadfile(filename);

    //start scanning
    startc = clock();   
    gettimeofday(&startt, NULL); 
    int ret = prsignal(RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof(ScanParams));
    endc = clock();
    gettimeofday(&endt, NULL);
    cpu_time_used = ((double) (endc - startc)) / CLOCKS_PER_SEC;
    time_taken = (endt.tv_sec - startt.tv_sec) + (endt.tv_usec - startt.tv_usec) / 1e6;
    printf("Time taken: %f seconds\n", time_taken);
    printf("Clock-Time: %f seconds\n", cpu_time_used);
    if (ret != 0) {
        printf("rsignal failed %d\n",ret);
    }

    printf("scan finished\n");
}

void submit_ip_ranges_nokafl() {
    // Get the module handle for the current process.
    if (hModule == NULL) {
        printf("Cannot get module handle\n");
    }

    // Get the PE header of the current module.
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid PE signature\n");
    }

    // Get the section headers.
    PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders + 
        sizeof(IMAGE_NT_HEADERS));
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER pSectionHeader = &pSectionHeaders[i];

        // Check for the .text section
        if (memcmp((LPVOID)pSectionHeader->Name, PE_CODE_SECTION_NAME, strlen(PE_CODE_SECTION_NAME)) == 0) {
            DWORD_PTR codeStart = (DWORD_PTR)hModule + pSectionHeader->VirtualAddress;
            DWORD_PTR codeEnd = codeStart + pSectionHeader->Misc.VirtualSize;
            printf("[+] code start %llx...\n", (UINT64)codeStart);
            printf("[+] code end %llx...\n", (UINT64)codeEnd);
            // submit them to kAFL
            uint64_t buffer[3] = {0};
            buffer[0] = codeStart; // low range
            buffer[1] = codeEnd; // high range
            buffer[2] = 0; // IP filter index [0-3]
            
            // ensure allways present in memory, avoid pagefaults for libxdc
            /*if (!VirtualLock((LPVOID)codeStart, pSectionHeader->Misc.VirtualSize)){
                printf("Failed to lock .text section in resident memory\n");
                DWORD err = GetLastError();
                printf("VirtualLock failed with error: %lu\n", err);
            }else{
                printf("locked code\n");
            }*/
            return;
        }
    }
    printf("Couldn't locate .text section in PE image\n");
}


int main(int argc, char** argv){
    HANDLE KernelHandle;
    BOOTENGINE_PARAMS BootParams;
    ENGINE_INFO EngineInfo;
    ENGINE_CONFIG EngineConfig;
    
    printf("[+] Starting... %s\n", argv[0]);
    
    ZeroMemory(&BootParams, sizeof BootParams);
    ZeroMemory(&EngineInfo, sizeof EngineInfo);
    ZeroMemory(&EngineConfig, sizeof EngineConfig);


    wchar_t SignatureLocation[] = L"C:\\tmp";
    wchar_t ProductName[] = L"Legitimate Antivirus";
    wchar_t QurantineLocation[] = L"quarantine";
    wchar_t Inclusions[] = L"*.*";

    BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION;
    BootParams.SignatureLocation = SignatureLocation;
    BootParams.Attributes = BOOT_ATTR_NORMAL;    
    BootParams.ProductName = ProductName;
    EngineConfig.QuarantineLocation = QurantineLocation;
    EngineConfig.Inclusions = Inclusions;
    EngineConfig.EngineFlags = 1 << 1;
    EngineConfig.UnknownAnsiString1 = NULL;
    EngineConfig.UnknownAnsiString2 = NULL;
    BootParams.EngineInfo = &EngineInfo;
    BootParams.EngineConfig = &EngineConfig;
    KernelHandle = NULL;    
    printf("[+++++++] NEW START!\n");
    SetCurrentDirectoryA("C:\\tmp");
    hModule = LoadLibraryA("C:\\tmp\\mpengine.dll");
    if(hModule == NULL){
        printf("laod dll failed1\n");
        printLastError();
        return 1;    
    }
    printf("laoded dll\n");

    prsignal = (__rsignal)GetProcAddress(hModule, "rsignal");
    if(prsignal == NULL){
        printf("GetProcAddress failed\n");
        return 1;    
    }
    printf("got rsignal addr %x\n", prsignal);
    
    printf("size BootParams: %x\n", sizeof BootParams);
    
    int status = prsignal(RSIG_BOOTENGINE, &BootParams, sizeof BootParams); //
    printf("status %d\n",status);
    if (status != 0) {
        printf("__rsignal(RSIG_BOOTENGINE) returned failure, missing definitions?");
        printf("Make sure the VDM files and mpengine.dll are in the engine directory\n");
        printLastError();
        //return 1;
    }
    
    printf("engine booted\n");

    /* if (AddVectoredExceptionHandler(1, exception_handle) == 0)
    {
        printf("[-] WARNING: Cannot add veh handler %u\n", (UINT32)GetLastError());
    }*/

    //if (!SetProcessWorkingSetSize((HANDLE)-1, 1 << 27 /* min: 64MB */, 1 << 30 /* max: 1GB */))
    /*{
        printf("[-] Err increasing min and max working sizes: %u\n", (UINT32)GetLastError());
    }*/
    submit_ip_ranges_nokafl();

    char filename[256];
    strncpy(filename, argv[1], sizeof(filename) - 1);
    filename[sizeof(filename) - 1] = '\0'; // Ensure null-termination
        
    //pause();
    scanFile(filename);

    ExitProcess(0);
    return 0;
}
