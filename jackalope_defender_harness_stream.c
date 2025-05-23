#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "include/engineboot_kafl.h"
#include "include/openscan_kafl.h"
#include "include/scanreply_kafl.h"
#include "include/streambuffer_kafl.h"
#define RSIG_BOOTENGINE                       0x4036
#define RSIG_SCAN_STREAMBUFFER                0x403D
#define PE_CODE_SECTION_NAME ".text"

//Max size of the shared memory region, note if the SHM_SIZE is larger than that specified by the
//process which created the shared memory, you will not be able to open it!
#define MAX_SAMPLE_SIZE 1000000
#define SHM_SIZE (4 + MAX_SAMPLE_SIZE)

//x86_64-w64-mingw32-gcc jackalope_defender_harness_stream.c  -o jackalope_defender_harness_stream.exe

unsigned char *shm_data;
BYTE* fileContent = NULL;
size_t inputSize = 0;


typedef DWORD(*__rsignal)(DWORD Code, PVOID Params, DWORD Size);


int setup_shared_memory(const char* name) {
  HANDLE map_file;

  map_file = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name); 

  if (map_file == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  shm_data = (unsigned char*)MapViewOfFile(map_file, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE);

  if (shm_data == NULL) {
    printf("Error accessing shared memory\n");
    return 0;
  }

  return 1;
}

static DWORD EngineScanCallback(PSCANSTRUCT Scan)
{
    return 0;
}


static size_t ReadStream(PVOID this, size_t offset, BYTE* buffer, size_t size, size_t* nsize)
{
    //printf("    ReadStream offset=%x, size=%d, inputSize=%d \n", offset, size, inputSize);    
    if (offset >= inputSize) {
        *nsize = 0;
        return TRUE;
    }

    size_t remainingSize = inputSize - offset;
    size_t bytesToRead = (size < remainingSize) ? size : remainingSize;

    memcpy(buffer, fileContent + offset, bytesToRead);
    *nsize = bytesToRead;

    return TRUE;
}

static size_t GetStreamSize(PVOID this, size_t* size)
{
    *size = inputSize;    
    //printf("    GetStreamSize size=%d\n", inputSize);    
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


__declspec(dllexport)
void scanFile(){
    //printf("called scanfile\n");
    char *sample_bytes = NULL;

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
    //ScanDescriptor.filename = name;
    //char filename[] = "C:\\tmp\\a";
    ScanDescriptor.UserPtr = NULL;//fopen(filename, "rb");
    
    inputSize = *(uint32_t *)(shm_data);
    //printf("input size: %d \n", inputSize);

    sample_bytes = (char *)malloc(inputSize);
    memcpy(sample_bytes, shm_data + sizeof(uint32_t), inputSize);
    fileContent = sample_bytes;
    
    //start scanning
    int ret = prsignal(RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof(ScanParams));
    
    if (ret != 0) {
        printf("rsignal failed %d\n",ret);
    }

    //printf("scan finished\n");
}


int main(int argc, char** argv){
    printf("setup shared mem %s\n", argv[1]);
    setup_shared_memory(argv[1]);

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
        printf("load dll failed\n");
        printLastError();
        return 1;    
    }
    printf("loaded dll\n");

    prsignal = (__rsignal)GetProcAddress(hModule, "rsignal");
    if(prsignal == NULL){
        printf("GetProcAddress failed\n");
        return 1;    
    }
    printf("rsignal addr %x\n", prsignal);

    int status = prsignal(RSIG_BOOTENGINE, &BootParams, sizeof BootParams); //
    printf("status %d\n",status);
    if (status != 0) {
        printf("__rsignal(RSIG_BOOTENGINE) returned failure, missing definitions?");
        printf("Make sure the VDM files and mpengine.dll are in the engine directory\n");
        printLastError();
        return 1;
    }
    
    printf("engine booted\n");

    // if (!SetProcessWorkingSetSize((HANDLE)-1, 1 << 27 /* min: 64MB */, 1 << 33 /* max: 1GB */))
    //{
    //    printf("[-] Err increasing min and max working sizes: %u\n", (UINT32)GetLastError());
    //}
    
    
    BYTE* buffer = (BYTE*)malloc(1024*100);
    size_t buffer_size = 0x10;

    printf("call scan file\n");
    scanFile();
    printf("scanFile exited\n");

    ExitProcess(0);
    return 0;
}
