#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <time.h>
#include "include/nyx_api.h"
#include "include/engineboot_kafl.h"
#include "include/openscan_kafl.h"
#include "include/scanreply_kafl.h"
#include "include/streambuffer_kafl.h"
#define RSIG_BOOTENGINE                       0x4036
#define RSIG_SCAN_STREAMBUFFER                0x403D
#define PE_CODE_SECTION_NAME ".text"

static uint8_t* fileContent = NULL;
static int fileSize = 0;

typedef DWORD(*__rsignal)(DWORD Code, PVOID Params, DWORD Size);


LONG CALLBACK exception_handle(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
    PEXCEPTION_RECORD pExceptionRecord = ExceptionInfo->ExceptionRecord;
    DWORD exception_code = pExceptionRecord->ExceptionCode;
    
    if((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
       (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
        (exception_code == 0xc0000374) ||
       (exception_code == EXCEPTION_STACK_OVERFLOW) ||
       (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
       (exception_code == STATUS_FATAL_APP_EXIT) ||
       (exception_code == 0xC0000421))
        
    {
        hprintf("Exception: 0x%lX\n", exception_code);
        hprintf("  Faulting instruction address: 0x%p\n", pExceptionRecord->ExceptionAddress);
        // Print specific details for Access Violation
        if (exception_code == EXCEPTION_ACCESS_VIOLATION)
        {
            ULONG_PTR violation_type = pExceptionRecord->ExceptionInformation[0];
            ULONG_PTR violation_address = pExceptionRecord->ExceptionInformation[1];

            if (violation_type == 0) {
                hprintf("  c005 Violation Type: Attempted to READ from address\n");
            } else if (violation_type == 1) {
                hprintf("  c005 Violation Type: Attempted to WRITE to address\n");
            } else if (violation_type == 8) {
                hprintf("  c005 Violation Type: Data Execution Prevention (DEP) violation at address\n");
            } else {
                hprintf("  c005 Violation Type: Unknown type (%p)\n", (void*)violation_type);
            }

            hprintf("  c005 Violated Address: 0x%p\n", (void*)violation_address);
            hprintf("  input size: %d", fileSize);
        }
        kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
        while(1){}; /* halt */

    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD EngineScanCallback(PSCANSTRUCT Scan)
{
    // if (Scan->Flags & SCAN_MEMBERNAME) {
    //     //hprintf("Scanning archive member %s", Scan->VirusName);
    // }
    // if (Scan->Flags & SCAN_FILENAME) {
    //     //hprintf("Scanning@@@@ %s", Scan->FileName);
    // }
    // if (Scan->Flags & SCAN_PACKERSTART) {
    //     //hprintf("Packer %s identified.", Scan->VirusName);
    // }
    // if (Scan->Flags & SCAN_ENCRYPTED) {
    //     //hprintf("File is encrypted.");
    // }
    // if (Scan->Flags & SCAN_CORRUPT) {
    //     //hprintf("File may be corrupt.");
    // }
    // if (Scan->Flags & SCAN_FILETYPE) {
    //     //hprintf("File %s is identified as %s", Scan->FileName, Scan->VirusName);
    // }
    // if (Scan->Flags & 0x08000022) {
    //     //hprintf("Threat %s identified.", Scan->VirusName);
    // }
    // // This may indicate PUA.
    // if ((Scan->Flags & 0x40010000) == 0x40010000) {
    //     //hprintf("Threat %s identified.", Scan->VirusName);
    // }

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
   
    return TRUE;
}

static size_t GetStreamSize(PVOID this, size_t* size)
{    
    *size = fileSize;
    //hprintf("    GetStreamSize size-x=%x\n", fileSize);    
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

void submit_ip_ranges() {
    // Get the module handle for the current process.
    if (hModule == NULL) {
        habort("Cannot get module handle\n");
    }

    // Get the PE header of the current module.
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        habort("Invalid PE signature\n");
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
            hprintf("[+] code start %llx...\n", (UINT64)codeStart);
            hprintf("[+] code end %llx...\n", (UINT64)codeEnd);
            // submit them to kAFL
            uint64_t buffer[3] = {0};
            buffer[0] = codeStart; // low range
            buffer[1] = codeEnd; // high range
            buffer[2] = 0; // IP filter index [0-3]
            kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uint64_t)buffer);
            // ensure allways present in memory, avoid pagefaults for libxdc
            if (!VirtualLock((LPVOID)codeStart, pSectionHeader->Misc.VirtualSize)){
                hprintf("Failed to lock .text section in resident memory\n");
                DWORD err = GetLastError();
                hprintf("VirtualLock failed with error: %lu\n", err);
            }
            return;
        }
    }
    habort("Couldn't locate .text section in PE image\n");
}

kAFL_payload* kafl_agent_init(void) {
    // initial fuzzer handshake
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // submit mode
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    // get host config
    host_config_t host_config = {0};
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    hprintf("[host_config] bitmap sizes = <0x%x,0x%x>\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
    hprintf("[host_config] payload size = %dKB\n", host_config.payload_buffer_size/1024);
    hprintf("[host_config] worker id = %02u\n", host_config.worker_id);

    // allocate buffer
    hprintf("[+] Allocating buffer for kAFL_payload struct\n");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, host_config.payload_buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // ensure really present in resident pages
    if (!VirtualLock(payload_buffer, host_config.payload_buffer_size)){
        hprintf("[+] WARNING: Virtuallock failed to lock payload buffer\n");
        DWORD err = GetLastError();
        hprintf("VirtualLock failed with error: %lu\n", err);
    }

    // submit buffer
    hprintf("[+] Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    // filters
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // submit agent config
    agent_config_t agent_config = {
        .agent_magic = NYX_AGENT_MAGIC,
        .agent_version = NYX_AGENT_VERSION,
    };
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    return payload_buffer;
}


void scanFile(char filename[], kAFL_payload* payload_buffer){
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
    ScanDescriptor.UserPtr = fopen(filename, "rb");
    //ScanDescriptor.filename_w = (wchar_t*)malloc((strlen(name) + 1) * sizeof(wchar_t));
    if (ScanDescriptor.UserPtr == NULL) {
        hprintf("open failed\n");
        //return;
    }
    
    hprintf("start scan\n");
      
    fileContent = payload_buffer->data;
    fileSize = payload_buffer->size;
    
    //start scanning  
    int ret = prsignal(RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof(ScanParams));
 
    if (ret != 0) {
        hprintf("rsignal failed %d\n",ret);
    }

    hprintf("scan finished\n");
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
    
    hprintf("[+++++++] NEW START!\n");
    SetCurrentDirectoryA("C:\\tmp");
    hModule = LoadLibraryA("C:\\tmp\\mpengine.dll");
    if(hModule == NULL){
        hprintf("load dll failed\n");
        printLastError();
        return 1;    
    }
    hprintf("loaded dll\n");

    prsignal = (__rsignal)GetProcAddress(hModule, "rsignal");
    if(prsignal == NULL){
        hprintf("GetProcAddress failed\n");
        return 1;    
    }
    hprintf("got rsignal addr %x\n", prsignal);
    
    hprintf("size BootParams: %x\n", sizeof BootParams);

    int status = prsignal(RSIG_BOOTENGINE, &BootParams, sizeof BootParams); //
    hprintf("status %d\n",status);
    if (status != 0) {
        hprintf("__rsignal(RSIG_BOOTENGINE) returned failure, missing definitions?");
        hprintf("Make sure the VDM files and mpengine.dll are in the engine directory\n");
        printLastError();
        //return 1;
    }
    
    hprintf("engine booted\n");

    if (AddVectoredExceptionHandler(1, exception_handle) == 0)
    {
        hprintf("[-] WARNING: Cannot add veh handler %u\n", (UINT32)GetLastError());
    }

    if (!SetProcessWorkingSetSize((HANDLE)-1, 1 << 27 /* min: 64MB */, 1 << 30 /* max: 2GB */))
    {
        hprintf("[-] Err increasing min and max working sizes: %u\n", (UINT32)GetLastError());
    }

    kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);
    kAFL_payload* payload_buffer = kafl_agent_init();
    submit_ip_ranges();
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    char filename[] = "C:\\tmp\\a";

    scanFile(filename, payload_buffer);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    
    exit(0);
    return 0;
}
