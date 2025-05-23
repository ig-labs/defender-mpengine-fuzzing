#ifndef __ENGINEBOOT_H
#define __ENGINEBOOT_H
#pragma once
#pragma pack(push, 1)
typedef unsigned long long ulong;

#define BOOTENGINE_PARAMS_VERSION 0xA400

enum {
    BOOT_CACHEENABLED           = 1 << 0,
    BOOT_NOFILECHANGES          = 1 << 3,
    BOOT_ENABLECALLISTO         = 1 << 6,
    BOOT_REALTIMESIGS           = 1 << 8,
    BOOT_DISABLENOTIFICATION    = 1 << 9,
    BOOT_CLOUDBHEAVIORBLOCK     = 1 << 10,
    BOOT_ENABLELOGGING          = 1 << 12,
    BOOT_ENABLEBETA             = 1 << 16,
    BOOT_ENABLEIEV              = 1 << 17,
    BOOT_ENABLEMANAGED          = 1 << 19,
};

enum {
    BOOT_ATTR_NORMAL     = 1 << 0,
    BOOT_ATTR_ISXBAC     = 1 << 2,
};

enum {
    ENGINE_UNPACK               = 1 << 1,
    ENGINE_HEURISTICS           = 1 << 3,
    ENGINE_DISABLETHROTTLING    = 1 << 11,
    ENGINE_PARANOID             = 1 << 12,
    ENGINE_DISABLEANTISPYWARE   = 1 << 15,
    ENGINE_DISABLEANTIVIRUS     = 1 << 16,
    ENGINE_DISABLENETWORKDRIVES = 1 << 20,
};

typedef struct _ENGINE_INFO {
    DWORD   field_0;
    DWORD   field_4;    // Possibly Signature UNIX time?
    DWORD   field_8;
    DWORD   field_C;
} ENGINE_INFO, *PENGINE_INFO;


typedef struct _ENGINE_CONFIG {
    ULONG64 EngineFlags;
    PWCHAR Inclusions;      // Example, "*.zip"
    PVOID Exceptions;
    PWCHAR UnknownString2;
    PWCHAR QuarantineLocation;
    DWORD field_14;
    DWORD field_18;
    DWORD field_1C;
    DWORD field_20;
    DWORD field_24;
    DWORD field_28;
    ULONG64 field_2C;         // Setting this seems to cause packer to be reported.
    ULONG64 field_30;
    ULONG64 field_34;
    PCHAR UnknownAnsiString1;
    PCHAR UnknownAnsiString2;
} ENGINE_CONFIG, *PENGINE_CONFIG;

typedef struct _ENGINE_CONTEXT {
    DWORD   field_0;
} ENGINE_CONTEXT, *PENGINE_CONTEXT;

/*
 BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION; 0xA400
    BootParams.SignatureLocation = wchar_t L"C:\\tmp";;
    BootParams.Attributes = BOOT_ATTR_NORMAL;    
    BootParams.ProductName = ProductName;
    EngineConfig.QuarantineLocation = QurantineLocation;
    EngineConfig.Inclusions = Inclusions;
    EngineConfig.EngineFlags = 1 << 1;
    EngineConfig.UnknownAnsiString1 = NULL;
    EngineConfig.UnknownAnsiString2 = NULL;
    BootParams.EngineInfo = &EngineInfo;
    BootParams.EngineConfig = &EngineConfig;*/
typedef struct _BOOTENGINE_PARAMS {
    ULONG64           ClientVersion;
    PWCHAR          SignatureLocation;
    PVOID           SpynetSource;
    PENGINE_CONFIG  EngineConfig;
    PENGINE_INFO    EngineInfo;
    PWCHAR          ScanReportLocation;
    DWORD           BootFlags;
    PWCHAR          LocalCopyDirectory;
    PWCHAR          OfflineTargetOS;
    CHAR            ProductString[16];
    ULONG64           field_34;
    PVOID           GlobalCallback;
    PENGINE_CONTEXT EngineContext;
    ULONG64           AvgCpuLoadFactor;
    CHAR            field_44[16];
    PWCHAR          SpynetReportingGUID;
    PWCHAR          SpynetVersion;
    PWCHAR          NISEngineVersion;
    PWCHAR          NISSignatureVersion;
    ULONG64           FlightingEnabled;
    DWORD           FlightingLevel;
    PVOID           DynamicConfig;
    DWORD           AutoSampleSubmission;
    DWORD           EnableThreatLogging;
    PWCHAR          ProductName;
    DWORD           PassiveMode;
    DWORD           SenseEnabled;
    PWCHAR          SenseOrgId;
    DWORD           Attributes;
    DWORD           BlockAtFirstSeen;
    DWORD           PUAProtection;
    DWORD           SideBySidePassiveMode;
    ULONG64 a;
    ULONG64 b;
    ULONG64 c;
    ULONG64 d;
    ULONG64 e;
    ULONG64 f;
    ULONG64 g;
    ULONG64 h;
    ULONG64 i;
    ULONG64 j;
    ULONG64 k;
    ULONG64 l;
    ULONG64 m;
    ULONG64 n;
    ULONG64 o;
    ULONG64 p;
    ULONG64 q;
    ULONG64 r;
    ULONG64 s;
    ULONG64 t;
    ULONG64 u;
    ULONG64 v;
    ULONG64 w;
    ULONG64 x;
    ULONG64 y;
    ULONG64 z;
    
    

} BOOTENGINE_PARAMS, *PBOOTENGINE_PARAMS;

#pragma pack(pop)
#endif // __ENGINEBOOT_H
