// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _NATIVE_H_
#define _NATIVE_H_
#include <Windows.h>

#include <cstdint>
#include <string>
#include <algorithm>

#include "./mouse_input_injection.h"
#include "./keybd_input_injection.h"
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#define SYSCALL_INSTR_SIZE 16    // most syscall instruction size
#define NT_FUNC_MAX_SEARCH_SIZE 32 // just incase

typedef struct _UNICODE_STRING UNICODE_STRING, *PUNICODE_STRING;
typedef struct _CLIENT_ID CLIENT_ID, *PCLIENT_ID;
typedef struct _OBJECT_ATTRIBUTES OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _PROCESS_BASIC_INFORMATION PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
typedef struct _PEB_LDR_DATA PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB PEB, *PPEB;
typedef struct _SYSTEM_PROCESS_INFORMATION SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

static ULONG g_NtOpenProcess_SyscallNum = 0;
static ULONG g_NtReadVirtualMemory_SyscallNum = 0;
static ULONG g_NtWriteVirtualMemory_SyscallNum = 0;
static ULONG g_NtProtectVirtualMemory_SyscallNum = 0;
static ULONG g_NtQueryInformationProcess_SyscallNum = 0;
static ULONG g_NtQuerySystemInformation_SyscallNum = 0;

typedef NTSTATUS(NTAPI* _NtOpenProcess)(PHANDLE ProcessHandle,
                                        ACCESS_MASK DesiredAccess,
                                        POBJECT_ATTRIBUTES ObjectAttributes,
                                        PCLIENT_ID ClientId);
static _NtOpenProcess pfnNtOpenProcess = nullptr;

typedef NTSTATUS(WINAPI* pNtReadVirtualMemory)(HANDLE ProcessHandle,
                                               PVOID BaseAddress, PVOID Buffer,
                                               ULONG NumberOfBytesToRead,
                                               PULONG NumberOfBytesRead);
static pNtReadVirtualMemory pfnNtReadVirtualMemory = nullptr;

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle,
                                                PVOID BaseAddress, PVOID Buffer,
                                                ULONG NumberOfBytesToWrite,
                                                PULONG NumberOfBytesWritten);
static pNtWriteVirtualMemory pfnNtWriteVirtualMemory = nullptr;

typedef NTSTATUS(WINAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection, PULONG OldAccessProtection);
static pNtProtectVirtualMemory pfnNtProtectVirtualMemory = nullptr;

constexpr PROCESS_INFORMATION_CLASS ProcessBasicInformation = (PROCESS_INFORMATION_CLASS)0;  // retarded
typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);
static pNtQueryInformationProcess pfnNtQueryInformationProcess = nullptr;

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
static pNtQuerySystemInformation pfnNtQuerySystemInformation = nullptr;


/* 
.text:0000000180162070                 public NtOpenProcess
.text:0000000180162070 NtOpenProcess   proc near               ; CODE XREF: RtlQueryProcessDebugInformation+17A↑p
.text:0000000180162070                                         ; RtlQueryProcessDebugInformation+22F↑p ...
.text:0000000180162070                 mov     r10, rcx        ; NtOpenProcess
.text:0000000180162073                 mov     eax, 26h ; '&'
.text:0000000180162078                 test    byte ptr ds:7FFE0308h, 1
.text:0000000180162080                 jnz     short loc_180162085
.text:0000000180162082                 syscall                 ; Low latency system call
.text:0000000180162084                 retn
.text:0000000180162085 ; ---------------------------------------------------------------------------
.text:0000000180162085
.text:0000000180162085 loc_180162085:                          ; CODE XREF: NtOpenProcess+10↑j
.text:0000000180162085                 int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
.text:0000000180162085                                         ; DS:SI -> counted CR-terminated command string
.text:0000000180162087                 retn
.text:0000000180162087 NtOpenProcess   endp
.text:0000000180162087
.text:0000000180162087 ; ---------------------------------------------------------------------------
.text:0000000180162088 algn_180162088:                         ; DATA XREF: .pdata:00000001801E34CC↓o
.text:0000000180162088                 align 10h
.text:0000000180162090 ; Exported entry 609. NtSetInformationFile
.text:0000000180162090 ; Exported entry 2256. ZwSetInformationFile
 */
static const BYTE g_SyscallTemplate[SYSCALL_INSTR_SIZE] = {
    0x4C, 0x8B, 0xD1,          
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x05,                
    0xC3                       
};

struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWCH Buffer;
};

struct _CLIENT_ID {
  PVOID UniqueProcess;
  PVOID UniqueThread;
};

struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
};

struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
};

struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
};

struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
};

struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    ULONG_PTR WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    ULONG_PTR CreateTime;
    ULONG_PTR UserTime;
    ULONG_PTR KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
};

static bool FindSyscallInstruction(PBYTE pFuncBytes, ULONG funcSearchSize, ULONG& syscallOffset)
{
    if (!pFuncBytes || funcSearchSize < 2)
        return false;

    for (ULONG i = 0; i <= funcSearchSize - 2; i++)
    {
        if (pFuncBytes[i] == 0x0F && pFuncBytes[i+1] == 0x05)
        {
            syscallOffset = i;
            return true;
        }
    }
    return false;
}

template <typename T>
static T ConstructSyscallFunction(ULONG syscallNum)
{
    if (syscallNum == 0)
        return nullptr;

    PBYTE pMem = (PBYTE)VirtualAlloc(nullptr, SYSCALL_INSTR_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem)
        return nullptr;

    memcpy(pMem, g_SyscallTemplate, SYSCALL_INSTR_SIZE);
    *(PULONG)(pMem + 4) = syscallNum;

    DWORD oldProtect = 0;
    if (!VirtualProtect(pMem, SYSCALL_INSTR_SIZE, PAGE_EXECUTE_READ, &oldProtect))
    {
        VirtualFree(pMem, 0, MEM_RELEASE);
        return nullptr;
    }

    return (T)pMem;
}

static void ManualSysCall_Init()
{
    PBYTE pNtdllBase = (PBYTE)GetModuleHandleW(L"ntdll.dll");
    if (!pNtdllBase)
        return;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pNtdllBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)pNtdllBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE || pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return;

    IMAGE_DATA_DIRECTORY exportDirData = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirData.VirtualAddress == 0 || exportDirData.Size == 0)
        return;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)pNtdllBase + exportDirData.VirtualAddress);
    if (!pExportDir)
        return;

    PDWORD pFuncNames = (PDWORD)((uintptr_t)pNtdllBase + pExportDir->AddressOfNames);
    PDWORD pFuncAddrs = (PDWORD)((uintptr_t)pNtdllBase + pExportDir->AddressOfFunctions);
    PWORD pFuncOrdinals = (PWORD)((uintptr_t)pNtdllBase + pExportDir->AddressOfNameOrdinals);

    for (ULONG i = 0; i < pExportDir->NumberOfNames; i++)
    {
        uintptr_t funcNameRva = pFuncNames[i];
        const char* pFuncName = (const char*)((uintptr_t)pNtdllBase + funcNameRva);
        if (!pFuncName)
            continue;

        if (strncmp(pFuncName, "Nt", 2) != 0 || strncmp(pFuncName, "Zw", 2) == 0)
            continue;

        uintptr_t funcRva = pFuncAddrs[pFuncOrdinals[i]];
        PBYTE pFuncBytes = (PBYTE)((uintptr_t)pNtdllBase + funcRva);
        if (!pFuncBytes)
            continue;

        if (pFuncBytes[0] != 0x4C || pFuncBytes[1] != 0x8B || pFuncBytes[2] != 0xD1 || pFuncBytes[3] != 0xB8)
        {
            continue;
        }

        ULONG syscallNum = *(PULONG)(pFuncBytes + 4);
        if (syscallNum == 0)
            continue;

        ULONG syscallOffset = 0;
        if (!FindSyscallInstruction(pFuncBytes, NT_FUNC_MAX_SEARCH_SIZE, syscallOffset))
        {
            continue;
        }

        if (strcmp(pFuncName, "NtOpenProcess") == 0)
        {
            g_NtOpenProcess_SyscallNum = syscallNum;
        }
        else if (strcmp(pFuncName, "NtReadVirtualMemory") == 0)
        {
            g_NtReadVirtualMemory_SyscallNum = syscallNum;
        }
        else if (strcmp(pFuncName, "NtWriteVirtualMemory") == 0)
        {
            g_NtWriteVirtualMemory_SyscallNum = syscallNum;
        }
        else if (strcmp(pFuncName, "NtProtectVirtualMemory") == 0)
        {
            g_NtProtectVirtualMemory_SyscallNum = syscallNum;
        }
        else if (strcmp(pFuncName, "NtQueryInformationProcess") == 0)
        {
            g_NtQueryInformationProcess_SyscallNum = syscallNum;
        }
        else if (strcmp(pFuncName, "NtQuerySystemInformation") == 0)
        {
            g_NtQuerySystemInformation_SyscallNum = syscallNum;
        }
    }

    pfnNtOpenProcess = ConstructSyscallFunction<_NtOpenProcess>(g_NtOpenProcess_SyscallNum);
    pfnNtReadVirtualMemory = ConstructSyscallFunction<pNtReadVirtualMemory>(g_NtReadVirtualMemory_SyscallNum);
    pfnNtWriteVirtualMemory = ConstructSyscallFunction<pNtWriteVirtualMemory>(g_NtWriteVirtualMemory_SyscallNum);
    pfnNtProtectVirtualMemory = ConstructSyscallFunction<pNtProtectVirtualMemory>(g_NtProtectVirtualMemory_SyscallNum);
    pfnNtQueryInformationProcess = ConstructSyscallFunction<pNtQueryInformationProcess>(g_NtQueryInformationProcess_SyscallNum);
    pfnNtQuerySystemInformation = ConstructSyscallFunction<pNtQuerySystemInformation>(g_NtQuerySystemInformation_SyscallNum);
}

static bool g_ManualSysCallInited = []() {
    ManualSysCall_Init();
    return true;
}();

inline static OBJECT_ATTRIBUTES InitObjectAttributes(
    PUNICODE_STRING name, ULONG attributes, HANDLE hRoot,
    PSECURITY_DESCRIPTOR security) noexcept {
  OBJECT_ATTRIBUTES object;

  object.Length = sizeof(OBJECT_ATTRIBUTES);
  object.ObjectName = name;
  object.Attributes = attributes;
  object.RootDirectory = hRoot;
  object.SecurityDescriptor = security;

  return object;
}

inline static HANDLE NtOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle,
                                   DWORD dwProcessId) noexcept {
  HANDLE hProcess = 0;
  CLIENT_ID clientId = {(PVOID)(ULONG_PTR)dwProcessId, NULL};
  OBJECT_ATTRIBUTES objAttr = InitObjectAttributes(NULL, 0, NULL, NULL);
  if (pfnNtOpenProcess)
  {
      pfnNtOpenProcess(&hProcess, dwDesiredAccess, &objAttr, &clientId);
  }
  return hProcess;
}
/* 
why not, cuz we have a warpper function already ^^^
inline static _NtOpenProcess NtOpenProcess = []() {
  return pfnNtOpenProcess;
}();
*/
inline static pNtReadVirtualMemory NtReadVirtualMemory = []() {
  return pfnNtReadVirtualMemory;
}();
inline static pNtWriteVirtualMemory NtWriteVirtualMemory = []() {
  return pfnNtWriteVirtualMemory;
}();
inline static pNtProtectVirtualMemory NtProtectVirtualMemory = []() {
  return pfnNtProtectVirtualMemory;
}();
inline static pNtQueryInformationProcess NtQueryInformationProcess = []() {
  return pfnNtQueryInformationProcess;
}();
inline static pNtQuerySystemInformation NtQuerySystemInformation = []() {
  return pfnNtQuerySystemInformation;
}();
class Native {
 public:
  Native() : target_process_handle_(nullptr), target_process_id_(0) {}

  ~Native() {
    if (target_process_handle_) {
      CloseHandle(target_process_handle_);
    }
  }

  bool Initialize(uint64_t process_id,
                  DWORD desired_access = PROCESS_ALL_ACCESS) {
    target_process_id_ = static_cast<DWORD>(process_id);
    target_process_handle_ =
        NtOpenProcess(desired_access, FALSE, target_process_id_);
    return target_process_handle_ != nullptr;
  }

  bool Initialize(const wchar_t* process_name,
                  DWORD desired_access = PROCESS_ALL_ACCESS) {
    DWORD pid = GetProcessIdByName(process_name);
    if (pid == 0) {
      return false;
    }
    return Initialize(static_cast<uint64_t>(pid), desired_access);
  }

  struct SafeULONG {
    ULONG value;
    ULONG reserved;
  };

  bool ReadMemoryNt(uintptr_t address, void* buffer, size_t size) {
    if (!target_process_handle_) return false;

    alignas(8) SafeULONG bytes_wrapper = {0, 0};
    NTSTATUS status = NtReadVirtualMemory(
        target_process_handle_, reinterpret_cast<PVOID>(address), buffer,
        static_cast<ULONG>(size), &(bytes_wrapper.value));
    return NT_SUCCESS(status) &&
           static_cast<size_t>(bytes_wrapper.value) == size;
  }

  bool WriteMemoryNt(uintptr_t address, const void* buffer, size_t size) {
    if (!target_process_handle_ || !buffer || size == 0) {
      return false;
    }

    PVOID pBaseAddr = reinterpret_cast<PVOID>(address);
    SIZE_T sSize = static_cast<SIZE_T>(size);
    ULONG oldProtect = 0;

    NTSTATUS status_protect =
        NtProtectVirtualMemory(target_process_handle_, &pBaseAddr, &sSize,
                               PAGE_READWRITE, &oldProtect);

    if (!NT_SUCCESS(status_protect)) {
      return false;
    }

    alignas(8) SafeULONG bytes_wrapper = {0, 0};
    NTSTATUS status_write = NtWriteVirtualMemory(
        target_process_handle_, reinterpret_cast<PVOID>(address),
        const_cast<PVOID>(buffer), static_cast<ULONG>(size),
        &(bytes_wrapper.value));

    ULONG temp = 0;
    NtProtectVirtualMemory(target_process_handle_, &pBaseAddr, &sSize,
                           oldProtect, &temp);

    return NT_SUCCESS(status_write) &&
           static_cast<size_t>(bytes_wrapper.value) == size;
  }

  uint64_t GetDllBaseAddress(const char* dll_name) {
    if (!target_process_handle_) return 0;

    PLDR_DATA_TABLE_ENTRY pLdrEntry = nullptr;
    if (!GetLdrDataTableEntryByName(dll_name, &pLdrEntry)) {
        return 0;
    }

    uint64_t baseAddr = reinterpret_cast<uint64_t>(pLdrEntry->DllBase);
    delete pLdrEntry;
    return baseAddr;
  }

  uint64_t GetDllSize(const char* dll_name) {
    if (!target_process_handle_) return 0;

    PLDR_DATA_TABLE_ENTRY pLdrEntry = nullptr;
    if (!GetLdrDataTableEntryByName(dll_name, &pLdrEntry)) {
        return 0;
    }

    uint64_t dllSize = static_cast<uint64_t>(pLdrEntry->SizeOfImage);
    delete pLdrEntry;
    return dllSize;
  }

  void MouseEvent(DWORD flags, DWORD x, DWORD y, DWORD data,
                  ULONG_PTR extra_info) {
    LONG dx = (LONG)x;
    LONG dy = (LONG)y;

    my_mouse_event(flags, dx, dy, data, extra_info);
  }

  void MouseLeftDown() { MouseEvent(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); }

  void MouseLeftUp() { MouseEvent(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); }

  void MouseMove(DWORD x, DWORD y) {
    if (dpi_ == 0) dpi_ = GetSystemDPI();
    DWORD dx = (x * 100 + dpi_ / 2) / dpi_;
    DWORD dy = (y * 100 + dpi_ / 2) / dpi_;
    MouseEvent(MOUSEEVENTF_MOVE, dx, dy, 0, 0);
  }

  void SetCursorPos(DWORD x, DWORD y) {
    int screen_width = GetSystemMetrics(SM_CXSCREEN) - 1;
    int screen_height = GetSystemMetrics(SM_CYSCREEN) - 1;
    int virtual_x = (x * 65535) / screen_width;
    int virtual_y = (y * 65535) / screen_height;
    MouseEvent(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, virtual_x, virtual_y, 0,
               0);
  }

  void KeybdEvent(BYTE vk, BYTE scan, DWORD flags,
                           ULONG_PTR extra_info) {
    my_keybd_event(vk, scan, flags, extra_info);
  }

  void AntiCapture(HWND window_handle, bool status = true) {
    SetWindowDisplayAffinity(window_handle, status ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
  }

  HANDLE GetProcessHandle() const { return target_process_handle_; }
  DWORD GetProcessId() const { return target_process_id_; }

 private:
  HANDLE target_process_handle_;
  DWORD target_process_id_;
  int dpi_ = 0;

  static int GetSystemDPI() {
    HDC hdc = GetDC(nullptr);
    int dpi = GetDeviceCaps(hdc, LOGPIXELSX);
    ReleaseDC(nullptr, hdc);
    return dpi;
  }

  static DWORD GetProcessIdByName(const wchar_t* process_name) {
    if (!pfnNtQuerySystemInformation || !process_name)
        return 0;

    DWORD dwPid = 0;
    ULONG ulBufferSize = 0x10000;
    PBYTE pBuffer = (PBYTE)VirtualAlloc(nullptr, ulBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuffer)
        return 0;

    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        status = pfnNtQuerySystemInformation(5, pBuffer, ulBufferSize, nullptr);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            VirtualFree(pBuffer, 0, MEM_RELEASE);
            ulBufferSize *= 2;
            pBuffer = (PBYTE)VirtualAlloc(nullptr, ulBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!pBuffer)
                return 0;
        }
    }

    if (!NT_SUCCESS(status))
    {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        return 0;
    }

    PSYSTEM_PROCESS_INFORMATION pSPI = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    while (true)
    {
        if (pSPI->ImageName.Buffer && pSPI->ProcessId != nullptr)
        {
            if (_wcsicmp(pSPI->ImageName.Buffer, process_name) == 0)
            {
                dwPid = (DWORD)(ULONG_PTR)pSPI->ProcessId;
                break;
            }
        }

        if (pSPI->NextEntryOffset == 0)
            break;
        pSPI = (PSYSTEM_PROCESS_INFORMATION)((uintptr_t)pSPI + pSPI->NextEntryOffset);
    }

    VirtualFree(pBuffer, 0, MEM_RELEASE);
    return dwPid;
  }

  bool GetLdrDataTableEntryByName(const char* dll_name, PLDR_DATA_TABLE_ENTRY* pOutLdrEntry) {
    if (!target_process_handle_ || !dll_name || !pOutLdrEntry) {
        return false;
    }

    *pOutLdrEntry = new LDR_DATA_TABLE_ENTRY();
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(
        target_process_handle_,
        ProcessBasicInformation,
        &pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        delete *pOutLdrEntry;
        *pOutLdrEntry = nullptr;
        return false;
    }

    PEB peb = {0};
    if (!ReadMemoryNt(reinterpret_cast<uintptr_t>(pbi.PebBaseAddress), &peb, sizeof(PEB))) {
        delete *pOutLdrEntry;
        *pOutLdrEntry = nullptr;
        return false;
    }

    PEB_LDR_DATA ldrData = {0};
    if (!ReadMemoryNt(reinterpret_cast<uintptr_t>(peb.Ldr), &ldrData, sizeof(PEB_LDR_DATA))) {
        delete *pOutLdrEntry;
        *pOutLdrEntry = nullptr;
        return false;
    }

    PLIST_ENTRY pModuleListHead = &ldrData.InLoadOrderModuleList;
    PLIST_ENTRY pCurrentListEntry = pModuleListHead->Flink;

    wchar_t dllNameWide[MAX_PATH] = {0};
    MultiByteToWideChar(CP_ACP, 0, dll_name, -1, dllNameWide, MAX_PATH);

    while (true) {
        PLDR_DATA_TABLE_ENTRY pRemoteLdrEntry = CONTAINING_RECORD(pCurrentListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!ReadMemoryNt(reinterpret_cast<uintptr_t>(pRemoteLdrEntry), *pOutLdrEntry, sizeof(LDR_DATA_TABLE_ENTRY))) {
            break;
        }

        wchar_t baseDllName[MAX_PATH] = {0};
        if ((*pOutLdrEntry)->BaseDllName.Buffer && (*pOutLdrEntry)->BaseDllName.Length > 0) {
            size_t len1 = static_cast<size_t>((*pOutLdrEntry)->BaseDllName.Length);
            size_t len2 = sizeof(baseDllName) - sizeof(wchar_t);
            ReadMemoryNt(
                reinterpret_cast<uintptr_t>((*pOutLdrEntry)->BaseDllName.Buffer),
                baseDllName,
                std::min(len1, len2)
            );
        }

        if (_wcsicmp(baseDllName, dllNameWide) == 0) {
            return true;
        }

        pCurrentListEntry = (*pOutLdrEntry)->InLoadOrderLinks.Flink;
        if (pCurrentListEntry == pModuleListHead) {
            break;
        }
    }

    delete *pOutLdrEntry;
    *pOutLdrEntry = nullptr;
    return false;
  }
};

#endif
