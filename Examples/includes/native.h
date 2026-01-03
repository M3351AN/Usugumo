// Copyright (c) 2026 渟雲. All rights reserved.
#pragma once
#ifndef _NATIVE_H_
#define _NATIVE_H_
#include <Windows.h>

#include <cstdint>
#include <string>
#include <algorithm>
#include <string_view>
#include <memory>
#include <unordered_map>

#include "./mouse_input_injection.h"
#include "./keybd_input_injection.h"
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

constexpr inline size_t kIndirectSyscallSize = 22uz;
constexpr inline size_t kSNtFuncMaxSize = 64uz; // usually wont exceed 64 bytes
constexpr inline ULONG kDefaultBufferSize = 0x10000u;

typedef struct _UNICODE_STRING UNICODE_STRING, *PUNICODE_STRING;
typedef struct _CLIENT_ID CLIENT_ID, *PCLIENT_ID;
typedef struct _OBJECT_ATTRIBUTES OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _PROCESS_BASIC_INFORMATION PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
typedef struct _PEB_LDR_DATA PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB PEB, *PPEB;
typedef struct _SYSTEM_PROCESS_INFORMATION SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

struct SyscallInfo {
    ULONG syscallNum;
    uintptr_t syscallAddr;
    void* funcPtr;
};

static std::unordered_map<std::string, SyscallInfo> g_SyscallInfoMap;

typedef NTSTATUS(WINAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);
static pNtAllocateVirtualMemory pfnNtAllocateVirtualMemory = nullptr;

typedef NTSTATUS(WINAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection, PULONG OldAccessProtection);
static pNtProtectVirtualMemory pfnNtProtectVirtualMemory = nullptr;

typedef NTSTATUS(WINAPI* pNtFreeVirtualMemory)(
    HANDLE ProcessHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
static pNtFreeVirtualMemory pfnNtFreeVirtualMemory = nullptr;


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

typedef BOOL(WINAPI* pNtUserSetWindowDisplayAffinity)(
    HWND hWnd, DWORD dwAffinity
);
static pNtUserSetWindowDisplayAffinity pfnNtUserSetWindowDisplayAffinity = nullptr;

/* 
.text:0000000180162070 ; Exported entry 451. NtOpenProcess
.text:0000000180162070 ; Exported entry 2098. ZwOpenProcess
.text:0000000180162070
.text:0000000180162070 ; =============== S U B R O U T I N E =======================================
.text:0000000180162070
.text:0000000180162070 ; Alternative name is 'NtOpenProcess'
.text:0000000180162070
.text:0000000180162070 ; __int64 NtOpenProcess()
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
 */
static const BYTE g_IndirectSyscallTemplate[] = {
    // here we construct our syscall
    0x4C, 0x8B, 0xD1,       // mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, SSN (4 bytes)
    // here we jump to syscall in the function
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip] (6 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // syscall addr (8 bytes)
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

using Address = uintptr_t;
using SizeType = size_t;
using ProcessId = DWORD;
using ProcessHandle = HANDLE;
using SyscallNum = ULONG;

struct VirtualMemDeleter {
    void operator()(PBYTE p) const noexcept {
        if (p != nullptr) {
            // Use NtFreeVirtualMemory if available, otherwise use VirtualFree
            if (pfnNtFreeVirtualMemory) {
                pfnNtFreeVirtualMemory(GetCurrentProcess(), &p, 0, MEM_RELEASE);
            } else {
                VirtualFree(p, 0, MEM_RELEASE);
            }
        }
    }
};

using UniqueVirtualMemPtr = std::unique_ptr<BYTE, VirtualMemDeleter>;

using UniqueLdrEntryPtr = std::unique_ptr<LDR_DATA_TABLE_ENTRY>;

static bool FindSyscallInstruction(PBYTE pFuncBytes, ULONG funcSearchSize, uintptr_t& syscallAddr) noexcept
{
    if (!pFuncBytes || funcSearchSize < 2)
        return false;

    for (ULONG i = 0; i <= funcSearchSize - 2; i++)
    {
        if (pFuncBytes[i] == 0x0F && pFuncBytes[i+1] == 0x05)
        {
            syscallAddr = reinterpret_cast<uintptr_t>(pFuncBytes + i);
            return true;
        }
    }
    return false;
}

static bool IsFunctionHooked(PBYTE pFuncBytes) noexcept
{
    if (!pFuncBytes) return false;
    
    if (pFuncBytes[0] == 0xE9) { // jmp
        return true;
    }
    
    if (pFuncBytes[0] == 0xFF && pFuncBytes[1] == 0x25) { // jmp [rip+imm32]
        return true;
    }
    
    return false;
}

template <typename FuncPtr>
static FuncPtr ConstructIndirectSyscall(ULONG syscallNum, uintptr_t syscallAddr) noexcept
{
    // here we direct called VirtualAlloc/Protect
    // any way better but wont cause DEP issue?
    if (syscallNum == 0 || syscallAddr == 0) {
        return nullptr;
    }

    PVOID pAllocBase = nullptr;
    SIZE_T allocSize = sizeof(g_IndirectSyscallTemplate);
    NTSTATUS allocStatus = STATUS_UNSUCCESSFUL;
    if (pfnNtAllocateVirtualMemory)
    {
        allocStatus = pfnNtAllocateVirtualMemory(
            GetCurrentProcess(),
            &pAllocBase,
            0,
            &allocSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
    } else {
    // fall back to VirtualAlloc for construct NtAllocateVirtualMemory it self.
        pAllocBase = VirtualAlloc(nullptr, sizeof(g_IndirectSyscallTemplate), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pAllocBase) {
            return nullptr;
        }
    }

    UniqueVirtualMemPtr pMem((PBYTE)pAllocBase);
    if (!pMem) {
        return nullptr;
    }

    memcpy(pMem.get(), g_IndirectSyscallTemplate, sizeof(g_IndirectSyscallTemplate));
    
    memcpy(pMem.get() + 4, &syscallNum, 4);
    
    memcpy(pMem.get() + 14, &syscallAddr, 8);
    
    DWORD oldProtect = 0;
    PVOID pProtectBase = pMem.get();
    SIZE_T protectSize = sizeof(g_IndirectSyscallTemplate);
    NTSTATUS protectStatus = STATUS_UNSUCCESSFUL;
    if (pfnNtProtectVirtualMemory)
    {
        protectStatus = pfnNtProtectVirtualMemory(
            GetCurrentProcess(),
            &pProtectBase,
            &protectSize,
            PAGE_EXECUTE_READ,
            &oldProtect
        );
    } else {
    // fall back to VirtualProtect for construct NtProtectVirtualMemory it self.
        if (!VirtualProtect(pMem.get(), sizeof(g_IndirectSyscallTemplate), PAGE_EXECUTE_READ, &oldProtect)) {
            return nullptr;
        }
    }
    
    FlushInstructionCache(GetCurrentProcess(), pMem.get(), sizeof(g_IndirectSyscallTemplate));
    
    return reinterpret_cast<FuncPtr>(pMem.release());
}

static void ParseModuleForSyscalls(HMODULE hModule) noexcept
{
    if (!hModule) {
        return;
    }

    PBYTE pModuleBase = reinterpret_cast<PBYTE>(hModule);

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pModuleBase);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return;
    }

    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pModuleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }

    IMAGE_DATA_DIRECTORY exportDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
        return;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pModuleBase + exportDir.VirtualAddress);

    PDWORD pFuncNames = reinterpret_cast<PDWORD>(pModuleBase + pExportDir->AddressOfNames);
    PDWORD pFuncAddrs = reinterpret_cast<PDWORD>(pModuleBase + pExportDir->AddressOfFunctions);
    PWORD pFuncOrdinals = reinterpret_cast<PWORD>(pModuleBase + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* pFuncName = reinterpret_cast<const char*>(pModuleBase + pFuncNames[i]);
        // Nt or Zw is 100% same in user mode, 
        // but we only care about Nt functions
        // skip just for performance
        // there are not "Zw only" functions in user mode
        // but there are "Nt only" functions, yes
        if (strncmp(pFuncName, "Nt", 2) != 0 || strncmp(pFuncName, "Zw", 2) == 0) {
            continue;
        }

        DWORD funcRVA = pFuncAddrs[pFuncOrdinals[i]];
        if (funcRVA == 0) {
            continue;
        }

        PBYTE pFuncBytes = pModuleBase + funcRVA;

        if (IsFunctionHooked(pFuncBytes)) {
            // incase of hooked, skip this function
            // anyway, usermode EDR/AV/AC should cant hook these functions
            continue;
        }

        // mov r10, rcx; mov eax, syscallNum
        if (pFuncBytes[0] != 0x4C || pFuncBytes[1] != 0x8B || pFuncBytes[2] != 0xD1 || pFuncBytes[3] != 0xB8) {
            continue;
        }

        ULONG syscallNum = *reinterpret_cast<ULONG*>(pFuncBytes + 4);
        if (syscallNum == 0) {
            continue;
        }

        uintptr_t syscallAddr = 0;
        if (!FindSyscallInstruction(pFuncBytes, kSNtFuncMaxSize, syscallAddr)) {
            continue;
        }

        SyscallInfo info;
        info.syscallNum = syscallNum;
        info.syscallAddr = syscallAddr;
        info.funcPtr = nullptr;

        g_SyscallInfoMap[pFuncName] = info;
    }
}

static void ManualSysCall_Init() noexcept
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    ParseModuleForSyscalls(hNtdll);

    HMODULE hWin32u = GetModuleHandleW(L"win32u.dll");
    if (!hWin32u) {
        // If win32u.dll is not loaded, we will try to load it manually.
        // for applications with window, this should be always loaded
        hWin32u = LoadLibraryW(L"win32u.dll");
        ParseModuleForSyscalls(hWin32u);
        FreeLibrary(hWin32u);
    } else {
        ParseModuleForSyscalls(hWin32u);
    }

    // NtAllocateVirtualMemory and NtProtectVirtualMemory
    {
        auto it = g_SyscallInfoMap.find("NtAllocateVirtualMemory");
        if (it != g_SyscallInfoMap.end()) {
            pfnNtAllocateVirtualMemory = ConstructIndirectSyscall<pNtAllocateVirtualMemory>(
                it->second.syscallNum, it->second.syscallAddr);
            it->second.funcPtr = reinterpret_cast<void*>(pfnNtAllocateVirtualMemory);
        }
    }

    {
        auto it = g_SyscallInfoMap.find("NtProtectVirtualMemory");
        if (it != g_SyscallInfoMap.end()) {
            pfnNtProtectVirtualMemory = ConstructIndirectSyscall<pNtProtectVirtualMemory>(
                it->second.syscallNum, it->second.syscallAddr);
            it->second.funcPtr = reinterpret_cast<void*>(pfnNtProtectVirtualMemory);
        }
    }
    // if we cant find NtAllocateVirtualMemory or NtProtectVirtualMemory, 
    // we cant construct other syscalls
    if (!pfnNtAllocateVirtualMemory || !pfnNtProtectVirtualMemory) {
        return;
    }

    // NtOpenProcess
    {
        auto it = g_SyscallInfoMap.find("NtOpenProcess");
        if (it != g_SyscallInfoMap.end()) {
            pfnNtOpenProcess = ConstructIndirectSyscall<_NtOpenProcess>(
                it->second.syscallNum, it->second.syscallAddr);
            it->second.funcPtr = reinterpret_cast<void*>(pfnNtOpenProcess);
        }
    }

    // NtReadVirtualMemory
    {
        auto it = g_SyscallInfoMap.find("NtReadVirtualMemory");
        if (it != g_SyscallInfoMap.end()) {
            pfnNtReadVirtualMemory = ConstructIndirectSyscall<pNtReadVirtualMemory>(
                it->second.syscallNum, it->second.syscallAddr);
            it->second.funcPtr = reinterpret_cast<void*>(pfnNtReadVirtualMemory);
        }
    }

    // NtWriteVirtualMemory
    {
        auto it = g_SyscallInfoMap.find("NtWriteVirtualMemory");
        if (it != g_SyscallInfoMap.end()) {
            pfnNtWriteVirtualMemory = ConstructIndirectSyscall<pNtWriteVirtualMemory>(
                it->second.syscallNum, it->second.syscallAddr);
            it->second.funcPtr = reinterpret_cast<void*>(pfnNtWriteVirtualMemory);
        }
    }

    // NtQueryInformationProcess
    {
        auto it = g_SyscallInfoMap.find("NtQueryInformationProcess");
        if (it != g_SyscallInfoMap.end()) {
            pfnNtQueryInformationProcess = ConstructIndirectSyscall<pNtQueryInformationProcess>(
                it->second.syscallNum, it->second.syscallAddr);
            it->second.funcPtr = reinterpret_cast<void*>(pfnNtQueryInformationProcess);
        }
    }

    // NtQuerySystemInformation
    {
        auto it = g_SyscallInfoMap.find("NtQuerySystemInformation");
        if (it != g_SyscallInfoMap.end()) {
            pfnNtQuerySystemInformation = ConstructIndirectSyscall<pNtQuerySystemInformation>(
                it->second.syscallNum, it->second.syscallAddr);
            it->second.funcPtr = reinterpret_cast<void*>(pfnNtQuerySystemInformation);
        }
    }

    // NtUserSetWindowDisplayAffinity
    {
        auto it = g_SyscallInfoMap.find("NtUserSetWindowDisplayAffinity");
        if (it != g_SyscallInfoMap.end()) {
            pfnNtUserSetWindowDisplayAffinity = ConstructIndirectSyscall<pNtUserSetWindowDisplayAffinity>(
                it->second.syscallNum, it->second.syscallAddr);
            it->second.funcPtr = reinterpret_cast<void*>(pfnNtUserSetWindowDisplayAffinity);
        }
    }

    // NtFreeVirtualMemory
    {
        auto it = g_SyscallInfoMap.find("NtFreeVirtualMemory");
        if (it != g_SyscallInfoMap.end()) {
            pfnNtFreeVirtualMemory = ConstructIndirectSyscall<pNtFreeVirtualMemory>(
                it->second.syscallNum, it->second.syscallAddr);
            it->second.funcPtr = reinterpret_cast<void*>(pfnNtFreeVirtualMemory);
        }
    }

    // fail openprocess, nosense to use other these syscalls
    if (!pfnNtOpenProcess) {
        pfnNtReadVirtualMemory = nullptr;
        pfnNtWriteVirtualMemory = nullptr;
        pfnNtProtectVirtualMemory = nullptr;
        pfnNtQueryInformationProcess = nullptr;
        pfnNtQuerySystemInformation = nullptr;
    }

}

static bool g_ManualSysCallInited = []() noexcept {
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

inline static ProcessHandle NtOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle,
                                   ProcessId dwProcessId) noexcept {
  ProcessHandle hProcess = 0;
  CLIENT_ID clientId = {(PVOID)(ULONG_PTR)dwProcessId, NULL};
  OBJECT_ATTRIBUTES objAttr = InitObjectAttributes(NULL, 0, NULL, NULL);
  if (pfnNtOpenProcess)
  {
      pfnNtOpenProcess(&hProcess, dwDesiredAccess, &objAttr, &clientId);
  }
  return hProcess;
}

inline static pNtReadVirtualMemory NtReadVirtualMemory = []() noexcept {
  return pfnNtReadVirtualMemory;
}();
inline static pNtWriteVirtualMemory NtWriteVirtualMemory = []() noexcept {
  return pfnNtWriteVirtualMemory;
}();
inline static pNtProtectVirtualMemory NtProtectVirtualMemory = []() noexcept {
  return pfnNtProtectVirtualMemory;
}();
inline static pNtQueryInformationProcess NtQueryInformationProcess = []() noexcept {
  return pfnNtQueryInformationProcess;
}();
inline static pNtQuerySystemInformation NtQuerySystemInformation = []() noexcept {
  return pfnNtQuerySystemInformation;
}();

class Native {
 public:
  Native() noexcept : target_process_handle_(nullptr), target_process_id_(0), dpi_(0) {}

  ~Native() noexcept {
    if (target_process_handle_) {
      CloseHandle(target_process_handle_);
    }
  }

  Native(const Native&) = delete;
  Native& operator=(const Native&) = delete;

  Native(Native&& other) noexcept {
    *this = std::move(other);
  }

  Native& operator=(Native&& other) noexcept {
    if (this != &other) {
      target_process_handle_ = other.target_process_handle_;
      target_process_id_ = other.target_process_id_;
      dpi_ = other.dpi_;

      other.target_process_handle_ = nullptr;
      other.target_process_id_ = 0;
      other.dpi_ = 0;
    }
    return *this;
  }

  bool Initialize(uint64_t process_id,
                  DWORD desired_access = PROCESS_ALL_ACCESS) noexcept {
    target_process_id_ = static_cast<ProcessId>(process_id);
    target_process_handle_ =
        NtOpenProcess(desired_access, FALSE, target_process_id_);
    return target_process_handle_ != nullptr;
  }

  bool Initialize(std::wstring_view process_name,
                  DWORD desired_access = PROCESS_ALL_ACCESS) noexcept {
    ProcessId pid = GetProcessIdByName(process_name);
    if (pid == 0) {
      return false;
    }
    return Initialize(static_cast<uint64_t>(pid), desired_access);
  }
  // dont askme why, ni idea. but hate this
  struct SafeULONG {
    ULONG value;
    ULONG reserved;
  };

  bool ReadMemoryNt(Address address, void* buffer, SizeType size) noexcept {
    if (!target_process_handle_ || !buffer || size == 0) return false;

    alignas(8) SafeULONG bytes_wrapper = {0, 0};
    NTSTATUS status = NtReadVirtualMemory(
        target_process_handle_, reinterpret_cast<PVOID>(address), buffer,
        static_cast<ULONG>(size), &(bytes_wrapper.value));
    return NT_SUCCESS(status) &&
           static_cast<SizeType>(bytes_wrapper.value) == size;
  }

  bool WriteMemoryNt(Address address, const void* buffer, SizeType size) noexcept {
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
           static_cast<SizeType>(bytes_wrapper.value) == size;
  }

  uint64_t GetDllBaseAddress(const char* dll_name) noexcept {
    if (!target_process_handle_) return 0;

    UniqueLdrEntryPtr pLdrEntry;
    if (!GetLdrDataTableEntryByName(dll_name, pLdrEntry)) {
        return 0;
    }

    return reinterpret_cast<uint64_t>(pLdrEntry->DllBase);
  }

  uint64_t GetDllSize(const char* dll_name) noexcept {
    if (!target_process_handle_) return 0;

    UniqueLdrEntryPtr pLdrEntry;
    if (!GetLdrDataTableEntryByName(dll_name, pLdrEntry)) {
        return 0;
    }

    return static_cast<uint64_t>(pLdrEntry->SizeOfImage);
  }

  void MouseEvent(DWORD flags, DWORD x, DWORD y, DWORD data,
                  ULONG_PTR extra_info) noexcept {
    LONG dx = (LONG)x;
    LONG dy = (LONG)y;

    my_mouse_event(flags, dx, dy, data, extra_info);
  }

  void MouseLeftDown() noexcept { MouseEvent(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); }

  void MouseLeftUp() noexcept { MouseEvent(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); }

  void MouseMove(DWORD x, DWORD y) noexcept {
    if (dpi_ == 0) dpi_ = GetSystemDPI();
    DWORD dx = (x * 100u + dpi_ / 2) / dpi_;
    DWORD dy = (y * 100u + dpi_ / 2) / dpi_;
    MouseEvent(MOUSEEVENTF_MOVE, dx, dy, 0, 0);
  }

  void SetCursorPos(DWORD x, DWORD y) noexcept {
    int screen_width = GetSystemMetrics(SM_CXSCREEN) - 1;
    int screen_height = GetSystemMetrics(SM_CYSCREEN) - 1;
    int virtual_x = (x * 65535u) / screen_width;
    int virtual_y = (y * 65535u) / screen_height;
    MouseEvent(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, virtual_x, virtual_y, 0,
               0);
  }

  void KeybdEvent(BYTE vk, BYTE scan, DWORD flags,
                           ULONG_PTR extra_info) noexcept {
    my_keybd_event(vk, scan, flags, extra_info);
  }

  void AntiCapture(HWND window_handle, bool status = true) noexcept {
    pfnNtUserSetWindowDisplayAffinity(window_handle, status ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
  }

  ProcessHandle GetProcessHandle() const noexcept { return target_process_handle_; }
  ProcessId GetProcessId() const noexcept { return target_process_id_; }

 private:
  ProcessHandle target_process_handle_;
  ProcessId target_process_id_;
  int dpi_;

  static int GetSystemDPI() noexcept {
    if (HDC hdc = GetDC(nullptr); hdc != nullptr) {
      int dpi = GetDeviceCaps(hdc, LOGPIXELSX);
      ReleaseDC(nullptr, hdc);
      return dpi;
    }
    return 96;
  }

  static ProcessId GetProcessIdByName(std::wstring_view process_name) noexcept {
    if (!pfnNtQuerySystemInformation || process_name.empty())
        return 0;

    ProcessId dwPid = 0;
    ULONG ulBufferSize = kDefaultBufferSize;
    UniqueVirtualMemPtr pBuffer(
        (PBYTE)VirtualAlloc(nullptr, ulBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    );
    if (!pBuffer)
        return 0;

    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        status = pfnNtQuerySystemInformation(5, pBuffer.get(), ulBufferSize, nullptr);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            ulBufferSize *= 2;
            pBuffer.reset(
                (PBYTE)VirtualAlloc(nullptr, ulBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            );
            if (!pBuffer)
                return 0;
        }
    }

    if (!NT_SUCCESS(status))
    {
        return 0;
    }

    PSYSTEM_PROCESS_INFORMATION pSPI = (PSYSTEM_PROCESS_INFORMATION)pBuffer.get();
    while (true)
    {
        if (pSPI->ImageName.Buffer && pSPI->ProcessId != nullptr)
        {
            if (_wcsicmp(pSPI->ImageName.Buffer, process_name.data()) == 0)
            {
                dwPid = (ProcessId)(ULONG_PTR)pSPI->ProcessId;
                break;
            }
        }

        if (pSPI->NextEntryOffset == 0)
            break;
        pSPI = (PSYSTEM_PROCESS_INFORMATION)((Address)pSPI + pSPI->NextEntryOffset);
    }

    return dwPid;
  }

  bool GetLdrDataTableEntryByName(const char* dll_name, UniqueLdrEntryPtr& pOutLdrEntry) noexcept {
    if (!target_process_handle_ || !dll_name) {
        return false;
    }

    pOutLdrEntry = std::make_unique<LDR_DATA_TABLE_ENTRY>();
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
        pOutLdrEntry.reset();
        return false;
    }

    PEB peb = {0};
    if (!ReadMemoryNt(reinterpret_cast<Address>(pbi.PebBaseAddress), &peb, sizeof(PEB))) {
        pOutLdrEntry.reset();
        return false;
    }

    PEB_LDR_DATA ldrData = {0};
    if (!ReadMemoryNt(reinterpret_cast<Address>(peb.Ldr), &ldrData, sizeof(PEB_LDR_DATA))) {
        pOutLdrEntry.reset();
        return false;
    }

    PLIST_ENTRY pModuleListHead = &ldrData.InLoadOrderModuleList;
    PLIST_ENTRY pCurrentListEntry = pModuleListHead->Flink;

    wchar_t dllNameWide[MAX_PATH] = {0};
    MultiByteToWideChar(CP_ACP, 0, dll_name, -1, dllNameWide, MAX_PATH);

    while (true) {
        PLDR_DATA_TABLE_ENTRY pRemoteLdrEntry = CONTAINING_RECORD(pCurrentListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!ReadMemoryNt(reinterpret_cast<Address>(pRemoteLdrEntry), pOutLdrEntry.get(), sizeof(LDR_DATA_TABLE_ENTRY))) {
            break;
        }

        wchar_t baseDllName[MAX_PATH] = {0};
        if (pOutLdrEntry->BaseDllName.Buffer && pOutLdrEntry->BaseDllName.Length > 0) {
            SizeType len1 = static_cast<SizeType>(pOutLdrEntry->BaseDllName.Length);
            SizeType len2 = sizeof(baseDllName) - sizeof(wchar_t);
            ReadMemoryNt(
                reinterpret_cast<Address>(pOutLdrEntry->BaseDllName.Buffer),
                baseDllName,
                std::min(len1, len2)
            );
        }

        if (_wcsicmp(baseDllName, dllNameWide) == 0) {
            return true;
        }

        pCurrentListEntry = pOutLdrEntry->InLoadOrderLinks.Flink;
        if (pCurrentListEntry == pModuleListHead) {
            break;
        }
    }

    pOutLdrEntry.reset();
    return false;
  }
};

#endif
