// Copyright (c) 2026 渟雲. All rights reserved.
#include "./common.h"

extern PLIST_ENTRY PsLoadedModuleList;
static GreProtectSpriteContentFn GreProtectSpriteContent = NULL;

static PVOID GetWin32kBase() {
  if (!PsLoadedModuleList) return NULL;
  for (PLIST_ENTRY Entry = PsLoadedModuleList->Flink;
       Entry != PsLoadedModuleList; Entry = Entry->Flink) {
    PLDR_DATA_TABLE_ENTRY Module =
        CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (Module->BaseDllName.Buffer &&
        kwcsicmp(Module->BaseDllName.Buffer, L"win32kfull.sys") == 0) {
      return Module->DllBase;
    }
  }

  return NULL;
}

BOOLEAN InitGreProtectSpriteContent() {
  if (!GreProtectSpriteContent) {
    PVOID ModuleBase = GetWin32kBase();
    if (!ModuleBase) return FALSE;

    UCHAR Pattern[] = {0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B,
                       0xCC, 0x85, 0xC0, 0x75, 0x0E};
    CHAR Mask[] = "x????x?xxxx";

    PVOID FoundAddress =
        SearchSignForImage(ModuleBase, Pattern, Mask, sizeof(Pattern));
    if (!FoundAddress) return FALSE;

    GreProtectSpriteContent =
        (GreProtectSpriteContentFn)ResolveRelativeAddress(FoundAddress, 1);
    if (!GreProtectSpriteContent) return FALSE;
  }
  return TRUE;  
}

BOOLEAN ZwProtectWindow(HWND hWnd, UINT Flags) {
  if (!GreProtectSpriteContent) {
    if (!InitGreProtectSpriteContent()) return FALSE;
  }

  return GreProtectSpriteContent(NULL, hWnd, TRUE, Flags) ? TRUE : FALSE;
}

BOOLEAN HandleAntiCapture(Requests* request) {
  if (!request) return FALSE;

  HWND hWnd = request->window_handle;
  UINT Flags = request->protect_flags;

  return ZwProtectWindow(hWnd, Flags);
}
