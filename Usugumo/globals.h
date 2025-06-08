#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H2 20180
#define WINDOWS_22H2 22621

#define WINDOWS11_21H2 22000
#define WINDOWS11_22H2 22509
#define WINDOWS11_24H2 26100

#define PAGE_OFFSET_SIZE 12

// request codes
#define DRIVER_READVM 0xCAFE1
#define DRIVER_WRITEVM 0xCAFE2
#define HID 0xCAFE3
#define DLL_BASE 0xCAFE4

static constexpr uint64_t mask = 0xFFFFFFFFFFF000;
#pragma pack(push, 1)
typedef struct _FixedStr64 {
  uint64_t blocks[4];
} FixedStr64;
#pragma pack(pop)
inline void encodeFixedStr64(const char *str, FixedStr64 *fs) {
  size_t len = 0;
  while (str[len] != '\0') {
    len++;
  }
  if (len > 32) {
    len = 32;
  }

  for (int i = 0; i < 4; i++) {
    fs->blocks[i] = 0;
  }

  for (size_t i = 0; i < len; i++) {
    size_t blockIndex = i / 8;
    size_t posInBlock = i % 8;
    int shift = 8 * (7 - posInBlock);
    fs->blocks[blockIndex] |= ((unsigned __int64)(unsigned char)str[i])
                              << shift;
  }
}

inline void decodeFixedStr64(const FixedStr64 *fs, char *output,
                             size_t origLen) {
  size_t idx = 0;
  for (size_t block = 0; block < 4; block++) {
    for (int i = 0; i < 8; i++) {
      if (idx >= origLen) {
        break;
      }
      int shift = 8 * (7 - i);
      output[idx++] = (char)((fs->blocks[block] >> shift) & 0xFF);
    }
  }
  output[origLen] = '\0';
}

#pragma pack(push, 1)
struct _requests {
  // function requests
  int request_key;

  // rw
  uint64_t src_pid;
  uint64_t src_addr;
  uint64_t dst_pid;
  uint64_t dst_addr;
  size_t size;

    // 鼠标事件参数
  DWORD dwFlags;          // 事件标志
  DWORD dx;               // X 坐标或相对移动量
  DWORD dy;               // Y 坐标或相对移动量
  DWORD dwData;           // 滚轮数据
  ULONG_PTR dwExtraInfo;  // 额外信息

  uint64_t dll_base;

  FixedStr64 dll_name;
  size_t dll_name_length;
};
#pragma pack(pop)
namespace globals {
uintptr_t hook_pointer = 0;
uintptr_t hook_address = 0;
}  // namespace globals

