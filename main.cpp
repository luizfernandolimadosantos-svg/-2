#include <cstdio>
#include <cstdlib>
#ifdef SYNC_WITH_YARA
#include <yara.h>
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <windowsx.h>
#include <ctime>
#include <cmath>
#include <iterator>
#include <winhttp.h>
#include <shellapi.h>
#pragma comment(lib,"shell32.lib")
#include <map>
#pragma comment(lib,"winhttp.lib")
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#pragma comment(lib,"dbghelp.lib")
#include <commdlg.h>
#include <d3d11.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <tcpmib.h>
#include <winevt.h>
#pragma comment(lib,"wevtapi.lib")
#include <cstring>
#include <array>
#include <chrono>
#include <system_error>
#include <cstdint>
#include <winreg.h>
#include <cctype>
#include <cwctype>
#include <unordered_set>
#include <unordered_map>
#include <filesystem>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <atomic>
#include <thread>
#include <mutex>
#include <memory>
#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"

#pragma comment(lib,"d3d11.lib")
#pragma comment(lib,"dxgi.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"gdi32.lib")
#pragma comment(lib,"comdlg32.lib")
#pragma comment(lib,"wintrust.lib")
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"psapi.lib")

// Compile-time XOR obfuscation for selected non-sensitive UI literals.
// This is not cryptography; decoded text is present during use.
namespace sync_xor {
template <std::size_t N, unsigned char Key = 0xA7>
struct Literal {
    std::array<char,N> encoded{};
    consteval Literal(const char (&value)[N]) {
        for(std::size_t i=0;i<N;++i)
            encoded[i]=static_cast<char>(static_cast<unsigned char>(value[i]) ^ Key);
    }
    std::string decode() const {
        std::string result;
        result.resize(N-1);
        for(std::size_t i=0;i<N-1;++i)
            result[i]=static_cast<char>(static_cast<unsigned char>(encoded[i]) ^ Key);
        return result;
    }
};
template <Literal Value>
std::string decode() { return Value.decode(); }
}
#define XOR_STR(value) (::sync_xor::decode<::sync_xor::Literal{value}>())

namespace fs=std::filesystem;

// Diagnostics are local and transparent: no Defender exclusions, concealment,
// privilege escalation, registry writes, or changes to security settings.
static std::mutex diagnosticMutex;
static std::wstring diagnosticPath(){
    wchar_t folder[MAX_PATH]{};
    DWORD n=GetEnvironmentVariableW(L"LOCALAPPDATA",folder,MAX_PATH);
    if(n==0 || n>=MAX_PATH){
        n=GetTempPathW(MAX_PATH,folder);
        if(n==0 || n>=MAX_PATH)return L"SyncPCChecker-diagnostic.log";
    }
    return (std::filesystem::path(folder)/L"SyncPCChecker"/
            L"diagnostic.log").wstring();
}
static void diagnosticLog(const char* message){
    try{
        std::lock_guard<std::mutex> guard(diagnosticMutex);
        const std::filesystem::path p(diagnosticPath());
        if(p.has_parent_path())std::filesystem::create_directories(p.parent_path());
        std::ofstream file(p,std::ios::app);
        if(!file)return;
        SYSTEMTIME now{};GetLocalTime(&now);
        char stamp[48]{};
        snprintf(stamp,sizeof(stamp),"%04u-%02u-%02u %02u:%02u:%02u",
            now.wYear,now.wMonth,now.wDay,now.wHour,now.wMinute,now.wSecond);
        file<<stamp<<" | "<<(message?message:"(null)")<<"\n";
    }catch(...){}
}
static void diagnosticHRESULT(const char* operation,HRESULT hr){
    char buffer[160]{};
    snprintf(buffer,sizeof(buffer),"%s failed (HRESULT 0x%08lX)",
             operation,static_cast<unsigned long>(hr));
    diagnosticLog(buffer);
}
static LONG WINAPI diagnosticUnhandledException(EXCEPTION_POINTERS* ep){
    char buffer[160]{};
    const unsigned long code=(ep && ep->ExceptionRecord)?
        ep->ExceptionRecord->ExceptionCode:0;
    snprintf(buffer,sizeof(buffer),"Unhandled Windows exception: 0x%08lX",code);
    diagnosticLog(buffer);
    return EXCEPTION_CONTINUE_SEARCH;
}

struct Process { DWORD pid; DWORD parent; std::wstring name,path; std::string assessment; bool suspicious=false; };
struct Record { std::string category,name,detail; };
struct FileResult { std::wstring path; std::string hash,signature; };
static HWND hwnd=nullptr;
static ID3D11Device* device=nullptr;
static ID3D11DeviceContext* context=nullptr;
static IDXGISwapChain* swapchain=nullptr;
static ID3D11RenderTargetView* target=nullptr;

// Original Sync PC Checker logo, embedded so the executable needs no external image.
#include <wincodec.h>
#pragma comment(lib,"windowscodecs.lib")
static const unsigned char syncLogoPng[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x08, 0x06, 0x00, 0x00, 0x00, 0xC3, 0x3E, 0x61, 0xCB, 0x00, 0x00, 0x21, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0xED, 0x9D, 0xF9, 0x73, 0x93, 0xD7, 0xF5, 0xFF, 0x5F, 0xDA, 0x25, 0x4B, 0xB2, 0x2C, 0x2F, 0x92, 0xF7, 0x15, 0xE3, 0x15, 0x83, 0xCD, 0x92, 0x10, 0xB2, 0x11, 0xD6, 0x40, 0xF6, 0xB5, 0x09, 0x9D, 0x49, 0x42, 0xA7, 0xED, 0x74, 0xA6, 0xED, 0xEF, 0xED, 0xF4, 0x87, 0x6F, 0x7F, 0x69, 0x7F, 0xE8, 0x3F, 0xD0, 0x36, 0xD3, 0xCE, 0x34, 0x69, 0x26, 0x9D, 0x34, 0x0D, 0x59, 0x26, 0x2D, 0x5B, 0x93, 0x12, 0x42, 0xD8, 0x21, 0xC1, 0x18, 0x3B, 0xC6, 0x18, 0xAF, 0x92, 0x17, 0x49, 0x96, 0xB5, 0xEF, 0xFA, 0xFE, 0x90, 0xCF, 0xBD, 0x23, 0x19, 0x93, 0x0D, 0x1B, 0x6C, 0xD0, 0x99, 0xD1, 0x20, 0x0B, 0x3D, 0x8F, 0x9E, 0xE7, 0xB9, 0xEF, 0x7B, 0xEE, 0x39, 0xEF, 0xB3, 0x5C, 0x05, 0x90, 0x26, 0x27, 0x77, 0xAC, 0x28, 0x73, 0x8F, 0x20, 0x07, 0x80, 0x9C, 0xE4, 0x00, 0x90, 0x93, 0x1C, 0x00, 0x72, 0x92, 0x03, 0x40, 0x4E, 0x72, 0x00, 0xC8, 0x49, 0x0E, 0x00, 0x39, 0xC9, 0x01, 0x20, 0x27, 0x39, 0x00, 0xE4, 0x24, 0x07, 0x80, 0x9C, 0xE4, 0x00, 0x70, 0x67, 0x8A, 0x42, 0xA1, 0x40, 0xA1, 0x50, 0xDC, 0x11, 0xF7, 0xAA, 0xCE, 0x0D, 0xF7, 0xB5, 0x83, 0xAF, 0x52, 0xA9, 0x00, 0x48, 0xA5, 0x52, 0xA4, 0x52, 0xA9, 0xDB, 0xFB, 0x7E, 0xC9, 0x05, 0x83, 0xB2, 0x66, 0xFD, 0xED, 0x3E, 0xE0, 0xB9, 0x25, 0xE0, 0x6B, 0x00, 0xA0, 0xD1, 0x68, 0x50, 0x2A, 0xEF, 0xAC, 0x47, 0xB2, 0x64, 0x35, 0xC0, 0xDC, 0x35, 0x38, 0x9D, 0x4E, 0x7F, 0xEF, 0xE3, 0xBF, 0xEE, 0x58, 0x85, 0x42, 0x81, 0x52, 0xA9, 0x24, 0x99, 0x4C, 0xCA, 0xCF, 0xAA, 0xAA, 0xAA, 0xD0, 0xEB, 0xF5, 0x4C, 0x4E, 0x4E, 0xE2, 0xF3, 0xF9, 0xB2, 0xCE, 0xF7, 0x5D, 0xAF, 0x23, 0xA7, 0x01, 0x6E, 0x00, 0x00, 0x6A, 0xB5, 0x1A, 0xB5, 0x5A, 0x8D, 0x52, 0xA9, 0xFC, 0xCE, 0x46, 0x59, 0xE6, 0xF1, 0xD7, 0x3B, 0x56, 0xA9, 0x54, 0xA2, 0xD1, 0x68, 0xD0, 0xEB, 0xF5, 0xF2, 0x33, 0x95, 0x4A, 0xC5, 0xAE, 0x5D, 0xBB, 0x78, 0xEE, 0xB9, 0xE7, 0xA8, 0xAD, 0xAD, 0xCD, 0xFA, 0xFC, 0x76, 0x34, 0x0C, 0x97, 0xAC, 0x11, 0x38, 0x9F, 0x01, 0x36, 0xDF, 0x00, 0x64, 0xCE, 0x48, 0xF1, 0xFF, 0x62, 0x2D, 0xCF, 0x3C, 0x3E, 0xF3, 0x58, 0x85, 0x42, 0x41, 0x3A, 0x9D, 0x26, 0x95, 0x4A, 0x11, 0x8B, 0xC5, 0x88, 0xC5, 0x62, 0x68, 0xB5, 0x5A, 0x5A, 0x5A, 0x5A, 0x68, 0x68, 0x68, 0xA0, 0xAA, 0xAA, 0x8A, 0x70, 0x38, 0x7C, 0xDD, 0xDF, 0xCC, 0x01, 0xE0, 0x16, 0x5A, 0xE7, 0x99, 0xAA, 0x58, 0xBC, 0xE6, 0xAA, 0x73, 0xA5, 0x52, 0x49, 0x34, 0x1A, 0xCD, 0x3A, 0x5E, 0x58, 0xF6, 0xE2, 0x7D, 0x2A, 0x95, 0x22, 0x91, 0x48, 0xC8, 0xE3, 0x57, 0xAC, 0x58, 0xC1, 0x6F, 0x7E, 0xF3, 0x1B, 0x6C, 0x36, 0x1B, 0xAF, 0xBF, 0xFE, 0x3A, 0x47, 0x8E, 0x1C, 0x61, 0x72, 0x72, 0x12, 0xB5, 0x5A, 0x4D, 0x32, 0x99, 0xCC, 0x5A, 0x22, 0x72, 0x00, 0x58, 0xA4, 0x01, 0xCE, 0x1C, 0xCC, 0xE2, 0xE2, 0x62, 0x4A, 0x4A, 0x4A, 0x88, 0xC7, 0xE3, 0x4C, 0x4D, 0x4D, 0xE1, 0xF3, 0xF9, 0x48, 0x24, 0x12, 0xDF, 0x78, 0x1E, 0x31, 0x50, 0x2A, 0x95, 0x8A, 0xAA, 0xAA, 0x2A, 0x92, 0xC9, 0x24, 0xA3, 0xA3, 0xA3, 0x59, 0xC7, 0x8A, 0xF7, 0x26, 0x93, 0x09, 0xAB, 0xD5, 0x8A, 0xD5, 0x6A, 0xE5, 0xD1, 0x47, 0x1F, 0x65, 0xC7, 0x8E, 0x1D, 0xB8, 0x5C, 0x2E, 0xFA, 0xFA, 0xFA, 0xB8, 0x7C, 0xF9, 0x32, 0x00, 0x5A, 0xAD, 0xF6, 0xB6, 0xF6, 0x0E, 0x96, 0x0C, 0x00, 0x54, 0x2A, 0x15, 0xC9, 0x64, 0x52, 0x82, 0x60, 0xD5, 0xAA, 0x55, 0x6C, 0xDB, 0xB6, 0x8D, 0x68, 0x34, 0xCA, 0xD1, 0xA3, 0x47, 0x39, 0x73, 0xE6, 0x8C, 0x34, 0xC8, 0xBE, 0x8D, 0x54, 0x57, 0x57, 0xF3, 0xCA, 0x2B, 0xAF, 0xE0, 0xF3, 0xF9, 0x78, 0xF5, 0xD5, 0x57, 0x99, 0x9D, 0x9D, 0xBD, 0xE6, 0x3B, 0xF5, 0xF5, 0xF5, 0xEC, 0xDC, 0xB9, 0x93, 0xFB, 0xEF, 0xBF, 0x9F, 0xA6, 0xA6, 0x26, 0xDC, 0x6E, 0x37, 0x07, 0x0F, 0x1E, 0x64, 0x6A, 0x6A, 0xEA, 0x7B, 0x1B, 0x9F, 0x39, 0x00, 0x2C, 0xB0, 0x26, 0xA8, 0xAD, 0xAD, 0x45, 0xA3, 0xD1, 0x60, 0x36, 0x9B, 0xE9, 0xE9, 0xE9, 0x41, 0xA5, 0x52, 0x91, 0x97, 0x97, 0x47, 0x38, 0x1C, 0x66, 0x7C, 0x7C, 0x1C, 0xBF, 0xDF, 0x8F, 0x42, 0xA1, 0xC0, 0x68, 0x34, 0x92, 0x9F, 0x9F, 0x8F, 0xD1, 0x68, 0xC4, 0x6C, 0x36, 0xB3, 0x63, 0xC7, 0x0E, 0x5E, 0x7C, 0xF1, 0x45, 0x9C, 0x4E, 0x27, 0x97, 0x2E, 0x5D, 0xE2, 0xF3, 0xCF, 0x3F, 0x27, 0x16, 0x8B, 0xA1, 0x56, 0xAB, 0xC9, 0xCB, 0xCB, 0xA3, 0xA8, 0xA8, 0x88, 0xCE, 0xCE, 0x4E, 0xB6, 0x6C, 0xD9, 0xC2, 0xF6, 0xED, 0xDB, 0x01, 0x78, 0xE3, 0x8D, 0x37, 0x78, 0xFB, 0xED, 0xB7, 0x71, 0xBB, 0xDD, 0x68, 0x34, 0x1A, 0x92, 0xC9, 0xE4, 0x6D, 0x4F, 0x06, 0x2D, 0x19, 0x00, 0x88, 0xD9, 0xAF, 0x56, 0xAB, 0x49, 0xA5, 0x52, 0x74, 0x77, 0x77, 0x33, 0x39, 0x39, 0x29, 0x55, 0x73, 0x5B, 0x5B, 0x1B, 0xE7, 0xCF, 0x9F, 0xC7, 0x68, 0x34, 0x52, 0x56, 0x56, 0xC6, 0x95, 0x2B, 0x57, 0x38, 0x7C, 0xF8, 0x30, 0x5F, 0x7E, 0xF9, 0x25, 0x3A, 0x9D, 0x8E, 0x8A, 0x8A, 0x0A, 0x9A, 0x9A, 0x9A, 0x58, 0xB5, 0x6A, 0x15, 0x2B, 0x57, 0xAE, 0x64, 0xCD, 0x9A, 0x35, 0xD4, 0xD4, 0xD4, 0x60, 0x30, 0x18, 0x78, 0xF2, 0xC9, 0x27, 0xA9, 0xAC, 0xAC, 0xC4, 0xED, 0x76, 0x53, 0x50, 0x50, 0x40, 0x63, 0x63, 0x23, 0x36, 0x9B, 0x8D, 0xBC, 0xBC, 0x3C, 0xAA, 0xAA, 0xAA, 0x00, 0x70, 0x3A, 0x9D, 0x9C, 0x3D, 0x7B, 0x96, 0x0B, 0x17, 0x2E, 0xE0, 0xF3, 0xF9, 0xA4, 0x91, 0xA8, 0x54, 0x2A, 0x6F, 0x6B, 0x2D, 0xB0, 0x64, 0x00, 0x20, 0x1E, 0xB2, 0x78, 0xE0, 0x2E, 0x97, 0x0B, 0x97, 0xCB, 0x45, 0x75, 0x75, 0x35, 0x3B, 0x77, 0xEE, 0xA4, 0xAD, 0xAD, 0x0D, 0x8D, 0x46, 0x83, 0xCB, 0xE5, 0x22, 0x9D, 0x4E, 0x53, 0x54, 0x54, 0xC4, 0xF6, 0xED, 0xDB, 0xB9, 0xFB, 0xEE, 0xBB, 0x51, 0x2A, 0x95, 0x94, 0x94, 0x94, 0x50, 0x5F, 0x5F, 0x4F, 0x5D, 0x5D, 0x1D, 0x65, 0x65, 0x65, 0x98, 0xCD, 0x66, 0xDC, 0x6E, 0x37, 0xE1, 0x70, 0x98, 0x35, 0x6B, 0xD6, 0x50, 0x5C, 0x5C, 0x4C, 0x30, 0x18, 0xA4, 0xA2, 0xA2, 0x82, 0xF6, 0xF6, 0x76, 0xCC, 0x66, 0x33, 0xE3, 0xE3, 0xE3, 0x18, 0x0C, 0x06, 0x12, 0x89, 0x04, 0x57, 0xAF, 0x5E, 0xE5, 0xD2, 0xA5, 0x4B, 0x52, 0xFD, 0xDF, 0x29, 0xA4, 0xD0, 0x92, 0xF4, 0x02, 0x94, 0x4A, 0x25, 0xA9, 0x54, 0x8A, 0x74, 0x3A, 0x4D, 0x28, 0x14, 0xE2, 0xEA, 0xD5, 0xAB, 0x98, 0xCD, 0x66, 0x52, 0xA9, 0x14, 0xC7, 0x8E, 0x1D, 0xE3, 0xCC, 0x99, 0x33, 0x34, 0x34, 0x34, 0xF0, 0xF2, 0xCB, 0x2F, 0xD3, 0xD5, 0xD5, 0x45, 0x32, 0x99, 0x24, 0x1E, 0x8F, 0x13, 0x8D, 0x46, 0x71, 0xBB, 0xDD, 0x9C, 0x3D, 0x7B, 0x96, 0x60, 0x30, 0x48, 0x32, 0x99, 0x44, 0xAF, 0xD7, 0x63, 0xB1, 0x58, 0x28, 0x2D, 0x2D, 0x25, 0x3F, 0x3F, 0x9F, 0xCA, 0xCA, 0x4A, 0xF2, 0xF3, 0xF3, 0xA5, 0xA1, 0x29, 0x96, 0x9D, 0x78, 0x3C, 0x9E, 0x65, 0xE9, 0x0B, 0xFE, 0x41, 0xA8, 0xFF, 0x9C, 0x11, 0x78, 0x93, 0x98, 0xBF, 0x78, 0x3C, 0x9E, 0xA5, 0x72, 0xAD, 0x56, 0x2B, 0x45, 0x45, 0x45, 0x14, 0x14, 0x14, 0xE0, 0x70, 0x38, 0x18, 0x18, 0x18, 0xE0, 0xFC, 0xF9, 0xF3, 0x38, 0x9D, 0x4E, 0x36, 0x6D, 0xDA, 0x44, 0x57, 0x57, 0x17, 0x25, 0x25, 0x25, 0x38, 0x9D, 0x4E, 0x2E, 0x5C, 0xB8, 0xC0, 0x85, 0x0B, 0x17, 0x18, 0x1E, 0x1E, 0xC6, 0xEB, 0xF5, 0xA2, 0x56, 0xAB, 0x29, 0x28, 0x28, 0xA0, 0xA4, 0xA4, 0x84, 0xB2, 0xB2, 0x32, 0xEC, 0x76, 0x3B, 0xC3, 0xC3, 0xC3, 0x98, 0x4C, 0x26, 0x94, 0x4A, 0x25, 0x06, 0x83, 0x81, 0xAA, 0xAA, 0x2A, 0xF2, 0xF3, 0xF3, 0x69, 0x6E, 0x6E, 0xE6, 0xB1, 0xC7, 0x1E, 0x23, 0x16, 0x8B, 0x71, 0xF2, 0xE4, 0x49, 0xC9, 0x03, 0x5C, 0xCF, 0x36, 0xC9, 0x01, 0x60, 0x11, 0x00, 0x30, 0x97, 0x92, 0x55, 0x28, 0x14, 0xAC, 0x5C, 0xB9, 0x92, 0x8D, 0x1B, 0x37, 0x52, 0x52, 0x52, 0x42, 0x6F, 0x6F, 0x2F, 0x06, 0x83, 0x01, 0x80, 0xE9, 0xE9, 0x69, 0xFE, 0xFC, 0xE7, 0x3F, 0x33, 0x3E, 0x3E, 0xCE, 0xDD, 0x77, 0xDF, 0xCD, 0xF8, 0xF8, 0x38, 0xEF, 0xBC, 0xF3, 0x0E, 0x23, 0x23, 0x23, 0x72, 0xF6, 0x0B, 0x9B, 0x42, 0xAF, 0xD7, 0x63, 0x34, 0x1A, 0x31, 0x18, 0x0C, 0x92, 0x4F, 0x28, 0x2E, 0x2E, 0xE6, 0xC1, 0x07, 0x1F, 0x64, 0xEB, 0xD6, 0xAD, 0x14, 0x14, 0x14, 0x60, 0xB7, 0xDB, 0x79, 0xE9, 0xA5, 0x97, 0x30, 0x1A, 0x8D, 0x4C, 0x4E, 0x4E, 0xF2, 0xE5, 0x97, 0x5F, 0x5E, 0xC3, 0x2A, 0x0A, 0xA3, 0x30, 0x07, 0x80, 0x45, 0x98, 0xF9, 0x99, 0xD6, 0x76, 0x51, 0x51, 0x11, 0x55, 0x55, 0x55, 0x74, 0x76, 0x76, 0x72, 0xF7, 0xDD, 0x77, 0x13, 0x0C, 0x06, 0x19, 0x1C, 0x1C, 0xE4, 0xD4, 0xA9, 0x53, 0xCC, 0xCE, 0xCE, 0x92, 0x9F, 0x9F, 0x8F, 0xCF, 0xE7, 0xA3, 0xB7, 0xB7, 0x97, 0x60, 0x30, 0x88, 0xCB, 0xE5, 0x62, 0x7A, 0x7A, 0x9A, 0x23, 0x47, 0x8E, 0x7C, 0xEB, 0xDF, 0xD5, 0x6A, 0xB5, 0x94, 0x96, 0x96, 0x52, 0x56, 0x56, 0x86, 0xCB, 0xE5, 0xA2, 0xBC, 0xBC, 0x1C, 0xBB, 0xDD, 0x4E, 0x67, 0x67, 0x27, 0x4F, 0x3F, 0xFD, 0x34, 0xC7, 0x8F, 0x1F, 0x27, 0x18, 0x0C, 0x32, 0x39, 0x39, 0xC9, 0xF0, 0xF0, 0x30, 0xF1, 0x78, 0x3C, 0x8B, 0x44, 0x9A, 0x8F, 0x81, 0x5C, 0x8E, 0x6E, 0xE3, 0x2D, 0x0F, 0x06, 0xA9, 0xD5, 0xEA, 0x2C, 0x72, 0xC6, 0x62, 0xB1, 0xB0, 0x65, 0xCB, 0x16, 0x5E, 0x7C, 0xF1, 0x45, 0xD6, 0xAF, 0x5F, 0xCF, 0xC4, 0xC4, 0x04, 0x87, 0x0E, 0x1D, 0xE2, 0x93, 0x4F, 0x3E, 0x61, 0x60, 0x60, 0x00, 0x8F, 0xC7, 0x43, 0x20, 0x10, 0x90, 0xDF, 0x2F, 0x29, 0x29, 0xA1, 0xB5, 0xB5, 0x15, 0x9F, 0xCF, 0xC7, 0xF9, 0xF3, 0xE7, 0xBF, 0xF5, 0xEF, 0x5A, 0x2C, 0x16, 0x76, 0xED, 0xDA, 0x45, 0x71, 0x71, 0xB1, 0x24, 0x8A, 0x3A, 0x3A, 0x3A, 0xD8, 0xB0, 0x61, 0x03, 0x55, 0x55, 0x55, 0x52, 0x13, 0xBC, 0xFF, 0xFE, 0xFB, 0xBC, 0xF6, 0xDA, 0x6B, 0x4C, 0x4F, 0x4F, 0xA3, 0x50, 0x28, 0xD0, 0xEB, 0xF5, 0xC4, 0xE3, 0x71, 0xF9, 0xFB, 0x99, 0x0C, 0x65, 0x2A, 0x95, 0x5A, 0x76, 0x8C, 0xA1, 0x0A, 0xF8, 0x7F, 0xB7, 0x6A, 0xE6, 0x67, 0x72, 0xF2, 0x00, 0x36, 0x9B, 0x8D, 0xC7, 0x1E, 0x7B, 0x8C, 0x3D, 0x7B, 0xF6, 0xB0, 0x61, 0xC3, 0x06, 0x02, 0x81, 0x00, 0x9F, 0x7E, 0xFA, 0x29, 0x6F, 0xBC, 0xF1, 0x06, 0xC7, 0x8E, 0x1D, 0x63, 0x66, 0x66, 0x86, 0x48, 0x24, 0x42, 0x2A, 0x95, 0x92, 0xE1, 0x5B, 0x9D, 0x4E, 0x47, 0x2C, 0x16, 0xCB, 0x02, 0x85, 0x52, 0xA9, 0x44, 0xA5, 0x52, 0x49, 0x5A, 0x58, 0xA5, 0x52, 0xA1, 0x56, 0xAB, 0xD1, 0x68, 0x34, 0xF2, 0xBD, 0xC5, 0x62, 0x41, 0xAF, 0xD7, 0x33, 0x3C, 0x3C, 0xCC, 0xF1, 0xE3, 0xC7, 0xE9, 0xE9, 0xE9, 0x61, 0x64, 0x64, 0x84, 0x54, 0x2A, 0x45, 0x49, 0x49, 0x09, 0x8D, 0x8D, 0x8D, 0xB4, 0xB5, 0xB5, 0x51, 0x55, 0x55, 0xC5, 0xEC, 0xEC, 0x2C, 0x0E, 0x87, 0x03, 0xBF, 0xDF, 0x4F, 0x22, 0x91, 0x90, 0xEE, 0x61, 0xE6, 0xF5, 0xCF, 0xD5, 0x0A, 0xCB, 0x49, 0xD2, 0xB7, 0xE2, 0xA5, 0xD1, 0x68, 0xD2, 0x2A, 0x95, 0x4A, 0xFE, 0x6D, 0xB7, 0xDB, 0xD3, 0x7B, 0xF7, 0xEE, 0x4D, 0x9F, 0x3E, 0x7D, 0x3A, 0x9D, 0x4C, 0x26, 0xD3, 0x07, 0x0F, 0x1E, 0x4C, 0x3F, 0xFC, 0xF0, 0xC3, 0xE9, 0xE6, 0xE6, 0xE6, 0xB4, 0x5E, 0xAF, 0x9F, 0xF7, 0x1C, 0x0A, 0x85, 0x22, 0xAD, 0x56, 0xAB, 0xD3, 0x3A, 0x9D, 0x2E, 0xAD, 0xD5, 0x6A, 0xD3, 0x4A, 0xA5, 0x32, 0xAD, 0x50, 0x28, 0xAE, 0xFB, 0x52, 0x2A, 0x95, 0xF2, 0xA5, 0xD3, 0xE9, 0xD2, 0x05, 0x05, 0x05, 0x69, 0xA3, 0xD1, 0x28, 0xCF, 0xA7, 0xD7, 0xEB, 0xD3, 0x65, 0x65, 0x65, 0xE9, 0xAE, 0xAE, 0xAE, 0xF4, 0x8F, 0x7F, 0xFC, 0xE3, 0x74, 0x5F, 0x5F, 0x5F, 0x3A, 0x9D, 0x4E, 0xA7, 0xCF, 0x9F, 0x3F, 0x9F, 0xFE, 0xD9, 0xCF, 0x7E, 0x96, 0x2E, 0x2C, 0x2C, 0xCC, 0xFA, 0xEE, 0xF5, 0xAE, 0x6B, 0x39, 0xBD, 0x16, 0x4D, 0x03, 0x88, 0x19, 0x2E, 0x8C, 0xBB, 0xB9, 0xEA, 0x52, 0x90, 0x3F, 0x4A, 0xA5, 0x92, 0xA2, 0xA2, 0x22, 0x76, 0xEE, 0xDC, 0xC9, 0x53, 0x4F, 0x3D, 0x45, 0x6B, 0x6B, 0x2B, 0x97, 0x2F, 0x5F, 0xE6, 0x6F, 0x7F, 0xFB, 0x1B, 0x6F, 0xBD, 0xF5, 0x16, 0x2E, 0x97, 0x8B, 0x44, 0x22, 0x81, 0xD1, 0x68, 0x9C, 0x77, 0x9D, 0x15, 0x6A, 0x37, 0x93, 0x46, 0xFE, 0x3A, 0xAE, 0x41, 0xBC, 0x92, 0xC9, 0x24, 0x91, 0x48, 0x84, 0x78, 0x3C, 0x2E, 0xC3, 0xC2, 0xA9, 0x54, 0x8A, 0xD9, 0xD9, 0x59, 0x9C, 0x4E, 0x27, 0xE7, 0xCF, 0x9F, 0x97, 0x5E, 0x42, 0x5B, 0x5B, 0x1B, 0x15, 0x15, 0x15, 0x84, 0xC3, 0x61, 0x26, 0x27, 0x27, 0x09, 0x85, 0x42, 0xC4, 0x62, 0x31, 0xA9, 0x71, 0x6A, 0x6A, 0x6A, 0xA8, 0xAC, 0xAC, 0x44, 0xA1, 0x50, 0x10, 0x0C, 0x06, 0xE7, 0xB5, 0x0D, 0xEE, 0x98, 0x25, 0x20, 0x33, 0x22, 0xA7, 0x52, 0xA9, 0xA4, 0x2A, 0x16, 0xEF, 0xB5, 0x5A, 0x6D, 0xD6, 0x60, 0xD8, 0xED, 0x76, 0xB6, 0x6E, 0xDD, 0xCA, 0x8F, 0x7E, 0xF4, 0x23, 0xD6, 0xAD, 0x5B, 0xC7, 0x89, 0x13, 0x27, 0xF8, 0xDD, 0xEF, 0x7E, 0xC7, 0xF1, 0xE3, 0xC7, 0xF1, 0xFB, 0xFD, 0x59, 0x4C, 0xE1, 0x62, 0x59, 0xE0, 0x42, 0x8D, 0xCF, 0x5D, 0xBF, 0x47, 0x46, 0x46, 0x18, 0x1E, 0x1E, 0xA6, 0xAD, 0xAD, 0x8D, 0x55, 0xAB, 0x56, 0xD1, 0xD2, 0xD2, 0x42, 0x34, 0x1A, 0x65, 0x74, 0x74, 0x54, 0xC6, 0x16, 0x2C, 0x16, 0x0B, 0x7B, 0xF6, 0xEC, 0x61, 0xDB, 0xB6, 0x6D, 0x04, 0x83, 0x41, 0x06, 0x06, 0x06, 0xE4, 0x32, 0xB4, 0x1C, 0x58, 0x44, 0xF5, 0x62, 0x3C, 0x4C, 0x71, 0xD3, 0xF3, 0x19, 0x44, 0xB1, 0x58, 0x2C, 0xCB, 0x10, 0xBB, 0xEF, 0xBE, 0xFB, 0xD8, 0xB3, 0x67, 0x0F, 0x9B, 0x37, 0x6F, 0x06, 0xE0, 0xB3, 0xCF, 0x3E, 0xE3, 0xD0, 0xA1, 0x43, 0x92, 0x8D, 0xD3, 0xEB, 0xF5, 0x84, 0x42, 0xA1, 0xEB, 0x1A, 0x57, 0x99, 0xB6, 0xC4, 0x77, 0x79, 0xD8, 0x99, 0x99, 0xBF, 0xE2, 0x38, 0xE1, 0xEE, 0xE9, 0x74, 0x3A, 0xC2, 0xE1, 0x30, 0x63, 0x63, 0x63, 0xBC, 0xF9, 0xE6, 0x9B, 0xD8, 0x6C, 0x36, 0x7E, 0xF8, 0xC3, 0x1F, 0xD2, 0xD9, 0xD9, 0xC9, 0xB3, 0xCF, 0x3E, 0x8B, 0xC7, 0xE3, 0xE1, 0xE3, 0x8F, 0x3F, 0x46, 0xA7, 0xD3, 0xD1, 0xD4, 0xD4, 0x44, 0x67, 0x67, 0x27, 0x06, 0x83, 0x41, 0x82, 0x7B, 0x39, 0x69, 0x80, 0x5B, 0xE6, 0x06, 0xAA, 0xD5, 0x6A, 0xD6, 0xAD, 0x5B, 0xC7, 0xAE, 0x5D, 0xBB, 0x78, 0xF0, 0xC1, 0x07, 0x01, 0x08, 0x87, 0xC3, 0x59, 0x11, 0xBF, 0x78, 0x3C, 0x2E, 0x63, 0x03, 0xDF, 0x06, 0x70, 0xDF, 0x87, 0x7A, 0x9E, 0xFB, 0x5E, 0x18, 0x79, 0x02, 0x70, 0xE9, 0x74, 0x9A, 0xBF, 0xFE, 0xF5, 0xAF, 0x5C, 0xB8, 0x70, 0x81, 0xDF, 0xFF, 0xFE, 0xF7, 0xAC, 0x5A, 0xB5, 0x8A, 0xDD, 0xBB, 0x77, 0x53, 0x5C, 0x5C, 0x4C, 0x55, 0x55, 0x15, 0x76, 0xBB, 0x1D, 0xAF, 0xD7, 0xCB, 0xA7, 0x9F, 0x7E, 0xCA, 0xA5, 0x4B, 0x97, 0x6E, 0xF8, 0xBA, 0x96, 0x1D, 0x00, 0x32, 0x19, 0x32, 0x61, 0x99, 0x1B, 0x8D, 0x46, 0x4C, 0x26, 0x13, 0x66, 0xB3, 0x59, 0xAE, 0xDD, 0x91, 0x48, 0x84, 0x60, 0x30, 0x88, 0x4A, 0xA5, 0xC2, 0x64, 0x32, 0xD1, 0xD8, 0xD8, 0xC8, 0x3D, 0xF7, 0xDC, 0x43, 0x5D, 0x5D, 0x1D, 0x6E, 0xB7, 0x9B, 0xA9, 0xA9, 0x29, 0xFC, 0x7E, 0x3F, 0x55, 0x55, 0x55, 0xAC, 0x5B, 0xB7, 0x0E, 0xA7, 0xD3, 0x89, 0xD3, 0xE9, 0x94, 0xCC, 0xE0, 0x62, 0x30, 0x71, 0xF3, 0x9D, 0x4F, 0xD8, 0x07, 0x4A, 0xA5, 0x92, 0xBC, 0xBC, 0x3C, 0xF9, 0x3E, 0x1C, 0x0E, 0x13, 0x8B, 0xC5, 0x50, 0x28, 0x14, 0x44, 0x22, 0x11, 0xE0, 0xAB, 0x90, 0x73, 0x79, 0x79, 0x39, 0x6F, 0xBF, 0xFD, 0x36, 0x07, 0x0E, 0x1C, 0x60, 0x74, 0x74, 0x34, 0x6B, 0xD6, 0x2F, 0x07, 0xD2, 0x68, 0xC1, 0x01, 0x90, 0x9F, 0x9F, 0x4F, 0x7D, 0x7D, 0x3D, 0x6D, 0x6D, 0x6D, 0xB4, 0xB6, 0xB6, 0xD2, 0xD0, 0xD0, 0x80, 0x46, 0xA3, 0x61, 0x72, 0x72, 0x12, 0xB7, 0xDB, 0x8D, 0xC9, 0x64, 0xA2, 0xA2, 0xA2, 0x02, 0xBB, 0xDD, 0x4E, 0x3A, 0x9D, 0x66, 0x70, 0x70, 0x90, 0x13, 0x27, 0x4E, 0x00, 0x50, 0x56, 0x56, 0x46, 0x5D, 0x5D, 0x1D, 0xCF, 0x3C, 0xF3, 0x0C, 0x9F, 0x7C, 0xF2, 0x09, 0x53, 0x53, 0x53, 0xD2, 0xD0, 0x52, 0xA9, 0x54, 0xDF, 0x2A, 0x21, 0x64, 0x21, 0xEE, 0x47, 0xE4, 0x26, 0x84, 0xC3, 0x61, 0xAC, 0x56, 0x2B, 0x3B, 0x77, 0xEE, 0xE4, 0x91, 0x47, 0x1E, 0x61, 0xE5, 0xCA, 0x95, 0xF4, 0xF6, 0xF6, 0xB2, 0x7F, 0xFF, 0x7E, 0xFA, 0xFA, 0xFA, 0xB0, 0x5A, 0xAD, 0x00, 0x5C, 0xBD, 0x7A, 0x95, 0xF1, 0xF1, 0x71, 0x09, 0x96, 0xE5, 0x14, 0x3B, 0x50, 0x2F, 0xC6, 0x03, 0x9C, 0x2B, 0xC5, 0xC5, 0xC5, 0x34, 0x35, 0x35, 0x61, 0x36, 0x9B, 0x51, 0x2A, 0x95, 0x44, 0x22, 0x11, 0x26, 0x26, 0x26, 0xF8, 0xE2, 0x8B, 0x2F, 0x38, 0x76, 0xEC, 0x18, 0xDD, 0xDD, 0xDD, 0xE8, 0x74, 0x3A, 0x1A, 0x1A, 0x1A, 0x68, 0x69, 0x69, 0xC9, 0x52, 0x9F, 0xB7, 0x42, 0x8D, 0x0A, 0x50, 0x8B, 0x01, 0x2D, 0x2C, 0x2C, 0xC4, 0x60, 0x30, 0x70, 0xE6, 0xCC, 0x19, 0xCE, 0x9D, 0x3B, 0x87, 0xDF, 0xEF, 0x67, 0xC5, 0x8A, 0x15, 0x98, 0xCD, 0x66, 0x26, 0x26, 0x26, 0x98, 0x9A, 0x9A, 0x22, 0x1E, 0x8F, 0x2F, 0xCB, 0x8A, 0xA2, 0x1B, 0x66, 0x02, 0xE7, 0x6A, 0x00, 0xAD, 0x56, 0x4B, 0x5E, 0x5E, 0x1E, 0x66, 0xB3, 0x19, 0x93, 0xC9, 0x84, 0xD1, 0x68, 0x64, 0xCD, 0x9A, 0x35, 0xBC, 0xF4, 0xD2, 0x4B, 0x6C, 0xDA, 0xB4, 0x09, 0x80, 0x8F, 0x3F, 0xFE, 0x98, 0x77, 0xDE, 0x79, 0x87, 0x8F, 0x3E, 0xFA, 0x08, 0x8F, 0xC7, 0x83, 0xD7, 0xEB, 0x45, 0xAB, 0xD5, 0xA2, 0xD3, 0xE9, 0x28, 0x28, 0x28, 0x40, 0xA5, 0x52, 0xE1, 0xF1, 0x78, 0x70, 0xB9, 0x5C, 0x72, 0x26, 0xDD, 0xCC, 0x60, 0x4C, 0xE6, 0x6F, 0xE9, 0x74, 0x3A, 0x6A, 0x6B, 0x6B, 0x31, 0x9B, 0xCD, 0x24, 0x93, 0x49, 0x54, 0x2A, 0x15, 0x8F, 0x3D, 0xF6, 0x18, 0x8F, 0x3F, 0xFE, 0x38, 0x56, 0xAB, 0x95, 0xE3, 0xC7, 0x8F, 0xF3, 0xC7, 0x3F, 0xFE, 0x91, 0x8F, 0x3F, 0xFE, 0x58, 0x6A, 0x2A, 0x85, 0x42, 0x71, 0x53, 0xB4, 0xD5, 0x92, 0xD0, 0x00, 0x73, 0x8D, 0xA9, 0x68, 0x34, 0x4A, 0x34, 0x1A, 0x65, 0x66, 0x66, 0x46, 0x7E, 0x3E, 0x30, 0x30, 0x40, 0x69, 0x69, 0xA9, 0xE4, 0xDB, 0x43, 0xA1, 0x10, 0x97, 0x2F, 0x5F, 0xCE, 0x32, 0x9A, 0xC4, 0xBA, 0x3A, 0x3D, 0x3D, 0xFD, 0xAD, 0xD7, 0xEB, 0x45, 0x63, 0xC6, 0x32, 0x7E, 0x2B, 0x1A, 0x8D, 0x66, 0x05, 0x86, 0xB4, 0x5A, 0x2D, 0x9B, 0x37, 0x6F, 0x46, 0xA9, 0x54, 0x52, 0x59, 0x59, 0x49, 0x4D, 0x4D, 0x8D, 0x0C, 0x2F, 0x2F, 0x27, 0xEB, 0xFF, 0xA6, 0x52, 0xC1, 0x91, 0x48, 0x84, 0x40, 0x20, 0x40, 0x32, 0x99, 0xA4, 0xBA, 0xBA, 0x9A, 0xCA, 0xCA, 0x4A, 0x26, 0x26, 0x26, 0x38, 0x79, 0xF2, 0xE4, 0xB2, 0xE3, 0xCE, 0x93, 0xC9, 0x24, 0x4E, 0xA7, 0x93, 0x2B, 0x57, 0xAE, 0xD0, 0xD6, 0xD6, 0x46, 0x59, 0x59, 0x19, 0xA7, 0x4E, 0x9D, 0xE2, 0xDC, 0xB9, 0x73, 0x59, 0x1A, 0x60, 0xB9, 0xD8, 0x00, 0x0B, 0x9E, 0xF2, 0x22, 0x88, 0x20, 0x8D, 0x46, 0x83, 0x46, 0xA3, 0x91, 0xBE, 0xF1, 0xB9, 0x73, 0xE7, 0xD8, 0xB7, 0x6F, 0x1F, 0xC3, 0xC3, 0xC3, 0x54, 0x56, 0x56, 0xD2, 0xD4, 0xD4, 0x84, 0xD5, 0x6A, 0x45, 0xAD, 0x56, 0x4B, 0x82, 0x48, 0xAD, 0x56, 0xCB, 0x7F, 0x97, 0x4A, 0x36, 0x8E, 0x30, 0x0A, 0x75, 0x3A, 0x1D, 0x16, 0x8B, 0x05, 0xA5, 0x52, 0xC9, 0xD5, 0xAB, 0x57, 0xD9, 0xB7, 0x6F, 0x1F, 0x5F, 0x7E, 0xF9, 0x25, 0x46, 0xA3, 0x91, 0x92, 0x92, 0x12, 0x74, 0x3A, 0xDD, 0xB2, 0x72, 0xFF, 0x16, 0x0D, 0x00, 0x99, 0xAC, 0x5A, 0x22, 0x91, 0xC8, 0x9A, 0xE1, 0xD3, 0xD3, 0xD3, 0x04, 0x83, 0x41, 0x52, 0xA9, 0x14, 0xC1, 0x60, 0x90, 0x99, 0x99, 0x99, 0x2C, 0x86, 0x4F, 0x64, 0xF6, 0x7C, 0x1B, 0x5A, 0xF7, 0x66, 0x2E, 0x07, 0xE2, 0x5E, 0x62, 0xB1, 0x98, 0xBC, 0x56, 0xBD, 0x5E, 0x8F, 0xC7, 0xE3, 0xC1, 0xED, 0x76, 0xCB, 0x74, 0x34, 0x9D, 0x4E, 0x27, 0xEF, 0x7D, 0xB9, 0x18, 0x84, 0xCA, 0xC5, 0x7E, 0x78, 0xE9, 0x74, 0x1A, 0xA5, 0x52, 0x89, 0xC5, 0x62, 0xA1, 0xBE, 0xBE, 0x9E, 0xFC, 0xFC, 0x7C, 0x02, 0x81, 0x00, 0x1E, 0x8F, 0x87, 0x68, 0x34, 0x7A, 0x8D, 0xC5, 0x3F, 0x5F, 0xC1, 0xC7, 0x52, 0x10, 0x51, 0x48, 0x22, 0xD8, 0xC2, 0xFC, 0xFC, 0x7C, 0xA6, 0xA7, 0xA7, 0x71, 0x3A, 0x9D, 0xD8, 0xED, 0x76, 0x56, 0xAF, 0x5E, 0x4D, 0x71, 0x71, 0x71, 0xD6, 0xB5, 0x2F, 0x87, 0x9C, 0xC2, 0x45, 0xBB, 0x42, 0x71, 0xF3, 0x02, 0x00, 0xCD, 0xCD, 0xCD, 0x6C, 0xDD, 0xBA, 0x95, 0x8A, 0x8A, 0x0A, 0xDC, 0x6E, 0x37, 0x6E, 0xB7, 0x7B, 0x59, 0xAD, 0xFD, 0x73, 0x03, 0x49, 0xA1, 0x50, 0x88, 0xA1, 0xA1, 0x21, 0xA6, 0xA6, 0xA6, 0x28, 0x2F, 0x2F, 0xE7, 0xAE, 0xBB, 0xEE, 0xA2, 0xA6, 0xA6, 0x26, 0x2B, 0xF0, 0x75, 0x47, 0x2E, 0x01, 0xF3, 0x01, 0x40, 0xA5, 0x52, 0xB1, 0x7E, 0xFD, 0x7A, 0x76, 0xEF, 0xDE, 0x4D, 0x41, 0x41, 0x01, 0x17, 0x2F, 0x5E, 0x64, 0x70, 0x70, 0x70, 0xD9, 0xB1, 0x66, 0x99, 0x60, 0x88, 0x44, 0x22, 0x0C, 0x0C, 0x0C, 0x30, 0x34, 0x34, 0x44, 0x7E, 0x7E, 0x3E, 0x2D, 0x2D, 0x2D, 0x14, 0x15, 0x15, 0xC9, 0xFB, 0x10, 0x01, 0xB0, 0xA5, 0x0E, 0x84, 0x45, 0x03, 0x40, 0xE6, 0x8D, 0xAB, 0x54, 0x2A, 0x9A, 0x9A, 0x9A, 0x68, 0x6B, 0x6B, 0x23, 0x12, 0x89, 0x70, 0xFA, 0xF4, 0x69, 0xFA, 0xFB, 0xFB, 0xAF, 0xCB, 0xC7, 0x2F, 0xE5, 0x81, 0x17, 0xF7, 0x96, 0x4C, 0x26, 0x19, 0x1B, 0x1B, 0x63, 0x64, 0x64, 0x04, 0x95, 0x4A, 0x45, 0x59, 0x59, 0x99, 0xA4, 0xBD, 0xE7, 0x1A, 0xB3, 0x4B, 0x19, 0x04, 0xEA, 0x9B, 0xF1, 0xB0, 0x04, 0x31, 0xE2, 0xF3, 0xF9, 0x98, 0x9A, 0x9A, 0x62, 0x6A, 0x6A, 0x8A, 0x40, 0x20, 0xC0, 0x72, 0x15, 0xC1, 0x77, 0xCC, 0xCE, 0xCE, 0x92, 0x48, 0x24, 0x28, 0x2E, 0x2E, 0xA6, 0xA8, 0xA8, 0x88, 0xE6, 0xE6, 0x66, 0xCC, 0x66, 0xB3, 0xCC, 0x1C, 0xBA, 0xA3, 0x97, 0x80, 0xB9, 0x00, 0x18, 0x1D, 0x1D, 0xE5, 0xE2, 0xC5, 0x8B, 0x4C, 0x4D, 0x4D, 0xA1, 0xD3, 0xE9, 0xC8, 0xCB, 0xCB, 0x5B, 0x76, 0x03, 0x3F, 0x77, 0x26, 0x9B, 0x4C, 0x26, 0xEC, 0x76, 0x3B, 0x45, 0x45, 0x45, 0xE8, 0x74, 0x3A, 0x56, 0xAF, 0x5E, 0x4D, 0x4B, 0x4B, 0xCB, 0xB2, 0xBA, 0x27, 0xF5, 0x62, 0x3D, 0x28, 0xA1, 0xFA, 0x52, 0xA9, 0x14, 0x81, 0x40, 0x00, 0xAF, 0xD7, 0x9B, 0x95, 0xB7, 0xB7, 0x9C, 0xD8, 0xB2, 0xCC, 0x7C, 0x03, 0x85, 0x42, 0x41, 0x5E, 0x5E, 0x1E, 0x95, 0x95, 0x95, 0x6C, 0xDB, 0xB6, 0x8D, 0xC6, 0xC6, 0x46, 0x59, 0xB8, 0xDA, 0xDF, 0xDF, 0xCF, 0x8A, 0x15, 0x2B, 0xD0, 0x6A, 0xB5, 0x84, 0x42, 0x21, 0xC2, 0xE1, 0x30, 0x33, 0x33, 0x33, 0xCC, 0xCE, 0xCE, 0x5E, 0x53, 0x67, 0x70, 0xDB, 0x02, 0x40, 0x10, 0x27, 0x82, 0x00, 0x12, 0x75, 0xFA, 0x25, 0x25, 0x25, 0xD4, 0xD5, 0xD5, 0x31, 0x36, 0x36, 0x26, 0x1F, 0xCA, 0x7C, 0x1A, 0x63, 0x49, 0xAA, 0xC9, 0xFF, 0xAB, 0x57, 0x48, 0x26, 0x93, 0xA8, 0xD5, 0x6A, 0xCA, 0xCA, 0xCA, 0xD8, 0xB2, 0x65, 0x0B, 0xCF, 0x3F, 0xFF, 0x3C, 0x6A, 0xB5, 0x9A, 0xD7, 0x5E, 0x7B, 0x8D, 0x43, 0x87, 0x0E, 0x61, 0x34, 0x1A, 0x79, 0xE8, 0xA1, 0x87, 0x78, 0xF8, 0xE1, 0x87, 0x31, 0x9B, 0xCD, 0x5C, 0xB9, 0x72, 0x85, 0x23, 0x47, 0x8E, 0x70, 0xE6, 0xCC, 0x99, 0xAC, 0x86, 0x13, 0x4B, 0x89, 0x29, 0x5C, 0x94, 0x8C, 0xA0, 0x44, 0x22, 0x21, 0xD3, 0xB9, 0xD4, 0x6A, 0x35, 0x75, 0x75, 0x75, 0x74, 0x74, 0x74, 0x50, 0x53, 0x53, 0x83, 0xCF, 0xE7, 0x5B, 0xB6, 0x05, 0x97, 0x99, 0x5A, 0x4B, 0x54, 0x16, 0xC5, 0xE3, 0x71, 0x1C, 0x0E, 0x07, 0xC3, 0xC3, 0xC3, 0xB4, 0xB7, 0xB7, 0xD3, 0xD8, 0xD8, 0xC8, 0xEA, 0xD5, 0xAB, 0x51, 0xAB, 0xD5, 0x04, 0x83, 0x41, 0x8C, 0x46, 0x63, 0x56, 0x73, 0x8A, 0xDB, 0x56, 0x03, 0x5C, 0x2F, 0x5A, 0x57, 0x53, 0x53, 0xC3, 0x13, 0x4F, 0x3C, 0x21, 0xF3, 0xE9, 0x92, 0xC9, 0x24, 0x56, 0xAB, 0x95, 0xFC, 0xFC, 0x7C, 0x9C, 0x4E, 0x67, 0x56, 0xB4, 0x6F, 0xA9, 0x8A, 0xB8, 0x46, 0x91, 0x27, 0xE0, 0x74, 0x3A, 0xF9, 0xDF, 0xFF, 0xFE, 0x47, 0x79, 0x79, 0x39, 0x2D, 0x2D, 0x2D, 0xDC, 0x75, 0xD7, 0x5D, 0x54, 0x54, 0x54, 0x50, 0x57, 0x57, 0x47, 0x45, 0x45, 0x05, 0xFD, 0xFD, 0xFD, 0x0C, 0x0F, 0x0F, 0xD3, 0xDD, 0xDD, 0x4D, 0x7F, 0x7F, 0x7F, 0x56, 0x6E, 0xE3, 0x52, 0x03, 0xFE, 0x82, 0x25, 0x84, 0x88, 0x1B, 0xB3, 0x5A, 0xAD, 0x14, 0x16, 0x16, 0x52, 0x5C, 0x5C, 0x4C, 0x61, 0x61, 0x21, 0x0F, 0x3C, 0xF0, 0x00, 0x1B, 0x37, 0x6E, 0x24, 0x10, 0x08, 0xF0, 0xEF, 0x7F, 0xFF, 0x9B, 0xD1, 0xD1, 0x51, 0x3C, 0x1E, 0x8F, 0x4C, 0xBD, 0x5A, 0x2E, 0x56, 0x7F, 0xE6, 0xBD, 0x06, 0x83, 0x41, 0x2E, 0x5E, 0xBC, 0xC8, 0xC1, 0x83, 0x07, 0x31, 0x18, 0x0C, 0xDC, 0x7F, 0xFF, 0xFD, 0x18, 0x0C, 0x06, 0xC6, 0xC7, 0xC7, 0xB9, 0x70, 0xE1, 0x02, 0xFD, 0xFD, 0xFD, 0xF4, 0xF7, 0xF7, 0xE3, 0x74, 0x3A, 0xF1, 0x7A, 0xBD, 0x59, 0x99, 0xC2, 0xB7, 0x9D, 0x06, 0x98, 0x9B, 0xA9, 0x53, 0x5D, 0x5D, 0xCD, 0xB6, 0x6D, 0xDB, 0xD8, 0xBA, 0x75, 0x2B, 0xAD, 0xAD, 0xAD, 0x14, 0x16, 0x16, 0x32, 0x3E, 0x3E, 0xCE, 0xBB, 0xEF, 0xBE, 0xCB, 0xE1, 0xC3, 0x87, 0x09, 0x87, 0xC3, 0xA8, 0x54, 0xAA, 0x25, 0x6B, 0x14, 0x7D, 0x1B, 0x20, 0x08, 0x30, 0xCC, 0xCC, 0xCC, 0x10, 0x0C, 0x06, 0x29, 0x2B, 0x2B, 0x43, 0xA5, 0x52, 0xF1, 0xDE, 0x7B, 0xEF, 0xF1, 0xE6, 0x9B, 0x6F, 0xE2, 0xF3, 0xF9, 0x08, 0x87, 0xC3, 0xB2, 0x62, 0x79, 0x2E, 0xD0, 0x97, 0x92, 0x16, 0x58, 0x90, 0x25, 0x40, 0xE4, 0x02, 0x1A, 0x0C, 0x06, 0xCC, 0x66, 0x33, 0x06, 0x83, 0x01, 0x9D, 0x4E, 0x47, 0x32, 0x99, 0x64, 0x78, 0x78, 0x98, 0x13, 0x27, 0x4E, 0x30, 0x31, 0x31, 0x41, 0x79, 0x79, 0x39, 0xF0, 0x55, 0xD0, 0x27, 0x16, 0x8B, 0x11, 0x0A, 0x85, 0xF0, 0xFB, 0xFD, 0xC4, 0xE3, 0xF1, 0x5B, 0x92, 0xF8, 0x71, 0x23, 0x46, 0xA1, 0xD9, 0x6C, 0x96, 0xF9, 0x0D, 0x4A, 0xA5, 0x92, 0xB1, 0xB1, 0x31, 0x4E, 0x9E, 0x3C, 0x29, 0x7B, 0x0B, 0x89, 0xEF, 0x2D, 0x75, 0x2D, 0xA7, 0xBE, 0x91, 0x41, 0xCF, 0x4C, 0x9B, 0xB2, 0x58, 0x2C, 0xB2, 0x68, 0xF3, 0xD0, 0xA1, 0x43, 0x9C, 0x38, 0x71, 0x82, 0x74, 0x3A, 0x2D, 0xCB, 0xB6, 0x76, 0xEE, 0xDC, 0xC9, 0xCF, 0x7F, 0xFE, 0x73, 0xCC, 0x66, 0x33, 0x97, 0x2F, 0x5F, 0xE6, 0xB3, 0xCF, 0x3E, 0x43, 0xAD, 0x56, 0xD3, 0xDD, 0xDD, 0x8D, 0xD7, 0xEB, 0xBD, 0x46, 0xCD, 0x2E, 0x45, 0x03, 0x50, 0xB8, 0xB6, 0x4A, 0xA5, 0x12, 0x93, 0xC9, 0xC4, 0xBA, 0x75, 0xEB, 0xE8, 0xE8, 0xE8, 0xC0, 0xE5, 0x72, 0xF1, 0xC9, 0x27, 0x9F, 0x30, 0x3A, 0x3A, 0x3A, 0xAF, 0xED, 0x70, 0x5B, 0xF3, 0x00, 0x73, 0xAB, 0x74, 0x04, 0xD3, 0x37, 0xF7, 0xE6, 0xDB, 0xDB, 0xDB, 0x49, 0x24, 0x12, 0x34, 0x35, 0x35, 0x51, 0x5A, 0x5A, 0xCA, 0xC8, 0xC8, 0x08, 0x81, 0x40, 0x40, 0x56, 0xDD, 0x2E, 0x97, 0x99, 0x2F, 0xBC, 0x9C, 0x60, 0x30, 0x48, 0x63, 0x63, 0x23, 0x0D, 0x0D, 0x0D, 0x1C, 0x38, 0x70, 0x40, 0x36, 0x97, 0xD2, 0x6A, 0xB5, 0x59, 0x81, 0xA3, 0xA5, 0x5E, 0x33, 0xA8, 0x5E, 0xA8, 0x81, 0x9F, 0x9D, 0x9D, 0x25, 0x18, 0x0C, 0x5E, 0xD7, 0xB8, 0x3B, 0x74, 0xE8, 0x10, 0xC3, 0xC3, 0xC3, 0xFC, 0xF6, 0xB7, 0xBF, 0x65, 0xC3, 0x86, 0x0D, 0xC4, 0x62, 0x31, 0x7A, 0x7A, 0x7A, 0x24, 0x00, 0xD4, 0x6A, 0x75, 0xD6, 0x52, 0xB0, 0x14, 0x35, 0x80, 0xA8, 0x72, 0x4A, 0xA5, 0x52, 0x44, 0xA3, 0x51, 0x0C, 0x06, 0x03, 0xE9, 0x74, 0x9A, 0xDE, 0xDE, 0x5E, 0xCE, 0x9E, 0x3D, 0x4B, 0x28, 0x14, 0xCA, 0x2A, 0x7B, 0x5B, 0xEA, 0xFC, 0xC6, 0x82, 0xD9, 0x00, 0x42, 0xD5, 0x8B, 0xAA, 0x1F, 0xF1, 0xB0, 0x44, 0x95, 0x4D, 0x28, 0x14, 0x92, 0x79, 0xFE, 0xE7, 0xCF, 0x9F, 0xE7, 0x9E, 0x7B, 0xEE, 0xA1, 0xA8, 0xA8, 0x48, 0x3E, 0x40, 0x11, 0x67, 0x5F, 0xCA, 0x33, 0x3F, 0x95, 0x4A, 0x11, 0x0A, 0x85, 0x48, 0xA7, 0xD3, 0x94, 0x96, 0x96, 0xD2, 0xD5, 0xD5, 0x45, 0x6D, 0x6D, 0x2D, 0x7E, 0xBF, 0x9F, 0x91, 0x91, 0x91, 0x2C, 0xDE, 0x63, 0x39, 0x0C, 0xBC, 0xBC, 0xB7, 0xC5, 0xB2, 0x96, 0x85, 0xA1, 0x97, 0x59, 0x44, 0x09, 0x5F, 0x95, 0x86, 0x25, 0x93, 0x49, 0x3A, 0x3A, 0x3A, 0x78, 0xEA, 0xA9, 0xA7, 0xA8, 0xAB, 0xAB, 0x93, 0x85, 0x99, 0xC2, 0xAB, 0x58, 0x8A, 0x33, 0x5F, 0xDC, 0x97, 0x56, 0xAB, 0x65, 0xE7, 0xCE, 0x9D, 0xFC, 0xF2, 0x97, 0xBF, 0xA4, 0xAE, 0xAE, 0x8E, 0xE1, 0xE1, 0xE1, 0xEB, 0x26, 0xB2, 0xDE, 0x51, 0x00, 0xC8, 0xAC, 0x06, 0xCE, 0xAC, 0x9B, 0x17, 0xED, 0x58, 0x55, 0x2A, 0x15, 0x46, 0xA3, 0x91, 0xFE, 0xFE, 0x7E, 0x4E, 0x9F, 0x3E, 0x4D, 0x49, 0x49, 0x09, 0xCF, 0x3D, 0xF7, 0x1C, 0x2B, 0x57, 0xAE, 0x94, 0x20, 0xC9, 0x7C, 0xD8, 0x4B, 0x89, 0xF9, 0x13, 0xD7, 0x65, 0x36, 0x9B, 0xE9, 0xE8, 0xE8, 0x60, 0xDB, 0xB6, 0x6D, 0xAC, 0x5D, 0xBB, 0x96, 0x81, 0x81, 0x01, 0xF6, 0xEF, 0xDF, 0xCF, 0xF8, 0xF8, 0x78, 0x56, 0x53, 0xA9, 0xE5, 0x94, 0xDB, 0xB0, 0xE8, 0x59, 0xC1, 0x99, 0x44, 0x91, 0x30, 0x12, 0x23, 0x91, 0x08, 0xAD, 0xAD, 0xAD, 0xAC, 0x5C, 0xB9, 0x92, 0x81, 0x81, 0x01, 0x8E, 0x1D, 0x3B, 0x06, 0x20, 0x13, 0x49, 0x85, 0x5D, 0x30, 0x17, 0x58, 0x8B, 0x79, 0x8D, 0x73, 0xCF, 0x2F, 0xAC, 0x7D, 0x11, 0x00, 0x32, 0x99, 0x4C, 0xAC, 0x59, 0xB3, 0x86, 0x1D, 0x3B, 0x76, 0xB0, 0x76, 0xED, 0x5A, 0x26, 0x26, 0x26, 0x78, 0xFD, 0xF5, 0xD7, 0xD9, 0xB7, 0x6F, 0x1F, 0xE3, 0xE3, 0xE3, 0x12, 0xC0, 0xCB, 0x8D, 0xE2, 0x5E, 0xF4, 0xA4, 0xB5, 0xCC, 0x0C, 0x19, 0xD1, 0xB7, 0xF7, 0xF0, 0xE1, 0xC3, 0x0C, 0x0E, 0x0E, 0x62, 0xB3, 0xD9, 0xB8, 0xF7, 0xDE, 0x7B, 0xA9, 0xAF, 0xAF, 0x47, 0xAB, 0xD5, 0x12, 0x8F, 0xC7, 0x89, 0x44, 0x22, 0x59, 0x06, 0xD7, 0xCD, 0xC8, 0x11, 0xCC, 0x3C, 0x7F, 0x26, 0xE0, 0xD4, 0x6A, 0xB5, 0xB4, 0x51, 0xD2, 0xE9, 0x34, 0x1D, 0x1D, 0x1D, 0xAC, 0x5B, 0xB7, 0x0E, 0x87, 0xC3, 0xC1, 0x5B, 0x6F, 0xBD, 0xC5, 0x87, 0x1F, 0x7E, 0x28, 0x9B, 0x52, 0xCD, 0x77, 0xAE, 0x1C, 0x00, 0x32, 0x8C, 0xA1, 0x4C, 0xD5, 0x3E, 0x3A, 0x3A, 0x4A, 0x5F, 0x5F, 0x1F, 0x91, 0x48, 0x84, 0x0D, 0x1B, 0x36, 0xF0, 0xF2, 0xCB, 0x2F, 0xD3, 0xD8, 0xD8, 0x28, 0x01, 0x23, 0x3A, 0x7B, 0x7D, 0x5D, 0xAF, 0xFF, 0x45, 0x51, 0x87, 0xFF, 0x67, 0xB8, 0x8A, 0xDA, 0x7E, 0x8D, 0x46, 0x23, 0x8D, 0x3A, 0xAD, 0x56, 0x4B, 0x73, 0x73, 0x33, 0x85, 0x85, 0x85, 0x7C, 0xF6, 0xD9, 0x67, 0x7C, 0xF0, 0xC1, 0x07, 0x4C, 0x4E, 0x4E, 0x66, 0x01, 0x7D, 0x39, 0x76, 0x10, 0xBB, 0x69, 0x3D, 0x82, 0x44, 0x77, 0x2D, 0x8D, 0x46, 0x43, 0x22, 0x91, 0x90, 0xBD, 0x7D, 0xAA, 0xAB, 0xAB, 0xE9, 0xE8, 0xE8, 0x40, 0xAF, 0xD7, 0xE3, 0x70, 0x38, 0x08, 0x06, 0x83, 0xB2, 0x73, 0x87, 0x70, 0xA5, 0xC4, 0x40, 0x2C, 0xC6, 0x03, 0x16, 0x03, 0x2D, 0x5C, 0x37, 0xE1, 0xB7, 0x8B, 0xBD, 0x04, 0x52, 0xA9, 0x14, 0x7A, 0xBD, 0x9E, 0xCE, 0xCE, 0x4E, 0x5E, 0x7C, 0xF1, 0x45, 0x4C, 0x26, 0x13, 0xFF, 0xF8, 0xC7, 0x3F, 0x38, 0x77, 0xEE, 0x1C, 0xA9, 0x54, 0x0A, 0x83, 0xC1, 0x70, 0x4D, 0x7B, 0xBB, 0x1C, 0x00, 0xBE, 0x46, 0x1B, 0x88, 0x7E, 0x7B, 0x53, 0x53, 0x53, 0x7C, 0xF1, 0xC5, 0x17, 0xD4, 0xD6, 0xD6, 0xF2, 0xC0, 0x03, 0x0F, 0xB0, 0x7A, 0xF5, 0x6A, 0x54, 0x2A, 0x15, 0x0E, 0x87, 0x03, 0x87, 0xC3, 0x21, 0x8F, 0xC9, 0xCB, 0xCB, 0xA3, 0xB4, 0xB4, 0x54, 0xBA, 0x93, 0x99, 0xAA, 0xFA, 0x46, 0x8D, 0x3B, 0x01, 0x2E, 0x51, 0x8F, 0x38, 0x77, 0x8F, 0x01, 0x21, 0xAD, 0xAD, 0xAD, 0x3C, 0xFD, 0xF4, 0xD3, 0xEC, 0xD8, 0xB1, 0x83, 0x58, 0x2C, 0xC6, 0x81, 0x03, 0x07, 0x64, 0x27, 0x10, 0xD1, 0xB7, 0x70, 0xBE, 0x14, 0xB0, 0xCC, 0xF6, 0x38, 0xB7, 0x35, 0x0F, 0xF0, 0x5D, 0x6C, 0x01, 0x31, 0xEB, 0x66, 0x67, 0x67, 0x99, 0x9D, 0x9D, 0xE5, 0xC8, 0x91, 0x23, 0x32, 0xA7, 0xBE, 0xAC, 0xAC, 0x8C, 0xF6, 0xF6, 0x76, 0x22, 0x91, 0x88, 0x74, 0x25, 0x4B, 0x4A, 0x4A, 0x30, 0x18, 0x0C, 0x38, 0x1C, 0x0E, 0xDC, 0x6E, 0xB7, 0x9C, 0xA1, 0x0B, 0x65, 0x70, 0x09, 0x7B, 0xC3, 0x6E, 0xB7, 0x53, 0x5E, 0x5E, 0x2E, 0xCB, 0xD8, 0xA2, 0xD1, 0x28, 0x66, 0xB3, 0x99, 0xFA, 0xFA, 0x7A, 0x76, 0xEF, 0xDE, 0xCD, 0xE3, 0x8F, 0x3F, 0x4E, 0x41, 0x41, 0x01, 0x43, 0x43, 0x43, 0x58, 0x2C, 0x16, 0x8A, 0x8A, 0x8A, 0x48, 0xA7, 0xD3, 0x14, 0x14, 0x14, 0xE0, 0xF5, 0x7A, 0x65, 0x6D, 0x63, 0x26, 0xC0, 0x96, 0x43, 0xE7, 0xB0, 0x9B, 0xDE, 0x21, 0x44, 0xB4, 0x58, 0x2B, 0x2A, 0x2A, 0xC2, 0x6A, 0xB5, 0x32, 0x3D, 0x3D, 0xCD, 0x5F, 0xFE, 0xF2, 0x17, 0xB4, 0x5A, 0x2D, 0xA9, 0x54, 0x8A, 0xBA, 0xBA, 0x3A, 0x36, 0x6E, 0xDC, 0x88, 0xC5, 0x62, 0xC1, 0xEF, 0xF7, 0x13, 0x0C, 0x06, 0x71, 0x38, 0x1C, 0xC4, 0x62, 0x31, 0xAE, 0x5E, 0xBD, 0x2A, 0xD7, 0xDA, 0x85, 0x08, 0xB4, 0x88, 0x64, 0xD5, 0x68, 0x34, 0x4A, 0x53, 0x53, 0x13, 0x9B, 0x36, 0x6D, 0x42, 0xA9, 0x54, 0xD2, 0xD3, 0xD3, 0x83, 0xC7, 0xE3, 0xA1, 0xA5, 0xA5, 0x45, 0x86, 0xB3, 0x4B, 0x4B, 0x4B, 0x19, 0x1B, 0x1B, 0xE3, 0xF2, 0xE5, 0xCB, 0x32, 0x0E, 0xA0, 0xD3, 0xE9, 0x24, 0x13, 0xE8, 0xF7, 0xFB, 0xE5, 0x75, 0xA9, 0x54, 0x2A, 0x99, 0x38, 0xBA, 0xD4, 0xE5, 0xA6, 0x01, 0x40, 0xAD, 0x56, 0x93, 0x48, 0x24, 0xA4, 0xAA, 0xDC, 0xB8, 0x71, 0x23, 0x8F, 0x3C, 0xF2, 0x08, 0x81, 0x40, 0x80, 0x93, 0x27, 0x4F, 0x32, 0x31, 0x31, 0x41, 0x45, 0x45, 0x05, 0x6D, 0x6D, 0x6D, 0x6C, 0xDB, 0xB6, 0x8D, 0xB2, 0xB2, 0x32, 0x66, 0x66, 0x66, 0x18, 0x1C, 0x1C, 0xE4, 0xF8, 0xF1, 0xE3, 0x24, 0x93, 0xC9, 0xAC, 0x4C, 0x62, 0xE1, 0x25, 0xCC, 0x35, 0x36, 0xE7, 0xBA, 0x9E, 0x5F, 0xE7, 0xF2, 0x89, 0xB5, 0xDB, 0xE3, 0xF1, 0x10, 0x89, 0x44, 0xA8, 0xAD, 0xAD, 0xA5, 0xA1, 0xA1, 0x81, 0xDA, 0xDA, 0x5A, 0x3C, 0x1E, 0x0F, 0x75, 0x75, 0x75, 0xD4, 0xD7, 0xD7, 0x33, 0x33, 0x33, 0xC3, 0xC5, 0x8B, 0x17, 0xE9, 0xED, 0xED, 0x65, 0x6C, 0x6C, 0x8C, 0xAA, 0xAA, 0x2A, 0x36, 0x6E, 0xDC, 0x88, 0x56, 0xAB, 0xE5, 0xD2, 0xA5, 0x4B, 0xF4, 0xF7, 0xF7, 0x4B, 0xD7, 0x55, 0x94, 0xB7, 0x89, 0xDF, 0x32, 0x99, 0x4C, 0xD2, 0xBB, 0xB9, 0xA3, 0x01, 0x30, 0x37, 0x6F, 0xA0, 0xAB, 0xAB, 0x8B, 0x3D, 0x7B, 0xF6, 0xC8, 0x36, 0x70, 0x97, 0x2E, 0x5D, 0x92, 0xD9, 0xB5, 0xE2, 0x01, 0xEA, 0xF5, 0x7A, 0xCC, 0x66, 0x73, 0xD6, 0xAE, 0x5E, 0x99, 0x6B, 0x77, 0x66, 0xB3, 0xC6, 0xB9, 0x83, 0x2D, 0x96, 0x90, 0xB9, 0x1B, 0x47, 0x09, 0x0B, 0x7F, 0x6E, 0x6F, 0x62, 0xBF, 0xDF, 0x8F, 0xDB, 0xED, 0xA6, 0xB5, 0xB5, 0x95, 0x8E, 0x8E, 0x0E, 0x69, 0x88, 0x9E, 0x3B, 0x77, 0x8E, 0xE3, 0xC7, 0x8F, 0xD3, 0xDD, 0xDD, 0xCD, 0xCC, 0xCC, 0x0C, 0x26, 0x93, 0x89, 0xBD, 0x7B, 0xF7, 0xF2, 0xF0, 0xC3, 0x0F, 0x63, 0x30, 0x18, 0x50, 0xA9, 0x54, 0xEC, 0xDF, 0xBF, 0x7F, 0xDE, 0x7B, 0x2E, 0x2C, 0x2C, 0x94, 0xFB, 0x14, 0x8C, 0x8D, 0x8D, 0x5D, 0x03, 0xD0, 0x3B, 0x02, 0x00, 0x73, 0x33, 0x6A, 0x0B, 0x0B, 0x0B, 0xE5, 0xCE, 0x1E, 0xC3, 0xC3, 0xC3, 0x78, 0x3C, 0x1E, 0x82, 0xC1, 0x20, 0xF1, 0x78, 0x1C, 0x97, 0xCB, 0xC5, 0xC5, 0x8B, 0x17, 0x51, 0x28, 0x14, 0xF8, 0xFD, 0x7E, 0xEC, 0x76, 0x3B, 0x36, 0x9B, 0x8D, 0xAE, 0xAE, 0x2E, 0xB9, 0x87, 0xDF, 0xF8, 0xF8, 0x38, 0x6E, 0xB7, 0x9B, 0x50, 0x28, 0xF4, 0x9D, 0x48, 0x9E, 0xCC, 0xB2, 0xAE, 0xB9, 0x16, 0x7B, 0x6B, 0x6B, 0x2B, 0xAB, 0x56, 0xAD, 0xC2, 0xEF, 0xF7, 0x73, 0xEA, 0xD4, 0x29, 0x00, 0x19, 0xBF, 0x38, 0x75, 0xEA, 0x94, 0xFC, 0x0C, 0xC0, 0x68, 0x34, 0xD2, 0xDB, 0xDB, 0xCB, 0xC0, 0xC0, 0x00, 0x1D, 0x1D, 0x1D, 0x34, 0x35, 0x35, 0x71, 0xDF, 0x7D, 0xF7, 0x31, 0x33, 0x33, 0xC3, 0xF4, 0xF4, 0x34, 0x4A, 0xA5, 0x92, 0xD2, 0xD2, 0x52, 0x8A, 0x8B, 0x8B, 0x65, 0x1D, 0xE4, 0x52, 0x2E, 0x83, 0x5B, 0x74, 0x2F, 0x40, 0xAC, 0x87, 0xA2, 0x46, 0x70, 0xED, 0xDA, 0xB5, 0xAC, 0x5B, 0xB7, 0x0E, 0xAF, 0xD7, 0xCB, 0xBB, 0xEF, 0xBE, 0xCB, 0xBE, 0x7D, 0xFB, 0x38, 0x79, 0xF2, 0x24, 0xFD, 0xFD, 0xFD, 0x0C, 0x0E, 0x0E, 0xCA, 0x96, 0xAC, 0x0A, 0x85, 0x02, 0xAB, 0xD5, 0x4A, 0x65, 0x65, 0x25, 0xD5, 0xD5, 0xD5, 0x34, 0x34, 0x34, 0x60, 0xB7, 0xDB, 0x51, 0xAB, 0xD5, 0xF3, 0x66, 0x15, 0x5F, 0x4F, 0x74, 0x3A, 0x5D, 0x56, 0x14, 0x6F, 0xAE, 0x14, 0x17, 0x17, 0xF3, 0xD3, 0x9F, 0xFE, 0x94, 0x47, 0x1E, 0x79, 0x84, 0x70, 0x38, 0xCC, 0x91, 0x23, 0x47, 0x78, 0xEF, 0xBD, 0xF7, 0x38, 0x78, 0xF0, 0x20, 0x9F, 0x7D, 0xF6, 0x59, 0xD6, 0xCC, 0x15, 0x9A, 0xC5, 0xE1, 0x70, 0xE0, 0x74, 0x3A, 0x29, 0x2D, 0x2D, 0xA5, 0xAD, 0xAD, 0x8D, 0xBA, 0xBA, 0x3A, 0xF4, 0x7A, 0x3D, 0x7E, 0xBF, 0x9F, 0xB2, 0xB2, 0x32, 0xF6, 0xEE, 0xDD, 0xCB, 0x4B, 0x2F, 0xBD, 0x84, 0x52, 0xA9, 0xE4, 0xD4, 0xA9, 0x53, 0xB2, 0x7F, 0xD0, 0x7C, 0x5E, 0xC8, 0x1D, 0xE5, 0x05, 0x64, 0x06, 0x55, 0xCE, 0x9E, 0x3D, 0xCB, 0x99, 0x33, 0x67, 0xAE, 0xF9, 0x9E, 0xD3, 0xE9, 0xC4, 0xE7, 0xF3, 0xC9, 0x0A, 0xE2, 0x91, 0x91, 0x11, 0x4A, 0x4B, 0x4B, 0xA9, 0xAA, 0xAA, 0x92, 0xED, 0xD9, 0x2C, 0x16, 0x0B, 0xBD, 0xBD, 0xBD, 0x44, 0xA3, 0x51, 0xC9, 0xD6, 0xC5, 0x62, 0x31, 0x7C, 0x3E, 0x9F, 0x34, 0x12, 0x67, 0x67, 0x67, 0x99, 0x98, 0x98, 0xB8, 0xC6, 0x10, 0x13, 0x3B, 0x85, 0xE9, 0x74, 0x3A, 0x0C, 0x06, 0x03, 0x5D, 0x5D, 0x5D, 0xEC, 0xDE, 0xBD, 0x9B, 0xE6, 0xE6, 0x66, 0xD4, 0x6A, 0x35, 0x5F, 0x7E, 0xF9, 0x25, 0xA3, 0xA3, 0xA3, 0x68, 0xB5, 0x5A, 0x99, 0xE1, 0x24, 0x28, 0x6C, 0xC1, 0x53, 0x8C, 0x8E, 0x8E, 0x62, 0x36, 0x9B, 0xF1, 0x78, 0x3C, 0x14, 0x14, 0x14, 0xB0, 0x66, 0xCD, 0x1A, 0xE2, 0xF1, 0x38, 0x05, 0x05, 0x05, 0x98, 0x4C, 0x26, 0x9E, 0x7C, 0xF2, 0x49, 0x8A, 0x8A, 0x8A, 0x38, 0x73, 0xE6, 0x0C, 0x13, 0x13, 0x13, 0x92, 0xDD, 0x5C, 0x8A, 0x54, 0xB1, 0xFA, 0x66, 0x0C, 0x7C, 0xE6, 0xFB, 0x9E, 0x9E, 0x1E, 0x86, 0x86, 0x86, 0xF0, 0x78, 0x3C, 0xD7, 0xE5, 0x0A, 0x46, 0x47, 0x47, 0x09, 0x06, 0x83, 0x74, 0x77, 0x77, 0x63, 0x32, 0x99, 0xD0, 0xEB, 0xF5, 0x3C, 0xF3, 0xCC, 0x33, 0xEC, 0xDD, 0xBB, 0x97, 0xCD, 0x9B, 0x37, 0x53, 0x5E, 0x5E, 0x8E, 0xCF, 0xE7, 0xC3, 0x62, 0xB1, 0x60, 0x32, 0x99, 0x88, 0xC5, 0x62, 0x38, 0x9D, 0x4E, 0x86, 0x86, 0x86, 0xA4, 0xEB, 0xF5, 0xF9, 0xE7, 0x9F, 0xF3, 0xEE, 0xBB, 0xEF, 0xE2, 0x74, 0x3A, 0xB3, 0xD4, 0xB7, 0x50, 0xF7, 0x8D, 0x8D, 0x8D, 0xD4, 0xD5, 0xD5, 0x51, 0x57, 0x57, 0xC7, 0x8A, 0x15, 0x2B, 0x50, 0xA9, 0x54, 0xD4, 0xD7, 0xD7, 0xF3, 0xEC, 0xB3, 0xCF, 0xB2, 0x7D, 0xFB, 0x76, 0x8C, 0x46, 0xA3, 0x6C, 0x0E, 0xE5, 0x70, 0x38, 0xF8, 0xCF, 0x7F, 0xFE, 0xC3, 0x9B, 0x6F, 0xBE, 0x49, 0x30, 0x18, 0x44, 0xAF, 0xD7, 0xB3, 0x7E, 0xFD, 0x7A, 0xEA, 0xEB, 0xEB, 0xE5, 0xB9, 0x4B, 0x4B, 0x4B, 0x79, 0xEC, 0xB1, 0xC7, 0x28, 0x2A, 0x2A, 0xC2, 0x62, 0xB1, 0x30, 0x38, 0x38, 0x48, 0x5F, 0x5F, 0x1F, 0xC1, 0x60, 0x50, 0x1A, 0xAB, 0x4A, 0xA5, 0x32, 0x6B, 0xAF, 0xC2, 0x3B, 0x02, 0x00, 0x73, 0x0B, 0x40, 0x33, 0x4B, 0xC3, 0x85, 0x21, 0x97, 0xD9, 0x10, 0x42, 0x70, 0xEF, 0x22, 0xB3, 0x28, 0xD3, 0xE8, 0xEB, 0xEA, 0xEA, 0xE2, 0xDE, 0x7B, 0xEF, 0xA5, 0xB3, 0xB3, 0x53, 0x26, 0x5B, 0xFA, 0xFD, 0x7E, 0x7C, 0x3E, 0x1F, 0x05, 0x05, 0x05, 0xB4, 0xB7, 0xB7, 0x53, 0x5E, 0x5E, 0x4E, 0x51, 0x51, 0x11, 0x6B, 0xD7, 0xAE, 0xC5, 0x6A, 0xB5, 0x72, 0xEA, 0xD4, 0x29, 0x52, 0xA9, 0x94, 0xAC, 0xE6, 0x59, 0xB9, 0x72, 0x25, 0x2D, 0x2D, 0x2D, 0xAC, 0x58, 0xB1, 0x82, 0x8A, 0x8A, 0x0A, 0x0C, 0x06, 0x03, 0xA9, 0x54, 0x8A, 0xE9, 0xE9, 0x69, 0xD9, 0xB0, 0xC2, 0x64, 0x32, 0x61, 0xB1, 0x58, 0xB0, 0x58, 0x2C, 0xE8, 0x74, 0x3A, 0xAA, 0xAB, 0xAB, 0xB9, 0xE7, 0x9E, 0x7B, 0x88, 0xC5, 0x62, 0xF4, 0xF7, 0xF7, 0x63, 0x36, 0x9B, 0x69, 0x6F, 0x6F, 0x97, 0x76, 0x0B, 0x20, 0xAB, 0x80, 0x5C, 0x2E, 0x17, 0x16, 0x8B, 0x85, 0x2B, 0x57, 0xAE, 0x30, 0x3C, 0x3C, 0x2C, 0xAD, 0xFF, 0xA5, 0x5A, 0x29, 0x7C, 0x4B, 0x37, 0x8C, 0x98, 0x2F, 0x82, 0x76, 0xBD, 0xD9, 0xE1, 0x72, 0xB9, 0x38, 0x7E, 0xFC, 0x38, 0x66, 0xB3, 0x19, 0xBB, 0xDD, 0x8E, 0xC3, 0xE1, 0xE0, 0x8B, 0x2F, 0xBE, 0xE0, 0xD4, 0xA9, 0x53, 0x4C, 0x4F, 0x4F, 0x63, 0xB5, 0x5A, 0x59, 0xBF, 0x7E, 0x3D, 0x9B, 0x37, 0x6F, 0xA6, 0xAA, 0xAA, 0x8A, 0xB5, 0x6B, 0xD7, 0x52, 0x55, 0x55, 0x85, 0xDB, 0xED, 0x96, 0x7C, 0xBE, 0x18, 0x08, 0x9D, 0x4E, 0x87, 0x56, 0xAB, 0x25, 0x10, 0x08, 0x48, 0x22, 0xC8, 0xE3, 0xF1, 0xF0, 0xD1, 0x47, 0x1F, 0xF1, 0xE9, 0xA7, 0x9F, 0xCA, 0xF8, 0xBE, 0x56, 0xAB, 0xC5, 0x6C, 0x36, 0xD3, 0xD6, 0xD6, 0x46, 0x67, 0x67, 0x27, 0x2F, 0xBF, 0xFC, 0x32, 0x89, 0x44, 0x82, 0xCB, 0x97, 0x2F, 0x33, 0x35, 0x35, 0xC5, 0xA5, 0x4B, 0x97, 0x88, 0xC5, 0x62, 0x54, 0x54, 0x54, 0x30, 0x3A, 0x3A, 0xCA, 0xDF, 0xFF, 0xFE, 0x77, 0xAE, 0x5C, 0xB9, 0xC2, 0xF6, 0xED, 0xDB, 0x59, 0xB9, 0x72, 0x65, 0x56, 0xF3, 0xA8, 0xC5, 0xA2, 0xB2, 0x97, 0x1D, 0x00, 0xE6, 0xBA, 0x6E, 0xF3, 0xED, 0x0F, 0x2C, 0x22, 0x71, 0x99, 0x06, 0x93, 0xA8, 0xBD, 0xEF, 0xEB, 0xEB, 0xE3, 0xE8, 0xD1, 0xA3, 0x72, 0x07, 0x11, 0x61, 0xA1, 0xEB, 0xF5, 0x7A, 0x26, 0x26, 0x26, 0xF0, 0x7A, 0xBD, 0xF4, 0xF7, 0xF7, 0xCB, 0x6D, 0xE1, 0x04, 0xCF, 0x2F, 0xAA, 0x93, 0x67, 0x66, 0x66, 0x64, 0x8D, 0xA2, 0xC9, 0x64, 0xA2, 0xA5, 0xA5, 0x85, 0xCA, 0xCA, 0x4A, 0xFC, 0x7E, 0x3F, 0x27, 0x4F, 0x9E, 0xE4, 0xFD, 0xF7, 0xDF, 0xBF, 0x86, 0xD6, 0xED, 0xEE, 0xEE, 0x26, 0x10, 0x08, 0x90, 0x97, 0x97, 0x87, 0xCD, 0x66, 0xA3, 0xB2, 0xB2, 0x12, 0x95, 0x4A, 0x45, 0x28, 0x14, 0x92, 0x60, 0xE9, 0xE9, 0xE9, 0xE1, 0xC0, 0x81, 0x03, 0x38, 0x9D, 0x4E, 0x42, 0xA1, 0x10, 0x2F, 0xBC, 0xF0, 0x02, 0xEB, 0xD7, 0xAF, 0x97, 0x1B, 0x5F, 0x0A, 0xAD, 0x27, 0xEE, 0x7F, 0xA9, 0xC4, 0x0E, 0x6E, 0x3A, 0x00, 0xBE, 0xA9, 0x09, 0xE4, 0xDC, 0x64, 0x4A, 0xF1, 0x1D, 0x9B, 0xCD, 0x46, 0x7D, 0x7D, 0x3D, 0x4E, 0xA7, 0x93, 0x37, 0xDE, 0x78, 0x83, 0xC9, 0xC9, 0x49, 0xBC, 0x5E, 0xAF, 0x3C, 0x2E, 0x12, 0x89, 0x70, 0xF2, 0xE4, 0x49, 0x06, 0x06, 0x06, 0x24, 0x77, 0x20, 0x36, 0x88, 0x10, 0x61, 0x65, 0x91, 0xD6, 0x15, 0x8F, 0xC7, 0x31, 0x9B, 0xCD, 0xAC, 0x5F, 0xBF, 0x1E, 0x8B, 0xC5, 0x82, 0xCD, 0x66, 0x93, 0xAD, 0xE0, 0xE7, 0xE3, 0xF4, 0x1D, 0x0E, 0x07, 0xFB, 0xF6, 0xED, 0xE3, 0xF8, 0xF1, 0xE3, 0xD8, 0xED, 0x76, 0x76, 0xEE, 0xDC, 0xC9, 0xDA, 0xB5, 0x6B, 0xE5, 0x36, 0x76, 0x23, 0x23, 0x23, 0xF4, 0xF6, 0xF6, 0x4A, 0x30, 0xF7, 0xF4, 0xF4, 0x70, 0xF6, 0xEC, 0x59, 0x7E, 0xF2, 0x93, 0x9F, 0xB0, 0x69, 0xD3, 0x26, 0x54, 0x2A, 0x15, 0xFF, 0xFA, 0xD7, 0xBF, 0xA4, 0x56, 0x51, 0x28, 0x14, 0x4B, 0xA6, 0x2E, 0xE2, 0x96, 0x00, 0xE0, 0xBB, 0x18, 0x8F, 0xE2, 0xDF, 0x40, 0x20, 0xC0, 0xC8, 0xC8, 0x08, 0x3D, 0x3D, 0x3D, 0x59, 0x5B, 0xC3, 0x88, 0xC6, 0x4C, 0x89, 0x44, 0x02, 0xAF, 0xD7, 0x9B, 0x05, 0x8A, 0x6F, 0x92, 0x50, 0x28, 0x44, 0x79, 0x79, 0x39, 0xA5, 0xA5, 0xA5, 0x84, 0xC3, 0x61, 0xC9, 0x2D, 0xA8, 0xD5, 0x6A, 0x0C, 0x06, 0x43, 0x56, 0x73, 0xA8, 0x91, 0x91, 0x11, 0x46, 0x46, 0x46, 0xE4, 0x32, 0x52, 0x5F, 0x5F, 0x2F, 0x73, 0x1B, 0x07, 0x06, 0x06, 0xE8, 0xEB, 0xEB, 0x23, 0x9D, 0x4E, 0xA3, 0xD3, 0xE9, 0x88, 0x44, 0x22, 0xF4, 0xF4, 0xF4, 0x10, 0x0E, 0x87, 0xD9, 0xB4, 0x69, 0x13, 0xCF, 0x3D, 0xF7, 0x1C, 0x57, 0xAE, 0x5C, 0x61, 0x70, 0x70, 0x50, 0x36, 0xC3, 0x5E, 0x2A, 0x2D, 0x65, 0x6F, 0xD9, 0x96, 0x31, 0xDF, 0x15, 0x2C, 0xB3, 0xB3, 0xB3, 0xF4, 0xF5, 0xF5, 0xC9, 0x8D, 0xA2, 0x32, 0x81, 0xF2, 0x7D, 0x83, 0x2E, 0x5E, 0xAF, 0x97, 0x68, 0x34, 0x8A, 0xCD, 0x66, 0x93, 0x1D, 0xBF, 0x45, 0x4A, 0xBB, 0x88, 0x13, 0xCC, 0x97, 0xE5, 0xEC, 0xF5, 0x7A, 0x31, 0x9B, 0xCD, 0xAC, 0x5D, 0xBB, 0x96, 0xB2, 0xB2, 0x32, 0xCE, 0x9F, 0x3F, 0xCF, 0xE1, 0xC3, 0x87, 0x99, 0x98, 0x98, 0x90, 0x56, 0x7E, 0x24, 0x12, 0xC1, 0x68, 0x34, 0x62, 0xB3, 0xD9, 0x58, 0xB5, 0x6A, 0x15, 0xF5, 0xF5, 0xF5, 0x38, 0x1C, 0x0E, 0xAE, 0x5E, 0xBD, 0x9A, 0xC5, 0x4F, 0xDC, 0xEA, 0x46, 0x12, 0x4B, 0x1A, 0x00, 0x73, 0x67, 0xAB, 0x60, 0x0D, 0x45, 0x6F, 0xC1, 0xCC, 0x32, 0xEB, 0xCC, 0x4C, 0x64, 0x91, 0x3F, 0x30, 0xF7, 0x95, 0x99, 0xA9, 0x9C, 0xC9, 0x1D, 0x28, 0x14, 0x0A, 0x5C, 0x2E, 0x17, 0x63, 0x63, 0x63, 0xB2, 0x8D, 0x5D, 0x26, 0xA8, 0xC4, 0x66, 0x17, 0x1A, 0x8D, 0x06, 0x85, 0x42, 0x81, 0xCF, 0xE7, 0x23, 0x1E, 0x8F, 0x53, 0x53, 0x53, 0x83, 0xD1, 0x68, 0x64, 0x60, 0x60, 0x80, 0x4B, 0x97, 0x2E, 0xE1, 0xF1, 0x78, 0x88, 0xC5, 0x62, 0x32, 0xB4, 0xEC, 0xF5, 0x7A, 0x09, 0x85, 0x42, 0x34, 0x34, 0x34, 0xB0, 0x6A, 0xD5, 0x2A, 0x54, 0x2A, 0x15, 0xE3, 0xE3, 0xE3, 0x84, 0x42, 0x21, 0x99, 0x42, 0x7F, 0xAB, 0x37, 0x96, 0x58, 0x36, 0x00, 0x98, 0xBB, 0x3C, 0x5C, 0x2F, 0xD8, 0x23, 0x06, 0x6F, 0xBE, 0x97, 0x88, 0x0D, 0x64, 0xD2, 0xC1, 0x91, 0x48, 0x04, 0xA7, 0xD3, 0xC9, 0xF8, 0xF8, 0x38, 0x1A, 0x8D, 0x86, 0xBC, 0xBC, 0x3C, 0x22, 0x91, 0x88, 0x6C, 0x61, 0x97, 0x19, 0xDA, 0x15, 0xC6, 0xA4, 0x38, 0x4E, 0xCC, 0xF4, 0x68, 0x34, 0x4A, 0x22, 0x91, 0x60, 0x66, 0x66, 0x46, 0xB6, 0xC8, 0x4D, 0xA7, 0xD3, 0xF8, 0xFD, 0x7E, 0xC6, 0xC7, 0xC7, 0x89, 0xC5, 0x62, 0x94, 0x94, 0x94, 0xB0, 0x6E, 0xDD, 0x3A, 0x9A, 0x9B, 0x9B, 0x99, 0x98, 0x98, 0xE0, 0xCA, 0x95, 0x2B, 0xD2, 0x26, 0x10, 0x81, 0xB2, 0x1C, 0x00, 0xBE, 0xC1, 0x7B, 0x98, 0xBB, 0x9D, 0xEB, 0x37, 0x19, 0x9A, 0xF3, 0xF5, 0x1D, 0xCC, 0x8C, 0x4B, 0x88, 0x2C, 0xA5, 0x50, 0x28, 0xC4, 0xCC, 0xCC, 0x8C, 0x0C, 0xEE, 0x88, 0x7C, 0x80, 0x4C, 0x2F, 0x24, 0x13, 0x0C, 0x42, 0x75, 0x87, 0x42, 0x21, 0xB9, 0xCB, 0x98, 0xC9, 0x64, 0x62, 0x62, 0x62, 0x42, 0x26, 0xB3, 0x08, 0x4B, 0x5F, 0xEC, 0x41, 0x94, 0x48, 0x24, 0x68, 0x6D, 0x6D, 0x95, 0x89, 0x2F, 0xA3, 0xA3, 0xA3, 0x84, 0xC3, 0x61, 0xA9, 0x09, 0x32, 0x93, 0x50, 0x73, 0x00, 0xF8, 0x86, 0x99, 0xBF, 0x58, 0x12, 0x8D, 0x46, 0x65, 0x4A, 0xDA, 0x7C, 0x20, 0x13, 0xE0, 0xCB, 0xAC, 0x0F, 0x2C, 0x2F, 0x2F, 0x67, 0xC5, 0x8A, 0x15, 0xE8, 0x74, 0x3A, 0x86, 0x87, 0x87, 0xB3, 0xEA, 0x03, 0x85, 0xBB, 0xEB, 0xF7, 0xFB, 0x71, 0x38, 0x1C, 0xB2, 0xA1, 0x54, 0x57, 0x57, 0x17, 0xAD, 0xAD, 0xAD, 0x4C, 0x4E, 0x4E, 0xCA, 0x62, 0x52, 0xAD, 0x56, 0x2B, 0xD3, 0xE5, 0xC4, 0xB1, 0x37, 0xA3, 0xC3, 0xD8, 0xB2, 0x5C, 0x02, 0x16, 0x52, 0x04, 0xE7, 0x20, 0x36, 0x90, 0xFE, 0xBA, 0xF2, 0xB4, 0xCC, 0x5D, 0x43, 0x15, 0x0A, 0x05, 0xAD, 0xAD, 0xAD, 0xDC, 0x7B, 0xEF, 0xBD, 0x74, 0x74, 0x74, 0x10, 0x8F, 0xC7, 0x39, 0x71, 0xE2, 0x84, 0x4C, 0x5A, 0x51, 0x2A, 0x95, 0xE8, 0xF5, 0x7A, 0x19, 0x81, 0xF4, 0xF9, 0x7C, 0x38, 0x1C, 0x0E, 0xE2, 0xF1, 0x38, 0x4D, 0x4D, 0x4D, 0x74, 0x74, 0x74, 0xA0, 0x56, 0xAB, 0x19, 0x1B, 0x1B, 0x93, 0x59, 0x48, 0x99, 0x9D, 0x48, 0xBF, 0x6E, 0x99, 0xCB, 0x01, 0x60, 0x11, 0xBC, 0x8D, 0x6F, 0x5A, 0x56, 0x32, 0xF7, 0x0F, 0x16, 0x7F, 0x3F, 0xF4, 0xD0, 0x43, 0x3C, 0xF1, 0xC4, 0x13, 0xB4, 0xB6, 0xB6, 0xE2, 0xF5, 0x7A, 0xF9, 0xE8, 0xA3, 0x8F, 0x18, 0x1F, 0x1F, 0x97, 0x56, 0x3E, 0x20, 0x37, 0x92, 0x10, 0xAE, 0xEC, 0xF8, 0xF8, 0x38, 0x91, 0x48, 0x04, 0xAB, 0xD5, 0x4A, 0x67, 0x67, 0x27, 0xED, 0xED, 0xED, 0xB8, 0xDD, 0x6E, 0xFA, 0xFA, 0xFA, 0xE4, 0x71, 0x7A, 0xBD, 0xFE, 0xA6, 0xF5, 0x4B, 0xCE, 0x01, 0x60, 0x1E, 0x16, 0x72, 0xBE, 0xCF, 0x33, 0x7D, 0x77, 0x8B, 0xC5, 0x42, 0x5B, 0x5B, 0x1B, 0x2F, 0xBC, 0xF0, 0x02, 0xBB, 0x77, 0xEF, 0xC6, 0x68, 0x34, 0xA2, 0x56, 0xAB, 0xE5, 0xBE, 0x48, 0xA1, 0x50, 0x48, 0xCE, 0x68, 0xA5, 0x52, 0x29, 0xC9, 0x1F, 0xA1, 0x09, 0x04, 0x08, 0x56, 0xAE, 0x5C, 0x49, 0x47, 0x47, 0x07, 0x2A, 0x95, 0x8A, 0x91, 0x91, 0x11, 0x69, 0x13, 0xC4, 0x62, 0x31, 0xD2, 0xE9, 0x34, 0x7A, 0xBD, 0x5E, 0xEE, 0x74, 0x9E, 0x69, 0x24, 0x2E, 0xE4, 0xB2, 0x90, 0x03, 0xC0, 0xB7, 0x79, 0x48, 0x19, 0xAA, 0x5F, 0xAB, 0xD5, 0xD2, 0xD2, 0xD2, 0xC2, 0x96, 0x2D, 0x5B, 0xD8, 0xBA, 0x75, 0x2B, 0x76, 0xBB, 0x1D, 0x40, 0x86, 0x96, 0xDB, 0xDB, 0xDB, 0x71, 0x38, 0x1C, 0xF4, 0xF7, 0xF7, 0xCB, 0x19, 0x2D, 0x02, 0x5C, 0x42, 0x02, 0x81, 0x00, 0x0E, 0x87, 0x83, 0x70, 0x38, 0x4C, 0x7E, 0x7E, 0x3E, 0x6D, 0x6D, 0x6D, 0x34, 0x37, 0x37, 0xE3, 0x76, 0xBB, 0xB3, 0x1A, 0x4C, 0x34, 0x36, 0x36, 0x52, 0x56, 0x56, 0x86, 0x42, 0xA1, 0x20, 0x10, 0x08, 0x64, 0x15, 0xD9, 0x2C, 0x94, 0x76, 0xC8, 0x01, 0xE0, 0x5B, 0x7A, 0x20, 0xE2, 0x81, 0xAB, 0xD5, 0x6A, 0xEC, 0x76, 0x3B, 0x15, 0x15, 0x15, 0xD2, 0xAF, 0xEF, 0xEE, 0xEE, 0xC6, 0xE1, 0x70, 0x50, 0x5A, 0x5A, 0x4A, 0x43, 0x43, 0x83, 0x4C, 0x5A, 0x11, 0xBD, 0x11, 0x45, 0x13, 0x0D, 0xA1, 0x09, 0x44, 0xEF, 0x44, 0xC1, 0x3B, 0x88, 0xCE, 0x62, 0xC2, 0x03, 0xA9, 0xA8, 0xA8, 0xE0, 0xEE, 0xBB, 0xEF, 0xC6, 0x6E, 0xB7, 0x13, 0x08, 0x04, 0x08, 0x04, 0x02, 0x92, 0x41, 0x5C, 0xE8, 0x1D, 0xD4, 0x6E, 0xF9, 0xEE, 0xE1, 0xCB, 0x65, 0x69, 0xC8, 0x6C, 0x01, 0x9F, 0x9F, 0x9F, 0x8F, 0xD5, 0x6A, 0xA5, 0xA0, 0xA0, 0x40, 0x72, 0x03, 0x46, 0xA3, 0x91, 0x7B, 0xEF, 0xBD, 0x97, 0x87, 0x1F, 0x7E, 0x98, 0xD6, 0xD6, 0x56, 0x7A, 0x7A, 0x7A, 0xF8, 0xC3, 0x1F, 0xFE, 0xC0, 0x81, 0x03, 0x07, 0xA4, 0x26, 0x50, 0x28, 0x14, 0xD2, 0xBD, 0x14, 0x03, 0x59, 0x52, 0x52, 0xC2, 0x13, 0x4F, 0x3C, 0xC1, 0x53, 0x4F, 0x3D, 0x45, 0x59, 0x59, 0x59, 0x96, 0xBD, 0xF1, 0xD6, 0x5B, 0x6F, 0xF1, 0xEA, 0xAB, 0xAF, 0x32, 0x33, 0x33, 0x43, 0x38, 0x1C, 0x46, 0xA3, 0xD1, 0xC8, 0xAD, 0xEB, 0x72, 0x1A, 0xE0, 0x16, 0x1A, 0x8C, 0x91, 0x48, 0x04, 0xAF, 0xD7, 0xCB, 0xC4, 0xC4, 0x84, 0xDC, 0x35, 0x6C, 0x6C, 0x6C, 0x8C, 0xFE, 0xFE, 0x7E, 0xC2, 0xE1, 0x30, 0x36, 0x9B, 0x8D, 0xE2, 0xE2, 0x62, 0x62, 0xB1, 0x98, 0xDC, 0x51, 0x2C, 0xD3, 0xCA, 0xCF, 0xD4, 0x04, 0xC1, 0x60, 0x50, 0x66, 0x0D, 0xD9, 0x6C, 0x36, 0x3A, 0x3B, 0x3B, 0xA9, 0xAE, 0xAE, 0xA6, 0xB0, 0xB0, 0x90, 0xA3, 0x47, 0x8F, 0xF2, 0xC1, 0x07, 0x1F, 0xC8, 0x24, 0xD9, 0x4C, 0x37, 0x31, 0x67, 0x03, 0x2C, 0x51, 0xBA, 0xDA, 0xE9, 0x74, 0xD2, 0xDD, 0xDD, 0xCD, 0xF4, 0xF4, 0x34, 0x6D, 0x6D, 0x6D, 0x32, 0xFF, 0x51, 0x30, 0x7F, 0xF3, 0xED, 0x2A, 0x16, 0x08, 0x04, 0x64, 0x03, 0x0D, 0x9F, 0xCF, 0x47, 0x2C, 0x16, 0x93, 0x4D, 0xA7, 0x3E, 0xFF, 0xFC, 0xF3, 0x2C, 0xED, 0xB3, 0xD0, 0x61, 0xE4, 0x1C, 0x00, 0xBE, 0xA7, 0x4D, 0x90, 0x19, 0x1F, 0x10, 0x99, 0x4D, 0x62, 0x46, 0x8F, 0x8E, 0x8E, 0x32, 0x36, 0x36, 0x46, 0x7B, 0x7B, 0x3B, 0x6B, 0xD6, 0xAC, 0x21, 0x1C, 0x0E, 0x33, 0x3C, 0x3C, 0x2C, 0x8B, 0x50, 0x84, 0x7F, 0x9F, 0x79, 0x5C, 0x20, 0x10, 0x60, 0x70, 0x70, 0x90, 0xD1, 0xD1, 0x51, 0x99, 0x06, 0x37, 0x36, 0x36, 0xC6, 0xC5, 0x8B, 0x17, 0xB3, 0x58, 0xC9, 0x85, 0x8E, 0x1E, 0xE6, 0x00, 0xF0, 0x3D, 0x97, 0x01, 0xC1, 0x1D, 0xCC, 0x8D, 0x2D, 0x08, 0x11, 0xA9, 0x60, 0x5A, 0xAD, 0x16, 0x9B, 0xCD, 0x46, 0x79, 0x79, 0xB9, 0xAC, 0x72, 0xCA, 0x0C, 0x32, 0x09, 0x03, 0x51, 0x9C, 0x73, 0x76, 0x76, 0x96, 0x55, 0xAB, 0x56, 0xB1, 0x61, 0xC3, 0x06, 0x12, 0x89, 0x84, 0xAC, 0x52, 0xCA, 0xFC, 0xED, 0x9C, 0x1B, 0xB8, 0x04, 0xC1, 0x20, 0x3C, 0x04, 0x51, 0x6D, 0x1C, 0x8F, 0xC7, 0xF1, 0x78, 0x3C, 0xF8, 0xFD, 0x7E, 0xD6, 0xAC, 0x59, 0x43, 0x67, 0x67, 0xA7, 0x0C, 0x69, 0x67, 0x6E, 0x2A, 0x95, 0x4A, 0xA5, 0xD0, 0x6A, 0xB5, 0x92, 0x63, 0x10, 0x74, 0xB1, 0xD8, 0x80, 0x42, 0xD4, 0x48, 0xB8, 0xDD, 0xEE, 0x6B, 0x62, 0x18, 0x39, 0x00, 0x2C, 0x51, 0x30, 0x08, 0xD2, 0x47, 0x10, 0x43, 0x9D, 0x9D, 0x9D, 0xB4, 0xB5, 0xB5, 0x91, 0x48, 0x24, 0x64, 0x6A, 0xB9, 0xD0, 0x18, 0x22, 0xB6, 0x90, 0xC9, 0xFC, 0xB9, 0x5C, 0x2E, 0x1C, 0x0E, 0x07, 0xB5, 0xB5, 0xB5, 0x32, 0xA3, 0x48, 0x94, 0xA3, 0x8B, 0x65, 0x67, 0xA1, 0x8C, 0xC1, 0x1C, 0x00, 0x16, 0x89, 0x38, 0x12, 0x60, 0x08, 0x85, 0x42, 0xB2, 0x4A, 0x48, 0xA5, 0x52, 0x11, 0x0C, 0x06, 0x19, 0x1A, 0x1A, 0x62, 0x76, 0x76, 0x36, 0x2B, 0xB0, 0x94, 0x59, 0x58, 0x2A, 0xEC, 0x88, 0xB5, 0x6B, 0xD7, 0xB2, 0x73, 0xE7, 0x4E, 0x52, 0xA9, 0x14, 0xC7, 0x8E, 0x1D, 0x93, 0x75, 0x0F, 0x0B, 0xB9, 0xE7, 0x82, 0x32, 0x37, 0x5C, 0x0B, 0x2F, 0x99, 0x51, 0xCB, 0x74, 0x3A, 0xCD, 0x85, 0x0B, 0x17, 0xF8, 0xE4, 0x93, 0x4F, 0xF0, 0x7A, 0xBD, 0x54, 0x55, 0x55, 0x49, 0xFE, 0x40, 0xB8, 0x76, 0x99, 0x09, 0xB0, 0x99, 0xA9, 0x70, 0x2E, 0x97, 0x0B, 0x8F, 0xC7, 0x83, 0x5E, 0xAF, 0xA7, 0xAE, 0xAE, 0xEE, 0x9A, 0x5E, 0x03, 0x0B, 0x01, 0x80, 0x9C, 0x06, 0x58, 0x24, 0x0D, 0x20, 0x66, 0xB7, 0xD8, 0x7C, 0x5A, 0x34, 0xC5, 0xAA, 0xA8, 0xA8, 0xA0, 0xB4, 0xB4, 0x14, 0xA5, 0x52, 0x49, 0x2C, 0x16, 0xC3, 0xEB, 0xF5, 0x4A, 0x7E, 0x20, 0xB3, 0x5D, 0x1E, 0x40, 0x7E, 0x7E, 0xBE, 0xCC, 0x31, 0x14, 0xCD, 0x35, 0x44, 0x25, 0x94, 0xE0, 0x06, 0x6E, 0xD4, 0x28, 0xCC, 0x01, 0x60, 0x11, 0x24, 0x33, 0x6A, 0xA8, 0xD1, 0x68, 0xD8, 0xB5, 0x6B, 0x17, 0x4F, 0x3F, 0xFD, 0x34, 0xB5, 0xB5, 0xB5, 0x58, 0xAD, 0x56, 0xB6, 0x6E, 0xDD, 0xCA, 0xD6, 0xAD, 0x5B, 0x99, 0x98, 0x98, 0x90, 0x09, 0xAE, 0x2A, 0x95, 0x4A, 0x46, 0x01, 0x33, 0x13, 0x61, 0x45, 0x49, 0x7C, 0x65, 0x65, 0x25, 0xED, 0xED, 0xED, 0xD4, 0xD4, 0xD4, 0x90, 0x4A, 0xA5, 0x64, 0xFE, 0x61, 0xE6, 0x92, 0x93, 0x03, 0xC0, 0x12, 0xE2, 0x09, 0x32, 0x1B, 0x5F, 0xB6, 0xB7, 0xB7, 0x53, 0x51, 0x51, 0xC1, 0xE4, 0xE4, 0x24, 0xC3, 0xC3, 0xC3, 0x98, 0x4C, 0x26, 0x59, 0x98, 0xE2, 0x72, 0xB9, 0x50, 0x2A, 0x95, 0x78, 0xBD, 0x5E, 0xD9, 0x93, 0x48, 0xA3, 0xD1, 0x60, 0x36, 0x9B, 0x81, 0xAF, 0x92, 0x61, 0xDD, 0x6E, 0x37, 0xE1, 0x70, 0x98, 0xEA, 0xEA, 0x6A, 0x9A, 0x9A, 0x9A, 0x88, 0x46, 0xA3, 0x5C, 0xBC, 0x78, 0x51, 0xBA, 0x9A, 0x37, 0x52, 0x74, 0xA2, 0xCE, 0x0D, 0xD7, 0xC2, 0x4B, 0xA6, 0x85, 0x1E, 0x8F, 0xC7, 0x39, 0x70, 0xE0, 0x00, 0xE7, 0xCE, 0x9D, 0x43, 0xA9, 0x54, 0xCA, 0x5C, 0x00, 0xBD, 0x5E, 0xCF, 0xAE, 0x5D, 0xBB, 0xF8, 0xD5, 0xAF, 0x7E, 0xC5, 0xFE, 0xFD, 0xFB, 0xF9, 0xD3, 0x9F, 0xFE, 0x24, 0x8F, 0xB1, 0x5A, 0xAD, 0x94, 0x97, 0x97, 0x93, 0x4E, 0xA7, 0xF1, 0x78, 0x3C, 0x5C, 0xBC, 0x78, 0x91, 0x2F, 0xBE, 0xF8, 0x02, 0xA5, 0x52, 0xC9, 0xF3, 0xCF, 0x3F, 0x8F, 0xCD, 0x66, 0xCB, 0xEA, 0xBA, 0x76, 0x23, 0x4B, 0x40, 0x0E, 0x00, 0x8B, 0xE4, 0x0E, 0x66, 0x1A, 0x84, 0xA3, 0xA3, 0xA3, 0xD7, 0xB4, 0x92, 0x87, 0xAF, 0x8A, 0x5D, 0x6A, 0x6B, 0x6B, 0xB1, 0xD9, 0x6C, 0x34, 0x34, 0x34, 0x00, 0x5F, 0xA5, 0xA5, 0x15, 0x15, 0x15, 0xA1, 0x56, 0xAB, 0x09, 0x87, 0xC3, 0x4C, 0x4F, 0x4F, 0x93, 0x4E, 0xA7, 0xA9, 0xA9, 0xA9, 0x61, 0xC5, 0x8A, 0x15, 0x14, 0x16, 0x16, 0x2E, 0x68, 0xFB, 0xBC, 0x1C, 0x00, 0x6E, 0xA1, 0xFC, 0xF7, 0xBF, 0xFF, 0xA5, 0xBF, 0xBF, 0x9F, 0xAA, 0xAA, 0x2A, 0x76, 0xEC, 0xD8, 0x41, 0x51, 0x51, 0x11, 0x53, 0x53, 0x53, 0x0C, 0x0D, 0x0D, 0xD1, 0xDD, 0xDD, 0x2D, 0x5B, 0xD7, 0xDC, 0x75, 0xD7, 0x5D, 0xFC, 0xE2, 0x17, 0xBF, 0xE0, 0xA1, 0x87, 0x1E, 0xC2, 0xE3, 0xF1, 0xE0, 0xF5, 0x7A, 0x17, 0xAC, 0xDF, 0x40, 0xCE, 0x0D, 0xBC, 0x49, 0x5E, 0x81, 0x56, 0xAB, 0x95, 0xAF, 0xBC, 0xBC, 0x3C, 0x74, 0x3A, 0x1D, 0x13, 0x13, 0x13, 0x9C, 0x3E, 0x7D, 0x9A, 0x73, 0xE7, 0xCE, 0x91, 0x4E, 0xA7, 0xA9, 0xAC, 0xAC, 0xA4, 0xB5, 0xB5, 0x95, 0x64, 0x32, 0x89, 0xC3, 0xE1, 0x90, 0x4D, 0xB5, 0x5F, 0x79, 0xE5, 0x15, 0x1E, 0x7F, 0xFC, 0x71, 0xCC, 0x66, 0x33, 0xA7, 0x4F, 0x9F, 0xE6, 0xC2, 0x85, 0x0B, 0x44, 0xA3, 0xD1, 0x6B, 0x52, 0xD6, 0x73, 0x1A, 0x60, 0x89, 0xF3, 0x02, 0x62, 0x69, 0x98, 0x9B, 0xEF, 0x27, 0xFA, 0x0F, 0x08, 0x55, 0x2F, 0xCA, 0xDB, 0xDA, 0xDB, 0xDB, 0xF9, 0xF5, 0xAF, 0x7F, 0xCD, 0x83, 0x0F, 0x3E, 0xC8, 0xD0, 0xD0, 0x10, 0x1F, 0x7E, 0xF8, 0x21, 0xFF, 0xFC, 0xE7, 0x3F, 0xB9, 0x7A, 0xF5, 0x2A, 0xD1, 0x68, 0x54, 0xA6, 0xA7, 0xDF, 0x08, 0x2B, 0x98, 0xF3, 0x02, 0x6E, 0x81, 0x5D, 0x20, 0xC0, 0x20, 0xCA, 0xC3, 0x04, 0x1F, 0xA0, 0xD1, 0x68, 0x28, 0x2E, 0x2E, 0x26, 0x12, 0x89, 0xA0, 0x56, 0xAB, 0x79, 0xF4, 0xD1, 0x47, 0xF9, 0xC1, 0x0F, 0x7E, 0x40, 0x34, 0x1A, 0xE5, 0xF5, 0xD7, 0x5F, 0xE7, 0x8D, 0x37, 0xDE, 0xA0, 0xBB, 0xBB, 0x9B, 0x70, 0x38, 0x2C, 0x5B, 0xEE, 0xDC, 0x70, 0xAB, 0x3C, 0x72, 0x19, 0x41, 0xB7, 0x9C, 0x30, 0x12, 0xE0, 0x68, 0x6E, 0x6E, 0x66, 0xD3, 0xA6, 0x4D, 0xD8, 0x6C, 0x36, 0xF2, 0xF3, 0xF3, 0x69, 0x6A, 0x6A, 0xA2, 0xB8, 0xB8, 0x98, 0xA3, 0x47, 0x8F, 0xF2, 0xDA, 0x6B, 0xAF, 0x31, 0x38, 0x38, 0x78, 0x4D, 0x27, 0xF5, 0x1B, 0xCD, 0x0C, 0xCA, 0x69, 0x80, 0x25, 0xA0, 0x19, 0x44, 0x0C, 0x40, 0x14, 0x82, 0xE4, 0xE7, 0xE7, 0x63, 0xB1, 0x58, 0xF0, 0xF9, 0x7C, 0x1C, 0x3D, 0x7A, 0x94, 0x0F, 0x3F, 0xFC, 0x50, 0x96, 0x9F, 0x8B, 0xFC, 0x83, 0x85, 0x4A, 0x0C, 0xC9, 0x69, 0x80, 0x25, 0x22, 0x22, 0x0F, 0x30, 0x2F, 0x2F, 0x0F, 0x8B, 0xC5, 0x82, 0xD1, 0x68, 0x24, 0x9D, 0x4E, 0xE3, 0xF3, 0xF9, 0x70, 0xB9, 0x5C, 0x59, 0xDB, 0xF1, 0x2C, 0x64, 0x62, 0x48, 0x0E, 0x00, 0xCB, 0x44, 0x04, 0xDB, 0xB7, 0xD0, 0x19, 0x41, 0x39, 0x00, 0x2C, 0x23, 0x0D, 0x31, 0xD7, 0x98, 0xCC, 0x11, 0x41, 0xB7, 0xE1, 0x20, 0xCF, 0x57, 0x14, 0x3A, 0xB7, 0xE5, 0x6D, 0x4E, 0x03, 0xDC, 0x01, 0x33, 0xFD, 0xEB, 0xDC, 0xC8, 0x1C, 0x00, 0x72, 0xB2, 0x60, 0x92, 0xA3, 0x82, 0x73, 0x00, 0xC8, 0x49, 0x0E, 0x00, 0x39, 0xC9, 0x01, 0x20, 0x27, 0x39, 0x00, 0xE4, 0x24, 0x07, 0x80, 0x9C, 0xE4, 0x00, 0x90, 0x93, 0x1C, 0x00, 0x72, 0x92, 0x03, 0x40, 0x4E, 0x72, 0x00, 0xC8, 0x49, 0x0E, 0x00, 0x39, 0xC9, 0x01, 0x20, 0x27, 0xB7, 0xB7, 0xFC, 0x7F, 0x8D, 0xB9, 0xE3, 0x4F, 0xF5, 0x3B, 0xC2, 0xED, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82};
static ID3D11ShaderResourceView* syncLogoTexture=nullptr;
static HICON syncLogoIcon=nullptr;

static bool loadSyncLogo() {
    IWICImagingFactory* factory=nullptr;
    IWICStream* stream=nullptr;
    IWICBitmapDecoder* decoder=nullptr;
    IWICBitmapFrameDecode* frame=nullptr;
    IWICFormatConverter* converter=nullptr;
    bool ok=false;
    HRESULT cohr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(FAILED(cohr) && cohr!=RPC_E_CHANGED_MODE) return false;
    do {
        if(FAILED(CoCreateInstance(CLSID_WICImagingFactory,nullptr,CLSCTX_INPROC_SERVER,
           IID_PPV_ARGS(&factory))))break;
        if(FAILED(factory->CreateStream(&stream)))break;
        if(FAILED(stream->InitializeFromMemory(
            const_cast<BYTE*>(syncLogoPng),static_cast<DWORD>(sizeof(syncLogoPng)))))break;
        if(FAILED(factory->CreateDecoderFromStream(stream,nullptr,WICDecodeMetadataCacheOnLoad,&decoder)))break;
        if(FAILED(decoder->GetFrame(0,&frame)))break;
        if(FAILED(factory->CreateFormatConverter(&converter)))break;
        if(FAILED(converter->Initialize(frame,GUID_WICPixelFormat32bppRGBA,
            WICBitmapDitherTypeNone,nullptr,0,WICBitmapPaletteTypeCustom)))break;
        UINT w=0,h=0;
        if(FAILED(converter->GetSize(&w,&h)) || !w || !h)break;
        std::vector<BYTE> pixels(static_cast<size_t>(w)*h*4);
        if(FAILED(converter->CopyPixels(nullptr,w*4,static_cast<UINT>(pixels.size()),pixels.data())))break;
        D3D11_TEXTURE2D_DESC desc{};
        desc.Width=w;desc.Height=h;desc.MipLevels=1;desc.ArraySize=1;
        desc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;desc.SampleDesc.Count=1;
        desc.Usage=D3D11_USAGE_DEFAULT;desc.BindFlags=D3D11_BIND_SHADER_RESOURCE;
        D3D11_SUBRESOURCE_DATA data{};
        data.pSysMem=pixels.data();data.SysMemPitch=w*4;
        ID3D11Texture2D* texture=nullptr;
        if(SUCCEEDED(device->CreateTexture2D(&desc,&data,&texture))) {
            device->CreateShaderResourceView(texture,nullptr,&syncLogoTexture);
            texture->Release();
        }
        // Windows window/taskbar icon using the same embedded artwork.
        BITMAPV5HEADER bh{};
        bh.bV5Size=sizeof(bh);bh.bV5Width=static_cast<LONG>(w);
        bh.bV5Height=-static_cast<LONG>(h);bh.bV5Planes=1;
        bh.bV5BitCount=32;bh.bV5Compression=BI_BITFIELDS;
        bh.bV5RedMask=0x00FF0000;bh.bV5GreenMask=0x0000FF00;
        bh.bV5BlueMask=0x000000FF;bh.bV5AlphaMask=0xFF000000;
        void* bits=nullptr;
        HDC dc=GetDC(nullptr);
        HBITMAP color=CreateDIBSection(dc,reinterpret_cast<BITMAPINFO*>(&bh),
            DIB_RGB_COLORS,&bits,nullptr,0);
        ReleaseDC(nullptr,dc);
        if(color && bits) {
            auto* dst=static_cast<BYTE*>(bits);
            for(size_t i=0;i<static_cast<size_t>(w)*h;i++) {
                dst[i*4+0]=pixels[i*4+2];
                dst[i*4+1]=pixels[i*4+1];
                dst[i*4+2]=pixels[i*4+0];
                dst[i*4+3]=pixels[i*4+3];
            }
            HBITMAP mask=CreateBitmap(w,h,1,1,nullptr);
            if(mask) {
                ICONINFO info{};
                info.fIcon=TRUE;info.hbmColor=color;info.hbmMask=mask;
                syncLogoIcon=CreateIconIndirect(&info);
                DeleteObject(mask);
            }
            DeleteObject(color);
        }
        if(syncLogoIcon) {
            SendMessageW(hwnd,WM_SETICON,ICON_BIG,reinterpret_cast<LPARAM>(syncLogoIcon));
            SendMessageW(hwnd,WM_SETICON,ICON_SMALL,reinterpret_cast<LPARAM>(syncLogoIcon));
        }
        ok=syncLogoTexture!=nullptr;
    }while(false);
    if(converter)converter->Release();
    if(frame)frame->Release();
    if(decoder)decoder->Release();
    if(stream)stream->Release();
    if(factory)factory->Release();
    return ok;
}

static std::vector<Process> processes;
static std::vector<FileResult> files;
struct TimelineEvent {
    std::string timestamp, source, eventId, description, detail;
    bool alert=false;
};
static std::vector<TimelineEvent> timelineEvents;
static std::atomic<size_t> timelineCount{0};
static std::vector<Record> records;
static std::atomic<int> defenderAlerts{0};
static std::atomic<bool> defenderNotificationPending{false};
static std::atomic<bool> cancelRequested{false};
static std::mutex dataMutex;
static std::atomic<bool> scanning{false};
static std::atomic<bool> done{false};
static std::atomic<int> stage{0};
static std::string status="Ready for inspection";
static int page=0;
static bool confirmScan=false;

static std::atomic<bool> scanFailed{false};
static std::atomic<bool> scanCancelled{false};
static std::atomic<int> completedStages{0};
static std::atomic<int> totalStages{6};
static std::atomic<size_t> processCount{0}, recordCount{0}, fileCount{0};
static std::atomic<size_t> peFilesInspected{0};
static std::wstring executablePath();
static int accentIndex=0, themeIndex=0, densityIndex=2;
static float interfaceScale=1.0f;
static int windowPreset=2;
static const char* windowPresetNames[]={"1024 x 720","1280 x 800","1440 x 900",
    "1600 x 900","1920 x 1080"};
static void applyWindowPreset(){
    static const int dims[][2]={{1024,720},{1280,800},{1440,900},{1600,900},{1920,1080}};
    int index=std::clamp(windowPreset,0,4);
    RECT work{};SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);
    int availableW=work.right-work.left,availableH=work.bottom-work.top;
    int w=(std::min)(dims[index][0],availableW);
    int h=(std::min)(dims[index][1],availableH);
    if(hwnd&&w>0&&h>0)SetWindowPos(hwnd,nullptr,
        work.left+(availableW-w)/2,work.top+(availableH-h)/2,
        w,h,SWP_NOZORDER|SWP_NOACTIVATE);
}
static bool highlightSuspicious=true, showSecurityWarnings=true;
static bool brandAnimation=true, showNavHover=true;
static bool ambientMotesEnabled=true;
static bool reducedMotion=false;
static int rainDensity=1; // 0 light, 1 balanced, 2 dense
static const char* rainDensityNames[]={"Light","Balanced","Dense"};
static int cornerStyle=1, scrollbarWidth=1;
static const char* cornerStyleNames[]={"Square","Soft","Rounded"};
static const char* scrollbarWidthNames[]={"Thin","Standard","Wide"};
static ImVec4 customAccent(.98f,.43f,.15f,1.f);
static bool settingsNotice=false;
static const char* accentNames[]={"Orange","Red","Blue","Purple","Green","Custom"};
static const char* themeNames[]={"Obsidian","Graphite","Charcoal"};
static const char* densityNames[]={"Compact","Comfortable","Spacious"};
// This preference changes ONLY the percentage label in the scan progress
// bar. All other UI elements stay strictly black, white and gray.
static ImVec4 accentColor() {
    switch(accentIndex){
        case 0:return ImVec4(.98f,.48f,.20f,1.f); // Orange
        case 1:return ImVec4(.96f,.28f,.31f,1.f); // Red
        case 2:return ImVec4(.39f,.67f,1.f,1.f);  // Blue
        case 3:return ImVec4(.72f,.49f,.98f,1.f); // Purple
        case 4:return ImVec4(.38f,.85f,.56f,1.f); // Green
        case 5:return ImVec4(customAccent.x,customAccent.y,customAccent.z,1.f);
        default:return ImVec4(1.f,1.f,1.f,1.f);
    }
}
static int displayLanguage=0; // 0 English, 1 Português (Brasil)
static const char* localized(const char* english){
    if(displayLanguage!=1 || !english)return english;
    static const std::unordered_map<std::string,std::string> labels={
        {"DASHBOARD","PAINEL"},
        {"THREAT ANALYSIS","ANÁLISE DE AMEAÇAS"},
        {"EVENT RECORDS","REGISTROS DE EVENTOS"},
        {"BINARY LAB","LABORATÓRIO BINÁRIO"},
        {"NETWORK","REDE"},
        {"DRIVER AUDIT","AUDITORIA DE DRIVERS"},
        {"ARTIFACT EXPLORER","EXPLORADOR DE ARTEFATOS"},
        {"KERNEL MEMORY DUMP","DUMP DE MEMÓRIA"},
        {"PREFERENCES","PREFERÊNCIAS"},
        {"Workspace Preferences","Preferências do ambiente"},
        {"Adjust appearance and investigation options","Ajuste a aparência e as opções de investigação"},
        {"PERSONALIZATION  /  LOCAL SETTINGS","PERSONALIZAÇÃO  /  CONFIGURAÇÕES LOCAIS"},
        {"Customize the scanner appearance and investigation workflow.","Personalize a aparência e o fluxo de investigação do scanner."},
        {"LANGUAGE","IDIOMA"},
        {"APPEARANCE","APARÊNCIA"},
        {"INTERFACE DETAILS","DETALHES DA INTERFACE"},
        {"PROCESS REVIEW","REVISÃO DE PROCESSOS"},
        {"Scan Percentage Color","Cor da porcentagem do scan"},
        {"Theme","Tema"},
        {"Interface Scale","Escala da interface"},
        {"Table Density","Densidade das tabelas"},
        {"Window size (maximum 1920 x 1080)","Tamanho da janela (máximo 1920 x 1080)"},
        {"Size is limited to the available desktop work area.","O tamanho é limitado à área disponível da tela."},
        {"Custom percentage color","Cor personalizada da porcentagem"},
        {"Animate scanner branding","Animar identidade visual do scanner"},
        {"Monochrome rain across the window","Chuva monocromática na janela"},
        {"Rain density","Densidade da chuva"},
        {"Reduce motion (disable transition and unlock animations)","Reduzir movimento (desativar transições e animações)"},
        {"Highlight navigation on hover","Destacar navegação ao passar o mouse"},
        {"Button corners","Cantos dos botões"},
        {"Scrollbar width","Largura da barra de rolagem"},
        {"Highlight suspicious processes in red","Destacar processos suspeitos em vermelho"},
        {"Show security assessment details","Mostrar detalhes da avaliação de segurança"},
        {"Save Settings","Salvar configurações"},
        {"Restore Defaults","Restaurar padrões"},
        {"Settings saved successfully.","Configurações salvas com sucesso."},
        {"Verify Scanner Executable","Verificar executável do scanner"},
        {"FULL INSPECTION  /  VERIFIED PROGRESS","INSPEÇÃO COMPLETA  /  PROGRESSO"},
        {"SYSTEM INTEGRITY","INTEGRIDADE DO SISTEMA"},
        {"EXECUTION ARTIFACTS","ARTEFATOS DE EXECUÇÃO"},
        {"PROCESS ANALYSIS","ANÁLISE DE PROCESSOS"},
        {"EVIDENCE CORRELATION","CORRELAÇÃO DE EVIDÊNCIAS"},
        {"INSPECTION COMPLETE","INSPEÇÃO CONCLUÍDA"},
        {"READY","PRONTO"},
        {"INSPECTION FAILED","INSPEÇÃO FALHOU"},
        {"INSPECTION CANCELLED","INSPEÇÃO CANCELADA"},
        {"PREPARING RESULTS","PREPARANDO RESULTADOS"},
        {"FINALIZING INSPECTION","FINALIZANDO INSPEÇÃO"},
        {"FULL INSPECTION IN PROGRESS","INSPEÇÃO COMPLETA EM ANDAMENTO"},
        {"START FULL INSPECTION","INICIAR INSPEÇÃO COMPLETA"},
        {"GO TO DASHBOARD","IR PARA O PAINEL"},
        {"RUN A FULL INSPECTION","EXECUTAR INSPEÇÃO COMPLETA"},
        {"Results unlock after inspection completes at 100%.","Os resultados são liberados quando a inspeção chega a 100%."},
        {"Run a full inspection to unlock this section.","Execute uma inspeção completa para liberar esta seção."},
        {"FINALIZING INSPECTION","FINALIZANDO INSPEÇÃO"},
        {"No scan results yet.","Ainda não há resultados de scan."},
        {"Changes only the 0-100%% number; the interface stays monochrome.","Altera apenas o número de 0 a 100%%; a interface permanece monocromática."},
        {"Animations are visual only; scanning is unaffected.","As animações são apenas visuais; a análise não é afetada."}
    };
    const auto it=labels.find(english);
    return it!=labels.end()?it->second.c_str():english;
}
static fs::path settingsPath() {
    wchar_t appdata[32768]{};
    DWORD n=GetEnvironmentVariableW(L"APPDATA",appdata,32768);
    if(n>0 && n<32768) return fs::path(appdata)/L"SyncPCChecker"/L"settings.ini";
    return fs::path(executablePath()).parent_path()/L"settings.ini";
}
static void saveSettings() {
    try {
        auto path=settingsPath();
        fs::create_directories(path.parent_path());
        std::ofstream out(path,std::ios::trunc);
        if(!out) {settingsNotice=false;return;}
        out<<"language="<<displayLanguage<<"\n"<<"accent="<<accentIndex<<"\n"<<"theme="<<themeIndex<<"\n"
           <<"density="<<densityIndex<<"\n"<<"scale="<<interfaceScale<<"\n"
           <<"window="<<windowPreset<<"\n"
           <<"highlight="<<highlightSuspicious<<"\n"
           <<"warnings="<<showSecurityWarnings<<"\n"
           <<"custom_r="<<customAccent.x<<"\n"
           <<"custom_g="<<customAccent.y<<"\n"
           <<"custom_b="<<customAccent.z<<"\n";
        settingsNotice=(bool)out;
    } catch(...) {settingsNotice=false;}
}
static void loadSettings() {
    std::ifstream in(settingsPath());
    std::string line;
    try {
        while(std::getline(in,line)) {
            auto pos=line.find('=');
            if(pos==std::string::npos)continue;
            auto key=line.substr(0,pos),v=line.substr(pos+1);
            if(key=="language")displayLanguage=std::clamp(std::stoi(v),0,1);
            else if(key=="accent")accentIndex=std::clamp(std::stoi(v),0,5);
            else if(key=="theme")themeIndex=std::clamp(std::stoi(v),0,2);
            else if(key=="density")densityIndex=std::clamp(std::stoi(v),0,2);
            else if(key=="scale")interfaceScale=std::clamp(std::stof(v),0.95f,1.10f);
            else if(key=="window")windowPreset=std::clamp(std::stoi(v),0,4);
            else if(key=="highlight")highlightSuspicious=(v=="1");
            else if(key=="warnings")showSecurityWarnings=(v=="1");
            else if(key=="brand_animation")brandAnimation=(v=="1");
            else if(key=="ambient_motes")ambientMotesEnabled=(v=="1");
            else if(key=="nav_hover")showNavHover=(v=="1");
            else if(key=="corners")cornerStyle=std::clamp(std::stoi(v),0,2);
            else if(key=="scrollbar")scrollbarWidth=std::clamp(std::stoi(v),0,2);
            else if(key=="custom_r")customAccent.x=std::clamp(std::stof(v),0.f,1.f);
            else if(key=="custom_g")customAccent.y=std::clamp(std::stof(v),0.f,1.f);
            else if(key=="custom_b")customAccent.z=std::clamp(std::stof(v),0.f,1.f);
        }
    } catch(...) {}
}
static bool showUnavailable=true;
static char fileInput[2048]="";
static char searchInput[256]="";

static std::string utf8(const std::wstring& s) {
    if(s.empty()) return {};
    int n=WideCharToMultiByte(CP_UTF8,0,s.c_str(),-1,nullptr,0,nullptr,nullptr);
    if(n<=0) return {};
    std::string out(n,'\0');
    WideCharToMultiByte(CP_UTF8,0,s.c_str(),-1,out.data(),n,nullptr,nullptr);
    out.pop_back();
    return out;
}
static std::wstring wide(const std::string& s) {
    if(s.empty()) return {};
    int n=MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,nullptr,0);
    if(n<=0) return {};
    std::wstring out(n,L'\0');
    MultiByteToWideChar(CP_UTF8,0,s.c_str(),-1,out.data(),n);
    out.pop_back();
    return out;
}
static std::wstring executablePath() {
    wchar_t buf[32768]{};
    DWORD n=GetModuleFileNameW(nullptr,buf,32768);
    return n?std::wstring(buf,n):L"";
}
// Query several documented Windows APIs without bypassing process protection.
static bool isResolvedPath(const std::wstring& path) {
    return path.size()>2 && path[1]==L':' && path[2]==L'\\';
}
static std::wstring devicePathToDos(const std::wstring& nativePath) {
    if(nativePath.empty()) return {};
    wchar_t drives[512]{};
    DWORD n=GetLogicalDriveStringsW(512,drives);
    if(n==0 || n>=512)return nativePath;
    for(const wchar_t* drive=drives;*drive;drive+=wcslen(drive)+1) {
        wchar_t device[1024]{};
        wchar_t letter[3]={drive[0],L':',0};
        if(!QueryDosDeviceW(letter,device,1024))continue;
        const size_t prefix=wcslen(device);
        if(nativePath.size()>=prefix &&
           _wcsnicmp(nativePath.c_str(),device,prefix)==0 &&
           (nativePath.size()==prefix || nativePath[prefix]==L'\\')) {
            return std::wstring(letter)+nativePath.substr(prefix);
        }
    }
    return nativePath;
}
static std::wstring processPath(DWORD pid) {
    if(pid==0)return L"[Idle process - no executable image]";
    if(pid==4)return L"[Windows kernel process - protected image]";
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    DWORD openError=h?ERROR_SUCCESS:GetLastError();
    if(h) {
        wchar_t buffer[32768]{};
        DWORD length=32768;
        if(QueryFullProcessImageNameW(h,0,buffer,&length)) {
            CloseHandle(h);
            return std::wstring(buffer,length);
        }
        // PSAPI may expose a native device path when the first query fails.
        DWORD chars=GetProcessImageFileNameW(h,buffer,32768);
        CloseHandle(h);
        if(chars)return devicePathToDos(std::wstring(buffer,chars));
    }
    // A module snapshot can sometimes resolve the main image independently.
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if(snap!=INVALID_HANDLE_VALUE) {
        MODULEENTRY32W module{};module.dwSize=sizeof(module);
        if(Module32FirstW(snap,&module)) {
            std::wstring result=module.szExePath;
            CloseHandle(snap);
            if(!result.empty())return result;
        } else CloseHandle(snap);
    }
    if(openError==ERROR_ACCESS_DENIED)
        return L"[Protected process - Windows denied image path access]";
    if(openError==ERROR_INVALID_PARAMETER)
        return L"[Process exited or is not queryable]";
    return L"[Image path not exposed by Windows APIs]";
}
static std::vector<Process> enumerateProcesses() {
    std::vector<Process> result;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE) return result;
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);
    if(Process32FirstW(snap,&entry)) {
        do {
            result.push_back({entry.th32ProcessID,entry.th32ParentProcessID,
                              entry.szExeFile,processPath(entry.th32ProcessID)});
        } while(Process32NextW(snap,&entry));
    }
    CloseHandle(snap);
    return result;
}
// Conservative, explainable checks. A warning is an indicator, not a malware verdict.
static std::wstring lowerPath(std::wstring value) {
    std::transform(value.begin(),value.end(),value.begin(),
        [](wchar_t c){return (wchar_t)towlower(c);});
    return value;
}
static bool pathContains(const std::wstring& path,const wchar_t* segment) {
    return path.find(segment)!=std::wstring::npos;
}
static bool startsWithPath(const std::wstring& path,const std::wstring& root) {
    if(root.empty() || path.size()<root.size())return false;
    if(path.compare(0,root.size(),root)!=0)return false;
    return path.size()==root.size() || root.back()==L'\\' || path[root.size()]==L'\\';
}
static std::wstring windowsRoot() {
    wchar_t buffer[MAX_PATH]{};
    UINT count=GetWindowsDirectoryW(buffer,MAX_PATH);
    if(!count || count>=MAX_PATH)return L"c:\\windows";
    return lowerPath(std::wstring(buffer,count));
}
static void appendWarning(std::string& warnings,const char* warning) {
    if(!warnings.empty())warnings+=" | ";
    warnings+=warning;
}
static void assessProcess(Process& process,const std::wstring& winRoot) {
    process.suspicious=false;
    process.assessment="No suspicious path indicators observed";
    if(process.path.empty() || process.path[0]==L'[') {
        process.assessment="Executable path inaccessible; no conclusion";
        return;
    }
    const std::wstring path=lowerPath(process.path);
    const std::wstring name=lowerPath(process.name);
    const bool inWindows=startsWithPath(path,winRoot);
    std::string warnings;
    if(pathContains(path,L"\\appdata\\local\\temp\\") ||
       pathContains(path,L"\\windows\\temp\\") ||
       pathContains(path,L"\\temp\\")) {
        appendWarning(warnings,"Executable running from a temporary directory");
    }
    if(pathContains(path,L"\\downloads\\") ||
       pathContains(path,L"\\recycle.bin\\")) {
        appendWarning(warnings,"Executable launched from a user download or recycle location");
    }
    // Only names that are normally Windows-owned are checked for impersonation.
    static const std::unordered_set<std::wstring> systemNames={
        L"lsass.exe",L"services.exe",L"winlogon.exe",L"smss.exe",
        L"csrss.exe",L"wininit.exe",L"svchost.exe",L"spoolsv.exe"
    };
    if(systemNames.count(name) && !inWindows)
        appendWarning(warnings,"Windows system process name used outside the Windows directory");
    if(pathContains(path,L".exe.exe") || pathContains(path,L".pdf.exe") ||
       pathContains(path,L".jpg.exe") || pathContains(path,L".txt.exe"))
        appendWarning(warnings,"Executable has a potentially misleading double extension");
    if(pathContains(path,L"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\"))
        appendWarning(warnings,"Executable resides in a user Startup folder");
    if(pathContains(path,L"\\users\\public\\") && !inWindows)
        appendWarning(warnings,"Executable is located in a shared user-writable directory");
    if(pathContains(path,L"\\programdata\\") && !inWindows &&
       !pathContains(path,L"\\programdata\\microsoft\\windows defender\\"))
        appendWarning(warnings,"Executable is located in ProgramData; verify publisher and purpose");
    if(path.rfind(L"\\\\",0)==0)
        appendWarning(warnings,"Executable path is a network location");
    DWORD attrs=GetFileAttributesW(process.path.c_str());
    if(attrs!=INVALID_FILE_ATTRIBUTES && (attrs&FILE_ATTRIBUTE_REPARSE_POINT))
        appendWarning(warnings,"Executable path is a reparse point; verify target");
    if(attrs!=INVALID_FILE_ATTRIBUTES && (attrs&FILE_ATTRIBUTE_HIDDEN))
        appendWarning(warnings,"Executable has the hidden file attribute");
    if(!warnings.empty()) {
        process.suspicious=true;
        process.assessment=warnings+"; manual review recommended";
    }
}
static std::string sha256(const std::wstring& path) {
    HANDLE f=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                         nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(f==INVALID_HANDLE_VALUE) return "Unavailable";
    BCRYPT_ALG_HANDLE alg=nullptr;
    BCRYPT_HASH_HANDLE hash=nullptr;
    std::string result="Unavailable";
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0) {
        DWORD objectSize=0,cb=0,hashSize=0;
        if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objectSize,sizeof(objectSize),&cb,0)>=0 &&
           BCryptGetProperty(alg,BCRYPT_HASH_LENGTH,(PUCHAR)&hashSize,sizeof(hashSize),&cb,0)>=0) {
            std::vector<UCHAR> object(objectSize),digest(hashSize),buffer(65536);
            if(BCryptCreateHash(alg,&hash,object.data(),objectSize,nullptr,0,0)>=0) {
                bool ok=true;
                DWORD read=0;
                for(;;) {
                    if(!ReadFile(f,buffer.data(),(DWORD)buffer.size(),&read,nullptr)) {
                        ok=false;break;
                    }
                    if(read==0) break;
                    if(BCryptHashData(hash,buffer.data(),read,0)<0) {ok=false;break;}
                }
                if(ok && BCryptFinishHash(hash,digest.data(),hashSize,0)>=0) {
                    std::ostringstream ss;
                    for(UCHAR b:digest) ss<<std::hex<<std::setfill('0')<<std::setw(2)<<(unsigned)b;
                    result=ss.str();
                }
            }
        }
    }
    if(hash) BCryptDestroyHash(hash);
    if(alg) BCryptCloseAlgorithmProvider(alg,0);
    CloseHandle(f);
    return result;
}
static std::string signatureStatus(const std::wstring& path) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct=sizeof(fi);fi.pcwszFilePath=path.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct=sizeof(wd);
    wd.dwUIChoice=WTD_UI_NONE;
    wd.fdwRevocationChecks=WTD_REVOKE_NONE; // Offline verification; revocation not checked.
    wd.dwUnionChoice=WTD_CHOICE_FILE;
    wd.pFile=&fi;
    wd.dwStateAction=WTD_STATEACTION_VERIFY;
    wd.dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID policy=WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG code=WinVerifyTrust(nullptr,&policy,&wd);
    wd.dwStateAction=WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr,&policy,&wd);
    if(code==ERROR_SUCCESS) return "Valid (offline; revocation not checked)";
    if(code==TRUST_E_NOSIGNATURE) return "Unsigned";
    if(code==TRUST_E_BAD_DIGEST) return "Invalid digest";
    if(code==CERT_E_UNTRUSTEDROOT) return "Untrusted certificate";
    if(code==CERT_E_EXPIRED) return "Expired certificate";
    return "Not trusted / unavailable (0x"+[] (unsigned long v) {
        std::ostringstream ss;ss<<std::hex<<v;return ss.str();
    }((unsigned long)code)+")";
}
static FileResult inspectFile(const std::wstring& path) {
    FileResult r{path,"Unavailable","Unavailable"};
    if(path.empty() || !fs::exists(path)) return r;
    r.hash=sha256(path);
    r.signature=signatureStatus(path);
    return r;
}

static bool isAdministrator() {
    BOOL admin=FALSE;
    SID_IDENTIFIER_AUTHORITY nt=SECURITY_NT_AUTHORITY;
    PSID sid=nullptr;
    if(AllocateAndInitializeSid(&nt,2,SECURITY_BUILTIN_DOMAIN_RID,
       DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&sid)) {
        CheckTokenMembership(nullptr,sid,&admin);
        FreeSid(sid);
    }
    return admin!=FALSE;
}
static std::vector<Record> enumerateServices() {
    std::vector<Record> out;
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE);
    if(!scm){out.push_back({"Services","Unavailable","Access denied or SCM unavailable"});return out;}
    DWORD needed=0,count=0,resume=0;
    EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32|SERVICE_DRIVER,
      SERVICE_STATE_ALL,nullptr,0,&needed,&count,&resume,nullptr);
    if(GetLastError()==ERROR_MORE_DATA && needed>0 && needed<32*1024*1024) {
        std::vector<BYTE> buffer(needed+4096);
        resume=0;
        if(EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32|SERVICE_DRIVER,
           SERVICE_STATE_ALL,buffer.data(),(DWORD)buffer.size(),&needed,&count,&resume,nullptr)) {
            auto entries=reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
            for(DWORD i=0;i<count;i++){
                if(cancelRequested)break;
                bool driver=(entries[i].ServiceStatusProcess.dwServiceType &
                    (SERVICE_KERNEL_DRIVER|SERVICE_FILE_SYSTEM_DRIVER))!=0;
                std::string state=entries[i].ServiceStatusProcess.dwCurrentState==SERVICE_RUNNING?"Running":"Not running";
                out.push_back({driver?"Drivers":"Services",utf8(entries[i].lpServiceName),
                               utf8(entries[i].lpDisplayName)+" | "+state});
            }
        } else out.push_back({"Services","Partial","Enumeration failed"});
    } else out.push_back({"Services","Unavailable","Could not size service enumeration"});
    CloseServiceHandle(scm);
    return out;
}
static std::vector<Record> enumerateStartup() {
    std::vector<Record> out;
    const wchar_t* keys[]={
       L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
       L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    HKEY roots[]={HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE};
    for(HKEY root:roots)for(auto key:keys) {
        if(cancelRequested)return out;
        HKEY h=nullptr;
        if(RegOpenKeyExW(root,key,0,KEY_READ,&h)!=ERROR_SUCCESS)continue;
        for(DWORD i=0;i<4096;i++){
            wchar_t name[512]{};
            DWORD nameLen=512;
            BYTE data[8192]{};
            DWORD dataLen=sizeof(data),type=0;
            LONG rc=RegEnumValueW(h,i,name,&nameLen,nullptr,&type,data,&dataLen);
            if(rc==ERROR_NO_MORE_ITEMS)break;
            if(rc!=ERROR_SUCCESS)continue;
            std::wstring value;
            if((type==REG_SZ||type==REG_EXPAND_SZ) && dataLen>=sizeof(wchar_t)){
                auto ptr=reinterpret_cast<const wchar_t*>(data);
                size_t chars=dataLen/sizeof(wchar_t);
                value.assign(ptr,ptr+wcsnlen_s(ptr,chars));
            } else value=L"(non-string value)";
            out.push_back({"Startup",utf8(name),utf8(value)});
        }
        RegCloseKey(h);
    }
    return out;
}
static std::vector<Record> enumerateTcp() {
    std::vector<Record> out;
    DWORD bytes=0;
    DWORD rc=GetExtendedTcpTable(nullptr,&bytes,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    if(rc!=ERROR_INSUFFICIENT_BUFFER || bytes>32*1024*1024)return out;
    std::vector<BYTE> buffer(bytes);
    rc=GetExtendedTcpTable(buffer.data(),&bytes,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    if(rc!=NO_ERROR){out.push_back({"Network","Unavailable","TCP table could not be read"});return out;}
    auto table=reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    for(DWORD i=0;i<table->dwNumEntries;i++){
        if(cancelRequested)break;
        const auto& e=table->table[i];
        IN_ADDR local{},remote{};
        local.S_un.S_addr=e.dwLocalAddr;remote.S_un.S_addr=e.dwRemoteAddr;
        char a[INET_ADDRSTRLEN]{},b[INET_ADDRSTRLEN]{};
        InetNtopA(AF_INET,&local,a,sizeof(a));
        InetNtopA(AF_INET,&remote,b,sizeof(b));
        auto port=[](DWORD p){return (unsigned)ntohs((u_short)p);};
        std::ostringstream detail;
        detail<<a<<":"<<port(e.dwLocalPort)<<" -> "<<b<<":"<<port(e.dwRemotePort)
              <<" | state "<<e.dwState;
        out.push_back({"Network","PID "+std::to_string(e.dwOwningPid),detail.str()});
    }
    return out;
}


// Read-only historical USB device inventory from multiple registry sources.
// Registry key modification timestamps are NOT USB connection timestamps.
static std::vector<Record> enumerateUsbStorage() {
    std::vector<Record> out;
    const struct {const wchar_t* key;const char* label;} sources[]={
        {L"SYSTEM\CurrentControlSet\Enum\USBSTOR","USBSTOR"},
        {L"SYSTEM\CurrentControlSet\Enum\USB","USB Enum"}
    };
    for(const auto& source:sources){
        HKEY root=nullptr;
        const LONG rc=RegOpenKeyExW(HKEY_LOCAL_MACHINE,source.key,0,
                                   KEY_ENUMERATE_SUB_KEYS,&root);
        if(rc!=ERROR_SUCCESS){
            out.push_back({"USB Coverage",source.label,
                "Registry enumeration unavailable | Win32 error="+std::to_string(rc)+
                " | Run with appropriate access; absence of records is not absence of devices."});
            continue;
        }
        size_t found=0;
        for(DWORD i=0;i<1024 && !cancelRequested;i++){
            wchar_t device[512]{};
            DWORD length=512;
            LONG result=RegEnumKeyExW(root,i,device,&length,nullptr,nullptr,nullptr,nullptr);
            if(result==ERROR_NO_MORE_ITEMS)break;
            if(result!=ERROR_SUCCESS)continue;
            HKEY typeKey=nullptr;
            if(RegOpenKeyExW(root,device,0,KEY_ENUMERATE_SUB_KEYS,&typeKey)!=ERROR_SUCCESS)
                continue;
            for(DWORD j=0;j<512 && !cancelRequested;j++){
                wchar_t instance[512]{};
                DWORD n=512;
                FILETIME lastWrite{};
                LONG r=RegEnumKeyExW(typeKey,j,instance,&n,nullptr,nullptr,nullptr,&lastWrite);
                if(r==ERROR_NO_MORE_ITEMS)break;
                if(r!=ERROR_SUCCESS)continue;
                ++found;
                out.push_back({"USB",utf8(device),
                    std::string("Source: ")+source.label+
                    " | Instance: "+utf8(instance)+
                    " | Registry entry (historical inventory, NOT a confirmed recent connection)"});
            }
            RegCloseKey(typeKey);
        }
        RegCloseKey(root);
        if(found==0)
            out.push_back({"USB Coverage",source.label,
                "No accessible device instances in this registry source; other USB device classes may exist."});
    }
    // MountedDevices can preserve historical volume mappings, but not exact attach times.
    HKEY mounted=nullptr;
    const LONG mountedRc=RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\MountedDevices",0,KEY_QUERY_VALUE,&mounted);
    if(mountedRc==ERROR_SUCCESS){
        size_t found=0;
        for(DWORD i=0;i<512 && !cancelRequested;i++){
            wchar_t value[512]{};
            DWORD n=512;
            LONG r=RegEnumValueW(mounted,i,value,&n,nullptr,nullptr,nullptr,nullptr);
            if(r==ERROR_NO_MORE_ITEMS)break;
            if(r!=ERROR_SUCCESS)continue;
            ++found;
            out.push_back({"USB Volume History",utf8(value),
                "MountedDevices historical volume mapping; not necessarily USB and not a connection timestamp."});
        }
        RegCloseKey(mounted);
        if(!found)out.push_back({"USB Coverage","MountedDevices","No accessible volume mappings."});
    }else{
        out.push_back({"USB Coverage","MountedDevices",
            "Volume mapping registry unavailable | Win32 error="+std::to_string(mountedRc)});
    }
    return out;
}

// UDP IPv4 endpoints and owning processes, using the Windows IP Helper API.
static std::vector<Record> enumerateUdp() {
    std::vector<Record> out;
    DWORD bytes=0;
    DWORD rc=GetExtendedUdpTable(nullptr,&bytes,FALSE,AF_INET,UDP_TABLE_OWNER_PID,0);
    if(rc!=ERROR_INSUFFICIENT_BUFFER || bytes==0)return out;
    std::vector<unsigned char> buffer(bytes);
    rc=GetExtendedUdpTable(buffer.data(),&bytes,FALSE,AF_INET,UDP_TABLE_OWNER_PID,0);
    if(rc!=NO_ERROR) {
        out.push_back({"Network","UDP unavailable","Windows IP Helper API returned an error"});
        return out;
    }
    auto* table=reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
    for(DWORD i=0;i<table->dwNumEntries && !cancelRequested;i++) {
        const auto& e=table->table[i];
        IN_ADDR addr{};
        addr.S_un.S_addr=e.dwLocalAddr;
        char ip[INET_ADDRSTRLEN]{};
        InetNtopA(AF_INET,&addr,ip,sizeof(ip));
        std::ostringstream detail;
        detail<<ip<<":"<<(unsigned)ntohs(static_cast<u_short>(e.dwLocalPort));
        out.push_back({"Network UDP","PID "+std::to_string(e.dwOwningPid),detail.str()});
    }
    return out;
}


// IPv6 TCP owner inventory. Endpoints are read using the Windows IP Helper API.
static std::vector<Record> enumerateTcp6() {
    // Windows TCP_OWNER_PID IPv6 row layout, defined locally to avoid
    // SDK-dependent MIB_TCP6ROW_OWNER_PID declarations.
    struct Tcp6OwnerRow {
        UCHAR localAddress[16];
        DWORD localScope;
        DWORD localPort;
        UCHAR remoteAddress[16];
        DWORD remoteScope;
        DWORD remotePort;
        DWORD state;
        DWORD pid;
    };
    static_assert(sizeof(Tcp6OwnerRow) == 56, "Unexpected TCP IPv6 row layout");

    std::vector<Record> out;
    DWORD bytes = 0;
    DWORD rc = GetExtendedTcpTable(nullptr, &bytes, FALSE, AF_INET6,
                                    TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(DWORD) ||
        bytes > 32u * 1024u * 1024u) return out;

    std::vector<BYTE> buffer(bytes);
    rc = GetExtendedTcpTable(buffer.data(), &bytes, FALSE, AF_INET6,
                             TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != NO_ERROR || bytes < sizeof(DWORD) || bytes > buffer.size())
        return out;

    DWORD count = 0;
    std::memcpy(&count, buffer.data(), sizeof(count));
    constexpr size_t offset = sizeof(DWORD);
    if (count > (static_cast<size_t>(bytes) - offset) / sizeof(Tcp6OwnerRow))
        return out;

    auto addressText = [](const UCHAR raw[16], DWORD scope) -> std::string {
        SOCKADDR_IN6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_scope_id = scope;
        std::memcpy(&addr.sin6_addr, raw, 16);
        char text[128]{};
        DWORD len = static_cast<DWORD>(sizeof(text));
        if (WSAAddressToStringA(reinterpret_cast<LPSOCKADDR>(&addr),
                                sizeof(addr), nullptr, text, &len) != 0)
            return "[IPv6 address unavailable]";
        return text;
    };

    WSADATA winsockData{};
    const bool winsockReady = (WSAStartup(MAKEWORD(2, 2), &winsockData) == 0);
    if (!winsockReady) return out;

    for (DWORD i = 0; i < count && !cancelRequested; ++i) {
        Tcp6OwnerRow entry{};
        std::memcpy(&entry, buffer.data() + offset +
                    static_cast<size_t>(i) * sizeof(entry), sizeof(entry));

        const std::string local = addressText(entry.localAddress, entry.localScope);
        const std::string remote = addressText(entry.remoteAddress, entry.remoteScope);
        std::ostringstream detail;
        detail << "[" << local << "]:" << ntohs(static_cast<u_short>(entry.localPort))
               << " -> [" << remote << "]:" << ntohs(static_cast<u_short>(entry.remotePort))
               << " | state " << entry.state;
        out.push_back({"Network IPv6", "PID " + std::to_string(entry.pid),
                       detail.str()});
    }
    WSACleanup();
    return out;
}


// Microsoft Defender operational event log: detection IDs 1116/1117/1118/1119.
// These are historical Defender reports, not a new malware verdict.
static std::vector<Record> enumerateDefenderDetections() {
    std::vector<Record> found;
    const wchar_t* channel=L"Microsoft-Windows-Windows Defender/Operational";
    const wchar_t* query=L"*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";
    EVT_HANDLE results=EvtQuery(nullptr,channel,query,EvtQueryChannelPath|EvtQueryReverseDirection);
    if(!results) {
        found.push_back({"Defender Status","Event log not accessible",
            "Microsoft Defender operational log could not be queried. This is not a clean result."});
        return found;
    }
    for(int page=0;page<4 && !cancelRequested;++page) {
        EVT_HANDLE events[32]{};
        DWORD count=0;
        if(!EvtNext(results,32,events,1500,0,&count))break;
        for(DWORD i=0;i<count;++i) {
            DWORD required=0,used=0;
            EvtRender(nullptr,events[i],EvtRenderEventXml,0,nullptr,&required,&used);
            if(GetLastError()==ERROR_INSUFFICIENT_BUFFER && required>0 && required<1024*1024) {
                std::vector<wchar_t> xml(required/sizeof(wchar_t)+1,L'\0');
                if(EvtRender(nullptr,events[i],EvtRenderEventXml,
                    (DWORD)(xml.size()*sizeof(wchar_t)),xml.data(),&required,&used)) {
                    std::wstring data(xml.data());
                    auto getTag=[&](const std::wstring& key)->std::wstring {
                        size_t start=data.find(key);
                        if(start==std::wstring::npos)return L"";
                        start+=key.size();
                        size_t end=data.find(L'<',start);
                        return end==std::wstring::npos?L"":data.substr(start,std::min<size_t>(end-start,400));
                    };
                    std::wstring id=getTag(L"<EventID>");
                    std::wstring timestamp;
                    size_t at=data.find(L"SystemTime='");
                    wchar_t quote=L'\'';
                    if(at==std::wstring::npos){at=data.find(L"SystemTime=\"");quote=L'"';}
                    if(at!=std::wstring::npos) {
                        at+=12;auto end=data.find(quote,at);
                        if(end!=std::wstring::npos)timestamp=data.substr(at,end-at);
                    }
                    std::wstring threat;
                    for(const wchar_t* key:{L"Threat Name",L"ThreatName",L"Name"}) {
                        std::wstring needle=L"Name='"+std::wstring(key)+L"'";
                        size_t n=data.find(needle);
                        if(n==std::wstring::npos)continue;
                        size_t gt=data.find(L'>',n);
                        size_t end=gt==std::wstring::npos?gt:data.find(L'<',gt+1);
                        if(gt!=std::wstring::npos && end!=std::wstring::npos) {
                            threat=data.substr(gt+1,std::min<size_t>(end-gt-1,250));break;
                        }
                    }
                    std::string kind=(id==L"1116")?"Threat detected":
                        (id==L"1117")?"Remediation action":
                        (id==L"1118")?"Remediation failed":"Remediation status";
                    std::string detail="Defender event "+utf8(id)+" | "+utf8(timestamp);
                    if(!threat.empty())detail+=" | "+utf8(threat);
                    detail+=" | Historical Windows Defender report. Inspect Windows Security for current status.";
                    found.push_back({"Defender Detection",kind,detail});
                    if(id==L"1116" || id==L"1118")++defenderAlerts;
                }
            }
            EvtClose(events[i]);
        }
        if(count<32)break;
    }
    EvtClose(results);
    return found;
}

// -----------------------------------------------------------------------------
// Windows security posture: registry-backed, read-only checks.
// A configuration difference is a review indicator, not a malware verdict.
// -----------------------------------------------------------------------------
static std::wstring readRegistryString(HKEY root,const wchar_t* key,const wchar_t* value) {
    HKEY handle=nullptr;
    if(RegOpenKeyExW(root,key,0,KEY_READ,&handle)!=ERROR_SUCCESS)return {};
    DWORD type=0,bytes=0;
    LONG rc=RegQueryValueExW(handle,value,nullptr,&type,nullptr,&bytes);
    if(rc!=ERROR_SUCCESS || (type!=REG_SZ && type!=REG_EXPAND_SZ) ||
       bytes<sizeof(wchar_t) || bytes>65536) {
        RegCloseKey(handle);return {};
    }
    std::vector<wchar_t> data(bytes/sizeof(wchar_t)+2,L'\0');
    rc=RegQueryValueExW(handle,value,nullptr,&type,
        reinterpret_cast<BYTE*>(data.data()),&bytes);
    RegCloseKey(handle);
    return rc==ERROR_SUCCESS?std::wstring(data.data()):std::wstring{};
}
static bool readRegistryDword(HKEY root,const wchar_t* key,
                              const wchar_t* value,DWORD& output) {
    HKEY handle=nullptr;
    if(RegOpenKeyExW(root,key,0,KEY_READ,&handle)!=ERROR_SUCCESS)return false;
    DWORD type=0,bytes=sizeof(output);
    LONG rc=RegQueryValueExW(handle,value,nullptr,&type,
        reinterpret_cast<BYTE*>(&output),&bytes);
    RegCloseKey(handle);
    return rc==ERROR_SUCCESS && type==REG_DWORD && bytes==sizeof(output);
}
static std::vector<Record> inspectWindowsSecurityConfiguration() {
    std::vector<Record> out;
    auto check=[&](const wchar_t* key,const wchar_t* name,
                   const char* title,DWORD suspiciousValue,const char* reason) {
        DWORD value=0;
        if(readRegistryDword(HKEY_LOCAL_MACHINE,key,name,value)) {
            std::string detail="Value: "+std::to_string(value);
            if(value==suspiciousValue)detail+=" | REVIEW: "+std::string(reason);
            else detail+=" | Configuration observed; no adverse conclusion from this value";
            out.push_back({"Security Configuration",title,detail});
        }
    };
    check(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
          L"DisableAntiSpyware","Defender disable policy",1,
          "Defender disable policy is set; confirm effective protection state");
    check(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
          L"DisableRealtimeMonitoring","Defender real-time monitoring policy",1,
          "Real-time monitoring disable policy is set");
    check(L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
          L"DisableBehaviorMonitoring","Defender behavior monitoring policy",1,
          "Behavior monitoring disable policy is set");
    check(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
          L"EnableLUA","User Account Control",0,
          "User Account Control is disabled");
    check(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
          L"ConsentPromptBehaviorAdmin","Administrator consent policy",0,
          "Administrator elevation may occur without prompting");
    check(L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
          L"RunAsPPL","LSA protection configuration",0,
          "LSA protection value is disabled; confirm actual system protection");
    check(L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",
          L"EnableSmartScreen","SmartScreen policy",0,
          "SmartScreen disable policy is set");
    return out;
}

// Image File Execution Options debugger entries can redirect process launches.
// We enumerate entries without executing or modifying any debugger command.
static std::vector<Record> inspectImageExecutionOptions() {
    std::vector<Record> out;
    HKEY root=nullptr;
    const wchar_t* base=L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,base,0,KEY_READ,&root)!=ERROR_SUCCESS)
        return out;
    for(DWORD index=0;index<4096 && !cancelRequested;++index) {
        wchar_t name[512]{};
        DWORD length=511;
        LONG rc=RegEnumKeyExW(root,index,name,&length,nullptr,nullptr,nullptr,nullptr);
        if(rc==ERROR_NO_MORE_ITEMS)break;
        if(rc!=ERROR_SUCCESS)continue;
        std::wstring key=std::wstring(base)+L"\\"+name;
        auto debugger=readRegistryString(HKEY_LOCAL_MACHINE,key.c_str(),L"Debugger");
        if(!debugger.empty()) {
            out.push_back({"Execution Redirect",
                utf8(name),
                "REVIEW: IFEO Debugger entry redirects executable launch to: "+
                utf8(debugger)+" | Verify administrative intent"});
        }
        DWORD globalFlag=0;
        if(readRegistryDword(HKEY_LOCAL_MACHINE,key.c_str(),L"GlobalFlag",globalFlag)
           && globalFlag!=0) {
            out.push_back({"Execution Configuration",utf8(name),
                "Image File Execution Options GlobalFlag: "+std::to_string(globalFlag)});
        }
    }
    RegCloseKey(root);
    return out;
}

// Winlogon startup values and AppInit_DLLs are useful persistence evidence.
// Do not assume a non-default value is automatically malicious.
static std::vector<Record> inspectLogonConfiguration() {
    std::vector<Record> out;
    const wchar_t* winlogon=L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    for(const wchar_t* field:{L"Shell",L"Userinit",L"Taskman"}) {
        auto value=readRegistryString(HKEY_LOCAL_MACHINE,winlogon,field);
        if(value.empty())continue;
        std::string detail=utf8(value);
        if(std::wstring(field)==L"Shell" &&
           _wcsicmp(value.c_str(),L"explorer.exe")!=0)
            detail+=" | REVIEW: Non-default Winlogon shell";
        if(std::wstring(field)==L"Taskman")
            detail+=" | REVIEW: Winlogon Taskman value is configured";
        out.push_back({"Logon Configuration",utf8(field),detail});
    }
    const wchar_t* appinit=L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    auto dlls=readRegistryString(HKEY_LOCAL_MACHINE,appinit,L"AppInit_DLLs");
    DWORD enabled=0;
    if(!dlls.empty()) {
        std::string detail=utf8(dlls);
        if(readRegistryDword(HKEY_LOCAL_MACHINE,appinit,L"LoadAppInit_DLLs",enabled)
           && enabled!=0)
            detail+=" | REVIEW: AppInit DLL loading is enabled";
        out.push_back({"Logon Configuration","AppInit_DLLs",detail});
    }
    return out;
}

// Read-only desktop window inventory. Win32 does not provide a reliable
// cross-process API to query another window's display affinity. These are
// visibility indicators only, not bypass/cheat detection.
struct WindowReviewContext {
    std::vector<Record> findings;
    HWND ownWindow=nullptr;
};
static BOOL CALLBACK reviewWindowProc(HWND target, LPARAM param) {
    auto* ctx=reinterpret_cast<WindowReviewContext*>(param);
    if(!ctx || ctx->findings.size()>=160)return FALSE;
    if(target==ctx->ownWindow)return TRUE;
    DWORD pid=0;
    GetWindowThreadProcessId(target,&pid);
    if(!pid || pid==GetCurrentProcessId())return TRUE;
    const LONG_PTR ex=GetWindowLongPtrW(target,GWL_EXSTYLE);
    const bool layered=(ex&WS_EX_LAYERED)!=0;
    const bool transparent=(ex&WS_EX_TRANSPARENT)!=0;
    const bool toolWindow=(ex&WS_EX_TOOLWINDOW)!=0;
    const bool visible=IsWindowVisible(target)!=FALSE;
    RECT bounds{};
    GetWindowRect(target,&bounds);
    const int width=bounds.right-bounds.left;
    const int height=bounds.bottom-bounds.top;
    // Avoid ordinary hidden helper windows, zero-size windows, and
    // tooltips. Only report windows with a sizable desktop footprint.
    if(width<180 || height<90 || width>16000 || height>16000)return TRUE;
    if(!layered && !transparent)return TRUE;
    if(!visible && !layered)return TRUE;
    wchar_t title[260]{};
    GetWindowTextW(target,title,260);
    if(!visible && title[0]==0)return TRUE;
    BYTE opacity=255;
    DWORD colorKey=0,layerFlags=0;
    const bool hasOpacity=layered &&
        GetLayeredWindowAttributes(target,&colorKey,&opacity,&layerFlags)!=FALSE;
    const bool lowOpacity=hasOpacity && (layerFlags&LWA_ALPHA) && opacity<70;
    if(!transparent && !lowOpacity && !(!visible && layered))return TRUE;
    std::wstring processPath;
    HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(process){
        wchar_t path[32768]{};
        DWORD chars=32768;
        if(QueryFullProcessImageNameW(process,0,path,&chars))
            processPath.assign(path,chars);
        CloseHandle(process);
    }
    std::string details="PID "+std::to_string(pid)+
        " | "+(visible?"Visible":"Hidden")+
        (transparent?" | Input-transparent":"")+
        (lowOpacity?" | Low opacity":"")+
        (toolWindow?" | Tool window":"")+
        " | "+std::to_string(width)+"x"+std::to_string(height);
    if(!processPath.empty())details+=" | "+utf8(processPath);
    details+=" | REVIEW ONLY: window styles do not prove a bypass";
    ctx->findings.push_back({"Window Visibility",
        title[0]?utf8(title):"Untitled desktop window",details});
    return TRUE;
}
static std::vector<Record> inspectDesktopWindowVisibility(HWND ownWindow){
    WindowReviewContext context;
    context.ownWindow=ownWindow;
    EnumWindows(reviewWindowProc,reinterpret_cast<LPARAM>(&context));
    return std::move(context.findings);
}

// Declarative detection rules: facts are collected separately from decisions.
// Rules require explicit evidence and report the exact matching conditions.
struct TaskEvidence {
    std::string command;
    std::string arguments;
    std::string taskPath;
    bool userWritablePath=false;
    bool scriptInterpreter=false;
    bool hiddenWindowArgument=false;
    bool encodedCommandArgument=false;
};
struct TaskDetectionRule {
    const char* id;
    const char* title;
    const char* severity;
    bool (*matches)(const TaskEvidence&);
    const char* rationale;
};
static std::string asciiLower(std::string value){
    std::transform(value.begin(),value.end(),value.begin(),
        [](unsigned char c){return static_cast<char>(std::tolower(c));});
    return value;
}
static bool taskUserWritableInterpreter(const TaskEvidence& e){
    return e.userWritablePath && e.scriptInterpreter;
}
static bool taskEncodedInterpreter(const TaskEvidence& e){
    return e.scriptInterpreter && e.encodedCommandArgument;
}
static bool taskHiddenInterpreter(const TaskEvidence& e){
    return e.scriptInterpreter && e.hiddenWindowArgument;
}
static bool taskUserWritableExecutable(const TaskEvidence& e){
    return e.userWritablePath && !e.scriptInterpreter;
}
static std::vector<Record> evaluateTaskRules(const TaskEvidence& e){
    static const TaskDetectionRule rules[]={
        {"TASK-001","Script interpreter in user-writable location","MEDIUM",
         taskUserWritableInterpreter,
         "Task command combines an interpreter with a user-writable path"},
        {"TASK-002","Encoded interpreter invocation","MEDIUM",
         taskEncodedInterpreter,
         "Task arguments include an encoded-command option"},
        {"TASK-003","Hidden interpreter invocation","LOW",
         taskHiddenInterpreter,
         "Task arguments request a hidden window"},
        {"TASK-004","Executable in user-writable location","LOW",
         taskUserWritableExecutable,
         "Task launches from a user-writable path"}
    };
    std::vector<Record> findings;
    for(const auto& rule:rules){
        if(!rule.matches(e))continue;
        findings.push_back({"Scheduled Task Rule",
            std::string(rule.id)+" | "+rule.title,
            std::string("REVIEW ONLY | Severity: ")+rule.severity+
            " | Evidence: "+rule.rationale+
            " | Command: "+e.command+
            " | Arguments: "+e.arguments+
            " | Task: "+e.taskPath+
            " | This is not a malware verdict"});
    }
    return findings;
}


// Coverage catalog. Listing a rule does NOT mean its detector is implemented.


// Extended read-only endpoint inventory. Results are evidence, not verdicts.
static std::vector<Record> inspectExtendedEndpoint(){
    std::vector<Record> result;
    // Scheduled task XML inventory: read only, bounded, and no command execution.
    const wchar_t* windir=_wgetenv(L"WINDIR");
    std::wstring root=windir?windir:L"C:\\Windows";
    root+=L"\\System32\\Tasks";
    std::error_code ec;
    if(fs::exists(root,ec)){
        fs::recursive_directory_iterator it(root,
            fs::directory_options::skip_permission_denied,ec),end;
        unsigned count=0;
        for(;it!=end && count<1200 && !cancelRequested;it.increment(ec)){
            if(ec){ec.clear();continue;}
            if(!it->is_regular_file(ec))continue;
            ++count;
            std::ifstream f(it->path(),std::ios::binary);
            if(!f)continue;
            std::string xml((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
            if(xml.size()>512*1024)continue;
            auto between=[&](const std::string& tag)->std::string{
                const auto a=xml.find("<"+tag+">");
                if(a==std::string::npos)return {};
                const auto start=a+tag.size()+2;
                const auto b=xml.find("</"+tag+">",start);
                return b==std::string::npos?std::string{}:
                    xml.substr(start,(std::min)(b-start,size_t(600)));
            };
            const auto command=between("Command");
            if(command.empty())continue;
            const auto arguments=between("Arguments");
            const auto cmd=asciiLower(command);
            const auto args=asciiLower(arguments);
            const auto writable=[](const std::string& v){
                return v.find("appdata")!=std::string::npos ||
                       v.find("\\temp\\")!=std::string::npos ||
                       v.find("%temp%")!=std::string::npos ||
                       v.find("\\users\\public\\")!=std::string::npos;
            };
            const bool interpreter=
                cmd.find("powershell.exe")!=std::string::npos ||
                cmd.find("pwsh.exe")!=std::string::npos ||
                cmd.find("wscript.exe")!=std::string::npos ||
                cmd.find("cscript.exe")!=std::string::npos ||
                cmd.find("mshta.exe")!=std::string::npos;
            TaskEvidence evidence{
                command,arguments,utf8(it->path().wstring()),
                writable(cmd)||writable(args),
                interpreter,
                args.find("-windowstyle hidden")!=std::string::npos ||
                    args.find("-w hidden")!=std::string::npos,
                args.find("-encodedcommand")!=std::string::npos ||
                    args.find("-enc ")!=std::string::npos
            };
            auto matches=evaluateTaskRules(evidence);
            result.insert(result.end(),matches.begin(),matches.end());
        }
    }
    // Internet Settings: proxy and auto-config scripts may redirect traffic.
    const wchar_t* internet=L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    auto proxy=readRegistryString(HKEY_CURRENT_USER,internet,L"ProxyServer");
    auto pac=readRegistryString(HKEY_CURRENT_USER,internet,L"AutoConfigURL");
    DWORD enabled=0;
    if(readRegistryDword(HKEY_CURRENT_USER,internet,L"ProxyEnable",enabled)&&enabled){
        result.push_back({"Network Configuration","User proxy",
            "Configured proxy: "+(proxy.empty()?"not specified":utf8(proxy))+
            " | Review expected network policy"});
    }
    if(!pac.empty())
        result.push_back({"Network Configuration","Automatic proxy configuration",
            "PAC URL: "+utf8(pac)+" | Informational"});
    // Browser extension inventory: IDs and directories only, no browser secrets.
    const wchar_t* local=_wgetenv(L"LOCALAPPDATA");
    if(local){
        const std::wstring base(local);
        const std::pair<const wchar_t*,const wchar_t*> browsers[]={
            {L"Chrome",L"\\Google\\Chrome\\User Data\\Default\\Extensions"},
            {L"Edge",L"\\Microsoft\\Edge\\User Data\\Default\\Extensions"}
        };
        for(const auto& browser:browsers){
            const fs::path dir=base+browser.second;
            std::error_code err;
            if(!fs::exists(dir,err))continue;
            unsigned n=0;
            for(fs::directory_iterator it(dir,
                    fs::directory_options::skip_permission_denied,err),end;
                it!=end && n<200 && !cancelRequested;it.increment(err)){
                if(err){err.clear();continue;}
                if(!it->is_directory(err))continue;
                ++n;
                result.push_back({"Browser Extension Inventory",
                    utf8(it->path().filename().wstring()),
                    std::string(std::wstring(browser.first)==L"Chrome"?
                        "Chrome":"Edge")+" | Installed extension directory; "
                    "not a threat verdict"});
            }
        }
    }
    return result;
}

// Read-only registry review of less-visible execution and persistence surfaces.
// These entries are configuration evidence, not proof of malware.
static std::vector<Record> inspectAdvancedPersistence() {
    std::vector<Record> out;
    const wchar_t* silentBase=
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";
    HKEY silent=nullptr;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,silentBase,0,KEY_READ,&silent)==ERROR_SUCCESS){
        for(DWORD i=0;i<2048 && !cancelRequested;++i){
            wchar_t name[512]{};
            DWORD chars=511;
            LONG rc=RegEnumKeyExW(silent,i,name,&chars,nullptr,nullptr,nullptr,nullptr);
            if(rc==ERROR_NO_MORE_ITEMS)break;
            if(rc!=ERROR_SUCCESS)continue;
            std::wstring key=std::wstring(silentBase)+L"\\"+name;
            auto monitor=readRegistryString(HKEY_LOCAL_MACHINE,key.c_str(),L"MonitorProcess");
            auto dumpFolder=readRegistryString(HKEY_LOCAL_MACHINE,key.c_str(),L"LocalDumpFolder");
            DWORD reporting=0;
            const bool hasReporting=readRegistryDword(
                HKEY_LOCAL_MACHINE,key.c_str(),L"ReportingMode",reporting);
            if(!monitor.empty()){
                out.push_back({"Execution Monitoring",utf8(name),
                    "REVIEW: SilentProcessExit MonitorProcess: "+utf8(monitor)+
                    " | Confirm expected diagnostic configuration"});
            }
            if(!dumpFolder.empty() || hasReporting){
                out.push_back({"Execution Monitoring",utf8(name),
                    "SilentProcessExit settings | ReportingMode: "+
                    (hasReporting?std::to_string(reporting):"not set")+
                    " | Dump folder: "+(dumpFolder.empty()?"not set":utf8(dumpFolder))});
            }
        }
        RegCloseKey(silent);
    }

    // Active Setup may launch a per-user initialization command at logon.
    // Report the command for analyst review; no automatic malicious verdict.
    const wchar_t* activeBase=
        L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components";
    for(HKEY hive:{HKEY_LOCAL_MACHINE,HKEY_CURRENT_USER}){
        HKEY active=nullptr;
        if(RegOpenKeyExW(hive,activeBase,0,KEY_READ,&active)!=ERROR_SUCCESS)
            continue;
        for(DWORD i=0;i<4096 && !cancelRequested;++i){
            wchar_t name[512]{};
            DWORD chars=511;
            LONG rc=RegEnumKeyExW(active,i,name,&chars,nullptr,nullptr,nullptr,nullptr);
            if(rc==ERROR_NO_MORE_ITEMS)break;
            if(rc!=ERROR_SUCCESS)continue;
            std::wstring key=std::wstring(activeBase)+L"\\"+name;
            auto stub=readRegistryString(hive,key.c_str(),L"StubPath");
            if(stub.empty())continue;
            out.push_back({"Active Setup",utf8(name),
                std::string(hive==HKEY_LOCAL_MACHINE?"HKLM":"HKCU")+
                " StubPath: "+utf8(stub)+" | Review publisher and purpose"});
        }
        RegCloseKey(active);
    }
    return out;
}

// Windows hosts file inspection: collects non-comment mappings and highlights
// redirects for well-known update/security domains. Never changes the file.
static std::vector<Record> inspectHostsFile() {
    std::vector<Record> out;
    wchar_t systemDir[MAX_PATH]{};
    UINT n=GetSystemDirectoryW(systemDir,MAX_PATH);
    if(!n || n>=MAX_PATH)return out;
    fs::path hosts=fs::path(systemDir)/L"drivers"/L"etc"/L"hosts";
    std::ifstream input(hosts);
    if(!input)return out;
    std::string line;
    size_t count=0;
    while(count<2048 && std::getline(input,line) && !cancelRequested) {
        ++count;
        auto pos=line.find('#');
        if(pos!=std::string::npos)line.resize(pos);
        auto start=line.find_first_not_of(" \t\r\n");
        if(start==std::string::npos)continue;
        line=line.substr(start);
        std::istringstream stream(line);
        std::string ip,host;
        stream>>ip;
        while(stream>>host) {
            if(host.empty())continue;
            std::string lowered=host;
            std::transform(lowered.begin(),lowered.end(),lowered.begin(),
                           [](unsigned char c){return char(std::tolower(c));});
            bool sensitive=lowered.find("microsoft.com")!=std::string::npos ||
                           lowered.find("windowsupdate.com")!=std::string::npos ||
                           lowered.find("defender.microsoft.com")!=std::string::npos;
            out.push_back({"Hosts File",host,
                ip+(sensitive?" | REVIEW: Security/update-related hostname is overridden":
                              " | Local hostname override; verify purpose")});
            if(out.size()>=512)return out;
        }
    }
    return out;
}


// Read-only PE structural inspection. Heuristics are not malware signatures.
static std::vector<Record> inspectPeStructure(const std::vector<Process>& items) {
    std::vector<Record> findings;
    std::unordered_set<std::wstring> visited;
    size_t examined=0;
    for(const auto& p:items) {
        if(cancelRequested || examined>=220)break;
        if(p.path.empty() || p.path[0]==L'[' || !visited.insert(lowerPath(p.path)).second)continue;
        HANDLE file=CreateFileW(p.path.c_str(),GENERIC_READ,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
        if(file==INVALID_HANDLE_VALUE)continue;
        ++examined;
        peFilesInspected=examined;
        LARGE_INTEGER length{};
        if(!GetFileSizeEx(file,&length) || length.QuadPart<512 || length.QuadPart>1024LL*1024*1024) {
            CloseHandle(file);continue;
        }
        const DWORD readSize=(DWORD)std::min<LONGLONG>(length.QuadPart,1024*1024);
        std::vector<BYTE> buffer(readSize);
        DWORD read=0;
        const bool success=ReadFile(file,buffer.data(),readSize,&read,nullptr)!=FALSE;
        CloseHandle(file);
        if(!success || read<sizeof(IMAGE_DOS_HEADER))continue;
        IMAGE_DOS_HEADER dos{};
        std::memcpy(&dos,buffer.data(),sizeof(dos));
        if(dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<0)continue;
        const size_t peOffset=(size_t)dos.e_lfanew;
        if(peOffset>read || read-peOffset<sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))continue;
        DWORD magic=0;
        std::memcpy(&magic,buffer.data()+peOffset,sizeof(magic));
        if(magic!=IMAGE_NT_SIGNATURE)continue;
        IMAGE_FILE_HEADER header{};
        std::memcpy(&header,buffer.data()+peOffset+sizeof(DWORD),sizeof(header));
        if(header.NumberOfSections==0 || header.NumberOfSections>96)continue;
        const size_t sectionsAt=peOffset+sizeof(DWORD)+sizeof(header)+(size_t)header.SizeOfOptionalHeader;
        if(sectionsAt>read || header.NumberOfSections>(read-sectionsAt)/sizeof(IMAGE_SECTION_HEADER))continue;
        for(WORD i=0;i<header.NumberOfSections;i++) {
            IMAGE_SECTION_HEADER section{};
            std::memcpy(&section,buffer.data()+sectionsAt+(size_t)i*sizeof(section),sizeof(section));
            const DWORD mask=IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE;
            if((section.Characteristics&mask)!=mask)continue;
            char sectionName[9]{};
            std::memcpy(sectionName,section.Name,8);
            findings.push_back({"PE Review",utf8(p.path),
                std::string("SUSPECT | Writable and executable PE section: ")+sectionName+
                " | PID "+std::to_string(p.pid)+
                " | This is a structural indicator, not a malware verdict"});
            if(findings.size()>=256)return findings;
        }
    }
    return findings;
}

// Categories are based on evidence; unknown information must not be called clean.
static bool isDetectedRecord(const Record& r) {
    return r.category=="Defender Detection" || r.category=="Defender Threat" ||
           r.detail.find("DETECTED |")!=std::string::npos;
}
static bool isSuspectRecord(const Record& r) {
    return r.category=="PE Review" ||
           r.detail.find("SUSPECT |")!=std::string::npos ||
           r.detail.find("REVIEW:")!=std::string::npos;
}
static const char* evidenceLabel(const Record& r) {
    return isDetectedRecord(r)?"DETECTED":isSuspectRecord(r)?"SUSPECT":"UNKNOWN";
}
static void tintEvidenceRow(const Record& r) {
    if(isDetectedRecord(r))ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(56,56,56,190));
    else if(isSuspectRecord(r))ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(94,94,94,175));
}


// Read-only Windows Event Log timeline. Only actual events are displayed.
static std::wstring xmlAttribute(const std::wstring& xml,
                                 const std::wstring& key) {
    for(wchar_t quote : {L'\'', L'"'}) {
        const std::wstring needle=key+L"="+quote;
        const size_t p=xml.find(needle);
        if(p==std::wstring::npos)continue;
        const size_t first=p+needle.size();
        const size_t last=xml.find(quote,first);
        if(last!=std::wstring::npos)
            return xml.substr(first,(std::min)(last-first,size_t(300)));
    }
    return L"";
}
static std::wstring xmlElement(const std::wstring& xml,
                               const std::wstring& name) {
    const std::wstring opening=L"<"+name+L">";
    const size_t p=xml.find(opening);
    if(p==std::wstring::npos)return L"";
    const size_t first=p+opening.size();
    const size_t last=xml.find(L'<',first);
    return last==std::wstring::npos?L"":
        xml.substr(first,(std::min)(last-first,size_t(256)));
}
static std::string timelineSummary(const std::string& channel,
                                   const std::string& id) {
    if(channel=="System") {
        if(id=="7045")return "A Windows service was installed";
        if(id=="7040")return "Service startup configuration changed";
        if(id=="7036")return "A Windows service changed state";
        if(id=="7000" || id=="7001")return "Service startup failure";
    }
    if(channel=="Task Scheduler") {
        if(id=="106")return "Scheduled task registered";
        if(id=="140")return "Scheduled task updated";
        if(id=="141")return "Scheduled task deleted";
        if(id=="200")return "Scheduled task action started";
        if(id=="201")return "Scheduled task action completed";
    }
    if(channel=="Microsoft Defender") {
        if(id=="1116")return "Microsoft Defender reported a threat detection";
        if(id=="1117")return "Microsoft Defender recorded remediation";
        if(id=="1118" || id=="1119")
            return "Microsoft Defender reported a remediation issue";
    }
    return "Windows event recorded";
}
static std::vector<TimelineEvent> collectWindowsTimeline() {
    std::vector<TimelineEvent> output;
    struct Channel { const wchar_t* path; const char* label; const wchar_t* query; };
    const Channel channels[]={
        {L"System","System",
         L"*[System[(EventID=7045 or EventID=7040 or EventID=7036 or EventID=7000 or EventID=7001) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"},
        {L"Microsoft-Windows-TaskScheduler/Operational","Task Scheduler",
         L"*[System[(EventID=106 or EventID=140 or EventID=141 or EventID=200 or EventID=201) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"},
        {L"Microsoft-Windows-Windows Defender/Operational","Microsoft Defender",
         L"*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"}
    };
    for(const auto& channel:channels) {
        if(cancelRequested)break;
        EVT_HANDLE query=EvtQuery(nullptr,channel.path,channel.query,
                                 EvtQueryChannelPath|EvtQueryReverseDirection);
        if(!query) {
            output.push_back({"",channel.label,"N/A",
                "Event channel could not be read",
                "Access denied, disabled channel, or no event log available. "
                "This is not evidence that the system is clean.",false});
            continue;
        }
        size_t processed=0;
        while(processed<120 && !cancelRequested) {
            EVT_HANDLE batch[16]{};
            DWORD count=0;
            if(!EvtNext(query,16,batch,1000,0,&count))break;
            for(DWORD i=0;i<count;++i) {
                if(processed>=120 || cancelRequested) {
                    EvtClose(batch[i]);
                    continue;
                }
                ++processed;
                DWORD needed=0,used=0;
                EvtRender(nullptr,batch[i],EvtRenderEventXml,0,nullptr,&needed,&used);
                if(GetLastError()==ERROR_INSUFFICIENT_BUFFER &&
                   needed>=sizeof(wchar_t) && needed<=1024*1024) {
                    std::vector<wchar_t> xml(needed/sizeof(wchar_t)+1,L'\0');
                    if(EvtRender(nullptr,batch[i],EvtRenderEventXml,
                        (DWORD)(xml.size()*sizeof(wchar_t)),xml.data(),
                        &needed,&used)) {
                        const std::wstring data(xml.data());
                        const std::string id=utf8(xmlElement(data,L"EventID"));
                        const std::string when=utf8(xmlAttribute(data,L"SystemTime"));
                        const std::string provider=utf8(xmlAttribute(data,L"Name"));
                        const bool alert=std::string(channel.label)=="Microsoft Defender" &&
                            (id=="1116" || id=="1118" || id=="1119");
                        std::string detail="Provider: "+provider+
                            " | Event ID: "+id+" | Source: "+channel.label;
                        output.push_back({when,channel.label,id,
                            timelineSummary(channel.label,id),detail,alert});
                    }
                }
                EvtClose(batch[i]);
            }
        }
        EvtClose(query);
    }
    std::stable_sort(output.begin(),output.end(),
        [](const TimelineEvent& a,const TimelineEvent& b){
            return a.timestamp>b.timestamp;
        });
    return output;
}

// 120 individual read-only Windows security policy probes. A missing value
// is NOT an adverse detection. Unfamiliar values are inventory-only.
static std::vector<Record> inspectPolicyRuleSet(){
    struct PolicyRule{
        const wchar_t* key;
        const wchar_t* value;
        int suspicious; // -1: inventory only
        const char* id;
    };
    static const PolicyRule rules[]={
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware", 1, "POL-001"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiVirus", 1, "POL-002"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableRoutinelyTakingAction", -1, "POL-003"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"PUAProtection", -1, "POL-004"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"ServiceKeepAlive", -1, "POL-005"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableLocalAdminMerge", -1, "POL-006"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"RandomizeScheduleTaskTimes", -1, "POL-007"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"ScanAvgCPULoadFactor", -1, "POL-008"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableCatchupFullScan", -1, "POL-009"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableCatchupQuickScan", -1, "POL-010"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableRealtimeMonitoring", 1, "POL-011"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableBehaviorMonitoring", 1, "POL-012"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableOnAccessProtection", 1, "POL-013"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableScanOnRealtimeEnable", -1, "POL-014"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableIOAVProtection", 1, "POL-015"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableScriptScanning", 1, "POL-016"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableRawWriteNotification", -1, "POL-017"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableIntrusionPreventionSystem", -1, "POL-018"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableInformationProtectionControl", -1, "POL-019"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"LocalSettingOverrideDisableRealtimeMonitoring", -1, "POL-020"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"SpynetReporting", -1, "POL-021"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"SubmitSamplesConsent", -1, "POL-022"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"DisableBlockAtFirstSeen", 1, "POL-023"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"LocalSettingOverrideSpynetReporting", -1, "POL-024"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"LocalSettingOverrideSubmitSamplesConsent", -1, "POL-025"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"DisableCloudProtection", -1, "POL-026"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"CloudBlockLevel", -1, "POL-027"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"CloudExtendedTimeout", -1, "POL-028"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"SpyNetReportingLocation", -1, "POL-029"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet", L"DisableSpyNetReporting", -1, "POL-030"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableRemovableDriveScanning", -1, "POL-031"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableScanningNetworkFiles", -1, "POL-032"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableArchiveScanning", 1, "POL-033"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableEmailScanning", -1, "POL-034"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableHeuristics", 1, "POL-035"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisablePackedExeScanning", -1, "POL-036"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableReparsePointScanning", -1, "POL-037"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableRestorePoint", -1, "POL-038"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableCatchupQuickScan", -1, "POL-039"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan", L"DisableCatchupFullScan", -1, "POL-040"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"ForceUpdateFromMU", -1, "POL-041"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"DisableUpdateOnStartupWithoutEngine", -1, "POL-042"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"SignatureUpdateInterval", -1, "POL-043"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"FallbackOrder", -1, "POL-044"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"DisableScanOnUpdate", -1, "POL-045"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"DisableUpdateOnStartup", -1, "POL-046"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"SignatureUpdateCatchupInterval", -1, "POL-047"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"ScheduleDay", -1, "POL-048"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"ScheduleTime", -1, "POL-049"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", L"UpdateOnStartUp", -1, "POL-050"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpCloudBlockLevel", -1, "POL-051"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpBafsExtendedTimeout", -1, "POL-052"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"EnableFileHashComputation", -1, "POL-053"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"DisableBlockAtFirstSeen", 1, "POL-054"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpEnablePus", -1, "POL-055"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpEnablePusAuditMode", -1, "POL-056"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpEngineRing", -1, "POL-057"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpEngineVersion", -1, "POL-058"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpEngineSignatureVersion", -1, "POL-059"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine", L"MpEnginePlatformVersion", -1, "POL-060"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"EnableSmartScreen", 0, "POL-061"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"ShellSmartScreenLevel", -1, "POL-062"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"EnableCdp", -1, "POL-063"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"AllowCrossDeviceClipboard", -1, "POL-064"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"EnableActivityFeed", -1, "POL-065"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"PublishUserActivities", -1, "POL-066"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"UploadUserActivities", -1, "POL-067"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"DisableCMD", -1, "POL-068"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"DisableRegistryTools", -1, "POL-069"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"EnableMPR", -1, "POL-070"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", 0, "POL-071"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorAdmin", -1, "POL-072"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ConsentPromptBehaviorUser", -1, "POL-073"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"PromptOnSecureDesktop", -1, "POL-074"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"FilterAdministratorToken", -1, "POL-075"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableInstallerDetection", -1, "POL-076"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableSecureUIAPaths", -1, "POL-077"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"ValidateAdminCodeSignatures", -1, "POL-078"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableVirtualization", -1, "POL-079"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"LocalAccountTokenFilterPolicy", -1, "POL-080"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"EnableVirtualizationBasedSecurity", -1, "POL-081"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"RequirePlatformSecurityFeatures", -1, "POL-082"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"Locked", -1, "POL-083"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"HypervisorEnforcedCodeIntegrity", -1, "POL-084"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"HVCIMATRequired", -1, "POL-085"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"LsaCfgFlags", -1, "POL-086"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"ConfigureSystemGuardLaunch", -1, "POL-087"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"Mandatory", -1, "POL-088"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"SecureLaunch", -1, "POL-089"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"Scenarios", -1, "POL-090"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", 0, "POL-091"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPLBoot", -1, "POL-092"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LsaCfgFlags", -1, "POL-093"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"DisableRestrictedAdmin", -1, "POL-094"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"DisableRestrictedAdminOutboundCreds", -1, "POL-095"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LimitBlankPasswordUse", 0, "POL-096"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"NoLMHash", 0, "POL-097"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LmCompatibilityLevel", -1, "POL-098"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RestrictAnonymous", -1, "POL-099"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RestrictAnonymousSAM", -1, "POL-100"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"VerifiedAndReputablePolicyState", -1, "POL-101"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"UpgradedSystem", -1, "POL-102"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"SkuPolicyRequired", -1, "POL-103"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"SkuPolicyRequiredDebug", -1, "POL-104"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"DebugFlags", -1, "POL-105"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"Enabled", -1, "POL-106"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"PolicyId", -1, "POL-107"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"PolicyVersion", -1, "POL-108"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"HVCIEnabled", -1, "POL-109"},
        {L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"AuditMode", -1, "POL-110"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"EnableVirtualizationBasedSecurity", -1, "POL-111"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"RequirePlatformSecurityFeatures", -1, "POL-112"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"HypervisorEnforcedCodeIntegrity", -1, "POL-113"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"LsaCfgFlags", -1, "POL-114"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"ConfigureSystemGuardLaunch", -1, "POL-115"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"Locked", -1, "POL-116"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"HVCIMATRequired", -1, "POL-117"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"EnableCredentialGuard", -1, "POL-118"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"EnableHVCI", -1, "POL-119"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard", L"SecureLaunch", -1, "POL-120"},
    };
    std::vector<Record> out;
    for(const auto& rule:rules){
        if(cancelRequested)break;
        DWORD value=0;
        if(!readRegistryDword(HKEY_LOCAL_MACHINE,rule.key,rule.value,value))
            continue;
        const bool review=rule.suspicious>=0 &&
            value==static_cast<DWORD>(rule.suspicious);
        std::string detail=std::string(rule.id)+" | DWORD="+
            std::to_string(value)+(review?
            " | REVIEW: security-related configuration; verify effective state":
            " | Observed policy value; not a threat verdict");
        out.push_back({"Security Policy Audit",utf8(rule.value),detail});
    }
    return out;
}
// Firmware and DMA: query supported Windows indicators. These checks do not
// claim to detect malicious firmware implants or DMA hardware directly.
static std::vector<Record> inspectFirmwareAndDmaIndicators(){
    std::vector<Record> out;
    FIRMWARE_TYPE firmware=FirmwareTypeUnknown;
    if(GetFirmwareType(&firmware)){
        out.push_back({"UEFI / Firmware","Boot firmware type",
            firmware==2?"UEFI firmware reported by Windows":
            firmware==1?"Legacy BIOS reported by Windows":
            "Firmware type unknown"});
    }
    DWORD secureBoot=0;
    if(readRegistryDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        L"UEFISecureBootEnabled",secureBoot)){
        out.push_back({"UEFI / Firmware","Secure Boot state",
            std::string("UEFISecureBootEnabled=")+std::to_string(secureBoot)+
            (secureBoot==0?" | REVIEW: Secure Boot disabled":
             " | Reported enabled")});
    }
    const struct{const wchar_t* key;const wchar_t* name;const char* label;} checks[]={
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
         L"EnableVirtualizationBasedSecurity","VBS configured"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
         L"Enabled","HVCI configured"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard",
         L"Enabled","Credential Guard configured"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard",
         L"Enabled","System Guard configured"},
        {L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
         L"RequirePlatformSecurityFeatures","Platform security requirements"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection",
         L"DeviceEnumerationPolicy","Kernel DMA device enumeration policy"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions",
         L"DenyUnspecified","Device installation restrictions"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
         L"RunAsPPL","LSA protection configuration"},
    };
    for(const auto& check:checks){
        if(cancelRequested)break;
        DWORD v=0;
        if(readRegistryDword(HKEY_LOCAL_MACHINE,check.key,check.name,v))
            out.push_back({"Firmware / DMA Posture",check.label,
                "Configured DWORD="+std::to_string(v)+
                " | Configuration indicator, not direct DMA/EFI compromise detection"});
    }
    return out;
}


// FiveM safe test harness: inspect ONLY a dedicated temporary marker directory.
// These findings prove the test pipeline works; they do NOT imply real malware.
static std::vector<Record> inspectFiveMSafeTestMarkers(){
    std::vector<Record> result;
    wchar_t temp[MAX_PATH]={};
    DWORD len=GetTempPathW(MAX_PATH,temp);
    if(!len || len>=MAX_PATH)return result;
    const fs::path root=fs::path(temp)/L"SyncPCChecker-FiveM-SafeTest";
    struct Marker {const wchar_t* filename;const char* label;const char* id;};
    const Marker markers[]={
        {L"injector-indicator.txt","FiveM injector indicator","FIVEM-TEST-001"},
        {L"credential-theft-indicator.txt","Credential theft indicator","FIVEM-TEST-002"},
        {L"startup-persistence-indicator.txt","Persistence indicator","FIVEM-TEST-003"},
        {L"network-c2-indicator.txt","Command-and-control indicator","FIVEM-TEST-004"},
    };
    for(const auto& marker:markers){
        if(cancelRequested)break;
        std::error_code ec;
        const fs::path path=root/marker.filename;
        if(!fs::is_regular_file(path,ec) || ec)continue;
        if(fs::file_size(path,ec)>4096 || ec)continue;
        std::ifstream in(path,std::ios::binary);
        if(!in)continue;
        std::string contents((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
        const std::string expected=std::string("SYNCPC_FIVEM_SAFE_TEST_V1|")+marker.id;
        if(contents.find(expected)==std::string::npos)continue;
        result.push_back({"FiveM Safe Test",marker.label,
            std::string(marker.id)+" | DETECTED TEST MARKER ONLY | "
            "Simulated evidence, NOT an actual malware detection"});
    }
    return result;
}


// Read-only executable provenance audit. No score and no malware verdict.
// Checks misleading executable names and Mark-of-the-Web metadata for active
// process images; each file is visited once, with bounded I/O.
static std::vector<Record> inspectExecutableProvenance(
    const std::vector<Process>& items) {
    std::vector<Record> out;
    std::unordered_set<std::wstring> visited;
    size_t inspected=0;
    for(const auto& proc:items) {
        if(cancelRequested || inspected>=350)break;
        if(proc.path.empty() || proc.path[0]==L'[')continue;
        const std::wstring path=lowerPath(proc.path);
        if(!visited.insert(path).second)continue;
        ++inspected;
        const fs::path exe(proc.path);
        const std::wstring filename=lowerPath(exe.filename().wstring());
        // An executable named like a document is worth reviewing, but is not
        // proof of malicious activity.
        static const wchar_t* deceptiveSuffixes[]={
            L".pdf.exe",L".jpg.exe",L".jpeg.exe",L".png.exe",
            L".doc.exe",L".docx.exe",L".txt.exe",L".zip.exe",
            L".mp4.exe",L".xlsx.exe",L".scr.exe"
        };
        for(const auto* suffix:deceptiveSuffixes){
            const std::wstring tail(suffix);
            if(filename.size()>=tail.size() &&
               filename.compare(filename.size()-tail.size(),tail.size(),tail)==0){
                out.push_back({"Executable Provenance",utf8(exe.filename().wstring()),
                    "REVIEW: Active executable has a document/media-like double extension. "
                    "Path: "+utf8(proc.path)+" | This alone does not establish malware."});
                break;
            }
        }
        // Zone.Identifier is an optional NTFS alternate data stream written by
        // Windows and browsers. Its absence is normal and not a clean verdict.
        const std::wstring ads=proc.path+L":Zone.Identifier";
        HANDLE file=CreateFileW(ads.c_str(),GENERIC_READ,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,
            OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file==INVALID_HANDLE_VALUE)continue;
        char buffer[2049]={};
        DWORD bytes=0;
        const BOOL ok=ReadFile(file,buffer,2048,&bytes,nullptr);
        CloseHandle(file);
        if(!ok || !bytes)continue;
        const std::string zone(buffer,bytes);
        const size_t pos=zone.find("ZoneId=");
        if(pos==std::string::npos)continue;
        const size_t digit=pos+7;
        if(digit>=zone.size())continue;
        if(zone[digit]=='3' || zone[digit]=='4'){
            out.push_back({"Executable Provenance",utf8(exe.filename().wstring()),
                std::string("INFO: Running executable carries Mark-of-the-Web ZoneId=")+
                zone[digit]+" (Internet/Restricted). Path: "+utf8(proc.path)+
                " | Origin metadata only; not a malware verdict."});
        }
    }
    return out;
}


// Engine 3.0: bounded, read-only inspection of modules actually loaded by
// processes. Findings describe evidence, not a confirmed injection or infection.
static std::vector<Record> inspectLoadedModuleProvenance(
    const std::vector<Process>& items){
    std::vector<Record> out;
    std::unordered_set<std::wstring> seen;
    const std::wstring windows=lowerPath(windowsRoot());
    wchar_t tempBuf[MAX_PATH]={};
    const DWORD tempLen=GetTempPathW(MAX_PATH,tempBuf);
    const std::wstring temp=(tempLen && tempLen<MAX_PATH)?
        lowerPath(std::wstring(tempBuf,tempLen)):L"";
    size_t processesChecked=0, modulesChecked=0, signatureChecks=0;
    for(const auto& proc:items){
        if(cancelRequested || processesChecked>=90 || modulesChecked>=1200)break;
        if(proc.pid==0 || proc.pid==4)continue;
        ++processesChecked;
        HANDLE snapshot=CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,proc.pid);
        if(snapshot==INVALID_HANDLE_VALUE)continue;
        MODULEENTRY32W module{};module.dwSize=sizeof(module);
        if(Module32FirstW(snapshot,&module)){
            do{
                if(cancelRequested || modulesChecked>=1200)break;
                ++modulesChecked;
                const std::wstring path=module.szExePath;
                if(path.empty() || !seen.insert(lowerPath(path)).second)continue;
                const std::wstring normalized=lowerPath(path);
                const bool inWindows=startsWithPath(normalized,windows);
                const bool inTemp=!temp.empty() && startsWithPath(normalized,temp);
                const bool inUserTemp=
                    normalized.find(L"\\appdata\\local\\temp\\")!=std::wstring::npos;
                if(inTemp || inUserTemp){
                    out.push_back({"Module Provenance",utf8(module.szModule),
                        "NEEDS REVIEW | A running process loaded a module from a temporary "
                        "directory. Process: "+utf8(proc.name)+
                        " | Module: "+utf8(path)+
                        " | Why: temporary paths are unusual for persistent libraries. "
                        "Check the publisher and application context; this is not proof of injection."});
                }
                // Validate a limited number of non-Windows modules. Unsigned
                // modules are common and are recorded as informational only.
                if(!inWindows && signatureChecks<75){
                    ++signatureChecks;
                    const std::string sig=signatureStatus(path);
                    if(sig.find("Valid")==std::string::npos){
                        out.push_back({"Module Signature",utf8(module.szModule),
                            "INFO | Signature verification: "+sig+
                            " | Loaded by: "+utf8(proc.name)+
                            " | Path: "+utf8(path)+
                            " | Missing/invalid signatures alone do not prove malware."});
                    }
                }
            }while(Module32NextW(snapshot,&module));
        }
        CloseHandle(snapshot);
    }
    return out;
}

// Read-only review of active executables located in temporary folders.
static std::vector<Record> inspectTemporaryExecutables(
    const std::vector<Process>& items){
    std::vector<Record> out;
    wchar_t tempBuf[MAX_PATH]={};
    const DWORD len=GetTempPathW(MAX_PATH,tempBuf);
    const std::wstring temp=(len && len<MAX_PATH)?
        lowerPath(std::wstring(tempBuf,len)):L"";
    std::unordered_set<std::wstring> seen;
    for(const auto& proc:items){
        if(cancelRequested)break;
        if(proc.path.empty())continue;
        const std::wstring path=lowerPath(proc.path);
        if(!seen.insert(path).second)continue;
        if((!temp.empty() && startsWithPath(path,temp)) ||
           path.find(L"\\appdata\\local\\temp\\")!=std::wstring::npos){
            out.push_back({"Executable Location",utf8(proc.name),
                "NEEDS REVIEW | An active executable is running from a temporary "
                "folder. PID: "+std::to_string(proc.pid)+
                " | Path: "+utf8(proc.path)+
                " | What to check: publisher, file origin and expected installer activity. "
                "Temporary-folder execution alone does not mean malware."});
        }
    }
    return out;
}


// Explicit filename-based FiveM screening rule requested by the operator.
// A name match is DETECTED as a rule hit, never as proof of malware.
// Match the filename only (not parent directories), case-insensitively.
static bool isCheatNameRuleMatch(const std::wstring& filename){
    const std::wstring name=lowerPath(fs::path(filename).filename().wstring());
    return name.find(L"cheat")!=std::wstring::npos ||
           name.find(L"external")!=std::wstring::npos;
}
static std::vector<Record> inspectCheatNamedProcesses(
    std::vector<Process>& items){
    std::vector<Record> out;
    for(auto& proc:items){
        if(cancelRequested)break;
        if(!isCheatNameRuleMatch(proc.name) &&
           (proc.path.empty() || !isCheatNameRuleMatch(proc.path)))continue;
        proc.suspicious=true;
        const std::string note=
            "DETECTED - NAME RULE | Process filename contains CHEAT or EXTERNAL. "
            "PID: "+std::to_string(proc.pid)+
            " | Path: "+utf8(proc.path)+
            " | Why: the operator enabled a broad FiveM cheat-name rule. "
            "This is a filename match, NOT confirmed malware or proof of cheating.";
        if(!proc.assessment.empty())proc.assessment+=" | ";
        proc.assessment+="DETECTED: CHEAT/EXTERNAL filename rule (name only)";
        out.push_back({"FiveM Cheat Name Detection",utf8(proc.name),note});
    }
    return out;
}

// Read-only heuristic inventory of loaded DLL names and locations.
// No code injection, execution, or attempt to bypass protected processes.
static std::atomic<unsigned> dllModulesExamined{0},dllReviewFindings{0};
static std::vector<Record> inspectExpandedDllIndicators(const std::vector<Process>& items){
    std::vector<Record> out;
    std::unordered_set<std::wstring> seen;
    static const std::vector<std::wstring> terms={
        L"bypass",L"cheat",L"inject",L"spoofer",L"aimbot",L"triggerbot",
        L"executor",L"redengine",L"eulen",L"fivem",L"hook",
        L"manualmap",L"mapper",L"loader",L"overlay"
    };
    size_t processes=0;
    for(const auto& proc:items){
        if(cancelRequested || processes>=180 || dllModulesExamined.load()>=3500)break;
        if(!proc.pid || proc.pid==4)continue;
        ++processes;
        HANDLE snapshot=CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,proc.pid);
        if(snapshot==INVALID_HANDLE_VALUE)continue;
        MODULEENTRY32W mod{};mod.dwSize=sizeof(mod);
        if(Module32FirstW(snapshot,&mod)){
            do{
                if(cancelRequested || dllModulesExamined.load()>=3500)break;
                const std::wstring path=mod.szExePath;
                const std::wstring filename=lowerPath(mod.szModule);
                if(fs::path(filename).extension()!=L".dll")continue;
                ++dllModulesExamined;
                const std::wstring unique=std::to_wstring(proc.pid)+L"|"+lowerPath(path);
                if(!seen.insert(unique).second)continue;
                std::string reason;
                for(const auto& term:terms){
                    if(filename.find(term)!=std::wstring::npos){
                        reason="Filename keyword: "+utf8(term);
                        break;
                    }
                }
                const auto normalized=lowerPath(path);
                const bool userWritableLocation=
                    normalized.find(L"\\appdata\\local\\temp\\")!=std::wstring::npos ||
                    normalized.find(L"\\downloads\\")!=std::wstring::npos ||
                    normalized.find(L"\\desktop\\")!=std::wstring::npos ||
                    normalized.find(L"\\recycle.bin\\")!=std::wstring::npos;
                if(userWritableLocation){
                    if(!reason.empty())reason+=" | ";
                    reason+="Loaded from user-writable/unusual location";
                }
                // User-mode DLL indicators: name alone is a lead, not a verdict.
                // Pair filename signals with the loading process and full path.
                const bool usermodeName=
                    filename.find(L"usermode")!=std::wstring::npos ||
                    filename.find(L"user_mode")!=std::wstring::npos ||
                    filename.find(L"umode")!=std::wstring::npos;
                const bool usermodeRelated=
                    usermodeName ||
                    (userWritableLocation &&
                     (filename.find(L"inject")!=std::wstring::npos ||
                      filename.find(L"manualmap")!=std::wstring::npos ||
                      filename.find(L"bypass")!=std::wstring::npos));
                const std::wstring procName=lowerPath(proc.name);
                const bool obsProcess=procName==L"obs64.exe" || procName==L"obs32.exe";
                if(obsProcess && userWritableLocation){
                    out.push_back({"OBS Module Review",utf8(mod.szModule),
                        "REVIEW ONLY | OBS loaded a DLL from a user-writable location"
                        " | PID: "+std::to_string(proc.pid)+
                        " | Path: "+utf8(path)+
                        " | Check the plugin origin and signature; this is not proof of injection."});
                }
                if(usermodeRelated){
                    out.push_back({"Usermode DLL Review",utf8(mod.szModule),
                        "REVIEW ONLY | Loaded user-mode DLL indicator"
                        " | Process: "+utf8(proc.name)+
                        " | PID: "+std::to_string(proc.pid)+
                        " | Path: "+utf8(path)+
                        " | Reason: "+std::string(usermodeName?
                          "usermode/umode filename token":
                          "injection-related filename in unusual location")+
                        " | A user-mode DLL is not inherently malicious; "
                        "this does not prove injection, cheating or bypass."});
                }
                if(reason.empty() && !usermodeRelated)continue;
                ++dllReviewFindings;
                out.push_back({"DLL Review Indicator",utf8(mod.szModule),
                    "REVIEW ONLY | "+reason+" | Process: "+utf8(proc.name)+
                    " | PID: "+std::to_string(proc.pid)+
                    " | Path: "+utf8(path)+
                    " | Filename/path heuristics do not prove injection or bypass."});
            }while(Module32NextW(snapshot,&mod));
        }
        CloseHandle(snapshot);
    }
    return out;
}
static std::vector<Record> inspectCheatNamedModules(
    const std::vector<Process>& items){
    std::vector<Record> out;
    std::unordered_set<std::wstring> seen;
    size_t checked=0;
    for(const auto& proc:items){
        if(cancelRequested || checked>=120)break;
        if(!proc.pid || proc.pid==4)continue;
        ++checked;
        HANDLE snap=CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,proc.pid);
        if(snap==INVALID_HANDLE_VALUE)continue;
        MODULEENTRY32W m{};m.dwSize=sizeof(m);
        if(Module32FirstW(snap,&m)){
            do{
                if(cancelRequested)break;
                if(!isCheatNameRuleMatch(m.szModule))continue;
                const std::wstring key=std::to_wstring(proc.pid)+L"|"+lowerPath(m.szExePath);
                if(!seen.insert(key).second)continue;
                out.push_back({"FiveM Cheat Name Detection",utf8(m.szModule),
                    "DETECTED - NAME RULE | Loaded module filename contains CHEAT "
                    "or EXTERNAL. Process: "+utf8(proc.name)+
                    " | PID: "+std::to_string(proc.pid)+
                    " | Module: "+utf8(m.szExePath)+
                    " | This is a name match only, not confirmed injection or malware."});
            }while(Module32NextW(snap,&m));
        }
        CloseHandle(snap);
    }
    return out;
}


// Read-only artifact inventory. Bounded directory traversal avoids unbounded
// scans of large user profiles and never follows directory symlinks.
static std::vector<Record> inspectArtifactLocations(){
    std::vector<Record> out;
    struct Root {fs::path path;std::string label;int depth;};
    std::vector<Root> roots;
    auto addRoot=[&](const fs::path& p,const char* label,int depth){
        std::error_code ec;
        if(fs::is_directory(p,ec))roots.push_back({p,label,depth});
    };
    wchar_t buf[32768]={};
    DWORD n=GetTempPathW(32768,buf);
    if(n && n<32768)addRoot(fs::path(buf),"User TEMP",5);
    n=GetWindowsDirectoryW(buf,32768);
    if(n && n<32768){
        addRoot(fs::path(buf)/L"Prefetch","Windows Prefetch",0);
        addRoot(fs::path(buf)/L"Temp","Windows TEMP",4);
    }
    auto envRoot=[&](const wchar_t* key)->fs::path{
        wchar_t value[32768]={};
        const DWORD size=GetEnvironmentVariableW(key,value,32768);
        return size && size<32768?fs::path(value):fs::path();
    };
    const fs::path user=envRoot(L"USERPROFILE");
    if(!user.empty()){
        addRoot(user/L"Desktop","Desktop",7);
        addRoot(user/L"Downloads","Downloads",8);
        addRoot(user/L"Documents","Documents",6);
        addRoot(user/L"AppData"/L"Local","Local AppData",5);
        addRoot(user/L"AppData"/L"Roaming","Roaming AppData",5);
    }
    const fs::path appdata=envRoot(L"APPDATA");
    if(!appdata.empty())
        addRoot(appdata/L"Microsoft"/L"Windows"/L"Start Menu"/
                L"Programs"/L"Startup","User Startup",2);
    const fs::path programData=envRoot(L"PROGRAMDATA");
    if(!programData.empty())
        addRoot(programData/L"Microsoft"/L"Windows"/L"Start Menu"/
                L"Programs"/L"Startup","Common Startup",2);
    const wchar_t* extensions[]={L".exe",L".dll",L".sys",L".pf",
                                  L".ps1",L".bat",L".cmd",L".vbs",L".js",L".lnk"};
    size_t inventoryCount=0,matchCount=0;
    std::unordered_set<std::wstring> seenMatches;
    for(const auto& root:roots){
        if(cancelRequested)break;
        std::error_code ec;
        fs::recursive_directory_iterator it(root.path,
            fs::directory_options::skip_permission_denied,ec),end;
        size_t visited=0;
        while(it!=end && !cancelRequested && visited<20000){
            if(it.depth()>=root.depth)it.disable_recursion_pending();
            std::error_code fileEc;
            if(it->is_symlink(fileEc))it.disable_recursion_pending();
            if(it->is_regular_file(fileEc) && !fileEc){
                const fs::path path=it->path();
                const std::wstring ext=lowerPath(path.extension().wstring());
                bool supported=false;
                for(const wchar_t* x:extensions)if(ext==x){supported=true;break;}
                if(supported){
                    const bool match=isCheatNameRuleMatch(path.filename().wstring());
                    const std::string name=utf8(path.filename().wstring());
                    const std::string fullPath=utf8(path.wstring());
                    if(match && matchCount<1200 &&
                       seenMatches.insert(lowerPath(path.wstring())).second){
                        ++matchCount;
                        out.push_back({"FiveM Cheat Name Detection",name,
                            "DETECTED - NAME RULE | Filename contains CHEAT or EXTERNAL. "
                            "Location: "+root.label+" | Path: "+fullPath+
                            " | This confirms a filename match, not actual cheating or malware."});
                    }
                    if(inventoryCount<2200){
                        ++inventoryCount;
                        const std::string category=ext==L".pf"?"Artifact: Prefetch":
                            ext==L".sys"?"Artifact: Driver":
                            ext==L".dll"?"Artifact: DLL":
                            ext==L".exe"?"Artifact: EXE":"Artifact: Script/Shortcut";
                        out.push_back({category,name,
                            std::string(match?"DETECTED - NAME RULE":"INVENTORY")+
                            " | Location: "+root.label+" | File: "+fullPath+
                            " | File presence alone does not prove malware."});
                    }
                }
            }
            ++visited;
            it.increment(ec);
            if(ec)ec.clear();
        }
        if(visited>=20000){
            out.push_back({"Artifact Scan Coverage",root.label,
                "PARTIAL SCAN | Directory visit limit reached (20,000 entries). "
                "Some files in this location may not have been checked."});
        }
    }
    return out;
}


// Engine 4: local indicator matching + read-only historical execution evidence.
// Indicator lists are optional. No network calls, no system changes.
static std::vector<Record> inspectAdditionalEvidence(
    const std::vector<Process>& processes){
    std::vector<Record> result;
    std::unordered_set<std::wstring> paths;
    for(const auto& p:processes)
        if(!p.path.empty() && p.path[0]!=L'[')paths.insert(p.path);
    wchar_t temp[MAX_PATH]={},win[MAX_PATH]={};
    DWORD tn=GetTempPathW(MAX_PATH,temp);
    UINT wn=GetWindowsDirectoryW(win,MAX_PATH);
    std::vector<fs::path> roots;
    if(tn && tn<MAX_PATH)roots.push_back(fs::path(temp));
    if(wn && wn<MAX_PATH)roots.push_back(fs::path(win)/L"Prefetch");
    wchar_t profile[MAX_PATH]={};
    DWORD pn=GetEnvironmentVariableW(L"USERPROFILE",profile,MAX_PATH);
    if(pn && pn<MAX_PATH){
        roots.push_back(fs::path(profile)/L"Desktop");
        roots.push_back(fs::path(profile)/L"Downloads");
    }
    // Local SHA-256 indicator database: supports 250,000 distinct hashes.
    // Format: <64 hex characters> [optional human-readable label]
    // Data is never downloaded or executed; malformed entries are ignored.
    std::unordered_map<std::string,std::string> knownHashes;
    size_t invalidHashLines=0;
    bool hashDatabaseFound=false;
    bool hashDatabaseTruncated=false;
    wchar_t self[MAX_PATH]={};
    if(GetModuleFileNameW(nullptr,self,MAX_PATH)){
        const fs::path database=fs::path(self).parent_path()/L"threat-hashes.txt";
        std::ifstream db(database);
        hashDatabaseFound=db.is_open();
        std::string line;
        size_t linesRead=0;
        while(db && std::getline(db,line) && linesRead<300000){
            ++linesRead;
            if(line.empty() || line[0]=='#')continue;
            if(line.size()<64){++invalidHashLines;continue;}
            std::string hash=line.substr(0,64);
            if(!std::all_of(hash.begin(),hash.end(),[](unsigned char c){
                return std::isxdigit(c)!=0;})){
                ++invalidHashLines;continue;
            }
            if(line.size()>64 && line[64]!=' ' && line[64]!='\t' &&
               line[64]!=';' && line[64]!='#'){
                ++invalidHashLines;continue;
            }
            std::transform(hash.begin(),hash.end(),hash.begin(),
                [](unsigned char c){return (char)std::tolower(c);});
            std::string label;
            if(line.size()>65){
                const size_t first=line.find_first_not_of(" \t;#",64);
                if(first!=std::string::npos)label=line.substr(first,120);
            }
            if(knownHashes.size()>=250000 && !knownHashes.count(hash)){
                hashDatabaseTruncated=true;
                break;
            }
            knownHashes.emplace(std::move(hash),std::move(label));
        }
        if(linesRead>=300000)hashDatabaseTruncated=true;
    }
    result.push_back({"Detection Coverage","SHA-256 indicator database",
        "INFO | Loaded "+std::to_string(knownHashes.size())+
        " unique SHA-256 indicators from threat-hashes.txt. "+
        (hashDatabaseFound?"Database file found. ":"Database not installed. ")+
        "Malformed lines: "+std::to_string(invalidHashLines)+
        (hashDatabaseTruncated?". Database safety limit reached.":"")+
        " | Hash matches require trusted, independently verified indicators."});
    size_t visited=0;
    for(const auto& root:roots){
        if(cancelRequested || visited>=9000)break;
        std::error_code ec;
        fs::recursive_directory_iterator it(root,
            fs::directory_options::skip_permission_denied,ec),end;
        while(it!=end && !cancelRequested && visited<9000){
            if(it.depth()>3 || it->is_symlink(ec))it.disable_recursion_pending();
            std::error_code fileEc;
            if(it->is_regular_file(fileEc) && !fileEc){
                const auto path=it->path();
                const std::wstring ext=lowerPath(path.extension().wstring());
                if(ext==L".exe" || ext==L".dll" || ext==L".sys")
                    paths.insert(path.wstring());
                if(ext==L".pf"){
                    const std::wstring name=lowerPath(path.filename().wstring());
                    if(name.find(L"cheat")!=std::wstring::npos ||
                       name.find(L"external")!=std::wstring::npos){
                        result.push_back({"Execution Artifact",utf8(path.filename().wstring()),
                            "DETECTED - NAME RULE | Prefetch filename contains CHEAT or "
                            "EXTERNAL. Path: "+utf8(path.wstring())+
                            " | Prefetch is historical execution-related evidence, "
                            "not proof of cheating or malware."});
                    }
                }
            }
            ++visited;
            it.increment(ec);
            if(ec)ec.clear();
        }
    }
    size_t hashed=0, signedChecked=0;
    size_t skippedLargeFiles=0;
    for(const auto& path:paths){
        if(cancelRequested || hashed>=350)break;
        std::error_code ec;
        const fs::path file(path);
        if(!fs::is_regular_file(file,ec) || ec)continue;
        const auto size=fs::file_size(file,ec);
        if(ec)continue;
        if(size>100ull*1024*1024){++skippedLargeFiles;continue;}
        const std::wstring ext=lowerPath(file.extension().wstring());
        if(ext!=L".exe" && ext!=L".dll" && ext!=L".sys")continue;
        ++hashed;
        const std::string digest=sha256(path);
        if(!digest.empty() && !knownHashes.empty()){
            std::string key=digest;
            std::transform(key.begin(),key.end(),key.begin(),
                [](unsigned char c){return (char)std::tolower(c);});
            const auto hit=knownHashes.find(key);
            if(hit!=knownHashes.end())
                result.push_back({"Known Hash Indicator",utf8(file.filename().wstring()),
                    "DETECTED - SHA256 MATCH | Hash: "+key+
                    " | Path: "+utf8(path)+
                    (hit->second.empty()?"":" | Indicator label: "+hit->second)+
                    " | Matched local threat-hashes.txt. Verify the indicator source."});
        }
        if(signedChecked<90){
            ++signedChecked;
            const std::string signature=signatureStatus(path);
            if(signature.find("Valid")==std::string::npos &&
               (isCheatNameRuleMatch(file.filename().wstring()) ||
                lowerPath(path).find(L"\\temp\\")!=std::wstring::npos)){
                result.push_back({"Signature Review",utf8(file.filename().wstring()),
                    "NEEDS REVIEW | Signature: "+signature+
                    " | Path: "+utf8(path)+
                    " | An absent or invalid signature alone does not prove malware."});
            }
        }
    }
    if(visited>=9000)
        result.push_back({"Scan Coverage","Artifact traversal limit",
            "INFO | Historical artifact inspection reached its 9000-entry "
            "safety limit. Some files were not inspected."});
    result.push_back({"Detection Coverage","File hash inspection",
        "INFO | Inspected "+std::to_string(hashed)+
        " executable/module files. Skipped oversized files: "+
        std::to_string(skippedLargeFiles)+
        ". This is partial coverage, not a clean-system verdict."});
    if(hashed>=350)
        result.push_back({"Scan Coverage","Hash inspection limit",
            "INFO | SHA-256 inspection reached its 350-file safety limit. "
            "Some files were not hashed."});
    return result;
}


// Additional read-only, evidence-based checks for persistence and masquerading.
// A hit is a review indicator, never a confirmed malware verdict.
static std::vector<Record> inspectExpandedPersistenceIndicators(){
    std::vector<Record> out;
    struct RegistryLocation {
        HKEY root; const wchar_t* key; const char* label;
    };
    const RegistryLocation locations[]={
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run","User policy autorun"},
        {HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run","Machine policy autorun"},
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows","User Windows load"},
        {HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows","Machine Windows load"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows","AppInit DLL configuration"},
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Command Processor","User command processor"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Command Processor","Machine command processor"},
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices","Legacy user autorun"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices","Legacy machine autorun"},
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce","Legacy user one-shot autorun"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce","Legacy machine one-shot autorun"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify","Winlogon notification"},
    };
    const std::wstring suspiciousTerms[]={
        L"\\temp\\",L"\\appdata\\local\\temp\\",L"powershell -enc",
        L"powershell.exe -enc",L" -encodedcommand",L"frombase64string",
        L"wscript.exe",L"cscript.exe",L"mshta.exe",L"regsvr32.exe",
        L"rundll32.exe",L"\\downloads\\",L".vbs",L".js",L".ps1"
    };
    for(const auto& location:locations){
        if(cancelRequested)break;
        HKEY key=nullptr;
        if(RegOpenKeyExW(location.root,location.key,0,KEY_READ,&key)!=ERROR_SUCCESS)
            continue;
        for(DWORD i=0;i<512 && !cancelRequested;++i){
            wchar_t name[512]={};DWORD nameLen=511;
            BYTE data[8192]={};DWORD dataSize=sizeof(data),type=0;
            const LONG rc=RegEnumValueW(key,i,name,&nameLen,nullptr,
                                        &type,data,&dataSize);
            if(rc==ERROR_NO_MORE_ITEMS)break;
            if(rc!=ERROR_SUCCESS || (type!=REG_SZ && type!=REG_EXPAND_SZ) ||
               dataSize<sizeof(wchar_t))continue;
            const auto* ptr=reinterpret_cast<const wchar_t*>(data);
            const size_t count=dataSize/sizeof(wchar_t);
            const std::wstring value(ptr,wcsnlen_s(ptr,count));
            if(value.empty())continue;
            const std::wstring normalized=lowerPath(value);
            std::string reasons;
            for(const auto& term:suspiciousTerms){
                if(normalized.find(term)!=std::wstring::npos){
                    if(!reasons.empty())reasons+=", ";
                    reasons+=utf8(term);
                }
            }
            if(isCheatNameRuleMatch(value) ||
               isCheatNameRuleMatch(name)){
                if(!reasons.empty())reasons+=", ";
                reasons+="CHEAT/EXTERNAL filename rule";
            }
            if(reasons.empty())continue;
            out.push_back({"Expanded Persistence",utf8(name),
                "NEEDS REVIEW | "+std::string(location.label)+
                " | Matched: "+reasons+
                " | Registry value: "+utf8(value)+
                " | Why: this autorun-related setting references a path or "
                "command worth checking. It is not proof of malware."});
        }
        RegCloseKey(key);
    }
    return out;
}

// Inspect accessible startup folders for executable and script filenames.
// Shortcut files are inventoried but their targets are not assumed.
static std::vector<Record> inspectStartupFolderIndicators(){
    std::vector<Record> out;
    wchar_t roaming[MAX_PATH]={},programData[MAX_PATH]={};
    DWORD r=GetEnvironmentVariableW(L"APPDATA",roaming,MAX_PATH);
    DWORD p=GetEnvironmentVariableW(L"PROGRAMDATA",programData,MAX_PATH);
    std::vector<fs::path> roots;
    const fs::path suffix=L"Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    if(r && r<MAX_PATH)roots.push_back(fs::path(roaming)/suffix);
    if(p && p<MAX_PATH)roots.push_back(fs::path(programData)/suffix);
    for(const auto& root:roots){
        if(cancelRequested)break;
        std::error_code ec;
        fs::directory_iterator it(root,
            fs::directory_options::skip_permission_denied,ec),end;
        size_t visited=0;
        while(it!=end && !cancelRequested && visited++<512){
            std::error_code fileEc;
            if(it->is_regular_file(fileEc) && !fileEc){
                const fs::path file=it->path();
                const std::wstring ext=lowerPath(file.extension().wstring());
                const bool script=ext==L".vbs"||ext==L".js"||
                    ext==L".ps1"||ext==L".bat"||ext==L".cmd"||ext==L".wsf";
                const bool executable=ext==L".exe"||ext==L".scr"||ext==L".com";
                const bool nameRule=isCheatNameRuleMatch(file.filename().wstring());
                if(script || executable || nameRule){
                    out.push_back({"Startup File Review",utf8(file.filename().wstring()),
                        std::string(nameRule?"DETECTED - NAME RULE":"NEEDS REVIEW")+
                        " | Startup folder contains "+
                        (script?"a script":executable?"an executable":"a name-rule match")+
                        " | Path: "+utf8(file.wstring())+
                        " | Verify that this entry is expected. Its presence "
                        "does not establish malicious behavior."});
                }
            }
            it.increment(ec);
            if(ec)ec.clear();
        }
    }
    return out;
}


// Engine 3.2 - Additional read-only persistence and file metadata evidence.
// All detections below describe observed settings, not proven compromise.
static std::vector<Record> inspectSpecialPersistenceKeys(){
    std::vector<Record> out;
    struct KeyRule{HKEY root;const wchar_t* key;const char* label;};
    const KeyRule keys[]={
        {HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls","AppCert DLL registration"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit","Silent Process Exit configuration"},
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit","User Silent Process Exit configuration"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options","Image Execution Options"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows","Windows AppInit configuration"},
        {HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Lsa","LSA configuration"}
    };
    size_t findings=0;
    for(const auto& rule:keys){
        if(cancelRequested || findings>=250)break;
        HKEY key=nullptr;
        if(RegOpenKeyExW(rule.root,rule.key,0,KEY_READ,&key)!=ERROR_SUCCESS)
            continue;
        // For large configuration roots, only inspect selected values,
        // never treat ordinary subkey presence as an infection.
        const wchar_t* wanted[]={
            L"AppInit_DLLs",L"LoadAppInit_DLLs",L"Notification Packages",
            L"Security Packages",L"Authentication Packages",
            L"GlobalFlag",L"ReportingMode",L"MonitorProcess",
            L"Debugger",L"VerifierDlls"
        };
        for(const wchar_t* valueName:wanted){
            if(cancelRequested || findings>=250)break;
            BYTE buffer[8192]={};DWORD type=0,size=sizeof(buffer);
            if(RegQueryValueExW(key,valueName,nullptr,&type,buffer,&size)!=ERROR_SUCCESS)
                continue;
            if(type!=REG_SZ && type!=REG_EXPAND_SZ && type!=REG_MULTI_SZ)
                continue;
            if(size<sizeof(wchar_t) || size>=sizeof(buffer))continue;
            const auto* wide=reinterpret_cast<const wchar_t*>(buffer);
            const size_t n=size/sizeof(wchar_t);
            std::wstring value(wide,wcsnlen_s(wide,n));
            if(value.empty())continue;
            const std::wstring low=lowerPath(value);
            const bool suspicious=
                low.find(L"\\temp\\")!=std::wstring::npos ||
                low.find(L"\\downloads\\")!=std::wstring::npos ||
                low.find(L"powershell")!=std::wstring::npos ||
                low.find(L"wscript")!=std::wstring::npos ||
                low.find(L"mshta")!=std::wstring::npos ||
                low.find(L"cheat")!=std::wstring::npos ||
                low.find(L"external")!=std::wstring::npos;
            if(!suspicious)continue;
            ++findings;
            out.push_back({"Special Persistence",utf8(valueName),
                "NEEDS REVIEW | "+std::string(rule.label)+
                " references an unusual location or command. Value: "+
                utf8(value)+" | Confirm whether the setting belongs to "
                "legitimate installed software. Not proof of malware."});
        }
        // AppCertDlls entries are named values, rather than one fixed value.
        if(std::wstring(rule.key).find(L"AppCertDlls")!=std::wstring::npos){
            for(DWORD i=0;i<128 && findings<250 && !cancelRequested;++i){
                wchar_t name[256]={};DWORD nameSize=255;
                BYTE data[4096]={};DWORD dataSize=sizeof(data),type=0;
                LONG rc=RegEnumValueW(key,i,name,&nameSize,nullptr,&type,data,&dataSize);
                if(rc==ERROR_NO_MORE_ITEMS)break;
                if(rc!=ERROR_SUCCESS ||
                   (type!=REG_SZ && type!=REG_EXPAND_SZ) ||
                   dataSize<sizeof(wchar_t))continue;
                const wchar_t* ptr=reinterpret_cast<const wchar_t*>(data);
                const std::wstring value(ptr,wcsnlen_s(ptr,dataSize/sizeof(wchar_t)));
                if(value.empty())continue;
                ++findings;
                out.push_back({"Special Persistence",utf8(name),
                    "NEEDS REVIEW | AppCert DLL entry points to: "+utf8(value)+
                    " | Verify the publisher and purpose of this registered module. "
                    "Registration alone does not prove malware."});
            }
        }
        RegCloseKey(key);
    }
    return out;
}

// NTFS alternate data streams can hold extra content. Only report streams
// actually enumerated on active executable images; do not read stream contents.
static std::vector<Record> inspectExecutableAlternateStreams(
    const std::vector<Process>& items){
    std::vector<Record> out;
    std::unordered_set<std::wstring> seen;
    size_t checked=0,reported=0;
    for(const auto& proc:items){
        if(cancelRequested || checked>=240 || reported>=120)break;
        if(proc.path.empty() || proc.path[0]==L'[')continue;
        const std::wstring normalized=lowerPath(proc.path);
        if(!seen.insert(normalized).second)continue;
        ++checked;
        WIN32_FIND_STREAM_DATA stream{};
        HANDLE handle=FindFirstStreamW(proc.path.c_str(),
            FindStreamInfoStandard,&stream,0);
        if(handle==INVALID_HANDLE_VALUE)continue;
        do{
            if(cancelRequested || reported>=120)break;
            const std::wstring streamName=stream.cStreamName;
            if(streamName==L"::$DATA" ||
               lowerPath(streamName)==L":zone.identifier:$data")continue;
            ++reported;
            out.push_back({"Executable Alternate Stream",utf8(proc.name),
                "NEEDS REVIEW | Additional NTFS data stream: "+
                utf8(streamName)+" | File: "+utf8(proc.path)+
                " | Extra streams can be legitimate metadata; inspect their "
                "origin before drawing conclusions."});
        }while(FindNextStreamW(handle,&stream));
        FindClose(handle);
    }
    return out;
}


// Additional evidence-based checks. Registry is opened read-only and bounded.
// A detection below means a configured rule matched, not confirmed malware.
static std::vector<Record> inspectImageExecutionHijackSettings(){
    std::vector<Record> out;
    struct Root {const wchar_t* path;const char* label;};
    const Root roots[]={
        {L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options","IFEO"},
        {L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit","SilentProcessExit"}
    };
    const wchar_t* names[]={L"Debugger",L"VerifierDlls",L"MonitorProcess"};
    for(const auto& root:roots){
        if(cancelRequested)break;
        HKEY parent=nullptr;
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,root.path,0,
                         KEY_READ|KEY_WOW64_64KEY,&parent)!=ERROR_SUCCESS)
            continue;
        for(DWORD i=0;i<1600 && !cancelRequested && out.size()<220;++i){
            wchar_t subkey[512]={};DWORD len=511;
            LONG rc=RegEnumKeyExW(parent,i,subkey,&len,nullptr,nullptr,nullptr,nullptr);
            if(rc==ERROR_NO_MORE_ITEMS)break;
            if(rc!=ERROR_SUCCESS)continue;
            HKEY child=nullptr;
            if(RegOpenKeyExW(parent,subkey,0,KEY_READ,&child)!=ERROR_SUCCESS)
                continue;
            for(const wchar_t* valueName:names){
                BYTE buffer[4096]={};DWORD type=0,size=sizeof(buffer);
                if(RegQueryValueExW(child,valueName,nullptr,&type,buffer,&size)
                   !=ERROR_SUCCESS || (type!=REG_SZ&&type!=REG_EXPAND_SZ) ||
                   size<sizeof(wchar_t) || size>=sizeof(buffer))continue;
                const auto* ptr=reinterpret_cast<const wchar_t*>(buffer);
                const std::wstring value(ptr,wcsnlen_s(ptr,size/sizeof(wchar_t)));
                if(value.empty())continue;
                const std::wstring low=lowerPath(value);
                const bool nameMatch=isCheatNameRuleMatch(value) ||
                                     isCheatNameRuleMatch(subkey);
                const bool unusual=low.find(L"\\temp\\")!=std::wstring::npos ||
                    low.find(L"\\downloads\\")!=std::wstring::npos ||
                    low.find(L"powershell")!=std::wstring::npos ||
                    low.find(L"mshta")!=std::wstring::npos ||
                    low.find(L"wscript")!=std::wstring::npos;
                out.push_back({"Execution Configuration",utf8(subkey),
                    std::string(nameMatch?"DETECTED - NAME RULE":
                                unusual?"NEEDS REVIEW":"INFO")+
                    " | "+root.label+" / "+utf8(valueName)+
                    " | Command or module: "+utf8(value)+
                    " | Why: Windows is configured to use this debugger, "
                    "verification DLL or exit monitor for the named program. "
                    "Review whether this is intentional; it is not proof of malware."});
            }
            RegCloseKey(child);
        }
        RegCloseKey(parent);
    }
    return out;
}

// Look for active executables using potentially misleading Unicode format
// characters in their names. No heuristic malware verdict is assigned.
static std::vector<Record> inspectFilenameMasquerading(
    const std::vector<Process>& processes){
    std::vector<Record> out;
    std::unordered_set<std::wstring> seen;
    for(const auto& p:processes){
        if(cancelRequested)break;
        if(p.path.empty() || p.path[0]==L'[')continue;
        const std::wstring name=fs::path(p.path).filename().wstring();
        if(!seen.insert(lowerPath(name)).second)continue;
        const bool rtl=name.find(wchar_t(0x202E))!=std::wstring::npos;
        const bool bidi=name.find(wchar_t(0x202D))!=std::wstring::npos ||
                        name.find(wchar_t(0x202A))!=std::wstring::npos ||
                        name.find(wchar_t(0x202B))!=std::wstring::npos ||
                        name.find(wchar_t(0x2066))!=std::wstring::npos ||
                        name.find(wchar_t(0x2067))!=std::wstring::npos ||
                        name.find(wchar_t(0x2068))!=std::wstring::npos;
        if(rtl || bidi)
            out.push_back({"Filename Masquerading",utf8(name),
                "NEEDS REVIEW | Active executable filename contains a "
                "bidirectional Unicode formatting character. Path: "+
                utf8(p.path)+" | Such characters can change how a name is "
                "displayed. Verify the actual file extension and publisher."});
    }
    return out;
}

// Check user and machine shell initialization values. This is informational
// unless the value references an unusual executable location or a name rule.
static std::vector<Record> inspectShellInitialization(){
    std::vector<Record> out;
    struct Key {HKEY hive;const wchar_t* path;const char* label;};
    const Key keys[]={
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","Machine Winlogon"},
        {HKEY_CURRENT_USER,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","User Winlogon"}
    };
    const wchar_t* values[]={L"Shell",L"Userinit",L"Taskman"};
    for(const auto& k:keys){
        HKEY key=nullptr;
        if(RegOpenKeyExW(k.hive,k.path,0,KEY_READ,&key)!=ERROR_SUCCESS)continue;
        for(const wchar_t* valueName:values){
            BYTE bytes[4096]={};DWORD size=sizeof(bytes),type=0;
            if(RegQueryValueExW(key,valueName,nullptr,&type,bytes,&size)
               !=ERROR_SUCCESS || (type!=REG_SZ&&type!=REG_EXPAND_SZ) ||
               size<sizeof(wchar_t)||size>=sizeof(bytes))continue;
            const auto* ptr=reinterpret_cast<const wchar_t*>(bytes);
            const std::wstring value(ptr,wcsnlen_s(ptr,size/sizeof(wchar_t)));
            if(value.empty())continue;
            const std::wstring low=lowerPath(value);
            const bool nameMatch=isCheatNameRuleMatch(value);
            const bool unusual=low.find(L"\\temp\\")!=std::wstring::npos ||
                low.find(L"\\downloads\\")!=std::wstring::npos ||
                low.find(L"powershell")!=std::wstring::npos ||
                low.find(L"cmd.exe")!=std::wstring::npos ||
                low.find(L"wscript")!=std::wstring::npos;
            if(!nameMatch && !unusual)continue;
            out.push_back({"Shell Initialization",utf8(valueName),
                std::string(nameMatch?"REVIEW - NAME RULE":
                    (unusual?"NEEDS REVIEW":"INVENTORY ONLY"))+
                " | "+k.label+" | Value: "+utf8(value)+
                " | Why: shell initialization references an unusual command "
                "or a name-rule match. Confirm this is expected."});
        }
        RegCloseKey(key);
    }
    return out;
}


// Explicitly configured Windows security weakening signals.
// Missing values are not flagged. Managed-device policy may explain findings.
static std::vector<Record> inspectSecurityPolicyWeakening(){
    std::vector<Record> out;
    struct PolicyRule {
        const wchar_t* key;
        const wchar_t* value;
        DWORD concerningValue;
        const char* title;
    };
    const PolicyRule rules[]={
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",L"DisableRealtimeMonitoring",1, "Defender real-time protection"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",L"DisableBehaviorMonitoring",1, "Defender behavior monitoring"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",L"DisableOnAccessProtection",1, "Defender on-access protection"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",L"DisableIOAVProtection",1, "Defender IOAV scanning"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",L"DisableScriptScanning",1, "Defender script scanning"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",L"DisableAntiSpyware",1, "Defender anti-spyware policy"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",L"DisableAntiVirus",1, "Defender anti-virus policy"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",L"EnableSmartScreen",0, "Windows SmartScreen"},
        {L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",L"EnableFirewall",0, "Windows firewall domain"},
        {L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",L"EnableFirewall",0, "Windows firewall private"},
        {L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",L"EnableFirewall",0, "Windows firewall public"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",L"EnableLUA",0, "UAC enabled"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",L"PromptOnSecureDesktop",0, "UAC secure desktop"},
        {L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",L"NoAutoUpdate",1, "Windows Update disabled"},
        {L"SYSTEM\\CurrentControlSet\\Services\\wuauserv",L"Start",4, "Windows Update service disabled"},
        {L"SYSTEM\\CurrentControlSet\\Services\\wscsvc",L"Start",4, "Security Center service disabled"},
        {L"SYSTEM\\CurrentControlSet\\Services\\WinDefend",L"Start",4, "Defender service disabled"},
        {L"SYSTEM\\CurrentControlSet\\Services\\EventLog",L"Start",4, "Windows event log service disabled"},
        {L"SYSTEM\\CurrentControlSet\\Services\\MpsSvc",L"Start",4, "Windows firewall service disabled"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",L"UserAuthentication",0, "RDP network level authentication"},
        {L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",L"fAllowToGetHelp",1, "Remote Assistance enabled"},
    };
    for(const auto& rule:rules){
        if(cancelRequested)break;
        HKEY key=nullptr;
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,rule.key,0,KEY_QUERY_VALUE,
                         &key)!=ERROR_SUCCESS)continue;
        DWORD actual=0,type=0,size=sizeof(actual);
        const LONG rc=RegQueryValueExW(key,rule.value,nullptr,&type,
                                       reinterpret_cast<BYTE*>(&actual),&size);
        RegCloseKey(key);
        if(rc!=ERROR_SUCCESS || type!=REG_DWORD || size!=sizeof(DWORD))
            continue;
        if(actual!=rule.concerningValue)continue;
        out.push_back({"Security Policy Review",rule.title,
            "NEEDS REVIEW | Configured registry value matches a potentially "
            "weakened security setting. Value: "+std::to_string(actual)+
            " | Registry path: "+utf8(rule.key)+
            " | Name: "+utf8(rule.value)+
            " | This is configuration evidence, not proof of malware. "
            "Verify against organizational policy and Windows version."});
    }
    return out;
}


// Read-only BAM execution-history inspection. BAM retention and coverage vary
// by Windows version; an entry does not establish malicious execution.
static std::vector<Record> inspectBamExecutionHistory(){
    std::vector<Record> out;
    const wchar_t* roots[]={
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings"
    };
    size_t examined=0;
    for(const wchar_t* rootPath:roots){
        if(cancelRequested)break;
        HKEY root=nullptr;
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,rootPath,0,KEY_READ,&root)!=ERROR_SUCCESS)continue;
        for(DWORD i=0;i<256 && !cancelRequested;++i){
            wchar_t sid[256]={};DWORD sidLen=255;
            LONG rc=RegEnumKeyExW(root,i,sid,&sidLen,nullptr,nullptr,nullptr,nullptr);
            if(rc==ERROR_NO_MORE_ITEMS)break;
            if(rc!=ERROR_SUCCESS)continue;
            HKEY user=nullptr;
            if(RegOpenKeyExW(root,sid,0,KEY_READ,&user)!=ERROR_SUCCESS)continue;
            for(DWORD j=0;j<2500 && examined<12000 && !cancelRequested;++j){
                wchar_t name[2048]={};DWORD nameLen=2047;
                LONG vr=RegEnumValueW(user,j,name,&nameLen,nullptr,nullptr,nullptr,nullptr);
                if(vr==ERROR_NO_MORE_ITEMS)break;
                if(vr!=ERROR_SUCCESS)continue;
                ++examined;
                const std::wstring entry(name,nameLen);
                if(!isCheatNameRuleMatch(entry))continue;
                out.push_back({"BAM Execution History",utf8(entry),
                    "DETECTED - NAME RULE | BAM/DAM execution-history entry "
                    "contains CHEAT or EXTERNAL. Historical record, not proof "
                    "of malware or cheating. Source: "+utf8(rootPath)});
                if(out.size()>=250)break;
            }
            RegCloseKey(user);
            if(out.size()>=250 || examined>=12000)break;
        }
        RegCloseKey(root);
        if(out.size()>=250 || examined>=12000)break;
    }
    return out;
}

// Inspect Defender exclusion paths/processes/extensions. Exclusions can be
// legitimate and may be inaccessible due to tamper protection.
static std::vector<Record> inspectDefenderExclusionIndicators(){
    std::vector<Record> out;
    const wchar_t* base=L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\";
    const wchar_t* groups[]={L"Paths",L"Processes",L"Extensions",L"IpAddresses"};
    for(const wchar_t* group:groups){
        if(cancelRequested)break;
        HKEY key=nullptr;
        const std::wstring path=std::wstring(base)+group;
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,path.c_str(),0,KEY_READ,&key)!=ERROR_SUCCESS)
            continue;
        for(DWORD i=0;i<1000 && !cancelRequested;++i){
            wchar_t name[2048]={};DWORD nameLen=2047;
            LONG rc=RegEnumValueW(key,i,name,&nameLen,nullptr,nullptr,nullptr,nullptr);
            if(rc==ERROR_NO_MORE_ITEMS)break;
            if(rc!=ERROR_SUCCESS)continue;
            const std::wstring value(name,nameLen);
            const std::wstring lower=lowerPath(value);
            const bool nameMatch=isCheatNameRuleMatch(value);
            const bool broad=(lower==L"c:\\" || lower==L"d:\\" ||
                lower==L"*" || lower==L".exe" || lower==L".dll");
            const bool temp=(lower.find(L"\\temp\\")!=std::wstring::npos ||
                lower.find(L"\\downloads\\")!=std::wstring::npos);
            out.push_back({"Defender Exclusion Review",utf8(value),
                std::string(nameMatch?"DETECTED - NAME RULE":"NEEDS REVIEW")+
                " | Defender exclusion group: "+utf8(group)+
                " | Exclusions reduce scanning for matching content. "
                "Confirm the exclusion is necessary and authorized."});
            if(out.size()>=200)break;
        }
        RegCloseKey(key);
        if(out.size()>=200)break;
    }
    return out;
}

// Task Scheduler stores task definitions under Windows\\System32\\Tasks.
// Only inspect names and paths here, not arbitrary XML or task execution.
static std::vector<Record> inspectScheduledTaskNames(){
    std::vector<Record> out;
    wchar_t win[MAX_PATH]={};
    const UINT len=GetWindowsDirectoryW(win,MAX_PATH);
    if(!len || len>=MAX_PATH)return out;
    const fs::path root=fs::path(win)/L"System32"/L"Tasks";
    std::error_code ec;
    fs::recursive_directory_iterator it(root,
        fs::directory_options::skip_permission_denied,ec),end;
    size_t checked=0;
    while(it!=end && !cancelRequested && checked<6000){
        if(it.depth()>6 || it->is_symlink(ec))it.disable_recursion_pending();
        std::error_code fe;
        if(it->is_regular_file(fe) && !fe){
            ++checked;
            const auto path=it->path();
            if(isCheatNameRuleMatch(path.filename().wstring())){
                out.push_back({"Scheduled Task Name",utf8(path.filename().wstring()),
                    "DETECTED - NAME RULE | Scheduled task filename matches "
                    "CHEAT or EXTERNAL. Task definition: "+utf8(path.wstring())+
                    " | Name-only match, not proof of malicious behavior."});
            }
        }
        it.increment(ec);
        if(ec)ec.clear();
    }
    if(checked>=6000)out.push_back({"Scan Coverage","Scheduled tasks",
        "INFO | Scheduled-task inspection stopped at its 6000-file limit."});
    return out;
}


// Read-only investigation of user-scoped COM registrations.
// Only unexpected paths and explicit name rules produce findings.
static std::vector<Record> inspectUserComRegistrationIndicators(){
    std::vector<Record> out;
    HKEY root=nullptr;
    if(RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Classes\\CLSID",0,KEY_READ,&root)!=ERROR_SUCCESS)
        return out;
    for(DWORD i=0;i<2400 && !cancelRequested && out.size()<160;++i){
        wchar_t clsid[128]={};DWORD count=127;
        LONG rc=RegEnumKeyExW(root,i,clsid,&count,nullptr,nullptr,nullptr,nullptr);
        if(rc==ERROR_NO_MORE_ITEMS)break;
        if(rc!=ERROR_SUCCESS)continue;
        for(const wchar_t* sub:{L"InprocServer32",L"LocalServer32"}){
            const std::wstring keyName=std::wstring(clsid)+L"\\"+sub;
            HKEY key=nullptr;
            if(RegOpenKeyExW(root,keyName.c_str(),0,KEY_READ,&key)!=ERROR_SUCCESS)
                continue;
            BYTE buffer[4096]={};DWORD size=sizeof(buffer),type=0;
            const LONG query=RegQueryValueExW(key,nullptr,nullptr,&type,buffer,&size);
            RegCloseKey(key);
            if(query!=ERROR_SUCCESS || (type!=REG_SZ&&type!=REG_EXPAND_SZ) ||
               size<sizeof(wchar_t) || size>=sizeof(buffer))continue;
            const wchar_t* data=reinterpret_cast<const wchar_t*>(buffer);
            const std::wstring path(data,wcsnlen_s(data,size/sizeof(wchar_t)));
            const std::wstring lower=lowerPath(path);
            const bool named=isCheatNameRuleMatch(path);
            const bool review=lower.find(L"\\temp\\")!=std::wstring::npos ||
                lower.find(L"\\downloads\\")!=std::wstring::npos ||
                lower.find(L"\\appdata\\roaming\\")!=std::wstring::npos;
            if(!named && !review)continue;
            out.push_back({"COM Registration Review",utf8(clsid),
                std::string(named?"DETECTED - NAME RULE":"NEEDS REVIEW")+
                " | User COM "+utf8(sub)+" references: "+utf8(path)+
                " | A user-level COM registration points to a name-rule match "
                "or an unusual location. Verify the file and its publisher; "
                "this is not confirmation of malicious behavior."});
        }
    }
    RegCloseKey(root);
    return out;
}

// Service image configuration: suspicious paths are review signals only.
static std::vector<Record> inspectServiceImagePathIndicators(){
    std::vector<Record> out;
    HKEY root=nullptr;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services",0,KEY_READ,&root)!=ERROR_SUCCESS)
        return out;
    for(DWORD i=0;i<3500 && !cancelRequested && out.size()<200;++i){
        wchar_t service[256]={};DWORD count=255;
        LONG rc=RegEnumKeyExW(root,i,service,&count,nullptr,nullptr,nullptr,nullptr);
        if(rc==ERROR_NO_MORE_ITEMS)break;
        if(rc!=ERROR_SUCCESS)continue;
        HKEY key=nullptr;
        if(RegOpenKeyExW(root,service,0,KEY_READ,&key)!=ERROR_SUCCESS)continue;
        BYTE bytes[8192]={};DWORD size=sizeof(bytes),type=0;
        rc=RegQueryValueExW(key,L"ImagePath",nullptr,&type,bytes,&size);
        RegCloseKey(key);
        if(rc!=ERROR_SUCCESS || (type!=REG_SZ&&type!=REG_EXPAND_SZ) ||
           size<sizeof(wchar_t)||size>=sizeof(bytes))continue;
        const wchar_t* data=reinterpret_cast<const wchar_t*>(bytes);
        const std::wstring command(data,wcsnlen_s(data,size/sizeof(wchar_t)));
        const std::wstring lower=lowerPath(command);
        const bool named=isCheatNameRuleMatch(command) ||
                         isCheatNameRuleMatch(service);
        const bool review=lower.find(L"\\temp\\")!=std::wstring::npos ||
            lower.find(L"\\downloads\\")!=std::wstring::npos ||
            lower.find(L"\\appdata\\roaming\\")!=std::wstring::npos ||
            lower.find(L"powershell")!=std::wstring::npos ||
            lower.find(L"wscript")!=std::wstring::npos;
        if(!named && !review)continue;
        out.push_back({"Service Image Review",utf8(service),
            std::string(named?"DETECTED - NAME RULE":"NEEDS REVIEW")+
            " | Service ImagePath: "+utf8(command)+
            " | A service references a name-rule match or an unusual location. "
            "Inspect its signature and provenance. This alone does not prove malware."});
    }
    RegCloseKey(root);
    return out;
}


// Read-only bypass / evidence-integrity diagnostics.
// Findings indicate review candidates, not proof of bypass usage.
static std::vector<Record> inspectBypassEvidenceIntegrity(){
    std::vector<Record> out;
    auto add=[&](const char* name,const std::string& detail){
        out.push_back({"Bypass Detection",name,detail});
    };
    auto readDword=[&](HKEY root,const wchar_t* key,const wchar_t* value,DWORD& data)->bool{
        HKEY h=nullptr;
        if(RegOpenKeyExW(root,key,0,KEY_QUERY_VALUE,&h)!=ERROR_SUCCESS)return false;
        DWORD type=0,size=sizeof(data);
        LONG rc=RegQueryValueExW(h,value,nullptr,&type,
            reinterpret_cast<BYTE*>(&data),&size);
        RegCloseKey(h);
        return rc==ERROR_SUCCESS && type==REG_DWORD && size==sizeof(data);
    };
    DWORD value=0;
    if(readDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
        L"EnablePrefetcher",value)){
        if(value==0)add("Prefetch configuration",
            "NEEDS REVIEW | Prefetch is disabled in registry. This may be an administrative setting; not proof of tampering.");
        else add("Prefetch configuration",
            "INFO | Prefetch registry setting is present and not disabled.");
    }else add("Prefetch configuration",
        "UNAVAILABLE | Prefetch registry value not accessible or not configured; no conclusion.");
    if(readDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting",
        L"Disabled",value) && value!=0)
        add("Error reporting policy",
            "NEEDS REVIEW | Windows Error Reporting disabled by policy; may be legitimate administration.");
    if(readDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        L"EnableScriptBlockLogging",value)){
        if(value==0)add("PowerShell logging policy",
            "NEEDS REVIEW | Script block logging explicitly disabled by policy; not proof of bypass.");
        else add("PowerShell logging policy",
            "INFO | Script block logging enabled by policy.");
    }else add("PowerShell logging policy",
        "INFO | No readable explicit script block logging policy; default behavior varies.");
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if(scm){
        for(const wchar_t* serviceName:{L"EventLog",L"WinDefend",L"wuauserv"}){
            SC_HANDLE svc=OpenServiceW(scm,serviceName,SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG);
            if(!svc){
                add("Security service visibility","UNAVAILABLE | Service status not accessible.");
                continue;
            }
            SERVICE_STATUS_PROCESS status{};
            DWORD needed=0;
            if(QueryServiceStatusEx(svc,SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status),sizeof(status),&needed)){
                if(status.dwCurrentState==SERVICE_STOPPED)
                    add("Security service status",
                        std::string("NEEDS REVIEW | Service stopped: ")+utf8(serviceName)+
                        ". This may be expected on some systems.");
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }else add("Security service visibility",
        "UNAVAILABLE | Cannot query Windows service manager.");
    // Query USN metadata only. Never enumerate deleted files or alter the journal.
    wchar_t windowsPath[MAX_PATH]={};
    UINT n=GetWindowsDirectoryW(windowsPath,MAX_PATH);
    if(n>2 && n<MAX_PATH && windowsPath[1]==L':'){
        wchar_t volume[]=L"\\\\.\\C:";
        volume[4]=windowsPath[0];
        HANDLE h=CreateFileW(volume,GENERIC_READ,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,
            OPEN_EXISTING,0,nullptr);
        if(h!=INVALID_HANDLE_VALUE){
            USN_JOURNAL_DATA_V0 journal{};
            DWORD bytes=0;
            if(DeviceIoControl(h,FSCTL_QUERY_USN_JOURNAL,nullptr,0,
                &journal,sizeof(journal),&bytes,nullptr)){
                add("USN Journal availability",
                    "INFO | System-volume USN journal metadata is readable. Journal availability alone does not prove historical coverage.");
            }else add("USN Journal availability",
                "UNAVAILABLE | USN journal cannot be queried (permissions, filesystem, or no journal).");
            CloseHandle(h);
        }else add("USN Journal availability",
            "UNAVAILABLE | System volume cannot be opened for read-only journal metadata query.");
    }
    return out;
}


// Additional read-only evidence-source and integrity checks.
// Absence or restricted access is not classified as malicious activity.
static std::vector<Record> inspectExtendedBypassEvidence(const std::vector<Process>& processes){
    std::vector<Record> out;
    auto add=[&](const char* name,const std::string& detail){
        out.push_back({"Bypass Detection",name,detail});
    };
    auto fileStatus=[&](const char* label,const fs::path& path){
        std::error_code ec;
        bool exists=fs::exists(path,ec);
        if(ec)add(label,"UNAVAILABLE | File metadata access failed.");
        else if(exists)add(label,"INFO | Evidence source exists. Presence alone does not establish useful historical coverage.");
        else add(label,"UNAVAILABLE | Evidence source not present at its standard path; Windows configuration may differ.");
    };
    wchar_t win[MAX_PATH]{};
    UINT count=GetWindowsDirectoryW(win,MAX_PATH);
    if(count>0 && count<MAX_PATH){
        fs::path root(win);
        fileStatus("Amcache evidence source",root/L"appcompat"/L"Programs"/L"Amcache.hve");
        fileStatus("SRUM evidence source",root/L"System32"/L"sru"/L"SRUDB.dat");
        fileStatus("Prefetch evidence directory",root/L"Prefetch");
        fileStatus("Windows Event Log directory",root/L"System32"/L"winevt"/L"Logs");
    }
    wchar_t local[MAX_PATH]{}, roaming[MAX_PATH]{};
    DWORD localLen=GetEnvironmentVariableW(L"LOCALAPPDATA",local,MAX_PATH);
    DWORD roamingLen=GetEnvironmentVariableW(L"APPDATA",roaming,MAX_PATH);
    if(roamingLen>0 && roamingLen<MAX_PATH){
        fs::path r(roaming);
        fileStatus("Automatic Destinations",r/L"Microsoft"/L"Windows"/L"Recent"/L"AutomaticDestinations");
        fileStatus("Custom Destinations",r/L"Microsoft"/L"Windows"/L"Recent"/L"CustomDestinations");
        fileStatus("Recent items",r/L"Microsoft"/L"Windows"/L"Recent");
    }
    if(localLen>0 && localLen<MAX_PATH)
        fileStatus("Explorer history",fs::path(local)/L"Microsoft"/L"Windows"/L"Explorer");

    // Read a small bounded set of Event Log records using the Windows Event Log API.
    // The query is backward and read-only, and does not clear or export logs.
    struct EventQuery {const wchar_t* channel; const wchar_t* xpath; const char* label;};
    const EventQuery queries[]={
        {L"Security",L"*[System[(EventID=1102)]]","Security log clearing (1102)"},
        {L"System",L"*[System[(EventID=104)]]","System log clearing (104)"},
        {L"Security",L"*[System[(EventID=4719)]]","Audit policy changes (4719)"},
        {L"System",L"*[System[(EventID=7036)]]","Service state transitions (7036)"}
    };
    for(const auto& q:queries){
        if(cancelRequested)break;
        EVT_HANDLE query=EvtQuery(nullptr,q.channel,q.xpath,
            EvtQueryChannelPath|EvtQueryReverseDirection);
        if(!query){
            add(q.label,"UNAVAILABLE | Event channel inaccessible, disabled, or query unsupported.");
            continue;
        }
        DWORD returned=0;
        EVT_HANDLE events[8]{};
        unsigned found=0;
        if(EvtNext(query,8,events,0,0,&returned)){
            found=returned;
            for(DWORD i=0;i<returned;++i)if(events[i])EvtClose(events[i]);
        }else if(GetLastError()!=ERROR_NO_MORE_ITEMS){
            add(q.label,"UNAVAILABLE | Event query failed or requires additional permissions.");
            EvtClose(query);
            continue;
        }
        EvtClose(query);
        if(found>0){
            add(q.label,std::string("NEEDS REVIEW | Found at least ")+std::to_string(found)+
                " matching recent records (bounded query). Verify timestamps, context and authorized maintenance.");
        }else{
            add(q.label,"INFO | No matching records returned in this query; this does not prove the event never occurred.");
        }
    }

    // UserAssist registry source availability (no sensitive per-user activity exported).
    HKEY key=nullptr;
    LONG rc=RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        0,KEY_READ,&key);
    if(rc==ERROR_SUCCESS){
        add("UserAssist evidence source","INFO | Current-user UserAssist registry source is readable.");
        RegCloseKey(key);
    }else add("UserAssist evidence source",
        "UNAVAILABLE | Current-user UserAssist source not readable.");

    // ShimCache storage varies by Windows version; check only availability.
    rc=RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
        0,KEY_READ,&key);
    if(rc==ERROR_SUCCESS){
        add("ShimCache evidence source","INFO | AppCompatCache registry key is readable; no execution claim.");
        RegCloseKey(key);
    }else add("ShimCache evidence source",
        "UNAVAILABLE | AppCompatCache registry key not readable.");

    // Bounded, per-process timestamp sanity checks. No file contents read.
    unsigned inspected=0, anomalies=0;
    FILETIME nowFt{}; GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER now{};now.LowPart=nowFt.dwLowDateTime;now.HighPart=nowFt.dwHighDateTime;
    for(const auto& proc:processes){
        if(cancelRequested || inspected>=80)break;
        if(proc.path.empty())continue;
        WIN32_FILE_ATTRIBUTE_DATA attrs{};
        if(!GetFileAttributesExW(proc.path.c_str(),GetFileExInfoStandard,&attrs))continue;
        ++inspected;
        ULARGE_INTEGER created{},modified{};
        created.LowPart=attrs.ftCreationTime.dwLowDateTime;
        created.HighPart=attrs.ftCreationTime.dwHighDateTime;
        modified.LowPart=attrs.ftLastWriteTime.dwLowDateTime;
        modified.HighPart=attrs.ftLastWriteTime.dwHighDateTime;
        constexpr ULONGLONG DAY=864000000000ULL;
        if(created.QuadPart>now.QuadPart+DAY || modified.QuadPart>now.QuadPart+DAY)
            ++anomalies;
    }
    if(anomalies)
        add("Executable timestamp sanity",
            "NEEDS REVIEW | "+std::to_string(anomalies)+
            " accessible process image(s) have future-dated timestamps. Clock changes and filesystem behavior can explain this.");
    else add("Executable timestamp sanity",
        "INFO | Checked "+std::to_string(inspected)+
        " accessible process images; no future-dated timestamps found. This is not a full timestamp-forensics assessment.");
    add("Cross-source evidence confidence",
        "INFO | Findings are observations, not proof of bypass or cheating. Correlate timestamps and independent sources manually.");
    return out;
}


// Additional bounded, read-only process and registry integrity diagnostics.
// These are triage indicators, never standalone evidence of cheating.
static std::vector<Record> inspectAdditionalCheatIndicators(const std::vector<Process>& processes){
    std::vector<Record> findings;
    auto emit=[&](const char* title,const std::string& detail){
        findings.push_back({"Advanced Integrity",title,detail});
    };
    auto lower=[](std::wstring v){
        std::transform(v.begin(),v.end(),v.begin(),[](wchar_t c){return (wchar_t)towlower(c);});
        return v;
    };
    // Suspicious executable location is contextual; never label as confirmed cheat.
    unsigned checked=0,unusual=0,invalidPe=0,signatureProblems=0;
    for(const auto& proc:processes){
        if(cancelRequested || checked>=100)break;
        if(proc.path.empty())continue;
        ++checked;
        std::wstring path=lower(proc.path);
        bool userWritable=(path.find(L"\\appdata\\local\\temp\\")!=std::wstring::npos ||
            path.find(L"\\downloads\\")!=std::wstring::npos ||
            path.find(L"\\recycle.bin\\")!=std::wstring::npos);
        if(userWritable){
            ++unusual;
            if(unusual<=12)emit("Unusual process image location",
                "NEEDS REVIEW | Running executable in a temporary, downloads or recycle location. Legitimate installers may use these paths.");
        }
        // Check file signature, not just extension. Read at most two bytes.
        HANDLE file=CreateFileW(proc.path.c_str(),GENERIC_READ,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file!=INVALID_HANDLE_VALUE){
            BYTE header[2]{};
            DWORD bytes=0;
            if(ReadFile(file,header,2,&bytes,nullptr) && bytes==2 &&
                !(header[0]=='M' && header[1]=='Z')){
                ++invalidPe;
                if(invalidPe<=8)emit("Executable format mismatch",
                    "NEEDS REVIEW | Running image path does not begin with the standard MZ executable header. Validate access and file changes.");
            }
            CloseHandle(file);
        }
        if(checked<=30){
            std::string sig=signatureStatus(proc.path);
            if(sig=="Invalid digest" || sig=="Untrusted certificate"){
                ++signatureProblems;
                if(signatureProblems<=8)emit("Executable signature integrity",
                    "NEEDS REVIEW | A running image has an invalid digest or untrusted certificate (offline verification).");
            }
        }
    }
    emit("Process integrity coverage",
        "INFO | Checked "+std::to_string(checked)+
        " accessible process paths; "+std::to_string(unusual)+
        " unusual locations, "+std::to_string(invalidPe)+
        " format mismatches, "+std::to_string(signatureProblems)+
        " signature issues. This is a bounded sample.");

    // AppInit DLLs can affect application startup; registry setting alone is not proof.
    HKEY key=nullptr;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key)==ERROR_SUCCESS){
        DWORD enabled=0,type=0,size=sizeof(enabled);
        if(RegQueryValueExW(key,L"LoadAppInit_DLLs",nullptr,&type,
            reinterpret_cast<LPBYTE>(&enabled),&size)==ERROR_SUCCESS &&
            type==REG_DWORD && enabled!=0){
            emit("AppInit DLL loading",
                "NEEDS REVIEW | Legacy AppInit DLL loading is enabled. Check approved software and OS policy.");
        }
        wchar_t dlls[2048]{};
        size=sizeof(dlls);type=0;
        if(RegQueryValueExW(key,L"AppInit_DLLs",nullptr,&type,
            reinterpret_cast<LPBYTE>(dlls),&size)==ERROR_SUCCESS &&
            (type==REG_SZ || type==REG_EXPAND_SZ) && dlls[0]!=0){
            emit("AppInit DLL configuration",
                "NEEDS REVIEW | AppInit_DLLs value is populated. Verify whether entries are authorized.");
        }
        RegCloseKey(key);
    }else emit("AppInit DLL configuration",
        "UNAVAILABLE | Registry configuration cannot be queried.");

    // Windows Error Reporting LocalDumps can be a legitimate debugging configuration.
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps",
        0,KEY_READ,&key)==ERROR_SUCCESS){
        emit("LocalDumps configuration",
            "INFO | Windows Error Reporting LocalDumps is configured; verify it matches administrative policy.");
        RegCloseKey(key);
    }
    return findings;
}


// Extended read-only audit and configuration evidence. No security settings
// are changed and missing records are never treated as proof of evasion.
static std::vector<Record> inspectAuditAndPlatformEvidence(){
    std::vector<Record> out;
    auto add=[&](const char* name,const std::string& detail){
        out.push_back({"Audit & Platform",name,detail});
    };
    struct EventSpec{const wchar_t* channel;int id;const char* label;};
    const EventSpec specs[]={
        {L"Security",1100,"Event log service shutdown"},
        {L"Security",1104,"Security log capacity"},
        {L"Security",1108,"Event log processing error"},
        {L"Security",4616,"System clock adjustment"},
        {L"Security",4688,"Audited process creation"},
        {L"Security",4697,"Audited service installation"},
        {L"Security",4698,"Scheduled task creation"},
        {L"Security",4702,"Scheduled task modification"},
        {L"System",7040,"Service startup configuration change"},
        {L"System",7045,"Service installation"},
        {L"Microsoft-Windows-Windows Defender/Operational",5007,
            "Defender configuration change"}
    };
    for(const auto& spec:specs){
        if(cancelRequested)break;
        wchar_t xpath[128]{};
        swprintf_s(xpath,L"*[System[(EventID=%d)]]",spec.id);
        EVT_HANDLE q=EvtQuery(nullptr,spec.channel,xpath,
            EvtQueryChannelPath|EvtQueryReverseDirection);
        if(!q){
            add(spec.label,"UNAVAILABLE | Channel or event query inaccessible. Check Windows auditing and permissions.");
            continue;
        }
        unsigned count=0;
        bool error=false;
        for(unsigned batch=0;batch<4 && !cancelRequested;++batch){
            EVT_HANDLE handles[16]{};
            DWORD returned=0;
            if(!EvtNext(q,16,handles,0,0,&returned)){
                if(GetLastError()!=ERROR_NO_MORE_ITEMS)error=true;
                break;
            }
            count+=returned;
            for(DWORD i=0;i<returned;++i)
                if(handles[i])EvtClose(handles[i]);
            if(returned<16)break;
        }
        EvtClose(q);
        if(error)
            add(spec.label,"UNAVAILABLE | Could not finish event query; partial results must not be interpreted.");
        else if(count)
            add(spec.label,"NEEDS REVIEW | At least "+std::to_string(count)+
                " matching historical events found (maximum 64 examined). Review the event details and timestamps.");
        else
            add(spec.label,"INFO | No matching event returned. Audit coverage and log retention may be limited.");
    }
    HKEY h=nullptr;
    DWORD value=0,type=0,size=sizeof(value);
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        0,KEY_QUERY_VALUE,&h)==ERROR_SUCCESS){
        if(RegQueryValueExW(h,L"UEFISecureBootEnabled",nullptr,&type,
            reinterpret_cast<LPBYTE>(&value),&size)==ERROR_SUCCESS &&
            type==REG_DWORD){
            add("Secure Boot state",value?
                "INFO | Windows reports Secure Boot enabled.":
                "INFO | Windows reports Secure Boot disabled. This can be an intentional platform configuration.");
        }else add("Secure Boot state","UNAVAILABLE | Secure Boot state not exposed.");
        RegCloseKey(h);
    }else add("Secure Boot state",
        "UNAVAILABLE | Secure Boot state key inaccessible or unsupported.");

    wchar_t systemDir[MAX_PATH]{};
    UINT n=GetSystemDirectoryW(systemDir,MAX_PATH);
    if(n>0 && n<MAX_PATH){
        wchar_t root[MAX_PATH]{};
        wcsncpy_s(root,systemDir,_TRUNCATE);
        if(root[0] && root[1]==L':'){
            wchar_t drive[]=L"C:\\";
            drive[0]=root[0];
            wchar_t fsName[64]{};
            if(GetVolumeInformationW(drive,nullptr,0,nullptr,nullptr,nullptr,
                                     fsName,64)){
                std::wstring fsType(fsName);
                add("System volume filesystem",
                    fsType==L"NTFS"?
                    "INFO | System volume uses NTFS; some artifacts still require elevated access.":
                    "INFO | System volume is not reported as NTFS; NTFS-specific checks may not apply.");
            }
        }
    }
    // Registry source presence is a coverage check, not a full parser.
    const struct {HKEY root;const wchar_t* key;const char* name;} keys[]={
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU","RunMRU history"},
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths","Explorer TypedPaths"},
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs","RecentDocs history"},
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU","OpenSavePidlMRU"},
        {HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU","LastVisitedPidlMRU"},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options","Image File Execution Options"}
    };
    for(const auto& item:keys){
        if(cancelRequested)break;
        HKEY key=nullptr;
        if(RegOpenKeyExW(item.root,item.key,0,KEY_READ,&key)==ERROR_SUCCESS){
            DWORD subkeys=0,values=0;
            LONG rc=RegQueryInfoKeyW(key,nullptr,nullptr,nullptr,&subkeys,
                nullptr,nullptr,&values,nullptr,nullptr,nullptr,nullptr);
            RegCloseKey(key);
            if(rc==ERROR_SUCCESS)
                add(item.name,"INFO | Registry evidence source readable; "+
                    std::to_string(subkeys)+" subkeys and "+
                    std::to_string(values)+" values. Contents not parsed.");
            else add(item.name,"UNAVAILABLE | Could not enumerate registry metadata.");
        }else add(item.name,"UNAVAILABLE | Registry source missing or inaccessible.");
    }
    return out;
}


// Read-only Windows defense and audit policy checks, with contextual findings.
static std::vector<Record> inspectExtraSecurityPolicies(){
    std::vector<Record> out;
    auto report=[&](const char* label,const std::string& message){
        out.push_back({"Defense Configuration",label,message});
    };
    struct Rule{
        HKEY root;const wchar_t* path;const wchar_t* name;
        const char* label;DWORD concerning;
    };
    const Rule rules[]={
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
         L"DisableAntiSpyware","Defender legacy disable policy",1},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         L"DisableRealtimeMonitoring","Defender realtime policy",1},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         L"DisableBehaviorMonitoring","Defender behavior monitoring policy",1},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
         L"EnableModuleLogging","PowerShell module logging policy",0},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
         L"EnableTranscripting","PowerShell transcription policy",0},
        {HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         L"EnableLUA","User Account Control policy",0}
    };
    for(const auto& rule:rules){
        if(cancelRequested)break;
        HKEY h=nullptr;
        if(RegOpenKeyExW(rule.root,rule.path,0,KEY_QUERY_VALUE,&h)!=ERROR_SUCCESS)
            continue; // Absent policy is normal; do not report as tampering.
        DWORD data=0,type=0,size=sizeof(data);
        LONG rc=RegQueryValueExW(h,rule.name,nullptr,&type,
            reinterpret_cast<LPBYTE>(&data),&size);
        RegCloseKey(h);
        if(rc==ERROR_SUCCESS && type==REG_DWORD && size==sizeof(data) &&
           data==rule.concerning)
            report(rule.label,"NEEDS REVIEW | Security policy has a potentially reduced-visibility setting. Verify administrative intent and effective protection state.");
    }
    return out;
}


// Session-to-session comparison. Metadata only; no evidence files are copied.
static std::vector<Record> previousScanRecords;
static std::vector<Process> previousScanProcesses;
static bool hasPreviousScan=false;
// Microsecond resolution avoids reporting completed fast stages as "0 ms".
static std::atomic<unsigned long long> stageElapsedUs[6]{};
static std::atomic<unsigned long long> scanElapsedUs{0};
static std::atomic<unsigned> stageWorkItems[6]{};

static std::chrono::steady_clock::time_point stageStartedAt;
static void markInspectionStage(unsigned completed){
    if(completed==0 || completed>6)return;
    const auto now=std::chrono::steady_clock::now();
    stageElapsedUs[completed-1].store(static_cast<unsigned long long>(
        std::chrono::duration_cast<std::chrono::microseconds>(now-stageStartedAt).count()));
    stageStartedAt=now;
    if(completed==6){
        unsigned long long total=0;
        for(const auto& elapsed:stageElapsedUs)total+=elapsed.load();
        scanElapsedUs=total;
    }
    completedStages=static_cast<int>(completed);
}
static std::string recordKey(const Record& r){
    return r.category+"\\x1f"+r.name+"\\x1f"+r.detail;
}
static void drawEvidenceComparison(){
    std::lock_guard<std::mutex> lock(dataMutex);
    if(!hasPreviousScan){
        ImGui::TextWrapped("Comparison requires TWO completed scans in this app session. The first scan is the baseline; run Start Full Scan again to see added and removed evidence.");
        ImGui::TextDisabled("Baseline is kept in memory only. Restarting the app clears it.");
        ImGui::Text("Current scan: %zu evidence records.",records.size());
        return;
    }
    std::unordered_set<std::string> oldKeys,newKeys;
    for(const auto& r:previousScanRecords)oldKeys.insert(recordKey(r));
    for(const auto& r:records)newKeys.insert(recordKey(r));
    size_t added=0,removed=0;
    for(const auto& k:newKeys)if(!oldKeys.count(k))++added;
    for(const auto& k:oldKeys)if(!newKeys.count(k))++removed;
    ImGui::Text("New records: %zu  |  No longer observed: %zu",added,removed);
    ImGui::TextDisabled("Differences can reflect normal Windows activity, permissions, or collection coverage.");
    if(ImGui::BeginTable("##scanDiff",3,
        ImGuiTableFlags_BordersInnerH|ImGuiTableFlags_RowBg|
        ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,320))){
        ImGui::TableSetupColumn("Change",ImGuiTableColumnFlags_WidthFixed,115);
        ImGui::TableSetupColumn("Source",ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Evidence",ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        unsigned shown=0;
        auto row=[&](const char* change,const Record& r){
            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(change);
            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(r.category.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextWrapped("%s | %s",r.name.c_str(),r.detail.c_str());
        };
        for(const auto& r:records){
            if(shown>=150)break;
            if(!oldKeys.count(recordKey(r))){row("NEW",r);++shown;}
        }
        for(const auto& r:previousScanRecords){
            if(shown>=150)break;
            if(!newKeys.count(recordKey(r))){row("NOT OBSERVED",r);++shown;}
        }
        ImGui::EndTable();
    }
}
static void drawEvidenceInspector(){
    std::lock_guard<std::mutex> lock(dataMutex);
    static int selected=-1;
    static char query[160]{};
    ImGui::InputTextWithHint("##evidenceSearch","Search category, name or details...",query,sizeof(query));
    ImGui::TextDisabled("%zu records available | Read-only evidence inspector",records.size());
    if(ImGui::BeginChild("##evidenceList",ImVec2(0,270),ImGuiChildFlags_Borders)){
        unsigned shown=0;
        for(size_t i=0;i<records.size() && shown<500;++i){
            const auto& r=records[i];
            const std::string text=r.category+" / "+r.name+" / "+r.detail;
            if(query[0] && text.find(query)==std::string::npos)continue;
            ImGui::PushID(static_cast<int>(i));
            if(ImGui::Selectable((r.category+" | "+r.name).c_str(),
                                 selected==static_cast<int>(i)))
                selected=static_cast<int>(i);
            ImGui::PopID();++shown;
        }
    }
    ImGui::EndChild();
    if(selected>=0 && static_cast<size_t>(selected)<records.size()){
        const auto& r=records[static_cast<size_t>(selected)];
        ImGui::Separator();
        ImGui::Text("SOURCE: %s",r.category.c_str());
        ImGui::Text("NAME: %s",r.name.c_str());
        ImGui::TextWrapped("DETAILS: %s",r.detail.c_str());
        if(ImGui::Button("COPY EVIDENCE")){
            const std::string text=r.category+" | "+r.name+" | "+r.detail;
            ImGui::SetClipboardText(text.c_str());
        }
        ImGui::TextDisabled("An indicator alone does not confirm a threat.");
    }
}


// Forensic source validation: bounded reads, no changes to source artifacts.
// These are metadata/header checks, not complete format-specific parsers.

// Bounded parsers: malformed or unsupported data never becomes a threat verdict.
static bool readLe32(const std::vector<unsigned char>& b,size_t o,uint32_t& v){
    if(o>b.size() || b.size()-o<4)return false;
    v=uint32_t(b[o])|(uint32_t(b[o+1])<<8)|
      (uint32_t(b[o+2])<<16)|(uint32_t(b[o+3])<<24);
    return true;
}
static bool readLe64(const std::vector<unsigned char>& b,size_t o,uint64_t& v){
    uint32_t lo=0,hi=0;
    if(!readLe32(b,o,lo)||!readLe32(b,o+4,hi))return false;
    v=uint64_t(lo)|(uint64_t(hi)<<32);
    return true;
}
static std::string safeAscii(const std::vector<unsigned char>& b,size_t offset,size_t length){
    if(offset>b.size()||length>b.size()-offset)return {};
    std::string out;
    for(size_t i=0;i<length;++i){
        const auto c=b[offset+i];
        if(c==0)break;
        out.push_back(c>=32&&c<=126?char(c):'?');
    }
    return out;
}

// Prefetch executable name is a 60-byte UTF-16LE field, not ASCII.
static std::string prefetchExecutableName(const std::vector<unsigned char>& b){
    if(b.size()<0x10+60)return {};
    std::wstring name;
    for(size_t o=0x10;o<0x10+60;o+=2){
        const uint16_t c=static_cast<uint16_t>(b[o])|
                         (static_cast<uint16_t>(b[o+1])<<8);
        if(c==0)break;
        if(c<32 || (c>=0xD800 && c<=0xDFFF))return {};
        name.push_back(static_cast<wchar_t>(c));
    }
    return utf8(name);
}
// Forensic parser guards: reject out-of-bounds sections before interpreting.
static bool prefetchSectionBounds(const std::vector<unsigned char>& b,
                                  size_t offset,size_t entrySize,size_t count){
    return offset<=b.size() && (entrySize==0 || count<=(b.size()-offset)/entrySize);
}
static std::vector<Record> parsePrefetchFile(const std::filesystem::path& path){
    std::vector<Record> out;
    std::error_code ec;
    const auto length=std::filesystem::file_size(path,ec);
    if(ec||length<8||length>32ull*1024*1024){
        out.push_back({"Prefetch","Unreadable / unsupported size",
            "Source file inaccessible or outside 8 B - 32 MiB safety bounds"});
        return out;
    }
    std::ifstream f(path,std::ios::binary);
    if(!f)return {{"Prefetch","Access denied","Could not open source file"}};
    std::vector<unsigned char> b(static_cast<size_t>(length));
    if(!f.read(reinterpret_cast<char*>(b.data()),static_cast<std::streamsize>(b.size())))
        return {{"Prefetch","Read error","Short read; source not interpreted"}};
    // MAM is a compressed container, not an ordinary SCCA header.
    if(b[0]=='M'&&b[1]=='A'&&b[2]=='M')
        return {{"Prefetch","Compressed container",
            "MAM container detected; decompression not available in this build"}};
    uint32_t version=0,declared=0,runCount=0;
    if(!readLe32(b,0,version)||std::memcmp(b.data()+4,"SCCA",4)!=0)
        return {{"Prefetch","Unknown signature","Not an SCCA prefetch stream"}};
    if(version!=17&&version!=23&&version!=26&&version!=30&&version!=31)
        return {{"Prefetch","Unsupported version","SCCA version "+std::to_string(version)}};
    if(!readLe32(b,12,declared)||declared!=b.size()||b.size()<0xD4)
        return {{"Prefetch","Invalid length","Declared and actual file lengths differ"}};
    const std::string executable=prefetchExecutableName(b);
    // Offsets are version-dependent. Run count offsets here are validated
    // only for the known uncompressed layouts.
    size_t countOffset=0;
    if(version==17)countOffset=0x90;
    else if(version==23)countOffset=0x98;
    else countOffset=0xD0;
    if(!readLe32(b,countOffset,runCount))
        return {{"Prefetch","Truncated metadata","Cannot read run count"}};
    if(runCount>10000000)
        return {{"Prefetch","Implausible metadata","Run count outside expected bounds"}};
    // The file metrics table has an offset/count pair at 0x54/0x58.
    // Only verify bounds here: entry layout differs by Windows version.
    uint32_t metricOffset=0,metricCount=0;
    if(!readLe32(b,0x54,metricOffset)||!readLe32(b,0x58,metricCount)||
       metricCount>100000 || metricOffset>b.size()){
        return {{"Prefetch","Invalid section","File metrics table offset/count is invalid"}};
    }
    // Do not guess the per-version entry size; table contents remain unparsed.
    out.push_back({"Prefetch Parsed",executable.empty()?"Unnamed executable":executable,
        "SCCA version="+std::to_string(version)+
        " | bytes="+std::to_string(b.size())+
        " | file metrics entries (header)="+std::to_string(metricCount)+
        " | recorded run count="+std::to_string(runCount)+
        " | Source metadata, not proof of recent execution"});
    return out;
}
static void enumerateAmcacheTree(HKEY parent,const std::wstring& branch,
                                 std::vector<Record>& out,unsigned depth,
                                 size_t& budget){
    if(depth>3||budget==0||cancelRequested)return;
    DWORD index=0;
    while(budget && index<300 && !cancelRequested){
        wchar_t name[512]{};
        DWORD nameLength=511;
        FILETIME modified{};
        const LSTATUS status=RegEnumKeyExW(parent,index++,name,&nameLength,
                                            nullptr,nullptr,nullptr,&modified);
        if(status==ERROR_NO_MORE_ITEMS)break;
        if(status!=ERROR_SUCCESS)continue;
        HKEY child=nullptr;
        if(RegOpenKeyExW(parent,name,0,KEY_READ,&child)!=ERROR_SUCCESS)continue;
        const std::wstring full=branch+L"\\"+name;
        --budget;
        DWORD values=0;
        RegQueryInfoKeyW(child,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,
                         &values,nullptr,nullptr,nullptr,nullptr);
        if(values){
            const std::string path=utf8(full);
            out.push_back({"Amcache Registry",path,
                "Subkey accessible | value entries="+std::to_string(values)+
                " | Key presence does not establish execution"});
        }
        enumerateAmcacheTree(child,full,out,depth+1,budget);
        RegCloseKey(child);
    }
}
// Explicit per-run coverage, independent of filtering and the visible evidence table.
static std::atomic<int> forensicSourceStatus{0}; // 0 pending, 1 completed, 2 failed
static std::atomic<unsigned> forensicSourceChecks{0};
static std::atomic<unsigned> forensicCorrelationNotices{0};
static std::vector<Record> inspectForensicSourceHeaders(){
    std::vector<Record> out;
    wchar_t win[MAX_PATH]{};
    if(!GetWindowsDirectoryW(win,MAX_PATH))
        return {{"Forensic Sources","Windows root","Windows directory unavailable"}};
    const std::filesystem::path root(win);
    const auto prefetch=root/L"Prefetch";
    std::error_code ec;
    if(std::filesystem::exists(prefetch,ec)&&!ec){
        size_t checked=0,parsed=0,compressed=0,invalid=0;
        std::filesystem::directory_iterator it(prefetch,
            std::filesystem::directory_options::skip_permission_denied,ec),end;
        while(!ec&&it!=end&&checked<250&&!cancelRequested){
            if(it->is_regular_file(ec)&&it->path().extension()==L".pf"){
                ++checked;
                auto items=parsePrefetchFile(it->path());
                for(auto& r:items){
                    if(r.category=="Prefetch Parsed")++parsed;
                    else if(r.name=="Compressed container")++compressed;
                    else ++invalid;
                    if(out.size()<280)out.push_back(std::move(r));
                }
            }
            it.increment(ec);
        }
        out.push_back({"Prefetch","Coverage",
            "Inspected="+std::to_string(checked)+
            " | Parsed="+std::to_string(parsed)+
            " | Compressed unsupported="+std::to_string(compressed)+
            " | Other unsupported/errors="+std::to_string(invalid)});
    }else out.push_back({"Prefetch","Unavailable",
        "Prefetch directory unavailable or access denied"});
    const auto amcache=root/L"AppCompat"/L"Programs"/L"Amcache.hve";
    ec.clear();
    if(std::filesystem::exists(amcache,ec)&&!ec){
        HKEY hive=nullptr;
        // RegLoadAppKey opens an application hive without mounting it globally.
        // On active Windows installations the hive may be locked by the OS.
        const LONG status=RegLoadAppKeyW(amcache.c_str(),&hive,
                                         KEY_READ,0,0);
        if(status==ERROR_SUCCESS && hive){
            size_t budget=250;
            enumerateAmcacheTree(hive,L"Amcache",out,0,budget);
            RegCloseKey(hive);
            out.push_back({"Amcache","Registry enumeration",
                "Read-only key enumeration completed (up to 250 subkeys); "
                "schema-specific file metadata decoding remains unsupported"});
        }else out.push_back({"Amcache","Hive inaccessible",
            "RegLoadAppKeyW returned "+std::to_string(status)+
            " | Live hive may be locked; no tampering conclusion"});
    }else out.push_back({"Amcache","Source unavailable",
        "Amcache hive not found or inaccessible"});
    HKEY key=nullptr;
    const LSTATUS status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
        0,KEY_QUERY_VALUE,&key);
    if(status==ERROR_SUCCESS){
        DWORD type=0,size=0;
        const LSTATUS result=RegQueryValueExW(key,L"AppCompatCache",nullptr,
            &type,nullptr,&size);
        if(result==ERROR_SUCCESS && type==REG_BINARY && size>=4 &&
           size<=8*1024*1024){
            std::vector<unsigned char> data(size);
            if(RegQueryValueExW(key,L"AppCompatCache",nullptr,&type,
                                data.data(),&size)==ERROR_SUCCESS){
                uint32_t signature=0;
                readLe32(data,0,signature);
                std::ostringstream ss;
                ss<<std::hex<<std::uppercase<<signature;
                out.push_back({"ShimCache","Binary format",
                    "Value bytes="+std::to_string(size)+
                    " | Header DWORD=0x"+ss.str()+
                    " | Version-specific record decoding not implemented; "
                    "execution cannot be inferred"});
            }
        }else out.push_back({"ShimCache","Unavailable / unsupported",
            "Registry value unavailable or outside bounded binary size"});
        RegCloseKey(key);
    }else out.push_back({"ShimCache","Source unavailable",
        "AppCompatCache registry key inaccessible"});
    return out;
}
static std::vector<Record> correlateForensicEvidence(const std::vector<Record>& input){
    std::vector<Record> out;
    bool eventLog=false,policy=false,provenance=false;
    for(const auto& r:input){
        const std::string joined=r.category+" "+r.name+" "+r.detail;
        if(joined.find("1102")!=std::string::npos ||
           joined.find("Event log cleared")!=std::string::npos)eventLog=true;
        if(joined.find("Defender")!=std::string::npos &&
           (joined.find("policy")!=std::string::npos ||
            joined.find("Policy")!=std::string::npos))policy=true;
        if(joined.find("Unsigned")!=std::string::npos ||
           joined.find("unsigned")!=std::string::npos)provenance=true;
    }
    if(eventLog && policy)
        out.push_back({"Evidence Correlation","Event log + security policy",
            "Two categories of potentially relevant indicators co-occur. "
            "Review timestamps and sources; causality is NOT established."});
    if(policy && provenance)
        out.push_back({"Evidence Correlation","Policy + executable provenance",
            "Independent review recommended. Co-occurrence alone is NOT proof of malicious activity."});
    return out;
}


// Optional libyara integration. Build with SYNC_WITH_YARA and link libyara.
// The operator supplies a trusted rules file. No network access or rule download.
#ifdef SYNC_WITH_YARA
static int syncYaraCallback(YR_SCAN_CONTEXT*,int message,void* messageData,void* userData){
    if(message==CALLBACK_MSG_RULE_MATCHING && messageData && userData){
        auto* names=static_cast<std::vector<std::string>*>(userData);
        const auto* rule=static_cast<const YR_RULE*>(messageData);
        if(names->size()<32)names->push_back(rule->identifier?rule->identifier:"unnamed");
    }
    return CALLBACK_CONTINUE;
}
static std::vector<Record> inspectYaraLocalFiles(const std::vector<Process>& p){
    std::vector<Record> results;
    const char* env=std::getenv("SYNC_YARA_RULES");
    if(!env || !*env){
        results.push_back({"YARA","Configuration",
            "Disabled: set SYNC_YARA_RULES to a trusted local compiled rules file"});
        return results;
    }
    if(yr_initialize()!=ERROR_SUCCESS){
        results.push_back({"YARA","Initialization","libyara initialization failed"});
        return results;
    }
    YR_RULES* rules=nullptr;
    const int load=yr_rules_load(env,&rules);
    if(load!=ERROR_SUCCESS || !rules){
        results.push_back({"YARA","Rules","Cannot load compiled YARA rules"});
        yr_finalize();return results;
    }
    // The caller controls the rules. Bound file count and scan timeout.
    size_t count=0;
    for(const auto& proc:p){
        if(cancelRequested || count>=20)break;
        // No file is scanned unless it is a regular file with a reasonable size.
        std::error_code ec;
        const std::filesystem::path path(proc.path);
        if(path.empty() || !std::filesystem::is_regular_file(path,ec) || ec)continue;
        const auto size=std::filesystem::file_size(path,ec);
        if(ec || size>64ull*1024*1024)continue;
        ++count;
        std::vector<std::string> matches;
        const auto narrow=path.u8string();
        const std::string fileName(narrow.begin(),narrow.end());
        const int status=yr_rules_scan_file(rules,fileName.c_str(),0,
            syncYaraCallback,&matches,15);
        if(status!=ERROR_SUCCESS){
            results.push_back({"YARA","Scan error",
                "One file could not be scanned; no conclusion"});
            continue;
        }
        for(const auto& rule:matches)
            results.push_back({"YARA Rule Match",rule,
                "Matched a local process executable. Review rule quality and context."});
    }
    results.push_back({"YARA","Coverage",
        "Local executable files scanned: "+std::to_string(count)+
        " (limit 20, 64 MiB/file, 15 s/file)"});
    yr_rules_destroy(rules);
    yr_finalize();
    return results;
}
#else
static std::vector<Record> inspectYaraLocalFiles(const std::vector<Process>&){
    return {{"YARA","Integration",
        "Not compiled: build with SYNC_WITH_YARA and a compatible libyara SDK"}};
}
#endif

// One-at-a-time execution telemetry; worker runs checks in a single sequence.
static std::atomic<unsigned> sequentialDone{0},sequentialTotal{0};
static std::mutex sequentialLabelMutex;
static std::string sequentialCurrent;
static void setSequentialItem(const std::string& label){
    std::lock_guard<std::mutex> lock(sequentialLabelMutex);
    sequentialCurrent=label;
}
static std::string getSequentialItem(){
    std::lock_guard<std::mutex> lock(sequentialLabelMutex);
    return sequentialCurrent;
}

// Read-only extended process inspection. One PID at a time, no process memory reads.
// Each field is collected independently; "unavailable" is not suspicious.
static constexpr unsigned kProcessChecksPerPid=34;
static std::atomic<unsigned long long> processChecksCompleted{0};
static std::atomic<unsigned long long> processChecksUnavailable{0};
static std::atomic<unsigned long long> processChecksPlanned{0};
static std::vector<Record> inspectIndividualProcesses(
    const std::vector<Process>& processes){
    std::vector<Record> output;
    output.reserve(processes.size()*kProcessChecksPerPid);
    std::unordered_set<DWORD> known;
    for(const auto& p:processes)known.insert(p.pid);
    std::unordered_map<DWORD,unsigned> threadCounts;
    HANDLE threadSnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(threadSnapshot!=INVALID_HANDLE_VALUE){
        THREADENTRY32 te{};te.dwSize=sizeof(te);
        if(Thread32First(threadSnapshot,&te)){
            do{++threadCounts[te.th32OwnerProcessID];}
            while(Thread32Next(threadSnapshot,&te));
        }
        CloseHandle(threadSnapshot);
    }
    for(const auto& p:processes){
        if(cancelRequested)break;
        const std::string pid=std::to_string(p.pid);
        HANDLE handle=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p.pid);
        const auto closeHandle=[](void* h){if(h)CloseHandle(static_cast<HANDLE>(h));};
        std::unique_ptr<void,decltype(closeHandle)> handleGuard(handle,closeHandle);
        const auto emit=[&](const char* check,const std::string& result,bool available){
            setSequentialItem("PID "+pid+" / "+check);
            output.push_back({"Process Check",pid+" / "+check,
                result.empty()?std::string("Unavailable"):result});
            if(available)++processChecksCompleted;
            else ++processChecksUnavailable;
            ++sequentialDone;
        };
        emit("PID",pid,true);
        if(cancelRequested)break;
        emit("Parent PID",std::to_string(p.parent),true);
        if(cancelRequested)break;
        emit("Parent in snapshot",p.parent==0?"Not applicable":
            known.count(p.parent)?"Present":"Not observed (may have exited)",true);
        if(cancelRequested)break;
        emit("Executable name",std::string(p.name.begin(),p.name.end()),!p.name.empty());
        if(cancelRequested)break;
        emit("Snapshot path",p.path.empty()?"Unavailable":
            std::string(p.path.begin(),p.path.end()),!p.path.empty());
        if(cancelRequested)break;
        DWORD session=0;
        const bool sessionOk=ProcessIdToSessionId(p.pid,&session)!=FALSE;
        emit("Session",sessionOk?std::to_string(session):"Unavailable",sessionOk);
        if(cancelRequested)break;
        DWORD handles=0;
        const bool handlesOk=handle&&GetProcessHandleCount(handle,&handles);
        emit("Handle count",handlesOk?std::to_string(handles):"Unavailable",handlesOk);
        if(cancelRequested)break;
        FILETIME created{},exited{},kernel{},user{};
        const bool timesOk=handle&&GetProcessTimes(handle,&created,&exited,&kernel,&user);
        ULARGE_INTEGER stamp{};
        if(timesOk){stamp.LowPart=created.dwLowDateTime;stamp.HighPart=created.dwHighDateTime;}
        emit("Creation FILETIME",timesOk?std::to_string(stamp.QuadPart):"Unavailable",timesOk);
        if(cancelRequested)break;
        if(timesOk){stamp.LowPart=kernel.dwLowDateTime;stamp.HighPart=kernel.dwHighDateTime;}
        emit("Kernel CPU time (100ns)",timesOk?std::to_string(stamp.QuadPart):"Unavailable",timesOk);
        if(cancelRequested)break;
        if(timesOk){stamp.LowPart=user.dwLowDateTime;stamp.HighPart=user.dwHighDateTime;}
        emit("User CPU time (100ns)",timesOk?std::to_string(stamp.QuadPart):"Unavailable",timesOk);
        if(cancelRequested)break;
        DWORD exitCode=0;
        const bool stateOk=handle&&GetExitCodeProcess(handle,&exitCode);
        emit("Process state",stateOk?(exitCode==STILL_ACTIVE?"Active":"Exited"):"Unavailable",stateOk);
        if(cancelRequested)break;
        DWORD priority=handle?GetPriorityClass(handle):0;
        emit("Priority class",priority?std::to_string(priority):"Unavailable",priority!=0);
        if(cancelRequested)break;
        BOOL wow64=FALSE;
        const bool wowOk=handle&&IsWow64Process(handle,&wow64);
        emit("WOW64",wowOk?(wow64?"Yes":"No"):"Unavailable",wowOk);
        if(cancelRequested)break;
        // Protected processes can deny queries. Record access as unknown, not a finding.
        const bool accessOk=handle!=nullptr;
        emit("Limited query access",accessOk?"Available":"Denied or process exited",accessOk);
        if(cancelRequested)break;
        std::error_code ec;
        const bool regular=!p.path.empty()&&fs::is_regular_file(fs::path(p.path),ec)&&!ec;
        emit("Executable file exists",regular?"Yes":(ec?"Unavailable":"No / not a file"),!ec);
        if(cancelRequested)break;
        ec.clear();
        const auto bytes=regular?fs::file_size(fs::path(p.path),ec):0;
        emit("Executable file size",regular&&!ec?std::to_string(bytes)+" bytes":"Unavailable",
             regular&&!ec);
        if(cancelRequested)break;
        const auto ti=threadCounts.find(p.pid);
        emit("Thread count",ti!=threadCounts.end()?std::to_string(ti->second):"Unavailable",
             ti!=threadCounts.end());
        if(cancelRequested)break;
        DWORD_PTR procMask=0,systemMask=0;
        const bool affinityOk=handle&&GetProcessAffinityMask(handle,&procMask,&systemMask);
        emit("Process affinity mask",affinityOk?std::to_string(static_cast<unsigned long long>(procMask)):"Unavailable",affinityOk);
        if(cancelRequested)break;
        emit("System affinity mask",affinityOk?std::to_string(static_cast<unsigned long long>(systemMask)):"Unavailable",affinityOk);
        if(cancelRequested)break;
        BOOL boostDisabled=FALSE;
        const bool boostOk=handle&&GetProcessPriorityBoost(handle,&boostDisabled);
        emit("Priority boost disabled",boostOk?(boostDisabled?"Yes":"No"):"Unavailable",boostOk);
        if(cancelRequested)break;
        wchar_t fullPath[32768]{};
        DWORD pathLength=32768;
        const bool fullPathOk=handle&&QueryFullProcessImageNameW(handle,0,fullPath,&pathLength);
        emit("Queried image path",fullPathOk?
             std::string(fullPath,fullPath+pathLength):
             "Unavailable",fullPathOk);
        if(cancelRequested)break;
        IO_COUNTERS io{};
        const bool ioOk=handle&&GetProcessIoCounters(handle,&io);
        emit("IO read operations",ioOk?std::to_string(io.ReadOperationCount):"Unavailable",ioOk);
        if(cancelRequested)break;
        emit("IO write operations",ioOk?std::to_string(io.WriteOperationCount):"Unavailable",ioOk);
        if(cancelRequested)break;
        emit("IO other operations",ioOk?std::to_string(io.OtherOperationCount):"Unavailable",ioOk);
        if(cancelRequested)break;
        emit("IO bytes read",ioOk?std::to_string(io.ReadTransferCount):"Unavailable",ioOk);
        if(cancelRequested)break;
        emit("IO bytes written",ioOk?std::to_string(io.WriteTransferCount):"Unavailable",ioOk);
        if(cancelRequested)break;
        emit("IO other bytes",ioOk?std::to_string(io.OtherTransferCount):"Unavailable",ioOk);
        if(cancelRequested)break;
        HANDLE memoryHandle=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,p.pid);
        std::unique_ptr<void,decltype(closeHandle)> memoryGuard(memoryHandle,closeHandle);
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        const bool memoryOk=memoryHandle&&GetProcessMemoryInfo(memoryHandle,
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),sizeof(pmc));
        emit("Working set bytes",memoryOk?std::to_string(pmc.WorkingSetSize):"Unavailable",memoryOk);
        if(cancelRequested)break;
        emit("Peak working set bytes",memoryOk?std::to_string(pmc.PeakWorkingSetSize):"Unavailable",memoryOk);
        if(cancelRequested)break;
        emit("Private usage bytes",memoryOk?std::to_string(pmc.PrivateUsage):"Unavailable",memoryOk);
        if(cancelRequested)break;
        emit("Page faults",memoryOk?std::to_string(pmc.PageFaultCount):"Unavailable",memoryOk);
        if(cancelRequested)break;
        emit("Pagefile usage bytes",memoryOk?std::to_string(pmc.PagefileUsage):"Unavailable",memoryOk);
        if(cancelRequested)break;
        emit("Peak pagefile usage bytes",memoryOk?std::to_string(pmc.PeakPagefileUsage):"Unavailable",memoryOk);
        if(cancelRequested)break;
        emit("Quota paged pool bytes",memoryOk?std::to_string(pmc.QuotaPagedPoolUsage):"Unavailable",memoryOk);
        // RAII closes both handles on normal completion or cancellation.
    }
    return output;
}


// Snapshot reconciliation: identifies actual PIDs observed after the initial inventory.
// This is not a continuous ETW trace and cannot recover short-lived missed processes.
static std::atomic<unsigned> processNewPids{0},processExitedPids{0};
static std::atomic<unsigned> processSecondSnapshot{0};
static std::atomic<unsigned> forensicProducedRecords{0};
static std::vector<Record> reconcileProcessSnapshots(
    const std::vector<Process>& before,const std::vector<Process>& after){
    std::unordered_map<DWORD,std::wstring> oldPids,newPids;
    for(const auto& p:before)oldPids[p.pid]=p.name;
    for(const auto& p:after)newPids[p.pid]=p.name;
    std::vector<Record> changes;
    unsigned added=0,exited=0;
    for(const auto& p:after){
        if(cancelRequested)break;
        const auto it=oldPids.find(p.pid);
        if(it==oldPids.end()){
            changes.push_back({"Process Snapshot Delta","PID "+std::to_string(p.pid),
                "Observed in second snapshot; not present in initial snapshot"});
            ++added;
        }else if(it->second!=p.name){
            changes.push_back({"Process Snapshot Delta","PID "+std::to_string(p.pid),
                "Name changed between snapshots; possible PID reuse"});
        }
    }
    for(const auto& p:before){
        if(cancelRequested)break;
        if(!newPids.count(p.pid)){
            changes.push_back({"Process Snapshot Delta","PID "+std::to_string(p.pid),
                "Absent from second snapshot; may have exited"});
            ++exited;
        }
    }
    processNewPids=added;
    processExitedPids=exited;
    processSecondSnapshot=static_cast<unsigned>(after.size());
    return changes;
}

// Deep mode: actual file-system, SHA-256 and Authenticode inspection for each
// unique executable path observed in the initial process snapshot.
// A cache avoids repeatedly hashing the same executable used by many PIDs.
// This is read-only. Results are published only after the worker finishes.
static std::atomic<unsigned> deepFilesChecked{0},deepFilesSkipped{0};
static std::atomic<unsigned> deepUniquePaths{0};

// Bounded PE section entropy inspection. Does not load or execute the file.
// The estimate uses at most 1 MiB per section; not a malware verdict.
static std::atomic<unsigned> peEntropyFiles{0},peEntropySections{0};
static std::atomic<unsigned> peEntropyInvalid{0},peEntropySectionsSkipped{0};
static std::atomic<unsigned> peEntropyCancelled{0};
static std::vector<Record> inspectPeSectionEntropy(const std::wstring& path){
    std::vector<Record> results;
    // Invalid/inaccessible files are counted, not silently treated as inspected.
    const auto reject=[&](){
        ++peEntropyInvalid;
        return std::vector<Record>{};
    };
    std::ifstream f(fs::path(path),std::ios::binary);
    if(!f)return reject();
    f.seekg(0,std::ios::end);
    const auto end=f.tellg();
    if(end<static_cast<std::streamoff>(sizeof(IMAGE_DOS_HEADER)))return reject();
    const auto length=static_cast<std::uint64_t>(end);
    f.seekg(0);
    IMAGE_DOS_HEADER dos{};
    f.read(reinterpret_cast<char*>(&dos),sizeof(dos));
    if(!f || dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<0)return reject();
    const auto ntOffset=static_cast<std::uint64_t>(dos.e_lfanew);
    if(ntOffset>length || length-ntOffset<sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER))
        return reject();
    f.seekg(static_cast<std::streamoff>(ntOffset));
    DWORD signature=0;
    IMAGE_FILE_HEADER header{};
    f.read(reinterpret_cast<char*>(&signature),sizeof(signature));
    f.read(reinterpret_cast<char*>(&header),sizeof(header));
    if(!f || signature!=IMAGE_NT_SIGNATURE ||
       header.NumberOfSections==0 || header.NumberOfSections>96)return reject();
    const auto tableOffset=ntOffset+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+header.SizeOfOptionalHeader;
    const auto sectionBytes=static_cast<std::uint64_t>(header.NumberOfSections)*sizeof(IMAGE_SECTION_HEADER);
    if(tableOffset>length || sectionBytes>length-tableOffset)return reject();
    // Verify optional header magic before claiming an executable PE was parsed.
    if(header.SizeOfOptionalHeader<sizeof(WORD))return reject();
    WORD optionalMagic=0;
    f.seekg(static_cast<std::streamoff>(
        ntOffset+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)));
    f.read(reinterpret_cast<char*>(&optionalMagic),sizeof(optionalMagic));
    if(!f || (optionalMagic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
              optionalMagic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC))return reject();
    f.seekg(static_cast<std::streamoff>(tableOffset));
    std::vector<IMAGE_SECTION_HEADER> sections(header.NumberOfSections);
    f.read(reinterpret_cast<char*>(sections.data()),
        static_cast<std::streamsize>(sectionBytes));
    if(!f)return reject();
    ++peEntropyFiles;
    results.push_back({"PE File Metadata",std::string(path.begin(),path.end()),
        "Machine="+std::to_string(header.Machine)+
        " | Sections="+std::to_string(header.NumberOfSections)+
        " | PE="+std::string(optionalMagic==IMAGE_NT_OPTIONAL_HDR64_MAGIC?"PE32+":"PE32")+
        " | Timestamp="+std::to_string(header.TimeDateStamp)+
        " | Characteristics="+std::to_string(header.Characteristics)});
    for(const auto& section:sections){
        if(cancelRequested){++peEntropyCancelled;break;}
        const auto offset=static_cast<std::uint64_t>(section.PointerToRawData);
        const auto rawSize=static_cast<std::uint64_t>(section.SizeOfRawData);
        if(!rawSize || offset>length || rawSize>length-offset){
            ++peEntropySectionsSkipped;
            continue;
        }
        const auto sample=static_cast<std::size_t>(
            std::min<std::uint64_t>(rawSize,1024ull*1024ull));
        std::vector<unsigned char> bytes(sample);
        f.clear();
        f.seekg(static_cast<std::streamoff>(offset));
        f.read(reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(sample));
        if(!f){++peEntropySectionsSkipped;continue;}
        std::array<std::uint64_t,256> histogram{};
        for(unsigned char byte:bytes)++histogram[byte];
        double entropy=0.0;
        for(auto count:histogram){
            if(!count)continue;
            const double probability=static_cast<double>(count)/sample;
            entropy-=probability*std::log2(probability);
        }
        std::string name(reinterpret_cast<const char*>(section.Name),8);
        const auto nullPosition=name.find('\0');
        if(nullPosition!=std::string::npos)name.resize(nullPosition);
        std::ostringstream details;
        details<<std::fixed<<std::setprecision(3)
            <<"Entropy: "<<entropy<<" bits/byte | Sample: "<<sample
            <<" bytes | Raw section: "<<rawSize<<" bytes"
            <<" | Virtual size: "<<section.Misc.VirtualSize
            <<" | Flags: "<<section.Characteristics;
        results.push_back({"PE Section Entropy",name,details.str()});
        ++peEntropySections;
    }
    return results;
}
static std::vector<Record> inspectDeepProcessExecutables(
    const std::vector<Process>& snapshot){
    std::vector<Record> findings;
    std::unordered_set<std::wstring> seen;
    constexpr std::uintmax_t kMaxHashBytes=128ull*1024ull*1024ull;
    for(const auto& proc:snapshot){
        if(cancelRequested)break;
        ++sequentialDone;
        setSequentialItem("Deep executable PID "+std::to_string(proc.pid));
        if(proc.path.empty() || proc.path[0]==L'['){
            ++deepFilesSkipped;
            continue;
        }
        std::wstring key=proc.path;
        std::transform(key.begin(),key.end(),key.begin(),
            [](wchar_t c){return static_cast<wchar_t>(std::towlower(c));});
        if(!seen.insert(key).second)continue;
        ++deepUniquePaths;
        std::error_code ec;
        const fs::path path(proc.path);
        if(!fs::is_regular_file(path,ec) || ec){
            ++deepFilesSkipped;
            findings.push_back({"Deep Executable Check",std::to_string(proc.pid),
                "Executable inaccessible or no longer present; not a suspicious finding"});
            continue;
        }
        const auto size=fs::file_size(path,ec);
        if(ec || size>kMaxHashBytes){
            ++deepFilesSkipped;
            findings.push_back({"Deep Executable Check",std::to_string(proc.pid),
                "Hash skipped (file size unavailable or exceeds 128 MiB safety limit)"});
            continue;
        }
        if(cancelRequested)break;
        setSequentialItem("SHA-256 PID "+std::to_string(proc.pid));
        const auto digest=sha256(proc.path);
        if(cancelRequested)break;
        setSequentialItem("Signature PID "+std::to_string(proc.pid));
        const auto signature=signatureStatus(proc.path);
        if(cancelRequested)break;
        setSequentialItem("PE section entropy PID "+std::to_string(proc.pid));
        auto sectionFindings=inspectPeSectionEntropy(proc.path);
        for(auto& item:sectionFindings)
            item.detail="PID="+std::to_string(proc.pid)+" | "+item.detail;
        findings.insert(findings.end(),sectionFindings.begin(),sectionFindings.end());
        ++deepFilesChecked;
        findings.push_back({"Deep Executable Check",std::to_string(proc.pid),
            "Path: "+utf8(proc.path)+" | Size: "+std::to_string(size)+
            " | SHA256: "+(digest.empty()?"Unavailable":digest)+
            " | Signature: "+signature});
    }
    return findings;
}
// Optional presentation hold, never counted as forensic work.
static constexpr unsigned kMinimumDisplaySeconds=15;
static std::atomic<unsigned> presentationWaitRemaining{0};
static std::atomic<bool> presentationHold{false};

// Stage-boundary process observer. It samples actual OS snapshots during the
// worker; it is not a lossless ETW event stream.
static std::atomic<unsigned> observedSnapshots{0},observedNewPids{0};
static std::atomic<unsigned> observedGonePids{0},observedUniquePids{0};
static std::vector<Record> observeProcessBoundary(
    const std::vector<Process>& snapshot,
    std::unordered_map<DWORD,std::wstring>& previous,
    std::unordered_set<DWORD>& everSeen){
    std::vector<Record> events;
    std::unordered_map<DWORD,std::wstring> current;
    for(const auto& proc:snapshot){
        current[proc.pid]=proc.name;
        everSeen.insert(proc.pid);
        const auto prior=previous.find(proc.pid);
        if(prior==previous.end() && !previous.empty()){
            events.push_back({"Process Observation","PID "+std::to_string(proc.pid),
                "New PID observed between scan stages; may have started earlier"});
            ++observedNewPids;
        }else if(prior!=previous.end() && prior->second!=proc.name){
            events.push_back({"Process Observation","PID "+std::to_string(proc.pid),
                "Executable name differs between observations; possible PID reuse"});
        }
    }
    for(const auto& prior:previous){
        if(!current.count(prior.first)){
            events.push_back({"Process Observation","PID "+std::to_string(prior.first),
                "PID absent from next scan-stage snapshot"});
            ++observedGonePids;
        }
    }
    previous=std::move(current);
    ++observedSnapshots;
    observedUniquePids=static_cast<unsigned>(everSeen.size());
    return events;
}

// Read-only, bounded filename screening for Windows batch scripts.
// A keyword hit is a review indicator, never proof of cheating.
static std::atomic<unsigned> batFilesSeen{0},batNameMatches{0},batDirsFailed{0};
static std::vector<Record> inspectNamedBatchScripts(){
    std::vector<Record> out;
    const auto env=[](const wchar_t* key)->std::wstring{
        wchar_t buffer[32768]{};
        DWORD n=GetEnvironmentVariableW(key,buffer,32768);
        return n>0 && n<32768 ? std::wstring(buffer,n) : L"";
    };
    const auto user=env(L"USERPROFILE");
    const auto local=env(L"LOCALAPPDATA");
    const auto roaming=env(L"APPDATA");
    const auto temp=env(L"TEMP");
    std::vector<fs::path> roots;
    if(!user.empty()){
        roots.emplace_back(fs::path(user)/L"Desktop");
        roots.emplace_back(fs::path(user)/L"Downloads");
        roots.emplace_back(fs::path(user)/L"Documents");
    }
    if(!local.empty())roots.emplace_back(local);
    if(!roaming.empty())roots.emplace_back(roaming);
    if(!temp.empty())roots.emplace_back(temp);
    const std::vector<std::wstring> keywords={
        L"cheat",L"bypass",L"external",L"inject",L"spoofer",
        L"fivem",L"executor",L"loader",L"redengine",L"eulen",
        L"skript",L"tzproject",L"lynx",L"aimbot",L"triggerbot"
    };
    std::unordered_set<std::wstring> visited;
    unsigned examined=0;
    constexpr unsigned kMaxEntries=30000;
    constexpr unsigned kMaxDepth=4;
    for(const auto& root:roots){
        if(cancelRequested || examined>=kMaxEntries)break;
        std::vector<std::pair<fs::path,unsigned>> pending{{root,0}};
        while(!pending.empty() && !cancelRequested && examined<kMaxEntries){
            auto current=pending.back();pending.pop_back();
            std::error_code ec;
            if(!fs::is_directory(current.first,ec))continue;
            const auto key=lowerPath(current.first.wstring());
            if(!visited.insert(key).second)continue;
            fs::directory_iterator it(current.first,
                fs::directory_options::skip_permission_denied,ec),last;
            if(ec){++batDirsFailed;continue;}
            for(;it!=last && !cancelRequested && examined<kMaxEntries;it.increment(ec)){
                if(ec){++batDirsFailed;ec.clear();break;}
                ++examined;
                std::error_code statusError;
                const auto status=it->symlink_status(statusError);
                if(statusError || fs::is_symlink(status))continue;
                if(fs::is_directory(status)){
                    if(current.second<kMaxDepth)
                        pending.emplace_back(it->path(),current.second+1);
                    continue;
                }
                if(!fs::is_regular_file(status))continue;
                const auto ext=lowerPath(it->path().extension().wstring());
                if(ext!=L".bat" && ext!=L".cmd")continue;
                ++batFilesSeen;
                const auto filename=lowerPath(it->path().filename().wstring());
                std::wstring matched;
                for(const auto& keyword:keywords){
                    if(filename.find(keyword)!=std::wstring::npos){
                        matched=keyword;break;
                    }
                }
                // Inspect a bounded script sample even when the filename is innocuous.
                // No commands are executed; content matches are investigation leads.
                std::string scriptSample;
                {
                    std::ifstream script(it->path(),std::ios::binary);
                    if(script){
                        scriptSample.resize(65536);
                        script.read(scriptSample.data(),static_cast<std::streamsize>(scriptSample.size()));
                        scriptSample.resize(static_cast<std::size_t>(script.gcount()));
                        std::transform(scriptSample.begin(),scriptSample.end(),
                            scriptSample.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
                    }
                }
                const std::vector<std::string> scriptIndicators={
                    "add-mppreference", "set-mppreference",
                    "disableantispyware", "exclusionpath",
                    "exclusionprocess", "exclusionextension",
                    "reg add", "schtasks /create", "powershell -enc",
                    "frombase64string", "certutil -decode",
                    "disable-realtimemonitoring", "disablerealtimemonitoring",
                    "disablebehaviormonitoring", "disableioavprotection",
                    "disablescriptscanning", "disableantispyware",
                    "remove-mppreference", "add-mppreference",
                    "set-mppreference", "exclusionpath",
                    "exclusionprocess", "exclusionextension",
                    "sc stop windefend", "net stop windefend",
                    "wevtutil cl", "clear-eventlog",
                    "remove-eventlog", "vssadmin delete shadows",
                    "bcdedit /set testsigning", "bcdedit /set nointegritychecks",
                    "reg delete", "reg add",
                    "schtasks /change", "schtasks /delete",
                    "powershell -encodedcommand", "powershell -enc",
                    "invoke-expression", "iex(", "downloadstring(",
                    "bitsadmin /transfer", "certutil -urlcache",
                    "mshta ", "rundll32 ", "regsvr32 ",
                    "tamperprotection", "exclusionipaddress"
                };
                std::string contentMatch;
                for(const auto& indicator:scriptIndicators){
                    if(scriptSample.find(indicator)!=std::string::npos){
                        contentMatch=indicator;break;
                    }
                }
                // Inventory all discovered batch files, not only filename matches.
                if(matched.empty() && contentMatch.empty()){
                    out.push_back({"Batch Script Inventory",utf8(it->path().filename().wstring()),
                        "INVENTORY ONLY | Path: "+utf8(it->path().wstring())+
                        " | No configured filename/content indicator in sampled bytes."});
                    continue;
                }
                ++batNameMatches;
                if(matched.empty()){
                    out.push_back({"Batch Script Content Review",utf8(it->path().filename().wstring()),
                        "REVIEW - CONTENT KEYWORD | Match: "+contentMatch+
                        " | Path: "+utf8(it->path().wstring())+
                        " | Sampled first 64 KiB only; script not executed."});
                    continue;
                }
                out.push_back({"Batch Script Name Rule",utf8(it->path().filename().wstring()),
                    "REVIEW - FILENAME KEYWORD | Match: "+utf8(matched)+
                    " | Extension: "+utf8(ext)+
                    " | Path: "+utf8(it->path().wstring())+
                    " | Filename only; script content not executed or interpreted. "
                    "This does not establish cheating or malicious behavior."});
            }
        }
    }
    return out;
}
static std::atomic<int> scanFailureStage{0};
static std::mutex scanFailureMutex;
static std::string scanFailureReason;
static void recordScanFailure(const char* reason){
    scanFailureStage=stage.load();
    {
        std::lock_guard<std::mutex> guard(scanFailureMutex);
        scanFailureReason=reason?reason:"Unknown scanner error";
    }
    diagnosticLog(reason?reason:"Unknown scanner error");
    scanFailed=true;
    if(forensicSourceStatus.load()==0)forensicSourceStatus=2;
}
// Conservative correlation: independent observed configuration and script/exclusion
// indicators are required. This is a review alert, not proof of successful evasion.
static std::atomic<bool> bypassCorrelatedAlert{false};
static std::atomic<unsigned> bypassCorrelatedSignals{0};
static std::vector<Record> correlateBypassIndicators(const std::vector<Record>& source){
    bool weakenedDefender=false,scriptIndicator=false,matchingExclusion=false;
    for(const auto& r:source){
        if(r.category=="Security Policy Review" &&
           (r.name.find("Defender")!=std::string::npos ||
            r.name.find("Windows event log")!=std::string::npos))
            weakenedDefender=true;
        if(r.category=="Batch Script Content Review")
            scriptIndicator=true;
        if(r.category=="Defender Exclusion Review" &&
           r.detail.find("DETECTED - NAME RULE")!=std::string::npos)
            matchingExclusion=true;
    }
    const unsigned signals=static_cast<unsigned>(weakenedDefender)+
        static_cast<unsigned>(scriptIndicator)+static_cast<unsigned>(matchingExclusion);
    bypassCorrelatedSignals=signals;
    bypassCorrelatedAlert=(weakenedDefender && (scriptIndicator||matchingExclusion));
    if(!bypassCorrelatedAlert)return {};
    return {{"Bypass Correlation Alert","Corroborated bypass indicators",
        "BYPASS DETECTED - REVIEW REQUIRED | An observed weakened Defender/event-log "
        "policy coincides with a batch-script content indicator or cheat-named "
        "Defender exclusion. This is correlation, NOT proof of execution, evasion "
        "or malicious intent. Inspect the underlying records."}};
}

// Read-only user-mode EXE and loaded kernel-driver inventory.
// These records are investigation leads, not evidence of a successful bypass.
static std::atomic<unsigned> exeReviewChecked{0},exeReviewFlagged{0};
static std::atomic<unsigned> driverReviewChecked{0},driverReviewFlagged{0};
static std::vector<Record> inspectExecutableAndDriverReview(const std::vector<Process>& processes){
    std::vector<Record> records;
    const std::vector<std::wstring> indicators={
        L"spoofer",L"bypass",L"injector",L"manualmap",L"kdmapper",
        L"aimbot",L"triggerbot",L"executor",L"redengine",L"eulen"
    };
    auto token=[&](const std::wstring& name)->std::wstring{
        for(const auto& item:indicators)
            if(name.find(item)!=std::wstring::npos)return item;
        return L"";
    };
    std::unordered_set<std::wstring> visited;
    for(const auto& process:processes){
        if(cancelRequested)break;
        if(process.path.empty() || process.path[0]==L'[')continue;
        const std::wstring path=lowerPath(process.path);
        if(!visited.insert(path).second)continue;
        ++exeReviewChecked;
        const auto filename=lowerPath(fs::path(path).filename().wstring());
        const auto match=token(filename);
        // Review executable names that impersonate core Windows components
        // outside their expected Windows directories.
        const bool coreName=
            filename==L"svchost.exe" || filename==L"lsass.exe" ||
            filename==L"services.exe" || filename==L"winlogon.exe" ||
            filename==L"csrss.exe" || filename==L"smss.exe";
        const bool windowsSystemDirectory=
            path.find(L"\\windows\\system32\\")!=std::wstring::npos ||
            path.find(L"\\windows\\syswow64\\")!=std::wstring::npos;
        if(coreName && !windowsSystemDirectory){
            records.push_back({"System Process Name Review",utf8(process.name),
                "REVIEW ONLY | Core Windows executable name outside system directory"
                " | PID="+std::to_string(process.pid)+
                " | Path="+utf8(process.path)+
                " | Check signature and actual Windows installation location."});
        }
        // Misleading file names are review leads, not proof of execution abuse.
        const bool doubleExtension=
            filename.find(L".pdf.exe")!=std::wstring::npos ||
            filename.find(L".jpg.exe")!=std::wstring::npos ||
            filename.find(L".png.exe")!=std::wstring::npos ||
            filename.find(L".txt.exe")!=std::wstring::npos ||
            filename.find(L".docx.exe")!=std::wstring::npos;
        if(doubleExtension){
            records.push_back({"Executable Extension Review",utf8(process.name),
                "REVIEW ONLY | Executable uses a misleading double extension"
                " | PID="+std::to_string(process.pid)+
                " | Path="+utf8(process.path)+
                " | Verify origin before drawing conclusions."});
        }
        const bool unusual=path.find(L"\\appdata\\local\\temp\\")!=std::wstring::npos ||
            path.find(L"\\downloads\\")!=std::wstring::npos;
        if(match.empty() && !unusual)continue;
        ++exeReviewFlagged;
        records.push_back({"Usermode EXE Review",utf8(process.name),
            "REVIEW ONLY | PID="+std::to_string(process.pid)+
            " | Path="+utf8(process.path)+
            " | Filename token="+(match.empty()?"none":utf8(match))+
            " | User-writable location="+(unusual?"yes":"no")+
            " | A name or location alone does not establish cheating."});
    }
    // EnumDeviceDrivers is an inventory of loaded kernel images, not a
    // hidden-driver or kernel-tampering detector.
    std::array<LPVOID,2048> addresses{};
    DWORD needed=0;
    if(EnumDeviceDrivers(addresses.data(),
            static_cast<DWORD>(addresses.size()*sizeof(LPVOID)),&needed)){
        const size_t count=std::min(addresses.size(),
            static_cast<size_t>(needed/sizeof(LPVOID)));
        for(size_t i=0;i<count && !cancelRequested;++i){
            wchar_t pathBuffer[MAX_PATH]{};
            if(!GetDeviceDriverFileNameW(addresses[i],pathBuffer,MAX_PATH))
                continue;
            ++driverReviewChecked;
            const std::wstring path=lowerPath(pathBuffer);
            const std::wstring filename=lowerPath(fs::path(path).filename().wstring());
            const auto match=token(filename);
            const bool unusual=path.find(L"\\temp\\")!=std::wstring::npos ||
                path.find(L"\\users\\")!=std::wstring::npos;
            if(match.empty() && !unusual)continue;
            ++driverReviewFlagged;
            records.push_back({"Kernel Driver Review",utf8(filename),
                "REVIEW ONLY | Loaded driver path="+utf8(pathBuffer)+
                " | Filename token="+(match.empty()?"none":utf8(match))+
                " | Unusual path="+(unusual?"yes":"no")+
                " | This does not prove kernel bypass or malicious activity."});
        }
    }else{
        records.push_back({"Kernel Driver Coverage","Driver inventory unavailable",
            "Windows did not expose the loaded driver list; not equivalent to no drivers."});
    }
    return records;
}
static void scanWorker() {
    try {
        stage=1;
        auto p=enumerateProcesses();
        std::unordered_map<DWORD,std::wstring> observedPrevious;
        std::unordered_set<DWORD> observedEver;
        std::vector<Record> observedEvents=
            observeProcessBoundary(p,observedPrevious,observedEver);
        const std::wstring winRoot=windowsRoot();
        sequentialTotal=static_cast<unsigned>(p.size()*(kProcessChecksPerPid+2));
        processChecksPlanned=static_cast<unsigned long long>(p.size())*kProcessChecksPerPid;
        processChecksCompleted=0;processChecksUnavailable=0;
        sequentialDone=0;
        for(auto& proc:p) {
            if(cancelRequested)break;
            setSequentialItem("Process PID "+std::to_string(proc.pid));
            assessProcess(proc,winRoot);
            ++sequentialDone;
        }
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        auto processDetails=inspectIndividualProcesses(p);
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        auto deepExecutables=inspectDeepProcessExecutables(p);
        auto exeAndDriverReview=inspectExecutableAndDriverReview(p);
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        stageWorkItems[0]=static_cast<unsigned>(p.size());
        if(!cancelRequested){
            setSequentialItem("Process observation between stages");
            auto observation=observeProcessBoundary(
                enumerateProcesses(),observedPrevious,observedEver);
            observedEvents.insert(observedEvents.end(),
                observation.begin(),observation.end());
        }
        markInspectionStage(1);
        stage=2;
        sequentialDone=0;sequentialTotal=0;
        setSequentialItem("Service inventory");
        auto services=enumerateServices();
        services.insert(services.end(),processDetails.begin(),processDetails.end());
        services.insert(services.end(),deepExecutables.begin(),deepExecutables.end());
        services.insert(services.end(),exeAndDriverReview.begin(),exeAndDriverReview.end());
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        stageWorkItems[1]=static_cast<unsigned>(services.size()-processDetails.size()-deepExecutables.size());
        if(!cancelRequested){
            setSequentialItem("Process observation between stages");
            auto observation=observeProcessBoundary(
                enumerateProcesses(),observedPrevious,observedEver);
            observedEvents.insert(observedEvents.end(),
                observation.begin(),observation.end());
        }
        markInspectionStage(2);
        stage=3;
        sequentialDone=0;sequentialTotal=0;
        setSequentialItem("Startup inventory");
        auto startup=enumerateStartup();
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        stageWorkItems[2]=static_cast<unsigned>(startup.size());
        if(!cancelRequested){
            setSequentialItem("Process observation between stages");
            auto observation=observeProcessBoundary(
                enumerateProcesses(),observedPrevious,observedEver);
            observedEvents.insert(observedEvents.end(),
                observation.begin(),observation.end());
        }
        markInspectionStage(3);
        stage=4;
        sequentialDone=0;sequentialTotal=0;
        setSequentialItem("Network and device inventory");
        auto network=enumerateTcp();
        auto udp=enumerateUdp();
        auto tcp6=enumerateTcp6();
        auto usb=enumerateUsbStorage();
        auto defender=enumerateDefenderDetections();
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        stageWorkItems[3]=static_cast<unsigned>(
            network.size()+udp.size()+tcp6.size()+usb.size()+defender.size());
        if(!cancelRequested){
            setSequentialItem("Process observation between stages");
            auto observation=observeProcessBoundary(
                enumerateProcesses(),observedPrevious,observedEver);
            observedEvents.insert(observedEvents.end(),
                observation.begin(),observation.end());
        }
        markInspectionStage(4);
        stage=5;
        sequentialDone=0;
        sequentialTotal=39;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectWindowsSecurityConfiguration");
        auto security=inspectWindowsSecurityConfiguration();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectPolicyRuleSet");
        auto policyRules=inspectPolicyRuleSet();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectFirmwareAndDmaIndicators");
        auto firmwareIndicators=inspectFirmwareAndDmaIndicators();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectFiveMSafeTestMarkers");
        auto fiveMTest=inspectFiveMSafeTestMarkers();
        ++sequentialDone;
        // Capture-protection diagnostics: inspect only our own window.
        // A protected window is not evidence of malware, and this does not
        // enumerate or bypass other applications' capture settings.
        if(hwnd && IsWindow(hwnd)){
            DWORD affinity=0;
            if(GetWindowDisplayAffinity(hwnd,&affinity)){
                const char* mode=affinity==0?"WDA_NONE":
                    affinity==1?"WDA_MONITOR":
                    affinity==0x11?"WDA_EXCLUDEFROMCAPTURE":"Unknown";
                security.push_back({"Capture Diagnostics","Scanner window",
                    std::string("Display affinity: ")+mode+
                    " | Informational only; not a malware indicator"});
            }else{
                security.push_back({"Capture Diagnostics","Scanner window",
                    "Display affinity unavailable for this window"});
            }
        }

        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectImageExecutionOptions");
        auto ifeo=inspectImageExecutionOptions();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectAdvancedPersistence");
        auto advancedPersistence=inspectAdvancedPersistence();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectExtendedEndpoint");
        auto extendedEndpoint=inspectExtendedEndpoint();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectDesktopWindowVisibility");
        auto windowVisibility=inspectDesktopWindowVisibility(hwnd);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectLogonConfiguration");
        auto logon=inspectLogonConfiguration();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectHostsFile");
        auto hosts=inspectHostsFile();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectCheatNamedProcesses");
        auto cheatNameProcesses=inspectCheatNamedProcesses(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectCheatNamedModules");
        auto cheatNameModules=inspectCheatNamedModules(p);
        auto dllReviewRecords=inspectExpandedDllIndicators(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectArtifactLocations");
        auto artifactLocations=inspectArtifactLocations();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectAdditionalEvidence");
        auto additionalEvidence=inspectAdditionalEvidence(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectExpandedPersistenceIndicators");
        auto expandedPersistence=inspectExpandedPersistenceIndicators();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectStartupFolderIndicators");
        auto startupFileIndicators=inspectStartupFolderIndicators();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectSpecialPersistenceKeys");
        auto specialPersistence=inspectSpecialPersistenceKeys();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectExecutableAlternateStreams");
        auto executableStreams=inspectExecutableAlternateStreams(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectImageExecutionHijackSettings");
        auto executionConfig=inspectImageExecutionHijackSettings();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectFilenameMasquerading");
        auto masquerading=inspectFilenameMasquerading(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectShellInitialization");
        auto shellInitialization=inspectShellInitialization();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectSecurityPolicyWeakening");
        auto securityWeakening=inspectSecurityPolicyWeakening();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectBamExecutionHistory");
        auto bamHistory=inspectBamExecutionHistory();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectDefenderExclusionIndicators");
        auto defenderExclusions=inspectDefenderExclusionIndicators();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectScheduledTaskNames");
        auto scheduledTaskNames=inspectScheduledTaskNames();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectUserComRegistrationIndicators");
        auto comRegistrations=inspectUserComRegistrationIndicators();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectServiceImagePathIndicators");
        auto serviceImagePaths=inspectServiceImagePathIndicators();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectPeStructure");
        auto peFindings=inspectPeStructure(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectExecutableProvenance");
        auto provenance=inspectExecutableProvenance(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectLoadedModuleProvenance");
        auto loadedModules=inspectLoadedModuleProvenance(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectTemporaryExecutables");
        auto temporaryExecutables=inspectTemporaryExecutables(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("collectWindowsTimeline");
        auto timeline=collectWindowsTimeline();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectBypassEvidenceIntegrity");
        auto bypassIntegrity=inspectBypassEvidenceIntegrity();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectExtendedBypassEvidence");
        auto bypassExtended=inspectExtendedBypassEvidence(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectAdditionalCheatIndicators");
        auto advancedIntegrity=inspectAdditionalCheatIndicators(p);
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectAuditAndPlatformEvidence");
        auto auditPlatform=inspectAuditAndPlatformEvidence();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectExtraSecurityPolicies");
        auto extraPolicies=inspectExtraSecurityPolicies();
        ++sequentialDone;
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectForensicSourceHeaders");
        auto forensicHeaders=inspectForensicSourceHeaders();
        ++sequentialDone;
        forensicSourceChecks.store(static_cast<unsigned>(forensicHeaders.size()));
        forensicSourceStatus.store(1);
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectYaraLocalFiles");
        auto yaraFindings=inspectYaraLocalFiles(p);
        ++sequentialDone;        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        setSequentialItem("inspectNamedBatchScripts (.bat/.cmd)");
        auto batchNameFindings=inspectNamedBatchScripts();
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        // Reconcile a second actual Windows snapshot; this is a bounded
        // discovery pass, not an invented process count or an ETW monitor.
        setSequentialItem("Second process snapshot / PID reconciliation");
        auto secondSnapshot=enumerateProcesses();
        auto processChanges=reconcileProcessSnapshots(p,secondSnapshot);
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        forensicProducedRecords=static_cast<unsigned>(forensicHeaders.size()+
            yaraFindings.size()+processChanges.size()+batchNameFindings.size());
        stageWorkItems[4]=forensicProducedRecords.load();
        markInspectionStage(5);
        stage=5;
        services.insert(services.end(),observedEvents.begin(),observedEvents.end());
        services.insert(services.end(),processChanges.begin(),processChanges.end());
        services.insert(services.end(),startup.begin(),startup.end());
        services.insert(services.end(),network.begin(),network.end());
        services.insert(services.end(),udp.begin(),udp.end());
        services.insert(services.end(),tcp6.begin(),tcp6.end());
        services.insert(services.end(),usb.begin(),usb.end());
        services.insert(services.end(),defender.begin(),defender.end());
        services.insert(services.end(),security.begin(),security.end());
        services.insert(services.end(),bypassIntegrity.begin(),bypassIntegrity.end());
        services.insert(services.end(),bypassExtended.begin(),bypassExtended.end());
        services.insert(services.end(),advancedIntegrity.begin(),advancedIntegrity.end());
        services.insert(services.end(),auditPlatform.begin(),auditPlatform.end());
        services.insert(services.end(),extraPolicies.begin(),extraPolicies.end());
        services.insert(services.end(),forensicHeaders.begin(),forensicHeaders.end());
        services.insert(services.end(),yaraFindings.begin(),yaraFindings.end());
        services.insert(services.end(),batchNameFindings.begin(),batchNameFindings.end());
        services.insert(services.end(),policyRules.begin(),policyRules.end());
        services.insert(services.end(),firmwareIndicators.begin(),firmwareIndicators.end());
        services.insert(services.end(),fiveMTest.begin(),fiveMTest.end());
        services.insert(services.end(),ifeo.begin(),ifeo.end());
        services.insert(services.end(),advancedPersistence.begin(),advancedPersistence.end());
        services.insert(services.end(),extendedEndpoint.begin(),extendedEndpoint.end());
        services.insert(services.end(),windowVisibility.begin(),windowVisibility.end());
        services.insert(services.end(),logon.begin(),logon.end());
        services.insert(services.end(),hosts.begin(),hosts.end());
        services.insert(services.end(),peFindings.begin(),peFindings.end());
        services.insert(services.end(),provenance.begin(),provenance.end());
        services.insert(services.end(),cheatNameProcesses.begin(),cheatNameProcesses.end());
        services.insert(services.end(),cheatNameModules.begin(),cheatNameModules.end());
        services.insert(services.end(),dllReviewRecords.begin(),dllReviewRecords.end());
        services.insert(services.end(),artifactLocations.begin(),artifactLocations.end());
        services.insert(services.end(),additionalEvidence.begin(),additionalEvidence.end());
        services.insert(services.end(),expandedPersistence.begin(),expandedPersistence.end());
        services.insert(services.end(),startupFileIndicators.begin(),startupFileIndicators.end());
        services.insert(services.end(),specialPersistence.begin(),specialPersistence.end());
        services.insert(services.end(),executableStreams.begin(),executableStreams.end());
        services.insert(services.end(),executionConfig.begin(),executionConfig.end());
        services.insert(services.end(),masquerading.begin(),masquerading.end());
        services.insert(services.end(),shellInitialization.begin(),shellInitialization.end());
        services.insert(services.end(),securityWeakening.begin(),securityWeakening.end());
        services.insert(services.end(),bamHistory.begin(),bamHistory.end());
        services.insert(services.end(),defenderExclusions.begin(),defenderExclusions.end());
        services.insert(services.end(),scheduledTaskNames.begin(),scheduledTaskNames.end());
        services.insert(services.end(),comRegistrations.begin(),comRegistrations.end());
        services.insert(services.end(),serviceImagePaths.begin(),serviceImagePaths.end());
        services.insert(services.end(),loadedModules.begin(),loadedModules.end());
        services.insert(services.end(),temporaryExecutables.begin(),temporaryExecutables.end());
        auto bypassCorrelations=correlateBypassIndicators(services);
        services.insert(services.end(),bypassCorrelations.begin(),bypassCorrelations.end());
        auto correlations=correlateForensicEvidence(services);
        forensicCorrelationNotices.store(static_cast<unsigned>(correlations.size()));
        services.insert(services.end(),correlations.begin(),correlations.end());
        if(defenderAlerts.load()>0)defenderNotificationPending=true;
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            processes=std::move(p);
            records=std::move(services);
            timelineEvents=std::move(timeline);
            timelineCount=timelineEvents.size();
            processCount=processes.size();
            recordCount=records.size();
        }
        stageWorkItems[5]=static_cast<unsigned>(recordCount.load());
        markInspectionStage(6);
        // The forensic scan has finished. Keep a separate, clearly labeled
        // presentation countdown; do not change scanElapsedUs or stage timings.
        const auto actualUs=scanElapsedUs.load();
        const auto minimumUs=static_cast<unsigned long long>(kMinimumDisplaySeconds)*1000000ULL;
        if(actualUs<minimumUs){
            presentationHold=true;
            const auto until=std::chrono::steady_clock::now()+
                std::chrono::microseconds(minimumUs-actualUs);
            while(!cancelRequested){
                const auto now=std::chrono::steady_clock::now();
                if(now>=until)break;
                const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(until-now).count();
                presentationWaitRemaining=static_cast<unsigned>((remaining+999)/1000);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            presentationWaitRemaining=0;
            presentationHold=false;
            if(cancelRequested){scanCancelled=true;scanning=false;return;}
        }
        done=true;
    } catch(const std::exception& e) {
        recordScanFailure(e.what());
    } catch(...) {
        recordScanFailure("Unknown exception inside scanWorker");
    }
    scanning=false;
}
// Progress reflects completed worker milestones, not an artificial timer.
static double inspectionProgressStart=0.0;
static double inspectionPresentationFraction(){
    if(inspectionProgressStart<=0.0)return 0.0;
    if(scanFailed || scanCancelled)return std::clamp(completedStages.load()/6.0,0.0,0.99);
    if(done)return 1.0;
    return std::clamp(completedStages.load()/6.0,0.0,0.99);
}
static int inspectionDisplayPercent(){
    return (int)std::round(inspectionPresentationFraction()*100.0);
}

static void startScan() {
    // Prevent duplicate starts and keep one completed verification per session.
    // Failed/cancelled attempts may be retried.
    if(scanning.load() || (done.load() && !scanFailed.load() &&
        !scanCancelled.load()))return;
    bypassCorrelatedAlert=false;
    bypassCorrelatedSignals=0;
    dllModulesExamined=0;
    dllReviewFindings=0;
    scanFailureStage=0;
    {
        std::lock_guard<std::mutex> guard(scanFailureMutex);
        scanFailureReason.clear();
    }
    peFilesInspected=0;
    processChecksPlanned=0;processChecksCompleted=0;processChecksUnavailable=0;
    processNewPids=0;processExitedPids=0;processSecondSnapshot=0;
    forensicProducedRecords=0;
    observedSnapshots=0;observedNewPids=0;
    observedGonePids=0;observedUniquePids=0;
    presentationHold=false;presentationWaitRemaining=0;
    deepFilesChecked=0;deepFilesSkipped=0;deepUniquePaths=0;
    exeReviewChecked=0;exeReviewFlagged=0;
    driverReviewChecked=0;driverReviewFlagged=0;
    peEntropyFiles=0;peEntropySections=0;
    peEntropyInvalid=0;peEntropySectionsSkipped=0;peEntropyCancelled=0;
    batFilesSeen=0;batNameMatches=0;batDirsFailed=0;
    sequentialDone=0;sequentialTotal=0;
    setSequentialItem("");
    forensicSourceStatus=0;
    forensicSourceChecks=0;
    forensicCorrelationNotices=0;
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        if(done && !scanFailed && !scanCancelled){
            previousScanRecords=records;
            previousScanProcesses=processes;
            hasPreviousScan=true;
        }
    }
    stageStartedAt=std::chrono::steady_clock::now();
    for(auto& elapsed:stageElapsedUs)elapsed=0;
    for(auto& count:stageWorkItems)count=0;
    scanElapsedUs=0;
    inspectionProgressStart=ImGui::GetTime();
    cancelRequested=false;done=false;scanFailed=false;scanCancelled=false;defenderAlerts=0;defenderNotificationPending=false;completedStages=0;stage=0;scanning=true;
    try{
        std::thread([]{
            diagnosticLog("Scan worker started.");
            try{
                scanWorker();
                diagnosticLog("Scan worker returned.");
            }catch(const std::exception& e){
                recordScanFailure(e.what());
                scanning=false;
            }catch(...){
                recordScanFailure("Unknown exception in scan worker thread.");
                scanning=false;
            }
        }).detach();
    }catch(const std::exception& e){
        diagnosticLog(e.what());
        scanFailed=true;
        scanning=false;
        status="Could not start scan worker. See diagnostic.log.";
    }
}
static std::string csvQuote(const std::string& s) {
    std::string out="\"";
    for(char c:s){if(c=='"')out+="\"\"";else out+=c;}
    return out+"\"";
}
static void exportCsv() {
    std::ofstream out("SyncPCChecker_Report.csv",std::ios::binary);
    if(!out){status="Could not write CSV";return;}
    out<<"Type,PID,ParentPID,Name,Path,SHA256,Signature,ReviewFlag,SecurityAssessment\n";
    out<<"Scan Metric,,,First process snapshot,"<<stageWorkItems[0].load()<<",,,,\n";
    out<<"Scan Metric,,,Second process snapshot,"<<processSecondSnapshot.load()<<",,,,\n";
    out<<"Scan Metric,,,New PIDs,"<<processNewPids.load()<<",,,,\n";
    out<<"Scan Metric,,,PIDs absent from second snapshot,"<<processExitedPids.load()<<",,,,\n";
    std::lock_guard<std::mutex> lock(dataMutex);
    for(const auto& p:processes)
        out<<"Process,"<<p.pid<<","<<p.parent<<","<<csvQuote(utf8(p.name))<<","
           <<csvQuote(utf8(p.path))<<",,,"<<(p.suspicious?"REVIEW":"NONE")<<","<<csvQuote(p.assessment)<<"\n";
    for(const auto& r:records)
        out<<csvQuote(r.category)<<",,,"<<csvQuote(r.name)<<","<<csvQuote(r.detail)<<",,,,\n";
    for(const auto& f:files)
        out<<"File,,,"<<csvQuote(utf8(fs::path(f.path).filename().wstring()))<<","
           <<csvQuote(utf8(f.path))<<","<<csvQuote(f.hash)<<","<<csvQuote(f.signature)<<",,\n";
    status="CSV saved: SyncPCChecker_Report.csv";
}

static std::string htmlEscape(const std::string& value) {
    std::string result;
    for(char c:value) {
        switch(c) {
            case '&': result+="&amp;";break;
            case '<': result+="&lt;";break;
            case '>': result+="&gt;";break;
            case '"': result+="&quot;";break;
            case '\'':result+="&#39;";break;
            default: result+=c;break;
        }
    }
    return result;
}
static std::string jsonEscape(const std::string& value) {
    std::string result="\"";
    const char* hex="0123456789abcdef";
    for(unsigned char c:value) {
        if(c=='"' || c=='\\') {result+='\\';result+=(char)c;}
        else if(c=='\n')result+="\\n";
        else if(c=='\r')result+="\\r";
        else if(c=='\t')result+="\\t";
        else if(c<0x20) {
            result+="\\u00";
            result+=hex[c>>4];
            result+=hex[c&15];
        } else result+=(char)c;
    }
    return result+"\"";
}
static void exportHtml() {
    std::lock_guard<std::mutex> lock(dataMutex);
    std::ofstream out("SyncPCChecker_Report.html",std::ios::binary);
    if(!out){status="HTML export failed";return;}
    out<<"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
          "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
          "<title>Sync PC Checker Report</title>"
          "<style>body{background:#101115;color:#e8e9ee;font:15px Segoe UI,Arial,sans-serif;"
          "margin:40px auto;max-width:1100px;padding:0 18px}h1,h2{color:#ff8739}"
          "table{width:100%;border-collapse:collapse;margin:16px 0 36px}"
          "td,th{border-bottom:1px solid #34363e;padding:9px;text-align:left;word-break:break-word}"
          "th{background:#22252d}tr.review{background:#67252b}small{color:#9da0a9}</style></head><body>"
          "<h1>Sync PC Checker</h1><p>Developer: Mudin</p>"
          "<small>Read-only inventory. An inventory entry is not a threat finding.</small>";
    out<<"<h2>Processes ("<<processes.size()<<")</h2><table><tr>"
          "<th>PID</th><th>Parent</th><th>Name</th><th>Path</th><th>Security assessment</th></tr>";
    for(const auto& p:processes)
        out<<(p.suspicious?"<tr class=\"review\"><td>":"<tr><td>")<<p.pid<<"</td><td>"<<p.parent<<"</td><td>"
           <<htmlEscape(utf8(p.name))<<"</td><td>"<<htmlEscape(utf8(p.path))<<"</td><td>"<<htmlEscape(p.assessment)<<"</td></tr>";
    out<<"</table><h2>System Inventory ("<<records.size()<<")</h2><table>"
          "<tr><th>Category</th><th>Name</th><th>Detail</th></tr>";
    for(const auto& r:records)
        out<<"<tr><td>"<<htmlEscape(r.category)<<"</td><td>"<<htmlEscape(r.name)
           <<"</td><td>"<<htmlEscape(r.detail)<<"</td></tr>";
    out<<"</table><h2>File Integrity ("<<files.size()<<")</h2><table>"
          "<tr><th>File</th><th>SHA-256</th><th>Signature</th></tr>";
    for(const auto& f:files)
        out<<"<tr><td>"<<htmlEscape(utf8(f.path))<<"</td><td>"
           <<htmlEscape(f.hash)<<"</td><td>"<<htmlEscape(f.signature)<<"</td></tr>";
    out<<"</table></body></html>";
    status="HTML saved: SyncPCChecker_Report.html";
}
static void exportJson() {
    std::lock_guard<std::mutex> lock(dataMutex);
    std::ofstream out("SyncPCChecker_Report.json",std::ios::binary);
    if(!out){status="JSON export failed";return;}
    out<<"{\n  \"application\": \"Sync PC Checker\",\n  \"developer\": \"Mudin\","
          "\n  \"disclaimer\": \"Inventory is not a threat finding\",\n  \"processes\": [\n";
    for(size_t i=0;i<processes.size();i++) {
        const auto& p=processes[i];
        out<<"    {\"pid\": "<<p.pid<<", \"parent\": "<<p.parent
           <<", \"name\": "<<jsonEscape(utf8(p.name))
           <<", \"path\": "<<jsonEscape(utf8(p.path))
           <<", \"review\": "<<(p.suspicious?"true":"false")
           <<", \"assessment\": "<<jsonEscape(p.assessment)<<"}"
           <<(i+1<processes.size()?",":"")<<"\n";
    }
    out<<"  ],\n  \"records\": [\n";
    for(size_t i=0;i<records.size();i++) {
        const auto& r=records[i];
        out<<"    {\"category\": "<<jsonEscape(r.category)
           <<", \"name\": "<<jsonEscape(r.name)
           <<", \"detail\": "<<jsonEscape(r.detail)<<"}"
           <<(i+1<records.size()?",":"")<<"\n";
    }
    out<<"  ],\n  \"files\": [\n";
    for(size_t i=0;i<files.size();i++) {
        const auto& f=files[i];
        out<<"    {\"path\": "<<jsonEscape(utf8(f.path))
           <<", \"sha256\": "<<jsonEscape(f.hash)
           <<", \"signature\": "<<jsonEscape(f.signature)<<"}"
           <<(i+1<files.size()?",":"")<<"\n";
    }
    out<<"  ]\n}\n";
    status="JSON saved: SyncPCChecker_Report.json";
}
static void inspectSelectedFile() {
    std::wstring path=wide(fileInput);
    if(path.empty()) {status="Enter a file path";return;}
    try {
        auto r=inspectFile(path);
        std::lock_guard<std::mutex> lock(dataMutex);
        files.push_back(std::move(r));
        fileCount=files.size();
        status="File inspection finished";
    } catch(...) {status="File inspection failed";}
}
static void chooseFile() {
    wchar_t name[32768]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize=sizeof(ofn);
    ofn.hwndOwner=hwnd;
    ofn.lpstrFile=name;
    ofn.nMaxFile=32768;
    ofn.lpstrFilter=L"Executable files\0*.exe;*.dll;*.sys\0All files\0*.*\0";
    ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
    if(GetOpenFileNameW(&ofn)) {
        auto s=utf8(name);
        strncpy_s(fileInput,sizeof(fileInput),s.c_str(),_TRUNCATE);
    }
}
static void renderTargetCreate() {
    ID3D11Texture2D* back=nullptr;
    if(SUCCEEDED(swapchain->GetBuffer(0,IID_PPV_ARGS(&back)))) {
        device->CreateRenderTargetView(back,nullptr,&target);
        back->Release();
    }
}
static void renderTargetDestroy() {
    if(target){target->Release();target=nullptr;}
}
static bool initD3D(HWND h) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount=2;sd.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow=h;sd.SampleDesc.Count=1;
    sd.Windowed=TRUE;sd.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;
    D3D_FEATURE_LEVEL level;
    D3D_FEATURE_LEVEL requested[]={D3D_FEATURE_LEVEL_11_0,D3D_FEATURE_LEVEL_10_0};
    HRESULT hr=D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,0,
        requested,2,D3D11_SDK_VERSION,&sd,&swapchain,&device,&level,&context);
    if(FAILED(hr)){
        diagnosticHRESULT("D3D11 hardware initialization",hr);
        // WARP is Microsoft's supported CPU renderer, not a security bypass.
        hr=D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_WARP,
            nullptr,0,requested,2,D3D11_SDK_VERSION,&sd,
            &swapchain,&device,&level,&context);
        if(FAILED(hr)){
            diagnosticHRESULT("D3D11 WARP initialization",hr);
            return false;
        }
        diagnosticLog("D3D11 initialized using Microsoft WARP fallback.");
    }else{
        diagnosticLog("D3D11 initialized using hardware acceleration.");
    }
    renderTargetCreate();
    if(!target){
        diagnosticLog("Render target creation failed.");
        return false;
    }
    return true;
}
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND,UINT,WPARAM,LPARAM);
static LRESULT WINAPI wndProc(HWND h,UINT msg,WPARAM w,LPARAM l) {
    // Native titlebar controls: process before ImGui, so an overlapping
    // invisible drag item cannot intercept minimize/close.
    // Let ImGui receive mouse events first. Old native hitboxes intercepted
    // controls in the header, causing unresponsive buttons and accidental drags.
    if(msg==WM_NCCALCSIZE && w){
        // Remove the native non-client frame (including the white strip at the
        // top/bottom) while retaining WS_THICKFRAME for normal window resizing.
        return 0;
    }
    if(msg==WM_NCHITTEST){
        POINT pt{GET_X_LPARAM(l),GET_Y_LPARAM(l)};
        ScreenToClient(h,&pt);
        RECT rc{};GetClientRect(h,&rc);
        // Since the entire window is now client area, provide resize handles
        // ourselves so removing the border never disables resizing.
        if(!IsZoomed(h)){
            constexpr int grip=7;
            const bool left=pt.x>=0&&pt.x<grip;
            const bool right=pt.x>=rc.right-grip&&pt.x<rc.right;
            const bool top=pt.y>=0&&pt.y<grip;
            const bool bottom=pt.y>=rc.bottom-grip&&pt.y<rc.bottom;
            if(top&&left)return HTTOPLEFT;
            if(top&&right)return HTTOPRIGHT;
            if(bottom&&left)return HTBOTTOMLEFT;
            if(bottom&&right)return HTBOTTOMRIGHT;
            if(left)return HTLEFT;
            if(right)return HTRIGHT;
            if(top)return HTTOP;
            if(bottom)return HTBOTTOM;
        }
        // Preserve dragging from the empty top strip, leaving UI controls free.
        if(pt.y>=7&&pt.y<14&&pt.x>=0&&pt.x<rc.right-120)return HTCAPTION;
    }
    if(ImGui_ImplWin32_WndProcHandler(h,msg,w,l)) return true;
    switch(msg) {
    case WM_SIZE:
        if(device && w!=SIZE_MINIMIZED) {
            renderTargetDestroy();
            swapchain->ResizeBuffers(0,LOWORD(l),HIWORD(l),DXGI_FORMAT_UNKNOWN,0);
            renderTargetCreate();
        }
        return 0;
    case WM_SYSCOMMAND: if((w&0xfff0)==SC_KEYMENU) return 0;break;
    case WM_DESTROY:PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(h,msg,w,l);
}

static ImVec4 orange(){return ImVec4(.88f,.88f,.88f,1.f);}
static void applyTheme() {
    ImGui::StyleColorsDark();
    ImGuiStyle& st=ImGui::GetStyle();
    st.WindowRounding=10.f;
    st.ChildRounding=12.f;
    st.FrameRounding=cornerStyle==0?3.f:cornerStyle==1?7.f:11.f;
    st.PopupRounding=12.f;
    st.ScrollbarRounding=3.f;
    st.TabRounding=9.f;
    st.GrabRounding=3.f;
    st.WindowBorderSize=0.f;
    st.ChildBorderSize=1.f;
    st.FrameBorderSize=1.f;
    st.WindowPadding=ImVec2(20,17);
    st.FramePadding=ImVec2(11,densityIndex==0?7.f:densityIndex==2?11.f:9.f);
    st.ItemSpacing=ImVec2(10,densityIndex==0?7.f:densityIndex==2?12.f:9.f);
    st.ItemInnerSpacing=ImVec2(9,7);
    st.CellPadding=ImVec2(16.f,densityIndex==0?11.f:densityIndex==2?16.f:13.f);
    st.ScrollbarSize=scrollbarWidth==0?7.f:scrollbarWidth==1?10.f:15.f;
    auto& c=st.Colors;
    c[ImGuiCol_WindowBg]=ImVec4(.027f,.027f,.027f,1);
    c[ImGuiCol_ChildBg]=ImVec4(.052f,.052f,.052f,1);
    c[ImGuiCol_PopupBg]=ImVec4(.075f,.075f,.075f,1);
    c[ImGuiCol_Border]=ImVec4(.22f,.22f,.22f,1);
    c[ImGuiCol_Separator]=ImVec4(.18f,.18f,.18f,1);
    c[ImGuiCol_Text]=ImVec4(.96f,.96f,.96f,1);
    c[ImGuiCol_TextDisabled]=ImVec4(.61f,.61f,.61f,1);
    c[ImGuiCol_FrameBg]=ImVec4(.105f,.105f,.105f,1);
    c[ImGuiCol_FrameBgHovered]=ImVec4(.17f,.17f,.17f,1);
    c[ImGuiCol_FrameBgActive]=ImVec4(.23f,.23f,.23f,1);
    c[ImGuiCol_Button]=ImVec4(.105f,.105f,.105f,1);
    c[ImGuiCol_ButtonHovered]=ImVec4(.22f,.22f,.22f,1);
    c[ImGuiCol_ButtonActive]=ImVec4(.33f,.33f,.33f,1);
    c[ImGuiCol_Header]=ImVec4(.18f,.18f,.18f,1);
    c[ImGuiCol_HeaderHovered]=ImVec4(.27f,.27f,.27f,1);
    c[ImGuiCol_HeaderActive]=ImVec4(.36f,.36f,.36f,1);
    c[ImGuiCol_CheckMark]=ImVec4(.95f,.95f,.95f,1);
    c[ImGuiCol_SliderGrab]=ImVec4(.72f,.72f,.72f,1);
    c[ImGuiCol_SliderGrabActive]=ImVec4(.95f,.95f,.95f,1);
    c[ImGuiCol_Tab]=ImVec4(.12f,.12f,.12f,1);
    c[ImGuiCol_TabHovered]=ImVec4(.24f,.24f,.24f,1);
    c[ImGuiCol_TabSelected]=ImVec4(.33f,.33f,.33f,1);
    c[ImGuiCol_TabDimmed]=ImVec4(.07f,.07f,.07f,1);
    c[ImGuiCol_TableHeaderBg]=ImVec4(.13f,.13f,.13f,1);
    c[ImGuiCol_TableBorderStrong]=ImVec4(.25f,.25f,.25f,1);
    c[ImGuiCol_TableBorderLight]=ImVec4(.17f,.17f,.17f,1);
    c[ImGuiCol_TableRowBg]=ImVec4(.045f,.045f,.045f,1);
    c[ImGuiCol_TableRowBgAlt]=ImVec4(.075f,.075f,.075f,1);
    c[ImGuiCol_TextSelectedBg]=ImVec4(.55f,.55f,.55f,.4f);
    c[ImGuiCol_ScrollbarBg]=ImVec4(.04f,.04f,.04f,1);
    c[ImGuiCol_ScrollbarGrab]=ImVec4(.30f,.30f,.30f,1);
    c[ImGuiCol_NavHighlight]=ImVec4(.80f,.80f,.80f,1);
    c[ImGuiCol_TitleBg]=ImVec4(.035f,.035f,.035f,1.f);
    c[ImGuiCol_TitleBgActive]=ImVec4(.055f,.055f,.055f,1.f);
    c[ImGuiCol_MenuBarBg]=ImVec4(.055f,.055f,.055f,1.f);
    c[ImGuiCol_TableRowBgAlt]=ImVec4(.088f,.088f,.088f,1.f);
    c[ImGuiCol_PlotLines]=ImVec4(.74f,.74f,.74f,1.f);
    c[ImGuiCol_PlotHistogram]=ImVec4(.82f,.82f,.82f,1.f);
    c[ImGuiCol_ResizeGrip]=ImVec4(.40f,.40f,.40f,.40f);
    c[ImGuiCol_ResizeGripHovered]=ImVec4(.65f,.65f,.65f,.65f);
    c[ImGuiCol_ResizeGripActive]=ImVec4(.88f,.88f,.88f,.90f);
}
static void sectionTitle(const char* title,const char* description=nullptr) {
    ImGui::Dummy(ImVec2(0,9));
    ImGui::SetWindowFontScale(1.0f);
    ImGui::TextUnformatted(title);
    ImGui::SetWindowFontScale(1.f);
    if(description)ImGui::TextDisabled("%s",description);
    ImGui::Dummy(ImVec2(0,3));
    ImGui::PushStyleColor(ImGuiCol_Separator,ImVec4(0.274f,0.274f,0.274f,.72f));
    ImGui::Separator();
    ImGui::PopStyleColor();
    ImGui::Dummy(ImVec2(0,5));
}
static const char* stateText() {
    if(scanning)return cancelRequested?"Cancelling...":"Scanning";
    if(scanFailed)return "Failed";
    if(scanCancelled)return "Cancelled";
    if(done)return "Completed";
    return "Ready";
}
static const char* stages[]={"Preparing","Processes","Services & Drivers","Startup Entries","Network Connections","Finalizing"};
// Module inspector: renders actual collected evidence, not generic coverage popups.
struct InspectionModule {
    const char* title;
    const char* summary;
    const char* categories;
    bool implemented;
};
static const InspectionModule inspectionModules[] = {
    {"Processes & Privileges","Process inventory, parent PIDs and executable paths","@process",true},
    {"Memory Integrity","Read-only process virtual-memory protection and region inspection","@memory",true},
    {"Injection Indicators","Heuristic review of private executable and writable executable memory","@injection",true},
    {"Hooks & Interception","Memory protection review only; actual hook verification not yet supported","@hooks",true},
    {"Kernel & Drivers","Installed drivers and service inventory","Drivers;Services",true},
    {"Persistence & Boot","Startup registry entries and service inventory","Startup;Services",true},
    {"Network & Firewall","TCP/UDP endpoint inventory; firewall rules not analyzed","Network;Network UDP;Network IPv6",true},
    {"Hardware & USB","Registered USB storage device inventory","USB",true},
    {"Execution Forensics","Collected Windows event timeline and security-provider alerts","@timeline",true},
    {"Files & Signatures","User-selected files: SHA-256 and Authenticode","@files",true},
    {"FiveM Integrity","Local file SHA-256 verification against a trusted reference hash","@fivem",true},
    {"Evidence Correlation","Correlates collected process paths with other evidence records","@correlation",true},
    {"Mounted Media Review","Enumerate mounted volumes and optical media; VHD/ISO backing not confirmed","@media",true},
    {"Administrative Tool Review","List running administrative and diagnostic tools for contextual review","@tools",true},
    {"Kernel Integrity Coverage","SSDT, IDT, MSR, IRP, DKOM, PspCidTable and BYOVD capability status","@kernelstatus",false},
    {"Graphics Hook Coverage","Present interception and Heaven's Gate capability status","@graphicstatus",false}
};
static int inspectedModule = -1;
static bool openInspectorRequested = false;
static char moduleSearch[192] = "";
static bool moduleMatches(const char* categories,const std::string& category) {
    std::string keys(categories ? categories : "");
    size_t from=0;
    while(from<keys.size()) {
        size_t to=keys.find(';',from);
        if(to==std::string::npos)to=keys.size();
        if(category==keys.substr(from,to-from))return true;
        from=to+1;
    }
    return false;
}
static bool moduleSearchMatches(const std::string& text) {
    if(!moduleSearch[0])return true;
    std::string hay=text, needle=moduleSearch;
    std::transform(hay.begin(),hay.end(),hay.begin(),[](unsigned char c){return (char)std::tolower(c);});
    std::transform(needle.begin(),needle.end(),needle.begin(),[](unsigned char c){return (char)std::tolower(c);});
    return hay.find(needle)!=std::string::npos;
}
static char fivemFile[32768]{};
static char fivemExpectedHash[65]{};
static std::string fivemActualHash;
static std::string fivemVerificationStatus="Choose a local file and enter a trusted SHA-256 reference.";
static bool validSha256Text(const char* h) {
    if(std::strlen(h)!=64)return false;
    for(size_t i=0;i<64;++i)if(!std::isxdigit((unsigned char)h[i]))return false;
    return true;
}

struct MemoryFinding {
    uintptr_t address=0;
    size_t size=0;
    DWORD protection=0;
    DWORD type=0;
    std::string category,explanation;
};
static std::mutex memoryGuard;
static std::vector<MemoryFinding> memoryFindings;
static std::string memoryStatus="Choose a PID and click Inspect memory.";
static std::atomic<bool> memoryBusy{false};
static bool memoryShowAll=false;
static int memoryPid=0;
static size_t memoryRegionsChecked=0;
static std::string memoryProtectName(DWORD p){
    switch(p&0xff){
    case PAGE_EXECUTE:return "EXECUTE";
    case PAGE_EXECUTE_READ:return "EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE:return "EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY:return "EXECUTE_WRITECOPY";
    case PAGE_READWRITE:return "READWRITE";
    case PAGE_READONLY:return "READONLY";
    default:return "OTHER";
    }
}
static void runMemoryInspection(DWORD pid){
    if(memoryBusy.exchange(true))return;
    const bool showAll=memoryShowAll;
    std::thread([pid,showAll](){
        std::vector<MemoryFinding> findings;
        size_t checked=0;
        std::string status;
        HANDLE proc=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);
        if(!proc)proc=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
        if(!proc){
            DWORD err=GetLastError();
            status="OpenProcess failed (Windows error "+std::to_string(err)+
                "). Protected/system processes may deny access. Try a normal user process.";
        }else{
            SYSTEM_INFO sys{};GetNativeSystemInfo(&sys);
            uintptr_t addr=(uintptr_t)sys.lpMinimumApplicationAddress;
            const uintptr_t maximum=(uintptr_t)sys.lpMaximumApplicationAddress;
            while(addr<maximum&&checked<250000){
                MEMORY_BASIC_INFORMATION mbi{};
                if(!VirtualQueryEx(proc,(LPCVOID)addr,&mbi,sizeof(mbi))){
                    DWORD err=GetLastError();
                    if(checked==0)status="VirtualQueryEx failed (Windows error "+
                        std::to_string(err)+"). Process may be protected or inaccessible.";
                    break;
                }
                ++checked;
                const DWORD p=mbi.Protect&0xff;
                const bool executable=p==PAGE_EXECUTE||p==PAGE_EXECUTE_READ||
                    p==PAGE_EXECUTE_READWRITE||p==PAGE_EXECUTE_WRITECOPY;
                const bool writable=p==PAGE_EXECUTE_READWRITE||p==PAGE_EXECUTE_WRITECOPY;
                const bool privateExec=mbi.Type==MEM_PRIVATE&&executable;
                const bool mappedExec=mbi.Type==MEM_MAPPED&&executable;
                if(mbi.State==MEM_COMMIT&&(showAll||
                    (executable&&(writable||privateExec||mappedExec)))){
                    MemoryFinding f{};
                    f.address=(uintptr_t)mbi.BaseAddress;
                    f.size=mbi.RegionSize;
                    f.protection=mbi.Protect;
                    f.type=mbi.Type;
                    if(privateExec&&writable){
                        f.category="REVIEW: private writable executable";
                        f.explanation="Executable private memory with write permissions; common in JITs and some legitimate software.";
                    }else if(privateExec){
                        f.category="REVIEW: private executable";
                        f.explanation="Executable private allocation; may be legitimate JIT/runtime code.";
                    }else if(writable){
                        f.category="REVIEW: writable executable";
                        f.explanation="Writable executable mapping; investigate context before drawing conclusions.";
                    }else{
                        f.category="INFO: mapped executable";
                        f.explanation="Executable mapped region; verify backing file and expected use.";
                    }
                    if(findings.size()<2000)findings.push_back(std::move(f));
                }
                uintptr_t base=(uintptr_t)mbi.BaseAddress;
                if(mbi.RegionSize==0||base>UINTPTR_MAX-mbi.RegionSize)break;
                uintptr_t next=base+mbi.RegionSize;
                if(next<=addr)break;
                addr=next;
            }
            CloseHandle(proc);
            if(checked>0)status="Inspection completed. Entries describe memory permissions, not confirmed malware.";
            else if(status.empty())status="No readable regions. Process may be protected or exited.";
        }
        {std::lock_guard<std::mutex> lock(memoryGuard);
            memoryFindings=std::move(findings);
            memoryRegionsChecked=checked;
            memoryStatus=std::move(status);}
        memoryBusy=false;
    }).detach();
}
static void drawMemoryInvestigation(const char* mode,bool embedded=false){
    const ImVec4 accent(.84f,.84f,.84f,1);
    const ImVec4 muted(.61f,.61f,.61f,1);
    ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.079f,0.079f,0.079f,1));
    ImGui::BeginChild("##memoryControls",ImVec2(0,204),ImGuiChildFlags_None);
    ImGui::TextColored(accent,"TARGET PROCESS");
    ImGui::TextColored(muted,"Read-only address-space inspection. Some protected processes deny access.");
    ImGui::Dummy(ImVec2(0,9));
    ImGui::SetNextItemWidth(130);
    ImGui::InputInt("PID##targetPid",&memoryPid,1,100);
    ImGui::SameLine(0,12);
    ImGui::SetNextItemWidth(300);
    if(ImGui::BeginCombo("##processPicker","Choose running process...")){
        std::vector<Process> snapshot;
        {std::lock_guard<std::mutex> lock(dataMutex);snapshot=processes;}
        for(const auto& proc:snapshot){
            std::string name=utf8(proc.name)+"  [PID "+std::to_string(proc.pid)+"]";
            if(ImGui::Selectable(name.c_str(),memoryPid==(int)proc.pid))
                memoryPid=(int)proc.pid;
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine(0,12);
    if(ImGui::Button("REFRESH PROCESSES##memory")){
        auto refreshed=enumerateProcesses();
        std::lock_guard<std::mutex> lock(dataMutex);
        processes=std::move(refreshed);
        processCount=processes.size();
    }
    ImGui::Checkbox("Show all committed regions",&memoryShowAll);
    if(memoryPid<0)memoryPid=0;
    ImGui::BeginDisabled(memoryPid<=0||memoryBusy.load());
    if(ImGui::Button("RUN MEMORY INSPECTION",ImVec2(240,37)))
        runMemoryInspection((DWORD)memoryPid);
    ImGui::EndDisabled();
    ImGui::EndChild();
    ImGui::PopStyleColor();
    std::vector<MemoryFinding> findings;
    std::string status;size_t regions=0;
    {std::lock_guard<std::mutex> lock(memoryGuard);
        findings=memoryFindings;status=memoryStatus;regions=memoryRegionsChecked;}
    ImGui::Dummy(ImVec2(0,13));
    ImGui::TextColored(accent,"INSPECTION RESULTS");
    ImGui::TextColored(muted,"REGIONS QUERIED: %zu   /   REVIEW ENTRIES: %zu",
        regions,findings.size());
    if(memoryBusy.load())ImGui::TextColored(accent,"Collecting accessible memory regions...");
    else ImGui::TextWrapped("%s",status.c_str());
    if(std::strcmp(mode,"@hooks")==0){
        ImGui::TextColored(muted,"Scope: memory protections only; inline/IAT/EAT hooks are not verified.");
    }else if(std::strcmp(mode,"@injection")==0){
        ImGui::TextColored(muted,"Executable private regions are review indicators, not confirmed injection.");
    }
    ImGui::Dummy(ImVec2(0,8));
    if(ImGui::BeginTable("memoryResults",4,ImGuiTableFlags_Borders|
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|
        ImGuiTableFlags_ScrollY,ImVec2(0,embedded?std::max(320.0f,ImGui::GetContentRegionAvail().y-12.0f):-40.0f))){
        ImGui::TableSetupColumn("Address",ImGuiTableColumnFlags_WidthFixed,150);
        ImGui::TableSetupColumn("Size",ImGuiTableColumnFlags_WidthFixed,100);
        ImGui::TableSetupColumn("Protection",ImGuiTableColumnFlags_WidthFixed,155);
        ImGui::TableSetupColumn("Assessment / explanation",ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for(const auto& f:findings){
            char address[40]{};
            std::snprintf(address,sizeof(address),"0x%llX",(unsigned long long)f.address);
            std::string filter=std::string(address)+" "+f.category+" "+f.explanation;
            if(!moduleSearchMatches(filter))continue;
            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(address);
            ImGui::TableSetColumnIndex(1);ImGui::Text("%llu KiB",(unsigned long long)(f.size/1024));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(memoryProtectName(f.protection).c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::TextWrapped("%s: %s",f.category.c_str(),f.explanation.c_str());
        }
        ImGui::EndTable();
    }
}
static void modulesList() {
    const float full=ImGui::GetContentRegionAvail().x;
    const float gap=10.f;
    const int columns=full>=930.f?3:full>=590.f?2:1;
    const float width=(std::max)(150.f,(full-gap*(columns-1))/columns);
    for(int i=0;i<IM_ARRAYSIZE(inspectionModules);++i) {
        const auto& m=inspectionModules[i];
        ImGui::PushID(i);
        if(i%columns)ImGui::SameLine(0,gap);
        ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.076f,0.076f,0.076f,1));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,ImVec2(16.f,14.f));
        ImGui::BeginChild("##tool",ImVec2(width,180),ImGuiChildFlags_Borders);
        // Inner padding keeps text away from card edges; no decorative stripe
        // overlaid on the module label.
        ImGui::SetCursorPos(ImVec2(16.f,14.f));
        ImGui::TextColored(ImVec4(0.650f,0.650f,0.650f,1),"MODULE %02d",i+1);
        ImGui::SameLine();
        ImGui::TextColored(m.implemented?ImVec4(0.731f,0.731f,0.731f,1):
            ImVec4(0.676f,0.676f,0.676f,1),m.implemented?"AVAILABLE":"LIMITED");
        ImGui::SetWindowFontScale(1.10f);
        ImGui::TextWrapped("%s",m.title);
        ImGui::SetWindowFontScale(1.f);
        ImGui::TextDisabled("%s",m.summary);
        const float bottom=ImGui::GetWindowHeight()-39.f;
        if(ImGui::GetCursorPosY()<bottom)ImGui::SetCursorPosY(bottom);
        if(ImGui::Button("INSPECT  >##module",ImVec2(-1,27))) {
            inspectedModule=i;
            moduleSearch[0]=0;
            openInspectorRequested=true;
        }
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
        ImGui::PopID();
    }
    if(openInspectorRequested) { ImGui::OpenPopup("Evidence inspector"); openInspectorRequested=false; }
    ImGui::SetNextWindowSize(ImVec2(
        (std::max)(700.f,ImGui::GetIO().DisplaySize.x*.89f),
        (std::max)(500.f,ImGui::GetIO().DisplaySize.y*.88f)),ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(ImVec2(ImGui::GetIO().DisplaySize.x*.5f,ImGui::GetIO().DisplaySize.y*.5f),ImGuiCond_Appearing,ImVec2(.5f,.5f));
    if(ImGui::BeginPopupModal("Evidence inspector",nullptr,ImGuiWindowFlags_NoSavedSettings)) {
        if(inspectedModule>=0 && inspectedModule<IM_ARRAYSIZE(inspectionModules)) {
            const auto& m=inspectionModules[inspectedModule];
            ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.127f,0.127f,0.127f,1));
            ImGui::BeginChild("##inspectorBanner",ImVec2(0,108),ImGuiChildFlags_None);
            ImGui::TextColored(ImVec4(0.762f,0.762f,0.762f,1),"INVESTIGATION  /  %02d",inspectedModule+1);
            ImGui::SetWindowFontScale(1.18f);
            ImGui::TextUnformatted(m.title);
            ImGui::SetWindowFontScale(1.f);
            ImGui::TextDisabled("%s",m.implemented?"EVIDENCE INSPECTION":"MODULE UNAVAILABLE");
            ImGui::EndChild();
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0,10));
            ImGui::TextWrapped("%s",m.summary);
            if(!m.implemented) {
                ImGui::Spacing();
                ImGui::TextWrapped("This module does not collect evidence yet. No detection claims are made.");
            } else {
                ImGui::SetNextItemWidth(-1);
                ImGui::InputTextWithHint("##moduleSearch","Search collected evidence...",moduleSearch,sizeof(moduleSearch));
                ImGui::Separator();
                if(std::string(m.categories)=="@memory"||
                   std::string(m.categories)=="@injection"||
                   std::string(m.categories)=="@hooks"){
                    drawMemoryInvestigation(m.categories);
                } else if(std::string(m.categories)=="@media") {
                    ImGui::TextWrapped("Mounted drives visible to Windows. Drive type does not establish whether a VHD or ISO is mounted.");
                    if(ImGui::BeginTable("mountedDrives",3,ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg)){
                        ImGui::TableSetupColumn("Drive");
                        ImGui::TableSetupColumn("Type");
                        ImGui::TableSetupColumn("Evidence");
                        ImGui::TableHeadersRow();
                        wchar_t buffer[2048]{};
                        DWORD length=GetLogicalDriveStringsW(2047,buffer);
                        if(length>0&&length<2047){
                            for(const wchar_t* d=buffer;*d;d+=wcslen(d)+1){
                                const UINT t=GetDriveTypeW(d);
                                const char* type=t==DRIVE_CDROM?"Optical":t==DRIVE_FIXED?"Fixed":
                                    t==DRIVE_REMOVABLE?"Removable":t==DRIVE_REMOTE?"Network":"Other";
                                const std::string path=utf8(d);
                                if(!moduleSearchMatches(path+" "+type))continue;
                                ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                                ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(path.c_str());
                                ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(type);
                                ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted("Backing image not verified");
                            }
                        }
                        ImGui::EndTable();
                    }
                } else if(std::string(m.categories)=="@tools") {
                    std::vector<Process> snapshot;
                    {std::lock_guard<std::mutex> lock(dataMutex);snapshot=processes;}
                    static const wchar_t* toolNames[]={L"powershell.exe",L"pwsh.exe",
                        L"cmd.exe",L"psexec.exe",L"procexp.exe",L"procexp64.exe",
                        L"procmon.exe",L"taskmgr.exe",L"reg.exe",L"sc.exe",
                        L"wmic.exe",L"mshta.exe",L"rundll32.exe",
                        L"wscript.exe",L"cscript.exe",L"certutil.exe",L"bitsadmin.exe"};
                    ImGui::TextWrapped("Running administrative tools. Their presence is not evidence of abuse.");
                    if(ImGui::BeginTable("adminTools",3,ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg)){
                        ImGui::TableSetupColumn("Process");
                        ImGui::TableSetupColumn("PID");
                        ImGui::TableSetupColumn("Executable path");
                        ImGui::TableHeadersRow();
                        for(const auto& proc:snapshot){
                            bool match=false;
                            for(const wchar_t* name:toolNames)
                                if(_wcsicmp(proc.name.c_str(),name)==0){match=true;break;}
                            if(!match)continue;
                            const std::string name=utf8(proc.name),path=utf8(proc.path);
                            if(!moduleSearchMatches(name+" "+path))continue;
                            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(name.c_str());
                            ImGui::TableSetColumnIndex(1);ImGui::Text("%lu",(unsigned long)proc.pid);
                            ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",path.c_str());
                        }
                        ImGui::EndTable();
                    }
                } else if(std::string(m.categories)=="@kernelstatus") {
                    ImGui::TextWrapped("UNAVAILABLE: SSDT, IDT, MSR, IRP, DKOM cross-view, PspCidTable, and BYOVD reputation.");
                    ImGui::TextWrapped("Reliable coverage needs trusted kernel telemetry and a maintained vulnerable-driver reference set. No kernel detections are claimed.");
                } else if(std::string(m.categories)=="@graphicstatus") {
                    ImGui::TextWrapped("UNAVAILABLE: DirectX Present hook verification and Heaven's Gate transition detection.");
                    ImGui::TextWrapped("Current user-mode memory heuristics do not establish these findings.");
                } else if(std::string(m.categories)=="@timeline") {
                    std::vector<TimelineEvent> snapshot;
                    {std::lock_guard<std::mutex> lock(dataMutex);snapshot=timelineEvents;}
                    ImGui::TextDisabled("%zu Windows events collected. Run a full scan to refresh.",snapshot.size());
                    if(ImGui::BeginTable("executionEvents",4,ImGuiTableFlags_Borders|
                        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-45))) {
                        ImGui::TableSetupColumn("Time",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("Provider",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("Event ID",ImGuiTableColumnFlags_WidthFixed,85);
                        ImGui::TableSetupColumn("Event / evidence",ImGuiTableColumnFlags_WidthStretch,3);
                        ImGui::TableHeadersRow();
                        for(const auto& e:snapshot){
                            if(!moduleSearchMatches(e.timestamp+" "+e.source+" "+e.eventId+
                                " "+e.description+" "+e.detail))continue;
                            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                            if(e.alert)ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(73,73,73,120));
                            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(e.timestamp.c_str());
                            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(e.source.c_str());
                            ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(e.eventId.c_str());
                            ImGui::TableSetColumnIndex(3);ImGui::TextWrapped("%s | %s",e.description.c_str(),e.detail.c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::TextDisabled("Prefetch parsing is not included; these are collected event-log records.");
                } else if(std::string(m.categories)=="@fivem") {
                    ImGui::TextWrapped("Verify a local FiveM-related file against a SHA-256 reference from a trusted source.");
                    ImGui::SetNextItemWidth(-140);
                    ImGui::InputTextWithHint("##fivemFile","Full path to the file to verify",
                        fivemFile,sizeof(fivemFile));
                    ImGui::SameLine();
                    if(ImGui::Button("Browse file##fivem")){
                        wchar_t path[32768]{};
                        OPENFILENAMEW ofn{};ofn.lStructSize=sizeof(ofn);
                        ofn.hwndOwner=hwnd;ofn.lpstrFile=path;ofn.nMaxFile=32768;
                        ofn.lpstrFilter=L"All files\\0*.*\\0";
                        ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
                        if(GetOpenFileNameW(&ofn))
                            strncpy_s(fivemFile,sizeof(fivemFile),utf8(path).c_str(),_TRUNCATE);
                    }
                    ImGui::SetNextItemWidth(-1);
                    ImGui::InputTextWithHint("##fivemHash","Trusted SHA-256 reference (64 hex characters)",
                        fivemExpectedHash,sizeof(fivemExpectedHash));
                    ImGui::BeginDisabled(!fivemFile[0]||!validSha256Text(fivemExpectedHash));
                    if(ImGui::Button("Verify file integrity",ImVec2(210,38))){
                        fivemActualHash=sha256(wide(fivemFile));
                        if(fivemActualHash.size()!=64)fivemVerificationStatus="Unable to hash file; verify access and path.";
                        else {
                            std::string expected=fivemExpectedHash,actual=fivemActualHash;
                            std::transform(expected.begin(),expected.end(),expected.begin(),
                                [](unsigned char c){return (char)std::tolower(c);});
                            std::transform(actual.begin(),actual.end(),actual.begin(),
                                [](unsigned char c){return (char)std::tolower(c);});
                            fivemVerificationStatus=expected==actual?
                                "MATCH: The selected file matches the supplied reference hash.":
                                "MISMATCH: The selected file differs from the supplied reference hash.";
                        }
                    }
                    ImGui::EndDisabled();
                    ImGui::TextWrapped("%s",fivemVerificationStatus.c_str());
                    if(!fivemActualHash.empty())ImGui::TextWrapped("Computed SHA-256: %s",fivemActualHash.c_str());
                    ImGui::TextDisabled("This checks one file only; it does not validate the complete FiveM installation.");
                } else if(std::string(m.categories)=="@correlation") {
                    std::vector<Process> ps;
                    std::vector<Record> rs;
                    {std::lock_guard<std::mutex> lock(dataMutex);ps=processes;rs=records;}
                    ImGui::TextDisabled("Cross-referencing %zu processes with %zu collected records.",ps.size(),rs.size());
                    ImGui::TextWrapped("A match means the same executable path occurs in multiple evidence sources. It is not a malware verdict.");
                    size_t matches=0;
                    if(ImGui::BeginTable("crossSource",4,ImGuiTableFlags_Borders|
                        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-45))){
                        ImGui::TableSetupColumn("Process",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("PID",ImGuiTableColumnFlags_WidthFixed,75);
                        ImGui::TableSetupColumn("Source",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("Matched record",ImGuiTableColumnFlags_WidthStretch,3);
                        ImGui::TableHeadersRow();
                        for(const auto& proc:ps){
                            const std::string path=utf8(proc.path);
                            if(path.size()<7)continue;
                            std::string lowPath=path;
                            std::transform(lowPath.begin(),lowPath.end(),lowPath.begin(),
                                [](unsigned char c){return (char)std::tolower(c);});
                            for(const auto& rec:rs){
                                std::string detail=rec.name+" "+rec.detail;
                                std::transform(detail.begin(),detail.end(),detail.begin(),
                                    [](unsigned char c){return (char)std::tolower(c);});
                                if(detail.find(lowPath)==std::string::npos)continue;
                                if(!moduleSearchMatches(path+" "+rec.category+" "+rec.name+" "+rec.detail))continue;
                                ++matches;
                                ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                                ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(utf8(proc.name).c_str());
                                ImGui::TableSetColumnIndex(1);ImGui::Text("%lu",(unsigned long)proc.pid);
                                ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(rec.category.c_str());
                                ImGui::TableSetColumnIndex(3);ImGui::TextWrapped("%s | %s",rec.name.c_str(),rec.detail.c_str());
                            }
                        }
                        ImGui::EndTable();
                    }
                    ImGui::TextDisabled("%zu matching records (exact path text, case-insensitive).",matches);
                } else if(std::string(m.categories)=="@process") {
                    std::vector<TimelineEvent> snapshot;
                    {std::lock_guard<std::mutex> lock(dataMutex);snapshot=timelineEvents;}
                    ImGui::TextDisabled("%zu Windows events collected. Run a full scan to refresh.",snapshot.size());
                    if(ImGui::BeginTable("executionEvents",4,ImGuiTableFlags_Borders|
                        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-45))) {
                        ImGui::TableSetupColumn("Time",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("Provider",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("Event ID",ImGuiTableColumnFlags_WidthFixed,85);
                        ImGui::TableSetupColumn("Event / evidence",ImGuiTableColumnFlags_WidthStretch,3);
                        ImGui::TableHeadersRow();
                        for(const auto& e:snapshot){
                            if(!moduleSearchMatches(e.timestamp+" "+e.source+" "+e.eventId+
                                " "+e.description+" "+e.detail))continue;
                            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                            if(e.alert)ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(73,73,73,120));
                            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(e.timestamp.c_str());
                            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(e.source.c_str());
                            ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(e.eventId.c_str());
                            ImGui::TableSetColumnIndex(3);ImGui::TextWrapped("%s | %s",e.description.c_str(),e.detail.c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::TextDisabled("Prefetch parsing is not included; these are collected event-log records.");
                } else if(std::string(m.categories)=="@fivem") {
                    ImGui::TextWrapped("Verify a local FiveM-related file against a SHA-256 reference from a trusted source.");
                    ImGui::SetNextItemWidth(-140);
                    ImGui::InputTextWithHint("##fivemFile","Full path to the file to verify",
                        fivemFile,sizeof(fivemFile));
                    ImGui::SameLine();
                    if(ImGui::Button("Browse file##fivem")){
                        wchar_t path[32768]{};
                        OPENFILENAMEW ofn{};ofn.lStructSize=sizeof(ofn);
                        ofn.hwndOwner=hwnd;ofn.lpstrFile=path;ofn.nMaxFile=32768;
                        ofn.lpstrFilter=L"All files\0*.*\0";
                        ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
                        if(GetOpenFileNameW(&ofn))
                            strncpy_s(fivemFile,sizeof(fivemFile),utf8(path).c_str(),_TRUNCATE);
                    }
                    ImGui::SetNextItemWidth(-1);
                    ImGui::InputTextWithHint("##fivemHash","Trusted SHA-256 reference (64 hex characters)",
                        fivemExpectedHash,sizeof(fivemExpectedHash));
                    ImGui::BeginDisabled(!fivemFile[0]||!validSha256Text(fivemExpectedHash));
                    if(ImGui::Button("Verify file integrity",ImVec2(210,38))){
                        fivemActualHash=sha256(wide(fivemFile));
                        if(fivemActualHash.size()!=64)fivemVerificationStatus="Unable to hash file; verify access and path.";
                        else {
                            std::string expected=fivemExpectedHash,actual=fivemActualHash;
                            std::transform(expected.begin(),expected.end(),expected.begin(),
                                [](unsigned char c){return (char)std::tolower(c);});
                            std::transform(actual.begin(),actual.end(),actual.begin(),
                                [](unsigned char c){return (char)std::tolower(c);});
                            fivemVerificationStatus=expected==actual?
                                "MATCH: The selected file matches the supplied reference hash.":
                                "MISMATCH: The selected file differs from the supplied reference hash.";
                        }
                    }
                    ImGui::EndDisabled();
                    ImGui::TextWrapped("%s",fivemVerificationStatus.c_str());
                    if(!fivemActualHash.empty())ImGui::TextWrapped("Computed SHA-256: %s",fivemActualHash.c_str());
                    ImGui::TextDisabled("This checks one file only; it does not validate the complete FiveM installation.");
                } else if(std::string(m.categories)=="@correlation") {
                    std::vector<Process> ps;
                    std::vector<Record> rs;
                    {std::lock_guard<std::mutex> lock(dataMutex);ps=processes;rs=records;}
                    ImGui::TextDisabled("Cross-referencing %zu processes with %zu collected records.",ps.size(),rs.size());
                    ImGui::TextWrapped("A match means the same executable path occurs in multiple evidence sources. It is not a malware verdict.");
                    size_t matches=0;
                    if(ImGui::BeginTable("crossSource",4,ImGuiTableFlags_Borders|
                        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-45))){
                        ImGui::TableSetupColumn("Process",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("PID",ImGuiTableColumnFlags_WidthFixed,75);
                        ImGui::TableSetupColumn("Source",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("Matched record",ImGuiTableColumnFlags_WidthStretch,3);
                        ImGui::TableHeadersRow();
                        for(const auto& proc:ps){
                            const std::string path=utf8(proc.path);
                            if(path.size()<7)continue;
                            std::string lowPath=path;
                            std::transform(lowPath.begin(),lowPath.end(),lowPath.begin(),
                                [](unsigned char c){return (char)std::tolower(c);});
                            for(const auto& rec:rs){
                                std::string detail=rec.name+" "+rec.detail;
                                std::transform(detail.begin(),detail.end(),detail.begin(),
                                    [](unsigned char c){return (char)std::tolower(c);});
                                if(detail.find(lowPath)==std::string::npos)continue;
                                if(!moduleSearchMatches(path+" "+rec.category+" "+rec.name+" "+rec.detail))continue;
                                ++matches;
                                ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                                ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(utf8(proc.name).c_str());
                                ImGui::TableSetColumnIndex(1);ImGui::Text("%lu",(unsigned long)proc.pid);
                                ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(rec.category.c_str());
                                ImGui::TableSetColumnIndex(3);ImGui::TextWrapped("%s | %s",rec.name.c_str(),rec.detail.c_str());
                            }
                        }
                        ImGui::EndTable();
                    }
                    ImGui::TextDisabled("%zu matching records (exact path text, case-insensitive).",matches);
                } else if(std::string(m.categories)=="@process") {
                    std::vector<Process> snapshot;
                    {std::lock_guard<std::mutex> lock(dataMutex);snapshot=processes;}
                    ImGui::TextDisabled("%zu processes collected",snapshot.size());
                    if(ImGui::BeginTable("processEvidence",5,ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|
                        ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-45))) {
                        ImGui::TableSetupColumn("PID",ImGuiTableColumnFlags_WidthFixed,75);
                        ImGui::TableSetupColumn("Parent",ImGuiTableColumnFlags_WidthFixed,75);
                        ImGui::TableSetupColumn("Process",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("Executable path",ImGuiTableColumnFlags_WidthStretch,3);
                        ImGui::TableSetupColumn("Assessment",ImGuiTableColumnFlags_WidthStretch,2);
                        ImGui::TableHeadersRow();
                        for(const auto& p:snapshot) {
                            std::string name=utf8(p.name), path=utf8(p.path);
                            if(!moduleSearchMatches(name+" "+path+" "+p.assessment))continue;
                            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                            if(p.suspicious && highlightSuspicious)
                                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(52,52,52,160));
                            ImGui::TableSetColumnIndex(0);ImGui::Text("%lu",(unsigned long)p.pid);
                            ImGui::TableSetColumnIndex(1);ImGui::Text("%lu",(unsigned long)p.parent);
                            ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(name.c_str());
                            ImGui::TableSetColumnIndex(3);ImGui::TextUnformatted(path.c_str());
                            ImGui::TableSetColumnIndex(4);ImGui::TextWrapped("%s",p.assessment.c_str());
                        }
                        ImGui::EndTable();
                    }
                } else if(std::string(m.categories)=="@files") {
                    std::vector<FileResult> snapshot;
                    {std::lock_guard<std::mutex> lock(dataMutex);snapshot=files;}
                    ImGui::TextDisabled("%zu files verified",snapshot.size());
                    ImGui::BeginChild("fileEvidence",ImVec2(0,-45),ImGuiChildFlags_Borders);
                    {
                        for(const auto& f:snapshot) {
                            std::string path=utf8(f.path);
                            if(!moduleSearchMatches(path))continue;
                            ImGui::TextWrapped("%s",path.c_str());
                            ImGui::Separator();
                        }
                    }
                    ImGui::EndChild();
                } else {
                    std::vector<Record> snapshot;
                    {std::lock_guard<std::mutex> lock(dataMutex);snapshot=records;}
                    size_t count=0;
                    for(const auto& r:snapshot)if(moduleMatches(m.categories,r.category))++count;
                    ImGui::TextDisabled("%zu records collected",count);
                    if(ImGui::BeginTable("recordEvidence",3,ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|
                        ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-45))) {
                        ImGui::TableSetupColumn("Source",ImGuiTableColumnFlags_WidthFixed,125);
                        ImGui::TableSetupColumn("Entry",ImGuiTableColumnFlags_WidthStretch,1);
                        ImGui::TableSetupColumn("Evidence",ImGuiTableColumnFlags_WidthStretch,3);
                        ImGui::TableHeadersRow();
                        for(const auto& r:snapshot) {
                            if(!moduleMatches(m.categories,r.category) ||
                               !moduleSearchMatches(r.category+" "+r.name+" "+r.detail))continue;
                            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                            tintEvidenceRow(r);
                            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(r.category.c_str());
                            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(r.name.c_str());
                            ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",r.detail.c_str());
                        }
                        ImGui::EndTable();
                    }
                }
            }
        }
        ImGui::Separator();
        if(ImGui::Button("CLOSE INVESTIGATION",ImVec2(205,38)))ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

// Read-only process details. The module list is a snapshot and may change after collection.
struct ModuleReview {
    std::wstring name,path;
    std::string assessment;
    bool suspicious=false;
};
static Process selectedProcess{};
static std::vector<ModuleReview> selectedModules;
static bool detailsOpen=false;
static std::string selectedHash,selectedSignature;
static std::string moduleNote(const std::wstring& name,const std::wstring& path) {
    if(path.empty())return "Module path not exposed; no conclusion";
    std::wstring low=lowerPath(path);
    std::wstring nm=lowerPath(name);
    std::string reason;
    if(pathContains(low,L"\\appdata\\local\\temp\\") ||
       pathContains(low,L"\\windows\\temp\\"))appendWarning(reason,"Module loaded from a temporary directory");
    if(pathContains(low,L"\\downloads\\"))appendWarning(reason,"Module loaded from Downloads");
    if(pathContains(low,L"\\appdata\\roaming\\"))appendWarning(reason,"Module loaded from a user-writable profile directory");
    if((nm==L"kernel32.dll"||nm==L"ntdll.dll"||nm==L"user32.dll"||
        nm==L"advapi32.dll"||nm==L"kernelbase.dll") &&
        !startsWithPath(low,windowsRoot()))
        appendWarning(reason,"Windows system DLL name outside the Windows directory");
    return reason.empty()?"No path-based review indicators observed":reason;
}
static std::vector<ModuleReview> inspectProcessModules(DWORD pid) {
    std::vector<ModuleReview> out;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
    if(snap==INVALID_HANDLE_VALUE)return out;
    MODULEENTRY32W entry{};entry.dwSize=sizeof(entry);
    if(Module32FirstW(snap,&entry)) {
        do {
            ModuleReview m;
            m.name=entry.szModule;
            m.path=entry.szExePath;
            m.assessment=moduleNote(m.name,m.path);
            m.suspicious=m.assessment!="No path-based review indicators observed";
            out.push_back(std::move(m));
        }while(Module32NextW(snap,&entry));
    }
    CloseHandle(snap);
    return out;
}
static std::vector<ModuleReview> inspectImportedDlls(const std::wstring& path);
static std::vector<ModuleReview> selectedImports;
static void selectProcessDetails(const Process& p) {
    selectedProcess=p;
    selectedModules=inspectProcessModules(p.pid);
    selectedImports=inspectImportedDlls(p.path);
    selectedHash.clear();
    selectedSignature.clear();
    detailsOpen=true;
}

// Inspect the PE import directory on disk. This does not require opening
// another process and is different from enumerating currently loaded DLLs.
static std::vector<ModuleReview> inspectImportedDlls(const std::wstring& path) {
    std::vector<ModuleReview> result;
    if(!isResolvedPath(path))return result;
    std::ifstream input(fs::path(path),std::ios::binary|std::ios::ate);
    if(!input)return result;
    auto length=input.tellg();
    if(length<=0 || length>static_cast<std::streamoff>(128ull*1024*1024))return result;
    std::vector<unsigned char> bytes(static_cast<size_t>(length));
    input.seekg(0);
    if(!input.read(reinterpret_cast<char*>(bytes.data()),bytes.size()))return result;
    auto read16=[&](size_t off,WORD& value)->bool {
        if(off>bytes.size() || bytes.size()-off<sizeof(value))return false;
        std::memcpy(&value,bytes.data()+off,sizeof(value));return true;
    };
    auto read32=[&](size_t off,DWORD& value)->bool {
        if(off>bytes.size() || bytes.size()-off<sizeof(value))return false;
        std::memcpy(&value,bytes.data()+off,sizeof(value));return true;
    };
    WORD mz=0;
    DWORD peOffset=0,signature=0;
    if(!read16(0,mz)||mz!=IMAGE_DOS_SIGNATURE||
       !read32(0x3c,peOffset)||peOffset>bytes.size()||
       !read32(peOffset,signature)||signature!=IMAGE_NT_SIGNATURE)return result;
    size_t fileHeader=static_cast<size_t>(peOffset)+4;
    WORD sectionCount=0,optionalSize=0,magic=0;
    if(!read16(fileHeader+2,sectionCount)||
       !read16(fileHeader+16,optionalSize)||
       sectionCount>96)return result;
    size_t opt=fileHeader+sizeof(IMAGE_FILE_HEADER);
    if(!read16(opt,magic))return result;
    size_t dirOffset=magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC?112:
                     magic==IMAGE_NT_OPTIONAL_HDR32_MAGIC?96:0;
    if(!dirOffset || optionalSize<dirOffset+16)return result;
    DWORD importRva=0,importSize=0;
    if(!read32(opt+dirOffset+8,importRva)||
       !read32(opt+dirOffset+12,importSize)||!importRva)return result;
    size_t sectionOffset=opt+optionalSize;
    auto toOffset=[&](DWORD rva)->size_t {
        for(WORD i=0;i<sectionCount;++i) {
            size_t off=sectionOffset+static_cast<size_t>(i)*sizeof(IMAGE_SECTION_HEADER);
            DWORD virtualSize=0,virtualAddress=0,rawSize=0,rawOffset=0;
            if(!read32(off+8,virtualSize)||!read32(off+12,virtualAddress)||
               !read32(off+16,rawSize)||!read32(off+20,rawOffset))return bytes.size();
            DWORD span=(std::max)(virtualSize,rawSize);
            if(rva>=virtualAddress && static_cast<uint64_t>(rva)-virtualAddress<span) {
                uint64_t pos=static_cast<uint64_t>(rawOffset)+rva-virtualAddress;
                return pos<bytes.size()?static_cast<size_t>(pos):bytes.size();
            }
        }
        return bytes.size();
    };
    size_t start=toOffset(importRva);
    for(size_t i=0;i<512 && start<bytes.size();++i) {
        size_t at=start+i*sizeof(IMAGE_IMPORT_DESCRIPTOR);
        DWORD nameRva=0,firstThunk=0,originalThunk=0;
        if(!read32(at+12,nameRva)||!read32(at+16,firstThunk)||
           !read32(at,originalThunk))break;
        if(!nameRva && !firstThunk && !originalThunk)break;
        size_t nameAt=toOffset(nameRva);
        if(nameAt>=bytes.size())continue;
        size_t end=nameAt;
        while(end<bytes.size() && end-nameAt<260 && bytes[end])++end;
        if(end==bytes.size() || end-nameAt>=260)continue;
        std::string dll(reinterpret_cast<const char*>(bytes.data()+nameAt),end-nameAt);
        std::wstring wide(dll.begin(),dll.end());
        ModuleReview m;
        m.name=wide;
        m.path=L"Import table (not a loaded-module path)";
        m.assessment="Declared PE import; loading and trust are not established";
        result.push_back(std::move(m));
    }
    return result;
}
static void drawProcessDetails() {
    if(!detailsOpen)return;
    ImGui::SetNextWindowSize(ImVec2(1020,680),ImGuiCond_FirstUseEver);
    if(!ImGui::Begin("Process Details - Read Only",&detailsOpen)) {
        ImGui::End();return;
    }
    ImGui::Text("Process: %s",utf8(selectedProcess.name).c_str());
    ImGui::SameLine();ImGui::TextDisabled("PID: %lu | Parent PID: %lu",
        (unsigned long)selectedProcess.pid,(unsigned long)selectedProcess.parent);
    ImGui::TextWrapped("Executable: %s",utf8(selectedProcess.path).c_str());
    if(selectedProcess.suspicious)
        ImGui::TextColored(ImVec4(0.558f,0.558f,0.558f,1.f),
            "Review indicator: %s",selectedProcess.assessment.c_str());
    else ImGui::TextDisabled("%s",selectedProcess.assessment.c_str());
    if(isResolvedPath(selectedProcess.path)) {
        if(ImGui::Button("Calculate executable SHA-256 and signature")) {
            selectedHash=sha256(selectedProcess.path);
            selectedSignature=signatureStatus(selectedProcess.path);
        }
        if(!selectedHash.empty())ImGui::TextWrapped("SHA-256: %s",selectedHash.c_str());
        if(!selectedSignature.empty())ImGui::TextWrapped("Signature: %s",selectedSignature.c_str());
    }
    ImGui::SameLine();
    if(ImGui::Button("Refresh loaded modules"))
        selectedModules=inspectProcessModules(selectedProcess.pid);
    ImGui::Separator();
    ImGui::Text("Loaded modules: %zu",selectedModules.size());
    ImGui::TextDisabled("Read-only module inventory. Inaccessible modules are not evidence of malware.");
    if(selectedModules.empty())
        ImGui::TextDisabled("%s",XOR_STR("No module list available (protected, exited, or access denied).").c_str());
    if(ImGui::BeginTable("detailModules",3,ImGuiTableFlags_BordersInnerH|
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,
        ImVec2(0,230))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("Module",ImGuiTableColumnFlags_WidthStretch,1.2f);
        ImGui::TableSetupColumn("Full path",ImGuiTableColumnFlags_WidthStretch,3.f);
        ImGui::TableSetupColumn("Security assessment",ImGuiTableColumnFlags_WidthStretch,2.2f);
        ImGui::TableHeadersRow();
        for(const auto& m:selectedModules) {
            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
            if(m.suspicious && highlightSuspicious)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(97,97,97,180));
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(utf8(m.name).c_str());
            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(utf8(m.path).c_str());
            ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",m.assessment.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::Separator();
    ImGui::Text("Imported DLLs (PE import table): %zu",selectedImports.size());
    ImGui::TextDisabled("These are file dependencies, not proof that a DLL is loaded or malicious.");
    if(ImGui::BeginTable("importedDlls",2,ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|
        ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,180))) {
        ImGui::TableSetupColumn("DLL",ImGuiTableColumnFlags_WidthStretch,1);
        ImGui::TableSetupColumn("Assessment",ImGuiTableColumnFlags_WidthStretch,3);
        ImGui::TableHeadersRow();
        for(const auto& m:selectedImports) {
            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(utf8(m.name).c_str());
            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(m.assessment.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::End();
}
// Stopped automatic services can warrant review, but many are trigger-started by design.
struct ServiceReview {
    std::wstring name,display;
    DWORD startType=SERVICE_DEMAND_START;
    DWORD currentState=SERVICE_STOPPED;
    bool review=false;
    std::string assessment;
};
static std::vector<ServiceReview> inspectServiceStates() {
    std::vector<ServiceReview> result;
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE|SC_MANAGER_CONNECT);
    if(!scm)return result;
    DWORD needed=0,count=0,resume=0;
    EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,
        nullptr,0,&needed,&count,&resume,nullptr);
    if(GetLastError()==ERROR_MORE_DATA && needed && needed<32*1024*1024) {
        std::vector<BYTE> buffer(needed+4096);
        resume=0;
        if(EnumServicesStatusExW(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,
            buffer.data(),(DWORD)buffer.size(),&needed,&count,&resume,nullptr)) {
            auto rows=reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
            for(DWORD i=0;i<count;i++) {
                ServiceReview item;
                item.name=rows[i].lpServiceName;
                item.display=rows[i].lpDisplayName;
                item.currentState=rows[i].ServiceStatusProcess.dwCurrentState;
                SC_HANDLE service=OpenServiceW(scm,item.name.c_str(),SERVICE_QUERY_CONFIG);
                if(service) {
                    DWORD bytes=0;
                    QueryServiceConfigW(service,nullptr,0,&bytes);
                    if(bytes && bytes<65536) {
                        std::vector<BYTE> cfg(bytes);
                        if(QueryServiceConfigW(service,
                            reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfg.data()),bytes,&bytes))
                            item.startType=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfg.data())->dwStartType;
                    }
                    CloseServiceHandle(service);
                }
                item.review=(item.startType==SERVICE_AUTO_START &&
                    item.currentState==SERVICE_STOPPED);
                item.assessment=item.review?
                    "Automatic-start service is stopped; verify expected configuration":
                    "No stopped automatic-start indicator";
                result.push_back(std::move(item));
            }
        }
    }
    CloseServiceHandle(scm);
    return result;
}
static std::vector<ServiceReview> serviceReviews;
static void drawServiceReviews() {
    // Search is local to Service Review; it never modifies collected evidence.
    static char serviceSearch[256]{};
    static int serviceStateFilter=0;
    if(serviceReviews.empty())serviceReviews=inspectServiceStates();
    if(ImGui::Button("Refresh service states"))
        serviceReviews=inspectServiceStates();
    ImGui::SameLine();
    ImGui::TextDisabled("Stopped automatic-start services are review candidates, not confirmed threats.");
    ImGui::Dummy(ImVec2(0,6));
    ImGui::TextUnformatted(XOR_STR("SEARCH  /").c_str());
    ImGui::SameLine();
    ImGui::SetNextItemWidth((std::max)(100.f,ImGui::GetContentRegionAvail().x-245.f));
    ImGui::InputTextWithHint("##serviceSearch","Search service name, display name, state, assessment...",serviceSearch,sizeof(serviceSearch));
    ImGui::SameLine();
    if(ImGui::SmallButton("Clear##serviceSearch"))serviceSearch[0]='\0';
    ImGui::SameLine();
    ImGui::SetNextItemWidth(128.f);
    ImGui::Combo("##serviceStateFilter",&serviceStateFilter,"All\\0Running\\0Stopped\\0Suspect\\0\\0");
    const std::string searchLower=[&]() {
        std::string v(serviceSearch);
        std::transform(v.begin(),v.end(),v.begin(),[](unsigned char c){return (char)std::tolower(c);});
        return v;
    }();
    auto matchesService=[&](const ServiceReview& item)->bool {
        if(serviceStateFilter==1 && item.currentState!=SERVICE_RUNNING)return false;
        if(serviceStateFilter==2 && item.currentState!=SERVICE_STOPPED)return false;
        if(serviceStateFilter==3 && !item.review)return false;
        if(searchLower.empty())return true;
        std::string value=utf8(item.name)+" "+utf8(item.display)+" "+item.assessment+" "+
            (item.currentState==SERVICE_RUNNING?"running":item.currentState==SERVICE_STOPPED?"stopped":"other");
        std::transform(value.begin(),value.end(),value.begin(),[](unsigned char c){return (char)std::tolower(c);});
        return value.find(searchLower)!=std::string::npos;
    };
    size_t visible=0;
    for(const auto& item:serviceReviews)if(matchesService(item))++visible;
    ImGui::TextDisabled("%zu of %zu services shown  |  Search applies to this table only.",
                        visible,serviceReviews.size());
    if(ImGui::BeginTable("serviceReviewTable",5,ImGuiTableFlags_BordersInnerH|
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,
        ImVec2(0,-1))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("Service",ImGuiTableColumnFlags_WidthStretch,1.5f);
        ImGui::TableSetupColumn("Display name",ImGuiTableColumnFlags_WidthStretch,2.f);
        ImGui::TableSetupColumn("State",ImGuiTableColumnFlags_WidthFixed,110);
        ImGui::TableSetupColumn("Security assessment",ImGuiTableColumnFlags_WidthStretch,3.5f);
        ImGui::TableSetupColumn("Details",ImGuiTableColumnFlags_WidthFixed,110);
        ImGui::TableHeadersRow();
        for(const auto& item:serviceReviews) {
            if(!matchesService(item))continue;
            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
            if(item.review && highlightSuspicious)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(97,97,97,180));
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(utf8(item.name).c_str());
            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(utf8(item.display).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(item.currentState==SERVICE_RUNNING?"Running":
                item.currentState==SERVICE_STOPPED?"Stopped":"Other");
            ImGui::TableSetColumnIndex(3);ImGui::TextWrapped("%s",item.assessment.c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::PushID((int)(&item-&serviceReviews[0]));
            if(ImGui::Button("Show Details",ImVec2(130,32)))ImGui::OpenPopup("Service details");
            if(ImGui::BeginPopup("Service details")) {
                ImGui::Text("Service: %s",utf8(item.name).c_str());
                ImGui::TextWrapped("Display name: %s",utf8(item.display).c_str());
                ImGui::Text("Start type: %s",item.startType==SERVICE_AUTO_START?"Automatic":
                    item.startType==SERVICE_DEMAND_START?"Manual":
                    item.startType==SERVICE_DISABLED?"Disabled":"Other");
                ImGui::Text("State: %s",item.currentState==SERVICE_RUNNING?"Running":
                    item.currentState==SERVICE_STOPPED?"Stopped":"Other");
                ImGui::TextWrapped("Assessment: %s",item.assessment.c_str());
                SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
                if(scm) {
                    SC_HANDLE svc=OpenServiceW(scm,item.name.c_str(),SERVICE_QUERY_CONFIG);
                    if(svc) {
                        DWORD needed=0;
                        QueryServiceConfigW(svc,nullptr,0,&needed);
                        if(needed>0 && needed<65536) {
                            std::vector<BYTE> buffer(needed);
                            auto* cfg=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
                            if(QueryServiceConfigW(svc,cfg,needed,&needed)) {
                                if(cfg->lpBinaryPathName)ImGui::TextWrapped("Command: %s",utf8(cfg->lpBinaryPathName).c_str());
                                if(cfg->lpServiceStartName)ImGui::TextWrapped("Account: %s",utf8(cfg->lpServiceStartName).c_str());
                                ImGui::Text("Error control: %lu",(unsigned long)cfg->dwErrorControl);
                            }
                        }
                        CloseServiceHandle(svc);
                    }
                    CloseServiceHandle(scm);
                }
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

// Process findings have only a heuristic review flag. Confirmed detections
// are never inferred from that flag.
static bool expandedFindingsTable=true;
static int processViewFilter=0; // 0 all, 1 suspect, 2 detected, 3 no indicators
static void processTable(float height) {
    ImGui::TextDisabled("%s",XOR_STR("PROCESS TRIAGE").c_str());
    ImGui::SameLine();
    ImGui::TextColored(orange(),"READ-ONLY");
    ImGui::Dummy(ImVec2(0,3));
    const char* filters[]={"All processes","Suspect","Detected","No indicators"};
    for(int f=0;f<4;f++) {
        ImGui::PushID(f);
        const bool active=processViewFilter==f;
        if(active) {
            ImGui::PushStyleColor(ImGuiCol_Button,
                ImVec4(orange().x*.28f,orange().y*.28f,orange().z*.28f,1));
            ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(1.000f,1.000f,1.000f,1));
        }
        if(ImGui::Button(filters[f],ImVec2(f==0?148.f:f==3?152.f:120.f,36.f)))
            processViewFilter=f;
        if(active)ImGui::PopStyleColor(2);
        ImGui::PopID();
        if(f<3)ImGui::SameLine(0,7);
    }
    ImGui::Dummy(ImVec2(0,6));
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x*0.76f);
    ImGui::InputTextWithHint("##search","Search processes, paths, or assessments...",searchInput,sizeof(searchInput));
    ImGui::SameLine();ImGui::Checkbox("Show inaccessible paths",&showUnavailable);
    size_t flagged=0;
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        for(const auto& p:processes)if(p.suspicious)++flagged;
    }
    if(flagged)
        ImGui::TextColored(ImVec4(0.776f,0.776f,0.776f,1.f),
            "%zu SUSPECT process(es). Yellow indicates review, not confirmed malware.",flagged);
    else
        ImGui::TextDisabled("No path-based review indicators found. This does not guarantee safety.");
    const ImGuiTableFlags flags=ImGuiTableFlags_BordersInnerH|
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|
        ImGuiTableFlags_ScrollY|ImGuiTableFlags_SizingStretchProp;
    if(ImGui::BeginTable("processes",6,flags,ImVec2(0,height<0.f?ImGui::GetContentRegionAvail().y:height))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("PID",ImGuiTableColumnFlags_WidthFixed,80);
        ImGui::TableSetupColumn("Parent",ImGuiTableColumnFlags_WidthFixed,90);
        ImGui::TableSetupColumn("Process",ImGuiTableColumnFlags_WidthStretch,1.6f);
        ImGui::TableSetupColumn("Executable path",ImGuiTableColumnFlags_WidthStretch,3.5f);
        ImGui::TableSetupColumn("Security assessment",ImGuiTableColumnFlags_WidthStretch,3.5f);
        ImGui::TableSetupColumn("Details",ImGuiTableColumnFlags_WidthFixed,150.f);
        ImGui::TableHeadersRow();
        std::lock_guard<std::mutex> lock(dataMutex);
        for(const auto& p:processes) {
            if(processViewFilter==1 && !p.suspicious)continue;
            if(processViewFilter==2)continue; // No verified process-level detections in this model.
            if(processViewFilter==3 && p.suspicious)continue;
            if(!showUnavailable&&(!p.path.empty() && p.path[0]==L'['))continue;
            const std::string name=utf8(p.name),path=utf8(p.path);
            std::string combined=name+" "+path+" "+p.assessment,q=searchInput;
            std::transform(combined.begin(),combined.end(),combined.begin(),
                [](unsigned char c){return (char)std::tolower(c);});
            std::transform(q.begin(),q.end(),q.begin(),
                [](unsigned char c){return (char)std::tolower(c);});
            if(combined.find(q)==std::string::npos)continue;
            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
            if(p.suspicious && highlightSuspicious)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(97,97,97,180));
            ImGui::TableSetColumnIndex(0);ImGui::Text("%lu",(unsigned long)p.pid);
            ImGui::TableSetColumnIndex(1);ImGui::Text("%lu",(unsigned long)p.parent);
            ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(name.c_str());
            ImGui::TableSetColumnIndex(3);ImGui::TextUnformatted(path.c_str());
            ImGui::TableSetColumnIndex(4);
            if(p.suspicious && highlightSuspicious)
                ImGui::TextColored(ImVec4(0.777f,0.777f,0.777f,1.f),"%s",p.assessment.c_str());
            else
                ImGui::TextDisabled("%s",p.assessment.c_str());
            ImGui::TableSetColumnIndex(5);
            ImGui::PushID((int)p.pid);
            if(ImGui::Button("Show Details",ImVec2(130,32)))selectProcessDetails(p);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if(processViewFilter==2)
        ImGui::TextDisabled("No confirmed process detections are available in this view. "
                            "Defender event detections are separate evidence.");
}

// Selection-based evidence details: no access to external network or modification of the system.
static bool evidenceDetailsOpen=false;
static std::string evidenceTitle,evidenceCategory,evidenceDescription,evidenceAssessment;
static std::wstring evidenceFile;
static std::string evidenceHash,evidenceSignature;
static void openEvidenceDetails(const std::string& category,const std::string& title,
                                const std::string& description,const std::wstring& file=L"",
                                const std::string& assessment="") {
    evidenceCategory=category; evidenceTitle=title; evidenceDescription=description;
    evidenceAssessment=assessment; evidenceFile=file;
    evidenceHash.clear(); evidenceSignature.clear(); evidenceDetailsOpen=true;
}

static std::string csvEscapeEvidence(const std::string& value){
    std::string out="\"";
    for(char c:value){
        if(c=='"')out+="\"\"";
        else if(c=='\r'||c=='\n')out+=' ';
        else out+=c;
    }
    return out+"\"";
}
static bool exportEvidenceCsv(const std::vector<Record>& rows,std::string& message){
    wchar_t module[MAX_PATH]={};
    if(!GetModuleFileNameW(nullptr,module,MAX_PATH)){
        message="Unable to locate the application folder.";return false;
    }
    std::error_code ec;
    const fs::path output=fs::path(module).parent_path()/L"SyncPCChecker-evidence.csv";
    std::ofstream file(output,std::ios::binary|std::ios::trunc);
    if(!file){message="Cannot write CSV in the application folder.";return false;}
    file<<"\xEF\xBB\xBF"<<"Category,Name,Status,Details\r\n";
    for(const auto& r:rows){
        const std::string status=
            r.detail.find("DETECTED")!=std::string::npos?"Detected":
            (r.detail.find("NEEDS REVIEW")!=std::string::npos ||
             r.detail.find("REVIEW:")!=std::string::npos)?"Needs Review":"Information";
        file<<csvEscapeEvidence(r.category)<<","
            <<csvEscapeEvidence(r.name)<<","
            <<csvEscapeEvidence(status)<<","
            <<csvEscapeEvidence(r.detail)<<"\r\n";
    }
    file.flush();
    if(!file){message="Failed to write complete CSV.";return false;}
    message="Saved "+std::to_string(rows.size())+
        " rows to SyncPCChecker-evidence.csv beside the application.";
    return true;
}

// Privacy boundary: permit user-mode dump capture only for processes running
// under the same Windows account as this application.
static bool isSameAccountProcess(HANDLE target){
    HANDLE ownToken=nullptr,targetToken=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&ownToken))return false;
    if(!OpenProcessToken(target,TOKEN_QUERY,&targetToken)){
        CloseHandle(ownToken);return false;
    }
    DWORD ownSize=0,targetSize=0;
    GetTokenInformation(ownToken,TokenUser,nullptr,0,&ownSize);
    GetTokenInformation(targetToken,TokenUser,nullptr,0,&targetSize);
    std::vector<BYTE> own(ownSize),other(targetSize);
    const bool valid=ownSize>0&&targetSize>0 &&
        GetTokenInformation(ownToken,TokenUser,own.data(),ownSize,&ownSize) &&
        GetTokenInformation(targetToken,TokenUser,other.data(),targetSize,&targetSize);
    bool match=false;
    if(valid){
        auto* a=reinterpret_cast<TOKEN_USER*>(own.data());
        auto* b=reinterpret_cast<TOKEN_USER*>(other.data());
        match=EqualSid(a->User.Sid,b->User.Sid)!=FALSE;
    }
    CloseHandle(targetToken);CloseHandle(ownToken);
    return match;
}
static bool isSensitiveDumpTarget(const std::wstring& path){
    const std::wstring name=lowerPath(fs::path(path).filename().wstring());
    static const wchar_t* blocked[]={
        L"lsass.exe",L"winlogon.exe",L"csrss.exe",L"services.exe",
        L"smss.exe",L"securityhealthservice.exe",L"credentialuibroker.exe",
        L"svchost.exe",L"system",L"registry"
    };
    for(const wchar_t* item:blocked)if(name==item)return true;
    return false;
}
static void drawEvidenceDetails() {
    if(!evidenceDetailsOpen)return;
    ImGui::SetNextWindowSize(ImVec2(790,510),ImGuiCond_FirstUseEver);
    if(!ImGui::Begin("Evidence Details - Read Only",&evidenceDetailsOpen)) {
        ImGui::End();return;
    }
    ImGui::TextColored(orange(),"%s",evidenceCategory.c_str());
    ImGui::Separator();
    ImGui::TextWrapped("Item: %s",evidenceTitle.c_str());
    ImGui::Spacing();
    ImGui::TextWrapped("%s",evidenceDescription.c_str());
    if(ImGui::SmallButton("Copy Evidence")){
        const std::string text="Category: "+evidenceCategory+
            "\nItem: "+evidenceTitle+"\nEvidence: "+evidenceDescription+
            "\nAssessment: "+evidenceAssessment;
        ImGui::SetClipboardText(text.c_str());
    }
    if(!evidenceAssessment.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.587f,0.587f,0.587f,1.f),"Security assessment");
        ImGui::TextWrapped("%s",evidenceAssessment.c_str());
    }
    if(!evidenceFile.empty()) {
        ImGui::Separator();
        ImGui::TextWrapped("File: %s",utf8(evidenceFile).c_str());
        if(ImGui::Button("Verify SHA-256 and Authenticode")) {
            evidenceHash=sha256(evidenceFile);
            evidenceSignature=signatureStatus(evidenceFile);
        }
        if(!evidenceHash.empty())ImGui::TextWrapped("SHA-256: %s",evidenceHash.c_str());
        if(!evidenceSignature.empty())ImGui::TextWrapped("Signature: %s",evidenceSignature.c_str());
    }
    ImGui::Spacing();
    ImGui::TextDisabled("%s",XOR_STR("Evidence is observational; an indicator alone does not confirm a threat.").c_str());
    ImGui::End();
}
static void recordsTable() {
    if(ImGui::BeginTable("records",4,ImGuiTableFlags_BordersInnerH|ImGuiTableFlags_RowBg|
        ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-1))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("Category",ImGuiTableColumnFlags_WidthFixed,110);
        ImGui::TableSetupColumn("Name",ImGuiTableColumnFlags_WidthFixed,230);
        ImGui::TableSetupColumn("Summary",ImGuiTableColumnFlags_WidthStretch,3.f);
        ImGui::TableSetupColumn("Details",ImGuiTableColumnFlags_WidthFixed,120.f);
        ImGui::TableHeadersRow();
        std::lock_guard<std::mutex> lock(dataMutex);
        for(const auto& r:records) {
            ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
            tintEvidenceRow(r);
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(r.category.c_str());
            ImGui::TableSetColumnIndex(1);ImGui::Text("%s | %s",r.name.c_str(),evidenceLabel(r));
            ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(r.detail.c_str());
            ImGui::TableSetColumnIndex(3);ImGui::PushID(&r);
            if(ImGui::Button("Show Details",ImVec2(130,32)))openEvidenceDetails(r.category,r.name,r.detail);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

// Offline binary inspection: no network requests and no code execution.
// API key stays in RAM. Files are never uploaded. HTTP runs off the UI thread.

namespace binaryInspector {
struct Section {std::string name; uint32_t rva=0,raw=0,size=0,flags=0; double entropy=0;};
struct Report {
    std::wstring path;
    std::string status="Choose an executable, DLL or other file.";
    std::string sha256,format,architecture,compileTime,signature,coverage;
    uint64_t bytes=0;
    bool pe=false,packedHint=false;
    std::vector<Section> sections;
    std::vector<std::string> imports,strings,notes;
    std::vector<unsigned char> head;
};
static Report report;
static std::mutex guard;
static std::atomic<bool> busy{false};
static char selected[32768]{};
static char search[160]{};
static int tab=0;
static std::string lower(std::string a){
    std::transform(a.begin(),a.end(),a.begin(),[](unsigned char c){return (char)std::tolower(c);});
    return a;
}
static uint16_t u16(const std::vector<unsigned char>& b,size_t off){
    if(off>b.size()||b.size()-off<2)return 0;
    return uint16_t(b[off])|(uint16_t(b[off+1])<<8);
}
static uint32_t u32(const std::vector<unsigned char>& b,size_t off){
    if(off>b.size()||b.size()-off<4)return 0;
    return uint32_t(b[off])|(uint32_t(b[off+1])<<8)|
        (uint32_t(b[off+2])<<16)|(uint32_t(b[off+3])<<24);
}
static uint64_t u64(const std::vector<unsigned char>& b,size_t off){
    return uint64_t(u32(b,off))|(uint64_t(u32(b,off+4))<<32);
}
static std::string cstr(const std::vector<unsigned char>& b,size_t off,size_t limit=256){
    std::string out;
    if(off>=b.size())return out;
    for(size_t i=off;i<b.size()&&out.size()<limit;++i){
        if(b[i]==0)break;
        if(b[i]<32||b[i]>126)break;
        out.push_back((char)b[i]);
    }
    return out;
}
static double entropy(const std::vector<unsigned char>& b,size_t off,size_t n){
    if(off>=b.size())return 0;
    n=(std::min)(n,b.size()-off);
    if(!n)return 0;
    size_t freq[256]{};
    for(size_t i=0;i<n;++i)++freq[b[off+i]];
    double h=0;
    for(auto f:freq)if(f){double p=(double)f/n;h-=p*std::log2(p);}
    return h;
}
static Report analyze(const std::wstring& path){
    Report r;r.path=path;
    std::error_code ec;
    const auto sz=fs::file_size(path,ec);
    if(ec){r.status="Cannot read file metadata.";return r;}
    r.bytes=sz;
    r.signature=signatureStatus(path);
    // Bounded analysis for large installers. Read enough of the file to
    // inspect the PE headers, sections, imports, and representative strings
    // without allocating memory proportional to an arbitrary file size.
    // SHA-256 below still covers the entire original file.
    constexpr uint64_t maxAnalysisBytes=256ull*1024*1024;
    const size_t bytesToRead=static_cast<size_t>(
        (std::min)(static_cast<uint64_t>(sz),maxAnalysisBytes));
    std::ifstream f(fs::path(path),std::ios::binary);
    if(!f){r.status="Cannot open file (access denied or missing).";return r;}
    std::vector<unsigned char> b(bytesToRead);
    f.read(reinterpret_cast<char*>(b.data()),
           static_cast<std::streamsize>(bytesToRead));
    b.resize(static_cast<size_t>(f.gcount()));
    if(b.empty() && sz>0){
        r.status="Unable to read binary data.";
        return r;
    }
    r.coverage=static_cast<uint64_t>(sz)>maxAnalysisBytes?
        "Partial (first 256 MiB; full-file SHA-256)":"Full file";
    if(static_cast<uint64_t>(sz)>maxAnalysisBytes)
        r.notes.push_back(
            "Large file: PE data and strings are analyzed from the first "
            "256 MiB; SHA-256 covers the full file.");
    r.sha256=sha256(path);
    r.head.assign(b.begin(),b.begin()+(std::min)(b.size(),size_t(4096)));
    r.format="Unknown / data";
    if(b.size()>=2&&b[0]=='M'&&b[1]=='Z')r.format="DOS executable / possible PE";
    if(b.size()>=4&&b[0]==0x7f&&b[1]=='E'&&b[2]=='L'&&b[3]=='F')r.format="ELF executable";
    if(b.size()>=4&&b[0]=='P'&&b[1]=='K')r.format="ZIP archive";
    if(b.size()>=4&&b[0]=='%'&&b[1]=='P'&&b[2]=='D'&&b[3]=='F')r.format="PDF document";
    if(b.size()>=0x40&&b[0]=='M'&&b[1]=='Z'){
        size_t pe=u32(b,0x3c);
        if(pe<=b.size()&&b.size()-pe>=24&&u32(b,pe)==0x00004550){
            r.pe=true;r.format="Windows Portable Executable (PE)";
            const uint16_t machine=u16(b,pe+4);
            r.architecture=machine==0x8664?"x64":machine==0x14c?"x86":
                machine==0xaa64?"ARM64":"Other / unknown";
            const size_t count=(std::min)(size_t(u16(b,pe+6)),size_t(96));
            const size_t opt=pe+24;
            const size_t sectionStart=opt+u16(b,pe+20);
            const bool is64=u16(b,opt)==0x20b;
            const size_t dirs=opt+(is64?112:96);
            if(opt>b.size()||b.size()-opt<2)
                r.notes.push_back("Optional header is truncated.");
            auto rvaToOff=[&](uint32_t rva)->size_t{
                for(const auto& sec:r.sections)
                    if(rva>=sec.rva&&uint64_t(rva)-sec.rva<sec.size&&
                       uint64_t(sec.raw)+(uint64_t(rva)-sec.rva)<b.size())
                        return size_t(sec.raw)+(rva-sec.rva);
                return size_t(-1);
            };
            for(size_t i=0;i<count;++i){
                const size_t pos=sectionStart+i*40;
                if(pos>b.size()||b.size()-pos<40)break;
                Section sec;
                sec.name=cstr(b,pos,8);
                sec.rva=u32(b,pos+12);
                sec.size=u32(b,pos+16);
                sec.raw=u32(b,pos+20);
                sec.flags=u32(b,pos+36);
                sec.entropy=entropy(b,sec.raw,sec.size);
                if(sec.size>1024&&sec.entropy>7.45){
                    r.packedHint=true;
                    r.notes.push_back("High-entropy section "+sec.name+
                        " (may be compressed, packed or encrypted; not proof of malware).");
                }
                if((sec.flags&0x20000000)&&(sec.flags&0x80000000))
                    r.notes.push_back("Writable and executable section: "+sec.name);
                r.sections.push_back(sec);
            }
            if(dirs<=b.size()&&b.size()-dirs>=16){
                uint32_t importsRva=u32(b,dirs+8);
                size_t pos=rvaToOff(importsRva);
                for(size_t i=0;i<256&&pos<b.size()&&b.size()-pos>=20;i++,pos+=20){
                    uint32_t lookup=u32(b,pos),nameRva=u32(b,pos+12),iat=u32(b,pos+16);
                    if(!lookup&&!nameRva&&!iat)break;
                    std::string dll=cstr(b,rvaToOff(nameRva),180);
                    if(dll.empty())continue;
                    r.imports.push_back(dll);
                    uint32_t thunkRva=lookup?lookup:iat;
                    size_t thunk=rvaToOff(thunkRva);
                    for(size_t j=0;j<1000&&thunk<b.size()&&b.size()-thunk>=(is64?8:4);++j){
                        uint64_t entry=is64?u64(b,thunk):u32(b,thunk);
                        if(!entry)break;
                        thunk+=is64?8:4;
                        if(entry&(is64?0x8000000000000000ull:0x80000000ull))continue;
                        if(entry>UINT32_MAX)continue;
                        size_t nameOff=rvaToOff((uint32_t)entry);
                        if(nameOff==size_t(-1)||nameOff>b.size()||b.size()-nameOff<2)continue;
                        std::string func=cstr(b,nameOff+2,150);
                        if(!func.empty()&&r.imports.size()<6000)r.imports.push_back("    "+func);
                    }
                }
            }
        }
    }
    std::string current;
    for(unsigned char c:b){
        if(c>=32&&c<=126){
            if(current.size()<300)current.push_back((char)c);
        }else{
            if(current.size()>=5&&r.strings.size()<18000)r.strings.push_back(current);
            current.clear();
        }
    }
    if(current.size()>=5&&r.strings.size()<18000)r.strings.push_back(current);
    // Extract readable UTF-16LE strings as well as ASCII. Many Windows
    // executables store paths, commands and configuration text in UTF-16LE.
    // Require at least 7 characters and cap the output to avoid UI overload.
    for(size_t parity=0;parity<2&&r.strings.size()<18000;++parity){
        std::string wideRun;
        for(size_t pos=parity;pos+1<b.size();pos+=2){
            const unsigned char lo=b[pos],hi=b[pos+1];
            if(hi==0&&lo>=32&&lo<=126){
                if(wideRun.size()<300)wideRun.push_back((char)lo);
            }else{
                if(wideRun.size()>=5&&r.strings.size()<18000)
                    r.strings.push_back("[UTF-16LE] "+wideRun);
                wideRun.clear();
            }
        }
        if(wideRun.size()>=5&&r.strings.size()<18000)
            r.strings.push_back("[UTF-16LE] "+wideRun);
    }
    if(!r.pe)r.notes.push_back("PE-specific sections and imports are not available for this format.");
    r.notes.push_back("Static inspection only. Decompiled source code cannot be recovered reliably from compiled binaries.");
    r.status="Local analysis completed.";
    return r;
}
static void select(){
    wchar_t path[32768]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize=sizeof(ofn);
    ofn.hwndOwner=hwnd;
    ofn.lpstrFile=path;
    ofn.nMaxFile=32768;
    ofn.lpstrFilter=L"Executables and libraries\0*.exe;*.dll;*.sys;*.ocx\0All files\0*.*\0";
    ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
    if(GetOpenFileNameW(&ofn)){
        strncpy_s(selected,sizeof(selected),utf8(path).c_str(),_TRUNCATE);
    }
}
static std::string jsonQuote(const std::string& value){
    std::string out="\"";
    for(unsigned char c:value){
        switch(c){
            case '"':out+="\\\"";break;
            case '\\':out+="\\\\";break;
            case '\n':out+="\\n";break;
            case '\r':out+="\\r";break;
            case '\t':out+="\\t";break;
            default:
                if(c<32){
                    char escaped[8]{};
                    snprintf(escaped,sizeof(escaped),"\\u%04x",unsigned(c));
                    out+=escaped;
                }else out+=char(c);
        }
    }
    return out+"\"";
}
static bool exportReport(const Report& r,bool csv){
    if(r.path.empty())return false;
    wchar_t destination[32768]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize=sizeof(dialog);
    dialog.hwndOwner=hwnd;
    dialog.lpstrFile=destination;
    dialog.nMaxFile=32768;
    dialog.lpstrFilter=csv?
        L"CSV report\0*.csv\0All files\0*.*\0":
        L"JSON report\0*.json\0All files\0*.*\0";
    dialog.lpstrDefExt=csv?L"csv":L"json";
    dialog.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST;
    if(!GetSaveFileNameW(&dialog))return false;
    std::ofstream out(fs::path(destination),std::ios::binary);
    if(!out)return false;
    const std::string path=utf8(r.path);
    if(csv){
        auto row=[&](const std::string& k,const std::string& v){
            // Quoted CSV fields, with quotes escaped by doubling.
            auto quote=[](const std::string& x){
                std::string y="\"";
                for(char c:x){if(c=='"')y+="\"\"";else y+=c;}
                return y+"\"";
            };
            out<<quote(k)<<","<<quote(v)<<"\r\n";
        };
        row("File",path);row("Status",r.status);
        row("SHA-256",r.sha256);row("Signature",r.signature);
        row("Coverage",r.coverage);row("Format",r.format);
        row("Architecture",r.architecture);
        row("Size (bytes)",std::to_string(r.bytes));
        for(const auto& sec:r.sections)
            row("Section",sec.name+" (entropy "+std::to_string(sec.entropy)+")");
        for(const auto& imp:r.imports)row("Import",imp);
        for(const auto& note:r.notes)row("Note",note);
    }else{
        out<<"{\n";
        auto field=[&](const char* k,const std::string& v){
            out<<"  "<<jsonQuote(k)<<": "<<jsonQuote(v)<<",\n";
        };
        field("file",path);field("status",r.status);
        field("sha256",r.sha256);field("signature",r.signature);
        field("coverage",r.coverage);field("format",r.format);
        field("architecture",r.architecture);
        out<<"  \"size_bytes\": "<<r.bytes<<",\n";
        auto array=[&](const char* key,const std::vector<std::string>& items,
                       bool comma){
            out<<"  "<<jsonQuote(key)<<": [";
            for(size_t i=0;i<items.size();++i){
                if(i)out<<",";
                out<<"\n    "<<jsonQuote(items[i]);
            }
            if(!items.empty())out<<"\n  ";
            out<<"]"<<(comma?",":"")<<"\n";
        };
        std::vector<std::string> sectionNames;
        for(const auto& sec:r.sections)
            sectionNames.push_back(sec.name+" | entropy="+std::to_string(sec.entropy));
        array("sections",sectionNames,true);
        array("imports",r.imports,true);
        array("notes",r.notes,false);
        out<<"}\n";
    }
    return out.good();
}
static void draw(){
    ImGui::SetWindowFontScale(1.18f);
    ImGui::TextUnformatted(XOR_STR("Binary Intelligence Studio").c_str());
    ImGui::SetWindowFontScale(1.f);
    ImGui::TextDisabled("Offline PE analysis  |  DLL imports  |  Extracted strings  |  Hex viewer");
    ImGui::Dummy(ImVec2(0,14));
    ImGui::TextColored(ImVec4(0.764f,0.764f,0.764f,1),"SELECT A BINARY");
    ImGui::SetNextItemWidth(-300.f);
    ImGui::InputTextWithHint("##binaryPath","Select a Windows executable or DLL...",selected,sizeof(selected));
    ImGui::SameLine();
    if(ImGui::Button("Browse...",ImVec2(112,0)))select();
    ImGui::SameLine();
    ImGui::BeginDisabled(busy.load()||!selected[0]);
    if(ImGui::Button("ANALYZE FILE",ImVec2(155,0))){
        std::wstring path=wide(selected);
        busy=true;
        std::thread([path](){
            Report r=analyze(path);
            {std::lock_guard<std::mutex> lock(guard);report=std::move(r);}
            busy=false;
        }).detach();
    }
    ImGui::EndDisabled();
    if(busy.load())ImGui::TextColored(orange(),"Reading binary structure...");
    Report r;
    {std::lock_guard<std::mutex> lock(guard);r=report;}
    ImGui::TextDisabled("%s",r.status.c_str());
    ImGui::Dummy(ImVec2(0,10));
    if(r.path.empty())return;
    ImGui::Text("FORMAT  %s",r.format.c_str());
    ImGui::SameLine(0,22);
    ImGui::Text("ARCH  %s",r.architecture.empty()?"N/A":r.architecture.c_str());
    ImGui::SameLine(0,22);
    ImGui::Text("SIZE  %llu bytes",(unsigned long long)r.bytes);
    ImGui::TextWrapped("SHA-256  %s",r.sha256.c_str());
    ImGui::TextWrapped("SIGNATURE  %s",
        r.signature.empty()?"Not checked":r.signature.c_str());
    ImGui::TextWrapped("COVERAGE  %s",
        r.coverage.empty()?"Unknown":r.coverage.c_str());
    if(ImGui::Button("EXPORT JSON",ImVec2(130,30))){
        if(!exportReport(r,false))
            diagnosticLog("Binary Lab JSON export cancelled or failed.");
    }
    ImGui::SameLine();
    if(ImGui::Button("EXPORT CSV",ImVec2(130,30))){
        if(!exportReport(r,true))
            diagnosticLog("Binary Lab CSV export cancelled or failed.");
    }
    ImGui::TextDisabled("Sections: %zu   |   Imported entries: %zu   |   Strings: %zu",
        r.sections.size(),r.imports.size(),r.strings.size());
    if(r.packedHint)ImGui::TextColored(ImVec4(0.757f,0.757f,0.757f,1),"SUSPECT  /  High entropy detected; inspect sections.");
    ImGui::Dummy(ImVec2(0,12));
    const char* tabs[]={"OVERVIEW","PE SECTIONS","IMPORTS / DLLs","STRINGS","HEX VIEW"};
    for(int i=0;i<5;i++){
        ImGui::PushID(i);
        bool active=tab==i;
        if(active){
            ImGui::PushStyleColor(ImGuiCol_Button,ImVec4(0.310f,0.310f,0.310f,1.f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered,ImVec4(0.394f,0.394f,0.394f,1.f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,ImVec4(0.263f,0.263f,0.263f,1.f));
            ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(0.966f,0.966f,0.966f,1.f));
        }
        if(ImGui::Button(tabs[i],ImVec2(i==2?156.f:125.f,36)))tab=i;
        if(active)ImGui::PopStyleColor(4);
        ImGui::PopID();
        if(i<4)ImGui::SameLine(0,7);
    }
    ImGui::Separator();
    ImGui::BeginChild("##binaryView",ImVec2(0,0),ImGuiChildFlags_None);
    if(tab==0){
        ImGui::TextColored(ImVec4(0.764f,0.764f,0.764f,1),"STATIC ANALYSIS NOTES");
        for(const auto& n:r.notes){ImGui::Bullet();ImGui::SameLine();ImGui::TextWrapped("%s",n.c_str());}
        ImGui::Dummy(ImVec2(0,8));
        ImGui::TextDisabled("Analysis is read-only and does not execute the selected file.");
    }else if(tab==1){
        if(ImGui::BeginTable("##peSections",5,ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable)){
            ImGui::TableSetupColumn("Section");ImGui::TableSetupColumn("RVA");
            ImGui::TableSetupColumn("File offset");ImGui::TableSetupColumn("Raw bytes");
            ImGui::TableSetupColumn("Entropy");ImGui::TableHeadersRow();
            for(const auto& sec:r.sections){
                ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                if(sec.entropy>7.45&&sec.size>1024)ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(70,70,70,120));
                ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(sec.name.c_str());
                ImGui::TableSetColumnIndex(1);ImGui::Text("0x%08X",sec.rva);
                ImGui::TableSetColumnIndex(2);ImGui::Text("0x%08X",sec.raw);
                ImGui::TableSetColumnIndex(3);ImGui::Text("%u",sec.size);
                ImGui::TableSetColumnIndex(4);ImGui::Text("%.2f",sec.entropy);
            }
            ImGui::EndTable();
        }
    }else if(tab==2||tab==3){
        ImGui::SetNextItemWidth(360);
        ImGui::InputTextWithHint("##binaryFilter","Filter DLLs, APIs, strings...",search,sizeof(search));
        const auto& rows=tab==2?r.imports:r.strings;
        const std::string filter=lower(search);
        ImGui::TextDisabled("%zu entries collected",rows.size());
        ImGuiListClipper clipper;
        // Filtering uses a local index; avoids drawing thousands of rows each frame.
        std::vector<size_t> indices;
        for(size_t i=0;i<rows.size();++i)if(filter.empty()||lower(rows[i]).find(filter)!=std::string::npos)
            indices.push_back(i);
        clipper.Begin((int)indices.size());
        while(clipper.Step())for(int j=clipper.DisplayStart;j<clipper.DisplayEnd;++j)
            ImGui::TextUnformatted(rows[indices[j]].c_str());
    }else{
        ImGui::TextDisabled("First %zu bytes of the file (read-only).",r.head.size());
        for(size_t i=0;i<r.head.size();i+=16){
            char line[128]{};
            int n=std::snprintf(line,sizeof(line),"%08llX  ",(unsigned long long)i);
            for(size_t j=0;j<16;++j)
                n+=std::snprintf(line+n,sizeof(line)-n,j+i<r.head.size()?"%02X ":"   ",
                    j+i<r.head.size()?r.head[j+i]:0);
            n+=std::snprintf(line+n,sizeof(line)-n,"  |");
            for(size_t j=0;j<16&&i+j<r.head.size();++j){
                unsigned char c=r.head[i+j];
                n+=std::snprintf(line+n,sizeof(line)-n,"%c",c>=32&&c<=126?c:'.');
            }
            ImGui::TextUnformatted(line);
        }
    }
    ImGui::EndChild();
}
} // namespace binaryInspector


// Shared primary action button for dashboard, file verification and settings.
static bool accentButton(const char* label, ImVec2 size=ImVec2(0,0)) {
    ImGui::PushStyleColor(ImGuiCol_Button,ImVec4(0.355f,0.355f,0.355f,1.f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,ImVec4(0.443f,0.443f,0.443f,1.f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,ImVec4(0.278f,0.278f,0.278f,1.f));
    ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(1.000f,1.000f,1.000f,1.f));
    const bool pressed=ImGui::Button(label,size);
    ImGui::PopStyleColor(4);
    return pressed;
}
// Subtle ambient motes distributed across the full application viewport.
// Foreground draw calls do not consume input or modify scan data.
// Quiet monochrome rain: deterministic vertical streaks instead of glowing
// particles. Drawn behind widgets so text and controls remain legible.
static void drawAmbientMotes(const ImVec2& origin,const ImVec2& size) {
    if(size.x<300.f || size.y<200.f)return;
    const float t=static_cast<float>(ImGui::GetTime());
    ImDrawList* draw=ImGui::GetForegroundDrawList();
    draw->PushClipRect(origin,
        ImVec2(origin.x+size.x,origin.y+size.y),true);
    // Low-opacity rain stays subtle even when drawn over opaque panels.
    // Several speeds and lengths add depth without per-frame randomness.
    // Positions are stable across frames and wrap smoothly at the bottom.
    const int rainDrops=rainDensity==0?48:rainDensity==2?150:85;
    for(int i=0;i<rainDrops;++i){
        const float seed=static_cast<float>(i+1);
        const float xFrac=std::fmod(seed*.61803398875f,1.f);
        const float offset=std::fmod(seed*.41421356237f,1.f);
        const float speed=85.f+static_cast<float>(i%9)*21.f;
        const float length=13.f+static_cast<float>(i%7)*6.f;
        const float travel=size.y+length+40.f;
        const float rainTime=reducedMotion?0.f:t;
        const float y=origin.y-length-20.f+
            std::fmod(offset*travel+rainTime*speed,travel);
        const float x=origin.x+9.f+xFrac*(size.x-18.f);
        const int shade=130+(i%4)*20;
        const int alpha=15+(i%5)*5;
        draw->AddLine(ImVec2(x,y-length),ImVec2(x,y),
            IM_COL32(shade,shade,shade,alpha),i%11==0?1.3f:.75f);
        // Small bright leading tip, no circular halo.
        if(i%6==0)
            draw->AddLine(ImVec2(x,y-3.f),ImVec2(x,y),
                IM_COL32(223,223,223,35),1.f);
    }
    draw->PopClipRect();
}

// Premium progress visualization. Percentage remains tied to the existing
// 35-second presentation and completed scan stages; no synthetic detections.
// Render-only easing: smooths the fill without changing the verified unlock gate.
static float smoothInspectionVisual(float target){
    static float displayed=0.f;
    static double lastTime=-1.0;
    static double lastScanStart=-1.0;
    const double now=ImGui::GetTime();
    if(inspectionProgressStart!=lastScanStart){
        displayed=0.f;lastTime=now;lastScanStart=inspectionProgressStart;
    }
    if(inspectionProgressStart<=0.0 || (!scanning && !done)){
        displayed=0.f;lastTime=now;return displayed;
    }
    if(lastTime<0.0 || now<lastTime || now-lastTime>3.0)lastTime=now;
    const float dt=std::clamp(static_cast<float>(now-lastTime),0.f,.1f);
    lastTime=now;
    // Never decrease during a scan; ease to the next measured/paced target.
    target=std::clamp(target,0.f,1.f);
    if(target<displayed-.15f)displayed=0.f; // new scan reset
    const float rate=1.f-std::exp(-dt*1.25f);
    displayed+=(std::max)(0.f,target-displayed)*rate;
    if(target>=1.f && 1.f-displayed<.0005f)displayed=1.f;
    return displayed;
}
static void drawProfessionalProgressTrack(const char* id,const char* label,
                                           float fraction,float width,float height,
                                           bool compact=false){
    ImGui::PushID(id);
    const ImVec2 p=ImGui::GetCursorScreenPos();
    const ImVec2 q(p.x+width,p.y+height);
    ImDrawList* dl=ImGui::GetWindowDrawList();
    fraction=std::clamp(fraction,0.f,1.f);
    dl->AddRectFilled(p,q,IM_COL32(27,27,27,255),6.f);
    dl->AddRect(p,q,IM_COL32(82,82,82,190),6.f);
    if(fraction>0.f){
        const float w=width*fraction;
        dl->AddRectFilled(ImVec2(p.x+2.f,p.y+2.f),
            ImVec2((std::min)(q.x-2.f,p.x+(std::max)(2.f,w)),q.y-2.f),
            IM_COL32(215,215,215,255),4.f);
        if(w>14.f)
            dl->AddRectFilled(ImVec2(p.x+3.f,p.y+3.f),
                ImVec2((std::min)(q.x-3.f,p.x+w-3.f),p.y+4.f),
                IM_COL32(248,248,248,220),1.f);
    }
    if(compact){
        char pct[16]{};
        std::snprintf(pct,sizeof(pct),"%.0f%%",fraction*100.f);
        const ImVec2 sz=ImGui::CalcTextSize(pct);
        dl->AddText(ImVec2(p.x+width-sz.x-9.f,p.y+(height-sz.y)*.5f),
                    IM_COL32(250,250,250,255),pct);
    }
    ImGui::Dummy(ImVec2(width,height));
    ImGui::PopID();
}
static void drawAtlasProgress(bool compact=false){
    const int verified=inspectionDisplayPercent();
    const float fraction=smoothInspectionVisual(
        static_cast<float>(inspectionPresentationFraction()));
    const float width=(std::max)(150.f,ImGui::GetContentRegionAvail().x);
    ImGui::TextDisabled(localized("FULL INSPECTION  /  VERIFIED PROGRESS"));
    ImGui::SameLine();
    ImGui::Text("%d%% verified",verified);
    drawProfessionalProgressTrack("overall","Overall inspection",fraction,width,
                                  compact?14.f:19.f);
    if(compact)return;
    ImGui::Spacing();
    // Show exactly one active worker milestone; no fabricated stage timing.
    const char* phaseNames[]={
        "PROCESS INVENTORY","SERVICE INVENTORY","STARTUP ENTRIES",
        "NETWORK AND DEVICE INVENTORY","SECURITY AND FORENSIC ARTIFACTS",
        "PUBLISHING RESULTS"
    };
    const char* phaseNamesPt[]={
        "INVENTÁRIO DE PROCESSOS","INVENTÁRIO DE SERVIÇOS","INICIALIZAÇÃO",
        "REDE E DISPOSITIVOS","SEGURANÇA E ARTEFATOS FORENSES",
        "PUBLICAÇÃO DOS RESULTADOS"
    };
    constexpr int phaseCount=6;
    const int completed=std::clamp(completedStages.load(),0,6);
    const int activeIndex=std::clamp(completed,0,5);
    const char* activeName=displayLanguage==1?
        phaseNamesPt[activeIndex]:phaseNames[activeIndex];
    ImGui::TextDisabled("%s",displayLanguage==1?"ETAPA ATUAL":"CURRENT STAGE");
    ImGui::SameLine();
    ImGui::TextDisabled("%02d / %02d",activeIndex+1,phaseCount);
    ImGui::TextUnformatted(done?
        (displayLanguage==1?"TODAS AS ETAPAS CONCLUÍDAS":"ALL STAGES COMPLETE"):activeName);
    // A stage reaches 100% only when its worker milestone is completed.
    // Use indeterminate activity rather than inventing a percentage within it.
    if(!done && scanning){
        const unsigned total=sequentialTotal.load();
        const unsigned checked=sequentialDone.load();
        const float t=static_cast<float>(ImGui::GetTime());
        const float pulse=0.12f+0.08f*(std::sin(t*2.2f)+1.f);
        const float progress=total?std::clamp(checked/static_cast<float>(total),0.f,1.f):pulse;
        drawProfessionalProgressTrack("active-stage",activeName,progress,width,11.f);
        if(total)ImGui::TextDisabled("%u / %u %s",checked,total,
            displayLanguage==1?"itens verificados":"items checked");
        else ImGui::TextDisabled("%s",displayLanguage==1?
            "Aguardando contagem da etapa":"Waiting for stage item count");
        const std::string current=getSequentialItem();
        if(!current.empty())ImGui::TextWrapped("%s: %s",
            displayLanguage==1?"Verificando agora":"Checking now",current.c_str());
    }else if(!done){
        drawProfessionalProgressTrack("active-stage",activeName,0.f,width,11.f);
    }
    ImGui::Spacing();
    const char* phase=scanFailed?"INSPECTION FAILED":
        scanCancelled?"INSPECTION CANCELLED":
        done?(verified>=100?"INSPECTION COMPLETE":"FINALIZING INSPECTION"):
        scanning?(cancelRequested?"CANCELLING INSPECTION":
            stages[std::clamp(stage.load(),0,5)]):"READY";
    ImGui::TextDisabled("%s",localized(phase));
    if(ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        ImGui::SetTooltip("Progress reflects completed worker milestones. Active stages do not report fabricated percentages.");
}

static bool simplifiedInterface=true;
static void renderUI() {
    if(defenderNotificationPending.exchange(false))
        ImGui::OpenPopup("Windows Defender detection alert");
    if(ImGui::BeginPopupModal("Windows Defender detection alert",nullptr,
        ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextColored(ImVec4(0.481f,0.481f,0.481f,1.f),"WINDOWS DEFENDER SECURITY EVENT");
        ImGui::Separator();
        ImGui::TextWrapped("%d recent Defender detection or failed-remediation events were found.",
            defenderAlerts.load());
        ImGui::TextWrapped("These are historical event records, not proof of an active infection.");
        ImGui::TextWrapped("Open Windows Security > Virus & threat protection > Protection history for current status.");
        if(ImGui::Button("View scan results",ImVec2(180,36))) {
            page=2;ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if(ImGui::Button("Dismiss",ImVec2(110,36)))ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    ImGuiViewport* vp=ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##application",nullptr,ImGuiWindowFlags_NoDecoration|
        ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoSavedSettings|
        ImGuiWindowFlags_NoBringToFrontOnFocus);
    // ATLAS: entirely different shell, no left rail, full-width operations canvas.
    if(page==1||page==5)page=0;
    const ImVec4 titleInk(.97f,.97f,.97f,1);
    const ImVec4 subtleInk(.60f,.60f,.60f,1);
    const ImVec4 accentInk(.84f,.84f,.84f,1);
    ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.039f,0.039f,0.039f,1));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,ImVec2(25,13));
    ImGui::BeginChild("##atlasHeader",ImVec2(0,72),ImGuiChildFlags_None);
    // Quiet brand animation: a restrained breathing frame around the original
    // logo and a short traveling highlight under the wordmark. Draw-only,
    // non-interactive, and independent of scan findings.
    const float brandTime=static_cast<float>(ImGui::GetTime());
    if(syncLogoTexture){
        ImGui::Image((ImTextureID)syncLogoTexture,ImVec2(44,44));
        const ImVec2 lo=ImGui::GetItemRectMin();
        const ImVec2 hi=ImGui::GetItemRectMax();
        ImDrawList* brandDraw=ImGui::GetWindowDrawList();
        const float breathe=brandAnimation?(.5f+.5f*std::sin(brandTime*1.35f)):.45f;
        const int borderAlpha=static_cast<int>(36.f+51.f*breathe);
        brandDraw->AddRect(ImVec2(lo.x-5.f,lo.y-5.f),
                           ImVec2(hi.x+5.f,hi.y+5.f),
                           IM_COL32(155,155,155,borderAlpha),5.f,0,1.f);
        // Two tiny moving corner accents, rather than a distracting radar glow.
        const float edge=brandAnimation?(8.f+24.f*(.5f+.5f*std::sin(brandTime*.65f))):16.f;
        if(brandAnimation)brandDraw->AddLine(ImVec2(lo.x-5.f,lo.y+edge),
                           ImVec2(lo.x-5.f,lo.y+edge+7.f),
                           IM_COL32(187,187,187,115),1.5f);
        if(brandAnimation)brandDraw->AddLine(ImVec2(hi.x+5.f,hi.y-edge),
                           ImVec2(hi.x+5.f,hi.y-edge-7.f),
                           IM_COL32(187,187,187,115),1.5f);
        ImGui::SameLine(0,15);
    }
    ImGui::BeginGroup();
    ImGui::SetWindowFontScale(1.08f);
    ImGui::TextColored(titleInk,"SYNC PC CHECKER");
    const ImVec2 wordmarkLeft=ImGui::GetItemRectMin();
    const ImVec2 wordmarkRight=ImGui::GetItemRectMax();
    ImGui::SetWindowFontScale(1.f);
    ImGui::TextColored(subtleInk,"DEVELOPED BY MUDIN");
    ImGui::EndGroup();
    {
        ImDrawList* brandDraw=ImGui::GetWindowDrawList();
        const float x1=wordmarkLeft.x;
        const float x2=wordmarkRight.x;
        const float y=wordmarkRight.y+3.f;
        const float width=x2-x1;
        brandDraw->AddLine(ImVec2(x1,y),ImVec2(x2,y),
                           IM_COL32(101,101,101,55),1.f);
        // Soft, slow light travel across the thin rule; text never flashes.
        const float phase=std::fmod(brandTime*24.f,width+40.f)-20.f;
        const float start=(std::max)(x1,x1+phase);
        const float end=(std::min)(x2,x1+phase+31.f);
        if(brandAnimation && end>start){
            brandDraw->AddLine(ImVec2(start,y),ImVec2(end,y),
                               IM_COL32(177,177,177,155),1.5f);
        }
    }
    ImGui::SameLine(0,30);
    ImGui::TextColored(accentInk,"ENDPOINT ANALYSIS");
    // Presentation progress remains visible while completed results await unlocking.
    if(inspectionProgressStart>0.0 && inspectionDisplayPercent()<100 && (scanning || done)){
        const ImVec2 wp=ImGui::GetWindowPos();
        const ImVec2 ws=ImGui::GetWindowSize();
        const float fraction=inspectionDisplayPercent()/100.f;
        ImGui::GetWindowDrawList()->AddRectFilled(
            ImVec2(wp.x,wp.y+ws.y-2.f),
            ImVec2(wp.x+ws.x*fraction,wp.y+ws.y),
            IM_COL32(150,150,150,220));
    }
    float right=ImGui::GetWindowContentRegionMax().x;
    ImGui::SetCursorPos(ImVec2(right-107.f,8.f));
    if(ImGui::Button("_##atlasMin",ImVec2(43,36)))ShowWindow(hwnd,SW_MINIMIZE);
    ImGui::SameLine(0,7);
    if(ImGui::Button("X##atlasExit",ImVec2(43,36)))PostMessageW(hwnd,WM_CLOSE,0,0);
    ImGui::EndChild();
    // Global alert appears on every main page after a completed scan.
    if(bypassCorrelatedAlert.load() && !scanning.load()){
        ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(.29f,.055f,.065f,1.f));
        ImGui::PushStyleColor(ImGuiCol_Border,ImVec4(.92f,.20f,.23f,1.f));
        ImGui::BeginChild("##globalBypassAlert",ImVec2(0,66),ImGuiChildFlags_Borders);
        ImGui::TextColored(ImVec4(1.f,.30f,.32f,1.f),"BYPASS DETECTED");
        ImGui::SameLine();
        ImGui::TextDisabled("Correlated indicators - review required, not proof of evasion.");
        if(ImGui::Button("View evidence##bypassGlobal"))page=9;
        ImGui::EndChild();
        ImGui::PopStyleColor(2);
    }

    ImGui::PopStyleVar();
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.030f,0.030f,0.030f,1));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,ImVec2(25,8));
    const float navAvailableWidth=ImGui::GetContentRegionAvail().x-50.f;
    const int navColumns=navAvailableWidth<430.f?1:navAvailableWidth<700.f?2:3;
    const int navRows=simplifiedInterface?1:(9+navColumns-1)/navColumns;
    const float navRowHeight=46.f;
    ImGui::BeginChild("##atlasNav",ImVec2(0,navRows*navRowHeight+16.f),ImGuiChildFlags_None,
        ImGuiWindowFlags_NoScrollbar|ImGuiWindowFlags_NoScrollWithMouse);
    // Persistent UI-only transition state; scan and evidence data are unaffected.
    static int lastNavPage=-1;
    static float navTransitionStart=0.f;
    const float uiNow=(float)ImGui::GetTime();
    const bool pageChanged=lastNavPage!=-1 && lastNavPage!=page;
    if(pageChanged)navTransitionStart=reducedMotion?-100.f:uiNow;
    lastNavPage=page;
    const char* nav[]={"DASHBOARD","THREAT ANALYSIS","EVENT RECORDS",
                       "BINARY LAB","NETWORK","DRIVER AUDIT","ARTIFACT EXPLORER","KERNEL MEMORY DUMP","PREFERENCES"};
    const int navPages[]={0,2,3,6,7,8,9,10,4};
    // Quick page navigation, ignored while editing text or using shortcuts.
    // Ctrl+1..9 follows the visible tab order.
    if(!ImGui::GetIO().WantTextInput && ImGui::GetIO().KeyCtrl &&
       !ImGui::GetIO().KeyAlt && !ImGui::GetIO().KeyShift){
        for(int shortcut=0;shortcut<9;shortcut++){
            if(ImGui::IsKeyPressed(static_cast<ImGuiKey>(ImGuiKey_1+shortcut),false)){
                page=navPages[shortcut];
                navTransitionStart=uiNow;
                lastNavPage=page;
            }
        }
    }
    // Simplified mode keeps only four primary destinations visible.
    // Advanced mode preserves the complete original navigation.
    const int simpleNavIndices[]={0,1,6,8};
    const int visibleNavCount=simplifiedInterface?4:9;
    const float navGap=10.f;
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,7.f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,ImVec2(12.f,9.f));
    const float navWidth=(std::max)(85.f,
        (ImGui::GetContentRegionAvail().x-
         ((simplifiedInterface?4:navColumns)-1)*navGap)/
         (simplifiedInterface?4:navColumns));
    for(int visible=0;visible<visibleNavCount;visible++){
        const int i=simplifiedInterface?simpleNavIndices[visible]:visible;
        ImGui::PushID(9100+i);
        const bool active=page==navPages[i];
        if(active){
            ImGui::PushStyleColor(ImGuiCol_Button,ImVec4(0.261f,0.261f,0.261f,1));
            ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(0.947f,0.947f,0.947f,1));
            ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize,1.f);
            ImGui::PushStyleColor(ImGuiCol_Border,ImVec4(0.590f,0.590f,0.590f,1));
        }
        const bool hoveredBefore=ImGui::IsMousePosValid() &&
            ImGui::IsMouseHoveringRect(ImGui::GetCursorScreenPos(),
                ImVec2(ImGui::GetCursorScreenPos().x+navWidth,
                       ImGui::GetCursorScreenPos().y+39.f),false);
        if(!active){
            ImGui::PushStyleColor(ImGuiCol_Button,
                hoveredBefore?ImVec4(0.149f,0.149f,0.149f,1.f):
                              ImVec4(0.078f,0.078f,0.078f,1.f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
                ImVec4(0.197f,0.197f,0.197f,1.f));
            ImGui::PushStyleColor(ImGuiCol_Border,
                ImVec4(0.214f,0.214f,0.214f,1.f));
            ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize,1.f);
        }
        if(ImGui::Button((std::string(localized(nav[i]))+"##nav"+std::to_string(i)).c_str(),ImVec2(navWidth,39))){
            if(page!=navPages[i]){
                page=navPages[i];
                navTransitionStart=uiNow;
                lastNavPage=page;
            }
        }
        if(ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)){
            ImGui::BeginTooltip();
            ImGui::Text("%s",localized(nav[i]));
            ImGui::TextDisabled("Ctrl + %d",i+1);
            ImGui::EndTooltip();
        }
        const ImVec2 tabMin=ImGui::GetItemRectMin();
        const ImVec2 tabMax=ImGui::GetItemRectMax();
        if(active){
            // A solid edge marker, not the disliked bottom underline.
            ImGui::GetWindowDrawList()->AddRectFilled(
                ImVec2(tabMin.x+1.f,tabMin.y+9.f),
                ImVec2(tabMin.x+3.f,tabMax.y-9.f),
                IM_COL32(186,186,186,230),1.f);
        } else if(showNavHover && ImGui::IsItemHovered()){
            ImGui::GetWindowDrawList()->AddRect(
                ImVec2(tabMin.x+.5f,tabMin.y+.5f),
                ImVec2(tabMax.x-.5f,tabMax.y-.5f),
                IM_COL32(149,149,149,115),7.f,0,1.f);
        }
        ImGui::PopStyleColor(3);
        ImGui::PopStyleVar();
        ImGui::PopID();
        if(simplifiedInterface){
            if(visible!=visibleNavCount-1)ImGui::SameLine(0,navGap);
        }else if(i%navColumns!=navColumns-1 && i!=8){
            ImGui::SameLine(0,navGap);
        }
    }
    ImGui::PopStyleVar(2);
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.019f,0.019f,0.019f,1));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,ImVec2(18,10));
    ImGui::BeginChild("##atlasMain",ImVec2(0,0),ImGuiChildFlags_None);
    // Professional workstation backdrop: restrained tonal separation.
    // No moving rings, artificial radar sweeps or fabricated activity.
    {
        const ImVec2 origin=ImGui::GetWindowPos();
        const ImVec2 extent=ImGui::GetWindowSize();
        ImDrawList* dl=ImGui::GetWindowDrawList();
        dl->PushClipRect(origin,ImVec2(origin.x+extent.x,origin.y+extent.y),true);
        dl->AddRectFilledMultiColor(
            origin,ImVec2(origin.x+extent.x,origin.y+210.f),
            IM_COL32(26,26,26,255),IM_COL32(21,21,21,255),
            IM_COL32(14,14,14,255),IM_COL32(17,17,17,255));
        dl->AddLine(ImVec2(origin.x+28.f,origin.y+207.f),
                    ImVec2(origin.x+extent.x-28.f,origin.y+207.f),
                    IM_COL32(100,100,100,33),1.f);
        dl->PopClipRect();
    }
    const char* section=page==0?"OPERATIONS":page==2?"THREAT INVESTIGATION":
        page==3?"SECURITY ACTIVITY":page==6?"BINARY INTELLIGENCE":
        page==7?"NETWORK CONNECTIONS":page==8?"DRIVER AUDIT":
        page==9?"ARTIFACT EXPLORER":page==10?"KERNEL MEMORY DUMP":"PREFERENCES";
    // A short title entrance signals navigation without obscuring the tables.
    const float elapsed=uiNow-navTransitionStart;
    const float entrance=(std::max)(0.f,1.f-(std::max)(0.f,elapsed)/.30f);
    const float titleAlpha=1.f-.42f*entrance;
    const float titleOffset=10.f*entrance;
    ImGui::SetCursorPosX(ImGui::GetCursorPosX()+titleOffset);
    ImGui::TextColored(ImVec4(accentInk.x,accentInk.y,accentInk.z,titleAlpha),
                       "SYNC / %s",section);
    if(ImGui::GetContentRegionAvail().x>195.f)ImGui::SameLine(0,24);
    ImGui::TextColored(subtleInk,"ENGINE: %s",stateText());
    if(ImGui::GetContentRegionAvail().x>190.f)ImGui::SameLine(0,16);
    if(ImGui::SmallButton(simplifiedInterface?"Advanced view":"Simple view"))
        simplifiedInterface=!simplifiedInterface;
    if(ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        ImGui::SetTooltip("Use Ctrl + 1 through Ctrl + 9 to switch pages.");
    {
        const ImVec2 lineStart=ImGui::GetCursorScreenPos();
        const float lineWidth=ImGui::GetContentRegionAvail().x;
        ImDrawList* dl=ImGui::GetWindowDrawList();
        const float lineY=lineStart.y+12.f;
        dl->AddLine(ImVec2(lineStart.x,lineY),
                    ImVec2(lineStart.x+lineWidth,lineY),
                    IM_COL32(81,81,81,105),1.f);
        dl->AddRectFilled(ImVec2(lineStart.x,lineY-1.f),
                          ImVec2(lineStart.x+44.f,lineY+1.f),
                          IM_COL32(158,158,158,190),1.f);
        ImGui::Dummy(ImVec2(0,12.f));
    }
    // Only Dashboard shows progress; remove the bar once it reaches 100%.
    // Investigation pages show the lock from launch until scan completion and 100%.
    if(page==0 && (scanning || done) && inspectionDisplayPercent()<100){
        drawAtlasProgress(false);
        ImGui::Spacing();
    }
    float available=ImGui::GetContentRegionAvail().x;
    // All non-dashboard pages are locked until the scan AND its presentation
    // reach 100%. This is a visual privacy curtain, not a fake scan result.
    const bool waitingForPresentation=
        !done || scanFailed || scanCancelled || inspectionProgressStart<=0.0 || inspectionDisplayPercent()<100;
    // Dashboard and Preferences remain accessible; investigation pages unlock at 100%.
    // Once progress reaches 100%, animate the shackle opening before
    // revealing scan-derived content. Reset on each new inspection.
    static bool wasWaitingForUnlock=false;
    static double unlockAnimationStart=-1.0;
    if(waitingForPresentation){
        wasWaitingForUnlock=true;
        unlockAnimationStart=-1.0;
    }else if(wasWaitingForUnlock){
        unlockAnimationStart=ImGui::GetTime();
        wasWaitingForUnlock=false;
    }
    const double unlockElapsed=unlockAnimationStart>=0.0 ?
        ImGui::GetTime()-unlockAnimationStart : 100.0;
    const bool unlocking=!waitingForPresentation &&
        unlockElapsed<1.65;
    if((waitingForPresentation || (unlocking && !reducedMotion)) &&
       page!=0 && page!=4) {
        const float opening=unlocking?
            std::clamp(static_cast<float>(unlockElapsed/1.25),0.f,1.f):0.f;
        const float eased=opening*opening*(3.f-2.f*opening);
        const float fade=unlocking?
            1.f-std::clamp((opening-.72f)/.28f,0.f,1.f):1.f;
        const auto fadeAlpha=[&](int alpha){
            return static_cast<int>(alpha*fade);
        };
        const ImVec2 area=ImGui::GetCursorScreenPos();
        const ImVec2 avail=ImGui::GetContentRegionAvail();
        const float w=(std::max)(300.f,avail.x);
        const float h=(std::max)(290.f,avail.y);
        ImDrawList* curtain=ImGui::GetWindowDrawList();
        // Frosted-glass approximation: layered translucent panels and
        // diffuse highlights. No unimplemented GPU blur is claimed.
        curtain->AddRectFilled(area,ImVec2(area.x+w,area.y+h),
            IM_COL32(17,17,17,fadeAlpha(247)),14.f);
        curtain->AddRectFilledMultiColor(
            ImVec2(area.x+12,area.y+12),ImVec2(area.x+w-12,area.y+h-12),
            IM_COL32(64,64,64,fadeAlpha(85)),IM_COL32(41,41,41,fadeAlpha(65)),
            IM_COL32(24,24,24,fadeAlpha(95)),IM_COL32(44,44,44,fadeAlpha(80)));
        for(int ring=9;ring>=1;--ring){
            const float r=95.f+ring*13.f;
            curtain->AddCircleFilled(
                ImVec2(area.x+w*.5f,area.y+h*.39f),r,
                IM_COL32(120,120,120,fadeAlpha(2)),48);
        }
        curtain->AddRect(area,ImVec2(area.x+w,area.y+h),
            IM_COL32(110,110,110,fadeAlpha(130)),14.f,0,1.2f);
        // Lock silhouette rendered directly with ImDrawList.
        const ImVec2 center(area.x+w*.5f,area.y+h*.39f);
        curtain->AddCircleFilled(center,54.f,IM_COL32(49,49,49,fadeAlpha(220)),48);
        curtain->AddCircle(center,54.f,IM_COL32(143,143,143,fadeAlpha(160)),48,1.6f);
        curtain->PathClear();
        // The shackle rotates and rises as the scan unlocks.
        const ImVec2 shackleCenter(center.x-9.f*eased,
                                   center.y-9.f-13.f*eased);
        curtain->PathArcTo(shackleCenter,19.f,
            3.14159265f-0.62f*eased,
            6.2831853f-0.62f*eased,24);
        curtain->PathStroke(IM_COL32(223,223,223,fadeAlpha(255)),0,5.f);
        curtain->AddRectFilled(
            ImVec2(center.x-26.f,center.y-13.f),
            ImVec2(center.x+26.f,center.y+26.f),
            IM_COL32(165,165,165,fadeAlpha(255)),7.f);
        curtain->AddCircleFilled(
            ImVec2(center.x,center.y+3.f),4.5f,IM_COL32(29,29,29,fadeAlpha(255)),16);
        curtain->AddRectFilled(
            ImVec2(center.x-2.f,center.y+3.f),
            ImVec2(center.x+2.f,center.y+14.f),
            IM_COL32(29,29,29,fadeAlpha(255)),2.f);
        ImGui::SetCursorScreenPos(ImVec2(area.x,center.y+76.f));
        ImGui::PushTextWrapPos(area.x+w-24.f);
        ImGui::SetWindowFontScale(1.10f);
        const char* heading=unlocking?"INSPECTION UNLOCKED":"INSPECTION LOCKED";
        ImGui::SetCursorPosX(ImGui::GetCursorPosX()+
            (w-ImGui::CalcTextSize(heading).x)*.5f);
        ImGui::TextColored(ImVec4(0.950f,0.950f,0.950f,1.f),"%s",heading);
        ImGui::SetWindowFontScale(1.f);
        ImGui::Dummy(ImVec2(0,9.f));
        const char* detail=unlocking?
            "Access granted. Opening inspection results...":
            inspectionProgressStart<=0.0 ?
                "Run a full inspection to unlock this section." :
                scanFailed ? "Inspection failed. Start a new scan to unlock." :
                scanCancelled ? "Inspection cancelled. Start a new scan to unlock." :
                "Results unlock after inspection completes at 100%.";
        ImGui::SetCursorPosX(ImGui::GetCursorPosX()+
            (w-ImGui::CalcTextSize(detail).x)*.5f);
        ImGui::TextColored(ImVec4(0.716f,0.716f,0.716f,1.f),"%s",detail);
        ImGui::PopTextWrapPos();
        ImGui::Dummy(ImVec2(0,22.f));
        const float buttonWidth=245.f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX()+
            (w-buttonWidth)*.5f);
        ImGui::PushStyleColor(ImGuiCol_Button,ImVec4(0.327f,0.327f,0.327f,1.f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered,ImVec4(0.430f,0.430f,0.430f,1.f));
        if(waitingForPresentation){
            if(ImGui::Button(localized("GO TO DASHBOARD"),ImVec2(buttonWidth,45.f)))
                page=0;
        }else{
            ImGui::BeginDisabled();
            ImGui::Button("UNLOCKING...",ImVec2(buttonWidth,45.f));
            ImGui::EndDisabled();
        }
        ImGui::PopStyleColor(2);
        ImGui::Dummy(ImVec2(0,1.f));
    } else if(page==0 && simplifiedInterface) {
        const ImVec4 muted(.67f,.67f,.67f,1.f);
        ImGui::SetWindowFontScale(1.12f);
        ImGui::TextUnformatted("PC Inspection");
        ImGui::SetWindowFontScale(1.f);
        ImGui::TextColored(muted,"One scan. Clear results. Advanced tools remain available.");
        ImGui::Dummy(ImVec2(0,16));
        if(scanning){
            ImGui::TextUnformatted(presentationHold.load()?
                "Scan finished - preparing results":"Scanning your PC...");
            if(presentationHold.load()){
                ImGui::TextDisabled("Display wait: %u seconds (not extra analysis)",
                    presentationWaitRemaining.load());
            }
            if(ImGui::Button("Cancel scan",ImVec2(170,44)))
                cancelRequested=true;
        }else if(done && !scanFailed && !scanCancelled){
            ImGui::TextColored(ImVec4(.45f,.85f,.56f,1.f),
                "VERIFIED  -  SCAN COMPLETED");
            ImGui::SameLine();
            if(ImGui::Button("View results",ImVec2(150,42)))page=9;
        }else{
            if(accentButton("START FULL SCAN",ImVec2(230,48)))startScan();
            ImGui::SameLine();
            if(ImGui::Button("View results",ImVec2(150,48)))page=9;
        }
        ImGui::Dummy(ImVec2(0,15));
        ImGui::Separator();
        ImGui::Text("Processes: %zu",processCount.load());
        ImGui::Text("Evidence records: %zu",recordCount.load());
        ImGui::Text("Files checked: %zu",fileCount.load());
        ImGui::Text("Status: %s",stateText());
        if(scanFailed){
            ImGui::Separator();
            ImGui::TextColored(ImVec4(1.f,.37f,.37f,1.f),
                "Scan failed at stage %d",scanFailureStage.load());
            std::string failure;
            {
                std::lock_guard<std::mutex> guard(scanFailureMutex);
                failure=scanFailureReason;
            }
            if(!failure.empty())ImGui::TextWrapped("%s",failure.c_str());
            ImGui::TextDisabled("Details: %%TEMP%%\\SyncPCChecker\\diagnostic.log");
        }
        ImGui::Dummy(ImVec2(0,18));
        ImGui::TextColored(muted,"Need more detail? Select Advanced view above.");
    } else if(page==0) {
        // Rebuilt command center; no legacy metric() tiles.
        const ImVec4 pale(.96f,.96f,.96f,1),quiet(.62f,.62f,.62f,1),accent(.78f,.78f,.78f,1);
        const float full=ImGui::GetContentRegionAvail().x;
        const bool side=full>=790.f;
        const float rightWidth=side?270.f:0.f;
        const float heroWidth=side?full-rightWidth-12.f:full;
        ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.073f,0.073f,0.073f,1));
        ImGui::BeginChild("##heroCommand",ImVec2(heroWidth,233),ImGuiChildFlags_Borders);
        ImGui::TextColored(accent,"SECURITY OPERATIONS / ENDPOINT");
        ImGui::Dummy(ImVec2(0,8));
        ImGui::SetWindowFontScale(1.12f);
        ImGui::TextColored(pale,"System Inspection");
        ImGui::SetWindowFontScale(1.f);
        ImGui::TextColored(quiet,"Processes, services, persistence and event evidence");
        ImGui::Dummy(ImVec2(0,14));
        if(scanning){
            if(presentationHold.load()){
                ImGui::TextColored(accent,"SCAN COMPLETE - RESULT PRESENTATION DELAY");
                ImGui::Text("Forensic work finished. Displaying results in about %u s.",
                    presentationWaitRemaining.load());
                ImGui::TextDisabled("This is an intentional display wait, not extra analysis.");
            }else{
                ImGui::TextColored(accent,"INSPECTION RUNNING - LIVE EVIDENCE COLLECTION");
            }
            if(ImGui::Button("CANCEL SCAN",ImVec2(155,37)))cancelRequested=true;
        }else if(done && !scanFailed && !scanCancelled){
            ImGui::TextColored(ImVec4(.45f,.85f,.56f,1.f),
                "VERIFIED  -  SCAN COMPLETED");
            if(ImGui::Button("VIEW RESULTS",
                ImVec2((std::min)(150.f,ImGui::GetContentRegionAvail().x),42)))page=2;
        }else{
            if(accentButton(localized("START FULL INSPECTION"),
                ImVec2((std::min)(220.f,ImGui::GetContentRegionAvail().x),42)))startScan();
            if(ImGui::GetContentRegionAvail().x>145.f)ImGui::SameLine(0,8);
            if(ImGui::Button("VIEW RESULTS",
                ImVec2((std::min)(130.f,ImGui::GetContentRegionAvail().x),42)))page=2;
        }
        if(scanFailed){
            ImGui::Separator();
            ImGui::TextColored(ImVec4(1.0f,.55f,.45f,1.0f),
                "SCAN FAILED - stage %d",scanFailureStage.load());
            std::string failure;
            {
                std::lock_guard<std::mutex> guard(scanFailureMutex);
                failure=scanFailureReason;
            }
            if(!failure.empty())ImGui::TextWrapped("Reason: %s",failure.c_str());
            ImGui::TextDisabled("Diagnostic log: %%TEMP%%\\SyncPCChecker\\diagnostic.log");
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
        if(side){
            ImGui::SameLine(0,12);
            ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.080f,0.080f,0.080f,1));
            ImGui::BeginChild("##liveCounters",ImVec2(rightWidth,233),ImGuiChildFlags_Borders);
            ImGui::TextColored(accent,"LIVE TELEMETRY");
            ImGui::Separator();
            ImGui::TextColored(quiet,"PROCESSES");ImGui::SameLine(145);ImGui::Text("%zu",processCount.load());
            ImGui::TextColored(quiet,"SYSTEM RECORDS");ImGui::SameLine(145);ImGui::Text("%zu",recordCount.load());
            ImGui::TextColored(quiet,"FILES VERIFIED");ImGui::SameLine(145);ImGui::Text("%zu",fileCount.load());
            ImGui::TextColored(quiet,"DEFENDER EVENTS");ImGui::SameLine(145);ImGui::Text("%d",defenderAlerts.load());
            ImGui::Separator();
            ImGui::TextColored(quiet,"%s",stateText());
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }else{
            ImGui::TextColored(quiet,"PROCESSES: %zu    RECORDS: %zu",
                processCount.load(),recordCount.load());
            ImGui::TextColored(quiet,"FILES VERIFIED: %zu    DEFENDER EVENTS: %d",
                fileCount.load(),defenderAlerts.load());
        }
        ImGui::Dummy(ImVec2(0,16));
        if(defenderAlerts.load()>0){
            ImGui::PushStyleColor(ImGuiCol_ChildBg,ImVec4(0.111f,0.111f,0.111f,1));
            ImGui::BeginChild("##defenderNotice",ImVec2(0,68),ImGuiChildFlags_Borders);
            ImGui::TextColored(ImVec4(0.684f,0.684f,0.684f,1),"DEFENDER EVENTS: %d",defenderAlerts.load());
            ImGui::TextDisabled("Historical alerts; review current protection status separately.");
            ImGui::SameLine();
            if(ImGui::SmallButton("OPEN EVENTS"))page=3;
            ImGui::EndChild();
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0,10));
        }
        if(done){
            if(ImGui::CollapsingHeader("SCAN PERFORMANCE / VERIFIED STAGES")){
                ImGui::Text("Batch scripts: %u found | %u filename matches | %u inaccessible folders",
                    batFilesSeen.load(),batNameMatches.load(),batDirsFailed.load());
                ImGui::Text("Loaded DLLs examined: %u | review indicators: %u",
                    dllModulesExamined.load(),dllReviewFindings.load());
                ImGui::Text("PE entropy: %u files | %u sections",
                    peEntropyFiles.load(),peEntropySections.load());
                ImGui::Text("PE invalid/unavailable: %u | sections skipped: %u",
                    peEntropyInvalid.load(),peEntropySectionsSkipped.load());
                ImGui::Text("PE inspection cancellations: %u",peEntropyCancelled.load());
                ImGui::Text("Deep executable files checked: %u",deepFilesChecked.load());
                ImGui::Text("Deep paths found: %u | skipped: %u",
                    deepUniquePaths.load(),deepFilesSkipped.load());
                ImGui::Text("Process observations: %u | unique PIDs: %u",
                    observedSnapshots.load(),observedUniquePids.load());
                ImGui::Text("Observed new PIDs: %u | disappeared PIDs: %u",
                    observedNewPids.load(),observedGonePids.load());
                ImGui::TextDisabled("Stage-boundary sampling, not continuous ETW tracing.");
                ImGui::Text("First process snapshot: %u",stageWorkItems[0].load());
                ImGui::Text("Second process snapshot: %u",processSecondSnapshot.load());
                ImGui::Text("New PIDs between snapshots: %u",processNewPids.load());
                ImGui::Text("PIDs absent from second snapshot: %u",processExitedPids.load());
                ImGui::TextDisabled("Two snapshots only: short-lived processes can be missed.");
                ImGui::TextDisabled("Forensic count below covers header checks, YARA findings and PID changes only.");
                const char* names[]={"Process inventory","Service inventory",
                    "Startup entries","Network and device inventory",
                    "Security and forensic artifacts","Result publication"};
                for(int i=0;i<6;++i){
                    const auto us=stageElapsedUs[i].load();
                    const auto count=stageWorkItems[i].load();
                    if(us<1000)
                        ImGui::Text("%s: %.2f ms  |  %u items",
                            names[i],us/1000.0,count);
                    else
                        ImGui::Text("%s: %.3f s  |  %u items",
                            names[i],us/1000000.0,count);
                }
                ImGui::Separator();
                ImGui::Text("Measured worker time: %.3f s",scanElapsedUs.load()/1000000.0);
                ImGui::TextDisabled("Items are collected entries, not a measure of forensic depth.");
                ImGui::TextDisabled("Stage 5 includes collection and enrichment; counts may overlap.");
            }
        }
        if(done || scanFailed){
            ImGui::TextColored(accent,"FORENSIC SOURCE COVERAGE");
            const int coverageState=forensicSourceStatus.load();
            if(coverageState==1){
                ImGui::Text("Source status checks: %u  |  Correlation notices: %u",
                    forensicSourceChecks.load(),forensicCorrelationNotices.load());
                if(forensicSourceChecks.load()==0)
                    ImGui::TextDisabled("No source-status records returned; inspect scanner diagnostics.");
            }else if(coverageState==2){
                ImGui::TextDisabled("Forensic collection failed before source checks completed.");
            }else{
                ImGui::TextDisabled("Forensic source checks were not completed in this run.");
            }
            ImGui::TextDisabled("Unavailable sources are not evidence of tampering.");
            ImGui::Dummy(ImVec2(0,8));
        }
        if(done){
            ImGui::TextColored(accent,"INDIVIDUAL PROCESS CHECKS");
            ImGui::Text("Planned: %llu | Completed: %llu | Unavailable: %llu",
                processChecksPlanned.load(),processChecksCompleted.load(),
                processChecksUnavailable.load());
            ImGui::TextDisabled("A process is counted once; checks are counted separately.");
            ImGui::Dummy(ImVec2(0,8));
        }
        ImGui::TextColored(accent,"INVESTIGATION MODULES");
        ImGui::TextColored(quiet,"Select a module to inspect collected evidence");
        ImGui::Dummy(ImVec2(0,8));
        ImGui::BeginChild("##dashboardModulesNew",ImVec2(0,0),ImGuiChildFlags_None);
        modulesList();
        ImGui::EndChild();
    } else if(page==2) {
        if(!expandedFindingsTable){
            sectionTitle("Investigation Results",
                         "Process inventory with explainable path-based review indicators.");
            ImGui::TextDisabled("%zu processes   |   %zu records   |   %zu files",
                              processCount.load(),recordCount.load(),fileCount.load());
        }
        if(ImGui::SmallButton(expandedFindingsTable?
            "Show overview##tableHeight":"Expand results table##tableHeight"))
            expandedFindingsTable=!expandedFindingsTable;
        ImGui::SameLine();
        ImGui::TextDisabled("%zu processes | %zu records",
                            processCount.load(),recordCount.load());
        if(ImGui::BeginTabBar("results")) {
            if(ImGui::BeginTabItem("Findings")) {
                if(!expandedFindingsTable)
                    ImGui::TextDisabled("Path-based indicators only; warnings are not confirmed threats.");
                processTable(-1.f);
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Evidence Inspector")){
                drawEvidenceInspector();
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Scan Comparison")){
                ImGui::TextDisabled("Scan Comparison is unavailable in single-scan mode.");
                ImGui::TextWrapped("Restart the application to run a new verification. "
                    "This mode does not compare two scans in one session.");
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Service Review")) {
                drawServiceReviews();
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("File Integrity")) {
                ImGui::InputTextWithHint("##file","Select a file to verify...",fileInput,sizeof(fileInput));
                ImGui::SameLine();if(ImGui::Button("Browse"))chooseFile();
                if(accentButton("Calculate SHA-256 + Verify Signature"))inspectSelectedFile();
                if(ImGui::BeginTable("files",4,ImGuiTableFlags_BordersInnerH|ImGuiTableFlags_RowBg|
                    ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-1))) {
                    ImGui::TableSetupColumn("File",ImGuiTableColumnFlags_WidthStretch,2);
                    ImGui::TableSetupColumn("SHA-256",ImGuiTableColumnFlags_WidthStretch,2);
                    ImGui::TableSetupColumn("Signature",ImGuiTableColumnFlags_WidthStretch,2);
                    ImGui::TableSetupColumn("Details",ImGuiTableColumnFlags_WidthFixed,110);
                    ImGui::TableHeadersRow();
                    std::lock_guard<std::mutex> lock(dataMutex);
                    for(const auto& f:files) {
                        ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                        ImGui::TableSetColumnIndex(0);ImGui::TextWrapped("%s",utf8(f.path).c_str());
                        ImGui::TableSetColumnIndex(1);ImGui::TextWrapped("%s",f.hash.c_str());
                        ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",f.signature.c_str());
                         ImGui::TableSetColumnIndex(3);ImGui::PushID(&f);
                         if(ImGui::Button("Show Details",ImVec2(130,32)))openEvidenceDetails("File Integrity",utf8(f.path),
                             "SHA-256: "+f.hash+"\nAuthenticode: "+f.signature,f.path);
                         ImGui::PopID();
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("System Inventory")) {
                recordsTable();ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("USB Review")) {
                ImGui::TextDisabled("Historical USB registry inventory and volume mappings. No reliable last-connected timestamp.");
                if(ImGui::BeginTable("usbDevices",4,ImGuiTableFlags_BordersInnerH|
                    ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-1))) {
                    ImGui::TableSetupScrollFreeze(0,1);
                    ImGui::TableSetupColumn("Category",ImGuiTableColumnFlags_WidthFixed,100);
                    ImGui::TableSetupColumn("Device",ImGuiTableColumnFlags_WidthStretch,1.5f);
                    ImGui::TableSetupColumn("Registry details",ImGuiTableColumnFlags_WidthStretch,3.f);
                    ImGui::TableSetupColumn("Details",ImGuiTableColumnFlags_WidthFixed,110);
                    ImGui::TableHeadersRow();
                    std::lock_guard<std::mutex> lock(dataMutex);
                    int found=0;
                    for(const auto& r:records) {
                        if(r.category!="USB" && r.category!="USB Coverage" && r.category!="USB Volume History")continue;
                        ++found;
                        ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                        ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(r.category.c_str());
                        ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(r.name.c_str());
                        ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",r.detail.c_str());
                         ImGui::TableSetColumnIndex(3);ImGui::PushID(&r);
                         if(ImGui::Button("Show Details",ImVec2(130,32)))openEvidenceDetails("USB Registry",r.name,
                             "Registry inventory: "+r.detail+"\nThis entry does not establish when a device was connected.");
                         ImGui::PopID();
                    }
                    if(!found) {
                        ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextDisabled("No USB inventory in current scan. Run Start Full Scan.");
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Modules")) {
                modulesList();ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    } else if(page==3) {
        sectionTitle("EXECUTION TIMELINE",
            "Real Windows events from the past 7 days, ordered newest first");
        if(!done && !scanning) {
            ImGui::TextDisabled("Run Start Full Scan on the Dashboard to collect events.");
        }
        if(scanning)ImGui::TextDisabled("Scan in progress. Previous timeline remains visible.");
        ImGui::Text("Timeline records: %zu",timelineCount.load());
        ImGui::Spacing();
        static char timelineSearch[180]{};
        static bool onlyTimelineAlerts=false;
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x*.68f);
        ImGui::InputTextWithHint("##timelineSearch",
            "Filter by event ID, provider or description...",
            timelineSearch,sizeof(timelineSearch));
        ImGui::SameLine();
        ImGui::Checkbox("Alerts only",&onlyTimelineAlerts);
        ImGui::Spacing();
        std::vector<TimelineEvent> snapshot;
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            snapshot=timelineEvents;
        }
        if(snapshot.empty() && done) {
            ImGui::TextDisabled("No matching events collected. Check event log permissions and enabled channels.");
        }
        static int selectedTimeline=-1;
        bool openTimelineDetails=false;
        if(ImGui::BeginTable("##timelineTable",5,
            ImGuiTableFlags_BordersInnerH|ImGuiTableFlags_RowBg|
            ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,
            ImVec2(0,ImGui::GetContentRegionAvail().y))) {
            ImGui::TableSetupColumn("UTC timestamp",ImGuiTableColumnFlags_WidthFixed,195);
            ImGui::TableSetupColumn("Source",ImGuiTableColumnFlags_WidthFixed,160);
            ImGui::TableSetupColumn("Event ID",ImGuiTableColumnFlags_WidthFixed,80);
            ImGui::TableSetupColumn("Event",ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Details",ImGuiTableColumnFlags_WidthFixed,95);
            ImGui::TableHeadersRow();
            for(size_t i=0;i<snapshot.size();++i) {
                const auto& ev=snapshot[i];
                if(onlyTimelineAlerts && !ev.alert)continue;
                const std::string hay=ev.timestamp+" "+ev.source+" "+ev.eventId+
                    " "+ev.description+" "+ev.detail;
                if(timelineSearch[0] && hay.find(timelineSearch)==std::string::npos)
                    continue;
                ImGui::PushID((int)i);
                ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                if(ev.alert)ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                    IM_COL32(92,92,92,150));
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(ev.timestamp.empty()?"N/A":ev.timestamp.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(ev.source.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(ev.eventId.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(ev.description.c_str());
                ImGui::TableSetColumnIndex(4);
                if(ImGui::Button("Show Details",ImVec2(130,32))) {
                    selectedTimeline=(int)i;
                    openTimelineDetails=true;
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        if(openTimelineDetails)ImGui::OpenPopup("Timeline Event Details");
        if(ImGui::BeginPopupModal("Timeline Event Details",nullptr,
                    ImGuiWindowFlags_AlwaysAutoResize)) {
                    if(selectedTimeline>=0 &&
                       (size_t)selectedTimeline<snapshot.size()) {
                        const auto& e=snapshot[(size_t)selectedTimeline];
                        ImGui::Text("Timestamp (UTC): %s",e.timestamp.c_str());
                        ImGui::Text("Source: %s",e.source.c_str());
                        ImGui::Text("Event ID: %s",e.eventId.c_str());
                        ImGui::Separator();
                        ImGui::TextWrapped("%s",e.description.c_str());
                        ImGui::TextWrapped("%s",e.detail.c_str());
                        if(e.alert)ImGui::TextColored(
                            ImVec4(0.769f,0.769f,0.769f,1.f),
                            "REVIEW: Security event requires investigation.");
                    }
                    if(ImGui::Button("Close"))ImGui::CloseCurrentPopup();
                    ImGui::EndPopup();
                }
    } else if(page==7||page==8) {
        const bool networkView=page==7;
        sectionTitle(networkView?"Network Evidence":"Driver Audit",
            networkView?"TCP/UDP endpoints collected by the scan":
            "Kernel driver and service-driver evidence collected by the scan");
        static char evidenceSearch[2][256]{};
        char* activeSearch=evidenceSearch[networkView?0:1];
        ImGui::SetNextItemWidth(420);
        ImGui::InputTextWithHint("##specialEvidenceSearch","Search evidence, names or paths...",
            activeSearch,256);
        ImGui::SameLine();
        std::vector<Record> snapshot;
        {std::lock_guard<std::mutex> lock(dataMutex);snapshot=records;}
        size_t shown=0;
        if(ImGui::BeginTable("##specialEvidence",3,
            ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|
            ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-1))){
            ImGui::TableSetupColumn("Source",ImGuiTableColumnFlags_WidthFixed,165);
            ImGui::TableSetupColumn("Item",ImGuiTableColumnFlags_WidthStretch,1);
            ImGui::TableSetupColumn("Evidence / details",ImGuiTableColumnFlags_WidthStretch,3);
            ImGui::TableHeadersRow();
            for(const auto& r:snapshot){
                std::string category=r.category;
                std::transform(category.begin(),category.end(),category.begin(),
                    [](unsigned char c){return (char)std::tolower(c);});
                bool relevant=networkView?
                    category.find("network")!=std::string::npos||
                    category.find("tcp")!=std::string::npos||
                    category.find("udp")!=std::string::npos:
                    category.find("driver")!=std::string::npos||
                    category.find("kernel")!=std::string::npos;
                if(!relevant)continue;
                std::string text=r.category+" "+r.name+" "+r.detail;
                std::transform(text.begin(),text.end(),text.begin(),
                    [](unsigned char c){return (char)std::tolower(c);});
                std::string query=activeSearch;
                std::transform(query.begin(),query.end(),query.begin(),
                    [](unsigned char c){return (char)std::tolower(c);});
                if(!query.empty()&&text.find(query)==std::string::npos)continue;
                ++shown;
                ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(r.category.c_str());
                ImGui::TableSetColumnIndex(1);ImGui::TextWrapped("%s",r.name.c_str());
                ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",r.detail.c_str());
            }
            ImGui::EndTable();
        }
        if(!shown)ImGui::TextDisabled("No matching evidence. Run a scan or adjust the search.");
    } else if(page==10) {
        sectionTitle("Memory Dump",
            "Create a local process memory dump and verify existing dump files");
        ImGui::TextWrapped(
            "Create a user-mode minidump of this application or a process "
            "owned by your Windows account. Protected/system processes are "
            "excluded. Dumps can contain private data; keep them local.");
        ImGui::Spacing();
        ImGui::TextColored(accentInk,"PROCESS MEMORY CAPTURE");
        static bool dumpConsent=false;
        static int selectedPid=0;
        static std::string captureStatus="No dump created.";
        static std::wstring capturedPath;
        const DWORD ownPid=GetCurrentProcessId();
        if(selectedPid==0)selectedPid=(int)ownPid;
        if(ImGui::SmallButton("SELECT SYNC PC CHECKER"))
            selectedPid=(int)ownPid;
        ImGui::SameLine();
        ImGui::TextDisabled("PID %lu",static_cast<unsigned long>(ownPid));
        ImGui::SetNextItemWidth(200.f);
        ImGui::InputInt("Target process PID",&selectedPid,1,100);
        ImGui::TextDisabled("Use a PID from the Processes tab. Same-account processes only.");
        ImGui::Checkbox("I understand the dump may contain private information",
                        &dumpConsent);
        if(!dumpConsent)ImGui::BeginDisabled();
        if(ImGui::Button("CREATE PROCESS DUMP",ImVec2(230,38))){
            capturedPath.clear();
            if(selectedPid<=0 || selectedPid==4){
                captureStatus="Invalid or protected process PID.";
            }else{
                const DWORD pid=(DWORD)selectedPid;
                HANDLE target=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
                                          FALSE,pid);
                if(!target){
                    captureStatus="Cannot open process with normal user permissions. "
                                  "No elevation attempted.";
                }else{
                    wchar_t imagePath[32768]={};
                    DWORD imageLen=static_cast<DWORD>(std::size(imagePath));
                    const bool knownPath=QueryFullProcessImageNameW(
                        target,0,imagePath,&imageLen)!=FALSE;
                    if(!knownPath || isSensitiveDumpTarget(imagePath) ||
                       !isSameAccountProcess(target)){
                        captureStatus="Process not eligible: protected, unknown "
                                      "or owned by another account.";
                    }else{
                        wchar_t folder[MAX_PATH]={};
                        const DWORD n=GetEnvironmentVariableW(
                            L"LOCALAPPDATA",folder,MAX_PATH);
                        if(!n || n>=MAX_PATH){
                            captureStatus="Local application data folder unavailable.";
                        }else{
                            const fs::path directory=fs::path(folder)/
                                L"SyncPCChecker"/L"MemoryDumps";
                            std::error_code ec;
                            fs::create_directories(directory,ec);
                            if(ec){
                                captureStatus="Cannot create dump directory.";
                            }else{
                                SYSTEMTIME now{};GetLocalTime(&now);
                                wchar_t filename[128]={};
                                swprintf_s(filename,
                                    L"Process-%lu-%04u%02u%02u-%02u%02u%02u.dmp",
                                    (unsigned long)pid,now.wYear,now.wMonth,
                                    now.wDay,now.wHour,now.wMinute,now.wSecond);
                                const fs::path output=directory/filename;
                                HANDLE file=CreateFileW(output.c_str(),GENERIC_WRITE,
                                    0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
                                if(file==INVALID_HANDLE_VALUE){
                                    captureStatus="Cannot create dump file.";
                                }else{
                                    const BOOL ok=MiniDumpWriteDump(target,pid,file,
                                        static_cast<MINIDUMP_TYPE>(
                                            MiniDumpNormal|MiniDumpWithThreadInfo|
                                            MiniDumpWithUnloadedModules),
                                        nullptr,nullptr,nullptr);
                                    const DWORD error=ok?ERROR_SUCCESS:GetLastError();
                                    CloseHandle(file);
                                    if(ok){
                                        capturedPath=output.wstring();
                                        captureStatus="Process minidump saved successfully.";
                                    }else{
                                        DeleteFileW(output.c_str());
                                        captureStatus="Dump failed (Windows error "+
                                            std::to_string(error)+").";
                                    }
                                }
                            }
                        }
                    }
                    CloseHandle(target);
                }
            }
        }
        if(!dumpConsent)ImGui::EndDisabled();
        ImGui::TextWrapped("STATUS: %s",captureStatus.c_str());
        if(!capturedPath.empty()){
            ImGui::TextWrapped("Saved to: %s",utf8(capturedPath).c_str());
            if(ImGui::SmallButton("COPY DUMP PATH"))
                ImGui::SetClipboardText(utf8(capturedPath).c_str());
        }
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextColored(accentInk,"VERIFY EXISTING DUMP");
        static char dumpPath[32768]{};
        static std::string dumpStatus="No dump selected.";
        static std::string dumpHash;
        static unsigned long long dumpBytes=0;
        ImGui::SetNextItemWidth(-118.f);
        ImGui::InputText("##dumpPath",dumpPath,sizeof(dumpPath));
        ImGui::SameLine();
        if(ImGui::Button("BROWSE",ImVec2(105,0))){
            wchar_t selected[MAX_PATH*8]{};
            OPENFILENAMEW ofn{};
            ofn.lStructSize=sizeof(ofn);
            ofn.hwndOwner=hwnd;
            ofn.lpstrFile=selected;
            ofn.nMaxFile=static_cast<DWORD>(std::size(selected));
            ofn.lpstrFilter=
                L"Memory dumps (*.dmp;*.mdmp;*.mem)\0*.dmp;*.mdmp;*.mem\0"
                L"All files (*.*)\0*.*\0";
            ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|
                      OFN_NOCHANGEDIR|OFN_EXPLORER;
            if(GetOpenFileNameW(&ofn)){
                const auto chosen=utf8(selected);
                strncpy_s(dumpPath,sizeof(dumpPath),chosen.c_str(),_TRUNCATE);
                dumpStatus="File selected. Choose VERIFY DUMP.";
                dumpHash.clear();
            }
        }
        if(ImGui::Button("VERIFY DUMP",ImVec2(180,36))){
            dumpHash.clear();
            dumpBytes=0;
            const std::wstring selected=wide(dumpPath);
            WIN32_FILE_ATTRIBUTE_DATA attrs{};
            if(selected.empty() ||
               !GetFileAttributesExW(selected.c_str(),GetFileExInfoStandard,&attrs) ||
               (attrs.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)){
                dumpStatus="Cannot access the selected file.";
            }else{
                dumpBytes=(static_cast<unsigned long long>(attrs.nFileSizeHigh)<<32)|
                    attrs.nFileSizeLow;
                dumpHash=sha256(selected);
                dumpStatus=dumpHash.empty()?
                    "File metadata read; SHA-256 unavailable.":
                    "File metadata and SHA-256 calculated.";
            }
        }
        ImGui::TextWrapped("STATUS: %s",dumpStatus.c_str());
        if(dumpBytes)
            ImGui::Text("File size: %.2f MiB",
                static_cast<double>(dumpBytes)/(1024.0*1024.0));
        if(!dumpHash.empty()){
            ImGui::TextUnformatted(XOR_STR("SHA-256").c_str());
            ImGui::TextWrapped("%s",dumpHash.c_str());
            if(ImGui::Button("COPY SHA-256"))
                ImGui::SetClipboardText(dumpHash.c_str());
        }
        ImGui::TextDisabled(
            "Verification calculates file metadata and a hash; it does not "
            "validate dump contents or analyze kernel memory.");
    } else if(page==9) {
        sectionTitle("Artifact Explorer",
            "EXE, DLL, SYS, Prefetch, TEMP, Startup and executable scripts");
        ImGui::TextDisabled("Read-only evidence from the last full scan. "
            "Inventory entries are not confirmed threats.");
        static int artifactType=0;
        static int artifactStatusFilter=0;
        static char artifactSearch[320]{};
        const char* artifactStatusNames[]={
            "All files","Suspect","Detected","No indicators"};
        for(int f=0;f<4;++f){
            ImGui::PushID(10000+f);
            const bool active=artifactStatusFilter==f;
            if(active){
                ImGui::PushStyleColor(ImGuiCol_Button,ImVec4(.28f,.28f,.28f,1.f));
                ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(1.f,1.f,1.f,1.f));
            }
            if(ImGui::Button(artifactStatusNames[f],
                ImVec2(f==0?148.f:f==3?152.f:120.f,36.f)))
                artifactStatusFilter=f;
            if(active)ImGui::PopStyleColor(2);
            ImGui::PopID();
            if(f<3)ImGui::SameLine(0,7);
        }
        ImGui::Dummy(ImVec2(0,7));
        const char* types[]={"All artifacts","EXE","DLL","SYS","Prefetch",
                             "Scripts / shortcuts","Cheat / External name matches","BAT / CMD name matches"};
        ImGui::SetNextItemWidth(215);
        ImGui::Combo("Type##artifact", &artifactType,types,IM_ARRAYSIZE(types));
        ImGui::SameLine();
        ImGui::SetNextItemWidth((std::max)(180.f,ImGui::GetContentRegionAvail().x-12.f));
        ImGui::InputTextWithHint("##artifactSearch",
            "Search filename, path, location or indicator...",
            artifactSearch,sizeof(artifactSearch));
        std::vector<Record> snapshot;
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            for(const auto& r:records)
                snapshot.push_back(r);
        }
        static std::string artifactExportMessage;
        ImGui::Text("Collected artifacts: %zu",snapshot.size());
        ImGui::SameLine(0,18);
        if(ImGui::SmallButton("OPEN BINARY LAB##artifact"))page=6;
        ImGui::SameLine(0,18);
        if(ImGui::SmallButton("EXPORT CSV##artifact"))
            exportEvidenceCsv(snapshot,artifactExportMessage);
        if(!artifactExportMessage.empty())
            ImGui::TextDisabled("%s",artifactExportMessage.c_str());
        ImGui::Separator();
        std::string query=artifactSearch;
        std::transform(query.begin(),query.end(),query.begin(),
            [](unsigned char c){return (char)std::tolower(c);});
        if(ImGui::BeginTable("##artifactExplorer",4,
            ImGuiTableFlags_BordersInnerH|ImGuiTableFlags_RowBg|
            ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-1))){
            ImGui::TableSetupScrollFreeze(0,1);
            ImGui::TableSetupColumn("Type",ImGuiTableColumnFlags_WidthFixed,140);
            ImGui::TableSetupColumn("File / Indicator",ImGuiTableColumnFlags_WidthStretch,1.5f);
            ImGui::TableSetupColumn("Evidence and location",ImGuiTableColumnFlags_WidthStretch,3.f);
            ImGui::TableSetupColumn("Details",ImGuiTableColumnFlags_WidthFixed,95);
            ImGui::TableHeadersRow();
            std::vector<const Record*> visibleArtifacts;
            visibleArtifacts.reserve(snapshot.size());
            for(const auto& r:snapshot){
                const bool matchType=artifactType==0 ||
                    (artifactType==1&&r.category=="Artifact: EXE") ||
                    (artifactType==2&&r.category=="Artifact: DLL") ||
                    (artifactType==3&&r.category=="Artifact: Driver") ||
                    (artifactType==4&&r.category=="Artifact: Prefetch") ||
                    (artifactType==5&&(r.category=="Artifact: Script/Shortcut" ||
                       r.category=="Batch Script Name Rule")) ||
                    (artifactType==6&&
                      (r.detail.find("DETECTED - NAME RULE")!=std::string::npos ||
                       r.category=="FiveM Cheat Name Detection")) ||
                    (artifactType==7&&(r.category=="Batch Script Name Rule" ||
                       r.category=="Batch Script Content Review" ||
                       r.category=="Batch Script Inventory"));
                if(!matchType)continue;
                const bool detected=
                    isDetectedRecord(r) ||
                    r.detail.find("DETECTED - NAME RULE")!=std::string::npos ||
                    r.category=="FiveM Cheat Name Detection";
                const bool suspect=!detected &&
                    (isSuspectRecord(r) ||
                     r.detail.find("NEEDS REVIEW")!=std::string::npos ||
                     r.detail.find("REVIEW:")!=std::string::npos ||
                     r.category=="Batch Script Name Rule" ||
                     r.category=="Batch Script Content Review" ||
                     r.category=="Usermode DLL Review" ||
                     r.category=="OBS Module Review");
                if(artifactStatusFilter==1 && !suspect)continue;
                if(artifactStatusFilter==2 && !detected)continue;
                if(artifactStatusFilter==3 && (detected||suspect))continue;
                std::string hay=r.category+" "+r.name+" "+r.detail;
                std::transform(hay.begin(),hay.end(),hay.begin(),
                    [](unsigned char c){return (char)std::tolower(c);});
                if(!query.empty()&&hay.find(query)==std::string::npos)continue;
                visibleArtifacts.push_back(&r);
            }
            ImGuiListClipper artifactClipper;
            artifactClipper.Begin((int)visibleArtifacts.size());
            while(artifactClipper.Step())
                for(int row=artifactClipper.DisplayStart;
                    row<artifactClipper.DisplayEnd;++row){
                    const Record& r=*visibleArtifacts[(size_t)row];
                    const bool detected=isDetectedRecord(r) ||
                        r.detail.find("DETECTED - NAME RULE")!=std::string::npos ||
                        r.category=="FiveM Cheat Name Detection";
                    const bool suspect=!detected &&
                        (isSuspectRecord(r) ||
                         r.detail.find("NEEDS REVIEW")!=std::string::npos ||
                         r.detail.find("REVIEW:")!=std::string::npos ||
                     r.category=="Batch Script Name Rule");
                ImGui::TableNextRow(ImGuiTableRowFlags_None,44.f);
                if(detected)ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                    IM_COL32(65,65,65,180));
                else if(suspect)ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                    IM_COL32(44,44,44,150));
                ImGui::TableSetColumnIndex(0);ImGui::TextWrapped("%s",r.category.c_str());
                ImGui::TableSetColumnIndex(1);ImGui::TextWrapped("%s",r.name.c_str());
                ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",r.detail.c_str());
                ImGui::TableSetColumnIndex(3);ImGui::PushID(&r);
                if(ImGui::Button("Show Details",ImVec2(130,32)))
                    openEvidenceDetails(r.category,r.name,r.detail);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    } else if(page==6) {
        binaryInspector::draw();
    } else if(page==4) {
        sectionTitle(localized("Workspace Preferences"),"Adjust appearance and investigation options");
        ImGui::BeginChild("settings",ImVec2(0,0),ImGuiChildFlags_Borders);
        ImGui::TextDisabled(localized("PERSONALIZATION  /  LOCAL SETTINGS"));
        ImGui::TextWrapped(localized("Customize the scanner appearance and investigation workflow."));
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextColored(orange(),"LANGUAGE");
        ImGui::Separator();
        ImGui::TextUnformatted(displayLanguage==1?"Idioma de exibição":"Display language");
        ImGui::SetNextItemWidth(320);
        const char* languages[]={"English","Português (Brasil)"};
        if(ImGui::Combo("##display_language",&displayLanguage,languages,IM_ARRAYSIZE(languages)))
            saveSettings();
        ImGui::TextDisabled("%s",displayLanguage==1?
            "O idioma altera os rótulos traduzidos; os dados técnicos permanecem no formato original.":
            "Translated interface labels change immediately; technical evidence stays in its original format.");
        ImGui::Spacing();ImGui::Separator();ImGui::Spacing();
        ImGui::TextColored(orange(),"APPEARANCE");
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::Text(localized("Scan Percentage Color"));
        ImGui::TextDisabled(localized("Changes only the 0-100%% number; the interface stays monochrome."));
        ImGui::SetNextItemWidth(320);
        ImGui::Combo("##accent",&accentIndex,accentNames,IM_ARRAYSIZE(accentNames));
        if(accentIndex==5) {
            ImGui::ColorEdit3("Custom percentage color",(float*)&customAccent,
                              ImGuiColorEditFlags_NoInputs);
        }
        ImGui::Spacing();
        ImGui::Text(localized("Theme"));
        ImGui::SetNextItemWidth(320);
        if(ImGui::Combo("##theme",&themeIndex,themeNames,IM_ARRAYSIZE(themeNames)))applyTheme();
        ImGui::Spacing();
        ImGui::Text(localized("Interface Scale"));
        ImGui::SetNextItemWidth(320);
        if(ImGui::SliderFloat("##scale",&interfaceScale,0.95f,1.10f,"%.2fx"))
            ImGui::GetIO().FontGlobalScale=interfaceScale;
        ImGui::Spacing();
        ImGui::Text(localized("Window size (maximum 1920 x 1080)"));
        ImGui::SetNextItemWidth(320);
        if(ImGui::Combo("##windowPreset",&windowPreset,windowPresetNames,
            IM_ARRAYSIZE(windowPresetNames)))applyWindowPreset();
        ImGui::TextDisabled(localized("Size is limited to the available desktop work area."));
        ImGui::Spacing();
        ImGui::Text(localized("Table Density"));
        ImGui::SetNextItemWidth(320);
        if(ImGui::Combo("##density",&densityIndex,densityNames,IM_ARRAYSIZE(densityNames)))
            applyTheme();
        ImGui::Spacing();ImGui::Separator();ImGui::Spacing();
        ImGui::TextColored(orange(),"INTERFACE DETAILS");
        ImGui::Checkbox(localized("Animate scanner branding"),&brandAnimation);
        ImGui::Checkbox(localized("Monochrome rain across the window"),&ambientMotesEnabled);
        ImGui::BeginDisabled(!ambientMotesEnabled);
        ImGui::SetNextItemWidth(200);
        ImGui::Combo("Rain density",&rainDensity,rainDensityNames,
                     IM_ARRAYSIZE(rainDensityNames));
        ImGui::EndDisabled();
        ImGui::Checkbox(localized("Reduce motion (disable transition and unlock animations)"),
                        &reducedMotion);
        ImGui::TextDisabled("Rain stays static with Reduce motion; scan results remain protected.");
        ImGui::Checkbox(localized("Highlight navigation on hover"),&showNavHover);
        ImGui::TextDisabled(localized("Animations are visual only; scanning is unaffected."));
        ImGui::Spacing();
        ImGui::Text(localized("Button corners"));
        ImGui::SetNextItemWidth(320);
        if(ImGui::Combo("##corners",&cornerStyle,cornerStyleNames,
                        IM_ARRAYSIZE(cornerStyleNames)))applyTheme();
        ImGui::Spacing();
        ImGui::Text(localized("Scrollbar width"));
        ImGui::SetNextItemWidth(320);
        if(ImGui::Combo("##scrollbar",&scrollbarWidth,scrollbarWidthNames,
                        IM_ARRAYSIZE(scrollbarWidthNames)))applyTheme();
        ImGui::Spacing();ImGui::Separator();ImGui::Spacing();
        ImGui::TextColored(orange(),"PROCESS REVIEW");
        ImGui::Checkbox(localized("Highlight suspicious processes in red"),&highlightSuspicious);
        ImGui::Checkbox(localized("Show security assessment details"),&showSecurityWarnings);
        ImGui::Spacing();ImGui::Separator();ImGui::Spacing();
        ImGui::TextColored(orange(),"PREFERENCES");
        if(accentButton(localized("Save Settings"),ImVec2(170,42)))saveSettings();
        ImGui::SameLine();
        if(ImGui::Button(localized("Restore Defaults"),ImVec2(170,42))) {
            displayLanguage=0;accentIndex=0;themeIndex=0;densityIndex=2;interfaceScale=1.0f;
            windowPreset=2;applyWindowPreset();
            highlightSuspicious=true;showSecurityWarnings=true;
            brandAnimation=true;ambientMotesEnabled=true;
            showNavHover=true;cornerStyle=1;scrollbarWidth=1;
            customAccent=ImVec4(0.527f,0.527f,0.527f,1.f);
            ImGui::GetIO().FontGlobalScale=interfaceScale;
            applyTheme();
            saveSettings();
        }
        if(settingsNotice)ImGui::TextColored(ImVec4(0.722f,0.722f,0.722f,1),"Settings saved successfully.");
        ImGui::Spacing();
        ImGui::TextDisabled("Preferences are stored locally in APPDATA\\SyncPCChecker\\settings.ini");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::TextDisabled("%s",XOR_STR("APPLICATION INTEGRITY").c_str());
        if(ImGui::Button(localized("Verify Scanner Executable"),ImVec2(240,38))) {
            try {
                auto result=inspectFile(executablePath());
                std::lock_guard<std::mutex> lock(dataMutex);
                files.push_back(std::move(result));
                fileCount=files.size();
                status="Executable verification recorded in Findings > File Integrity";
            } catch(...) {status="Executable verification failed";}
        }
        ImGui::EndChild();
    }
    // Atlas navigation transition: a short monochrome cinematic wipe.
    // Rendered over the content only, so navigation and the top bar stay
    // responsive. No result state, scan progress or evidence is modified.
    if(!reducedMotion && navTransitionStart>0.f){
        const float dt=static_cast<float>(ImGui::GetTime())-navTransitionStart;
        constexpr float duration=.56f;
        if(dt>=0.f && dt<duration){
            const float progress=std::clamp(dt/duration,0.f,1.f);
            const float smooth=progress*progress*(3.f-2.f*progress);
            const ImVec2 lo=ImGui::GetWindowPos();
            const ImVec2 sz=ImGui::GetWindowSize();
            const ImVec2 hi(lo.x+sz.x,lo.y+sz.y);
            ImDrawList* transitionDraw=ImGui::GetWindowDrawList();
            transitionDraw->PushClipRect(lo,hi,true);
            // The initial dark veil lifts, making the destination appear.
            const float veil=(1.f-smooth)*(1.f-smooth);
            transitionDraw->AddRectFilled(lo,hi,
                IM_COL32(9,9,9,static_cast<int>(208.f*veil)));
            // Bright scanning edge travels across the content horizontally.
            const float edgeX=lo.x-70.f+(sz.x+140.f)*smooth;
            const float edgeAlpha=std::sin(progress*3.14159265f);
            for(int stripe=12;stripe>=0;--stripe){
                const float x=edgeX-static_cast<float>(stripe)*5.f;
                const int alpha=static_cast<int>(
                    100.f*edgeAlpha*(1.f-stripe/13.f));
                transitionDraw->AddRectFilled(
                    ImVec2(x,lo.y),ImVec2(x+5.f,hi.y),
                    IM_COL32(222,222,222,alpha));
            }
            transitionDraw->AddLine(
                ImVec2(edgeX,lo.y+12.f),ImVec2(edgeX,hi.y-12.f),
                IM_COL32(245,245,245,
                    static_cast<int>(190.f*edgeAlpha)),1.6f);
            // Brief top-edge confirmation flash, no colored highlights.
            transitionDraw->AddRectFilled(
                ImVec2(lo.x,lo.y),ImVec2(hi.x,lo.y+2.f),
                IM_COL32(234,234,234,
                    static_cast<int>(125.f*edgeAlpha)));
            transitionDraw->PopClipRect();
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::End();
    drawProcessDetails();
    drawEvidenceDetails();
}
int WINAPI wWinMain(HINSTANCE inst,HINSTANCE,LPWSTR,int) {
    SetUnhandledExceptionFilter(diagnosticUnhandledException);
    diagnosticLog("Application starting.");
    HICON appIcon=reinterpret_cast<HICON>(
        LoadImageW(inst,MAKEINTRESOURCEW(1),IMAGE_ICON,32,32,LR_DEFAULTCOLOR));
    if(!appIcon)appIcon=LoadIconW(nullptr,IDI_APPLICATION);
    WNDCLASSEXW wc{sizeof(wc),CS_CLASSDC,wndProc,0,0,inst,appIcon,nullptr,nullptr,nullptr,
                  L"SyncPCChecker",appIcon};
    RegisterClassExW(&wc);
    hwnd=CreateWindowW(wc.lpszClassName,L"Sync PC Checker - Mudin",
                       WS_POPUP|WS_MINIMIZEBOX|WS_SYSMENU|WS_THICKFRAME|WS_MAXIMIZEBOX,100,100,1360,860,nullptr,nullptr,inst,nullptr);
    if(!hwnd){
        diagnosticLog("CreateWindowW failed.");
        MessageBoxW(nullptr,L"Unable to create the application window. "
            L"See diagnostic.log in LocalAppData\\SyncPCChecker.",
            L"Sync PC Checker - Startup Error",MB_OK|MB_ICONERROR);
        return 1;
    }
    if(!initD3D(hwnd)){
        diagnosticLog("Graphics initialization failed; exiting.");
        MessageBoxW(hwnd,L"DirectX 11 initialization failed. "
            L"Check LocalAppData\\SyncPCChecker\\diagnostic.log for details.",
            L"Sync PC Checker - Startup Error",MB_OK|MB_ICONERROR);
        return 1;
    }
    ShowWindow(hwnd,SW_SHOWDEFAULT);UpdateWindow(hwnd);
    IMGUI_CHECKVERSION();ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard;
    loadSettings();
    applyWindowPreset();
    applyTheme();
    ImGui::GetIO().FontGlobalScale=interfaceScale;
    // Use Windows' modern UI font when available; fallback to the built-in font.
    ImGuiIO& io=ImGui::GetIO();
    ImFontConfig fontCfg{};
    fontCfg.OversampleH=2;
    if(!io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf",16.f,&fontCfg))
        io.Fonts->AddFontDefault();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(device,context);
    loadSyncLogo();
    MSG msg{};
    while(msg.message!=WM_QUIT) {
        while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)) {
            TranslateMessage(&msg);DispatchMessageW(&msg);
        }
        if(msg.message==WM_QUIT)break;
        ImGui_ImplDX11_NewFrame();ImGui_ImplWin32_NewFrame();ImGui::NewFrame();
        renderUI();
        if(ambientMotesEnabled){
            ImGuiViewport* mainViewport=ImGui::GetMainViewport();
            drawAmbientMotes(mainViewport->WorkPos,mainViewport->WorkSize);
        }
        ImGui::Render();
        const float clear[4]={.035f,.035f,.035f,1.f};
        context->OMSetRenderTargets(1,&target,nullptr);
        context->ClearRenderTargetView(target,clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        swapchain->Present(1,0);
    }
    if(scanning) cancelRequested=true;
    while(scanning) Sleep(10);
    if(syncLogoTexture) {syncLogoTexture->Release();syncLogoTexture=nullptr;}
    if(syncLogoIcon) {DestroyIcon(syncLogoIcon);syncLogoIcon=nullptr;}
    ImGui_ImplDX11_Shutdown();ImGui_ImplWin32_Shutdown();ImGui::DestroyContext();
    renderTargetDestroy();
    if(swapchain)swapchain->Release();
    if(context)context->Release();
    if(device)device->Release();
    DestroyWindow(hwnd);UnregisterClassW(wc.lpszClassName,inst);
    diagnosticLog("Application exited normally.");
    return 0;
}
