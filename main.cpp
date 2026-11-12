#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <commdlg.h>
#include <d3d11.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <winreg.h>
#include <cctype>
#include <cwctype>
#include <unordered_set>
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

namespace fs=std::filesystem;
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
static const unsigned char syncLogoPng[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x40, 0x08, 0x06, 0x00, 0x00, 0x00, 0xAD, 0x2B, 0xAF, 0xCB, 0x00, 0x00, 0x00, 0x01, 0x73, 0x52, 0x47, 0x42, 0x00, 0xAE, 0xCE, 0x1C, 0xE9, 0x00, 0x00, 0x00, 0x04, 0x67, 0x41, 0x4D, 0x41, 0x00, 0x00, 0xB1, 0x8F, 0x0B, 0xFC, 0x61, 0x05, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0E, 0xC3, 0x00, 0x00, 0x0E, 0xC3, 0x01, 0xC7, 0x6F, 0xA8, 0x64, 0x00, 0x00, 0x0F, 0x54, 0x49, 0x44, 0x41, 0x54, 0x78, 0x5E, 0xD5, 0x5B, 0x7B, 0x4C, 0x14, 0x57, 0xFB, 0x7E, 0x66, 0x86, 0x99, 0xDD, 0x85, 0xDD, 0x65, 0xD7, 0x65, 0x01, 0x01, 0xA1, 0x72, 0xD1, 0xAA, 0x9F, 0xCA, 0x45, 0x8D, 0x18, 0x5B, 0xAF, 0x51, 0xA9, 0x41, 0x6D, 0x2C, 0x41, 0xA3, 0x26, 0xD5, 0x6A, 0x93, 0x1A, 0x8D, 0xD5, 0x34, 0x6D, 0x53, 0x13, 0xFD, 0xAC, 0xD5, 0x68, 0xA3, 0x26, 0xD6, 0x6A, 0xFF, 0x50, 0x1B, 0xA3, 0x36, 0x31, 0xB6, 0xD6, 0xB4, 0x31, 0x6D, 0x44, 0x0B, 0x5A, 0xB5, 0x69, 0xA3, 0x84, 0x54, 0x01, 0xAB, 0x50, 0x13, 0xAA, 0xE8, 0x82, 0x17, 0x2E, 0x22, 0x7B, 0x83, 0x7D, 0x7E, 0x7F, 0xC8, 0x8C, 0xEC, 0x2C, 0x72, 0x11, 0xE8, 0xCF, 0xEF, 0x49, 0x9E, 0x64, 0xE6, 0x9D, 0x33, 0x67, 0xCE, 0xFB, 0x9E, 0x73, 0xDE, 0x73, 0xCE, 0x7B, 0xE6, 0x08, 0xC9, 0xC9, 0xC9, 0x14, 0x04, 0x01, 0x00, 0x20, 0x08, 0x02, 0x48, 0x42, 0x10, 0x04, 0x44, 0xDA, 0xA2, 0x60, 0x36, 0xDB, 0xD0, 0x11, 0xDC, 0xCD, 0x4F, 0x50, 0x57, 0xF7, 0x10, 0x8D, 0x8D, 0xF5, 0x78, 0xF2, 0xA4, 0x09, 0x5E, 0xAF, 0x07, 0x2D, 0x2D, 0x7E, 0x90, 0xD4, 0x27, 0xED, 0x17, 0x08, 0x82, 0x80, 0xB0, 0x30, 0x19, 0x06, 0x83, 0x11, 0x11, 0x11, 0x66, 0x58, 0xAD, 0x36, 0xD8, 0xED, 0x0E, 0x98, 0xC2, 0x23, 0xF4, 0x49, 0x01, 0x00, 0x5E, 0xEF, 0x13, 0xB8, 0x9B, 0x1B, 0x83, 0xF4, 0x03, 0x00, 0x21, 0x25, 0x25, 0x25, 0x48, 0xF9, 0x30, 0x59, 0x81, 0xCD, 0x16, 0x0D, 0x45, 0x31, 0xE8, 0xB2, 0x00, 0xEE, 0xDD, 0xBB, 0x0D, 0x97, 0xAB, 0x1A, 0x8D, 0x0D, 0xF5, 0xFA, 0x47, 0x2F, 0x05, 0xAC, 0x91, 0x36, 0xC4, 0xC6, 0xC6, 0x63, 0xE0, 0xC0, 0x41, 0xFA, 0x47, 0x68, 0x6D, 0x6D, 0x81, 0xDB, 0xDD, 0x80, 0xD6, 0x16, 0x7F, 0xC7, 0xCA, 0x1B, 0x8C, 0xE1, 0x70, 0x0C, 0x88, 0x85, 0x20, 0x8A, 0x41, 0x2F, 0xBA, 0xEE, 0xDD, 0x41, 0x55, 0xD5, 0xDF, 0xF0, 0x78, 0xDC, 0x41, 0xF2, 0x97, 0x15, 0x46, 0xA3, 0x09, 0x49, 0x49, 0x29, 0x88, 0x1D, 0x98, 0x10, 0xFC, 0x80, 0x44, 0xB3, 0xBB, 0x01, 0x2D, 0x7E, 0x2F, 0x00, 0x40, 0x48, 0x4D, 0x4D, 0xA5, 0x20, 0x08, 0x30, 0x18, 0xC3, 0x31, 0x60, 0x40, 0xAC, 0x66, 0x15, 0x00, 0xF0, 0x78, 0xDC, 0xA8, 0xAC, 0x28, 0xC7, 0xC3, 0x87, 0xF7, 0xDB, 0xE5, 0xF0, 0xBF, 0x03, 0x87, 0xC3, 0x89, 0xD4, 0xB4, 0xE1, 0x30, 0x1A, 0x4D, 0x9A, 0x8C, 0x64, 0x5B, 0x0B, 0xF0, 0x41, 0x48, 0x4B, 0x4B, 0x63, 0x98, 0xAC, 0xC0, 0x19, 0x15, 0x1F, 0x54, 0xE3, 0x75, 0x8F, 0x1E, 0xE0, 0xFA, 0x5F, 0x57, 0xE1, 0xF7, 0xF9, 0x34, 0x59, 0x7F, 0x43, 0x51, 0x14, 0xF8, 0xFA, 0xF8, 0x7B, 0xB2, 0xA2, 0x60, 0xD8, 0xAB, 0xA3, 0x60, 0x1F, 0x10, 0xF5, 0x4C, 0x48, 0xE2, 0x49, 0x73, 0x1D, 0x44, 0x41, 0x10, 0x60, 0xB7, 0xC7, 0x04, 0x29, 0x7E, 0xFF, 0x7E, 0x0D, 0xAE, 0x5E, 0xBD, 0xF2, 0xAF, 0x29, 0x2E, 0x08, 0x02, 0x64, 0x59, 0x46, 0x4B, 0x4B, 0x4B, 0x50, 0xCB, 0xEB, 0x0B, 0xF8, 0x7D, 0x3E, 0x5C, 0xBD, 0x7A, 0x05, 0xF7, 0xEF, 0xD7, 0x3C, 0x13, 0x0A, 0x02, 0x8C, 0x46, 0x2B, 0x44, 0x8B, 0x75, 0x00, 0x64, 0x59, 0xD1, 0xE4, 0x75, 0x8F, 0x1E, 0xA0, 0xBC, 0xAC, 0xE4, 0x59, 0xC2, 0x7F, 0x01, 0x24, 0x11, 0x08, 0x04, 0x10, 0x1E, 0x1E, 0x0E, 0x51, 0xE7, 0x6F, 0xFA, 0x0A, 0xE5, 0x65, 0x25, 0xA8, 0x7B, 0xF4, 0x40, 0xBB, 0x97, 0xA4, 0x30, 0x88, 0xED, 0x87, 0x33, 0x8F, 0xC7, 0x8D, 0xEB, 0x7F, 0x5D, 0xD5, 0xEE, 0xFF, 0x2D, 0x88, 0xA2, 0x88, 0x94, 0x94, 0x14, 0xBC, 0xF1, 0xC6, 0x1B, 0x10, 0x45, 0xB1, 0xCF, 0x6B, 0x5F, 0xC5, 0xF5, 0xBF, 0xAE, 0x06, 0x39, 0xED, 0x20, 0x33, 0x57, 0x56, 0x94, 0xF7, 0xB8, 0xA9, 0x8B, 0xA2, 0x08, 0x83, 0xC1, 0x00, 0x45, 0x79, 0xD6, 0x7A, 0x3A, 0x82, 0x28, 0x8A, 0x90, 0x65, 0x19, 0x36, 0x9B, 0x4D, 0xAB, 0x5D, 0xA3, 0xD1, 0x08, 0x00, 0x98, 0x34, 0x69, 0x12, 0xF6, 0xEF, 0xDF, 0x8F, 0x4B, 0x97, 0x2E, 0x21, 0x10, 0x08, 0xF4, 0xDB, 0x7C, 0xC1, 0xEF, 0xF3, 0xA1, 0xB2, 0xA2, 0x5C, 0xBB, 0xD7, 0x94, 0x77, 0xDD, 0xBB, 0xF3, 0x42, 0x5E, 0x5D, 0x92, 0x24, 0x18, 0x0C, 0x06, 0xE4, 0xE6, 0xE6, 0x62, 0xDA, 0xB4, 0x69, 0x90, 0x65, 0x19, 0x82, 0x20, 0x40, 0x10, 0x04, 0x88, 0xA2, 0x08, 0x45, 0x51, 0x60, 0x34, 0x1A, 0x41, 0x12, 0x0B, 0x16, 0x2C, 0xC0, 0xC4, 0x89, 0x13, 0x11, 0x08, 0x04, 0x20, 0x49, 0x12, 0x64, 0x59, 0xC6, 0xFB, 0xEF, 0xBF, 0x8F, 0xB3, 0x67, 0xCF, 0xE2, 0xE8, 0xD1, 0xA3, 0xA8, 0xAE, 0xAE, 0x46, 0x6B, 0x6B, 0xAB, 0xFE, 0x13, 0x7D, 0x8A, 0x87, 0x0F, 0xEF, 0xC3, 0x75, 0xEF, 0xCE, 0xD3, 0x9B, 0x49, 0x93, 0x67, 0x71, 0xD2, 0xE4, 0x59, 0x34, 0x1A, 0x4D, 0x04, 0xF0, 0x42, 0x94, 0x65, 0x99, 0x31, 0x31, 0x31, 0xBC, 0x74, 0xE9, 0x12, 0xF7, 0xEF, 0xDF, 0xCF, 0x29, 0x53, 0xA6, 0xD0, 0x66, 0xB3, 0x11, 0x00, 0x05, 0x41, 0xA0, 0x2C, 0xCB, 0x1C, 0x33, 0x66, 0x0C, 0x2B, 0x2A, 0x2A, 0x38, 0x6E, 0xDC, 0x38, 0x4A, 0x92, 0xC4, 0x94, 0x94, 0x14, 0x1E, 0x3F, 0x7E, 0x9C, 0x24, 0x59, 0x54, 0x54, 0x44, 0x83, 0xC1, 0x40, 0x83, 0xC1, 0x10, 0x92, 0x77, 0x7F, 0xD0, 0x68, 0x34, 0x71, 0xD2, 0xE4, 0x59, 0x14, 0x26, 0x4D, 0x9E, 0xC5, 0x7B, 0xF7, 0x6E, 0xE3, 0xE6, 0x8D, 0x32, 0xBD, 0x91, 0x7A, 0x8C, 0x11, 0x23, 0x46, 0xA0, 0xA0, 0xA0, 0x00, 0x55, 0x55, 0x55, 0xB0, 0x5A, 0xAD, 0xF8, 0xF5, 0xD7, 0x5F, 0xE1, 0xF3, 0xF9, 0x90, 0x91, 0x91, 0x81, 0xCC, 0xCC, 0x4C, 0x98, 0xCD, 0x66, 0x14, 0x17, 0x17, 0xC3, 0xE5, 0x72, 0x21, 0x3D, 0x3D, 0x1D, 0x24, 0x11, 0x1F, 0x1F, 0x8F, 0x4F, 0x3E, 0xF9, 0x04, 0xDB, 0xB6, 0x6D, 0x83, 0x24, 0x49, 0x5A, 0xCD, 0xAB, 0x53, 0xD1, 0xFE, 0xC2, 0x90, 0xA1, 0x23, 0x9E, 0x36, 0x7B, 0x97, 0xAB, 0x5A, 0xFF, 0xAC, 0xDB, 0x90, 0x65, 0x19, 0x68, 0xEB, 0xBF, 0xD7, 0xAF, 0x5F, 0x87, 0xCB, 0xE5, 0x82, 0x28, 0x8A, 0xD8, 0xBD, 0x7B, 0x37, 0x66, 0xCF, 0x9E, 0x8D, 0x35, 0x6B, 0xD6, 0x20, 0x3E, 0x3E, 0x1E, 0xE7, 0xCF, 0x9F, 0xC7, 0xA9, 0x53, 0xA7, 0x00, 0x00, 0x63, 0xC7, 0x8E, 0x45, 0x7C, 0x7C, 0x3C, 0xEC, 0x76, 0x3B, 0x5A, 0x5A, 0x5A, 0x60, 0x32, 0x99, 0x20, 0x49, 0x12, 0x44, 0x51, 0x84, 0x24, 0x49, 0x5A, 0x97, 0x51, 0xA1, 0xBF, 0xEF, 0x0B, 0xB8, 0x5C, 0xD5, 0xC0, 0xB8, 0x71, 0xAF, 0x85, 0x34, 0x8B, 0x9E, 0x50, 0x10, 0x04, 0x9A, 0x4C, 0x26, 0xCA, 0xB2, 0xCC, 0x4D, 0x9B, 0x36, 0x91, 0x24, 0x7F, 0xF9, 0xE5, 0x17, 0x02, 0xE0, 0xF2, 0xE5, 0xCB, 0xF9, 0xF3, 0xCF, 0x3F, 0x53, 0x51, 0x14, 0xAD, 0x49, 0x2B, 0x8A, 0xC2, 0xE8, 0xE8, 0x68, 0x8E, 0x1F, 0x3F, 0x9E, 0x17, 0x2F, 0x5E, 0xA4, 0xDF, 0xEF, 0x67, 0x53, 0x53, 0x13, 0xD7, 0xAE, 0x5D, 0xCB, 0xC8, 0xC8, 0x48, 0x2A, 0x8A, 0x42, 0xB3, 0xD9, 0x4C, 0x41, 0x10, 0xB4, 0xFC, 0x01, 0x50, 0x14, 0xC5, 0x90, 0x6F, 0xF7, 0x9A, 0x69, 0x69, 0xC3, 0x43, 0x85, 0x3D, 0xA0, 0xDA, 0xDF, 0x4F, 0x9F, 0x3E, 0x4D, 0xBF, 0xDF, 0xCF, 0xDD, 0xBB, 0x77, 0x33, 0x23, 0x23, 0x83, 0x76, 0xBB, 0x9D, 0x89, 0x89, 0x89, 0xDC, 0xB2, 0x65, 0x0B, 0xCD, 0x66, 0x73, 0x48, 0x7F, 0x16, 0x45, 0x91, 0x07, 0x0F, 0x1E, 0xE4, 0xBA, 0x75, 0xEB, 0x78, 0xEC, 0xD8, 0x31, 0xBA, 0xDD, 0x6E, 0x56, 0x55, 0x55, 0x71, 0xEA, 0xD4, 0xA9, 0x04, 0x40, 0x49, 0x92, 0x68, 0x34, 0x1A, 0xB5, 0xB4, 0x16, 0x8B, 0x25, 0xE4, 0xDB, 0xBD, 0x66, 0x4C, 0x4C, 0x5C, 0xA8, 0xB0, 0x07, 0x0C, 0x0F, 0x0F, 0x67, 0x61, 0x61, 0x21, 0xFD, 0x7E, 0x3F, 0x73, 0x72, 0x72, 0x88, 0x36, 0x83, 0xC8, 0xB2, 0x4C, 0x00, 0x1C, 0x3E, 0x7C, 0x38, 0x6D, 0x36, 0x5B, 0x50, 0xCD, 0x89, 0xA2, 0xC8, 0xC4, 0xC4, 0x44, 0x8E, 0x18, 0x31, 0x82, 0x92, 0x24, 0x51, 0x96, 0x65, 0xE6, 0xE7, 0xE7, 0xB3, 0xB9, 0xB9, 0x99, 0x37, 0x6F, 0xDE, 0xE4, 0xB0, 0x61, 0xC3, 0xB4, 0xB4, 0x4E, 0xA7, 0x93, 0xF9, 0xF9, 0xF9, 0xB4, 0xDB, 0xED, 0x54, 0x14, 0x25, 0xE4, 0xFB, 0xBD, 0xA2, 0xD9, 0x6C, 0x0D, 0x15, 0x3E, 0x87, 0xA2, 0x28, 0x52, 0x51, 0x14, 0x4A, 0x92, 0xC4, 0xF8, 0xF8, 0x78, 0x2E, 0x5B, 0xB6, 0x8C, 0x05, 0x05, 0x05, 0x24, 0xC9, 0xDC, 0xDC, 0x5C, 0x0A, 0x82, 0x10, 0x42, 0x7D, 0x1E, 0xFA, 0xE7, 0x6A, 0x7E, 0x00, 0x98, 0x9D, 0x9D, 0x4D, 0xAF, 0xD7, 0xCB, 0x5B, 0xB7, 0x6E, 0x71, 0xF1, 0xE2, 0xC5, 0x5C, 0xB3, 0x66, 0x0D, 0x4B, 0x4B, 0x4B, 0x39, 0x77, 0xEE, 0x5C, 0x02, 0xD0, 0x5A, 0x42, 0x9F, 0x51, 0x96, 0x3B, 0xB7, 0x66, 0x64, 0x64, 0x24, 0x87, 0x0C, 0x19, 0xC2, 0x91, 0x23, 0x47, 0x72, 0xD0, 0xA0, 0x41, 0x8C, 0x8D, 0x8D, 0xA5, 0xC3, 0xE1, 0x60, 0x6C, 0x6C, 0x2C, 0x8F, 0x1E, 0x3D, 0x4A, 0x92, 0xAC, 0xAF, 0xAF, 0xE7, 0xB4, 0x69, 0xD3, 0x28, 0xCB, 0x72, 0x88, 0x72, 0x5D, 0x51, 0x55, 0xDC, 0x6C, 0x36, 0x13, 0x00, 0x57, 0xAC, 0x58, 0x41, 0x92, 0x2C, 0x28, 0x28, 0x60, 0x55, 0x55, 0x15, 0xBF, 0xFC, 0xF2, 0x4B, 0x8A, 0xA2, 0x48, 0x49, 0x92, 0xFA, 0xBC, 0xE6, 0x05, 0x41, 0x10, 0xD8, 0xD9, 0x90, 0x62, 0x34, 0x1A, 0x91, 0x91, 0x91, 0x81, 0xDC, 0xDC, 0x5C, 0x4C, 0x9C, 0x38, 0x11, 0xA9, 0xA9, 0xA9, 0x68, 0x6A, 0x6A, 0x82, 0xCD, 0x66, 0x43, 0x43, 0x43, 0x03, 0xCE, 0x9D, 0x3B, 0x87, 0xF8, 0xF8, 0x78, 0x98, 0x4C, 0x26, 0x6C, 0xDC, 0xB8, 0x11, 0x17, 0x2E, 0x5C, 0xD0, 0x67, 0xD1, 0x29, 0xD4, 0x6F, 0x8B, 0xA2, 0x88, 0x51, 0xA3, 0x46, 0xE1, 0xD0, 0xA1, 0x43, 0xB0, 0x5A, 0xAD, 0x38, 0x72, 0xE4, 0x08, 0x66, 0xCF, 0x9E, 0x8D, 0x15, 0x2B, 0x56, 0xA0, 0xB4, 0xB4, 0x14, 0x82, 0x20, 0xC0, 0xE7, 0xF3, 0x85, 0x4C, 0x7D, 0x3B, 0x2B, 0x7B, 0x77, 0x10, 0x62, 0x91, 0xF6, 0x54, 0x6B, 0x46, 0x10, 0x04, 0x3A, 0x1C, 0x0E, 0x6E, 0xD8, 0xB0, 0x81, 0x24, 0x59, 0x56, 0x56, 0xC6, 0xD8, 0xD8, 0x58, 0x46, 0x46, 0x46, 0xD2, 0x6C, 0x36, 0x33, 0x32, 0x32, 0x92, 0x83, 0x07, 0x0F, 0x0E, 0xA9, 0xD9, 0xAE, 0xD8, 0xBE, 0xE6, 0x17, 0x2F, 0x5E, 0xCC, 0x77, 0xDE, 0x79, 0x87, 0x73, 0xE7, 0xCE, 0xA5, 0xCB, 0xE5, 0x62, 0x75, 0x75, 0x35, 0x13, 0x12, 0x12, 0x88, 0xB6, 0x51, 0x42, 0x92, 0xA4, 0x90, 0xF7, 0xF5, 0xE5, 0xED, 0x21, 0x43, 0x04, 0x44, 0x07, 0x7D, 0x53, 0x14, 0x45, 0x8D, 0xFB, 0xF6, 0xED, 0x23, 0x49, 0xAE, 0x5B, 0xB7, 0x4E, 0x6B, 0x8A, 0xFA, 0xF4, 0x2F, 0x4A, 0xB4, 0x39, 0xCC, 0xC9, 0x93, 0x27, 0x33, 0x10, 0x08, 0x70, 0xC6, 0x8C, 0x19, 0x04, 0x10, 0x32, 0x5A, 0xF4, 0x05, 0x7B, 0x3C, 0x73, 0x90, 0x24, 0x09, 0xD5, 0xD5, 0x4F, 0x27, 0x45, 0x37, 0x6E, 0xDC, 0xD0, 0x3F, 0xEE, 0x35, 0x24, 0x49, 0x82, 0xD1, 0x68, 0x44, 0x49, 0x49, 0x09, 0xEE, 0xDD, 0xBB, 0x87, 0x79, 0xF3, 0xE6, 0x69, 0x6B, 0xFD, 0xFE, 0x40, 0x88, 0x45, 0xD0, 0x41, 0x4D, 0xAA, 0xB5, 0x2E, 0x08, 0x02, 0xAF, 0x5C, 0xB9, 0xC2, 0xEA, 0xEA, 0x6A, 0x5A, 0x2C, 0x16, 0x2A, 0x8A, 0x12, 0x92, 0xB6, 0x37, 0x6C, 0x3F, 0xBE, 0x17, 0x16, 0x16, 0xB2, 0xAC, 0xAC, 0x8C, 0xE1, 0xE1, 0xE1, 0x21, 0xE5, 0xEB, 0x0B, 0xF6, 0xB8, 0xE6, 0xB3, 0xB3, 0xB3, 0x91, 0x95, 0x95, 0x85, 0xDF, 0x7E, 0xFB, 0x0D, 0x8F, 0x1F, 0x3F, 0xEE, 0xB5, 0xC3, 0xD1, 0xA3, 0xB5, 0xB5, 0x15, 0xAD, 0xAD, 0xAD, 0x10, 0x45, 0x11, 0x15, 0x15, 0x15, 0x48, 0x49, 0x49, 0x41, 0x54, 0x54, 0x94, 0xB6, 0x74, 0xEE, 0x4B, 0x3C, 0x57, 0x79, 0x92, 0x20, 0xA9, 0xAD, 0xC3, 0x03, 0x81, 0x00, 0x2C, 0x16, 0x0B, 0xEA, 0xEA, 0xEA, 0x50, 0x5A, 0x5A, 0x0A, 0x51, 0x14, 0xFB, 0x7C, 0xBE, 0x8D, 0xB6, 0xD1, 0x45, 0x10, 0x04, 0xC4, 0xC5, 0xC5, 0x21, 0x3E, 0x3E, 0x1E, 0x06, 0x83, 0x01, 0x1B, 0x36, 0x6C, 0x80, 0xD5, 0x6A, 0x85, 0xD7, 0xFB, 0x34, 0xEA, 0xDA, 0x57, 0xE8, 0x56, 0xE9, 0xFD, 0x7E, 0x3F, 0x00, 0xC0, 0xED, 0x76, 0xA3, 0xAE, 0xAE, 0x0E, 0x83, 0x07, 0x0F, 0x46, 0x63, 0x63, 0x23, 0x02, 0x81, 0x00, 0x02, 0x81, 0x80, 0x3E, 0x79, 0xAF, 0xE0, 0xF1, 0x78, 0x90, 0x90, 0x90, 0x80, 0x4D, 0x9B, 0x36, 0x21, 0x3B, 0x3B, 0x1B, 0x6F, 0xBE, 0xF9, 0x26, 0xAC, 0x56, 0x2B, 0x6E, 0xDC, 0xB8, 0x81, 0x23, 0x47, 0x8E, 0x20, 0x3F, 0x3F, 0x1F, 0xE9, 0xE9, 0xE9, 0xB0, 0x5A, 0xAD, 0x5D, 0x06, 0x50, 0xBA, 0x42, 0x97, 0xCA, 0x9B, 0x4C, 0x26, 0xAD, 0x69, 0x4F, 0x9D, 0x3A, 0x15, 0xC7, 0x8F, 0x1F, 0x47, 0x53, 0x53, 0x13, 0x22, 0x22, 0x22, 0xB4, 0x15, 0x9D, 0x7E, 0xEC, 0xED, 0x2D, 0xAA, 0xAB, 0xAB, 0xB1, 0x71, 0xE3, 0x46, 0x5C, 0xBB, 0x76, 0x0D, 0xEB, 0xD7, 0xAF, 0x47, 0x4A, 0x4A, 0x0A, 0x0A, 0x0A, 0x0A, 0x50, 0x5E, 0xFE, 0x2C, 0x0A, 0xD3, 0x57, 0x08, 0x71, 0x04, 0x7A, 0x66, 0x65, 0x65, 0xF1, 0xE4, 0xC9, 0x93, 0x24, 0xC9, 0x3B, 0x77, 0xEE, 0x70, 0xE7, 0xCE, 0x9D, 0xDC, 0xB5, 0x6B, 0x97, 0x16, 0x98, 0x68, 0x3F, 0x17, 0xE8, 0x2D, 0xD1, 0x6E, 0x58, 0x3B, 0x71, 0xE2, 0x04, 0x1B, 0x1B, 0x1B, 0x39, 0x7F, 0xFE, 0xFC, 0x90, 0x32, 0xF5, 0x05, 0x85, 0xB6, 0x8B, 0xE7, 0x62, 0xCC, 0x98, 0x31, 0x98, 0x39, 0x73, 0x26, 0x3C, 0x1E, 0x0F, 0xAE, 0x5D, 0xBB, 0x86, 0xC4, 0xC4, 0x44, 0x6C, 0xDB, 0xB6, 0x0D, 0x82, 0x20, 0xE0, 0xD0, 0xA1, 0x43, 0xD8, 0xB7, 0x6F, 0x1F, 0x6E, 0xDF, 0xBE, 0x0D, 0x9F, 0xCF, 0x07, 0x45, 0x51, 0xB4, 0x2E, 0xF2, 0xA2, 0x50, 0x5B, 0x91, 0xC5, 0x62, 0x41, 0x45, 0x45, 0x05, 0x2E, 0x5C, 0xB8, 0x80, 0xBC, 0xBC, 0x3C, 0x98, 0xCD, 0xE6, 0x7E, 0x71, 0xB0, 0x21, 0x16, 0x69, 0x4F, 0x75, 0x8D, 0xAD, 0xDE, 0x4B, 0x92, 0xC4, 0x25, 0x4B, 0x96, 0x30, 0x10, 0x08, 0x70, 0xC5, 0x8A, 0x15, 0x44, 0xDB, 0xEC, 0x4B, 0xB3, 0x66, 0x07, 0xB5, 0xD9, 0x13, 0xAA, 0x73, 0xF8, 0x9C, 0x9C, 0x1C, 0xBA, 0xDD, 0x6E, 0x2E, 0x59, 0xB2, 0x84, 0xE1, 0xE1, 0xE1, 0x7D, 0x3E, 0xAF, 0x6F, 0x63, 0x88, 0x20, 0x88, 0x92, 0x24, 0x69, 0xF1, 0x35, 0xF5, 0x3A, 0x3A, 0x3A, 0x9A, 0x0D, 0x0D, 0x0D, 0x2C, 0x2C, 0x2C, 0xA4, 0xC9, 0x64, 0xEA, 0xD3, 0x66, 0x9F, 0x96, 0x96, 0xC6, 0x95, 0x2B, 0x57, 0xF2, 0xF6, 0xED, 0xDB, 0x2C, 0x2F, 0x2F, 0x67, 0x6C, 0x6C, 0x6C, 0x7F, 0x29, 0xCE, 0x2E, 0x95, 0xD7, 0x53, 0x9D, 0x80, 0x7C, 0xFE, 0xF9, 0xE7, 0x24, 0xA9, 0x4D, 0x3F, 0x55, 0xC3, 0xE8, 0x95, 0xE9, 0x29, 0x47, 0x8E, 0x1C, 0xC9, 0x33, 0x67, 0xCE, 0xB0, 0xB8, 0xB8, 0x98, 0x16, 0x8B, 0x85, 0x26, 0xD3, 0xB3, 0xC0, 0xAA, 0xD0, 0xFB, 0xB9, 0xBC, 0x9E, 0x21, 0x82, 0x4E, 0xA9, 0x16, 0x20, 0x27, 0x27, 0x87, 0x77, 0xEF, 0xDE, 0xE5, 0xB5, 0x6B, 0xD7, 0x18, 0x15, 0x15, 0xA5, 0x3D, 0x57, 0x14, 0x25, 0x68, 0xDD, 0xAD, 0x57, 0x4E, 0x4F, 0x87, 0xC3, 0x41, 0x45, 0x51, 0xB4, 0x16, 0x14, 0x15, 0x15, 0x45, 0x97, 0xCB, 0xC5, 0x65, 0xCB, 0x96, 0x31, 0x21, 0x21, 0x81, 0x0E, 0x87, 0x43, 0xCB, 0x57, 0x0D, 0x90, 0xF4, 0x21, 0x43, 0x04, 0x5D, 0x52, 0xF5, 0xC6, 0xB3, 0x66, 0xCD, 0x22, 0x49, 0x16, 0x17, 0x17, 0x33, 0x37, 0x37, 0x97, 0x13, 0x26, 0x4C, 0xE0, 0xE6, 0xCD, 0x9B, 0x69, 0xB7, 0xDB, 0xB5, 0xB4, 0x7A, 0x65, 0xF5, 0xFC, 0xF0, 0xC3, 0x0F, 0x39, 0x6D, 0xDA, 0x34, 0x02, 0xA0, 0xDD, 0x6E, 0x67, 0x51, 0x51, 0x11, 0xBD, 0x5E, 0x2F, 0x57, 0xAF, 0x5E, 0xCD, 0x35, 0x6B, 0xD6, 0x68, 0x01, 0x14, 0xF4, 0x43, 0x1C, 0xAF, 0x4B, 0x6F, 0xAF, 0x87, 0xC9, 0xF4, 0x74, 0xBB, 0xD7, 0xEB, 0xF5, 0xE2, 0xC0, 0x81, 0x03, 0xF0, 0xFB, 0xFD, 0x50, 0x14, 0x05, 0xD3, 0xA7, 0x4F, 0x07, 0x49, 0xFC, 0xF9, 0xE7, 0x9F, 0xC8, 0xCB, 0xCB, 0x83, 0x28, 0x8A, 0xF0, 0x78, 0x3C, 0x5D, 0x7A, 0xE7, 0x8F, 0x3E, 0xFA, 0x08, 0x79, 0x79, 0x79, 0x28, 0x2B, 0x2B, 0x43, 0x66, 0x66, 0x26, 0x92, 0x93, 0x93, 0x51, 0x52, 0x52, 0x82, 0xDB, 0xB7, 0x6F, 0x03, 0x00, 0x16, 0x2E, 0x5C, 0x08, 0x8B, 0xC5, 0x02, 0xB7, 0xDB, 0x0D, 0x59, 0x96, 0xD1, 0xDC, 0xDC, 0xAC, 0xCF, 0xE2, 0x85, 0xD1, 0xE5, 0x24, 0x47, 0x0F, 0xAF, 0xD7, 0x0B, 0xB7, 0xDB, 0x8D, 0x45, 0x8B, 0x16, 0x61, 0xE9, 0xD2, 0xA5, 0x48, 0x4B, 0x4B, 0x83, 0xC5, 0x62, 0x41, 0x20, 0x10, 0x80, 0xD3, 0xE9, 0x44, 0x54, 0x54, 0x14, 0x6C, 0x36, 0x5B, 0xB7, 0x0B, 0x49, 0x12, 0x3E, 0x9F, 0x0F, 0x63, 0xC7, 0x8E, 0xC5, 0x3F, 0xFF, 0xFC, 0x83, 0xA1, 0x43, 0x87, 0xE2, 0xC0, 0x81, 0x03, 0x78, 0xED, 0xB5, 0xD7, 0xF0, 0xFA, 0xEB, 0xAF, 0x63, 0xD8, 0xB0, 0x61, 0x68, 0x6C, 0x6C, 0xC4, 0xE8, 0xD1, 0xA3, 0xB1, 0x61, 0xC3, 0x06, 0xFD, 0xEB, 0xBD, 0x82, 0x04, 0xE0, 0xBF, 0x7A, 0x61, 0x67, 0x20, 0x89, 0xAC, 0xAC, 0x2C, 0x2C, 0x5D, 0xBA, 0x14, 0x07, 0x0E, 0x1C, 0xC0, 0x77, 0xDF, 0x7D, 0x87, 0x5B, 0xB7, 0x6E, 0xA1, 0xA1, 0xA1, 0x01, 0xD1, 0xD1, 0xD1, 0x48, 0x4F, 0x4F, 0xC7, 0xFC, 0xF9, 0xF3, 0x11, 0x1D, 0x1D, 0x0D, 0x92, 0xF0, 0xFB, 0x9F, 0xFE, 0x06, 0x12, 0x11, 0x11, 0x81, 0xF0, 0xF0, 0x70, 0xCD, 0x28, 0x26, 0x93, 0x09, 0xE3, 0xC6, 0x8D, 0xC3, 0x9E, 0x3D, 0x7B, 0x50, 0x5A, 0x5A, 0x8A, 0x9D, 0x3B, 0x77, 0xE2, 0xFB, 0xEF, 0xBF, 0x47, 0x65, 0x65, 0x25, 0x4A, 0x4A, 0x4A, 0x20, 0x08, 0x02, 0x72, 0x73, 0x73, 0x91, 0x93, 0x93, 0x83, 0xF4, 0xF4, 0x74, 0xEC, 0xDD, 0xBB, 0x17, 0x67, 0xCE, 0x9C, 0xC1, 0xC5, 0x8B, 0x17, 0xA1, 0x28, 0x4A, 0x9F, 0x6D, 0x6B, 0x85, 0xF4, 0x85, 0xCE, 0xA8, 0x28, 0x0A, 0x87, 0x0F, 0x1F, 0xDE, 0xE1, 0x32, 0xD3, 0x64, 0x32, 0x71, 0xD5, 0xAA, 0x55, 0x6C, 0x6E, 0x6E, 0xA6, 0xDB, 0xED, 0x26, 0x49, 0x7A, 0x3C, 0x1E, 0x56, 0x54, 0x54, 0xF0, 0xD6, 0xAD, 0x5B, 0x5C, 0xBF, 0x7E, 0x3D, 0xC7, 0x8F, 0x1F, 0xCF, 0x5D, 0xBB, 0x76, 0xF1, 0x8F, 0x3F, 0xFE, 0x60, 0x53, 0x53, 0x13, 0x49, 0xB2, 0xB6, 0xB6, 0x96, 0xB5, 0xB5, 0xB5, 0x5A, 0x84, 0x68, 0xED, 0xDA, 0xB5, 0x3C, 0x7C, 0xF8, 0x30, 0x49, 0xB2, 0xB1, 0xB1, 0x91, 0x1E, 0x8F, 0x87, 0x77, 0xEF, 0xDE, 0xD5, 0x7C, 0x83, 0x1A, 0xEF, 0xEB, 0x2D, 0x7B, 0xDC, 0xE7, 0x55, 0xA8, 0x7F, 0x51, 0x48, 0x92, 0x04, 0x00, 0x08, 0x0B, 0x0B, 0x83, 0x20, 0x08, 0x08, 0x0B, 0x0B, 0xC3, 0x89, 0x13, 0x27, 0x90, 0x98, 0x98, 0x88, 0xA2, 0xA2, 0x22, 0xDC, 0xB8, 0x71, 0x03, 0x33, 0x67, 0xCE, 0xC4, 0xD4, 0xA9, 0x53, 0xB5, 0xE7, 0x4D, 0x4D, 0x4D, 0x70, 0xBB, 0xDD, 0x08, 0x0B, 0x0B, 0x43, 0x44, 0x44, 0x04, 0xF6, 0xEC, 0xD9, 0x83, 0xB3, 0x67, 0xCF, 0xC2, 0xE9, 0x74, 0xE2, 0xAD, 0xB7, 0xDE, 0xC2, 0xF4, 0xE9, 0xD3, 0x51, 0x5A, 0x5A, 0x0A, 0x45, 0x51, 0x10, 0x1E, 0x1E, 0x8E, 0xBD, 0x7B, 0xF7, 0x62, 0xE1, 0xC2, 0x85, 0xF8, 0xE9, 0xA7, 0x9F, 0xB0, 0x75, 0xEB, 0x56, 0x18, 0x0C, 0x06, 0x78, 0x3C, 0x1E, 0x7D, 0x91, 0x5E, 0x08, 0x21, 0x16, 0xE9, 0x8C, 0x4A, 0xBB, 0xDD, 0x17, 0x95, 0x26, 0x93, 0x89, 0x42, 0x5B, 0xC0, 0x23, 0x2D, 0x2D, 0x8D, 0x97, 0x2F, 0x5F, 0xE6, 0x84, 0x09, 0x13, 0x28, 0x08, 0x82, 0x36, 0xEC, 0x2D, 0x5D, 0xBA, 0x94, 0xEF, 0xBE, 0xFB, 0x2E, 0xB3, 0xB2, 0xB2, 0x68, 0xB5, 0x5A, 0x69, 0xB3, 0xD9, 0xF8, 0xE3, 0x8F, 0x3F, 0xB2, 0xBE, 0xBE, 0x9E, 0x71, 0x71, 0x71, 0x5A, 0x5A, 0x51, 0x14, 0xF9, 0xDE, 0x7B, 0xEF, 0xB1, 0xAC, 0xAC, 0x8C, 0x35, 0x35, 0x35, 0x3C, 0x7C, 0xF8, 0x30, 0x01, 0x70, 0xF3, 0xE6, 0xCD, 0xF4, 0xFB, 0xFD, 0xCC, 0xCC, 0xCC, 0xD4, 0xBE, 0xA9, 0x2F, 0xDB, 0x0B, 0x30, 0x44, 0xD0, 0x29, 0xF5, 0x43, 0x55, 0xFB, 0xD8, 0x9E, 0x28, 0x8A, 0xCC, 0xCB, 0xCB, 0xD3, 0x26, 0x3E, 0x6A, 0xD0, 0x51, 0x6A, 0xDB, 0x98, 0x90, 0x65, 0x99, 0x8A, 0xA2, 0x68, 0x06, 0x34, 0x18, 0x0C, 0x3C, 0x77, 0xEE, 0x1C, 0x57, 0xAE, 0x5C, 0x19, 0x62, 0xA8, 0x2D, 0x5B, 0xB6, 0x90, 0x24, 0xB7, 0x6F, 0xDF, 0xAE, 0x85, 0xC4, 0x8B, 0x8A, 0x8A, 0x58, 0x57, 0x57, 0xC7, 0xD1, 0xA3, 0x47, 0x6B, 0x11, 0x1F, 0x75, 0xF8, 0x6B, 0x5F, 0x26, 0x7D, 0x99, 0x3B, 0x61, 0x88, 0xA0, 0x53, 0x76, 0xA5, 0x7C, 0x46, 0x46, 0x46, 0x87, 0xFE, 0x40, 0x9F, 0x5E, 0x35, 0x4A, 0x4A, 0x4A, 0x0A, 0x37, 0x6D, 0xDA, 0xA4, 0xBD, 0x63, 0x34, 0x1A, 0xB5, 0x3E, 0xFD, 0xCD, 0x37, 0xDF, 0xF0, 0x87, 0x1F, 0x7E, 0xD0, 0xD2, 0x1B, 0x8D, 0x46, 0x16, 0x16, 0x16, 0xB2, 0xBE, 0xBE, 0x3E, 0x68, 0x45, 0xD9, 0x43, 0x85, 0xDB, 0x33, 0x44, 0xD0, 0x29, 0xBB, 0x52, 0x1E, 0x3D, 0xDC, 0x59, 0x31, 0x18, 0x0C, 0x8C, 0x8B, 0x8B, 0x63, 0x52, 0x52, 0x92, 0xA6, 0x84, 0xDA, 0xA4, 0xBF, 0xFE, 0xFA, 0x6B, 0x5E, 0xBE, 0x7C, 0x39, 0x48, 0x06, 0x80, 0xE7, 0xCF, 0x9F, 0x67, 0x7D, 0x7D, 0x3D, 0x47, 0x8F, 0x1E, 0xAD, 0xBD, 0xA3, 0x96, 0xA5, 0x87, 0x86, 0x08, 0x11, 0x74, 0x4A, 0xBD, 0xF2, 0x7A, 0xAA, 0x46, 0x10, 0xDA, 0x56, 0x68, 0xEA, 0xF5, 0xF3, 0x0A, 0x25, 0xB6, 0xDB, 0x02, 0x43, 0x5B, 0xD8, 0x1A, 0x00, 0x63, 0x62, 0x62, 0x78, 0xF7, 0xEE, 0x5D, 0x3E, 0x7C, 0xF8, 0x90, 0xE9, 0xE9, 0xE9, 0xB4, 0x58, 0x2C, 0x41, 0x46, 0x55, 0x5B, 0x40, 0x56, 0x56, 0x16, 0xD1, 0x66, 0x70, 0xA7, 0xD3, 0x19, 0xE2, 0x8F, 0xBA, 0x60, 0x88, 0xA0, 0x53, 0xEA, 0x15, 0xD1, 0x2B, 0xAF, 0xCA, 0xD5, 0x56, 0xF0, 0x3C, 0xA5, 0xF5, 0x54, 0xD3, 0x19, 0x0C, 0x06, 0x2A, 0x8A, 0xC2, 0x63, 0xC7, 0x8E, 0xB1, 0xA9, 0xA9, 0x89, 0xF5, 0xF5, 0xF5, 0x0C, 0x04, 0x02, 0xFC, 0xE0, 0x83, 0x0F, 0x82, 0x7C, 0x86, 0xD1, 0x68, 0xE4, 0x99, 0x33, 0x67, 0x58, 0x53, 0x53, 0xC3, 0x39, 0x73, 0xE6, 0x70, 0xFD, 0xFA, 0xF5, 0xDC, 0xBE, 0x7D, 0xBB, 0xF6, 0xDD, 0x6E, 0xB1, 0xBB, 0x85, 0x53, 0xA9, 0x57, 0xF2, 0x79, 0xEC, 0x4E, 0x1A, 0x7D, 0x7A, 0x95, 0xC9, 0xC9, 0xC9, 0x5C, 0xBE, 0x7C, 0x39, 0x27, 0x4C, 0x98, 0xC0, 0xEC, 0xEC, 0x6C, 0x6D, 0x54, 0x18, 0x37, 0x6E, 0x1C, 0xD1, 0xB6, 0x33, 0x2C, 0x49, 0x12, 0xAD, 0x56, 0x2B, 0x0B, 0x0B, 0x0B, 0x49, 0x92, 0x7E, 0xBF, 0x9F, 0x79, 0x79, 0x79, 0x21, 0xF9, 0x76, 0xCA, 0xAE, 0x36, 0x2A, 0xF5, 0xEC, 0x6F, 0xE5, 0xD5, 0x66, 0x6B, 0x32, 0x99, 0xB4, 0x2E, 0x01, 0x80, 0x9F, 0x7E, 0xFA, 0x29, 0x2B, 0x2B, 0x2B, 0xE9, 0x74, 0x3A, 0x35, 0x87, 0xA8, 0x28, 0x0A, 0x93, 0x92, 0x92, 0x78, 0xF0, 0xE0, 0x41, 0x16, 0x17, 0x17, 0x73, 0xF2, 0xE4, 0xC9, 0x21, 0xF9, 0x76, 0xCA, 0x9E, 0x6C, 0x51, 0xA3, 0x9F, 0x95, 0x57, 0xAF, 0xF5, 0xC1, 0x0B, 0xB5, 0xAF, 0x1F, 0x3C, 0x78, 0x90, 0xBF, 0xFF, 0xFE, 0x3B, 0x4D, 0x26, 0x93, 0x36, 0xB7, 0x30, 0x9B, 0xCD, 0x54, 0x14, 0x85, 0x95, 0x95, 0x95, 0xDC, 0xBA, 0x75, 0x6B, 0x48, 0xBE, 0x9D, 0xB2, 0xB7, 0x3F, 0x27, 0xF4, 0x96, 0xED, 0x9B, 0xBB, 0xFE, 0x5E, 0x95, 0x19, 0x0C, 0x06, 0xAD, 0xA9, 0xDF, 0xBC, 0x79, 0x93, 0x5F, 0x7D, 0xF5, 0x95, 0x26, 0x17, 0xDA, 0x9C, 0xEC, 0xC7, 0x1F, 0x7F, 0x4C, 0x97, 0xCB, 0xA5, 0x39, 0xCE, 0xEE, 0x50, 0x8A, 0x8B, 0x1B, 0xF4, 0xDF, 0x47, 0x8F, 0x7A, 0xFE, 0xFF, 0x5D, 0x5F, 0xA1, 0x7D, 0xD8, 0xBB, 0xA3, 0x10, 0xB8, 0xD0, 0xF6, 0x4F, 0x9F, 0xD7, 0xEB, 0x05, 0x49, 0xA4, 0xA7, 0xA7, 0x63, 0xC8, 0x90, 0x21, 0x68, 0x69, 0x69, 0x41, 0x79, 0x79, 0x39, 0x5A, 0x5A, 0x5A, 0x40, 0x12, 0x95, 0x95, 0x95, 0xC8, 0xCF, 0xCF, 0x47, 0x72, 0x72, 0x32, 0x6A, 0x6B, 0x6B, 0x11, 0x15, 0x15, 0x85, 0x07, 0x0F, 0x1E, 0x74, 0xBA, 0xA4, 0x16, 0xED, 0x76, 0x87, 0x5E, 0xF6, 0xD2, 0x41, 0xDD, 0xA4, 0x8C, 0x8B, 0x8B, 0xC3, 0xF4, 0xE9, 0xD3, 0x91, 0x94, 0x94, 0x84, 0x23, 0x47, 0x8E, 0x60, 0xC6, 0x8C, 0x19, 0x00, 0x00, 0x87, 0xC3, 0x81, 0xFB, 0xF7, 0xEF, 0xE3, 0xDB, 0x6F, 0xBF, 0x45, 0x6A, 0x6A, 0x2A, 0x76, 0xEC, 0xD8, 0x01, 0xA7, 0xD3, 0xD9, 0xE5, 0x86, 0x8A, 0x68, 0x0A, 0x8F, 0x80, 0x35, 0xB2, 0xE3, 0xE3, 0x24, 0x2F, 0x03, 0xD8, 0x76, 0x2C, 0x44, 0x92, 0x24, 0xBC, 0xF2, 0xCA, 0x2B, 0xD8, 0xB1, 0x63, 0x07, 0xE6, 0xCD, 0x9B, 0x87, 0xD5, 0xAB, 0x57, 0xE3, 0x8B, 0x2F, 0xBE, 0xC0, 0xAA, 0x55, 0xAB, 0xF0, 0xF8, 0xF1, 0x63, 0x7C, 0xF6, 0xD9, 0x67, 0x78, 0xF4, 0xE8, 0x11, 0xB6, 0x6E, 0xDD, 0x8A, 0x98, 0x98, 0x18, 0xFC, 0xFD, 0xF7, 0xDF, 0xDA, 0xA2, 0xAB, 0x23, 0x58, 0x23, 0x6D, 0x4F, 0xFF, 0xC0, 0x1C, 0x32, 0x74, 0x44, 0x48, 0x7F, 0xF8, 0xB7, 0xA8, 0xEF, 0xE3, 0x7A, 0xB6, 0x4F, 0xA3, 0x5E, 0xAB, 0x53, 0x5D, 0xB3, 0xD9, 0xCC, 0x93, 0x27, 0x4F, 0xF2, 0xD4, 0xA9, 0x53, 0x5C, 0xB0, 0x60, 0x01, 0xB3, 0xB3, 0xB3, 0xD9, 0xD4, 0xD4, 0xC4, 0xD2, 0xD2, 0x52, 0x26, 0x26, 0x26, 0x76, 0x9A, 0xFF, 0x90, 0xA1, 0x23, 0x9E, 0xEE, 0xD2, 0x0E, 0x1C, 0x38, 0x28, 0xE8, 0x34, 0xC2, 0xCB, 0x04, 0xBD, 0x1F, 0x50, 0x37, 0x50, 0x5B, 0x5B, 0x5B, 0xE1, 0xF3, 0xF9, 0xB0, 0x68, 0xD1, 0x22, 0xB4, 0xB6, 0xB6, 0xC2, 0x6C, 0x36, 0xE3, 0xF4, 0xE9, 0xD3, 0xB8, 0x7A, 0xF5, 0x2A, 0xE6, 0xCC, 0x99, 0x83, 0x3B, 0x77, 0xEE, 0x3C, 0x77, 0x57, 0xD7, 0x68, 0x34, 0x61, 0xE0, 0xC0, 0x41, 0xCF, 0xC2, 0x58, 0x49, 0x49, 0x29, 0xC1, 0x29, 0x5E, 0x42, 0xA8, 0xCE, 0x2F, 0x10, 0x08, 0xC0, 0xEF, 0xF7, 0xC3, 0xE7, 0xF3, 0x21, 0x21, 0x21, 0x01, 0x35, 0x35, 0x35, 0x78, 0xFB, 0xED, 0xB7, 0x71, 0xE5, 0xCA, 0x15, 0x4C, 0x99, 0x32, 0x05, 0x55, 0x55, 0x55, 0x5A, 0x1A, 0xBD, 0xF1, 0x00, 0x20, 0x31, 0x31, 0xF9, 0x69, 0x7E, 0x93, 0x26, 0xCF, 0xA2, 0x2A, 0x2C, 0xBD, 0x56, 0xFC, 0x42, 0x7F, 0x5E, 0xF7, 0x06, 0x1D, 0x15, 0xAE, 0x2B, 0xB4, 0xF7, 0xE0, 0x31, 0x31, 0x31, 0xF0, 0x7A, 0xBD, 0xF0, 0x78, 0x3C, 0x88, 0x8C, 0x8C, 0x44, 0x6D, 0x6D, 0x2D, 0x48, 0x42, 0x96, 0xE5, 0x0E, 0x95, 0x77, 0x38, 0x9C, 0x18, 0xF1, 0x9F, 0x4C, 0x40, 0x1F, 0xC0, 0x4C, 0x4D, 0x1B, 0x0E, 0xB9, 0x97, 0xDB, 0xBE, 0xFD, 0x0D, 0xFD, 0xD0, 0x55, 0x53, 0x53, 0x83, 0xFA, 0xFA, 0x7A, 0x78, 0x3C, 0x1E, 0xD4, 0xD4, 0xD4, 0x68, 0xCF, 0x3B, 0xDA, 0x33, 0x94, 0x15, 0x05, 0x29, 0xA9, 0xC3, 0xB4, 0xFB, 0x20, 0xE5, 0x8D, 0x46, 0x13, 0x86, 0xBD, 0x3A, 0xAA, 0xBD, 0xE8, 0xA5, 0x82, 0x5E, 0xF1, 0x9E, 0xE2, 0xD5, 0xA1, 0x23, 0x83, 0x7C, 0x5B, 0x48, 0xE8, 0xDA, 0x3E, 0x20, 0x0A, 0xC3, 0x47, 0x64, 0xE8, 0xC5, 0xFF, 0xF3, 0x18, 0x36, 0x3C, 0x3D, 0xF8, 0x84, 0x55, 0x47, 0xCA, 0x03, 0x80, 0xD3, 0x19, 0x83, 0x51, 0xA3, 0xC6, 0xBC, 0xF4, 0x5D, 0xA0, 0x3B, 0x90, 0x15, 0x05, 0x23, 0x47, 0x66, 0xC1, 0xE9, 0x8C, 0xD1, 0x3F, 0x0A, 0x56, 0xBE, 0x7D, 0xA3, 0xB2, 0x0F, 0x88, 0x42, 0x66, 0x66, 0x36, 0x1C, 0x0E, 0x67, 0x3B, 0xE9, 0xFF, 0x2F, 0xF4, 0xCE, 0xAB, 0x2B, 0x38, 0x1C, 0x4E, 0x64, 0x64, 0x8C, 0x0F, 0xAA, 0xF1, 0xF6, 0x3A, 0x06, 0x79, 0xFB, 0xE7, 0xA1, 0x3F, 0x8F, 0x93, 0xF6, 0x54, 0xA1, 0xEE, 0xF4, 0xFB, 0xE7, 0x1E, 0x27, 0xD5, 0xA1, 0x5B, 0xCA, 0xAB, 0xE8, 0x8F, 0x83, 0xC4, 0x7D, 0xA9, 0x7C, 0x67, 0x07, 0x89, 0x3B, 0x42, 0x8F, 0x94, 0x57, 0xD1, 0x97, 0x47, 0xC8, 0x5F, 0x44, 0xF9, 0xA7, 0x9B, 0x1F, 0xDD, 0x3F, 0x42, 0xFE, 0x3C, 0xFC, 0x1F, 0x8A, 0x5D, 0xC6, 0xE5, 0xA7, 0x61, 0xB0, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82};
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
static std::vector<Record> records;
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
static std::atomic<int> totalStages{4};
static std::atomic<size_t> processCount{0}, recordCount{0}, fileCount{0};
static std::wstring executablePath();
static int accentIndex=0, themeIndex=0, densityIndex=1;
static float interfaceScale=1.0f;
static bool highlightSuspicious=true, showSecurityWarnings=true;
static ImVec4 customAccent(.98f,.43f,.15f,1.f);
static bool settingsNotice=false;
static const char* accentNames[]={"Orange","Red","Blue","Purple","Green","Custom"};
static const char* themeNames[]={"Carbon Ember","Dark Graphite","Midnight"};
static const char* densityNames[]={"Compact","Comfortable","Spacious"};
static ImVec4 accentColor() {
    static const ImVec4 palette[]={
        ImVec4(.98f,.43f,.15f,1),ImVec4(.92f,.27f,.31f,1),
        ImVec4(.29f,.57f,.98f,1),ImVec4(.67f,.42f,.95f,1),
        ImVec4(.27f,.77f,.54f,1)};
    return accentIndex==5?customAccent:palette[std::clamp(accentIndex,0,4)];
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
        out<<"accent="<<accentIndex<<"\n"<<"theme="<<themeIndex<<"\n"
           <<"density="<<densityIndex<<"\n"<<"scale="<<interfaceScale<<"\n"
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
            if(key=="accent")accentIndex=std::clamp(std::stoi(v),0,5);
            else if(key=="theme")themeIndex=std::clamp(std::stoi(v),0,2);
            else if(key=="density")densityIndex=std::clamp(std::stoi(v),0,2);
            else if(key=="scale")interfaceScale=std::clamp(std::stof(v),.8f,1.4f);
            else if(key=="highlight")highlightSuspicious=(v=="1");
            else if(key=="warnings")showSecurityWarnings=(v=="1");
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
    DWORD attrs=GetFileAttributesW(process.path.c_str());
    if(attrs!=INVALID_FILE_ATTRIBUTES && (attrs&FILE_ATTRIBUTE_REPARSE_POINT))
        appendWarning(warnings,"Executable path is a reparse point; verify target");
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


// Read-only USBSTOR device inventory. This is not a historical connection timeline.
static std::vector<Record> enumerateUsbStorage() {
    std::vector<Record> out;
    HKEY root=nullptr;
    const wchar_t* key=L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR";
    LONG rc=RegOpenKeyExW(HKEY_LOCAL_MACHINE,key,0,KEY_READ,&root);
    if(rc!=ERROR_SUCCESS) {
        out.push_back({"USB","Unavailable","USBSTOR registry inventory could not be opened"});
        return out;
    }
    for(DWORD i=0;i<512 && !cancelRequested;i++) {
        wchar_t typeName[512]{};
        DWORD n=512;
        LONG result=RegEnumKeyExW(root,i,typeName,&n,nullptr,nullptr,nullptr,nullptr);
        if(result==ERROR_NO_MORE_ITEMS)break;
        if(result!=ERROR_SUCCESS)continue;
        HKEY typeKey=nullptr;
        if(RegOpenKeyExW(root,typeName,0,KEY_READ,&typeKey)!=ERROR_SUCCESS)continue;
        for(DWORD j=0;j<256 && !cancelRequested;j++) {
            wchar_t instance[512]{};
            DWORD count=512;
            LONG r=RegEnumKeyExW(typeKey,j,instance,&count,nullptr,nullptr,nullptr,nullptr);
            if(r==ERROR_NO_MORE_ITEMS)break;
            if(r!=ERROR_SUCCESS)continue;
            out.push_back({"USB",utf8(typeName),utf8(instance)});
        }
        RegCloseKey(typeKey);
    }
    RegCloseKey(root);
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
        detail<<ip<<":"<<(unsigned)ntohs((u_short)e.dwLocalPort);
        out.push_back({"Network UDP","PID "+std::to_string(e.dwOwningPid),detail.str()});
    }
    return out;
}

static void scanWorker() {
    try {
        stage=1;
        auto p=enumerateProcesses();
        const std::wstring winRoot=windowsRoot();
        for(auto& proc:p) {
            if(cancelRequested)break;
            assessProcess(proc,winRoot);
        }
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        completedStages=1;
        stage=2;
        auto services=enumerateServices();
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        completedStages=2;
        stage=3;
        auto startup=enumerateStartup();
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        completedStages=3;
        stage=4;
        auto network=enumerateTcp();
        auto udp=enumerateUdp();
        auto usb=enumerateUsbStorage();
        if(cancelRequested){scanCancelled=true;scanning=false;return;}
        completedStages=4;
        stage=5;
        services.insert(services.end(),startup.begin(),startup.end());
        services.insert(services.end(),network.begin(),network.end());
        services.insert(services.end(),udp.begin(),udp.end());
        services.insert(services.end(),usb.begin(),usb.end());
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            processes=std::move(p);
            records=std::move(services);
            processCount=processes.size();
            recordCount=records.size();
        }
        done=true;
    } catch(...) {
        scanFailed=true;
    }
    scanning=false;
}
static void startScan() {
    if(scanning)return;
    cancelRequested=false;done=false;scanFailed=false;scanCancelled=false;completedStages=0;stage=0;scanning=true;
    std::thread(scanWorker).detach();
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
    if(FAILED(hr)) return false;
    renderTargetCreate();
    return true;
}
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND,UINT,WPARAM,LPARAM);
static LRESULT WINAPI wndProc(HWND h,UINT msg,WPARAM w,LPARAM l) {
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

static ImVec4 orange(){return accentColor();}
static void applyTheme() {
    ImGui::StyleColorsDark();
    ImGuiStyle& st=ImGui::GetStyle();
    st.WindowRounding=0; st.ChildRounding=12; st.FrameRounding=7;
    st.PopupRounding=9; st.ScrollbarRounding=9;
    st.WindowPadding=ImVec2(18,18);st.FramePadding=ImVec2(11,densityIndex==0?5.f:densityIndex==2?12.f:8.f);
    st.ItemSpacing=ImVec2(11,densityIndex==0?5.f:densityIndex==2?15.f:10.f);st.ItemInnerSpacing=ImVec2(9,6);
    st.ScrollbarSize=11;
    auto& c=st.Colors;
    c[ImGuiCol_WindowBg]=themeIndex==2?ImVec4(.028f,.031f,.075f,1):themeIndex==1?ImVec4(.080f,.083f,.092f,1):ImVec4(.047f,.052f,.066f,1);
    c[ImGuiCol_ChildBg]=themeIndex==2?ImVec4(.048f,.056f,.108f,1):themeIndex==1?ImVec4(.11f,.12f,.13f,1):ImVec4(.080f,.088f,.109f,1);
    c[ImGuiCol_PopupBg]=ImVec4(.105f,.115f,.140f,1);
    c[ImGuiCol_Border]=ImVec4(.18f,.20f,.24f,1);
    c[ImGuiCol_Text]=ImVec4(.94f,.95f,.97f,1);
    c[ImGuiCol_TextDisabled]=ImVec4(.57f,.60f,.66f,1);
    c[ImGuiCol_FrameBg]=ImVec4(.14f,.15f,.19f,1);
    c[ImGuiCol_FrameBgHovered]=ImVec4(.19f,.21f,.26f,1);
    c[ImGuiCol_Button]=ImVec4(.16f,.18f,.22f,1);
    c[ImGuiCol_ButtonHovered]=ImVec4(.24f,.26f,.31f,1);
    c[ImGuiCol_ButtonActive]=ImVec4(.29f,.31f,.37f,1);
    c[ImGuiCol_Header]=ImVec4(.18f,.20f,.25f,1);
    c[ImGuiCol_HeaderHovered]=ImVec4(.24f,.26f,.32f,1);
    c[ImGuiCol_HeaderActive]=ImVec4(.28f,.30f,.36f,1);
    c[ImGuiCol_CheckMark]=orange();
    c[ImGuiCol_SliderGrab]=orange();
    c[ImGuiCol_Tab]=ImVec4(.12f,.14f,.18f,1);
    c[ImGuiCol_TabHovered]=orange();
    c[ImGuiCol_TabSelected]=ImVec4(orange().x*.5f,orange().y*.5f,orange().z*.5f,1);
    c[ImGuiCol_TableRowBgAlt]=ImVec4(.12f,.13f,.16f,.55f);
}
static bool accentButton(const char* text,ImVec2 size=ImVec2(0,0)) {
    ImGui::PushStyleColor(ImGuiCol_Button,orange());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,ImVec4(std::min(1.f,orange().x+.12f),std::min(1.f,orange().y+.12f),std::min(1.f,orange().z+.12f),1));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,ImVec4(orange().x*.8f,orange().y*.8f,orange().z*.8f,1));
    ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(.08f,.08f,.10f,1));
    bool clicked=ImGui::Button(text,size);
    ImGui::PopStyleColor(4);
    return clicked;
}
static void sectionTitle(const char* title,const char* description=nullptr) {
    ImGui::TextColored(orange(),"%s",title);
    if(description)ImGui::TextDisabled("%s",description);
    ImGui::Spacing();
}
static void metric(const char* label,const std::string& value,float width) {
    ImGui::BeginChild(label,ImVec2(width,94),ImGuiChildFlags_Borders);
    ImGui::TextDisabled("%s",label);
    ImGui::SetWindowFontScale(1.35f);
    ImGui::Text("%s",value.c_str());
    ImGui::SetWindowFontScale(1.f);
    ImGui::EndChild();
}
static const char* stateText() {
    if(scanning)return cancelRequested?"Cancelling...":"Scanning";
    if(scanFailed)return "Failed";
    if(scanCancelled)return "Cancelled";
    if(done)return "Completed";
    return "Ready";
}
static const char* stages[]={"Preparing","Processes","Services & Drivers","Startup Entries","Network Connections","Finalizing"};
static void modulesList() {
    struct Module {const char* name;const char* detail;bool available;};
    static const Module items[]={
        {"Processes & Privileges","Process inventory, parent IDs and accessible paths",true},
        {"Memory Integrity","Memory analysis is not implemented",false},
        {"Injection Indicators","Advanced injection checks are not implemented",false},
        {"Hooks & Interception","Hook verification is not implemented",false},
        {"Kernel & Drivers","Service and driver inventory",true},
        {"Persistence & Boot","Run / RunOnce entries and services",true},
        {"Network & Firewall","TCP/UDP IPv4 endpoints; firewall analysis not implemented",true},
        {"Hardware & USB","USB storage registry inventory; connection timeline not implemented",true},
        {"Execution Forensics","Prefetch, Amcache and event analysis unavailable",false},
        {"Files & Signatures","Manual SHA-256 and offline Authenticode checks",true},
        {"FiveM Integrity","Reference-manifest verification unavailable",false},
        {"Evidence Correlation","Cross-source correlation unavailable",false}
    };
    for(const auto& m:items) {
        ImGui::PushID(m.name);
        ImGui::BeginChild("module",ImVec2(0,86),ImGuiChildFlags_Borders);
        ImGui::Text("%s",m.name);
        ImGui::SameLine(ImGui::GetContentRegionAvail().x>150?ImGui::GetWindowWidth()-125:0);
        ImGui::TextColored(m.available?ImVec4(.45f,.78f,.59f,1):ImVec4(.69f,.70f,.75f,1),
                           "%s",m.available?"AVAILABLE":"PLANNED");
        ImGui::TextDisabled("%s",m.detail);
        if(ImGui::SmallButton("Show Details"))ImGui::OpenPopup("Module coverage details");
        if(ImGui::BeginPopup("Module coverage details")) {
            ImGui::TextColored(orange(),"%s",m.name);
            ImGui::Separator();
            ImGui::TextWrapped("%s",m.detail);
            ImGui::TextDisabled("Status: %s",m.available?"Available":"Not implemented");
            ImGui::TextWrapped("Coverage status describes implemented inventory, not a guarantee of threat detection.");
            ImGui::EndPopup();
        }
        ImGui::EndChild();
        ImGui::PopID();
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
static void selectProcessDetails(const Process& p) {
    selectedProcess=p;
    selectedModules=inspectProcessModules(p.pid);
    selectedHash.clear();
    selectedSignature.clear();
    detailsOpen=true;
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
        ImGui::TextColored(ImVec4(1.f,.44f,.43f,1.f),
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
        ImGui::TextDisabled("No module list available (protected, exited, or access denied).");
    if(ImGui::BeginTable("detailModules",3,ImGuiTableFlags_BordersInnerH|
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,
        ImVec2(0,-1))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("Module",ImGuiTableColumnFlags_WidthStretch,1.2f);
        ImGui::TableSetupColumn("Full path",ImGuiTableColumnFlags_WidthStretch,3.f);
        ImGui::TableSetupColumn("Security assessment",ImGuiTableColumnFlags_WidthStretch,2.2f);
        ImGui::TableHeadersRow();
        for(const auto& m:selectedModules) {
            ImGui::TableNextRow();
            if(m.suspicious && highlightSuspicious)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(125,32,37,190));
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(utf8(m.name).c_str());
            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(utf8(m.path).c_str());
            ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",m.assessment.c_str());
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
    if(serviceReviews.empty())serviceReviews=inspectServiceStates();
    if(ImGui::Button("Refresh service states"))
        serviceReviews=inspectServiceStates();
    ImGui::SameLine();
    ImGui::TextDisabled("Stopped automatic-start services are review candidates, not confirmed threats.");
    if(ImGui::BeginTable("serviceReviewTable",5,ImGuiTableFlags_BordersInnerH|
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,
        ImVec2(0,-1))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("Service",ImGuiTableColumnFlags_WidthStretch,1.5f);
        ImGui::TableSetupColumn("Display name",ImGuiTableColumnFlags_WidthStretch,2.f);
        ImGui::TableSetupColumn("State",ImGuiTableColumnFlags_WidthFixed,110);
        ImGui::TableSetupColumn("Security assessment",ImGuiTableColumnFlags_WidthStretch,3.f);
        ImGui::TableSetupColumn("Details",ImGuiTableColumnFlags_WidthFixed,110);
        ImGui::TableHeadersRow();
        for(const auto& item:serviceReviews) {
            ImGui::TableNextRow();
            if(item.review && highlightSuspicious)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(125,32,37,190));
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(utf8(item.name).c_str());
            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(utf8(item.display).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(item.currentState==SERVICE_RUNNING?"Running":
                item.currentState==SERVICE_STOPPED?"Stopped":"Other");
            ImGui::TableSetColumnIndex(3);ImGui::TextWrapped("%s",item.assessment.c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::PushID((int)(&item-&serviceReviews[0]));
            if(ImGui::SmallButton("Show Details"))ImGui::OpenPopup("Service details");
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

static void processTable(float height) {
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x*0.68f);
    ImGui::InputTextWithHint("##search","Search processes, paths, or assessments...",searchInput,sizeof(searchInput));
    ImGui::SameLine();ImGui::Checkbox("Show inaccessible paths",&showUnavailable);
    size_t flagged=0;
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        for(const auto& p:processes)if(p.suspicious)++flagged;
    }
    if(flagged)
        ImGui::TextColored(ImVec4(1.f,.43f,.40f,1.f),
            "%zu process(es) with review indicators. Red does not mean confirmed malware.",flagged);
    else
        ImGui::TextDisabled("No path-based review indicators found. This does not guarantee safety.");
    const ImGuiTableFlags flags=ImGuiTableFlags_BordersInnerH|
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|
        ImGuiTableFlags_ScrollY|ImGuiTableFlags_SizingStretchProp;
    if(ImGui::BeginTable("processes",6,flags,ImVec2(0,height))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("PID",ImGuiTableColumnFlags_WidthFixed,64);
        ImGui::TableSetupColumn("Parent",ImGuiTableColumnFlags_WidthFixed,68);
        ImGui::TableSetupColumn("Process",ImGuiTableColumnFlags_WidthStretch,1.2f);
        ImGui::TableSetupColumn("Executable path",ImGuiTableColumnFlags_WidthStretch,3.f);
        ImGui::TableSetupColumn("Security assessment",ImGuiTableColumnFlags_WidthStretch,3.f);
        ImGui::TableSetupColumn("Details",ImGuiTableColumnFlags_WidthFixed,112.f);
        ImGui::TableHeadersRow();
        std::lock_guard<std::mutex> lock(dataMutex);
        for(const auto& p:processes) {
            if(!showUnavailable&&(!p.path.empty() && p.path[0]==L'['))continue;
            const std::string name=utf8(p.name),path=utf8(p.path);
            std::string combined=name+" "+path+" "+p.assessment,q=searchInput;
            std::transform(combined.begin(),combined.end(),combined.begin(),
                [](unsigned char c){return (char)std::tolower(c);});
            std::transform(q.begin(),q.end(),q.begin(),
                [](unsigned char c){return (char)std::tolower(c);});
            if(combined.find(q)==std::string::npos)continue;
            ImGui::TableNextRow();
            if(p.suspicious && highlightSuspicious)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,IM_COL32(125,32,37,190));
            ImGui::TableSetColumnIndex(0);ImGui::Text("%lu",(unsigned long)p.pid);
            ImGui::TableSetColumnIndex(1);ImGui::Text("%lu",(unsigned long)p.parent);
            ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(name.c_str());
            ImGui::TableSetColumnIndex(3);ImGui::TextUnformatted(path.c_str());
            ImGui::TableSetColumnIndex(4);
            if(p.suspicious && highlightSuspicious)
                ImGui::TextColored(ImVec4(1.f,.72f,.68f,1.f),"%s",p.assessment.c_str());
            else
                ImGui::TextDisabled("%s",p.assessment.c_str());
            ImGui::TableSetColumnIndex(5);
            ImGui::PushID((int)p.pid);
            if(ImGui::SmallButton("Show Details"))selectProcessDetails(p);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
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
    if(!evidenceAssessment.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.f,.48f,.43f,1.f),"Security assessment");
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
    ImGui::TextDisabled("Evidence is observational; an indicator alone does not confirm a threat.");
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
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(r.category.c_str());
            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(r.name.c_str());
            ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(r.detail.c_str());
            ImGui::TableSetColumnIndex(3);ImGui::PushID(&r);
            if(ImGui::SmallButton("Show Details"))openEvidenceDetails(r.category,r.name,r.detail);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}
static void renderUI() {
    ImGuiViewport* vp=ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##application",nullptr,ImGuiWindowFlags_NoDecoration|
        ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoSavedSettings|
        ImGuiWindowFlags_NoBringToFrontOnFocus);
    const float sidebar=264.f;
    ImGui::BeginChild("##sidebar",ImVec2(sidebar,0),ImGuiChildFlags_None);
    ImGui::Dummy(ImVec2(0,18));
    if(syncLogoTexture) {
        ImGui::Image((ImTextureID)syncLogoTexture,ImVec2(76,77));
        ImGui::SameLine();
        ImGui::BeginGroup();
        ImGui::SetWindowFontScale(1.20f);
        ImGui::TextColored(orange(),"SYNC PC");
        ImGui::Text("CHECKER");
        ImGui::SetWindowFontScale(1.f);
        ImGui::EndGroup();
    } else {
        ImGui::TextColored(orange(),"SYNC PC CHECKER");
    }
    ImGui::TextDisabled("Developer: Mudin");
    ImGui::Spacing();ImGui::Separator();ImGui::Spacing();
    const char* names[]={"Dashboard","Inspection","Results","Timeline","Settings","Digital Identity"};
    for(int i=0;i<6;i++) {
        ImGui::PushID(i);
        const bool selected=(page==i);
        if(selected) {
            ImGui::PushStyleColor(ImGuiCol_Button,ImVec4(orange().x*.34f,orange().y*.34f,orange().z*.34f,1));
            ImGui::PushStyleColor(ImGuiCol_Text,orange());
        }
        const bool clicked=ImGui::Button(names[i],ImVec2(-1,50));
        if(selected)ImGui::PopStyleColor(2);
        if(clicked)page=i;
        ImGui::PopID();
    }
    ImGui::Dummy(ImVec2(0,22));
    ImGui::Separator();
    ImGui::TextDisabled("SYSTEM ACCESS");
    ImGui::TextColored(isAdministrator()?ImVec4(.43f,.81f,.60f,1):ImVec4(1,.65f,.36f,1),
                       "%s",isAdministrator()?"Administrator":"Standard User");
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("##main",ImVec2(0,0),ImGuiChildFlags_None);
    ImGui::TextColored(orange(),"SYNC PC CHECKER");
    ImGui::SameLine();ImGui::TextDisabled(" /  %s",names[page]);
    ImGui::Separator();ImGui::Dummy(ImVec2(0,8));
    float available=ImGui::GetContentRegionAvail().x;
    float metricWidth=(available-24.f)/3.f;
    if(page==0) {
        sectionTitle("SYSTEM OVERVIEW","Comprehensive read-only system inspection");
        ImGui::BeginChild("hero",ImVec2(0,183),ImGuiChildFlags_Borders);
        ImGui::TextDisabled("INSPECTION CENTER");
        ImGui::SetWindowFontScale(1.6f);
        ImGui::Text("%s",scanning?"Inspection in Progress":done?"Inspection Completed":"Ready for Inspection");
        ImGui::SetWindowFontScale(1.f);
        ImGui::TextDisabled("All available modules. One complete workflow.");
        ImGui::Spacing();
        if(!scanning) {
            if(accentButton("Start Full Scan",ImVec2(225,46))) { startScan(); page=1; }
        } else {
            if(ImGui::Button("View Inspection",ImVec2(225,46)))page=1;
        }
        ImGui::EndChild();
        ImGui::Spacing();
        metric("Processes",std::to_string(processCount.load()),metricWidth);
        ImGui::SameLine();
        metric("System Records",std::to_string(recordCount.load()),metricWidth);
        ImGui::SameLine();
        metric("Files Verified",std::to_string(fileCount.load()),metricWidth);
        ImGui::Spacing();
        sectionTitle("INSPECTION COVERAGE","Real collection status; no fabricated findings");
        ImGui::BeginChild("coverage",ImVec2(0,0),ImGuiChildFlags_Borders);
        ImGui::Text("Current status: %s",stateText());
        ImGui::Separator();
        ImGui::TextDisabled("Available: Processes, Services, Drivers, Startup, TCP/UDP IPv4, USB storage, File Integrity");
        ImGui::TextDisabled("Planned: Memory, Hooks, USB timestamps, Execution forensics, FiveM reference checks");
        if(ImGui::Button("Browse Inspection Modules"))page=1;
        ImGui::EndChild();
    } else if(page==1) {
        sectionTitle("SYSTEM INSPECTION","Live collection status and module availability");
        ImGui::BeginChild("inspectionCard",ImVec2(0,scanning?160:126),ImGuiChildFlags_Borders);
        ImGui::Text("Status: %s",stateText());
        if(scanning) {
            int idx=(std::min)(stage.load(),5);
            ImGui::TextDisabled("Current stage: %s",stages[idx]);
            ImGui::ProgressBar(completedStages.load()/(float)totalStages.load(),ImVec2(-1,15));
            if(ImGui::Button("Cancel Inspection"))cancelRequested=true;
        } else {
            ImGui::TextDisabled("Read-only inspection of accessible Windows sources.");
            if(accentButton("Start Full Scan",ImVec2(210,42))) startScan();
        }
        ImGui::EndChild();
        ImGui::Spacing();
        sectionTitle("MODULE COVERAGE","12 inspection categories preserved");
        modulesList();
    } else if(page==2) {
        sectionTitle(done?"SCAN COMPLETED":"INSPECTION RESULTS",
                     "Process inventory with explainable path-based review indicators.");
        if(ImGui::Button("Export CSV",ImVec2(120,38)))exportCsv();
        ImGui::SameLine();if(ImGui::Button("Export HTML",ImVec2(120,38)))exportHtml();
        ImGui::SameLine();if(ImGui::Button("Export JSON",ImVec2(120,38)))exportJson();
        ImGui::SameLine();ImGui::TextDisabled("%zu processes   |   %zu records   |   %zu files",
                          processCount.load(),recordCount.load(),fileCount.load());
        ImGui::Spacing();
        if(ImGui::BeginTabBar("results")) {
            if(ImGui::BeginTabItem("Findings")) {
                ImGui::TextDisabled("Path-based indicators only; warnings are not confirmed threats.");
                processTable(-1.f);
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
                    ImGui::TableHeadersRow();
                    std::lock_guard<std::mutex> lock(dataMutex);
                    for(const auto& f:files) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);ImGui::TextWrapped("%s",utf8(f.path).c_str());
                        ImGui::TableSetColumnIndex(1);ImGui::TextWrapped("%s",f.hash.c_str());
                        ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",f.signature.c_str());
                         ImGui::TableSetColumnIndex(3);ImGui::PushID(&f);
                         if(ImGui::SmallButton("Show Details"))openEvidenceDetails("File Integrity",utf8(f.path),
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
                ImGui::TextDisabled("USB storage devices registered in Windows. This is not a connection timeline.");
                if(ImGui::BeginTable("usbDevices",4,ImGuiTableFlags_BordersInnerH|
                    ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-1))) {
                    ImGui::TableSetupScrollFreeze(0,1);
                    ImGui::TableSetupColumn("Category",ImGuiTableColumnFlags_WidthFixed,100);
                    ImGui::TableSetupColumn("Device",ImGuiTableColumnFlags_WidthStretch,1.5f);
                    ImGui::TableSetupColumn("Registry details",ImGuiTableColumnFlags_WidthStretch,3.f);
                    ImGui::TableHeadersRow();
                    std::lock_guard<std::mutex> lock(dataMutex);
                    int found=0;
                    for(const auto& r:records) {
                        if(r.category!="USB")continue;
                        ++found;
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(r.category.c_str());
                        ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(r.name.c_str());
                        ImGui::TableSetColumnIndex(2);ImGui::TextWrapped("%s",r.detail.c_str());
                         ImGui::TableSetColumnIndex(3);ImGui::PushID(&r);
                         if(ImGui::SmallButton("Show Details"))openEvidenceDetails("USB Registry",r.name,
                             "Registry inventory: "+r.detail+"\nThis entry does not establish when a device was connected.");
                         ImGui::PopID();
                    }
                    if(!found) {
                        ImGui::TableNextRow();
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
        sectionTitle("EXECUTION TIMELINE","Chronological correlation of Windows evidence");
        ImGui::BeginChild("timeline",ImVec2(0,210),ImGuiChildFlags_Borders);
        ImGui::TextDisabled("PLANNED");
        ImGui::TextWrapped("Prefetch, Amcache, event log and USB timeline collection are not implemented.");
        ImGui::TextWrapped("The scanner will not generate synthetic events or timestamps.");
        ImGui::EndChild();
    } else if(page==4) {
        sectionTitle("APPEARANCE & SETTINGS","Customize the scanner interface. Changes apply immediately.");
        ImGui::BeginChild("settings",ImVec2(0,0),ImGuiChildFlags_Borders);
        ImGui::TextColored(orange(),"APPEARANCE");
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::Text("Accent Color");
        ImGui::SetNextItemWidth(320);
        if(ImGui::Combo("##accent",&accentIndex,accentNames,IM_ARRAYSIZE(accentNames)))applyTheme();
        if(accentIndex==5) {
            if(ImGui::ColorEdit3("Custom accent",(float*)&customAccent,ImGuiColorEditFlags_NoInputs))
                applyTheme();
        }
        ImGui::Spacing();
        ImGui::Text("Theme");
        ImGui::SetNextItemWidth(320);
        if(ImGui::Combo("##theme",&themeIndex,themeNames,IM_ARRAYSIZE(themeNames)))applyTheme();
        ImGui::Spacing();
        ImGui::Text("Interface Scale");
        ImGui::SetNextItemWidth(320);
        if(ImGui::SliderFloat("##scale",&interfaceScale,.8f,1.4f,"%.2fx"))
            ImGui::GetIO().FontGlobalScale=interfaceScale;
        ImGui::Spacing();
        ImGui::Text("Table Density");
        ImGui::SetNextItemWidth(320);
        if(ImGui::Combo("##density",&densityIndex,densityNames,IM_ARRAYSIZE(densityNames)))
            applyTheme();
        ImGui::Spacing();ImGui::Separator();ImGui::Spacing();
        ImGui::TextColored(orange(),"PROCESS REVIEW");
        ImGui::Checkbox("Highlight suspicious processes in red",&highlightSuspicious);
        ImGui::Checkbox("Show English security assessments",&showSecurityWarnings);
        ImGui::Spacing();ImGui::Separator();ImGui::Spacing();
        ImGui::TextColored(orange(),"PREFERENCES");
        if(accentButton("Save Settings",ImVec2(170,42)))saveSettings();
        ImGui::SameLine();
        if(ImGui::Button("Restore Defaults",ImVec2(170,42))) {
            accentIndex=0;themeIndex=0;densityIndex=1;interfaceScale=1.f;
            highlightSuspicious=true;showSecurityWarnings=true;
            customAccent=ImVec4(.98f,.43f,.15f,1.f);
            ImGui::GetIO().FontGlobalScale=1.f;
            applyTheme();
            saveSettings();
        }
        if(settingsNotice)ImGui::TextColored(ImVec4(.35f,.85f,.55f,1),"Settings saved successfully.");
        ImGui::Spacing();
        ImGui::TextDisabled("Preferences are stored locally in APPDATA\\SyncPCChecker\\settings.ini");
        ImGui::EndChild();
    } else if(page==5) {
        sectionTitle("DIGITAL IDENTITY","Application integrity and developer information");
        ImGui::BeginChild("identity",ImVec2(0,270),ImGuiChildFlags_Borders);
        ImGui::Text("Application       Sync PC Checker");
        ImGui::Text("Developer         Mudin");
        ImGui::Text("Privileges        %s",isAdministrator()?"Administrator":"Standard User");
        ImGui::TextWrapped("Executable: %s",utf8(executablePath()).c_str());
        ImGui::Separator();
        if(accentButton("Verify This Executable",ImVec2(240,43))) {
            try {
                auto r=inspectFile(executablePath());
                std::lock_guard<std::mutex> lock(dataMutex);
                files.push_back(std::move(r));
        fileCount=files.size();
                status="Executable verification recorded in Results > File Integrity";
            } catch(...) {status="Executable verification failed";}
        }
        ImGui::TextDisabled("A self-signed certificate is not publicly trusted by default.");
        ImGui::EndChild();
    }
    ImGui::EndChild();
    ImGui::End();
    drawProcessDetails();
    drawEvidenceDetails();
}
int WINAPI wWinMain(HINSTANCE inst,HINSTANCE,LPWSTR,int) {
    WNDCLASSEXW wc{sizeof(wc),CS_CLASSDC,wndProc,0,0,inst,nullptr,nullptr,nullptr,nullptr,
                  L"SyncPCChecker",nullptr};
    RegisterClassExW(&wc);
    hwnd=CreateWindowW(wc.lpszClassName,L"Sync PC Checker - Mudin",
                       WS_OVERLAPPEDWINDOW,100,100,1200,780,nullptr,nullptr,inst,nullptr);
    if(!hwnd || !initD3D(hwnd))return 1;
    ShowWindow(hwnd,SW_SHOWDEFAULT);UpdateWindow(hwnd);
    IMGUI_CHECKVERSION();ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard;
    loadSettings();
    applyTheme();
    ImGui::GetIO().FontGlobalScale=interfaceScale;
    // Use Windows' modern UI font when available; fallback to the built-in font.
    ImGuiIO& io=ImGui::GetIO();
    ImFontConfig fontCfg{};
    fontCfg.OversampleH=2;
    if(!io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf",17.f,&fontCfg))
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
        renderUI();ImGui::Render();
        const float clear[4]={.055f,.060f,.075f,1};
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
    return 0;
}
