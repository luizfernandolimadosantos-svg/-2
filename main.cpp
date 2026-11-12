#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <commdlg.h>
#include <d3d11.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
#include <winsvc.ha>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <winreg.h>
#include <cctype>
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

namespace fs=std::filesystem;
struct Process { DWORD pid; DWORD parent; std::wstring name,path; };
struct Record { std::string category,name,detail; };
struct FileResult { std::wstring path; std::string hash,signature; };
static HWND hwnd=nullptr;
static ID3D11Device* device=nullptr;
static ID3D11DeviceContext* context=nullptr;
static IDXGISwapChain* swapchain=nullptr;
static ID3D11RenderTargetView* target=nullptr;
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
static bool requestScanPopup=false;
static std::atomic<bool> scanFailed{false};
static std::atomic<bool> scanCancelled{false};
static std::atomic<int> completedStages{0};
static std::atomic<int> totalStages{4};
static std::atomic<size_t> processCount{0}, recordCount{0}, fileCount{0};
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
static std::wstring processPath(DWORD pid) {
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!h) return L"Unavailable";
    wchar_t buf[32768]{};
    DWORD n=32768;
    bool ok=QueryFullProcessImageNameW(h,0,buf,&n)!=0;
    CloseHandle(h);
    return ok?std::wstring(buf,n):L"Unavailable";
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
    std::ofstream out("MacaquitoScanner_Report.csv",std::ios::binary);
    if(!out){status="Could not write CSV";return;}
    out<<"Type,PID,ParentPID,Name,Path,SHA256,Signature\n";
    std::lock_guard<std::mutex> lock(dataMutex);
    for(const auto& p:processes)
        out<<"Process,"<<p.pid<<","<<p.parent<<","<<csvQuote(utf8(p.name))<<","
           <<csvQuote(utf8(p.path))<<",,\n";
    for(const auto& r:records)
        out<<csvQuote(r.category)<<",,,"<<csvQuote(r.name)<<","<<csvQuote(r.detail)<<",,\n";
    for(const auto& f:files)
        out<<"File,,,"<<csvQuote(utf8(fs::path(f.path).filename().wstring()))<<","
           <<csvQuote(utf8(f.path))<<","<<csvQuote(f.hash)<<","<<csvQuote(f.signature)<<"\n";
    status="CSV saved: MacaquitoScanner_Report.csv";
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
    std::ofstream out("MacaquitoScanner_Report.html",std::ios::binary);
    if(!out){status="HTML export failed";return;}
    out<<"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
          "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
          "<title>Macaquito Scanner Report</title>"
          "<style>body{background:#101115;color:#e8e9ee;font:15px Segoe UI,Arial,sans-serif;"
          "margin:40px auto;max-width:1100px;padding:0 18px}h1,h2{color:#ff8739}"
          "table{width:100%;border-collapse:collapse;margin:16px 0 36px}"
          "td,th{border-bottom:1px solid #34363e;padding:9px;text-align:left;word-break:break-word}"
          "th{background:#22252d}small{color:#9da0a9}</style></head><body>"
          "<h1>Macaquito Scanner</h1><p>Developer: Mudin</p>"
          "<small>Read-only inventory. An inventory entry is not a threat finding.</small>";
    out<<"<h2>Processes ("<<processes.size()<<")</h2><table><tr>"
          "<th>PID</th><th>Parent</th><th>Name</th><th>Path</th></tr>";
    for(const auto& p:processes)
        out<<"<tr><td>"<<p.pid<<"</td><td>"<<p.parent<<"</td><td>"
           <<htmlEscape(utf8(p.name))<<"</td><td>"<<htmlEscape(utf8(p.path))<<"</td></tr>";
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
    status="HTML saved: MacaquitoScanner_Report.html";
}
static void exportJson() {
    std::lock_guard<std::mutex> lock(dataMutex);
    std::ofstream out("MacaquitoScanner_Report.json",std::ios::binary);
    if(!out){status="JSON export failed";return;}
    out<<"{\n  \"application\": \"Macaquito Scanner\",\n  \"developer\": \"Mudin\","
          "\n  \"disclaimer\": \"Inventory is not a threat finding\",\n  \"processes\": [\n";
    for(size_t i=0;i<processes.size();i++) {
        const auto& p=processes[i];
        out<<"    {\"pid\": "<<p.pid<<", \"parent\": "<<p.parent
           <<", \"name\": "<<jsonEscape(utf8(p.name))
           <<", \"path\": "<<jsonEscape(utf8(p.path))<<"}"
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
    status="JSON saved: MacaquitoScanner_Report.json";
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

static ImVec4 orange(){return ImVec4(.98f,.43f,.15f,1.f);}
static void applyTheme() {
    ImGui::StyleColorsDark();
    ImGuiStyle& st=ImGui::GetStyle();
    st.WindowRounding=0; st.ChildRounding=12; st.FrameRounding=7;
    st.PopupRounding=9; st.ScrollbarRounding=9;
    st.WindowPadding=ImVec2(18,18);st.FramePadding=ImVec2(11,8);
    st.ItemSpacing=ImVec2(11,10);st.ItemInnerSpacing=ImVec2(9,6);
    st.ScrollbarSize=11;
    auto& c=st.Colors;
    c[ImGuiCol_WindowBg]=ImVec4(.047f,.052f,.066f,1);
    c[ImGuiCol_ChildBg]=ImVec4(.080f,.088f,.109f,1);
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
    c[ImGuiCol_TabHovered]=ImVec4(.27f,.20f,.17f,1);
    c[ImGuiCol_TabSelected]=ImVec4(.29f,.19f,.14f,1);
    c[ImGuiCol_TableRowBgAlt]=ImVec4(.12f,.13f,.16f,.55f);
}
static bool accentButton(const char* text,ImVec2 size=ImVec2(0,0)) {
    ImGui::PushStyleColor(ImGuiCol_Button,ImVec4(.96f,.39f,.11f,1));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,ImVec4(1,.49f,.19f,1));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,ImVec4(.83f,.30f,.07f,1));
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
        ImGui::BeginChild("module",ImVec2(0,66),ImGuiChildFlags_Borders);
        ImGui::Text("%s",m.name);
        ImGui::SameLine(ImGui::GetContentRegionAvail().x>150?ImGui::GetWindowWidth()-125:0);
        ImGui::TextColored(m.available?ImVec4(.45f,.78f,.59f,1):ImVec4(.69f,.70f,.75f,1),
                           "%s",m.available?"AVAILABLE":"PLANNED");
        ImGui::TextDisabled("%s",m.detail);
        ImGui::EndChild();
        ImGui::PopID();
    }
}
static void processTable(float height) {
    ImGui::InputTextWithHint("##search","Search processes or paths...",searchInput,sizeof(searchInput));
    ImGui::SameLine();ImGui::Checkbox("Show inaccessible paths",&showUnavailable);
    if(ImGui::BeginTable("processes",4,ImGuiTableFlags_BordersInnerH|
        ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,
        ImVec2(0,height))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("PID",ImGuiTableColumnFlags_WidthFixed,75);
        ImGui::TableSetupColumn("Parent",ImGuiTableColumnFlags_WidthFixed,75);
        ImGui::TableSetupColumn("Process",ImGuiTableColumnFlags_WidthFixed,190);
        ImGui::TableSetupColumn("Executable path");
        ImGui::TableHeadersRow();
        std::lock_guard<std::mutex> lock(dataMutex);
        for(const auto& p:processes) {
            if(!showUnavailable&&p.path==L"Unavailable")continue;
            auto name=utf8(p.name),path=utf8(p.path);
            std::string combined=name+" "+path,q=searchInput;
            std::transform(combined.begin(),combined.end(),combined.begin(),[](unsigned char c){return (char)tolower(c);});
            std::transform(q.begin(),q.end(),q.begin(),[](unsigned char c){return (char)tolower(c);});
            if(combined.find(q)==std::string::npos)continue;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);ImGui::Text("%lu",(unsigned long)p.pid);
            ImGui::TableSetColumnIndex(1);ImGui::Text("%lu",(unsigned long)p.parent);
            ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(name.c_str());
            ImGui::TableSetColumnIndex(3);ImGui::TextUnformatted(path.c_str());
        }
        ImGui::EndTable();
    }
}
static void recordsTable() {
    if(ImGui::BeginTable("records",3,ImGuiTableFlags_BordersInnerH|ImGuiTableFlags_RowBg|
        ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,370))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("Category",ImGuiTableColumnFlags_WidthFixed,110);
        ImGui::TableSetupColumn("Name",ImGuiTableColumnFlags_WidthFixed,230);
        ImGui::TableSetupColumn("Details");
        ImGui::TableHeadersRow();
        std::lock_guard<std::mutex> lock(dataMutex);
        for(const auto& r:records) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(r.category.c_str());
            ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(r.name.c_str());
            ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(r.detail.c_str());
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
    const float sidebar=210.f;
    ImGui::BeginChild("##sidebar",ImVec2(sidebar,0),ImGuiChildFlags_None);
    ImGui::Dummy(ImVec2(0,8));
    ImGui::TextColored(orange(),"MACAQUITO");
    ImGui::Text("SCANNER");
    ImGui::TextDisabled("Developer: Mudin");
    ImGui::Spacing();ImGui::Separator();ImGui::Spacing();
    const char* names[]={"Dashboard","Inspection","Results","Timeline","Settings","Digital Identity"};
    for(int i=0;i<6;i++) {
        ImGui::PushID(i);
        const bool selected=(page==i);
        if(selected) {
            ImGui::PushStyleColor(ImGuiCol_Button,ImVec4(.35f,.20f,.14f,1));
            ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(1,.57f,.30f,1));
        }
        const bool clicked=ImGui::Button(names[i],ImVec2(-1,43));
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
    ImGui::TextColored(orange(),"MACAQUITO SCANNER");
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
            if(accentButton("Start Full Scan",ImVec2(225,46)))requestScanPopup=true;
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
            if(accentButton("Start Full Scan",ImVec2(210,42)))requestScanPopup=true;
        }
        ImGui::EndChild();
        ImGui::Spacing();
        sectionTitle("MODULE COVERAGE","12 inspection categories preserved");
        modulesList();
    } else if(page==2) {
        sectionTitle(done?"SCAN COMPLETED":"INSPECTION RESULTS",
                     "Inventory is not a threat finding. No automated threat rules are enabled.");
        if(ImGui::Button("Export CSV",ImVec2(120,38)))exportCsv();
        ImGui::SameLine();if(ImGui::Button("Export HTML",ImVec2(120,38)))exportHtml();
        ImGui::SameLine();if(ImGui::Button("Export JSON",ImVec2(120,38)))exportJson();
        ImGui::SameLine();ImGui::TextDisabled("%zu processes   |   %zu records   |   %zu files",
                          processCount.load(),recordCount.load(),fileCount.load());
        ImGui::Spacing();
        if(ImGui::BeginTabBar("results")) {
            if(ImGui::BeginTabItem("Findings")) {
                ImGui::TextDisabled("No threat classification is implemented. Process inventory:");
                processTable(370);
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("File Integrity")) {
                ImGui::InputTextWithHint("##file","Select a file to verify...",fileInput,sizeof(fileInput));
                ImGui::SameLine();if(ImGui::Button("Browse"))chooseFile();
                if(accentButton("Calculate SHA-256 + Verify Signature"))inspectSelectedFile();
                if(ImGui::BeginTable("files",3,ImGuiTableFlags_BordersInnerH|ImGuiTableFlags_RowBg|
                    ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,310))) {
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
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("System Inventory")) {
                recordsTable();ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("USB Review")) {
                ImGui::TextDisabled("USB storage inventory is collected under System Inventory. Historical timestamps are not implemented.");
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
        sectionTitle("SETTINGS","Single full inspection. No scan profiles.");
        ImGui::BeginChild("settings",ImVec2(0,230),ImGuiChildFlags_Borders);
        ImGui::Text("Detection");
        ImGui::TextDisabled("Offline Authenticode verification and read-only inventory.");
        ImGui::Separator();
        ImGui::Text("Privacy");
        ImGui::TextDisabled("Results are collected locally. CSV export is manual.");
        ImGui::Separator();
        ImGui::Text("Performance");
        ImGui::TextDisabled("System inventory runs in a background worker.");
        ImGui::EndChild();
    } else if(page==5) {
        sectionTitle("DIGITAL IDENTITY","Application integrity and developer information");
        ImGui::BeginChild("identity",ImVec2(0,270),ImGuiChildFlags_Borders);
        ImGui::Text("Application       Macaquito Scanner");
        ImGui::Text("Developer         Mudin");
        ImGui::Text("Publisher         Mudin (display name)");
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
    if(requestScanPopup) {
        ImGui::OpenPopup("Confirm Inspection");
        requestScanPopup=false;
    }
    if(ImGui::BeginPopupModal("Confirm Inspection",nullptr,ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped("Inspect accessible Windows sources on this PC?");
        ImGui::TextDisabled("Read-only. No files or settings will be modified.");
        if(accentButton("Start Inspection",ImVec2(155,40))) {
            startScan();page=1;ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if(ImGui::Button("Cancel",ImVec2(120,40)))ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    ImGui::EndChild();
    ImGui::End();
}
int WINAPI wWinMain(HINSTANCE inst,HINSTANCE,LPWSTR,int) {
    WNDCLASSEXW wc{sizeof(wc),CS_CLASSDC,wndProc,0,0,inst,nullptr,nullptr,nullptr,nullptr,
                  L"MacaquitoScanner",nullptr};
    RegisterClassExW(&wc);
    hwnd=CreateWindowW(wc.lpszClassName,L"Macaquito Scanner - Mudin",
                       WS_OVERLAPPEDWINDOW,100,100,1200,780,nullptr,nullptr,inst,nullptr);
    if(!hwnd || !initD3D(hwnd))return 1;
    ShowWindow(hwnd,SW_SHOWDEFAULT);UpdateWindow(hwnd);
    IMGUI_CHECKVERSION();ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard;
    applyTheme();
    // Use Windows' modern UI font when available; fallback to the built-in font.
    ImGuiIO& io=ImGui::GetIO();
    ImFontConfig fontCfg{};
    fontCfg.OversampleH=2;
    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf",17.f,&fontCfg);
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(device,context);
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
    while(scanning) Sleep(10);
    ImGui_ImplDX11_Shutdown();ImGui_ImplWin32_Shutdown();ImGui::DestroyContext();
    renderTargetDestroy();
    if(swapchain)swapchain->Release();
    if(context)context->Release();
    if(device)device->Release();
    DestroyWindow(hwnd);UnregisterClassW(wc.lpszClassName,inst);
    return 0;
}
