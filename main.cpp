#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <commdlg.h>
#include <d3d11.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>
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

namespace fs=std::filesystem;
struct Process { DWORD pid; DWORD parent; std::wstring name,path; };
struct FileResult { std::wstring path; std::string hash,signature; };
static HWND hwnd=nullptr;
static ID3D11Device* device=nullptr;
static ID3D11DeviceContext* context=nullptr;
static IDXGISwapChain* swapchain=nullptr;
static ID3D11RenderTargetView* target=nullptr;
static std::vector<Process> processes;
static std::vector<FileResult> files;
static std::mutex dataMutex;
static std::atomic<bool> scanning{false};
static std::atomic<bool> done{false};
static std::atomic<int> stage{0};
static std::string status="Ready for inspection";
static int page=0;
static bool confirmScan=false;
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
static void scanWorker() {
    stage=1;
    auto p=enumerateProcesses();
    stage=2;
    // This prototype deliberately does not read process memory or collect private user files.
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        processes=std::move(p);
    }
    stage=3;
    done=true;
    scanning=false;
}
static void startScan() {
    if(scanning) return;
    done=false;stage=0;scanning=true;
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
    for(const auto& f:files)
        out<<"File,,,"<<csvQuote(utf8(fs::path(f.path).filename().wstring()))<<","
           <<csvQuote(utf8(f.path))<<","<<csvQuote(f.hash)<<","<<csvQuote(f.signature)<<"\n";
    status="CSV saved to current working directory";
}
static void inspectSelectedFile() {
    std::wstring path=wide(fileInput);
    if(path.empty()) {status="Enter a file path";return;}
    try {
        auto r=inspectFile(path);
        std::lock_guard<std::mutex> lock(dataMutex);
        files.push_back(std::move(r));
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
static void applyTheme() {
    ImGui::StyleColorsDark();
    auto& s=ImGui::GetStyle();
    s.WindowRounding=10;s.FrameRounding=6;s.ChildRounding=8;
    s.GrabRounding=6;s.WindowPadding=ImVec2(16,16);
    s.ItemSpacing=ImVec2(10,10);
    auto& c=s.Colors;
    c[ImGuiCol_WindowBg]=ImVec4(.055f,.060f,.075f,1);
    c[ImGuiCol_ChildBg]=ImVec4(.095f,.105f,.125f,1);
    c[ImGuiCol_FrameBg]=ImVec4(.15f,.16f,.19f,1);
    c[ImGuiCol_Button]=ImVec4(.90f,.37f,.12f,1);
    c[ImGuiCol_ButtonHovered]=ImVec4(1,.48f,.19f,1);
    c[ImGuiCol_ButtonActive]=ImVec4(.78f,.29f,.09f,1);
    c[ImGuiCol_Header]=ImVec4(.31f,.20f,.16f,1);
    c[ImGuiCol_HeaderHovered]=ImVec4(.50f,.25f,.14f,1);
    c[ImGuiCol_CheckMark]=ImVec4(1,.52f,.23f,1);
    c[ImGuiCol_Tab]=ImVec4(.13f,.14f,.17f,1);
    c[ImGuiCol_TabHovered]=ImVec4(.80f,.36f,.14f,1);
    c[ImGuiCol_TabSelected]=ImVec4(.55f,.25f,.12f,1);
}
static void textDim(const char* s) {ImGui::TextDisabled("%s",s);}
static void renderUI() {
    const ImGuiViewport* vp=ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("Macaquito Scanner",nullptr,ImGuiWindowFlags_NoDecoration|
                 ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoSavedSettings);
    ImGui::TextColored(ImVec4(1,.52f,.23f,1),"MACAQUITO SCANNER");
    ImGui::SameLine();ImGui::TextDisabled("V47  |  Developer: Mudin");
    ImGui::Separator();
    const char* tabs[]={"Dashboard","Inspection","Results","Timeline","Settings","Digital Identity"};
    for(int i=0;i<6;i++) {
        if(i) ImGui::SameLine();
        if(ImGui::Button(tabs[i],ImVec2(i==5?140:110,34))) page=i;
    }
    ImGui::Separator();
    if(page==0) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1,.52f,.23f,1),"INSPECTION CENTER");
        ImGui::SetWindowFontScale(1.5f);ImGui::TextUnformatted("Ready to Inspect");
        ImGui::SetWindowFontScale(1.f);
        textDim("One full scan. Available modules run automatically.");
        ImGui::Spacing();
        if(ImGui::Button("Start Full Scan",ImVec2(240,48))) ImGui::OpenPopup("Confirm Inspection");
        ImGui::Spacing();
        ImGui::Text("Process inventory: %zu",processes.size());
        ImGui::Text("Files checked: %zu",files.size());
        textDim("This build includes real process inventory and manual file integrity checks.");
        textDim("Other forensic modules remain planned; no fabricated detections.");
    } else if(page==1) {
        ImGui::Text("Inspection Status: %s",scanning?"Running":done?"Completed":"Ready");
        if(scanning) {
            const char* labels[]={"Starting","Enumerating processes","Recording results","Completed"};
            int i=(std::min)(stage.load(),3);
            ImGui::Text("Current stage: %s",labels[i]);
            ImGui::ProgressBar(i/3.f,ImVec2(-1,18));
        }
        if(!scanning && ImGui::Button("Start Full Scan",ImVec2(220,40)))
            ImGui::OpenPopup("Confirm Inspection");
        ImGui::Separator();
        ImGui::TextUnformatted("Implemented");
        ImGui::BulletText("Process inventory and process paths");
        ImGui::BulletText("SHA-256 file hashing (manual file selection)");
        ImGui::BulletText("Authenticode verification (offline)");
        ImGui::BulletText("CSV report export");
        ImGui::Separator();
        ImGui::TextUnformatted("Planned / not collected in this build");
        ImGui::BulletText("Memory, injection indicators, hooks, drivers");
        ImGui::BulletText("Persistence, network, USB, execution forensics");
        ImGui::BulletText("FiveM reference integrity and evidence correlation");
    } else if(page==2) {
        ImGui::TextUnformatted(done?"Scan Completed":"Inspection Results");
        if(ImGui::Button("Export CSV",ImVec2(160,36))) exportCsv();
        ImGui::SameLine();ImGui::Checkbox("Show unavailable paths",&showUnavailable);
        if(ImGui::BeginTabBar("results")) {
            if(ImGui::BeginTabItem("Findings")) {
                textDim("No threat detection rules are enabled. Inventory is not a finding.");
                ImGui::InputTextWithHint("##search","Search process name or path",searchInput,sizeof(searchInput));
                if(ImGui::BeginTable("processes",4,ImGuiTableFlags_Borders|
                    ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,
                    ImVec2(0,300))) {
                    ImGui::TableSetupScrollFreeze(0,1);
                    ImGui::TableSetupColumn("PID",ImGuiTableColumnFlags_WidthFixed,70);
                    ImGui::TableSetupColumn("Parent",ImGuiTableColumnFlags_WidthFixed,70);
                    ImGui::TableSetupColumn("Process");
                    ImGui::TableSetupColumn("Path");
                    ImGui::TableHeadersRow();
                    std::lock_guard<std::mutex> lock(dataMutex);
                    for(const auto& p:processes) {
                        if(!showUnavailable && p.path==L"Unavailable")continue;
                        auto name=utf8(p.name),path=utf8(p.path);
                        std::string combined=name+" "+path;
                        std::string q=searchInput;
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
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("File Integrity")) {
                ImGui::InputText("File path",fileInput,sizeof(fileInput));
                ImGui::SameLine();if(ImGui::Button("Browse"))chooseFile();
                if(ImGui::Button("Verify SHA-256 + Signature"))inspectSelectedFile();
                if(ImGui::BeginTable("files",3,ImGuiTableFlags_Borders|
                    ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,
                    ImVec2(0,250))) {
                    ImGui::TableSetupColumn("File");ImGui::TableSetupColumn("SHA-256");
                    ImGui::TableSetupColumn("Signature");ImGui::TableHeadersRow();
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
            if(ImGui::BeginTabItem("USB Review")) {
                textDim("Not implemented in this build.");ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Modules")) {
                textDim("Process inventory and file verification: available.");
                textDim("Other forensic modules: planned, not collected.");
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    } else if(page==3) {
        ImGui::TextUnformatted("Execution Timeline");
        textDim("Timeline correlation is planned; no events have been collected.");
    } else if(page==4) {
        ImGui::TextUnformatted("Settings");
        textDim("Single Full Scan workflow. No Quick / Standard / Deep modes.");
        textDim("Read-only collection; offline signature validation.");
        textDim("The current prototype does not persist preferences.");
    } else if(page==5) {
        ImGui::TextUnformatted("Digital Identity Center");
        ImGui::Separator();
        ImGui::Text("Application: Macaquito Scanner");
        ImGui::Text("Developer: Mudin");
        ImGui::Text("Publisher (display): Mudin");
        ImGui::Text("Version: V47");
        ImGui::Text("Executable: %s",utf8(executablePath()).c_str());
        if(ImGui::Button("Verify This Executable",ImVec2(240,38))) {
            try {
                auto r=inspectFile(executablePath());
                std::lock_guard<std::mutex> lock(dataMutex);
                files.push_back(r);
                status="Self verification recorded under Results > File Integrity";
            } catch(...) {status="Self verification failed";}
        }
        textDim("Self-signed certificates are not automatically trusted by other PCs.");
        textDim("A publicly trusted signature requires a code-signing certificate.");
    }
    if(ImGui::BeginPopupModal("Confirm Inspection",nullptr,ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped("Inspect running processes on this PC? No files will be modified.");
        if(ImGui::Button("Start",ImVec2(120,0))) {
            startScan();page=1;ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if(ImGui::Button("Cancel",ImVec2(120,0)))ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
    ImGui::Separator();
    ImGui::TextDisabled("%s",status.c_str());
    ImGui::End();
}
int WINAPI wWinMain(HINSTANCE inst,HINSTANCE,LPWSTR,int) {
    WNDCLASSEXW wc{sizeof(wc),CS_CLASSDC,wndProc,0,0,inst,nullptr,nullptr,nullptr,nullptr,
                  L"MacaquitoScannerV47",nullptr};
    RegisterClassExW(&wc);
    hwnd=CreateWindowW(wc.lpszClassName,L"Macaquito Scanner V47 - Mudin",
                       WS_OVERLAPPEDWINDOW,100,100,1200,780,nullptr,nullptr,inst,nullptr);
    if(!hwnd || !initD3D(hwnd))return 1;
    ShowWindow(hwnd,SW_SHOWDEFAULT);UpdateWindow(hwnd);
    IMGUI_CHECKVERSION();ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard;
    applyTheme();
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
