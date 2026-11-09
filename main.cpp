#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <d3d11.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <chrono>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")

static ID3D11Device* device=nullptr;
static ID3D11DeviceContext* context=nullptr;
static IDXGISwapChain* swapchain=nullptr;
static ID3D11RenderTargetView* target=nullptr;
static bool resized=false;
static UINT newWidth=0,newHeight=0;
static void CreateTarget(){ID3D11Texture2D* back=nullptr;if(SUCCEEDED(swapchain->GetBuffer(0,IID_PPV_ARGS(&back)))){device->CreateRenderTargetView(back,nullptr,&target);back->Release();}}
static void DestroyTarget(){if(target){target->Release();target=nullptr;}}
static bool CreateDevice(HWND hwnd){
 DXGI_SWAP_CHAIN_DESC d={};d.BufferCount=2;d.BufferDesc.Format=DXGI_FORMAT_R8G8B8A8_UNORM;d.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;d.OutputWindow=hwnd;d.SampleDesc.Count=1;d.Windowed=TRUE;d.SwapEffect=DXGI_SWAP_EFFECT_DISCARD;
 D3D_FEATURE_LEVEL level;D3D_FEATURE_LEVEL levels[]={D3D_FEATURE_LEVEL_11_0,D3D_FEATURE_LEVEL_10_0};
 if(FAILED(D3D11CreateDeviceAndSwapChain(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,0,levels,2,D3D11_SDK_VERSION,&d,&swapchain,&device,&level,&context)))return false;
 CreateTarget();return target!=nullptr;
}
static void Cleanup(){DestroyTarget();if(swapchain)swapchain->Release();if(context)context->Release();if(device)device->Release();}
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND,UINT,WPARAM,LPARAM);
static LRESULT WINAPI WndProc(HWND h,UINT m,WPARAM w,LPARAM l){
 if(ImGui_ImplWin32_WndProcHandler(h,m,w,l))return true;
 switch(m){case WM_SIZE:if(w!=SIZE_MINIMIZED){newWidth=LOWORD(l);newHeight=HIWORD(l);resized=true;}return 0;
 case WM_SYSCOMMAND:if((w&0xfff0)==SC_KEYMENU)return 0;break;
 case WM_DESTROY:PostQuitMessage(0);return 0;}return DefWindowProcW(h,m,w,l);
}
struct Process{DWORD pid;std::wstring name,path;bool accessible;};
static std::vector<Process> processes;
static bool scanned=false;
static std::string status="Ready. Read-only process inspection.";
static std::string Utf8(const std::wstring& s){if(s.empty())return {};int n=WideCharToMultiByte(CP_UTF8,0,s.c_str(),(int)s.size(),nullptr,0,nullptr,nullptr);std::string o(n,'\0');WideCharToMultiByte(CP_UTF8,0,s.c_str(),(int)s.size(),o.data(),n,nullptr,nullptr);return o;}
static void Scan(){
 processes.clear();
 HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
 if(snap==INVALID_HANDLE_VALUE){status="Failed: Windows process snapshot unavailable.";scanned=false;return;}
 PROCESSENTRY32W e={};e.dwSize=sizeof(e);
 if(Process32FirstW(snap,&e))do{
  Process p={};p.pid=e.th32ProcessID;p.name=e.szExeFile;p.accessible=false;
  HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p.pid);
  if(h){wchar_t path[32768];DWORD size=32768;if(QueryFullProcessImageNameW(h,0,path,&size)){p.path.assign(path,size);p.accessible=true;}CloseHandle(h);}
  processes.push_back(std::move(p));
 }while(Process32NextW(snap,&e));
 CloseHandle(snap);
 std::sort(processes.begin(),processes.end(),[](auto&a,auto&b){return a.pid<b.pid;});
 scanned=true;status="Scan completed. Process inventory collected.";
}
static std::string Csv(const std::string& s){std::string v="\"";for(char c:s){if(c=='"')v+="\"\"";else if(c!='\r'&&c!='\n')v+=c;}return v+"\"";}
static void Export(){
 if(!scanned){status="Run a scan before exporting.";return;}
 wchar_t exe[MAX_PATH];GetModuleFileNameW(nullptr,exe,MAX_PATH);
 std::filesystem::path out=std::filesystem::path(exe).parent_path()/L"MacaquitoScanner-processes.csv";
 std::ofstream f(out,std::ios::binary);
 if(!f){status="Export failed. Move EXE to a writable folder.";return;}
 f<<"PID,Process,Executable Path,Status\r\n";
 for(auto&p:processes)f<<p.pid<<","<<Csv(Utf8(p.name))<<","<<Csv(Utf8(p.path))<<","<<Csv(p.accessible?"Accessible":"Unavailable")<<"\r\n";
 status="CSV saved beside MacaquitoScanner.exe";
}
static void ApplyStyle(){
 ImGuiStyle& s=ImGui::GetStyle();s.WindowRounding=10;s.ChildRounding=9;s.FrameRounding=6;s.GrabRounding=5;s.ScrollbarRounding=7;s.WindowPadding=ImVec2(16,16);s.FramePadding=ImVec2(11,8);s.ItemSpacing=ImVec2(10,10);
 auto& c=s.Colors;c[ImGuiCol_WindowBg]=ImVec4(.065f,.070f,.083f,1);c[ImGuiCol_ChildBg]=ImVec4(.095f,.102f,.12f,1);c[ImGuiCol_PopupBg]=ImVec4(.11f,.12f,.14f,1);c[ImGuiCol_Border]=ImVec4(.20f,.21f,.24f,1);c[ImGuiCol_Text]=ImVec4(.94f,.94f,.96f,1);c[ImGuiCol_TextDisabled]=ImVec4(.55f,.57f,.62f,1);c[ImGuiCol_Button]=ImVec4(.93f,.40f,.12f,1);c[ImGuiCol_ButtonHovered]=ImVec4(1,.48f,.18f,1);c[ImGuiCol_ButtonActive]=ImVec4(.75f,.31f,.08f,1);c[ImGuiCol_Header]=ImVec4(.20f,.22f,.25f,1);c[ImGuiCol_HeaderHovered]=ImVec4(.27f,.28f,.31f,1);c[ImGuiCol_HeaderActive]=ImVec4(.31f,.32f,.35f,1);c[ImGuiCol_FrameBg]=ImVec4(.14f,.15f,.17f,1);c[ImGuiCol_FrameBgHovered]=ImVec4(.19f,.20f,.23f,1);c[ImGuiCol_Separator]=ImVec4(.20f,.21f,.24f,1);c[ImGuiCol_TableHeaderBg]=ImVec4(.15f,.16f,.18f,1);c[ImGuiCol_TableRowBg]=ImVec4(.095f,.102f,.12f,1);c[ImGuiCol_TableRowBgAlt]=ImVec4(.12f,.13f,.15f,1);c[ImGuiCol_CheckMark]=ImVec4(1,.52f,.2f,1);
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int){
 WNDCLASSEXW wc={sizeof(wc),CS_CLASSDC,WndProc,0,0,instance,nullptr,nullptr,nullptr,nullptr,L"MacaquitoScanner",nullptr};RegisterClassExW(&wc);
 HWND hwnd=CreateWindowW(wc.lpszClassName,L"Macaquito Scanner V38 - System Inspection",WS_OVERLAPPEDWINDOW,100,90,1150,740,nullptr,nullptr,instance,nullptr);
 if(!CreateDevice(hwnd)){MessageBoxW(nullptr,L"DirectX 11 initialization failed.",L"Macaquito Scanner",MB_OK|MB_ICONERROR);DestroyWindow(hwnd);UnregisterClassW(wc.lpszClassName,instance);return 1;}
 ShowWindow(hwnd,SW_SHOWDEFAULT);UpdateWindow(hwnd);
 IMGUI_CHECKVERSION();ImGui::CreateContext();ImGuiIO& io=ImGui::GetIO();io.ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard;ApplyStyle();
 ImGui_ImplWin32_Init(hwnd);ImGui_ImplDX11_Init(device,context);
 int page=0;bool confirm=false;bool showUnavailable=true;bool done=false;
 while(!done){
  MSG msg;while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);if(msg.message==WM_QUIT)done=true;}
  if(done)break;
  if(resized&&newWidth&&newHeight){DestroyTarget();swapchain->ResizeBuffers(0,newWidth,newHeight,DXGI_FORMAT_UNKNOWN,0);CreateTarget();resized=false;}
  ImGui_ImplDX11_NewFrame();ImGui_ImplWin32_NewFrame();ImGui::NewFrame();
  ImGuiViewport* vp=ImGui::GetMainViewport();ImGui::SetNextWindowPos(vp->WorkPos);ImGui::SetNextWindowSize(vp->WorkSize);
  ImGui::Begin("##app",nullptr,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoSavedSettings);
  ImGui::TextColored(ImVec4(1,.49f,.18f,1),"MACAQUITO");ImGui::SameLine();ImGui::Text("SCANNER");ImGui::SameLine();ImGui::TextDisabled("  V38  |  LOCAL SYSTEM INSPECTION");
  ImGui::Separator();
  const char* tabs[]={"Dashboard","Inspection","Results","Settings"};
  for(int i=0;i<4;i++){if(i)ImGui::SameLine();if(ImGui::Selectable(tabs[i],page==i,0,ImVec2(130,32)))page=i;}
  ImGui::Separator();ImGui::Spacing();
  if(page==0){
   ImGui::TextDisabled("SYSTEM STATUS");ImGui::Text("Ready to Inspect");ImGui::TextDisabled("Read-only Windows process inventory. No automatic threat verdicts.");
   ImGui::Spacing();
   if(ImGui::Button("Start Full Scan",ImVec2(240,46))){if(confirm)ImGui::OpenPopup("Confirm Inspection");else{Scan();page=2;}}
   ImGui::Spacing();ImGui::Text("Processes: %zu",processes.size());ImGui::Text("Inspection module: Process Inventory");ImGui::TextDisabled("File Integrity / USB Review / FiveM Integrity: Not implemented");
  }else if(page==1){
   ImGui::Text("Inspection");ImGui::TextDisabled("Available module: Process Inventory");
   if(ImGui::Button("Start Scan",ImVec2(180,40))){if(confirm)ImGui::OpenPopup("Confirm Inspection");else{Scan();page=2;}}
   ImGui::TextWrapped("This scan lists running processes and accessible executable paths. It does not read private files or send data.");
  }else if(page==2){
   ImGui::Text("Scan Completed");ImGui::SameLine();ImGui::TextDisabled(scanned?"- process inventory":"- no scan performed");
   ImGui::Text("Processes: %zu",processes.size());ImGui::SameLine();ImGui::TextDisabled("Findings: Not evaluated");
   if(ImGui::Button("Export CSV",ImVec2(150,36)))Export();
   ImGui::SameLine();ImGui::Checkbox("Show unavailable paths",&showUnavailable);
   if(ImGui::BeginTabBar("results")){
    if(ImGui::BeginTabItem("Findings")){
     ImGui::TextDisabled("No threat detection rules are implemented. Processes below are inventory, not findings.");
     if(ImGui::BeginTable("processes",4,ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY,ImVec2(0,-8))){
      ImGui::TableSetupScrollFreeze(0,1);ImGui::TableSetupColumn("PID",ImGuiTableColumnFlags_WidthFixed,80);ImGui::TableSetupColumn("Process",ImGuiTableColumnFlags_WidthFixed,200);ImGui::TableSetupColumn("Executable Path");ImGui::TableSetupColumn("Status",ImGuiTableColumnFlags_WidthFixed,115);ImGui::TableHeadersRow();
      for(auto&p:processes){if(!showUnavailable&&!p.accessible)continue;ImGui::TableNextRow();ImGui::TableSetColumnIndex(0);ImGui::Text("%lu",(unsigned long)p.pid);ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(Utf8(p.name).c_str());ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(p.accessible?Utf8(p.path).c_str():"Unavailable");ImGui::TableSetColumnIndex(3);ImGui::TextUnformatted(p.accessible?"Done":"Partial");}
      ImGui::EndTable();
     }ImGui::EndTabItem();
    }
    if(ImGui::BeginTabItem("USB Review")){ImGui::TextDisabled("Not implemented yet.");ImGui::EndTabItem();}
    if(ImGui::BeginTabItem("Modules")){ImGui::BulletText("Process Inventory - Available");ImGui::BulletText("Other inspection modules - Planned");ImGui::EndTabItem();}
    ImGui::EndTabBar();
   }
  }else{
   ImGui::Text("Settings");ImGui::Separator();ImGui::Checkbox("Confirm before scanning",&confirm);ImGui::Checkbox("Show unavailable process paths",&showUnavailable);
   ImGui::TextDisabled("Theme: Carbon Ember");ImGui::TextDisabled("Scan mode: Read-only");ImGui::TextDisabled("Network uploads: None");
   ImGui::TextDisabled("Settings apply during this session only.");
  }
  if(ImGui::BeginPopupModal("Confirm Inspection",nullptr,ImGuiWindowFlags_AlwaysAutoResize)){
   ImGui::TextWrapped("Inspect running processes on this PC? No files will be modified.");
   if(ImGui::Button("Start",ImVec2(120,0))){Scan();page=2;ImGui::CloseCurrentPopup();}
   ImGui::SameLine();if(ImGui::Button("Cancel",ImVec2(120,0)))ImGui::CloseCurrentPopup();
   ImGui::EndPopup();
  }
ImGui::SetCursorPosY((std::max)(ImGui::GetCursorPosY(), ImGui::GetWindowHeight() - 35.f)); ImGui::Separator(); ImGui::TextDisabled("%s", status.c_str());
  ImGui::End();
  ImGui::Render();const float clear[4]={.065f,.070f,.083f,1};context->OMSetRenderTargets(1,&target,nullptr);context->ClearRenderTargetView(target,clear);ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());swapchain->Present(1,0);
 }
 ImGui_ImplDX11_Shutdown();ImGui_ImplWin32_Shutdown();ImGui::DestroyContext();Cleanup();DestroyWindow(hwnd);UnregisterClassW(wc.lpszClassName,instance);return 0;
}
