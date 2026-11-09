#define UNICODE
#define _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

struct ProcessInfo { DWORD pid; std::wstring name, path, status; };
static HWND gList=nullptr, gStatus=nullptr, gButton=nullptr;
static std::vector<ProcessInfo> gProcesses;

static std::wstring csvEscape(const std::wstring& s) {
    std::wstring r=L"\"";
    for(wchar_t c:s) { if(c==L'"') r+=L'"'; r+=c; }
    return r+L"\"";
}
static void setStatus(const std::wstring& s) { SetWindowTextW(gStatus,s.c_str()); }
static void scan() {
    EnableWindow(gButton,FALSE);
    setStatus(L"Scanning processes...");
    gProcesses.clear();
    ListView_DeleteAllItems(gList);
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE) {
        setStatus(L"Unable to enumerate processes.");
        EnableWindow(gButton,TRUE); return;
    }
    PROCESSENTRY32W e{}; e.dwSize=sizeof(e);
    if(Process32FirstW(snap,&e)) {
        do {
            ProcessInfo p{e.th32ProcessID,e.szExeFile,L"",L"Unavailable"};
            HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p.pid);
            if(h) {
                wchar_t buf[32768]; DWORD size=32768;
                if(QueryFullProcessImageNameW(h,0,buf,&size)) {
                    p.path.assign(buf,size); p.status=L"OK";
                } else p.status=L"Access denied or unavailable";
                CloseHandle(h);
            } else p.status=L"Access denied or unavailable";
            gProcesses.push_back(p);
        } while(Process32NextW(snap,&e));
    }
    CloseHandle(snap);
    for(size_t i=0;i<gProcesses.size();++i) {
        const auto& p=gProcesses[i];
        std::wstring pid=std::to_wstring(p.pid);
        LVITEMW item{}; item.mask=LVIF_TEXT; item.iItem=(int)i;
        item.pszText=const_cast<wchar_t*>(pid.c_str());
        int row=ListView_InsertItem(gList,&item);
        ListView_SetItemText(gList,row,1,const_cast<wchar_t*>(p.name.c_str()));
        ListView_SetItemText(gList,row,2,const_cast<wchar_t*>(p.path.c_str()));
        ListView_SetItemText(gList,row,3,const_cast<wchar_t*>(p.status.c_str()));
    }
    setStatus(L"Scan completed: "+std::to_wstring(gProcesses.size())+L" processes. No threat classification performed.");
    EnableWindow(gButton,TRUE);
}
static void exportCsv(HWND owner) {
    if(gProcesses.empty()) { MessageBoxW(owner,L"Run a scan first.",L"Macaquito Scanner",MB_OK); return; }
    wchar_t path[MAX_PATH]=L"MacaquitoScanner-processes.csv";
    OPENFILENAMEW ofn{}; ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=owner;
    ofn.lpstrFilter=L"CSV files (*.csv)\0*.csv\0All files (*.*)\0*.*\0";
    ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH; ofn.lpstrDefExt=L"csv";
    ofn.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST;
    if(!GetSaveFileNameW(&ofn)) return;
    std::wofstream f{std::filesystem::path(path)};
    if(!f) { MessageBoxW(owner,L"Could not write report.",L"Error",MB_ICONERROR); return; }
    f << L"PID,Process,Executable Path,Collection Status\n";
    for(const auto& p:gProcesses)
        f << p.pid << L"," << csvEscape(p.name) << L"," << csvEscape(p.path) << L"," << csvEscape(p.status) << L"\n";
    f.close();
    MessageBoxW(owner,L"CSV report saved locally.",L"Macaquito Scanner",MB_OK);
}
static LRESULT CALLBACK wndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        INITCOMMONCONTROLSEX ic{sizeof(ic),ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&ic);
        gButton=CreateWindowW(L"BUTTON",L"Start Scan",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,16,16,140,34,hwnd,(HMENU)101,nullptr,nullptr);
        CreateWindowW(L"BUTTON",L"Export CSV",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,166,16,140,34,hwnd,(HMENU)102,nullptr,nullptr);
        gStatus=CreateWindowW(L"STATIC",L"Ready. Read-only process inventory.",WS_CHILD|WS_VISIBLE,320,25,680,25,hwnd,nullptr,nullptr,nullptr);
        gList=CreateWindowW(WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|WS_BORDER,16,64,960,520,hwnd,(HMENU)103,nullptr,nullptr);
        ListView_SetExtendedListViewStyle(gList,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_GRIDLINES);
        const wchar_t* names[]={L"PID",L"Process",L"Executable Path",L"Status"};
        int widths[]={90,190,490,190};
        for(int i=0;i<4;i++){ LVCOLUMNW c{};c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;c.pszText=const_cast<wchar_t*>(names[i]);c.cx=widths[i];c.iSubItem=i;ListView_InsertColumn(gList,i,&c); }
        return 0;
    }
    case WM_SIZE: {
        int w=LOWORD(lp),h=HIWORD(lp);
        if(gList) MoveWindow(gList,16,64,(w>32?w-32:0),(h>80?h-80:0),TRUE);
        if(gStatus) MoveWindow(gStatus,320,25,(w>340?w-340:0),25,TRUE);
        return 0;
    }
    case WM_COMMAND:
        if(LOWORD(wp)==101) scan();
        else if(LOWORD(wp)==102) exportCsv(hwnd);
        return 0;
    case WM_DESTROY: PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}
int WINAPI wWinMain(HINSTANCE inst,HINSTANCE,PWSTR,int show) {
    const wchar_t* cls=L"MacaquitoScannerProcessInventory";
    WNDCLASSW wc{};wc.lpfnWndProc=wndProc;wc.hInstance=inst;wc.lpszClassName=cls;
    wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc)) return 1;
    HWND hwnd=CreateWindowExW(0,cls,L"Macaquito Scanner - Process Inventory (Functional Prototype)",WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,1040,680,nullptr,nullptr,inst,nullptr);
    if(!hwnd) return 2;
    ShowWindow(hwnd,show);UpdateWindow(hwnd);
    MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    return (int)msg.wParam;
}
