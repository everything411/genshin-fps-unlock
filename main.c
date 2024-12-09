#define KEY_TOGGLE VK_END
#define KEY_INCREASE VK_UP
#define KEY_INCREASE_SMALL VK_RIGHT
#define KEY_DECREASE VK_DOWN
#define KEY_DECREASE_SMALL VK_LEFT
#define FPS_TARGET 120

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

int FpsValue = FPS_TARGET;

//credit by winTEuser
const BYTE _shellcode_genshin_Const[] =
{
    0x00, 0x00, 0x00, 0x00,                         //uint32_t unlocker_pid              _shellcode_genshin[0]
    0x00, 0xC0, 0x9C, 0x66,                         //uint32_t shellcode_timestamp       _shellcode_genshin[4]  //2024-07-21 16:00:00
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t unlocker_FpsValue_addr    _shellcode_genshin[8]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_OpenProcess           _shellcode_genshin[16]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_ReadProcessmem        _shellcode_genshin[24]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_Sleep                 _shellcode_genshin[32]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_MessageBoxA           _shellcode_genshin[40]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_CloseHandle           _shellcode_genshin[48]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //FREE                               _shellcode_genshin[56]
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
    0x48, 0x83, 0xEC, 0x38,                  //sub rsp,0x38                              _shellcode_genshin[80] _sync_thread
    0x8B, 0x05, 0xA6, 0xFF, 0xFF, 0xFF,      //mov eax,dword[unlocker_pid]
    0x85, 0xC0,                              //test eax, eax
    0x74, 0x5C,                              //jz return
    0x41, 0x89, 0xC0,                        //mov r8d, eax
    0x33, 0xD2,                              //xor edx, edx
    0xB9, 0xFF, 0xFF, 0x1F, 0x00,            //mov ecx,1FFFFF
    0xFF, 0x15, 0xA2, 0xFF, 0xFF, 0xFF,      //call [API_OpenProcess]
    0x85, 0xC0,                              //test eax, eax
    0x74, 0x48,                              //jz return
    0x89, 0xC6,                              //mov esi, eax
    0x48, 0x8B, 0x3D, 0x8D, 0xFF, 0xFF, 0xFF,//mov rdi,qword[unlocker_FpsValue_addr]
    0x0F, 0x1F, 0x44, 0x00, 0x00,            //nop
    0x89, 0xF1,                              //mov ecx, esi          //Read_tar_fps
    0x48, 0x89, 0xFA,                        //mov rdx, rdi
    0x4C, 0x8D, 0x05, 0x08, 0x01, 0x00, 0x00,//lea r8, qword:[Readmem_buffer]
    0x41, 0xB9, 0x04, 0x00, 0x00, 0x00,      //mov r9d, 4
    0x31, 0xC0,                              //xor eax, eax
    0x48, 0x89, 0x44, 0x24, 0x20,            //mov qword ptr ss:[rsp+20],rax
    0xFF, 0x15, 0x79, 0xFF, 0xFF, 0xFF,      //call [API_ReadProcessmem]
    0x85, 0xC0,                              //test eax, eax
    0x74, 0x12,                              //jz Show msg and closehandle
    0xB9, 0xF4, 0x01, 0x00, 0x00,            //mov ecx,0x1F4     (500ms)
    0xFF, 0x15, 0x72, 0xFF, 0xFF, 0xFF,      //call [API_Sleep]
    0xE8, 0x5D, 0x00, 0x00, 0x00,            //call Sync_auto
    0xEB, 0xCB,                              //jmp Read_tar_fps
    0xE8, 0x76, 0x00, 0x00, 0x00,            //call Show Errormsg and CloseHandle
    0x48, 0x83, 0xC4, 0x38,                  //add rsp,0x38
    0xC3,                                    //return
    //int3
    0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
    0x89, 0x0D, 0xBA, 0x00, 0x00, 0x00,     //mov [Game_Current_set], ecx           //hook_fps_set      _shellcode_genshin[0xD0]
    0x31, 0xC0,                             //xor eax, eax       
    0x83, 0xF9, 0x1E,                       //cmp ecx, 0x1E 
    0x74, 0x0E,                             //je set 60
    0x83, 0xF9, 0x2D,                       //cmp ecx, 0x2D
    0x74, 0x15,                             //je Sync_buffer
    0x2E, 0xB9, 0xE8, 0x03, 0x00, 0x00,     //mov ecx, 0x3E8                    
    0xEB, 0x06,                             //jmp set
    0xCC, //int3                            
    0xB9, 0x3C, 0x00, 0x00, 0x00,           //mov ecx, 0x3C                     
    0x89, 0x0D, 0x0B, 0x00, 0x00, 0x00,     //mov [hook_fps_get+1], ecx        //set
    0xC3,                                   //ret
    0x8B, 0x0D, 0x97, 0x00, 0x00, 0x00,     //mov ecx, dword[Readmem_buffer]   //Sync_buffer
    0xEB, 0xF1,                             //jmp set
    0xCC,
    //int3
    0xB8, 0x78, 0x00, 0x00, 0x00,           //mov eax,0x78                          //hook_fps_get      _shellcode_genshin[0xF0]
    0xC3,                                   //ret
    //int3
    0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
    0x8B, 0x05, 0x7A, 0x00, 0x00, 0x00,     //mov eax, dword[Game_Current_set]      //Sync_auto
    0x83, 0xF8, 0x2D,                       //cmp eax, 0x2D
    0x75, 0x0C,                             //jne return
    0x8B, 0x05, 0x73, 0x00, 0x00, 0x00,     //mov eax, dword[Readmem_buffer]
    0x89, 0x05, 0xDA, 0xFF, 0xFF, 0xFF,     //mov dword[hook_fps_get + 1], eax
    0xC3,                                   //ret
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
    0x48, 0x83, 0xEC, 0x28,                  //sub rsp, 0x28                        //Show Errormsg and closehandle
    0x31, 0xC9,                              //xor ecx, ecx 
    0x48, 0x8D, 0x15, 0x33, 0x00, 0x00, 0x00,//lea rdx, qword:["Sync failed!"]
    0x4C, 0x8D, 0x05, 0x3C, 0x00, 0x00, 0x00,//lea r8, qword:["Error"]
    0x41, 0xB9, 0x10, 0x00, 0x00, 0x00,      //mov r9d, 0x10 
    0xFF, 0x15, 0xD8, 0xFE, 0xFF, 0xFF,      //call [API_MessageBoxA] 
    0x89, 0xF1,                              //mov ecx, esi 
    0xFF, 0x15, 0xD8, 0xFE, 0xFF, 0xFF,      //call [API_CloseHandle] 
    0x48, 0x83, 0xC4, 0x28,                  //add rsp, 0x28
    0xC3,                                    //ret
    //int3
    0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    'S','y','n','c',' ','f','a','i','l','e','d','!', 0x00, 0x00, 0x00, 0x00,
    'E','r','r','o','r', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,             //uint32_t Game_Current_set  
    0x00, 0x00, 0x00, 0x00,             //uint32_t Readmem_buffer    
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


// 特征搜索 winTEuser
int* pattern_to_byte(const char* pattern, int *ppos)
{
    static int bytes[1024];
    int bytes_pos = 0;
    const char* start = pattern;
    const char* end = pattern + strlen(pattern);

    for (const char* current = start; current < end; ++current) {
        if (*current == '?') {
            ++current;
            if (*current == '?')
                ++current;
            bytes[bytes_pos++] = -1;
        }
        else {
            bytes[bytes_pos++] = strtoul(current, (char**)&current, 16);
        }
    }
    *ppos = bytes_pos;
    return bytes;
};
static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    int patternBytessize = 0;
    int* patternBytes = pattern_to_byte(signature, &patternBytessize);
    uint8_t* scanBytes = (uint8_t*)startAddress;

    for (size_t i = 0; i < regionSize - patternBytessize; ++i)
    {
        bool found = true;
        for (size_t j = 0; j < patternBytessize; ++j) {
            if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return (uintptr_t)&scanBytes[i];
        }
    }
    return 0;
}

const char *GetLastErrorAsString(DWORD code)
{
    LPSTR buf = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
    static char ret[4096];
    strcpy(ret, buf);
    LocalFree(buf);
    return ret;
}

static bool GetModule(DWORD pid, const char *ModuleName, PMODULEENTRY32 pEntry)
{
    if (!pEntry)
        return false;

    MODULEENTRY32 mod32 = {};
    mod32.dwSize = sizeof(mod32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    bool temp = Module32First(snap, &mod32);
    if (temp)
    {
        do
        {
            if (mod32.th32ProcessID != pid)
            {
                break;
            }
            if (!strcmp(mod32.szModule, ModuleName))
            {
                *pEntry = mod32;
                CloseHandle(snap);
                return 1;
            }

        } while (Module32Next(snap, &mod32));

    }
    CloseHandle(snap);
    return 0;
}
// 通过进程名搜索进程ID
DWORD GetPID(const char* ProcessName)
{
    DWORD pid = 0;
    PROCESSENTRY32 pe32 = {};
    pe32.dwSize = sizeof(pe32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32First(snap, &pe32); Process32Next(snap, &pe32);)
    {
        if (!strcmp(pe32.szExeFile, ProcessName))
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return pid;
}

//Hotpatch
static DWORD64 inject_patch(LPVOID text_buffer, DWORD text_size, DWORD64 _text_baseaddr, uint64_t _ptr_fps, HANDLE Tar_handle)
{
    if (text_buffer == 0 || text_size == 0 || _text_baseaddr == 0 || _ptr_fps == 0 || Tar_handle == 0)
        return 0;

    DWORD64 Module_TarSec_RVA = (DWORD64)text_buffer;
    DWORD Module_TarSec_Size = text_size;

    DWORD64 address = 0;
    DWORD64 Hook_addr_fpsget = 0;   //in buffer
    DWORD64 Hook_addr_tar_fpsget = 0;
    DWORD64 Hook_addr_fpsSet = 0;   //in buffer
    DWORD64 Hook_addr_tar_fpsSet = 0;
    DWORD64 _addr_tar_fpsget_TarFun = 0;
    DWORD64 _addr_tar_fpsSet_TarFun = 0;
	
__Get_fpsSet_addr:
    uint64_t _shellcode_buffer = (uint64_t)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (_shellcode_buffer == 0)
    {
        printf_s("Buffer Alloc Fail! \n");
        return 0;
    }
    memcpy((void*)_shellcode_buffer, &_shellcode_genshin_Const, sizeof(_shellcode_genshin_Const));

    uint64_t _Addr_OpenProcess = (uint64_t)(&OpenProcess);
    uint64_t _Addr_ReadProcessmem = (uint64_t)(&ReadProcessMemory);
    uint64_t _Addr_Sleep = (uint64_t)(&Sleep);
    uint64_t _Addr_MessageBoxA = (uint64_t)(&MessageBoxA);
    uint64_t _Addr_CloseHandle = (uint64_t)(&CloseHandle);
    *(uint32_t*)_shellcode_buffer = GetCurrentProcessId();       //unlocker PID
    *(uint64_t*)(_shellcode_buffer + 8) = (uint64_t)(&FpsValue); //unlocker fps ptr
    *(uint64_t*)(_shellcode_buffer + 16) = _Addr_OpenProcess;
    *(uint64_t*)(_shellcode_buffer + 24) = _Addr_ReadProcessmem;
    *(uint64_t*)(_shellcode_buffer + 32) = _Addr_Sleep;
    *(uint64_t*)(_shellcode_buffer + 40) = _Addr_MessageBoxA;
    *(uint64_t*)(_shellcode_buffer + 48) = _Addr_CloseHandle;
    *(uint32_t*)(_shellcode_buffer + 0xE4) = 1000;
    *(uint32_t*)(_shellcode_buffer + 0xEC) = 60;

    *(uint64_t*)(_shellcode_buffer + 0x110) = 0xB848;                //mov rax, game_pfps
    *(uint64_t*)(_shellcode_buffer + 0x118) = 0x741D8B0000;          //mov ebx, dword[Readmem_buffer]
    *(uint64_t*)(_shellcode_buffer + 0x120) = 0xCCCCCCCCCCC31889;    //mov [rax], ebx 
    *(uint64_t*)(_shellcode_buffer + 0x112) = _ptr_fps;              //ret
    *(uint64_t*)(_shellcode_buffer + 0x15C) = 0x5C76617E8834858;    //keep thread
    *(uint64_t*)(_shellcode_buffer + 0x164) = 0xE0FF21EBFFFFFF16;

    LPVOID __Tar_proc_buffer = VirtualAllocEx(Tar_handle, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (__Tar_proc_buffer)
    {
        if (WriteProcessMemory(Tar_handle, __Tar_proc_buffer, (void*)_shellcode_buffer, sizeof(_shellcode_genshin_Const), 0))
        {
            VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
            HANDLE temp = CreateRemoteThread(Tar_handle, 0, 0, (LPTHREAD_START_ROUTINE)((uint64_t)__Tar_proc_buffer + 0x50), 0, 0, 0);
            if (temp)
            {
                CloseHandle(temp);
            }
            else
            {
                printf_s("Create InGame SyncThread Fail! ");
                return 0;
            }
            return ((uint64_t)__Tar_proc_buffer + 0x194);
        }
        printf_s("Inject shellcode Fail! ");
        VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
        return 0;
    }
    else
    {
        printf_s("Alloc shellcode space Fail! ");
        return 0;
    }
}


int main(int argc, char** argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: \"%s\" target-fps /path/to/genshin/exe [args]\n", argv[0]);
        return 1;
    }

    FpsValue = atoi(argv[1]);
    if(FpsValue < 60 || FpsValue > 240)
    {
        fprintf(stderr, "usage: \"%s\" target-fps /path/to/genshin/exe [args]\n", argv[0]);
        return 1;
    }
    const char* ProcessPath = argv[2];

    if (strlen(ProcessPath) < 12) // min(strlen(YuanShen.exe), strlen(GenshinImpact.exe))
    {
        fprintf(stderr, "usage: \"%s\" target-fps /path/to/genshin/exe [args]\n", argv[0]);
        return 1;
    }

    printf("Credits to winTEuser and xiaonian233\n");

    const char* procname;

    if(strstr(ProcessPath, "YuanShen.exe"))
        procname = "YuanShen.exe";
    else if(strstr(ProcessPath, "GenshinImpact.exe"))
        procname = "GenshinImpact.exe";
    else
    {
        fprintf(stderr, "usage: \"%s\" target-fps /path/to/genshin/exe [args]\n", argv[0]);
        return 1;
    }

    char *ProcessDir = strdup(ProcessPath);
    *strstr(ProcessDir, procname) = 0;

    char* cmdline = calloc(1, 4096);
    char* tmpcmdline = calloc(1, 4096);
    sprintf(cmdline, "\"%s\"", procname);
    for(int i = 3; i < argc; i++)
    {
        if (strchr(argv[i], ' '))
            sprintf(tmpcmdline, " \"%s\"", argv[i]);
        else
            sprintf(tmpcmdline, " %s", argv[i]);
        strcat(cmdline, tmpcmdline);
    }
    printf("call %s with args \"%s\" in %s\n", ProcessPath, cmdline, ProcessDir);

    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(ProcessPath, cmdline, NULL, NULL, FALSE, 0, NULL, ProcessDir, &si, &pi))
    {
        DWORD code = GetLastError();
        printf("CreateProcess failed (%d): %s", code, GetLastErrorAsString(code));
        return 2;
    }

    CloseHandle(pi.hThread);
    printf("PID: %d\n", pi.dwProcessId);
    Sleep(200);
    // 等待UnityPlayer.dll加载和获取DLL信息
    MODULEENTRY32 hUnityPlayer = {};
    {
        DWORD times = 1000;
        while (times != 0)
        {
            if (GetModule(pi.dwProcessId, procname, &hUnityPlayer))
            {
                goto __get_procbase_ok;
            }
            Sleep(50);
            times -= 5;
        }
        printf("Get BaseModule time out! \n");
        CloseHandle(pi.hProcess);
        return (int)-1;
    }
    {
        DWORD times = 1000;
        while (!GetModule(pi.dwProcessId, "UnityPlayer.dll", &hUnityPlayer))
        {
            Sleep(50);
            times -= 5;
            if (GetModule(pi.dwProcessId, "unityplayer.dll", &hUnityPlayer))
            {
                goto __get_procbase_ok;
            }
            if (times == 0)
            {
                printf("Get Unitymodule time out! \n");
                CloseHandle(pi.hProcess);
                return (int)-1;
            }
        }
    }
    printf("UnityPlayer: %X%X\n", (uintptr_t)hUnityPlayer.modBaseAddr >> 32 & -1, hUnityPlayer.modBaseAddr);
__get_procbase_ok:
    LPVOID _mbase_PE_buffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (_mbase_PE_buffer == 0)
    {
        printf_s("VirtualAlloc Failed! (PE_buffer)");
        CloseHandle(pi.hProcess);
        return (int)-1;
    }
    if (hUnityPlayer.modBaseAddr == 0)
        return (int)-1;
    if (ReadProcessMemory(pi.hProcess, hUnityPlayer.modBaseAddr, _mbase_PE_buffer, 0x1000, 0) == 0)
    {
        printf_s("Readmem Failed! (PE_buffer)");
        VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        return (int)-1;
    }
    BYTE search_sec[8] = ".text";//max 8 byte
    uint64_t tar_sec = *(uint64_t*)&search_sec;
    uintptr_t WinPEfileVA = *(uintptr_t*)(&_mbase_PE_buffer) + 0x3c; //dos_header
    uintptr_t PEfptr = *(uintptr_t*)(&_mbase_PE_buffer) + *(uint32_t*)WinPEfileVA; //get_winPE_VA
    struct _IMAGE_NT_HEADERS64 _FilePE_Nt_header = *(struct _IMAGE_NT_HEADERS64*)PEfptr;
    struct _IMAGE_SECTION_HEADER _sec_temp = {};
    uintptr_t Text_Remote_RVA;
    uint32_t Text_Vsize;
    if (_FilePE_Nt_header.Signature == 0x00004550)
    {
        DWORD sec_num = _FilePE_Nt_header.FileHeader.NumberOfSections;//获得指定节段参数
        DWORD num = sec_num;
        DWORD target_sec_VA_start = 0;
        while (num)
        {
            _sec_temp = *(struct _IMAGE_SECTION_HEADER*)(PEfptr + 264 + (40 * ((unsigned long long)(sec_num) - num)));

            //printf_s("sec_%d_is:  %s\n", sec_num - num, _sec_temp.Name);

            if (*(uint64_t*)(_sec_temp.Name) == tar_sec)
            {
                target_sec_VA_start = _sec_temp.VirtualAddress;
                Text_Vsize = _sec_temp.Misc.VirtualSize;
                Text_Remote_RVA = (uintptr_t)hUnityPlayer.modBaseAddr + target_sec_VA_start;
                goto __Get_target_sec;
            }
            num--;
        }
    }
    else
    {
        printf_s("Invalid PE header!");
        VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        return (int)-1;
    }
__Get_target_sec:
    // 在本进程内申请代码段大小的内存 - 用于特征搜索
    LPVOID Copy_Text_VA = VirtualAlloc(0, Text_Vsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Copy_Text_VA == NULL)
    {
        printf("VirtualAlloc Failed! (Text)");
        CloseHandle(pi.hProcess);
        return (int)-1;
    }
    // 把整个模块读出来
    if (ReadProcessMemory(pi.hProcess, (void*)Text_Remote_RVA, Copy_Text_VA, Text_Vsize, 0) == 0)
    {
        printf("Readmem Fail ! (text)");
        VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
        CloseHandle(pi.hProcess);
        return (int)-1;
    }

    printf("Searching for pattern...\n");

	//credit by winTEuser
    uintptr_t address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - last 
    if (!address)
    {
        printf("outdated pattern\n");
        return 0;
    }

    // 计算相对地址 (FPS)
    uintptr_t pfps = 0;
    {
        uintptr_t rip = address;
        rip += 3;
        rip += *(int32_t*)(rip)+6;
        rip += *(int32_t*)(rip)+4;
        pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
        printf("FPS Offset: %X\n", pfps);
        goto __offset_ok;
    }
__offset_ok:
    uintptr_t Patch_ptr = 0;
    {
        Patch_ptr = inject_patch(Copy_Text_VA, Text_Vsize, Text_Remote_RVA, pfps, pi.hProcess);//patch inject 
        if (Patch_ptr == (uintptr_t)NULL)
        {
            printf_s("Inject Patch Fail!\n\n");
        }
    }

    VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
    VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
    printf("Done\n\n");

    DWORD dwExitCode = STILL_ACTIVE;
    while (dwExitCode == STILL_ACTIVE)
    {
        GetExitCodeProcess(pi.hProcess, &dwExitCode);
        Sleep(2000);
    }

    CloseHandle(pi.hProcess);

    return 0;
}
