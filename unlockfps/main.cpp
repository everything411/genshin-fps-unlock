#define KEY_TOGGLE VK_END
#define KEY_INCREASE VK_UP
#define KEY_INCREASE_SMALL VK_RIGHT
#define KEY_DECREASE VK_DOWN
#define KEY_DECREASE_SMALL VK_LEFT
#define FPS_TARGET 120

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <thread>
#include <Psapi.h>
#include "inireader.h"

std::string GamePath{};
int FpsValue = FPS_TARGET;

DWORD StartPriority = 0;
const std::vector<DWORD> PrioityClass = {
   REALTIME_PRIORITY_CLASS,
   HIGH_PRIORITY_CLASS,
   ABOVE_NORMAL_PRIORITY_CLASS,
   NORMAL_PRIORITY_CLASS,
   BELOW_NORMAL_PRIORITY_CLASS,
   IDLE_PRIORITY_CLASS
};
// �������� - ������д�� - �������Ŀ���
uintptr_t PatternScan(void* module, const char* signature)
{
    static auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

    auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

    auto s = patternBytes.size();
    auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
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

std::string GetLastErrorAsString(DWORD code)
{
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
    std::string ret = buf;
    LocalFree(buf);
    return ret;
}

bool GetModule2(HANDLE GameHandle, std::string ModuleName, PMODULEENTRY32 pEntry)
{
    if (!pEntry)
        return false;

    std::vector<HMODULE> modules(1024);
    ZeroMemory(modules.data(), modules.size() * sizeof(HMODULE));
    DWORD cbNeeded = 0;

    if (!EnumProcessModules(GameHandle, modules.data(), modules.size() * sizeof(HMODULE), &cbNeeded))
        return false;

    modules.resize(cbNeeded / sizeof(HMODULE));
    for (auto& it : modules)
    {
        char szModuleName[MAX_PATH]{};
        if (!GetModuleBaseNameA(GameHandle, it, szModuleName, MAX_PATH))
            continue;
        if (ModuleName != szModuleName)
            continue;
        MODULEINFO modInfo{};
        if (!GetModuleInformation(GameHandle, it, &modInfo, sizeof(MODULEINFO)))
            continue;

        pEntry->modBaseAddr = (BYTE*)modInfo.lpBaseOfDll;
        pEntry->modBaseSize = modInfo.SizeOfImage;
        return true;
    }


    return false;
}
// ͨ����������������ID
DWORD GetPID(std::string ProcessName)
{
    DWORD pid = 0;
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32First(snap, &pe32); Process32Next(snap, &pe32);)
    {
        if (pe32.szExeFile == ProcessName)
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return pid;
}

bool WriteConfig(std::string GamePath, int fps)
{
    HANDLE hFile = CreateFileA("fps_config.ini", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD code = GetLastError();
        printf("CreateFileA failed (%d): %s\n", code, GetLastErrorAsString(code).c_str());
        return false;
    }

    std::string content{};
    content = "[Setting]\n";
    content += "Path=" + GamePath + "\n";
    content += "FPS=" + std::to_string(fps);

    DWORD written = 0;
    WriteFile(hFile, content.data(), content.size(), &written, nullptr);
    CloseHandle(hFile);
}

void LoadConfig()
{
    if (GetFileAttributesA("config") != INVALID_FILE_ATTRIBUTES)
        DeleteFileA("config");

    INIReader reader("fps_config.ini");
    if (reader.ParseError() != 0)
    {
        printf("���ò�����\n�벻Ҫ�رմ˽��� - Ȼ���ֶ�������Ϸ\n��ֻ��Ҫ����һ�� - ���ڻ�ȡ��Ϸ·��\n");
        printf("\n�ȴ���Ϸ����...\n");

        DWORD pid = 0;
        while (!(pid = GetPID("YuanShen.exe")) && !(pid = GetPID("GenshinImpact.exe")))
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // ��ȡ���̾�� - ��Ȩ�޺ܵ͵��� - ��Ӧ�û�ȡ����
        // PROCESS_QUERY_LIMITED_INFORMATION - ���ڲ�ѯ����·�� (K32GetModuleFileNameExA)
        // SYNCHRONIZE - ���ڵȴ����̽��� (WaitForSingleObject)
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess)
        {
            DWORD code = GetLastError();
            printf("OpenProcess failed (%d): %s", code, GetLastErrorAsString(code).c_str());
            return;
        }

        char szPath[MAX_PATH]{};
        DWORD length = sizeof(szPath);
        QueryFullProcessImageNameA(hProcess, 0, szPath, &length);

        GamePath = szPath;
        WriteConfig(GamePath, FpsValue);

        HWND hwnd = nullptr;
        while (!(hwnd = FindWindowA("UnityWndClass", nullptr)))
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

        DWORD ExitCode = STILL_ACTIVE;
        while (ExitCode == STILL_ACTIVE)
        {
            SendMessageA(hwnd, WM_CLOSE, 0, 0);
            GetExitCodeProcess(hProcess, &ExitCode);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        // wait for the game to close then continue
        WaitForSingleObject(hProcess, -1);
        CloseHandle(hProcess);

        system("cls");
        return;
    }

    GamePath = reader.Get("Setting", "Path", "");
    FpsValue = reader.GetInteger("Setting", "FPS", FpsValue);

    if (GetFileAttributesA(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        printf("���������Ϸ·���ı��� - ��ʼ��������\n");
        DeleteFileA("config.ini");
        LoadConfig();
    }
}

// �ȼ��߳�
DWORD __stdcall Thread1(LPVOID p)
{
    if (!p)
        return 0;

    int* pTargetFPS = (int*)p;
    int fps = *pTargetFPS;
    int prev = fps;
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
        if (GetAsyncKeyState(KEY_DECREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
            fps -= 20;
        if (GetAsyncKeyState(KEY_DECREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
            fps -= 2;
        if (GetAsyncKeyState(KEY_INCREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
            fps += 20;
        if (GetAsyncKeyState(KEY_INCREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
            fps += 2;
        if (GetAsyncKeyState(KEY_TOGGLE) & 1)
            fps = fps != 60 ? 60 : prev;
        if (prev != fps)
            WriteConfig(GamePath, fps);
        if (fps > 60)
            prev = fps;
        if (fps < 60)
            fps = 60;
        printf("\rFPS: %d - %s    ", fps, fps > 60 ? "ON" : "OFF");
        *pTargetFPS = fps;
    }

    return 0;
}
int main(int argc, char** argv)
{
    std::atexit([] {
        system("pause");
    });

    SetConsoleTitleA("");
    
    std::string CommandLine{};
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
            CommandLine += argv[i] + std::string(" ");
    }

    // ��ȡ����
    LoadConfig();
    int TargetFPS = FpsValue;
    std::string ProcessPath = GamePath;
    std::string ProcessDir{};

    if (ProcessPath.length() < 8)
        return 0;

    printf("FPS���� ���õĻ����star��\n");
    printf("https://github.com/xiaonian233/genshin-fps-unlock \n4.7�汾�ر��лwinTEuser�ϸ�֧�� \n");
    printf("��Ϸ·��: %s\n\n", ProcessPath.c_str());
    ProcessDir = ProcessPath.substr(0, ProcessPath.find_last_of("\\"));

    DWORD pid = GetPID(ProcessPath.substr(ProcessPath.find_last_of("\\") + 1));
    if (pid)
    {
        printf("��⵽��Ϸ�������У�\n");
        printf("�ֶ�������Ϸ�ᵼ��ʧЧ��\n");
        printf("���ֶ��ر���Ϸ - ���������Զ�������Ϸ\n");
        return 0;
    }

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(ProcessPath.c_str(), (LPSTR)CommandLine.c_str(), nullptr, nullptr, FALSE, 0, nullptr, ProcessDir.c_str(), &si, &pi))
    {
        DWORD code = GetLastError();
        printf("CreateProcess failed (%d): %s", code, GetLastErrorAsString(code).c_str());
        return 0;
    }

    CloseHandle(pi.hThread);
    printf("PID: %d\n", pi.dwProcessId);
    StartPriority = PrioityClass[3];
    SetPriorityClass(pi.hProcess, StartPriority);

    // �ȴ�UnityPlayer.dll���غͻ�ȡDLL��Ϣ
    MODULEENTRY32 hUnityPlayer{};
    while (!GetModule2(pi.hProcess, "UnityPlayer.dll", &hUnityPlayer))
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    printf("UnityPlayer: %X%X\n", (uintptr_t)hUnityPlayer.modBaseAddr >> 32 & -1, hUnityPlayer.modBaseAddr);


    // �ڱ�����������UnityPlayer.dll��С���ڴ� - ������������
    LPVOID up = VirtualAlloc(nullptr, hUnityPlayer.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!up)
    {
        DWORD code = GetLastError();
        printf("VirtualAlloc UP failed (%d): %s", code, GetLastErrorAsString(code).c_str());
        return 0;
    }

    // ������ģ�������
    if (!ReadProcessMemory(pi.hProcess, hUnityPlayer.modBaseAddr, up, hUnityPlayer.modBaseSize, nullptr))
    {
        DWORD code = GetLastError();
        printf("ReadProcessMemory unity failed (%d): %s", code, GetLastErrorAsString(code).c_str());
        return 0;
    }


    printf("Searching for pattern...\n");

	//credit by winTEuser
	
    uintptr_t address = PatternScan(up, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - last 
    if (!address)
    {
            printf("outdated pattern\n");
            return 0;
    }

    // ������Ե�ַ (FPS)
    uintptr_t pfps = 0;
    {
        uintptr_t rip = address;
        rip += 3;
        rip += *(int32_t*)(rip)+6;
        rip += *(int32_t*)(rip)+4;
        pfps = rip - (uintptr_t)up + (uintptr_t)hUnityPlayer.modBaseAddr;
        printf("FPS Offset: %X\n", pfps);
    }

    // ������Ե�ַ (��ֱͬ��)
    address = PatternScan(up, "E8 ? ? ? ? 8B E8 49 8B 1E");
    uintptr_t pvsync = 0;
    if (address)
    {
        uintptr_t ppvsync = 0;
        uintptr_t rip = address;
        int32_t rel = *(int32_t*)(rip + 1);
        rip = rip + rel + 5;
        uint64_t rax = *(uint32_t*)(rip + 3);
        ppvsync = rip + rax + 7;
        ppvsync -= (uintptr_t)up;
        printf("VSync Offset: %X\n", ppvsync);
        ppvsync = (uintptr_t)hUnityPlayer.modBaseAddr + ppvsync;

        uintptr_t buffer = 0;
        while (!buffer)
        {
            ReadProcessMemory(pi.hProcess, (LPCVOID)ppvsync, &buffer, sizeof(buffer), nullptr);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        rip += 7;
        pvsync = *(uint32_t*)(rip + 2);
        pvsync = buffer + pvsync;
    }

    VirtualFree(up, 0, MEM_RELEASE);
    printf("Done\n\n");
    printf("����ctrl + ��ͷ����������:\n");
    printf("  ��ctrl + ��: +20\n");
    printf("  ��ctrl + ��: -20\n");
    printf("  ��ctrl + ��: -2\n");
    printf("  ��ctrl + ��: +2\n\n");

    // �����ȼ��߳�
    HANDLE hThread = CreateThread(nullptr, 0, Thread1, &TargetFPS, 0, nullptr);
    if (hThread)
        CloseHandle(hThread);

    DWORD dwExitCode = STILL_ACTIVE;
    while (dwExitCode == STILL_ACTIVE)
    {
        GetExitCodeProcess(pi.hProcess, &dwExitCode);

        // ÿ������һ��
        std::this_thread::sleep_for(std::chrono::seconds(2));
        int fps = 0;
        ReadProcessMemory(pi.hProcess, (LPVOID)pfps, &fps, sizeof(fps), nullptr);
        if (fps == -1)
            continue;
        if (fps != TargetFPS)
            WriteProcessMemory(pi.hProcess, (LPVOID)pfps, &TargetFPS, sizeof(TargetFPS), nullptr);

        int vsync = 0;
        ReadProcessMemory(pi.hProcess, (LPVOID)pvsync, &vsync, sizeof(vsync), nullptr);
        if (vsync)
        {
            vsync = 0;
            // �رմ�ֱͬ��
            WriteProcessMemory(pi.hProcess, (LPVOID)pvsync, &vsync, sizeof(vsync), nullptr);
        }
    }

    CloseHandle(pi.hProcess);
    TerminateProcess((HANDLE)-1, 0);

    return 0;
}
