# Win32 编程简述

## 核心组件

### 1. Win32 SDK (Software Development Kit)

Win32 SDK 是 Microsoft 提供的一套开发工具和库，用于创建 Windows 应用程序。它包含了：

- 头文件：定义了 Windows API 函数、数据类型和常量。
- 库文件：包含了 API 函数的实现。
- 文档：详细的 API 参考和编程指南。
- 工具：如资源编辑器、调试器等。

SDK 允许开发者直接访问 Windows 操作系统的核心功能，如文件系统、图形用户界面、网络等。

### 2. API (Application Programming Interface)

Windows API 是一组函数、协议和工具，用于构建软件应用程序。主要特点包括：

- 提供了访问 Windows 操作系统功能的标准化方法。
- 分为多个子系统，如用户界面、图形设备接口、文件 I/O 等。
- 使用 C 语言风格的函数调用。

许多高级 C 函数在底层确实是通过调用 Win32 API 来实现的。例如：

- fopen() 函数可能在底层调用 CreateFile() Win32 API。
- malloc() 可能使用 HeapAlloc() Win32 API。

### COM (Component Object Model)

Microsoft 的一种跨语言组件技术。
允许不同编程语言编写的组件相互通信。

### .NET Framework

一个高级开发平台，构建于 Win32 之上。
提供了更简单的编程模型和更多的抽象。

### Windows Runtime (WinRT)

- 用于开发现代 Windows 应用的 API 集。
- 支持多种编程语言，如 C++、C#、JavaScript 等。

### HANDLE

Windows 中用于表示资源的不透明数据类型。
常用于文件、进程、线程等资源的引用。

### 消息循环：

Windows 应用程序的核心机制，用于处理用户输入和系统事件。

### GDI (Graphics Device Interface)：

Windows 的核心图形系统，用于绘制图形和文本。

## CPU 保护模式与多任务实现

### CPU 保护模式

80386 及以上 CPU 支持保护模式，为多任务操作系统提供基础：

- 提供高效的任务切换机制
- 实现任务间的内存保护和隔离

### Windows 多任务实现

- 使用"进程"作为资源分配的基本单位
- 进程包含一个或多个线程，线程是 CPU 调度的基本单位
- CPU 通过时间片分配实现多任务
- 任务调度基于线程优先级（可动态调整）
- 进程管理虚拟地址空间，线程执行代码

## Windows 虚拟内存系统

### 基本概念

1. 虚拟地址空间：
   - 32 位系统：0x00000000 到 0xFFFFFFFF（4GB）
   - 64 位系统：理论上可达 16 EB（实际上 Windows 限制为 128 TB）
2. 页面：虚拟内存的基本单位，通常为 4KB
3. 分页：将虚拟地址转换为物理地址的机制

### 虚拟内存的实现

1. 硬件支持：
   - 内存管理单元（MMU）
   - 页表和转换后备缓冲器（TLB）
2. 操作系统支持：
   - 内存管理器
   - 页面文件（页交换文件）

### 进程地址空间布局

1. 用户空间：

   - 32 位系统：0x00000000 到 0x7FFFFFFF（2GB）
   - 可通过 /3GB 开关扩展至 3GB

2. 系统空间：

   - 32 位系统：0x80000000 到 0xFFFFFFFF（2GB）
   - 包含内核、驱动程序等

3. 特点：

   - 每个进程拥有独立的用户空间
   - 系统空间在所有进程间共享

### 虚拟内存的优势

1. 内存隔离：进程间地址空间互相独立，提高安全性
1. 更大的地址空间：超过物理内存限制
1. 内存映射文件：将文件直接映射到内存，提高 I/O 效率
1. 内存保护：可以为不同内存区域设置不同的访问权限
1. 内存优化：通过按需分页（demand paging）提高内存利用率

### 重要概念

1. 提交：为虚拟地址空间分配物理存储（RAM 或页面文件）
1. 保留：标记地址范围为进程专用，但不分配物理存储
1. 释放：返回虚拟地址空间给系统
1. 工作集：进程当前驻留在物理内存中的页面集合

### 编程注意事项

1. 内存分配：使用 `VirtualAlloc` 函数进行大块内存分配
1. 内存释放：使用 `VirtualFree` 函数释放分配的内存
1. 内存保护：使用 `VirtualProtect` 函数更改内存页面的保护属性
1. 大地址感知：64 位系统上启用大地址感知以使用更大的地址空间
1. 内存映射文件：使用 `CreateFileMapping` 和 `MapViewOfFile` 函数

虚拟内存是现代操作系统的核心特性之一，它为应用程序提供了一个抽象的、统一的内存视图，大大简化了内存管理并提高了系统的安全性和效率。理解虚拟内存的工作原理对于开发高性能、可靠的 Windows 应用程序至关重要。

## 用户模式和内核模式

x86 处理器有四种特权级别（0-3），Windows 主要使用两种级别：0（内核模式）和 3（用户模式）。

### 用户模式 (User Mode)

用户模式是应用程序和大多数系统服务运行的模式。用户模式有以下特点：

- 限制权限：用户模式代码不能直接访问硬件或内存中的关键系统区域，访问这些资源需要通过系统调用（System Call）进入内核模式。
- 隔离性：每个应用程序运行在独立的虚拟地址空间中，相互之间隔离，防止一个应用程序的崩溃影响其他应用程序或系统稳定性。
- 内存保护：用户模式代码只能访问受限的内存区域，这有助于防止内存损坏和安全漏洞。
- 系统调用：用户模式程序通过系统调用接口与操作系统内核通信，请求系统服务。

### 内核模式 (Kernel Mode)

内核模式是操作系统核心部分运行的模式，包括操作系统内核、设备驱动程序和一些系统服务。内核模式有以下特点：

- 高权限：内核模式代码具有完全的权限，可以访问所有系统资源，包括硬件、内存和 CPU 指令集。
- 共享地址空间：所有内核模式代码共享相同的地址空间，没有用户模式下的隔离机制，因此内核模式代码的错误可能导致整个系统崩溃。
- 直接硬件访问：内核模式代码可以直接与硬件设备交互，这对于实现高性能的设备驱动程序是必需的。
- 中断处理：内核模式处理硬件中断和异常，确保系统的稳定性和实时响应。

# Windows 系统架构

## Windows 内核对象和句柄

### 内核对象概述

1. 定义：内核对象是操作系统用来管理系统资源的数据结构，存在于内核空间（Ring 0）
1. 作用：提供用户模式（Ring 3）和内核模式（Ring 0）之间的交互接口
1. 特点：

   - 内部结构对用户模式程序不可见
   - 只能通过系统 API 访问
   - 具有安全属性和引用计数

### 句柄（Handle）

1. 定义：句柄是用户模式程序用来引用内核对象的标识符。
1. 类比：可以将句柄理解为数组索引或特殊形式的"指针"。
1. 特点：

   - 对用户程序来说是不透明的（opaque）
   - 进程特定，不能跨进程使用
   - 由操作系统管理生命周期

### 访问机制

- 访问方式：必须同时使用 API 函数和相应的句柄来操作内核对象。
- 安全性：防止用户模式程序直接访问或修改内核数据结构。
- 抽象层：提供了一层抽象，隐藏了底层实现细节。

### 常见内核对象类型

- 进程对象
- 线程对象
- 文件对象
- 事件对象
- 互斥量对象
- 信号量对象

句柄使用示例：

```cpp
HANDLE hFile = CreateFile(
    L"example.txt",
    GENERIC_READ,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);

if (hFile == INVALID_HANDLE_VALUE) {
    // 错误处理
} else {
    // 使用文件句柄进行操作
    // ...
    // 操作完成后关闭句柄
    CloseHandle(hFile);
}
```

**注意事项**

- 资源管理：正确关闭不再使用的句柄，防止资源泄漏。
- 句柄继承：某些情况下，句柄可以被子进程继承，需要注意安全性。
- 句柄复制：使用 `DuplicateHandle` 函数可以在进程间复制句柄。
- 伪句柄：某些特殊句柄（如 `GetCurrentProcess()` 返回的句柄）是伪句柄，不需要关闭。
- 线程安全：在多线程环境中使用句柄时需考虑同步问题。

## Windows 程序和 Console 程序的区别

### 入口函数

- Windows GUI 程序: `WinMain`。
- Console 程序: `main`。
-

### 链接选项

- Windows GUI 程序：`/subsystem:windows`
- console 控制台程序：`/subsystem:console`

Windows 程序示例：

```c
// HelloMsg
#include <windows.h>
int WINAPI WinMain(HINSTANCE hInstance,      //应用程序实例句柄
                    HINSTANCE hPrevInstance, //上一个应用程序实例句柄，暂时没有使用，总是为NULL
                    LPSTR lpCmdLine,         //命令行参数
                    int nCmdShow)            //窗口显示模式
{
    /*
        WINAPI: #define WINAPI  __stdcall 函数调用约定
        windows 所有的API调用约定都是__stdcall，wsprintf(不定长参数)例外
        HINSTANCE LPSTR 都是windows给一些基本数据类型起的别名，目的是为了能
    跨64位平台使用，所以在使用Win32编程时最好使用windows提供的别名。
    还有一个作用就是可读性好。
        在进行位操作时，最好是先获取位数，然后再进行操作，防止32和64位平台不通用
    */
    MessageBox(NULL, "HelloMsg", "Msg", MB_OK);
    return 0;
}
```

编译和链接：

```bash
// 编译链接一起进行
cl /DUNICODE /D_UNICODE /utf-8 HelloMsg.cpp /link user32.lib

// 编译
cl /DUNICODE /D_UNICODE /utf-8 HelloMsg.cpp
// 链接
link HelloMsg.obj /subsystem:windows /entry:wWinMainCRTStartup user32.lib
```

**注意：**

- WINAPI 定义为 `__stdcall`（标准调用约定）。
- 大多数 Windows API 使用 `__stdcall` 调用约定，C 运行时库（CRT）函数使用 `__cdecl` 调用约定。
- 建议使用 Windows 定义的数据类型别名，以提高可读性和跨平台兼容性。
- 在进行位操作时，应考虑 32 位和 64 位平台的差异，适当使用条件编译或跨平台类型。

## 错误处理

### 对所有的 API 都要检查返回值

```cpp
// 显示错误消息
void ShowErrorMsg(int line, const char *function){
    // 获取具体错误信息
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError(); // 获取最后一个错误码
    // 格式化错误消息
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 默认语言
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);
    // 创建包含错误代码、详细信息、行号和函数名的消息缓冲区
    TCHAR szFullMessage[512];
    StringCchPrintf(szFullMessage, _countof(szFullMessage),
                    TEXT("错误代码: %d\n错误描述: %s\n函数: %S\n行号: %d"), dw,
                    (LPTSTR)lpMsgBuf, function, line);
    // 显示错误消息框
    MessageBox(NULL, szFullMessage, TEXT("错误消息"), MB_OK | MB_ICONERROR);
    // 释放由 FormatMessage 分配的内存
    LocalFree(lpMsgBuf);
}
```

关于错误处理的其他重要点：

- `GetLastError()`：这个函数只有在 API 函数明确表示失败时才有意义。一些函数（如 `RegOpenKeyEx`）在失败时会设置一个错误码，而其他函数（如 `GetMessage`）则不会。
- 错误查找工具：

  - 可以使用 VC6.0 中的 `Tool -> ErrorLookup`。
  - 在更现代的 Visual Studio 版本中，可以使用 `Debug -> Windows -> Exception Settings` 来设置特定错误码的断点。

- 在 Watch 窗口中输入 `@err,hr` 可以快速查看最近的错误。
- 系统错误码：Windows 定义了许多标准错误码，如 `ERROR_FILE_NOT_FOUND`，`ERROR_ACCESS_DENIED` 等。这些定义在 `<winerror.h>` 头文件中。
- `HRESULT`：除了 `GetLastError()`，Windows COM 编程中常用 `HRESULT` 来表示错误。可以使用 `SUCCEEDED(hr)` 和 `FAILED(hr)` 宏来检查 `HRESULT` 值。
- 错误日志：在实际应用中，除了显示错误消息，还应该考虑将错误信息记录到日志文件中，以便后续分析。

### 链接错误处理

在 Windows SDK 编程中，有时会遇到这样的情况：使用某个 API 时，代码编译无误，但在链接阶段报错。这通常意味着缺少了必要的库文件。

**解决方法**

1. 查找所需库文件

   - 访问 [Microsoft Docs](https://learn.microsoft.com/zh-cn/windows/win32/api/)（取代了旧的 MSDN）
   - 查找使用的 API 文档
   - 在文档底部查看 "Requirements" 部分，找到 "Library" 信息

2. 添加所需库

   - 对于现代 Visual Studio（推荐使用）：

     - 右击项目 `-> Properties`
     - 导航到 `Linker -> Input`
     - 在 `Additional Dependencies` 中添加所需的库文件

   - 对于命令行编译：

     - 添加 `/LIBPATH` 和相应的库名到链接命令

   - 使用 `#pragma comment()`
     - `#pragma comment(lib, "user32.lib")` 这种方式可以在源代码中直接指定需要链接的库。

3. 常见系统库

   - `kernel32.lib`：核心 Windows 功能
   - `user32.lib`：用户界面相关
   - `gdi32.lib`：图形设备接口
   - `comctl32.lib`：通用控件
   - `comdlg32.lib`：通用对话框

## 字符编码：ASCII 码和 Unicode 码

在 Windows 编程中，我们主要使用两种字符编码：ASCII（American Standard Code for Information Interchange）和 Unicode。

**ASCII 码：**

- 优点：省内存，每个字符只占 1 字节
- 缺点：仅支持 128 个字符，不适用于多语言环境

**Unicode 码：**

- 优点：支持多种语言和符号，更加通用
- 缺点：相对占用更多内存

为了方便开发不同版本的应用程序，Windows 提供了一系列宏和数据类型，使得代码可以在 ASCII 和 Unicode 之间轻松切换。以下是一些常用的宏和类型：

- `TCHAR`：根据编译设置自动选择 `char`（ASCII）或 `wchar_t`（Unicode）
- `TEXT("字符串")`或 `_T("字符串")`：根据编译设置自动选择 ASCII 字符串或 Unicode 字符串
- `LPTSTR`：根据编译设置自动选择 `char*` 或 `wchar_t*` 类型的指针

建议在项目中始终使用这些宏和类型，以确保代码的可移植性和兼容性。

### Windows API 的 Unicode 支持

Windows 系统内部实际上是基于 Unicode 实现的，Unicode 主要使用 `UTF-16LE`（Little Endian）编码。。当我们调用 ASCII 版本的 API 时，系统会自动将参数转换为 Unicode 版本，然后调用相应的 Unicode API。例如：

- 调用 `MessageBoxA`（ASCII 版）实际上会被系统转换并调用 `MessageBoxW`（Unicode 版）
- 调用 `CreateFileA`（ASCII 版）实际上会被系统转换并调用 `CreateFileW`（Unicode 版）

为了获得最佳性能，建议在开发中直接使用 Unicode 版本的 API。可以通过在项目设置中定义 `UNICODE` 和 `_UNICODE` 宏来实现这一点。

一些有用的字符转换 API：

- `MultiByteToWideChar`：将 ASCII（多字节）字符串转换为 Unicode（宽字节）字符串
- `WideCharToMultiByte`：将 Unicode（宽字节）字符串转换为 ASCII（多字节）字符串

## Win32 SDK 开发的步骤

1. WinMain 函数

`_tWinMain` 是 Windows 程序的入口点，相当于控制台程序的 `main` 函数。`_t` 前缀允许代码在 Unicode 和 ANSI 版本之间切换。

```cpp
int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    TCHAR * szCmdLine, int nCmdShow){
}
```

2. 设计、注册窗口类

```cpp
WNDCLASS wc = {0};
wc.style = CS_VREDRAW | CS_HREDRAW;
wc.lpfnWndProc = WindowProc;
wc.hInstance = hInstance;
wc.lpszClassName = TEXT("CKCat");

if (!RegisterClass(&wc))
{
   ShowErrorMsg();
   return 0;
}
```

这段代码定义并注册了一个窗口类。还可以添加图标、光标和背景画刷：

```cpp
wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
wc.hCursor = LoadCursor(NULL, IDC_ARROW);
wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
```

3. 创建并显示窗口

```cpp
HWND hwnd = CreateWindow(...);
if (hwnd == NULL){
   ShowErrorMsg();
   return 0;
}
ShowWindow(hwnd, SW_SHOWNORMAL);
```

创建窗口后，应该添加 `UpdateWindow(hwnd);` 来刷新客户区。

4. 消息循环

```cpp
MSG msg = {0};
while (GetMessage(&msg, NULL, 0, 0)){
   DispatchMessage(&msg);
}
```

为了更好地处理键盘消息，还应在 `DispatchMessage` 前添加 `TranslateMessage(&msg);`。

5. 编写过程函数

```cpp
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg,
    WPARAM wParam, LPARAM lParam){
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
```

这是一个基本的窗口过程函数。在实际应用中，需要在这里处理各种窗口消息。例如：

```cpp
switch (uMsg)
{
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        // 绘制代码
        EndPaint(hwnd, &ps);
    }
    return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
}
```

# Windows 消息

Windows 消息是 Windows GUI 编程的核心概念之一，它是实现用户交互和系统事件处理的基础机制。

在实际开发中，经常需要确定一个 API 是否会发送消息，这时可以在 MSDN 文档中，查看 Remarks 部分通常会说明一个 API 是否发送消息。

- `Return value` 部分可能会提到某些返回值对应于发送的消息
- `See also` 部分可能会链接到相关的消息定义

进行 windows 消息测试时不应该使用窗口输出，也不应该使用 debug 模式进行调试，因为有可能发生窗口覆盖问题，导致消息不能被全部接收到。可以使用下面的方法查看消息：

1. 可以使用 `OutputDebugString()`函数配合 `DebugView` 工具查看消息。

   ```c
   void TraceMessage(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
   {
       TCHAR szBuffer[256];
       StringCchPrintf(szBuffer, _countof(szBuffer),
           TEXT("Message: 0x%04X, wParam: 0x%08X, lParam: 0x%08X\n"),
           message, wParam, lParam);
       OutputDebugString(szBuffer);
   }

   // 在WindowProc中使用
   LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
   {
       TraceMessage(hwnd, uMsg, wParam, lParam);
       // ... 其他处理代码
   }
   ```

2. 在 Visual Studio 中，可以使用 Watch 窗口来监视消息。将 `uMsg, wm` 添加到 Watch 窗口中，以查看当前消息的值。

3. 在窗口过程函数中设置条件断点，只在特定消息时中断。这有助于集中调试特定的消息。

   ```c

   LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
       if (uMsg == WM_PAINT) {
           __debugbreak();  // 仅在 WM_PAINT 消息时中断
       }

       // ... 其他消息处理
       return DefWindowProc(hwnd, uMsg, wParam, lParam);
   }
   ```

4. 使用 Spy++ 工具

   Spy++ 是 Visual Studio 附带的一个强大工具，可以实时监视和记录窗口消息。它可以显示消息、参数和时间戳，有助于分析和调试窗口消息。

   - 启动 Spy++（在 Visual Studio 的工具菜单中）。
   - 使用 Spy++ 查找窗口（可以通过窗口标题或句柄）。
   - 使用 Spy++ 监视窗口消息。
     - 选择窗口后，右键单击并选择“Messages”以开始监视消息。

## 客户区与非客户区

这是 Windows 编程中的一个基本概念：

- 客户区：窗口的主要工作区域，应用程序可以在此绘制和响应用户输入。
- 非客户区：包括标题栏、菜单、滚动条和边框等窗口装饰部分。

重要的区别：

- 绘制：客户区通过处理 `WM_PAINT` 消息来绘制；非客户区由系统处理。
- 消息：某些消息（如 `WM_NCHITTEST`）专门用于非客户区。
- 坐标系：客户区和非客户区使用不同的坐标系。

示例代码，展示如何区分客户区和非客户区点击：

```cpp
case WM_NCHITTEST:
{
    POINT pt = { LOWORD(lParam), HIWORD(lParam) };
    ScreenToClient(hwnd, &pt);
    if (pt.y < 30)  // 假设前30像素是自定义标题栏
        return HTCAPTION;
    return HTCLIENT;
}

case WM_LBUTTONDOWN:
{
    // 这里处理客户区的鼠标点击
    POINT pt = { LOWORD(lParam), HIWORD(lParam) };
    // 处理点击...
}
```

## 消息的分类

### 标准消息 (WM_xxxxxx)

标准消息包括所有 Windows 系统定义的基本消息，这些消息用于处理窗口的基本行为，例如创建、销毁、绘制和输入处理等。以下是一些常见的标准消息：

- `WM_CREATE`: 在窗口创建时发送。
- `WM_DESTROY`: 在窗口销毁时发送。
- `WM_PAINT`: 在窗口需要重绘时发送。
- `WM_CLOSE`: 用户尝试关闭窗口时发送。

示例：

```c
case WM_CREATE:
    // 处理窗口创建
    break;
case WM_DESTROY:
    PostQuitMessage(0);
    break;
case WM_PAINT:
    // 处理窗口重绘
    break;
```

### 命令消息 (WM_COMMAND)

命令消息用于处理来自菜单、按钮等控件的命令。当用户与控件交互时，例如点击按钮或选择菜单项，控件会向其父窗口发送 `WM_COMMAND` 消息。

示例：

```c
case WM_COMMAND:
    switch (LOWORD(wParam)) {
        case ID_FILE_OPEN:
            // 处理“打开”命令
            break;
        case ID_FILE_SAVE:
            // 处理“保存”命令
            break;
    }
    break;
```

### 通知消息 (WM_NOTIFY)

通知消息用于控件向其父窗口发送的复杂消息，通常与高级控件如列表视图、树视图等相关。这些消息通常包含更详细的信息，如控件的状态变化或用户的特定操作。

示例：

```c
case WM_NOTIFY:
    LPNMHDR pnmhdr = (LPNMHDR)lParam;
    switch (pnmhdr->code) {
        case NM_CLICK:
            // 处理点击事件
            break;
        case LVN_ITEMCHANGED:
            // 处理列表视图项更改
            break;
    }
    break;
```

### 定义自定义消息

自定义消息的定义通常使用 `WM_USER` 或 `WM_APP` 常量来确保不与系统保留的消息值冲突：

```c
#define WM_MY_CUSTOM_MESSAGE (WM_USER + 1)
```

可以使用 `SendMessage` 或 `PostMessage` 函数发送自定义消息：

```c
// 发送消息
SendMessage(hWnd, WM_MY_CUSTOM_MESSAGE, wParam, lParam);

// 发布消息
PostMessage(hWnd, WM_MY_CUSTOM_MESSAGE, wParam, lParam);
```

在窗口过程函数中处理自定义消息：

```c

LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_MY_CUSTOM_MESSAGE:
            // 处理自定义消息
            return 0;
        // 其他消息处理
        default:
            return DefWindowProc(hWnd, uMsg, wParam, lParam);
    }
}
```

## 获取窗口句柄

在 Windows 编程中，获取窗口句柄是一项常见的任务。除了 `FindWindow()` 和 `GetWindow()` 方法，还有其他方法可以用于获取窗口句柄，例如 `EnumWindows()`、`EnumChildWindows()` 和 `GetDesktopWindow()`。

1. `FindWindow()` 根据窗口类名和窗口标题查找窗口句柄。它返回第一个匹配的窗口句柄。

```c
HWND hWnd = FindWindow(TEXT("ClassName"), TEXT("WindowTitle"));
if (hWnd != NULL) {
    // 窗口句柄 hWnd 有效
}
```

2. `GetWindow()` 获取与指定窗口相关的窗口句柄，例如兄弟窗口、父窗口或子窗口。

```c
HWND hWndNext = GetWindow(hWnd, GW_HWNDNEXT); // 获取下一个兄弟窗口
if (hWndNext != NULL) {
    // 窗口句柄 hWndNext 有效
}
```

3. `EnumWindows()` 枚举所有顶级窗口。它会调用一个回调函数来处理每个窗口。

```c
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    // 处理每个顶级窗口
    return TRUE; // 返回 TRUE 继续枚举，返回 FALSE 停止枚举
}

EnumWindows(EnumWindowsProc, 0);
```

4. `EnumChildWindows()` 枚举指定父窗口的所有子窗口。它也会调用一个回调函数来处理每个子窗口。

```c
BOOL CALLBACK EnumChildProc(HWND hWnd, LPARAM lParam) {
    // 处理每个子窗口
    return TRUE; // 返回 TRUE 继续枚举，返回 FALSE 停止枚举
}

EnumChildWindows(parentHWnd, EnumChildProc, 0);
```

5. `GetDesktopWindow()` 获取桌面窗口的句柄，桌面窗口是所有顶级窗口的父窗口。

```c
HWND hDesktopWnd = GetDesktopWindow();
if (hDesktopWnd != NULL) {
    // 窗口句柄 hDesktopWnd 有效
}
```

示例代码:

```c
#include <windows.h>
#include <tchar.h>
#include <stdio.h>

// 回调函数，用于处理顶级窗口
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    TCHAR windowTitle[256];
    GetWindowText(hWnd, windowTitle, sizeof(windowTitle) / sizeof(TCHAR));
    _tprintf(TEXT("窗口句柄: %p, 窗口标题: %s\n"), hWnd, windowTitle);
    return TRUE; // 继续枚举
}

int main() {
    // 1. 使用 FindWindow 查找窗口
    HWND hWnd = FindWindow(TEXT("Notepad"), NULL);
    if (hWnd != NULL) {
        _tprintf(TEXT("找到的窗口句柄: %p\n"), hWnd);
    } else {
        _tprintf(TEXT("未找到窗口\n"));
    }

    // 2. 使用 GetWindow 获取下一个兄弟窗口
    HWND hNextWnd = GetWindow(hWnd, GW_HWNDNEXT);
    if (hNextWnd != NULL) {
        _tprintf(TEXT("下一个兄弟窗口句柄: %p\n"), hNextWnd);
    }

    // 3. 使用 EnumWindows 枚举所有顶级窗口
    _tprintf(TEXT("枚举所有顶级窗口:\n"));
    EnumWindows(EnumWindowsProc, 0);

    // 4. 使用 GetDesktopWindow 获取桌面窗口句柄
    HWND hDesktopWnd = GetDesktopWindow();
    if (hDesktopWnd != NULL) {
        _tprintf(TEXT("桌面窗口句柄: %p\n"), hDesktopWnd);
    }

    return 0;
}
```

使用 spy++ 可以获取窗口的类名等信息。

## Z-Order

Z-Order 决定了重叠窗口的显示顺序。窗口的 Z-Order 越高，它在显示时越靠前。Windows 提供了几个 API 来操作窗口的 Z-Order。

1. `SetWindowPos()`用于改变窗口的位置、大小和 Z-Order。它可以将窗口置于其他窗口之前或之后。

示例：

```c
SetWindowPos(hWnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
```

参数说明：

    - hWnd: 要设置的窗口句柄。
    - `HWND_TOP`: 表示将窗口置于 Z-Order 的顶层。其他选项包括 `HWND_BOTTOM`（底层）、`HWND_TOPMOST`（始终在顶层）和 `HWND_NOTOPMOST`（不总是在顶层）。
    - 0, 0, 0, 0: 窗口的新位置和大小。当只改变 Z-Order 时可以忽略这些值。
    - `SWP_NOMOVE | SWP_NOSIZE`: 不改变窗口的位置和大小，只改变 Z-Order。

2. `BringWindowToTop()` 将指定窗口置于顶层。它相当于调用 `SetWindowPos()` 并将 `HWND_TOP` 作为参数。

示例：

```c
BringWindowToTop(hWnd);
```

3. `GetTopWindow()` 获取 Z-Order 最顶层的子窗口句柄。

示例：

```c
HWND hTopWnd = GetTopWindow(parentHWnd);
if (hTopWnd != NULL) {
    // 处理顶层子窗口
}
```

以下示例展示了如何使用这些 API 来改变窗口的 Z-Order 并获取 Z-Order 最顶层的子窗口：

```c
#include <windows.h>
#include <tchar.h>

int main() {
    // 获取桌面窗口句柄
    HWND hDesktopWnd = GetDesktopWindow();

    // 查找一个示例窗口（假设是记事本窗口）
    HWND hWnd = FindWindow(TEXT("Notepad"), NULL);
    if (hWnd != NULL) {
        // 将窗口置于顶层
        SetWindowPos(hWnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

        // 或使用 BringWindowToTop 将窗口置于顶层
        BringWindowToTop(hWnd);
    } else {
        _tprintf(TEXT("未找到窗口\n"));
    }

    // 获取桌面窗口最顶层的子窗口
    HWND hTopWnd = GetTopWindow(hDesktopWnd);
    if (hTopWnd != NULL) {
        TCHAR windowTitle[256];
        GetWindowText(hTopWnd, windowTitle, sizeof(windowTitle) / sizeof(TCHAR));
        _tprintf(TEXT("顶层子窗口句柄: %p, 窗口标题: %s\n"), hTopWnd, windowTitle);
    } else {
        _tprintf(TEXT("未找到顶层子窗口\n"));
    }

    return 0;
}
```

## 获取设备上下文句柄

在 Windows 编程中，获取设备上下文句柄（Device Context Handle, DC）用于在窗口或控件上绘图。主要方法包括 `BeginPaint` 和 `GetDC`，它们在不同情况下具有不同的用途。以下是它们的详细说明及用法：

1. `BeginPaint` 函数用于在处理 `WM_PAINT` 消息时获取设备上下文句柄。它只有在产生无效区域时才会重新绘制，可以使用 `InvalidateRect` 或 `InvalidateRgn` 强制产生无效区域。在处理 `WM_PAINT` 消息时，必须成对地调用 `BeginPaint` 和 `EndPaint`。

示例：

```c
case WM_PAINT:
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hWnd, &ps);
    // 在这里进行绘图操作，只会在无效区域上绘图
    TextOut(hdc, 10, 10, TEXT("Hello, World!"), 13);
    EndPaint(hWnd, &ps);
    break;
}
```

2. `GetDC` 函数用于获取整个窗口（客户区）的设备上下文句柄，不仅限于无效区域。`GetDC` 传回的设备上下文句柄具有一个剪裁矩形，它等于整个显示区域，可以在显示区域的任何部分绘图。与 `BeginPaint` 不同，`GetDC` 不会使任何无效区域变为有效。在使用 `GetDC` 时，必须成对地调用 `GetDC` 和 `ReleaseDC`。

示例：

```c
HDC hdc = GetDC(hWnd);
// 在这里进行绘图操作，可以在整个窗口区域绘图
Rectangle(hdc, 50, 50, 200, 200);
ReleaseDC(hWnd, hdc);
```

3. `GetWindowDC` 函数用于获取指定窗口整个窗口区域（包括客户区和非客户区）的设备上下文句柄。它可以用于在窗口的非客户区进行绘图操作。

```c
HDC hdc = GetWindowDC(hWnd);
// 在整个窗口区域进行绘图操作
TextOut(hdc, 10, 10, TEXT("Drawing in Non-Client Area"), 27);
ReleaseDC(hWnd, hdc);
```

什么是无效区域？

无效区域（Invalid Region）是窗口中需要重新绘制的部分。系统会在以下情况自动创建无效区域：

- 窗口被遮挡并重新显示。
- 窗口大小发生变化。
- 用户调用 `InvalidateRect` 或 `InvalidateRgn` 函数。

## 菜单

### 使用资源脚本（.rc 文件）创建菜单

这是最常见的方法，特别是对于静态菜单。

1. 在资源文件中定义菜单：

```c
IDR_MAINMENU MENU
BEGIN
    POPUP "&File"
    BEGIN
        MENUITEM "&New",                        ID_FILE_NEW
        MENUITEM "&Open...",                    ID_FILE_OPEN
        MENUITEM SEPARATOR
        MENUITEM "E&xit",                       ID_FILE_EXIT
    END
    POPUP "&Help"
    BEGIN
        MENUITEM "&About",                      ID_HELP_ABOUT
    END
END
```

2. 在窗口创建时设置菜单：

```c
HWND hwnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
    CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

HMENU hMenu = LoadMenu(hInstance, MAKEINTRESOURCE(IDR_MAINMENU));
SetMenu(hwnd, hMenu);
```

### 使用 API 动态创建菜单

这种方法适用于需要在运行时动态更改的菜单。

```c
HMENU hMenu = CreateMenu();
HMENU hSubMenu = CreatePopupMenu();

AppendMenu(hSubMenu, MF_STRING, ID_FILE_NEW, TEXT("&New"));
AppendMenu(hSubMenu, MF_STRING, ID_FILE_OPEN, TEXT("&Open..."));
AppendMenu(hSubMenu, MF_SEPARATOR, 0, NULL);
AppendMenu(hSubMenu, MF_STRING, ID_FILE_EXIT, TEXT("E&xit"));

AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hSubMenu, TEXT("&File"));

HMENU hHelpMenu = CreatePopupMenu();
AppendMenu(hHelpMenu, MF_STRING, ID_HELP_ABOUT, TEXT("&About"));
AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, TEXT("&Help"));

SetMenu(hwnd, hMenu);
```

### 处理菜单消息

无论使用哪种方法创建菜单，都需要处理菜单消息：

```c
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case ID_FILE_NEW:
                    // 处理"新建"菜单项
                    break;
                case ID_FILE_OPEN:
                    // 处理"打开"菜单项
                    break;
                case ID_FILE_EXIT:
                    DestroyWindow(hwnd);
                    break;
                case ID_HELP_ABOUT:
                    // 显示"关于"对话框
                    break;
            }
            break;

        // ... 其他消息处理
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
```

## 上下文菜单（右键菜单）

创建和显示上下文菜单：

```c
case WM_CONTEXTMENU:
{
    HMENU hPopupMenu = CreatePopupMenu();
    AppendMenu(hPopupMenu, MF_STRING, ID_CONTEXT_ITEM1, TEXT("Item 1"));
    AppendMenu(hPopupMenu, MF_STRING, ID_CONTEXT_ITEM2, TEXT("Item 2"));

    POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
    TrackPopupMenu(hPopupMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hPopupMenu);
    break;
}
```

添加图标到菜单项

```c
HICON hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MYICON));
SetMenuItemBitmaps(hMenu, ID_FILE_NEW, MF_BYCOMMAND, (HBITMAP)hIcon, (HBITMAP)hIcon);
```

启用/禁用菜单项

```c
EnableMenuItem(hMenu, ID_FILE_SAVE, MF_BYCOMMAND | MF_GRAYED);
```

检查/取消检查菜单项

```c
CheckMenuItem(hMenu, ID_VIEW_STATUSBAR, MF_BYCOMMAND | MF_CHECKED);
```

更新菜单状态

在 WM_INITMENUPOPUP 消息中更新菜单状态：

```c
case WM_INITMENUPOPUP:
{
    HMENU hPopupMenu = (HMENU)wParam;
    // 更新菜单项状态
    break;
}
```

## 创建图标

### 使用 Visual Studio 工具创建图标

- 右键单击解决方案资源管理器中的项目。
- 选择“添加” -> “新建项”。
- 选择“图标文件 (.ico)”并命名图标文件，例如 myicon.ico。

在资源脚本文件 (.rc) 中定义图标资源：

```c
// 资源脚本文件 (resource.rc)
IDI_MYICON ICON "myicon.ico"
```

加载并使用图标资源，例如设置窗口的图标：

```c

// 在窗口创建时设置图标
HICON hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MYICON));
SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
```

## 控件

Windows 控件是预定义的特殊子窗口，用于实现常见的用户界面元素。以下是一些常见控件和高级控件的说明，以及使用通用控件的初始化方法。
常见控件

### Button

按钮控件，用于触发事件。

```c
HWND hButton = CreateWindow(
    TEXT("BUTTON"), TEXT("Click Me"),
    WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
    10, 10, 100, 30,
    hwnd, (HMENU)IDC_BUTTON, hInstance, NULL);
```

### Edit

编辑框控件，用于文本输入。

```c
HWND hEdit = CreateWindow(
    TEXT("EDIT"), NULL,
    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
    10, 50, 200, 20,
    hwnd, (HMENU)IDC_EDIT, hInstance, NULL);
```

### ListBox

列表框控件，用于显示列表项。

```c
HWND hListBox = CreateWindow(
    TEXT("LISTBOX"), NULL,
    WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOTIFY,
    10, 80, 200, 100,
    hwnd, (HMENU)IDC_LISTBOX, hInstance, NULL);
```

### ComboBox

组合框控件，结合了编辑框和列表框。

```c
HWND hComboBox = CreateWindow(
    TEXT("COMBOBOX"), NULL,
    WS_CHILD | WS_VISIBLE | WS_BORDER | CBS_DROPDOWN,
    10, 190, 200, 200,
    hwnd, (HMENU)IDC_COMBOBOX, hInstance, NULL);
```

### Static

静态控件，用于显示文本或图像。

```c
HWND hStatic = CreateWindow(
    TEXT("STATIC"), TEXT("Label"),
    WS_CHILD | WS_VISIBLE,
    10, 220, 200, 20,
    hwnd, (HMENU)IDC_STATIC, hInstance, NULL);
```

### ScrollBar

滚动条控件，用于滚动内容。

```c
    HWND hScrollBar = CreateWindow(
        TEXT("SCROLLBAR"), NULL,
        WS_CHILD | WS_VISIBLE | SBS_HORZ,
        10, 250, 200, 20,
        hwnd, (HMENU)IDC_SCROLLBAR, hInstance, NULL);
```

### ListView

列表视图控件，用于显示项的集合，可以是详细信息、图标等形式。

```c
HWND hListView = CreateWindow(
    WC_LISTVIEW, NULL,
    WS_CHILD | WS_VISIBLE | LVS_REPORT,
    220, 10, 300, 200,
    hwnd, (HMENU)IDC_LISTVIEW, hInstance, NULL);
```

### TreeView

树视图控件，用于显示分层数据。

```c
HWND hTreeView = CreateWindow(
    WC_TREEVIEW, NULL,
    WS_CHILD | WS_VISIBLE | TVS_HASLINES,
    220, 220, 300, 200,
    hwnd, (HMENU)IDC_TREEVIEW, hInstance, NULL);
```

### TabControl

选项卡控件，用于在同一个区域显示多个页面。

```c
    HWND hTabControl = CreateWindow(
        WC_TABCONTROL, NULL,
        WS_CHILD | WS_VISIBLE,
        530, 10, 300, 200,
        hwnd, (HMENU)IDC_TABCONTROL, hInstance, NULL);
```

### 使用通用控件

一些高级控件（如 ListView、TreeView、TabControl 等）属于通用控件，需要通过 `CommCtrl32.dll` 初始化。

1. 包含头文件和链接库：

```c

#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")
```

2. 初始化通用控件：

```c
INITCOMMONCONTROLSEX icex;
icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_TAB_CLASSES;
InitCommonControlsEx(&icex);
```

## 创建子窗口

在 Windows 应用程序中，子窗口是附属于父窗口的窗口，可以在父窗口的客户区内显示和操作。子窗口的创建通常在处理 WM_CREATE 消息时进行。

以下示例展示了如何在 WM_CREATE 消息中创建一个编辑控件 (EDIT) 作为子窗口：

```c
#include <windows.h>

#define IDC_EDIT 1000

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSEX wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WindowProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = TEXT("MainWindowClass");
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    RegisterClassEx(&wcex);

    HWND hwnd = CreateWindow(
        TEXT("MainWindowClass"), TEXT("Main Window with Sub Window"),
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 500, 400,
        NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            HWND hEdit = CreateWindow(
                TEXT("EDIT"), NULL,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE,
                10, 10, 300, 200,
                hwnd, (HMENU)IDC_EDIT, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
            if (!hEdit) {
                MessageBox(hwnd, TEXT("Failed to create edit control."), TEXT("Error"), MB_OK | MB_ICONERROR);
                return -1;
            }
            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
```

## WM_COMMAND 消息

WM_COMMAND 消息用于处理菜单、控件和快捷键的通知。通过检查 wParam 和 lParam 的值，可以确定消息的来源和类型。

WM_COMMAND 消息包含以下参数：

- wParam：
  - 高位字 (HIWORD(wParam)): 通知码 (wNotifyCode)
  - 低位字 (LOWORD(wParam)): 资源 ID (wID)
- lParam：控件句柄 (hwndCtl)

WM_COMMAND 消息来源

| 消息来源 | HIWORD(wParam) (高位字) | LOWORD(wParam) (低位字) | lParam   |
| -------- | ----------------------- | ----------------------- | -------- |
| 菜单     | 0                       | 菜单标识符 (IDM\_\*)    | 0        |
| 快捷键   | 1                       | 快捷键标识符 (IDM\_\*)  | 0        |
| 控件     | 控件定义的通知码        | 控件标识符              | 控件句柄 |

以下是处理 WM_COMMAND 消息的代码示例：

```c
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_COMMAND: {
            int wNotifyCode = HIWORD(wParam); // 通知码
            int wID = LOWORD(wParam);         // 资源ID
            HWND hwndCtl = (HWND)lParam;      // 控件句柄

            // 判断消息来源
            if (hwndCtl != NULL) {
                // 消息来自控件
                switch (wID) {
                    case IDC_BUTTON1:
                        // 处理按钮点击
                        break;
                    case IDC_EDIT1:
                        // 处理编辑控件通知
                        if (wNotifyCode == EN_CHANGE) {
                            // 编辑内容改变
                        }
                        break;
                    // 处理其他控件通知
                }
            } else if (wNotifyCode == 0) {
                // 消息来自菜单
                switch (wID) {
                    case IDM_FILE_NEW:
                        // 处理“新建”菜单项
                        break;
                    case IDM_FILE_OPEN:
                        // 处理“打开”菜单项
                        break;
                    case IDM_FILE_EXIT:
                        // 处理“退出”菜单项
                        DestroyWindow(hwnd);
                        break;
                    // 处理其他菜单项
                }
            } else if (wNotifyCode == 1) {
                // 消息来自快捷键
                switch (wID) {
                    case IDM_SHORTCUT1:
                        // 处理快捷键
                        break;
                    // 处理其他快捷键
                }
            }
            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
```

## 控件消息

Windows 应用程序中，控件发送的通知消息通过 WM_COMMAND 消息传递到父窗口。了解不同控件的通知消息类型，以及如何处理和发送这些消息，对于开发交互式用户界面非常重要。

1. 通知消息类型

不同类型的控件有各自特定的通知消息，常见的有：

    Edit 控件通知消息：EN_xxxx
    Button 控件通知消息：BN_xxxx
    ListBox 控件通知消息：LBN_xxxx
    ComboBox 控件通知消息：CBN_xxxx

2. 消息处理

通过 WM_COMMAND 消息响应控件的通知消息。可以解析 wParam 和 lParam 来获取通知码、控件 ID 和控件句柄：

```c
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_COMMAND: {
            UINT notifyCode = HIWORD(wParam);  // 通知码
            UINT controlId = LOWORD(wParam);   // 控件 ID
            HWND hwndControl = (HWND)lParam;   // 控件句柄

            // 根据不同的控件 ID 和通知码处理消息
            switch (controlId) {
                case IDC_EDIT:
                    switch (notifyCode) {
                        case EN_CHANGE:
                            // 处理 Edit 控件内容改变的通知
                            break;
                        // 处理其他 Edit 控件的通知
                    }
                    break;

                case IDC_BUTTON:
                    switch (notifyCode) {
                        case BN_CLICKED:
                            // 处理 Button 控件的点击事件
                            break;
                        // 处理其他 Button 控件的通知
                    }
                    break;

                // 处理其他控件的通知消息
            }
            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
```

3. 通知码含义

   - notifyCode == 1：快捷键
   - notifyCode == 0：菜单项
   - 其他值：控件特定通知

4. 向控件发送消息

可以使用 SendMessage 函数向控件发送消息。例如，向编辑控件发送 WM_SETTEXT 消息以设置其文本：

```c
SendMessage(hwndControl, WM_SETTEXT, 0, (LPARAM)TEXT("New Text"));
```

## SendMessage 和 PostMessage

### SendMessage

SendMessage 函数将消息发送到指定的窗口，并等待消息处理完毕后返回。它是一种同步的消息传递方式。

```c
LRESULT SendMessage(
    HWND hWnd,      // 目标窗口句柄
    UINT Msg,       // 消息标识符
    WPARAM wParam,  // 第一个消息参数
    LPARAM lParam   // 第二个消息参数
);
```

### PostMessage

PostMessage 函数将消息放入指定窗口的消息队列中，并立即返回而不等待消息处理。它是一种异步的消息传递方式。

```c
BOOL PostMessage(
    HWND hWnd,      // 目标窗口句柄
    UINT Msg,       // 消息标识符
    WPARAM wParam,  // 第一个消息参数
    LPARAM lParam   // 第二个消息参数
);
```

### 同步 vs. 异步:

    SendMessage 是同步的：调用者会等待消息被目标窗口处理完毕后才返回。
    PostMessage 是异步的：消息被放入目标窗口的消息队列后，函数立即返回，不等待消息处理。

### 返回值:

    SendMessage 返回消息处理的结果 (LRESULT)。
    PostMessage 只返回一个布尔值，表示消息是否成功被放入消息队列。

### 应用场景:

    使用 SendMessage 当你需要立即获得消息处理的结果，或者需要确保消息被立即处理。
    使用 PostMessage 当你不需要立即获得消息处理的结果，或者想要避免长时间的等待。

## 获取控件句柄

在 Windows 编程中，获取控件句柄是非常常见的操作。通常，我们会使用 GetDlgItem 函数来获取控件句柄。此外，还有其他一些方法可以用于获取控件句柄。下面详细介绍这些方法。

### 使用 GetDlgItem 函数

GetDlgItem 函数可以根据父窗口句柄和控件的 ID 获取控件句柄。这是最常用的方法。
语法

```c
HWND GetDlgItem(
    HWND hDlg,    // 父窗口句柄
    int nIDDlgItem  // 控件的 ID
);
```

示例

```c
#include <windows.h>

void GetEditControlHandle(HWND hwndParent) {
    int controlId = 1000; // 控件 ID
    HWND hEdit = GetDlgItem(hwndParent, controlId);
    if (hEdit != NULL) {
        // 成功获取控件句柄
        SetWindowText(hEdit, TEXT("Hello, Edit Control!"));
    }
}
```

### 遍历子窗口

可以使用 EnumChildWindows 函数枚举所有子窗口，通过回调函数查找特定的控件句柄。
语法

```c

BOOL EnumChildWindows(
    HWND hWndParent,     // 父窗口句柄
    WNDENUMPROC lpEnumFunc,  // 回调函数指针
    LPARAM lParam        // 传递给回调函数的应用程序定义值
);
```

示例

```c

#include <windows.h>

BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam) {
    int controlId = GetDlgCtrlID(hwnd); // 获取控件 ID
    if (controlId == 1000) {
        // 找到目标控件
        HWND *phEdit = (HWND *)lParam;
        *phEdit = hwnd;
        return FALSE; // 停止枚举
    }
    return TRUE; // 继续枚举
}

void FindControlWithEnum(HWND hwndParent) {
    HWND hEdit = NULL;
    EnumChildWindows(hwndParent, EnumChildProc, (LPARAM)&hEdit);
    if (hEdit != NULL) {
        // 成功获取控件句柄
        SetWindowText(hEdit, TEXT("Hello, EnumChildWindows!"));
    }
}
```

### 直接在创建控件时获取句柄

在创建控件时，CreateWindow 或 CreateWindowEx 函数会返回控件的句柄。
语法

```c

HWND CreateWindowEx(
    DWORD dwExStyle,    // 扩展窗口风格
    LPCTSTR lpClassName,  // 注册的窗口类名或控件类名
    LPCTSTR lpWindowName, // 窗口名称
    DWORD dwStyle,      // 窗口风格
    int x,              // 窗口位置的 x 坐标
    int y,              // 窗口位置的 y 坐标
    int nWidth,         // 窗口宽度
    int nHeight,        // 窗口高度
    HWND hWndParent,    // 父窗口句柄
    HMENU hMenu,        // 菜单句柄或控件 ID
    HINSTANCE hInstance, // 应用程序实例句柄
    LPVOID lpParam      // 窗口创建数据
);
```

示例

```c

#include <windows.h>

void CreateAndStoreControlHandle(HWND hwndParent) {
    HWND hEdit = CreateWindowEx(
        0, TEXT("EDIT"), NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE,
        0, 100, 300, 500,
        hwndParent, (HMENU)1000, NULL, NULL
    );

    if (hEdit != NULL) {
        // 成功创建控件并获取控件句柄
        SetWindowText(hEdit, TEXT("Hello, CreateWindowEx!"));
    }
}
```

### 使用控件类名查找控件

在某些情况下，可以使用 FindWindowEx 函数通过控件类名和窗口名称来查找控件。
语法

```c

HWND FindWindowEx(
    HWND hWndParent,    // 父窗口句柄
    HWND hWndChildAfter, // 子窗口句柄
    LPCTSTR lpszClass,  // 控件类名
    LPCTSTR lpszWindow // 窗口名称
);
```

示例

```c

#include <windows.h>

void FindControlWithClassName(HWND hwndParent) {
    HWND hEdit = FindWindowEx(hwndParent, NULL, TEXT("EDIT"), NULL);
    if (hEdit != NULL) {
        // 成功查找控件并获取控件句柄
        SetWindowText(hEdit, TEXT("Hello, FindWindowEx!"));
    }
}
```

## 快捷键

在 Windows 编程中，快捷键（也称为加速键或热键）是一种用户可以通过键盘快速执行命令的方式。快捷键可以通过多种方式实现，常见的方法包括使用 WM_COMMAND 消息、注册全局热键和使用加速表（Accelerator Table）。

### 使用 WM_COMMAND 处理快捷键

当快捷键与菜单项绑定时，按下快捷键会发送 WM_COMMAND 消息。这种方式非常适合在菜单项中指定快捷键。
示例

```c

#include <windows.h>

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_FILE_OPEN) {
                // 处理 "Ctrl+O" 快捷键
                MessageBox(hwnd, TEXT("Open command triggered by Ctrl+O"), TEXT("Info"), MB_OK);
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 注册窗口类和创建窗口代码省略...

    HMENU hMenu = CreateMenu();
    AppendMenu(hMenu, MF_STRING, ID_FILE_OPEN, TEXT("Open\tCtrl+O"));

    SetMenu(hwnd, hMenu);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
```

### 使用加速表（Accelerator Table）

加速表是一种定义快捷键和命令之间关系的资源，可以在资源文件中定义加速键，并在程序初始化时加载并使用它们。
定义加速表

在资源脚本文件中定义加速表：

```rc

// resource.rc
IDR_ACCELERATOR ACCELERATORS
BEGIN
    "O", ID_FILE_OPEN, VIRTKEY, CONTROL, NOINVERT
END
```

加载并使用加速表

在程序中加载并使用加速表：

```c

#include <windows.h>

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_FILE_OPEN) {
                // 处理 "Ctrl+O" 快捷键
                MessageBox(hwnd, TEXT("Open command triggered by Ctrl+O"), TEXT("Info"), MB_OK);
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 注册窗口类和创建窗口代码省略...

    HACCEL hAccel = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDR_ACCELERATOR));

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!TranslateAccelerator(hwnd, hAccel, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int)msg.wParam;
}
```

3. 注册全局热键

全局热键可以在应用程序之外也能响应，使用 RegisterHotKey 和 UnregisterHotKey 函数。
注册和处理全局热键

```c

#include <windows.h>

#define HOTKEY_ID 1

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_HOTKEY:
            if (wParam == HOTKEY_ID) {
                // 处理全局热键
                MessageBox(hwnd, TEXT("Global hotkey triggered"), TEXT("Info"), MB_OK);
            }
            break;

        case WM_DESTROY:
            UnregisterHotKey(hwnd, HOTKEY_ID);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 注册窗口类和创建窗口代码省略...

    if (!RegisterHotKey(hwnd, HOTKEY_ID, MOD_CONTROL | MOD_SHIFT, 'A')) {
        MessageBox(NULL, TEXT("Failed to register hotkey"), TEXT("Error"), MB_OK | MB_ICONERROR);
        return 1;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
```

快捷键总结

    WM_COMMAND 处理快捷键: 简单易用，适用于与菜单项绑定的快捷键。
    加速表（Accelerator Table）: 适用于需要集中管理快捷键的情况，特别是在资源文件中定义加速键。
    全局热键（RegisterHotKey）: 适用于需要在应用程序之外也能响应的快捷键。

## 对话框

在 Windows 编程中，对话框是一种常用的用户界面元素，用于与用户交互。对话框可以是模态的或非模态的，可以通过资源脚本或代码动态创建。下面详细介绍如何创建和使用对话框。

1. 使用资源脚本创建模态对话框
   定义对话框资源

首先在资源脚本文件（.rc 文件）中定义对话框资源：

```rc

// resource.rc
IDD_MYDIALOG DIALOGEX 0, 0, 200, 150
STYLE DS_SETFONT | WS_POPUP | WS_CAPTION | WS_SYSMENU
CAPTION "My Dialog"
FONT 8, "MS Shell Dlg"
BEGIN
    DEFPUSHBUTTON   "OK",IDOK,70,130,50,14
    PUSHBUTTON      "Cancel",IDCANCEL,130,130,50,14
END
```

### 实现对话框过程

对话框过程是一个回调函数，用于处理对话框的消息：

```c

#include <windows.h>
#include "resource.h"

BOOL CALLBACK DialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_INITDIALOG:
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDOK:
                case IDCANCEL:
                    EndDialog(hDlg, LOWORD(wParam));
                    return TRUE;
            }
            break;
    }
    return FALSE;
}
```

### 显示模态对话框

使用 DialogBox 函数显示模态对话框：

```c

#include <windows.h>
#include "resource.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_MYDIALOG), NULL, DialogProc);
    return 0;
}
```

### 动态创建模态对话框

可以使用 CreateDialog 和 CreateDialogParam 函数动态创建对话框。

示例

```c

#include <windows.h>
#include "resource.h"

BOOL CALLBACK DialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_INITDIALOG:
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDOK:
                case IDCANCEL:
                    EndDialog(hDlg, LOWORD(wParam));
                    return TRUE;
            }
            break;
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    HWND hDlg = CreateDialog(hInstance, MAKEINTRESOURCE(IDD_MYDIALOG), NULL, DialogProc);
    ShowWindow(hDlg, SW_SHOW);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return (int)msg.wParam;
}
```

### 创建非模态对话框

非模态对话框允许用户在对话框打开的同时与其他窗口进行交互。
示例

```c

#include <windows.h>
#include "resource.h"

BOOL CALLBACK DialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_INITDIALOG:
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDOK:
                case IDCANCEL:
                    DestroyWindow(hDlg);
                    return TRUE;
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            return TRUE;
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    HWND hDlg = CreateDialog(hInstance, MAKEINTRESOURCE(IDD_MYDIALOG), NULL, DialogProc);
    ShowWindow(hDlg, SW_SHOW);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return (int)msg.wParam;
}
```

### 使用对话框控件

在对话框中，可以使用 GetDlgItem 获取控件句柄，然后使用标准的 Windows API 操作控件。
示例

```c

BOOL CALLBACK DialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_INITDIALOG:
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDOK: {
                    HWND hEdit = GetDlgItem(hDlg, IDC_MYEDIT);
                    TCHAR szText[100];
                    GetWindowText(hEdit, szText, 100);
                    MessageBox(hDlg, szText, TEXT("You Entered"), MB_OK);
                    EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
            }
            break;
    }
    return FALSE;
}
```

通过以上步骤和示例，可以轻松地创建和使用对话框，以实现丰富的用户交互。根据需求选择模态或非模态对话框，并通过对话框过程处理各种消息，实现所需的功能。

## WM_NOTIFY 消息处理

在 Windows 编程中，WM_NOTIFY 消息用于通知父窗口关于某些事件或操作的发生，通常与通用控件（如 ListView、TreeView、TabControl 等）有关。WM_NOTIFY 消息通过 NMHDR 结构传递详细信息。

1. WM_NOTIFY 消息结构

WM_NOTIFY 消息的参数结构如下：

```c
WM_NOTIFY
    WPARAM wParam;     // 控件的ID
    LPARAM lParam;     // 指向 NMHDR 结构的指针
```

NMHDR 结构包含以下成员：

```c

typedef struct tagNMHDR {
    HWND hwndFrom;   // 发送通知消息的控件句柄
    UINT idFrom;     // 控件的ID
    UINT code;       // 通知码
} NMHDR;
```

2. 处理 WM_NOTIFY 消息

处理 WM_NOTIFY 消息通常在窗口过程（Window Procedure）中完成：

```c

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_NOTIFY: {
            NMHDR* pNMHDR = (NMHDR*)lParam;
            switch (pNMHDR->code) {
                // 根据不同的控件和通知码进行处理
                case NM_CLICK:       // 示例：点击通知
                    MessageBox(hwnd, TEXT("Item clicked"), TEXT("Notification"), MB_OK);
                    break;

                case LVN_ITEMCHANGED: // 示例：ListView 项目变化
                    NMLISTVIEW* pNMListView = (NMLISTVIEW*)lParam;
                    if (pNMListView->uChanged & LVIF_STATE) {
                        if ((pNMListView->uOldState & LVIS_SELECTED) != (pNMListView->uNewState & LVIS_SELECTED)) {
                            if (pNMListView->uNewState & LVIS_SELECTED) {
                                // 项目被选中
                            } else {
                                // 项目被取消选中
                            }
                        }
                    }
                    break;

                // 处理其他通知码...

                default:
                    break;
            }
            break;
        }

        // 其他消息处理...

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
```

3. 示例：处理 ListView 控件的 WM_NOTIFY 消息

假设我们有一个 ListView 控件，需要处理 LVN_ITEMCHANGED 通知消息以响应项目选择变化：
定义 ListView 控件

在窗口创建过程中创建 ListView 控件：

```c

HWND hListView = CreateWindow(WC_LISTVIEW,
                              NULL,
                              WS_CHILD | WS_VISIBLE | LVS_REPORT,
                              10, 10, 300, 200,
                              hwnd,
                              (HMENU)IDC_LISTVIEW,
                              hInstance,
                              NULL);
```

处理 LVN_ITEMCHANGED 消息

在窗口过程（Window Procedure）中处理 WM_NOTIFY 消息：

```c

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_NOTIFY: {
            LPNMHDR pNMHDR = (LPNMHDR)lParam;
            if (pNMHDR->idFrom == IDC_LISTVIEW) {
                switch (pNMHDR->code) {
                    case LVN_ITEMCHANGED: {
                        LPNMLISTVIEW pNMListView = (LPNMLISTVIEW)lParam;
                        if (pNMListView->uChanged & LVIF_STATE) {
                            if ((pNMListView->uOldState & LVIS_SELECTED) != (pNMListView->uNewState & LVIS_SELECTED)) {
                                if (pNMListView->uNewState & LVIS_SELECTED) {
                                    MessageBox(hwnd, TEXT("Item selected"), TEXT("Notification"), MB_OK);
                                } else {
                                    MessageBox(hwnd, TEXT("Item deselected"), TEXT("Notification"), MB_OK);
                                }
                            }
                        }
                        break;
                    }

                    // 处理其他 ListView 通知消息...

                    default:
                        break;
                }
            }
            break;
        }

        // 其他消息处理...

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
```

4. 示例：处理 TreeView 控件的 WM_NOTIFY 消息

假设我们有一个 TreeView 控件，需要处理 TVN_SELCHANGED 通知消息以响应选定项变化：
定义 TreeView 控件

在窗口创建过程中创建 TreeView 控件：

```c

HWND hTreeView = CreateWindow(WC_TREEVIEW,
                              NULL,
                              WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS,
                              10, 220, 300, 200,
                              hwnd,
                              (HMENU)IDC_TREEVIEW,
                              hInstance,
                              NULL);
```

处理 TVN_SELCHANGED 消息

在窗口过程（Window Procedure）中处理 WM_NOTIFY 消息：

```c

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_NOTIFY: {
            LPNMHDR pNMHDR = (LPNMHDR)lParam;
            if (pNMHDR->idFrom == IDC_TREEVIEW) {
                switch (pNMHDR->code) {
                    case TVN_SELCHANGED: {
                        LPNMTREEVIEW pNMTV = (LPNMTREEVIEW)lParam;
                        HTREEITEM hSelectedItem = pNMTV->itemNew.hItem;
                        MessageBox(hwnd, TEXT("TreeView item selected"), TEXT("Notification"), MB_OK);
                        break;
                    }

                    // 处理其他 TreeView 通知消息...

                    default:
                        break;
                }
            }
            break;
        }

        // 其他消息处理...

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
```

通过以上步骤，您可以处理各种控件的 WM_NOTIFY 消息，响应特定事件和操作。根据控件的不同和需要处理的通知类型，调整相应的消息处理逻辑即可。
