# Unicorn-Engine API Documentation

| Version | 2.1.3 |
| ------- | ----- |

**Official API document by [kabeor](https://github.com/kabeor)**

[Unicorn Engine](http://www.unicorn-engine.org/)是一个轻量级, 多平台, 多架构的 CPU 模拟器框架，当前版本基于[Qemu](https://www.qemu.org/) 5.0.1 开发，它可以代替 CPU 模拟代码的执行，常用于程序虚拟、恶意代码分析、Fuzzing 等，本项目被用于[Qiling](https://github.com/qilingframework/qiling) 虚拟框架，[Radare2](https://github.com/radareorg/radare2) 逆向分析框架，[GEF](https://github.com/hugsy/gef)(gdb 的 pwn 分析插件)，[Pwndbg](https://github.com/pwndbg/pwndbg)，[Angr](https://github.com/angr/angr) 符号执行框架等多个著名项目。

## 开发准备

Unicorn 官网: http://www.unicorn-engine.org

```bash
git clone https://github.com/unicorn-engine/unicorn.git
```

Unicorn 源码文件结构如下：

```bash
. <- 主要引擎core engine + README + 编译文档COMPILE.TXT 等
├── bindings <- 绑定
│ ├── dotnet <- .Net 绑定 + 测试代码
│ ├── go <- go 绑定 + 测试代码
│ ├── haskell <- Haskell 绑定 + 测试代码
│ ├── java <- Java 绑定 + 测试代码
│ ├── pascal <- Pascal 绑定 + 测试代码
│ ├── python <- Python 绑定 + 测试代码
│ ├── ruby <- Ruby 绑定 + 测试代码
│ ├── rust <- Rust 绑定 + 测试代码
│ └── vb6 <- VB6 绑定 + 测试代码
├── docs <- 文档
├── glib_compat <- 基于glib 2.64.4修改的兼容库
├── include <- C头文件
├── msvc <- Microsoft Visual Studio 支持（Windows）
├── qemu <- qemu(已修改)源码
├── samples <- Unicorn使用示例
└── tests <- C语言测试用例
```

### 编译

#### Linux & MacOS & Windows

Ubuntu

```bash
$ sudo apt install cmake pkg-config
```

MacOS

```bash
$ brew install cmake pkg-config
```

windows

下载安装 [camke](https://cmake.org/download/)，并将 cmake 添加到环境变量中 。

使用以下命令编译：

```bash
$ cmake -B build
$ cmake --build build
```

官方目前使用 [Github Action](https://github.com/unicorn-engine/unicorn/actions/workflows/build-uc2.yml) 编译，可以自行前往下载最新的版本，也可以自己编辑最新版本源码，以获得更多可用 API。

> 其他编译方式点击[这里](https://github.com/unicorn-engine/unicorn/blob/master/docs/COMPILE.md)

### 安装

- Python 模块

```bash
pip install unicorn

// 如已安装1.x版本可直接通过以下命令升级
pip install unicorn --upgrade
```

- MacOS HomeBrew 包

```bash
brew install unicorn
```

### 引擎调用测试

（以 Windows VS2019 为例）新建一个 VS 项目，将编译好的 `unicorn-import.lib` 和 `unicorn.dll` 文件以及 unicorn 源码中 include 下的 unicorn 目录拷贝到新建项目的源码目录下。

![](assets/项目结构.png)

在 VS 解决方案中，头文件添加现有项 -> 选择 unicorn 目录中所有的头文件进行添加，资源文件中添加 `unicorn-import.lib` 文件，重新生成解决方案

![](assets/解决方案结构.png)

接下来测试我们生成的 Unicorn 引擎，主文件代码如下：

主文件代码如下:

```cpp
#include <iostream>
#include "unicorn/unicorn.h"

int main()
{
    // 要模拟的指令 mov x0, 0x100; mov x1, 0x200;
	const char code[] = "\x00\x20\x80\xD2\x01\x40\x80\xD2";
    // 模拟的起始地址
	const unsigned long adderss = 0x1000;
	uc_engine* uc;
	uc_err err;

    // 模拟的寄存器初始值.
	int64_t x0 = 0x1;
	int64_t x1 = 0x2;
	printf("start emulate arm64 code.\n");
	// 以 arm 模式初始化 uc .
	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
	if (err != UC_ERR_OK){ // 后面所有的函数都应该检测错误.
		printf("uc_open error code %u.\n", err);
		return -1;
	}
	// 申请 2MB 内存用于模拟执行.
	err = uc_mem_map(uc, adderss, 2 * 1024 * 1024, UC_PROT_ALL);
	// 将需要模拟执行的指令写入内存.
	err = uc_mem_write(uc, adderss, code, sizeof(code) - 1);

	// 初始化寄存器.
	uc_reg_write(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_write(uc, UC_ARM64_REG_X1, &x1);
	printf(">>> x0 = 0x%x\n", x0);
	printf(">>> x1 = 0x%x\n", x1);

	// 开始模拟执行.
	uc_emu_start(uc, adderss, adderss + sizeof(code) - 1, 0, 0);

	// 获取执行后的寄存器值.
	uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
	printf("emulate arm64 code done.\n");
	printf(">>> x0 = 0x%x\n", x0);
	printf(">>> x1 = 0x%x\n", x1);

	// 关闭 uc, 释放资源.
	err = uc_close(uc);
	return 0;
}
```

运行结果如下

```bash
start emulate arm64 code.
>>> x0 = 0x1
>>> x1 = 0x2
emulate arm64 code done.
>>> x0 = 0x100
>>> x1 = 0x200
```

`mov x0, 0x100` 和 `mov x1, 0x200` 成功模拟。

## 数据类型

---

### uc_arch

架构选择。

```cpp
typedef enum uc_arch {
    UC_ARCH_ARM = 1,    // ARM 架构 (包括 Thumb, Thumb-2)
    UC_ARCH_ARM64,      // ARM-64, 也称 AArch64
    UC_ARCH_MIPS,       // Mips 架构
    UC_ARCH_X86,        // X86 架构 (包括 x86 & x86-64)
    UC_ARCH_PPC,        // PowerPC 架构
    UC_ARCH_SPARC,      // Sparc 架构
    UC_ARCH_M68K,       // M68K 架构
    UC_ARCH_RISCV,      // RISCV 架构
    UC_ARCH_S390X,      // S390X 架构
    UC_ARCH_TRICORE,    // TriCore 架构
    UC_ARCH_MAX,
} uc_arch;
```

### uc_mode

模式选择。

```cpp
typedef enum uc_mode {
    UC_MODE_LITTLE_ENDIAN = 0,    // 小端序模式 (默认)
    UC_MODE_BIG_ENDIAN = 1 << 30, // 大端序模式

    // arm / arm64
    UC_MODE_ARM = 0,              // ARM 模式
    UC_MODE_THUMB = 1 << 4,       // THUMB 模式 (包括 Thumb-2)

    //已弃用，转为使用UC_ARM_CPU_* 和 uc_ctl
    UC_MODE_MCLASS = 1 << 5,      // ARM's Cortex-M 系列
    UC_MODE_V8 = 1 << 6,          // ARMv8 A32 encodings for ARM
    UC_MODE_ARMBE8 = 1 << 10, // 大端序数据和小端序代码 仅为兼容UC1版本

    // arm (32bit) cpu 类型
    //已弃用，转为使用UC_ARM_CPU_* 和 uc_ctl
    UC_MODE_ARM926 = 1 << 7,	  // ARM926 CPU 类型
    UC_MODE_ARM946 = 1 << 8,	  // ARM946 CPU 类型
    UC_MODE_ARM1176 = 1 << 9,	  // ARM1176 CPU 类型

    // mips
    UC_MODE_MICRO = 1 << 4,       // MicroMips 模式 (暂不支持)
    UC_MODE_MIPS3 = 1 << 5,       // Mips III ISA (暂不支持)
    UC_MODE_MIPS32R6 = 1 << 6,    // Mips32r6 ISA (暂不支持)
    UC_MODE_MIPS32 = 1 << 2,      // Mips32 ISA
    UC_MODE_MIPS64 = 1 << 3,      // Mips64 ISA

    // x86 / x64
    UC_MODE_16 = 1 << 1,          // 16-bit 模式
    UC_MODE_32 = 1 << 2,          // 32-bit 模式
    UC_MODE_64 = 1 << 3,          // 64-bit 模式

    // ppc
    UC_MODE_PPC32 = 1 << 2,       // 32-bit 模式
    UC_MODE_PPC64 = 1 << 3,       // 64-bit 模式 (暂不支持)
    UC_MODE_QPX = 1 << 4,         // Quad Processing eXtensions 模式 (暂不支持)

    // sparc
    UC_MODE_SPARC32 = 1 << 2,     // 32-bit 模式
    UC_MODE_SPARC64 = 1 << 3,     // 64-bit 模式
    UC_MODE_V9 = 1 << 4,          // SparcV9 模式 (暂不支持)

    // riscv
    UC_MODE_RISCV32 = 1 << 2,     // 32-bit 模式
    UC_MODE_RISCV64 = 1 << 3,     // 64-bit 模式

    // m68k
} uc_mode;
```

### uc_err

错误类型，是 [uc_errno()](#uc_errno) 的返回值。

```cpp
typedef enum uc_err {
    UC_ERR_OK = 0,           // 无错误
    UC_ERR_NOMEM,            // 内存不足: uc_open(), uc_emulate()
    UC_ERR_ARCH,             // 不支持的架构: uc_open()
    UC_ERR_HANDLE,           // 不可用句柄
    UC_ERR_MODE,             // 不可用/不支持架构: uc_open()
    UC_ERR_VERSION,          // 不支持版本 (或语言绑定)
    UC_ERR_READ_UNMAPPED,    // 由于在未映射的内存上读取而退出模拟: uc_emu_start()
    UC_ERR_WRITE_UNMAPPED,   // 由于在未映射的内存上写入而退出模拟: uc_emu_start()
    UC_ERR_FETCH_UNMAPPED,   // 由于在未映射的内存中获取数据而退出模拟: uc_emu_start()
    UC_ERR_HOOK,             // 无效的hook类型: uc_hook_add()
    UC_ERR_INSN_INVALID,     // 由于指令无效而退出模拟: uc_emu_start()
    UC_ERR_MAP,              // 无效的内存映射: uc_mem_map()
    UC_ERR_WRITE_PROT,       // 由于UC_MEM_WRITE_PROT冲突而停止模拟: uc_emu_start()
    UC_ERR_READ_PROT,        // 由于UC_MEM_READ_PROT冲突而停止模拟: uc_emu_start()
    UC_ERR_FETCH_PROT,       // 由于UC_MEM_FETCH_PROT冲突而停止模拟: uc_emu_start()
    UC_ERR_ARG,              // 提供给uc_xxx函数的无效参数
    UC_ERR_READ_UNALIGNED,   // 未对齐读取
    UC_ERR_WRITE_UNALIGNED,  // 未对齐写入
    UC_ERR_FETCH_UNALIGNED,  // 未对齐的提取
    UC_ERR_HOOK_EXIST,       // 此事件的钩子已经存在
    UC_ERR_RESOURCE,         // 资源不足: uc_emu_start()
    UC_ERR_EXCEPTION,        // 未处理的CPU异常
} uc_err;
```

### uc_mem_type

`UC_HOOK_MEM_*` 的所有内存访问类型。

```cpp
typedef enum uc_mem_type {
    UC_MEM_READ = 16,        // 内存从..读取
    UC_MEM_WRITE,            // 内存写入到..
    UC_MEM_FETCH,            // 内存被获取
    UC_MEM_READ_UNMAPPED,    // 未映射内存从..读取
    UC_MEM_WRITE_UNMAPPED,   // 未映射内存写入到..
    UC_MEM_FETCH_UNMAPPED,   // 未映射内存被获取
    UC_MEM_WRITE_PROT,       // 内存写保护，但是已映射
    UC_MEM_READ_PROT,        // 内存读保护，但是已映射
    UC_MEM_FETCH_PROT,       // 内存不可执行，但是已映射
    UC_MEM_READ_AFTER,       // 内存从 (成功访问的地址) 读入
} uc_mem_type;
```

### uc_hook_type

[uc_hook_add()](#uc_hook_add) 的所有 hook 类型参数。

```cpp
typedef enum uc_hook_type {
    // Hook 所有中断/syscall 事件
    UC_HOOK_INTR = 1 << 0,
    // Hook 一条特定的指令 - 只支持非常小的指令子集
    UC_HOOK_INSN = 1 << 1,
    // Hook 一段代码
    UC_HOOK_CODE = 1 << 2,
    // Hook 基本块
    UC_HOOK_BLOCK = 1 << 3,
    // 用于在未映射的内存上读取内存的Hook
    UC_HOOK_MEM_READ_UNMAPPED = 1 << 4,
    // Hook 无效的内存写事件
    UC_HOOK_MEM_WRITE_UNMAPPED = 1 << 5,
    // Hook 执行事件的无效内存
    UC_HOOK_MEM_FETCH_UNMAPPED = 1 << 6,
    // Hook 读保护的内存
    UC_HOOK_MEM_READ_PROT = 1 << 7,
    // Hook 写保护的内存
    UC_HOOK_MEM_WRITE_PROT = 1 << 8,
    // Hook 不可执行内存上的内存
    UC_HOOK_MEM_FETCH_PROT = 1 << 9,
    // Hook 内存读取事件
    UC_HOOK_MEM_READ = 1 << 10,
    // Hook 内存写入事件
    UC_HOOK_MEM_WRITE = 1 << 11,
    // Hook 内存获取执行事件
    UC_HOOK_MEM_FETCH = 1 << 12,
    // Hook 内存读取事件，只允许能成功访问的地址
    // 成功读取后将触发回调
    UC_HOOK_MEM_READ_AFTER = 1 << 13,
    // Hook 无效指令异常
    UC_HOOK_INSN_INVALID = 1 << 14,
    // Hook 新的(执行流的)边生成事件. 在程序分析中可能有用.
    // 注意: 该Hook有两个方面不同于 UC_HOOK_BLOCK:
    //       1. 该Hook在指令执行前被调用.
    //       2. 该Hook仅在生成事件触发时被调用.
    UC_HOOK_EDGE_GENERATED = 1 << 15,
    // Hook 特定的 tcg 操作码. 用法与UC_HOOK_INSN相似.
    UC_HOOK_TCG_OPCODE = 1 << 16,
} uc_hook_type;
```

### hook_types

宏定义 Hook 类型。

```cpp
// Hook 所有未映射内存访问的事件
#define UC_HOOK_MEM_UNMAPPED (UC_HOOK_MEM_READ_UNMAPPED + UC_HOOK_MEM_WRITE_UNMAPPED + UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook 所有对受保护内存的非法访问事件
#define UC_HOOK_MEM_PROT (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_FETCH_PROT)
// Hook 所有非法读取存储器的事件
#define UC_HOOK_MEM_READ_INVALID (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_READ_UNMAPPED)
// Hook 所有非法写入存储器的事件
#define UC_HOOK_MEM_WRITE_INVALID (UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_WRITE_UNMAPPED)
// Hook 所有非法获取内存的事件
#define UC_HOOK_MEM_FETCH_INVALID (UC_HOOK_MEM_FETCH_PROT + UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook 所有非法的内存访问事件
#define UC_HOOK_MEM_INVALID (UC_HOOK_MEM_UNMAPPED + UC_HOOK_MEM_PROT)
// Hook 所有有效内存访问的事件
// 注意: UC_HOOK_MEM_READ 在 UC_HOOK_MEM_READ_PROT 和 UC_HOOK_MEM_READ_UNMAPPED 之前触发 ,
//       因此这个Hook可能会触发一些无效的读取。
#define UC_HOOK_MEM_VALID (UC_HOOK_MEM_READ + UC_HOOK_MEM_WRITE + UC_HOOK_MEM_FETCH)
```

### hook callback

```cpp
/*
  用于跟踪代码 (UC_HOOK_CODE 和 UC_HOOK_BLOCK) 的回调函数

  @address: 正在执行代码的地址
  @size: 正在执行的机器指令的大小，如果大小未知则为 0
  @user_data: 传递给跟踪 API 的用户数据。
*/
typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size,
                                 void *user_data);

/*
  用于跟踪中断 (uc_hook_intr() 使用) 的回调函数

  @intno: 中断号
  @user_data: 传递给跟踪 API 的用户数据。
*/
typedef void (*uc_cb_hookintr_t)(uc_engine *uc, uint32_t intno,
                                 void *user_data);

/*
  用于跟踪无效指令的回调函数

  @user_data: 传递给跟踪 API 的用户数据。

  @return: 返回 true 以继续执行，或返回 false 以停止程序 (由于无效指令)。
*/
typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);

/*
  用于跟踪 X86 IN 指令的回调函数

  @port: 端口号
  @size: 要从此端口读取的数据大小 (1/2/4字节)
  @user_data: 传递给跟踪 API 的用户数据。
*/
typedef uint32_t (*uc_cb_insn_in_t)(uc_engine *uc, uint32_t port, int size,
                                    void *user_data);

/*
  用于跟踪 X86 OUT 指令的回调函数

  @port: 端口号
  @size: 要写入此端口的数据大小 (1/2/4字节)
  @value: 要写入此端口的数据值
  @user_data: 传递给跟踪 API 的用户数据。
*/
typedef void (*uc_cb_insn_out_t)(uc_engine *uc, uint32_t port, int size,
                                 uint32_t value, void *user_data);

/*
  用于翻译块之间新边的回调函数。

  @cur_tb: 将要生成的当前翻译块。
  @prev_tb: 前一个翻译块。
  @user_data: 传递给跟踪 API 的用户数据。
*/
typedef void (*uc_hook_edge_gen_t)(uc_engine *uc, uc_tb *cur_tb, uc_tb *prev_tb,
                                   void *user_data);

/*
  用于处理两个参数的 tcg 操作码的回调函数。

  @address: 当前程序计数器。
  @arg1: 第一个参数。
  @arg2: 第二个参数。
  @size: 操作数大小。
  @user_data: 传递给跟踪 API 的用户数据。
*/
typedef void (*uc_hook_tcg_op_2)(uc_engine *uc, uint64_t address, uint64_t arg1,
                                 uint64_t arg2, uint32_t size, void *user_data);


/*
  MMIO 读操作的回调函数

  @offset: 相对于 IO 内存基地址的偏移量。
  @size: 要读取的数据大小
  @user_data: 传递给 uc_mmio_map() 的用户数据
*/
typedef uint64_t (*uc_cb_mmio_read_t)(uc_engine *uc, uint64_t offset,
                                      unsigned size, void *user_data);

/*
  MMIO 写操作的回调函数

  @offset: 相对于 IO 内存基地址的偏移量。
  @size: 要写入的数据大小
  @value: 要写入的数据值
  @user_data: 传递给 uc_mmio_map() 的用户数据
*/
typedef void (*uc_cb_mmio_write_t)(uc_engine *uc, uint64_t offset,
                                   unsigned size, uint64_t value,
                                   void *user_data);

/*
  用于钩取内存 (读、写和取指) 的回调函数

  @type: 表示内存正在被读取、写入或取指
  @address: 正在执行代码的地址
  @size: 正在读取或写入的数据大小
  @value: 正在写入内存的数据值，如果 type = READ 则此参数无关紧要。
  @user_data: 传递给跟踪 API 的用户数据
*/
typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type,
                                uint64_t address, int size, int64_t value,
                                void *user_data);
/*
  用于处理无效内存访问事件 (UNMAPPED 和 PROT 事件) 的回调函数

  @type: 表示内存正在被读取、写入或取指
  @address: 正在执行代码的地址
  @size: 正在读取或写入的数据大小
  @value: 正在写入内存的数据值，如果 type = READ 则此参数无关紧要。
  @user_data: 传递给跟踪 API 的用户数据

  @return: 返回 true 以继续执行，或返回 false 以停止程序 (由于无效内存)。
           注意：只有在钩子执行期间，通过正确的权限使被访问的内存变得可访问，
           返回 true 以继续执行才会生效。

           在发生 UC_MEM_READ_UNMAPPED 或 UC_MEM_WRITE_UNMAPPED 回调时，
           应使用 uc_mem_map() 以正确的权限映射内存，
           然后指令将按预期读取或写入该地址。

           在发生 UC_MEM_FETCH_UNMAPPED 回调时，可以将内存映射为可执行，
           在这种情况下，执行将从取指的地址恢复。可以写入指令指针以更改
           执行恢复的位置，但如果要恢复执行，则取指必须成功。
*/
typedef bool (*uc_cb_eventmem_t)(uc_engine *uc, uc_mem_type type,
                                 uint64_t address, int size, int64_t value,
                                 void *user_data);
```

### uc_mem_region

由 [uc_mem_map()](#uc_mem_map) 函数和[uc_mem_map_ptr()](#uc_mem_map_ptr) 函数映射内存区域。

使用 [uc_mem_regions()](#uc_mem_regions) 函数检索该内存区域的列表。

```cpp
typedef struct uc_mem_region {
    uint64_t begin; // 区域起始地址 (包括)
    uint64_t end;   // 区域结束地址 (包括)
    uint32_t perms; // 区域的内存权限
} uc_mem_region;
```

### uc_query_type

[uc_query()](#uc_query) 的所有查询类型参数。

```cpp
typedef enum uc_query_type {
    // 动态查询当前硬件模式
    UC_QUERY_MODE = 1,
    UC_QUERY_PAGE_SIZE, // 查询引擎实例的pagesize
    UC_QUERY_ARCH,      // 查询引擎实例的架构类型
    UC_QUERY_TIMEOUT,   // 查询是否由于超时停止模拟 (如果 result = True 则表示是)
} uc_query_type;
```

### uc_control_type

[uc_ctl()](#uc_ctl) 的所有查询类型参数。

```cpp
// uc_ctl 的实现与 Linux ioctl 较为类似但略有不同
//
// uc_control_type 在 uc_ctl 中的组织结构如下:
//
//    R/W       NR       Reserved     Type
//  [      ] [      ]  [         ] [       ]
//  31    30 29     26 25       16 15      0
//
//  @R/W: 是否操作是一个读/写访问.
//  @NR: 参数数量.
//  @Reserved: 为0，为未来扩展保留.
//  @Type: uc_control_type 中的枚举.

// 无输入和输出参数.
#define UC_CTL_IO_NONE (0)
// 仅有输入参数为了一个写操作.
#define UC_CTL_IO_WRITE (1)
// 仅有输出参数为了一个读操作.
#define UC_CTL_IO_READ (2)
// 参数中同时包含读和写操作.
#define UC_CTL_IO_READ_WRITE (UC_CTL_IO_WRITE | UC_CTL_IO_READ)

#define UC_CTL(type, nr, rw)                                                   \
    (uc_control_type)((type) | ((nr) << 26) | ((rw) << 30))
#define UC_CTL_NONE(type, nr) UC_CTL(type, nr, UC_CTL_IO_NONE)
#define UC_CTL_READ(type, nr) UC_CTL(type, nr, UC_CTL_IO_READ)
#define UC_CTL_WRITE(type, nr) UC_CTL(type, nr, UC_CTL_IO_WRITE)
#define UC_CTL_READ_WRITE(type, nr) UC_CTL(type, nr, UC_CTL_IO_READ_WRITE)
```

```cpp
// 控制链以树状结构组织.
// 如果一个控制状态没有为@args填入 `Set` 或 `Get`, 则是 r/o 或 w/o.
typedef enum uc_control_type {
    // 当前模式.
    // Read: @args = (int*)
    UC_CTL_UC_MODE = 0,
    // 当前 page size.
    // Write: @args = (uint32_t)
    // Read: @args = (uint32_t*)
    UC_CTL_UC_PAGE_SIZE,
    // 当前架构.
    // Read: @args = (int*)
    UC_CTL_UC_ARCH,
    // 当前超时.
    // Read: @args = (uint64_t*)
    UC_CTL_UC_TIMEOUT,
    // 允许存在多个退出点.
    // 没有该控制状态, 读取/设置退出点将不能使用.
    // Write: @args = (int)
    UC_CTL_UC_USE_EXITS,
    // 当前输入数.
    // Read: @args = (size_t*)
    UC_CTL_UC_EXITS_CNT,
    // 当前输入.
    // Write: @args = (uint64_t* exits, size_t len)
    //        @len = UC_CTL_UC_EXITS_CNT
    // Read: @args = (uint64_t* exits, size_t len)
    //       @len = UC_CTL_UC_EXITS_CNT
    UC_CTL_UC_EXITS,

    // 设置uc实例的cpu模式.
    // Note this option can only be set before any Unicorn
    // API is called except for uc_open.
    // Write: @args = (int)
    // Read:  @args = (int*)
    UC_CTL_CPU_MODEL,
    // 查询特定地址的 tb(翻译块) 缓存
    // Read: @args = (uint64_t, uc_tb*)
    UC_CTL_TB_REQUEST_CACHE,
    // 禁用特定地址的 tb(翻译块) 缓存
    // Write: @args = (uint64_t, uint64_t)
    UC_CTL_TB_REMOVE_CACHE,
    // 禁用所有的 tb(翻译块)
    // 无参数
    UC_CTL_TB_FLUSH

} uc_control_type;
```

### uc_context

与 `uc_context_*()` 函数一起使用，管理 CPU 上下文的不透明存储。

```cpp
struct uc_context;
typedef struct uc_context uc_context;
```

### uc_prot

新映射区域的权限。

```cpp
typedef enum uc_prot {
   UC_PROT_NONE = 0,    //无
   UC_PROT_READ = 1,    //读取
   UC_PROT_WRITE = 2,   //写入
   UC_PROT_EXEC = 4,    //可执行
   UC_PROT_ALL = 7,     //所有权限
} uc_prot;
```

## API

---

### uc_version

```cpp
unsigned int uc_version(unsigned int *major, unsigned int *minor);
```

用于返回 Unicorn API 主次版本信息。

```
@major: API主版本号
@minor: API次版本号
@return 16进制数，计算方式 (major << 8 | minor)

提示: 该返回值可以和宏 UC_MAKE_VERSION 比较
```

<details><summary> 源码实现 </summary>

```c
unsigned int uc_version(unsigned int *major, unsigned int *minor)
{
    if (major != NULL && minor != NULL) {
        *major = UC_API_MAJOR;  //宏
        *minor = UC_API_MINOR;  //宏
    }

    return (UC_API_MAJOR << 8) + UC_API_MINOR;   //(major << 8 | minor)
}
```

</details>

编译后不可更改，不接受自定义版本。

使用示例：

```cpp
#include <iostream>
#include "unicorn/unicorn.h"
using namespace std;

int main()
{
	unsigned int version = 0;
	unsigned int major = 0;
	unsigned int minor = 0;

	version = uc_version(&major, &minor);
	cout << "verson: 0x" << hex << version << endl;
	cout << "major: 0x" << hex << ((version & 0xFF000000) >> 24) << endl;
	cout << "minor: 0x" << hex << ((version & 0x00FF0000) >> 16) << endl;
	cout << "patch: 0x" << hex << ((version & 0x0000FF00) >> 8) << endl;
	cout << "extra: 0x" << hex << (version & 0x000000FF) << endl;
	cout << "major: " << major << ", minor: " << minor << endl;
}
```

输出：

```bash
verson: 0x20103ff
major: 0x2
minor: 0x1
patch: 0x3
extra: 0xff
major: 2, minor: 1
```

得到版本号 2.1.3。

### uc_arch_supported

```c
bool uc_arch_supported(uc_arch arch);
```

确定 Unicorn 是否支持当前架构。

```
 @arch: 架构类型 (UC_ARCH_*)
 @return 如果支持返回True
```

<details><summary> 源码实现 </summary>

```c
bool uc_arch_supported(uc_arch arch)
{
    switch (arch) {
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:   return true;
#endif
#ifdef UNICORN_HAS_ARM64
        case UC_ARCH_ARM64: return true;
#endif
#ifdef UNICORN_HAS_M68K
        case UC_ARCH_M68K:  return true;
#endif
#ifdef UNICORN_HAS_MIPS
        case UC_ARCH_MIPS:  return true;
#endif
#ifdef UNICORN_HAS_PPC
        case UC_ARCH_PPC:   return true;
#endif
#ifdef UNICORN_HAS_SPARC
        case UC_ARCH_SPARC: return true;
#endif
#ifdef UNICORN_HAS_X86
        case UC_ARCH_X86:   return true;
#endif
        /* 无效或禁用架构 */
        default:            return false;
    }
}
```

</details>

使用示例：

```cpp
#include <iostream>
#include "unicorn/unicorn.h"
using namespace std;

int main()
{
	cout << "is supported ARM: " << uc_arch_supported(UC_ARCH_ARM64) << endl;
	return 0;
}
```

输出：

```bash
is supported ARM: 1
```

### uc_open

```c
uc_err uc_open(uc_arch arch, uc_mode mode, uc_engine **uc);
```

创建新的 Unicorn 实例。

```
@arch: 架构类型 (UC_ARCH_*)
@mode: 硬件模式. 由 UC_MODE_* 组合
@uc: 指向 uc_engine 的指针, 返回时更新

@return 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_open(uc_arch arch, uc_mode mode, uc_engine **result)
{
    struct uc_struct *uc;

    if (arch < UC_ARCH_MAX) {
        uc = calloc(1, sizeof(*uc));  //申请内存
        if (!uc) {
            // 内存不足
            return UC_ERR_NOMEM;
        }

        uc->errnum = UC_ERR_OK;
        uc->arch = arch;
        uc->mode = mode;

        // 初始化
        // uc->ram_list = { .blocks = QTAILQ_HEAD_INITIALIZER(ram_list.blocks) };
        uc->ram_list.blocks.tqh_first = NULL;
        uc->ram_list.blocks.tqh_last = &(uc->ram_list.blocks.tqh_first);

        uc->memory_listeners.tqh_first = NULL;
        uc->memory_listeners.tqh_last = &uc->memory_listeners.tqh_first;

        uc->address_spaces.tqh_first = NULL;
        uc->address_spaces.tqh_last = &uc->address_spaces.tqh_first;

        switch(arch) {   // 根据架构进行预处理
            default:
                break;
#ifdef UNICORN_HAS_M68K
            case UC_ARCH_M68K:
                if ((mode & ~UC_MODE_M68K_MASK) ||
                        !(mode & UC_MODE_BIG_ENDIAN)) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                uc->init_arch = m68k_uc_init;
                break;
#endif
#ifdef UNICORN_HAS_X86
            case UC_ARCH_X86:
                if ((mode & ~UC_MODE_X86_MASK) ||
                        (mode & UC_MODE_BIG_ENDIAN) ||
                        !(mode & (UC_MODE_16|UC_MODE_32|UC_MODE_64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                uc->init_arch = x86_uc_init;
                break;
#endif
#ifdef UNICORN_HAS_ARM
            case UC_ARCH_ARM:
                if ((mode & ~UC_MODE_ARM_MASK)) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_BIG_ENDIAN) {
                    uc->init_arch = armeb_uc_init;
                } else {
                    uc->init_arch = arm_uc_init;
                }

                if (mode & UC_MODE_THUMB)
                    uc->thumb = 1;
                break;
#endif
#ifdef UNICORN_HAS_ARM64
            case UC_ARCH_ARM64:
                if (mode & ~UC_MODE_ARM_MASK) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_BIG_ENDIAN) {
                    uc->init_arch = arm64eb_uc_init;
                } else {
                    uc->init_arch = arm64_uc_init;
                }
                break;
#endif

#if defined(UNICORN_HAS_MIPS) || defined(UNICORN_HAS_MIPSEL) || defined(UNICORN_HAS_MIPS64) || defined(UNICORN_HAS_MIPS64EL)
            case UC_ARCH_MIPS:
                if ((mode & ~UC_MODE_MIPS_MASK) ||
                        !(mode & (UC_MODE_MIPS32|UC_MODE_MIPS64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_BIG_ENDIAN) {
#ifdef UNICORN_HAS_MIPS
                    if (mode & UC_MODE_MIPS32)
                        uc->init_arch = mips_uc_init;
#endif
#ifdef UNICORN_HAS_MIPS64
                    if (mode & UC_MODE_MIPS64)
                        uc->init_arch = mips64_uc_init;
#endif
                } else {    // 小端序
#ifdef UNICORN_HAS_MIPSEL
                    if (mode & UC_MODE_MIPS32)
                        uc->init_arch = mipsel_uc_init;
#endif
#ifdef UNICORN_HAS_MIPS64EL
                    if (mode & UC_MODE_MIPS64)
                        uc->init_arch = mips64el_uc_init;
#endif
                }
                break;
#endif

#ifdef UNICORN_HAS_SPARC
            case UC_ARCH_SPARC:
                if ((mode & ~UC_MODE_SPARC_MASK) ||
                        !(mode & UC_MODE_BIG_ENDIAN) ||
                        !(mode & (UC_MODE_SPARC32|UC_MODE_SPARC64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_SPARC64)
                    uc->init_arch = sparc64_uc_init;
                else
                    uc->init_arch = sparc_uc_init;
                break;
#endif
        }

        if (uc->init_arch == NULL) {
            return UC_ERR_ARCH;
        }

        if (machine_initialize(uc))
            return UC_ERR_RESOURCE;

        *result = uc;

        if (uc->reg_reset)
            uc->reg_reset(uc);

        return UC_ERR_OK;
    } else {
        return UC_ERR_ARCH;
    }
}
```

</details>

**注意： uc_open 会申请堆内存，使用完必须用 uc_close 释放，否则会发生泄露**

使用示例：

```cpp
#include <iostream>
#include "unicorn/unicorn.h"
using namespace std;

int main()
{
	uc_engine* uc = NULL;
	uc_err err = UC_ERR_OK;

	// 初始化 ARM64 模式模拟器.
	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}
	cout << "uc engine created successfully." << endl;

	// 关闭 uc
	err = uc_close(uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_close() with error returned: %u\n", err);
		return -1;
	}
	cout << "uc engine closed successfully." << endl;
}
```

输出

```bash
uc engine created successfully.
uc engine closed successfully.
```

### uc_close

```c
uc_err uc_close(uc_engine *uc);
```

关闭一个 uc 实例，将释放内存，关闭后无法恢复。

```
@uc: 指向由 uc_open() 返回的指针

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_close(uc_engine *uc)
{
    int i;
    struct list_item *cur;
    struct hook *hook;

    // 清理内部数据
    if (uc->release)
        uc->release(uc->tcg_ctx);
    g_free(uc->tcg_ctx);

    // 清理 CPU.
    g_free(uc->cpu->tcg_as_listener);
    g_free(uc->cpu->thread);

    // 清理所有 objects.
    OBJECT(uc->machine_state->accelerator)->ref = 1;
    OBJECT(uc->machine_state)->ref = 1;
    OBJECT(uc->owner)->ref = 1;
    OBJECT(uc->root)->ref = 1;

    object_unref(uc, OBJECT(uc->machine_state->accelerator));
    object_unref(uc, OBJECT(uc->machine_state));
    object_unref(uc, OBJECT(uc->cpu));
    object_unref(uc, OBJECT(&uc->io_mem_notdirty));
    object_unref(uc, OBJECT(&uc->io_mem_unassigned));
    object_unref(uc, OBJECT(&uc->io_mem_rom));
    object_unref(uc, OBJECT(uc->root));

    // 释放内存
    g_free(uc->system_memory);

    // 释放相关线程
    if (uc->qemu_thread_data)
        g_free(uc->qemu_thread_data);

    // 释放其他数据
    free(uc->l1_map);

    if (uc->bounce.buffer) {
        free(uc->bounce.buffer);
    }

    g_hash_table_foreach(uc->type_table, free_table, uc);
    g_hash_table_destroy(uc->type_table);

    for (i = 0; i < DIRTY_MEMORY_NUM; i++) {
        free(uc->ram_list.dirty_memory[i]);
    }

    // 释放hook和hook列表
    for (i = 0; i < UC_HOOK_MAX; i++) {
        cur = uc->hook[i].head;
        // hook 可存在于多个列表，可通过计数获取释放的时间
        while (cur) {
            hook = (struct hook *)cur->data;
            if (--hook->refs == 0) {
                free(hook);
            }
            cur = cur->next;
        }
        list_clear(&uc->hook[i]);
    }

    free(uc->mapped_blocks);

    // 最后释放uc自身
    memset(uc, 0, sizeof(*uc));
    free(uc);

    return UC_ERR_OK;
}
```

</details>

使用实例同 [uc_open()](#uc_open) 。

### uc_query

```c
uc_err uc_query(uc_engine *uc, uc_query_type type, size_t *result);
```

查询引擎的内部状态

```
 @uc: uc_open() 返回的句柄
 @type: uc_query_type 中枚举的类型

 @result: 保存被查询的内部状态的指针

 @return: 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_query(uc_engine *uc, uc_query_type type, size_t *result)
{
    if (type == UC_QUERY_PAGE_SIZE) {
        *result = uc->target_page_size;
        return UC_ERR_OK;
    }

    if (type == UC_QUERY_ARCH) {
        *result = uc->arch;
        return UC_ERR_OK;
    }

    switch(uc->arch) {
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:
            return uc->query(uc, type, result);
#endif
        default:
            return UC_ERR_ARG;
    }

    return UC_ERR_OK;
}
```

</details>

使用示例：

```cpp
#include <iostream>
#include "unicorn/unicorn.h"
using namespace std;
int main()
{
	uc_engine* uc;
	uc_err err;

	// 初始化 ARM64 模式模拟器.
	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}
	cout << "uc engine created successfully." << endl;

	size_t result[] = { 0 };
	// 查询架构
	err = uc_query(uc, UC_QUERY_ARCH, result);
	if (!err)
		cout << "query successful: " << *result << endl;

	err = uc_close(uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_close() with error returned: %u\n", err);
		return -1;
	}
	cout << "uc engine closed successfully." << endl;
    return 0;
}
```

输出

```bash
uc engine created successfully.
query successful: 2
uc engine closed successfully.
```

架构查询结果为 2，对应的正是 UC_ARCH_ARM64 枚举值。

### uc_errno

```c
uc_err uc_errno(uc_engine *uc);
```

当某个 API 函数失败时，报告最后的错误号，一旦被访问，uc_errno 可能不会保留原来的值。

> 目前该函数已经没有被维护了 参考 [issues/2191](https://github.com/unicorn-engine/unicorn/issues/2191) 。

```
@uc: uc_open() 返回的句柄

@return: 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_errno(uc_engine *uc)
{
    return uc->errnum;
}
```

</details>

使用示例：

```cpp
#include <iostream>
#include "unicorn/unicorn.h"
using namespace std;

int main()
{
	uc_engine *uc;
	uc_err err;

	// 初始化 ARM64 模式模拟器.
	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
	if (err != UC_ERR_OK)
	{
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}
	cout << "uc engine created successfully." << endl;
	// 尝试从一个未映射的地址写入数据
    uint8_t val = 1;
    err = uc_mem_write(uc, 0, &val, sizeof(val));
	// 获取最后一次错误码，总是返回 UC_ERR_OK，不知道是否为 bug.
    uc_err error_code = uc_errno(uc);

	printf("Error code: %u\n", error_code);
	// 输出错误描述
	printf("Error description: %s\n", uc_strerror(error_code));
	printf("Error description: %s\n", uc_strerror(err));

	uc_close(uc);
	cout << "uc engine closed successfully." << endl;
	return 0;
}
```

输出

```bash
uc engine created successfully.
Error code: 0
Error description: OK (UC_ERR_OK)
Error description: Invalid memory write (UC_ERR_WRITE_UNMAPPED)
uc engine closed successfully.
```

uc_errno 返回的错误码始终为 0。

### uc_strerror

```c
const char *uc_strerror(uc_err code);
```

返回给定错误号的解释。

```
 @code: 错误号

 @return: 指向给定错误号的解释的字符串指针
```

<details><summary> 源码实现 </summary>

```cpp
const char *uc_strerror(uc_err code)
{
    switch(code) {
        default:
            return "Unknown error code";
        case UC_ERR_OK:
            return "OK (UC_ERR_OK)";
        case UC_ERR_NOMEM:
            return "No memory available or memory not present (UC_ERR_NOMEM)";
        case UC_ERR_ARCH:
            return "Invalid/unsupported architecture (UC_ERR_ARCH)";
        case UC_ERR_HANDLE:
            return "Invalid handle (UC_ERR_HANDLE)";
        case UC_ERR_MODE:
            return "Invalid mode (UC_ERR_MODE)";
        case UC_ERR_VERSION:
            return "Different API version between core & binding (UC_ERR_VERSION)";
        case UC_ERR_READ_UNMAPPED:
            return "Invalid memory read (UC_ERR_READ_UNMAPPED)";
        case UC_ERR_WRITE_UNMAPPED:
            return "Invalid memory write (UC_ERR_WRITE_UNMAPPED)";
        case UC_ERR_FETCH_UNMAPPED:
            return "Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)";
        case UC_ERR_HOOK:
            return "Invalid hook type (UC_ERR_HOOK)";
        case UC_ERR_INSN_INVALID:
            return "Invalid instruction (UC_ERR_INSN_INVALID)";
        case UC_ERR_MAP:
            return "Invalid memory mapping (UC_ERR_MAP)";
        case UC_ERR_WRITE_PROT:
            return "Write to write-protected memory (UC_ERR_WRITE_PROT)";
        case UC_ERR_READ_PROT:
            return "Read from non-readable memory (UC_ERR_READ_PROT)";
        case UC_ERR_FETCH_PROT:
            return "Fetch from non-executable memory (UC_ERR_FETCH_PROT)";
        case UC_ERR_ARG:
            return "Invalid argument (UC_ERR_ARG)";
        case UC_ERR_READ_UNALIGNED:
            return "Read from unaligned memory (UC_ERR_READ_UNALIGNED)";
        case UC_ERR_WRITE_UNALIGNED:
            return "Write to unaligned memory (UC_ERR_WRITE_UNALIGNED)";
        case UC_ERR_FETCH_UNALIGNED:
            return "Fetch from unaligned memory (UC_ERR_FETCH_UNALIGNED)";
        case UC_ERR_RESOURCE:
            return "Insufficient resource (UC_ERR_RESOURCE)";
        case UC_ERR_EXCEPTION:
            return "Unhandled CPU exception (UC_ERR_EXCEPTION)";
        case UC_ERR_TIMEOUT:
            return "Emulation timed out (UC_ERR_TIMEOUT)";
    }
}
```

</details>

使用示例同 [uc_errno()](#uc_errno)

### uc_reg_write

```c
uc_err uc_reg_write(uc_engine *uc, int regid, const void *value);
```

将值写入寄存器。

```
@uc: uc_open()返回的句柄
@regid:  将被修改的寄存器ID
@value:  指向寄存器将被修改成的值的指针

@return 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```cpp
uc_err uc_reg_write(uc_engine *uc, int regid, const void *value)
{
    return uc_reg_write_batch(uc, &regid, (void *const *)&value, 1);
}

uc_err uc_reg_write_batch(uc_engine *uc, int *ids, void *const *vals, int count)
{
    int ret = UC_ERR_OK;
    if (uc->reg_write)
        ret = uc->reg_write(uc, (unsigned int *)ids, vals, count);    //结构体中写入
    else
        return UC_ERR_EXCEPTION;

    return ret;
}
```

</details>

使用示例同 [引擎调用测试](#引擎调用测试)

### uc_reg_read

```c
uc_err uc_reg_read(uc_engine *uc, int regid, void *value);
```

读取寄存器的值。

```
@uc: uc_open()返回的句柄
@regid:  将被读取的寄存器ID
@value:  指向保存寄存器值的指针

@return 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_reg_read(uc_engine *uc, int regid, void *value)
{
    return uc_reg_read_batch(uc, &regid, &value, 1);
}

uc_err uc_reg_read_batch(uc_engine *uc, int *ids, void **vals, int count)
{
    if (uc->reg_read)
        uc->reg_read(uc, (unsigned int *)ids, vals, count);
    else
        return -1;

    return UC_ERR_OK;
}
```

</details>

使用示例同 [引擎调用测试](#引擎调用测试)

### uc_reg_write_batch

```c
uc_err uc_reg_write_batch(uc_engine *uc, int *regs, void *const *vals, int count);
```

同时将多个值写入多个寄存器。

```
@uc: uc_open()返回的句柄
@regid:  存储将被写入的多个寄存器ID的数组
@value:  指向保存多个值的数组的指针
@count: *regs 和 *vals 数组的长度

@return 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_reg_write_batch(uc_engine *uc, int *ids, void *const *vals, int count)
{
    int ret = UC_ERR_OK;
    if (uc->reg_write)
        ret = uc->reg_write(uc, (unsigned int *)ids, vals, count);
    else
        return UC_ERR_EXCEPTION;

    return ret;
}
```

</details>

使用示例：

```cpp
#include <iostream>
#include <string>
#include "unicorn/unicorn.h"
using namespace std;

int main()
{
	uc_engine *uc;
	uc_err err;
	int regs[] = {UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3};
	int64_t vals[] = {0x1, 0x2, 0x3, 0x4};
	void * prts[4];
	for (int i = 0; i < 4; i++)
	{
		prts[i] = &vals[i];
	}

	// 初始化 ARM64 模式模拟器.
	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
	if (err != UC_ERR_OK)
	{
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}
	printf("reg_write_batch({0x1, 0x2, 0x3, 0x4})\n");
	// 批量写入寄存器值.
	err = uc_reg_write_batch(uc, regs, prts, 4);
	if (err != UC_ERR_OK)
	{
		printf("Failed on uc_reg_write_batch() with error returned: %u\n", err);
		return -1;
	}
	// 批量读取寄存器值.
	memset(vals, 0, sizeof(vals));
	err = uc_reg_read_batch(uc, regs, prts, 4);
	if (err != UC_ERR_OK)
	{
		printf("Failed on uc_reg_read_batch() with error returned: %u\n", err);
		return -1;
	}
	for (int i = 0; i < 4; i++)
	{
		printf("X%d = 0x%llx\n", i, vals[i]);
	}

	uc_close(uc);
	return 0;
}
```

输出

```bash
reg_write_batch({0x1, 0x2, 0x3, 0x4})
X0 = 0x1
X1 = 0x2
X2 = 0x3
X3 = 0x4
```

### uc_reg_read_batch

```c
uc_err uc_reg_read_batch(uc_engine *uc, int *regs, void **vals, int count);
```

同时读取多个寄存器的值。

```
@uc: uc_open()返回的句柄
@regid:  存储将被读取的多个寄存器ID的数组
@value:  指向保存多个值的数组的指针
@count: *regs 和 *vals 数组的长度

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_reg_read_batch(uc_engine *uc, int *ids, void **vals, int count)
{
    if (uc->reg_read)
        uc->reg_read(uc, (unsigned int *)ids, vals, count);
    else
        return -1;

    return UC_ERR_OK;
}
```

</details>

使用示例同 [uc_reg_write_batch()](#uc_reg_write_batch) 。

### uc_mem_write

```c
uc_err uc_mem_write(uc_engine *uc, uint64_t address, const void *bytes, size_t size);
```

在内存中写入一段字节码。

```
@uc: uc_open() 返回的句柄
@address: 写入字节的起始地址
@bytes:   指向一个包含要写入内存的数据的指针
@size:   要写入的内存大小。

注意: @bytes 必须足够大以包含 @size 字节。

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_mem_write(uc_engine *uc, uint64_t address, const void *_bytes, size_t size)
{
    size_t count = 0, len;
    const uint8_t *bytes = _bytes;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    if (!check_mem_area(uc, address, size))
        return UC_ERR_WRITE_UNMAPPED;

    // 内存区域可以重叠相邻的内存块
    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            uint32_t operms = mr->perms;
            if (!(operms & UC_PROT_WRITE)) // 没有写保护
                // 标记为可写
                uc->readonly_mem(mr, false);

            len = (size_t)MIN(size - count, mr->end - address);
            if (uc->write_mem(&uc->as, address, bytes, len) == false)
                break;

            if (!(operms & UC_PROT_WRITE)) // 没有写保护
                // 设置写保护
                uc->readonly_mem(mr, true);

            count += len;
            address += len;
            bytes += len;
        } else  // 此地址尚未被映射
            break;
    }

    if (count == size)
        return UC_ERR_OK;
    else
        return UC_ERR_WRITE_UNMAPPED;
}
```

</details>

使用示例同 [引擎调用测试](#引擎调用测试) 。

### uc_mem_read

```c
uc_err uc_mem_read(uc_engine *uc, uint64_t address, void *bytes, size_t size);
```

从内存中读取字节。

```
 @uc: uc_open() 返回的句柄
 @address: 读取字节的起始地址
 @bytes:   指向一个包含要读取内存的数据的指针
 @size:   要读取的内存大小。

 注意: @bytes 必须足够大以包含 @size 字节。

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_mem_read(uc_engine *uc, uint64_t address, void *_bytes, size_t size)
{
    size_t count = 0, len;
    uint8_t *bytes = _bytes;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    if (!check_mem_area(uc, address, size))
        return UC_ERR_READ_UNMAPPED;

    // 内存区域可以重叠相邻的内存块
    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            len = (size_t)MIN(size - count, mr->end - address);
            if (uc->read_mem(&uc->as, address, bytes, len) == false)
                break;
            count += len;
            address += len;
            bytes += len;
        } else  // 此地址尚未被映射
            break;
    }

    if (count == size)
        return UC_ERR_OK;
    else
        return UC_ERR_READ_UNMAPPED;
}
```

</details>

使用示例同[uc_mem_write()](#uc_mem_write)

### uc_emu_start

```c
uc_err uc_emu_start(uc_engine *uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);
```

在指定的时间内模拟机器码。

```
@uc: uc_open() 返回的句柄
@begin: 开始模拟的地址
@until: 模拟停止的地址 (当到达该地址时)
@timeout: 模拟代码的持续时间(以微秒计)。当这个值为0时，将无时间限制模拟代码，直到模拟完成。
@count: 要模拟的指令数。当这个值为0时，将模拟所有可执行的代码，直到模拟完成

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_emu_start(uc_engine* uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count)
{
    // 重制计数器
    uc->emu_counter = 0;
    uc->invalid_error = UC_ERR_OK;
    uc->block_full = false;
    uc->emulation_done = false;
    uc->timed_out = false;

    switch(uc->arch) {
        default:
            break;
#ifdef UNICORN_HAS_M68K
        case UC_ARCH_M68K:
            uc_reg_write(uc, UC_M68K_REG_PC, &begin);
            break;
#endif
#ifdef UNICORN_HAS_X86
        case UC_ARCH_X86:
            switch(uc->mode) {
                default:
                    break;
                case UC_MODE_16: {
                    uint64_t ip;
                    uint16_t cs;

                    uc_reg_read(uc, UC_X86_REG_CS, &cs);
                    // 抵消后面增加的 IP 和 CS
                    ip = begin - cs*16;
                    uc_reg_write(uc, UC_X86_REG_IP, &ip);
                    break;
                }
                case UC_MODE_32:
                    uc_reg_write(uc, UC_X86_REG_EIP, &begin);
                    break;
                case UC_MODE_64:
                    uc_reg_write(uc, UC_X86_REG_RIP, &begin);
                    break;
            }
            break;
#endif
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:
            uc_reg_write(uc, UC_ARM_REG_R15, &begin);
            break;
#endif
#ifdef UNICORN_HAS_ARM64
        case UC_ARCH_ARM64:
            uc_reg_write(uc, UC_ARM64_REG_PC, &begin);
            break;
#endif
#ifdef UNICORN_HAS_MIPS
        case UC_ARCH_MIPS:
            // TODO: MIPS32/MIPS64/BIGENDIAN etc
            uc_reg_write(uc, UC_MIPS_REG_PC, &begin);
            break;
#endif
#ifdef UNICORN_HAS_SPARC
        case UC_ARCH_SPARC:
            // TODO: Sparc/Sparc64
            uc_reg_write(uc, UC_SPARC_REG_PC, &begin);
            break;
#endif
    }

    uc->stop_request = false;

    uc->emu_count = count;
    // 如果不需要计数，则移除计数挂钩hook
    if (count <= 0 && uc->count_hook != 0) {
        uc_hook_del(uc, uc->count_hook);
        uc->count_hook = 0;
    }
    // 设置计数hook记录指令数
    if (count > 0 && uc->count_hook == 0) {
        uc_err err;
        // 对计数指令的回调必须在所有其他操作之前运行，因此必须在hook列表的开头插入hook，而不是附加hook
        uc->hook_insert = 1;
        err = uc_hook_add(uc, &uc->count_hook, UC_HOOK_CODE, hook_count_cb, NULL, 1, 0);
        // 恢复到 uc_hook_add()
        uc->hook_insert = 0;
        if (err != UC_ERR_OK) {
            return err;
        }
    }

    uc->addr_end = until;

    if (timeout)
        enable_emu_timer(uc, timeout * 1000);   // microseconds -> nanoseconds

    if (uc->vm_start(uc)) {
        return UC_ERR_RESOURCE;
    }

    // 模拟完成
    uc->emulation_done = true;

    if (timeout) {
        // 等待超时
        qemu_thread_join(&uc->timer);
    }

    if(uc->timed_out)
        return UC_ERR_TIMEOUT;

    return uc->invalid_error;
}
```

</details>

使用示例同 [引擎调用测试](#引擎调用测试) 。

### uc_emu_stop

```c
uc_err uc_emu_stop(uc_engine *uc);
```

停止模拟，通常是从通过 tracing API 注册的回调函数中调用。

```
@uc: uc_open() 返回的句柄

@return 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_emu_stop(uc_engine *uc)
{
    if (uc->emulation_done)
        return UC_ERR_OK;

    uc->stop_request = true;

    if (uc->current_cpu) {
        // 退出当前线程
        cpu_exit(uc->current_cpu);
    }

    return UC_ERR_OK;
}
```

</details>

使用示例：

```cpp
#include <iostream>
#include <unicorn/unicorn.h>
using namespace std;

// 定义回调函数，当执行到特定位置时停止模拟
static bool stopping = false;
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%" PRIx64 ", instruction size = 0x%x\n", address, size);
    if (address == 0x1008) {  // 当执行到特定地址时停止
        printf(">>> Stopping emulation at 0x%" PRIx64 "\n", address);
        uc_emu_stop(uc);
        stopping = true;
    }
}

int main()
{
    uc_engine *uc;
    uc_err err;

    // 初始化模拟器
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error: %u (%s)\n", err, uc_strerror(err));
        return -1;
    }

    // 分配内存
    const uint64_t ADDRESS = 0x1000;
    const uint32_t SIZE = 0x1000; // 4KB
    err = uc_mem_map(uc, ADDRESS, SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        printf("Failed to map memory: %s\n", uc_strerror(err));
        return -1;
    }

    // ARM64 指令：简单的 NOP 序列
    uint32_t code[] = {
        0xd503201f,    // nop
        0xd503201f,    // nop
        0xd503201f     // nop
    };

    // 写入代码
    err = uc_mem_write(uc, ADDRESS, code, sizeof(code));
    if (err != UC_ERR_OK) {
        printf("Failed to write memory: %s\n", uc_strerror(err));
        return -1;
    }

    // 添加代码执行钩子
    uc_hook trace;
    err = uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook_code, NULL, 1, 0);
    if (err != UC_ERR_OK) {
        printf("Failed to add hook: %s\n", uc_strerror(err));
        return -1;
    }

    printf("Starting emulation...\n");
    // 开始模拟执行
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(code), 0, 0);
    if (err != UC_ERR_OK && !stopping) {
        printf("Failed on uc_emu_start() with error: %s\n", uc_strerror(err));
        return -1;
    }

    printf("Emulation finished\n");
    uc_close(uc);
    return 0;
}
```

输出：

```bash
Starting emulation...
>>> Tracing instruction at 0x1000, instruction size = 0x4
>>> Tracing instruction at 0x1004, instruction size = 0x4
>>> Tracing instruction at 0x1008, instruction size = 0x4
>>> Stopping emulation at 0x1008
Emulation finished
```

### uc_hook_add

```c
uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback,
        void *user_data, uint64_t begin, uint64_t end, ...);
```

注册 hook 事件的回调，当 hook 事件被触发将会进行回调，回调函数的参数可以通过在 unicorn.h 中搜索 `Callback function for` 字符串查找获取。

```
 @uc: uc_open() 返回的句柄
 @hh: 注册hook得到的句柄. uc_hook_del() 中使用
 @type: hook 类型
 @callback: 当指令被命中时要运行的回调
 @user_data: 用户自定义数据. 将被传递给回调函数的最后一个参数 @user_data
 @begin: 回调生效区域的起始地址(包括)
 @end: 回调生效区域的结束地址(包括)
   注意 1: 只有回调的地址在[@begin, @end]中才会调用回调
   注意 2: 如果 @begin > @end, 每当触发此hook类型时都会调用回调
 @...: 变量参数 (取决于 @type)
   注意: 如果 @type = UC_HOOK_INSN, 这里是指令ID (如: UC_X86_INS_OUT)

 @return 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型。
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback,
        void *user_data, uint64_t begin, uint64_t end, ...)
{
    int ret = UC_ERR_OK;
    int i = 0;

    struct hook *hook = calloc(1, sizeof(struct hook));
    if (hook == NULL) {
        return UC_ERR_NOMEM;
    }

    hook->begin = begin;
    hook->end = end;
    hook->type = type;
    hook->callback = callback;
    hook->user_data = user_data;
    hook->refs = 0;
    *hh = (uc_hook)hook;

    // UC_HOOK_INSN 有一个额外参数：指令ID
    if (type & UC_HOOK_INSN) {
        va_list valist;

        va_start(valist, end);
        hook->insn = va_arg(valist, int);
        va_end(valist);

        if (uc->insn_hook_validate) {
            if (! uc->insn_hook_validate(hook->insn)) {
                free(hook);
                return UC_ERR_HOOK;
            }
        }

        if (uc->hook_insert) {
            if (list_insert(&uc->hook[UC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                return UC_ERR_NOMEM;
            }
        } else {
            if (list_append(&uc->hook[UC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                return UC_ERR_NOMEM;
            }
        }

        hook->refs++;
        return UC_ERR_OK;
    }

    while ((type >> i) > 0) {
        if ((type >> i) & 1) {
            if (i < UC_HOOK_MAX) {
                if (uc->hook_insert) {
                    if (list_insert(&uc->hook[i], hook) == NULL) {
                        if (hook->refs == 0) {
                            free(hook);
                        }
                        return UC_ERR_NOMEM;
                    }
                } else {
                    if (list_append(&uc->hook[i], hook) == NULL) {
                        if (hook->refs == 0) {
                            free(hook);
                        }
                        return UC_ERR_NOMEM;
                    }
                }
                hook->refs++;
            }
        }
        i++;
    }

    if (hook->refs == 0) {
        free(hook);
    }

    return ret;
}
```

</details>

使用示例：

```cpp
#include <iostream>
#include <string>
#include "unicorn/unicorn.h"
using namespace std;

uc_err hook_intr_callback(uc_engine* uc, uint32_t intno, void* user_data)
{
	uint64_t x8;
	uc_reg_read(uc, UC_ARM64_REG_X8, &x8);
	printf("intno: %u\n", intno);
	printf("Caught svc (syscall): x8 = 0x%llx\n", x8);

	if (x8 == 93) {
		// exit() 的 syscall 号是 93
		uint64_t status;
		uc_reg_read(uc, UC_ARM64_REG_X0, &status);
		printf("Emulating exit(%lld)\n", status);

		// 停止模拟
		uc_emu_stop(uc);
	}
	else {
		printf("Unknown syscall %lld. Stopping emulation.\n", x8);
		uc_emu_stop(uc);
	}

	return UC_ERR_OK;
}

uc_err hook_code_callback(uc_engine* uc, uint64_t address, uint32_t size,
	void* user_data) {
	uint32_t code = 0;
	uc_mem_read(uc, address,&code, size);
	printf("address: %llx; value:%x; size: %u\n", address, code, size);
	return UC_ERR_OK;
}

int main()
{
	// ARM64 汇编指令：
	// mov x0, #0       --> exit status 0
	// mov x8, #93      --> syscall number for exit()
	// svc #0           --> trigger syscall
	const char code[] = "\x00\x00\x80\xD2\xA8\x0B\x80\xD2\x01\x00\x00\xD4";
	const int64_t address = 0x10000;
	uc_engine* uc;
	uc_err err;

	// 初始化 Unicorn 引擎：ARM64 架构，ARM 模式
	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed to open Unicorn engine: %s\n", uc_strerror(err));
		return -1;
	}

	// 分配内存空间用于写入代码
	uc_mem_map(uc, address, 2 * 1024 * 1024, UC_PROT_ALL);


	// 写入代码到内存
	uc_mem_write(uc, address, code, sizeof(code) - 1);

	// 添加 hook 来拦截 svc 指令
	uc_hook hook_intr;
	err = uc_hook_add(uc, &hook_intr, UC_HOOK_INTR, hook_intr_callback, NULL, 1, 0);
	if (err != UC_ERR_OK) {
		printf("Failed to uc_hook_add: %s\n", uc_strerror(err));
	}

	uc_hook hook_code;
	err = uc_hook_add(uc, &hook_code, UC_HOOK_CODE, hook_code_callback, NULL, 1, 0);
	if (err != UC_ERR_OK) {
		printf("Failed to uc_hook_add: %s\n", uc_strerror(err));
	}

	// 开始执行模拟
	printf("Starting emulation...\n");
	err = uc_emu_start(uc, address, address + sizeof(code) - 1, 0, 0);
	if (err != UC_ERR_OK) {
		printf("Failed to start emulation: %s\n", uc_strerror(err));
	}
	printf("Emulation stopped.\n");

	// 关闭引擎
	uc_close(uc);
	return 0;
}
```

输出

```bash
Starting emulation...
address: 10000; value:d2800000; size: 4
address: 10004; value:d2800ba8; size: 4
address: 10008; value:d4000001; size: 4
intno: 2
Caught svc (syscall): x8 = 0x5d
Emulating exit(0)
Emulation stopped.
```

实现了对 syscall 和 code 的 hook。

### uc_hook_del

```cpp
uc_err uc_hook_del(uc_engine *uc, uc_hook hh);
```

删除一个已注册的 hook 事件

```
@uc: uc_open() 返回的句柄
@hh: uc_hook_add() 返回的句柄

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_hook_del(uc_engine *uc, uc_hook hh)
{
    int i;
    struct hook *hook = (struct hook *)hh;

    for (i = 0; i < UC_HOOK_MAX; i++) {
        if (list_remove(&uc->hook[i], (void *)hook)) {
            if (--hook->refs == 0) {
                free(hook);
                break;
            }
        }
    }
    return UC_ERR_OK;
}
```

</details>

使用示例：

```cpp
if ((err = uc_hook_add(uc, &sys_hook, UC_HOOK_CODE, hook_syscall, NULL, 1, 0))) {
    uc_perror("uc_hook_add", err);
    return 1;
}

if ((err = uc_hook_del(uc, &sys_hook))) {
    uc_perror("uc_hook_del", err);
    return 1;
}
```

### uc_mem_map

```c
uc_err uc_mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms);
```

为模拟映射一块内存。

```
@uc: uc_open() 返回的句柄
@address: 要映射到的新内存区域的起始地址。这个地址必须与4KB对齐，否则将返回UC_ERR_ARG错误。
@size: 要映射到的新内存区域的大小。这个大小必须是4KB的倍数，否则将返回UC_ERR_ARG错误。
@perms: 新映射区域的权限。参数必须是UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC或这些的组合，否则返回UC_ERR_ARG错误。

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms)
{
    uc_err res;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    res = mem_map_check(uc, address, size, perms);    //内存安全检查
    if (res)
        return res;

    return mem_map(uc, address, size, perms, uc->memory_map(uc, address, size, perms));
}
```

</details>

使用示例同 [uc_hook_add()](#uc_hook_add) 。

### uc_mem_map_ptr

```c
uc_err uc_mem_map_ptr(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, void *ptr);
```

在模拟中映射现有的主机内存。

```
@uc: uc_open() 返回的句柄
@address: 要映射到的新内存区域的起始地址。这个地址必须与4KB对齐，否则将返回 UC_ERR_ARG 错误。
@size: 要映射到的新内存区域的大小。这个大小必须是4KB的倍数，否则将返回 UC_ERR_ARG 错误。
@perms: 新映射区域的权限。参数必须是UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC或这些的组合，否则返回UC_ERR_ARG错误。
@ptr: 指向支持新映射内存的主机内存的指针。映射的主机内存的大小应该与size的大小相同或更大，并且至少使用PROT_READ | PROT_WRITE进行映射，否则不定义映射。

@return 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_mem_map_ptr(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, void *ptr)
{
    uc_err res;

    if (ptr == NULL)
        return UC_ERR_ARG;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    res = mem_map_check(uc, address, size, perms);    //内存安全检查
    if (res)
        return res;

    return mem_map(uc, address, size, UC_PROT_ALL, uc->memory_map_ptr(uc, address, size, perms, ptr));
}
```

</details>

使用示例同 [uc_mem_map()](#uc_mem_map)

### uc_mem_unmap

```c
uc_err uc_mem_unmap(uc_engine *uc, uint64_t address, size_t size);
```

取消对模拟内存区域的映射。

```
@uc: uc_open() 返回的句柄
@address: 要映射到的新内存区域的起始地址。这个地址必须与4KB对齐，否则将返回UC_ERR_ARG错误。
@size: 要映射到的新内存区域的大小。这个大小必须是4KB的倍数，否则将返回UC_ERR_ARG错误。

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_mem_unmap(struct uc_struct *uc, uint64_t address, size_t size)
{
    MemoryRegion *mr;
    uint64_t addr;
    size_t count, len;

    if (size == 0)
        // 没有要取消映射的区域
        return UC_ERR_OK;

    // 地址必须对齐到 uc->target_page_size
    if ((address & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    // 大小必须是 uc->target_page_size 的倍数
    if ((size & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    // 检查用户请求的整个块是否被映射
    if (!check_mem_area(uc, address, size))
        return UC_ERR_NOMEM;

    // 如果这个区域跨越了相邻的区域，可能需要分割区域
    addr = address;
    count = 0;
    while(count < size) {
        mr = memory_mapping(uc, addr);
        len = (size_t)MIN(size - count, mr->end - addr);
        if (!split_region(uc, mr, addr, len, true))
            return UC_ERR_NOMEM;

        // 取消映射
        mr = memory_mapping(uc, addr);
        if (mr != NULL)
           uc->memory_unmap(uc, mr);
        count += len;
        addr += len;
    }

    return UC_ERR_OK;
}
```

</details>

使用示例：

```cpp
if ((err = uc_mem_map(uc, BASE, 0x1000, UC_PROT_ALL))) {
    uc_perror("uc_mem_map", err);
    return 1;
}

if ((err = uc_mem_unmap(uc, BASE, 0x1000))) {
    uc_perror("uc_mem_unmap", err);
    return 1;
}
```

### uc_mem_protect

```c
uc_err uc_mem_protect(uc_engine *uc, uint64_t address, size_t size, uint32_t perms);
```

设置模拟内存的权限。

```
@uc: uc_open() 返回的句柄
@address: 要映射到的新内存区域的起始地址。这个地址必须与4KB对齐，否则将返回UC_ERR_ARG错误。
@size: 要映射到的新内存区域的大小。这个大小必须是4KB的倍数，否则将返回UC_ERR_ARG错误。
@perms: 映射区域的新权限。参数必须是UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC或这些的组合，否则返回UC_ERR_ARG错误。

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_mem_protect(struct uc_struct *uc, uint64_t address, size_t size, uint32_t perms)
{
    MemoryRegion *mr;
    uint64_t addr = address;
    size_t count, len;
    bool remove_exec = false;

    if (size == 0)
        // trivial case, no change
        return UC_ERR_OK;

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    // check for only valid permissions
    if ((perms & ~UC_PROT_ALL) != 0)
        return UC_ERR_ARG;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    // check that user's entire requested block is mapped
    if (!check_mem_area(uc, address, size))
        return UC_ERR_NOMEM;

    // Now we know entire region is mapped, so change permissions
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while(count < size) {
        mr = memory_mapping(uc, addr);
        len = (size_t)MIN(size - count, mr->end - addr);
        if (!split_region(uc, mr, addr, len, false))
            return UC_ERR_NOMEM;

        mr = memory_mapping(uc, addr);
        // will this remove EXEC permission?
        if (((mr->perms & UC_PROT_EXEC) != 0) && ((perms & UC_PROT_EXEC) == 0))
            remove_exec = true;
        mr->perms = perms;
        uc->readonly_mem(mr, (perms & UC_PROT_WRITE) == 0);

        count += len;
        addr += len;
    }

    // if EXEC permission is removed, then quit TB and continue at the same place
    if (remove_exec) {
        uc->quit_request = true;
        uc_emu_stop(uc);
    }

    return UC_ERR_OK;
}
```

</details>

使用示例：

```cpp
if ((err = uc_mem_protect(uc, BASE, 0x1000, UC_PROT_ALL))) {  //可读可写可执行
    uc_perror("uc_mem_protect", err);
    return 1;
}
```

### uc_mem_regions

```c
uc_err uc_mem_regions(uc_engine *uc, uc_mem_region **regions, uint32_t *count);
```

检索由 `uc_mem_map()` 和 `uc_mem_map_ptr()` 映射的内存的信息。

这个 API 为 `@regions` 分配内存，用户之后必须通过 `uc_free()` 释放这些内存来避免内存泄漏。

```
@uc: uc_open() 返回的句柄
@regions: 指向 uc_mem_region 结构体的数组的指针. 由Unicorn申请，必须通过 uc_free()释放这些内存
@count: 指向@regions中包含的uc_mem_region结构体的数量的指针

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

源码分析

<details><summary> Code </summary>

```c
uint32_t uc_mem_regions(uc_engine *uc, uc_mem_region **regions, uint32_t *count)
{
    uint32_t i;
    uc_mem_region *r = NULL;

    *count = uc->mapped_block_count;

    if (*count) {
        r = g_malloc0(*count * sizeof(uc_mem_region));
        if (r == NULL) {
            // 内存不足
            return UC_ERR_NOMEM;
        }
    }

    for (i = 0; i < *count; i++) {
        r[i].begin = uc->mapped_blocks[i]->addr;
        r[i].end = uc->mapped_blocks[i]->end - 1;
        r[i].perms = uc->mapped_blocks[i]->perms;
    }

    *regions = r;

    return UC_ERR_OK;
}
```

</details>

使用示例：

```cpp
#include <iostream>
#include <string>
#include "unicorn/unicorn.h"
using namespace std;

int main()
{
	uc_err err;
	uc_engine* uc;

	if ((err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc))) {
		printf("uc_open error: %s\n", uc_strerror(err));
		return -1;
	}

	if ((err = uc_mem_map(uc, BASE, 0x1000, UC_PROT_ALL))) {
		printf("uc_mem_map error: %s\n", uc_strerror(err));
		return -1;
	}

	uc_mem_region* region;
	uint32_t count;

	if ((err = uc_mem_regions(uc, &region, &count))) {
		printf("uc_mem_regions error: %s\n", uc_strerror(err));
		return -1;
	}

	cout << "start addr: 0x" << hex << region->begin << "\nend addr: 0x" << hex << region->end \
		<< "\nmem permissions:  " << region->perms << "\nNumber of allocated memory blocks: " << count << endl;

	if ((err = uc_free(region))) {    ////注意释放内存
		printf("uc_free error: %s\n", uc_strerror(err));
		return -1;
	}
```

输出

```bash
start addr: 0x10000
end addr: 0x10fff
mem permissions:  7
Number of allocated memory blocks: 1
```


### uc_free

```c
uc_err uc_free(void *mem);
```

释放由 [uc_mem_regions()](#uc_mem_regions) 申请的内存。

```
@mem: 由 uc_mem_regions (返回 *regions)申请的内存

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_free(void *mem)
{
    g_free(mem);
    return UC_ERR_OK;
}

void g_free(gpointer ptr)
{
   free(ptr);
}
```

</details>

使用示例同 [uc_mem_regions()](#uc_mem_regions) 。

### uc_context_alloc

```c
uc_err uc_context_alloc(uc_engine *uc, uc_context **context);
```

分配一个可以与 `uc_context_{save,restore}` 一起使用的区域来执行 CPU 上下文的快速保存/回滚，包括寄存器和内部元数据。上下文不能在具有不同架构或模式的引擎实例之间共享。

```
@uc: uc_open() 返回的句柄
@context: 指向uc_engine*的指针。当这个函数成功返回时，将使用指向新上下文的指针更新它。之后必须使用uc_context_free()释放这些分配的内存。

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_context_alloc(uc_engine *uc, uc_context **context)
{
    struct uc_context **_context = context;
    size_t size = uc->cpu_context_size;

    *_context = g_malloc(size);
    if (*_context) {
        (*_context)->jmp_env_size = sizeof(*uc->cpu->jmp_env);
        (*_context)->context_size = size - sizeof(uc_context) - (*_context)->jmp_env_size;
        return UC_ERR_OK;
    } else {
        return UC_ERR_NOMEM;
    }
}
```

</details>

使用示例

```cpp
#include <iostream>
#include <string>
#include "unicorn/unicorn.h"
using namespace std;

int main()
{
	const int64_t address = 0x1000;
	const char code[] = "\x00\x04\x00\x91"; // add X0, X0, 1
	uc_engine* uc;
	uc_context* context;
	uc_err err;
	int64_t x0 = 0x1;
	printf("===================================\n");
	printf("Save/restore CPU context in opaque blob\n");
	if ((err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc)) != UC_ERR_OK) {
		printf("uc_open error: %s\n", uc_strerror(err));
		return -1;
	}
	if ((err = uc_mem_map(uc, address, 8 * 1024, UC_PROT_ALL)) != UC_ERR_OK) {
		printf("uc_mem_map error: %s\n", uc_strerror(err));
		return -1;
	}
	if ((err = uc_mem_write(uc, address, code, sizeof(code) - 1)) != UC_ERR_OK) {
		printf("uc_mem_map error: %s\n", uc_strerror(err));
		return -1;
	}
	// 初始化寄存器
	if ((err = uc_reg_write(uc, UC_ARM64_REG_X0, &x0)) != UC_ERR_OK) {
		printf("uc_reg_write error: %s\n", uc_strerror(err));
		return -1;
	}
	printf(">>> Running emulation for the first time\n");
	if ((err = uc_emu_start(uc, address, address + sizeof(code) - 1, 0, 0)) != UC_ERR_OK) {
		printf("uc_emu_start error: %s\n", uc_strerror(err));
		return -1;
	}
	printf(">>> Emulation done. Below is the CPU context\n");
	if ((err = uc_reg_read(uc, UC_ARM64_REG_X0, &x0)) != UC_ERR_OK) {
		printf("uc_reg_read error: %s\n", uc_strerror(err));
		return -1;
	}
	printf(">>> x0 = 0x%x\n", x0);
	// 申请并保存 CPU 上下文
	printf(">>> Saving CPU context\n");
	if ((err = uc_context_alloc(uc, &context)) != UC_ERR_OK) {
		printf("uc_context_alloc error: %s\n", uc_strerror(err));
		return -1;
	}
	if ((err = uc_context_save(uc, context)) != UC_ERR_OK) {
		printf("uc_context_save error: %s\n", uc_strerror(err));
		return -1;
	}
	printf(">>> Running emulation for the second time\n");
	if ((err = uc_emu_start(uc, address, address + sizeof(code) - 1, 0, 0)) != UC_ERR_OK) {
		printf("uc_emu_start error: %s\n", uc_strerror(err));
		return -1;
	}
	printf(">>> Emulation done. Below is the CPU context\n");
	if ((err = uc_reg_read(uc, UC_ARM64_REG_X0, &x0)) != UC_ERR_OK) {
		printf("uc_reg_read error: %s\n", uc_strerror(err));
		return -1;
	}
	printf(">>> x0 = 0x%x\n", x0);
	// 恢复 CPU 上下文
	if ((err = uc_context_restore(uc, context)) != UC_ERR_OK) {
		printf("uc_context_restore error: %s\n", uc_strerror(err));
		return -1;
	}
	printf(">>> CPU context restored. Below is the CPU context\n");

	if ((err = uc_reg_read(uc, UC_ARM64_REG_X0, &x0)) != UC_ERR_OK) {
		printf("uc_reg_read error: %s\n", uc_strerror(err));
		return -1;
	}
	printf(">>> x0 = 0x%x\n", x0);

	// 释放 CPU 上下文
	if ((err = uc_context_free(context)) != UC_ERR_OK) {
		printf("uc_reg_read error: %s\n", uc_strerror(err));
		return -1;
	}
	if ((err = uc_close(uc)) != UC_ERR_OK) {
		printf("uc_close error: %s\n", uc_strerror(err));
		return -1;
	}
    return 0;
}
```

输出

```bash
===================================
Save/restore CPU context in opaque blob
>>> Running emulation for the first time
>>> Emulation done. Below is the CPU context
>>> x0 = 0x2
>>> Saving CPU context
>>> Running emulation for the second time
>>> Emulation done. Below is the CPU context
>>> x0 = 0x3
>>> CPU context restored. Below is the CPU context
>>> x0 = 0x2
```


### uc_context_save

```c
uc_err uc_context_save(uc_engine *uc, uc_context *context);
```

保存当前 CPU 上下文

```
@uc: uc_open() 返回的句柄
@context: uc_context_alloc() 返回的句柄

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_context_save(uc_engine *uc, uc_context *context)
{
    struct uc_context *_context = context;
    memcpy(_context->data, uc->cpu->env_ptr, _context->size);
    return UC_ERR_OK;
}
```

</details>

使用示例同 [uc_context_alloc()](#uc_context_alloc)

### uc_context_restore

```c
uc_err uc_context_restore(uc_engine *uc, uc_context *context);
```

恢复已保存的 CPU 上下文。

```
@uc: uc_open() 返回的句柄
@context: uc_context_alloc() 返回并且已使用 uc_context_save 保存的句柄

@return 成功则返回UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

<details><summary> 源码实现 </summary>

```c
uc_err uc_context_restore(uc_engine *uc, uc_context *context)
{
    struct uc_context *_context = context;
    memcpy(uc->cpu->env_ptr, _context->data, _context->size);
    return UC_ERR_OK;
}
```

</details>

使用示例同 [uc_context_alloc()](#uc_context_alloc)

### uc_context_size

```c
size_t uc_context_size(uc_engine *uc);
```

返回存储 cpu 上下文所需的大小。可以用来分配一个缓冲区来包含 cpu 上下文，并直接调用 uc_context_save。

```
@uc: uc_open() 返回的句柄

@return 存储cpu上下文所需的大小，类型为 size_t.
```

<details><summary> 源码实现 </summary>

```c
size_t uc_context_size(uc_engine *uc)
{
    return sizeof(uc_context) + uc->cpu_context_size + sizeof(*uc->cpu->jmp_env);
}
```

</details>

使用示例同 [uc_context_alloc()](#uc_context_alloc) 。

### uc_context_free

```c
uc_err uc_context_free(uc_context *context);
```

释放由 [uc_context_alloc()](#uc_context_alloc) 申请的内存。

```
@context: 由 uc_context_alloc 创建的 uc_context 

@return 成功则返回 UC_ERR_OK , 否则返回 uc_err 枚举的其他错误类型
```

使用示例同 [uc_context_alloc()](#uc_context_alloc) 。
