# Unicorn 学习与应用

## Unicorn、Keystone、Capstone 介绍

[Unicorn](https://github.com/unicorn-engine/unicorn)、[Keystone](https://github.com/keystone-engine/keyskeystone-enginetone) 和 [Capstone](https://github.com/capstone-engine/capstone) 是三款在逆向工程和安全研究领域中广泛使用的开源工具，它们各自具有不同的功能和用途。

- Unicorn ：Unicorn 是一个轻量级、多平台、多架构的 CPU 模拟器框架。它允许开发者专注于 CPU 操作，而无需担心机器设备之间的差异。这意味着它可以用来模拟执行二进制代码，这对于分析恶意软件或理解编译后的程序非常有用。
- Keystone ：Keystone 是一个汇编器引擎，支持多种处理器架构。它能够将汇编语言转换为机器码，这在创建自定义编译工具或者需要直接生成可执行代码的情况下特别有用。Keystone 与 Capstone 和 Unicorn 一起被提及，作为逆向工程的标准工具集的一部分。
- Capstone ：Capstone 被誉为“终极反汇编器”，是一个下一代的反汇编引擎，提供了一个轻量级的支持多平台和多架构的反汇编框架。它的设计目的是为了从二进制文件中提取汇编代码，这对于进行逆向工程和安全分析至关重要。

如果需要使用 Unicorn，最好将上面三个框架都安装。这样就可以使用 Unicorn 来模拟 CPU 执行二进制代码，使用 Keystone 来将汇编语言转换为机器码，并使用 Capstone 来反汇编二进制文件。

这里直接使用 python 版本进行安装：

```bash
$ pip install unicorn
$ pip install keystone-engine
$ pip install capstone
```

### antiFrida

根据课程中给出的例子，我们需要过掉检测 frida 的方法。首先观察到使用 frida 后，应用就会退出。所以可以通过退出的时机来判断检测代码在哪里。
由于这里的测试例子比较简单，所以这一步可以忽略。下面还是给出相关的代码，判断检测点在哪个 so 中。

```javascript
function hook_dlopen() {
  Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function (args) {
      let so_path_ptr = args[0];
      if (so_path_ptr !== undefined && so_path_ptr !== null) {
        let path = so_path_ptr.readCString();
        console.log("load: " + path);
      }
    },
  });
}

function main() {
  hook_dlopen();
}

setImmediate(main);
```

然后使用 frida 加载脚本即可找到检测的 so 文件为 `libnative-lib.so` 。

```bash
➜ frida  frida -Uf com.example.test -l capstonetest.js
     ____
    / _  |   Frida 16.6.6 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel (id=FA6AF0309510)
Spawned `com.example.test`. Resuming main thread!
[Pixel::com.example.test ]-> load: /data/app/com.example.test-pQBCsbbccuyK6mlYBQv7tg==/oat/arm64/base.odex
load: /data/app/com.example.test-pQBCsbbccuyK6mlYBQv7tg==/lib/arm64/libnative-lib.so
Process terminated
[Pixel::com.example.test ]->

Thank you for using Frida!
```

下面就开始分析 `libnative-lib.so` 中的反调试代码。使用 IDA 打开 `libnative-lib.so`，发现导入表中存在 kill 和 exit 函数。

![](assets/2025-05-20-15-00-50.png)

使用快捷键 x 分别查看 kill 和 exit 函数的调用位置，如下图所示：

![](assets/2025-05-20-15-02-29.png)

![](assets/2025-05-20-15-03-33.png)

找到了相关调用地址之后，就可以使用 IDA 进行静态 patch 了。

这里为了学习课程中的内容，使用 frida 进行动态 patch。

首先需要在 libnative-lib.so 加载时进行 hook，避免 hook 时机太晚导致失败。

在 Android 系统中，linker 加载 so 文件时会调用 `call_function` 函数，这个函数会调用 `.init_proc` 等类型的函数，这是常见的反调试手段插入点。通过查阅 [Android Linker](https://xrefandroid.com/android-15.0.0_r1/search?full=call_function&project=bionic) 源码，可以了解 `call_function` 的实现和调用时机，如下图所示：

![](assets/2025-05-20-11-31-17.png)

`call_function` 函数会被 `call_constructors` 调用，由于调用 `call_function` 时会传递 so 的路径，因此这是一个理想的 hook 点，可以在这里获取 so 的路径。、

为了进一步确认 `call_function` 函数在 so 中的名称，将手机中的 `/apex/com.android.runtime/bin/linker64` 文件导出并用 IDA 反编译后，发现找不到 `call_function`，原因是该函数被内联到 `call_constructors` 函数中了。此时可以选择 hook `call_constructors` 函数来间接获取 so 路径。

![](assets/2025-05-20-11-40-07.png)

通过对比源码可知，v1 为 soinfo 对象，v9 保存了 so 的路径。进一步分析发现，v9 的值为 `[v1 + 432]`，据此可获取 so 路径。

获取了 so 的路径之后，就可以在加载 `libnative-lib.so` 时使用 frida 进行动态 patch 了。下面是完整的代码：

```javascript
// 输出汇编指令
function dis(address, num) {
  for (let i = 0; i < num; i++) {
    let ins = Instruction.parse(address);
    console.log("address: " + address + "--dis:" + ins.toString());
    address = ins.next;
  }
}
function hook() {
  // linker 加载 so 时会调用 call_function 函数，该函数会在so加载时被调用。
  // hook call_function("DT_INIT", init_func_, get_realpath());
  let linker_module = Process.getModuleByName("linker64");
  let call_function_addr = null;
  let symbols = linker_module.enumerateSymbols();
  for (let i = 0; i < symbols.length; i++) {
    let symbol = symbols[i];
    // console.log(linker_module.name + " symbol:" + symbol.name + " -- " + symbol.address);
    if (symbol.name.indexOf("_dl__ZN6soinfo17call_constructorsEv") !== -1) {
      console.log(
        linker_module.name + " symbol:" + symbol.name + " -- " + symbol.address
      );
      call_function_addr = symbol.address;
    }
  }
  Interceptor.attach(call_function_addr, {
    onEnter: function (args) {
      let soinfo = args[0];
      let path = ptr(soinfo).add(432).readPointer().readCString();
      if (path.indexOf("libnative-lib.so") !== -1) {
        let libnative_module = Process.getModuleByName("libnative-lib.so");
        let base = libnative_module.base;
        console.log("-----------patch kill before----------");
        dis(base.add(0xffb4), 10);
        // FFC4 4B FE FF 97     BL .kill
        let patchaddr = base.add(0xffc4);
        Memory.patchCode(patchaddr, 4, (patchaddr) => {
          let cw = new Arm64Writer(patchaddr);
          cw.putNop();
          cw.flush();
        });
        console.log("-----------patch kill after----------");
        dis(base.add(0xffb4), 10);

        // 10340 74 FD FF 97     BL .exit
        console.log("-----------patch exit before-----------");
        dis(base.add(0x10330), 10);
        Memory.protect(base.add(0x10340), 4, "rwx");
        base.add(0x10340).writeByteArray([0x1f, 0x20, 0x03, 0xd5]);
        console.log("-----------patch exit after----------");
        dis(base.add(0x10330), 10);
      }
    },
  });
}

function main() {
  hook();
}

setImmediate(main);
```

运行 frida 脚本后，发现应用不会退出了。

```bash
$ frida -Uf com.example.test -l capstonetest.js
     ____
    / _  |   Frida 16.6.6 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel (id=FA6AF0309510)
Spawning `com.example.test`...
linker64 symbol:__dl__ZN6soinfo17call_constructorsEv -- 0x72e9f40e48
Spawned `com.example.test`. Resuming main thread!
[Pixel::com.example.test ]-> -----------patch kill before----------
address: 0x71f4f94fb4--dis:mov w1, #9
address: 0x71f4f94fb8--dis:str w1, [sp, #0xc]
address: 0x71f4f94fbc--dis:bl #0x71f4f945f0
address: 0x71f4f94fc0--dis:ldr w1, [sp, #0xc]
address: 0x71f4f94fc4--dis:bl #0x71f4f948f0
address: 0x71f4f94fc8--dis:add x8, sp, #0x48
address: 0x71f4f94fcc--dis:add x3, sp, #0x248
address: 0x71f4f94fd0--dis:add x2, sp, #0x254
address: 0x71f4f94fd4--dis:add x5, sp, #0x258
address: 0x71f4f94fd8--dis:add x9, sp, #0x267
-----------patch kill after----------
address: 0x71f4f94fb4--dis:mov w1, #9
address: 0x71f4f94fb8--dis:str w1, [sp, #0xc]
address: 0x71f4f94fbc--dis:bl #0x71f4f945f0
address: 0x71f4f94fc0--dis:ldr w1, [sp, #0xc]
address: 0x71f4f94fc4--dis:nop
address: 0x71f4f94fc8--dis:add x8, sp, #0x48
address: 0x71f4f94fcc--dis:add x3, sp, #0x248
address: 0x71f4f94fd0--dis:add x2, sp, #0x254
address: 0x71f4f94fd4--dis:add x5, sp, #0x258
address: 0x71f4f94fd8--dis:add x9, sp, #0x267
-----------patch exit before-----------
address: 0x71f4f95330--dis:bl #0x71f4f94420
address: 0x71f4f95334--dis:cbz w0, #0x71f4f95344
address: 0x71f4f95338--dis:b #0x71f4f9533c
address: 0x71f4f9533c--dis:mov w0, #-1
address: 0x71f4f95340--dis:bl #0x71f4f94910
address: 0x71f4f95344--dis:ldr x0, [sp, #0x10]
address: 0x71f4f95348--dis:bl #0x71f4f943f0
address: 0x71f4f9534c--dis:mrs x30, tpidr_el0
address: 0x71f4f95350--dis:ldr x30, [x30, #0x28]
address: 0x71f4f95354--dis:ldur x8, [x29, #-8]
-----------patch exit after----------
address: 0x71f4f95330--dis:bl #0x71f4f94420
address: 0x71f4f95334--dis:cbz w0, #0x71f4f95344
address: 0x71f4f95338--dis:b #0x71f4f9533c
address: 0x71f4f9533c--dis:mov w0, #-1
address: 0x71f4f95340--dis:nop
address: 0x71f4f95344--dis:ldr x0, [sp, #0x10]
address: 0x71f4f95348--dis:bl #0x71f4f943f0
address: 0x71f4f9534c--dis:mrs x30, tpidr_el0
address: 0x71f4f95350--dis:ldr x30, [x30, #0x28]
address: 0x71f4f95354--dis:ldur x8, [x29, #-8]
[Pixel::com.example.test ]->

```

## Unicorn 简单上手

unicorn 模拟执行的步骤如下：

1. 创建一个 Unicorn 对象
2. 内存映射
3. 将代码写入内存
4. 开始模拟运行

```python
import unicorn


def unicorn_emu_arm64_add():
    # 简单的模拟 arm64 下的 add 指令
    # 1. 创建一个unicorn 对象
    emu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    # 2. 内存映射
    emu.mem_map(0x10000, 2 * 1024 * 1024)
    # 3. 将代码写入内存
    # mov x0, #1; mov x1, #2, add x0, x0, x1
    CODE = b'\x20\x00\x80\xD2\x41\x00\x80\xD2\x00\x00\x01\x8B'
    emu.mem_write(0x10000, CODE)
    # 4. 开始模拟执行
    emu.emu_start(0x10000, 0x10000 + len(CODE))
    x0 = emu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X0)
    print(f"0x{x0:08x}")


if __name__ == '__main__':
    unicorn_emu_arm64_add()
```

运行输出：

```
0x00000003
```

这样就模拟执行了一段简单的 ARM64 代码，将两个数字相加，并输出结果。

在模拟过程执行过程中，我们还可以通过 uc_hook_add() 函数添加各种 Hook 回调函数，实现更多的功能。

<details><summary> 源码实现 </summary>

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

// 回调函数指针
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

</details>

```python
import capstone
import unicorn

def uc_cb_hookintr(emu: unicorn, intno: int, user_data: int):
    X0 = emu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X0)
    X8 = emu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X8)
    print(f"syscall intno: {intno} x0={X0:08x} X8={X8:08x}")


def uc_cb_hookcode(emu: unicorn, address: int, size: int, user_data: int):
    code = emu.mem_read(address, size)
    Cp = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for i in Cp.disasm(code, 0, size):
        print(f"disasm {address:08x}: {i.mnemonic}, {i.op_str}")


def uc_cb_eventmem(emu: unicorn, event_type: int, address: int, size: int, value: int, user_data: int):
    if event_type == unicorn.UC_MEM_WRITE_UNMAPPED:
        print(f"mem upmaped:{address:08X}, {value}, {size}, {user_data}")
        address = address & 0x1000
        emu.mem_map(address, 0x1000)
        return True
    return False


def uc_cb_hookmem(emu: unicorn, event_type: int, address: int, size: int, value: int, user_data: int):
    if event_type == unicorn.UC_MEM_READ:
        print(f"read mem: {address:08X}, {value}, {size}, {user_data}")
    elif event_type == unicorn.UC_MEM_WRITE:
        print(f"write mem {address:08X}, {value}, {size}, {user_data}")


def unicorn_emu_arm64_add_hook():
    # 1. 创建一个unicorn 对象
    emu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    # 2. 内存映射
    emu.mem_map(0x10000, 2 * 1024 * 1024)
    # 3. 将代码写入内存
    """
    // mov x0, #0       --> exit status 0
	// mov x8, #93      --> syscall number for exit()
	// svc #0           --> trigger syscall
	// STR X8, [sp, #0xb8]
	// LDR X0, [sp, #0xb8]
    """
    CODE = b"\x00\x00\x80\xD2\xA8\x0B\x80\xD2\x01\x00\x00\xD4\xE8\x5F\x00\xF9\xE0\x5F\x40\xF9"

    emu.mem_write(0x10000, CODE)
    # 添加 hook
    emu.hook_add(unicorn.UC_HOOK_INTR, uc_cb_hookintr)
    emu.hook_add(unicorn.UC_HOOK_CODE, uc_cb_hookcode)
    emu.hook_add(unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, uc_cb_eventmem)
    emu.hook_add(unicorn.UC_HOOK_MEM_READ, uc_cb_hookmem)
    emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, uc_cb_hookmem)
    # 4. 开始模拟执行
    emu.emu_start(0x10000, 0x10000 + len(CODE))
    x0 = emu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X0)
    print(f"x0 = 0x{x0:08x}")


if __name__ == '__main__':
    unicorn_emu_arm64_add_hook()
```

运行结果：

```bash
disasm 00010000: mov, x0, #0
disasm 00010004: mov, x8, #0x5d
disasm 00010008: svc, #0
syscall intno: 2 x0=00000000 X8=0000005d
disasm 0001000c: str, x8, [sp, #0xb8]
write mem 000000B8, 93, 8, None
mem upmaped:000000B8, 93, 8, None
disasm 00010010: ldr, x0, [sp, #0xb8]
read mem: 000000B8, 0, 8, None
x0 = 0x0000005d
```

## unicorn 模拟执行 so

### 模拟传参

- ARM(Thumb) 传参规则为 R0-R3 为前 4 个参数，大于 4 个参数则使用栈传递，返回值保存在 R0 中。
- ARM64 传参规则为 X0-X7 为前 8 个参数，大于 8 个参数则使用栈传递，返回值保存在 X0-X1 或 X8 中。

```python
import capstone
import unicorn

def print_arm64_regs(mu):
    regs = [
        "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7",
        "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15",
        "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23",
        "X24", "X25", "X26", "X27", "X28", "X29", "X30", "SP", "PC"
    ]
    count = 0
    output = ''
    for reg in regs:
        val = mu.reg_read(getattr(unicorn.arm64_const, f"UC_ARM64_REG_{reg}"))
        if count < 8:
            output +=f"{reg} = 0x{val:x}\t"
            count += 1
        else:
            output += f"\n{reg} = 0x{val:x}\t"
            count = 0
    print(output)
# unicorn 调用 so
def hook_code_args2(mu:unicorn, address:int, size:int, user_data:int):
    code = mu.mem_read(address, size)
    CP = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for i in CP.disasm(code, 0, size):
        print(f"0x{address:08X}: {i.mnemonic}: {i.op_str}")
    print_arm64_regs(mu)

def test_arm64_arg2():
    CODE_OFFSET = 0x940
    CODE_SIZE = 0x1C
    CODE = None
    with open("so/libuniron.so", "rb") as f:
        CODE = f.read()
    # 使用 Capstone 反汇编 add 代码, add 地址为 24FF0
    CP = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for i in CP.disasm(CODE[CODE_OFFSET:CODE_OFFSET+CODE_SIZE], 0, CODE_SIZE):
        address = i.address + CODE_OFFSET
        print(f"0x{address:08X}: {i.mnemonic}: {i.op_str}")
    # 开始模拟执行
    mu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    ADDRESS = 0x1000
    SIZE = 10*1024*1024
    # 映射内存并将代码写入内存
    mu.mem_map(ADDRESS, SIZE)
    mu.mem_write(ADDRESS, CODE)
    # 使用 W0, W1 传参
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W0, 0x1)
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W1, 0x2)
    # 设置堆栈
    SP = ADDRESS + SIZE - 0x64
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, SP)
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_LR, ADDRESS+0x100)
    # 添加 UC_HOOK_CODE 回调
    mu.hook_add(unicorn.UC_HOOK_CODE, hook_code_args2)

    # 开始模拟执行
    mu.emu_start(ADDRESS + CODE_OFFSET, ADDRESS+CODE_OFFSET + CODE_SIZE)
    print("emulate over!!!")
    print_arm64_regs(mu)
```

上面的代码模拟了 arm64 的代码传递两个参数的过程。

### 模拟 libc 函数

```python
import struct
import capstone
import unicorn

def print_arm64_regs(mu):
    regs = [
        "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7",
        "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15",
        "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23",
        "X24", "X25", "X26", "X27", "X28", "X29", "X30", "SP", "PC"
    ]
    count = 0
    output = ''
    for reg in regs:
        val = mu.reg_read(getattr(unicorn.arm64_const, f"UC_ARM64_REG_{reg}"))
        if count < 8:
            output +=f"{reg} = 0x{val:x}\t"
            count += 1
        else:
            output += f"\n{reg} = 0x{val:x}\t"
            count = 0
    print(output)

def readstring(mu:unicorn,address:int):
    result=''
    tmp=mu.mem_read(address,1)
    while(tmp[0]!=0):
        result=result+chr(tmp[0])
        address=address+1
        tmp = mu.mem_read(address, 1)
    return result

def hook_code_args_stack(mu:unicorn, address:int, size:int, user_data:int):
    code = mu.mem_read(address, size)
    if address == 0x9C0:
        # 模拟 strcmp 函数
        x0 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X0)
        x0value = readstring(mu, x0)
        x1 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X1)
        print(f"x0 = 0x{x0:08X}, x0value = {x0value}")
        x1value = readstring(mu, x1)
        print(f"x1= 0x{x1:08X}, x1value= {x1value}")
        if x0value == x1value:
            mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0, 0)
        else:
            mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0, 1)

    CP = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for i in CP.disasm(code, 0, size):
        print(f"0x{address:08X}: {i.mnemonic}: {i.op_str}")
    # print_arm64_regs(mu)


def test_arm64_args_stack():
    CODE_OFFSET = 0x960
    CODE_SIZE = 0xA60 - 0x960
    CODE = None
    with open("so/libuniron.so", "rb") as f:
        CODE = f.read()
    # 使用 Capstone 反汇编 add 代码, add 地址为 24FF0
    CP = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for i in CP.disasm(CODE[CODE_OFFSET:CODE_OFFSET+CODE_SIZE], 0, CODE_SIZE):
        address = i.address + CODE_OFFSET
        print(f"0x{address:08X}: {i.mnemonic}: {i.op_str}")
    print("="*80)
    # 开始模拟执行
    mu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    ADDRESS = 0
    SIZE = 10*1024*1024
    # 映射内存并将代码写入内存
    mu.mem_map(ADDRESS, SIZE)
    mu.mem_write(ADDRESS, CODE)
    # patch 掉 bl strcmp
    mu.mem_write(ADDRESS + 0x9C0, b'\x1F\x20\x03\xD5')
    # 传参
    mu.mem_write(ADDRESS + 10, b"add")
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W0, ADDRESS + 10)
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W1, 0x1)
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W2, 0x2)
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W3, 0x3)
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W4, 0x4)
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W5, 0x5)
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W6, 0x6)
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_W7, 0x7)
    # 使用栈传参数
    SP = ADDRESS + SIZE - 0x64
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, SP)
    mu.mem_write(SP, struct.pack('I', 10))
    mu.mem_write(SP+8, struct.pack('I', 9))
    mu.mem_write(SP+16, struct.pack('I', 8))
    mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_LR, ADDRESS+0x100)
    # 添加 hook
    mu.hook_add(unicorn.UC_HOOK_CODE, hook_code_args_stack)

    # 开始模拟执行
    mu.emu_start(ADDRESS + CODE_OFFSET, ADDRESS+CODE_OFFSET+CODE_SIZE)
    print("emulate over!!!")
    print_arm64_regs(mu)

if __name__ == '__main__':
    test_arm64_args_stack()
```

上面的代码模拟了 libc 中的 `strcmp` 函数，首先 `NOP` 掉调用 `strcmp` 函数的指令，当执行到该地址时，模拟 `strcmp` 的功能，并将返回值写入 X0 中，这样就完成了模拟了 `strcmp` 函数。

### 模拟 jni 函数

Java Native Interface（JNI）是 Java 提供的一种标准接口，允许 Java 代码与本地代码（如 C/C++）进行交互。通过 JNI，Java 可以调用本地方法，本地代码也可以访问 Java 对象和类。

JNI 函数的模拟，首先需要了解 JNI 函数的定义方式，JNI 函数的第一个参数是 `JNIEnv` 指针，通过这个指针可以访问 JNI 提供的所有函数来操作 Java 对象、调用方法、处理异常等；第二个参数是 `jobject` 指针，就是调用这个函数的对象；其他参数是函数的参数。

`JNIEnv` 的本质是一个 指向 JNI 函数表的指针结构体 ，它封装了 JVM 提供给本地代码（C/C++）的一系列接口函数。模拟 JNI 函数的调用，首先就需要模拟这个结构体以及对应的函数。该结构体实际为 [JNINativeInterface](https://android.googlesource.com/platform/development/+/3598d53/ndk/platforms/android-3/include/jni.h#164) 结构体。

除了 JNIEnv 结构体，还需要模拟 JavaVM 结构体，该结构体实际为 [JNIInvokeInterface](https://android.googlesource.com/platform/development/+/3598d53/ndk/platforms/android-3/include/jni.h#1069) 结构体。

```python
import struct
import capstone
import unicorn

def readstring(mu:unicorn,address:int):
    result=''
    tmp=mu.mem_read(address,1)
    while(tmp[0]!=0):
        result=result+chr(tmp[0])
        address=address+1
        tmp = mu.mem_read(address, 1)
    return result

def hook_code_jni(mu:unicorn, address:int, size:int, user_data:int):
    code = mu.mem_read(address, size)
    CP = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    for i in CP.disasm(code, 0, size):
        print(f"0x{address:08X}: {i.mnemonic}: {i.op_str}")

    if address >= 0 and address <= 300*8:
        index = address // 8
        print(f"call jnienv function 0x{address:08X}: {index}")
        if index == 6:
            print("call FindClass:")
            # jclass (*FindClass)(JNIEnv*, const char*);
            x1 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X1)
            classname = readstring(mu, x1)
            print(f"jnienv FindClass {classname}")
            mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0, 123)
        elif index == 215:
            # jint (*RegisterNatives)(JNIEnv*, jclass, const JNINativeMethod*,jint);
            print("jnienv RegisterNatives:")
            x0 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X0)
            x1 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X1)
            x2 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X2)
            x3 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X3)
            print(f"jnienv = {x0:08X}, jclass = {x1}, gMethods = {x2:08X}, gMethods_size = {x3}")
            # 设置返回值
            mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0, 0)
        elif index == 169:
            # const char* (*GetStringUTFChars)(JNIEnv*, jstring, jboolean*);
            print("call GetStringUTFChars")
            x0 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X0)
            x1 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X1)
            x2 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X2)
            content = readstring(mu, x1)
            print(f"jnienv GetStringUTFChars {content}")
            mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0, x1)
        elif index == 170:
            # void (*ReleaseStringUTFChars)(JNIEnv*, jstring, const char*);
            print("call ReleaseStringUTFChars")
            x0 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X0)
            x1 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X1)
            x2 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X2)
            content = readstring(mu, x2)
            print(f"jnienv ReleaseStringUTFChars {content}")
        elif index == 167:
            # jstring (*NewStringUTF)(JNIEnv*, const char*);
            print("call NewStringUTF------------------")
            x0 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X0)
            x1 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X1)
            content = readstring(mu, x1)
            mu.reg_write(unicorn.arm_const.UC_ARM_REG_R0, x1)
            print(f"jnienv NewStringUTF----{content}")
        else:
            mu.emu_stop()
    elif address >= 700*8 and address <= 710*8:
        index = (address - 700*8) // 8
        print(f"call javaVM function 0x{address:08X}: {index}")
        if index == 6:
            print("call javaVM GetEnv function")
            x1 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X1)
            x30 = mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_X30)
            print(f"r1 = 0x{x1:08X}, x30 = 0x{x30:08X}")
            # jint (*GetEnv)(JavaVM*, void**, jint);
            # 写入 jnienv
            mu.mem_write(x1, struct.pack('q', 600 * 8))
            # 写入返回值
            mu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0, 0)


def test_arm64_jni():

    with open("so/libuniron.so", "rb") as f:
        CODE = f.read()
    emu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    JNIFUNCTION_ADDRESS = 0x0
    JNIFUNCTION_SIZE = 0x1000*4
    emu.mem_map(JNIFUNCTION_ADDRESS, JNIFUNCTION_SIZE)
    # 设置 JNIEnv 结构
    # 首先填充函数体
    for i in range(0, 300):
        # 写入 ret 指令
        emu.mem_write(i*8, b'\xC0\x03\x5F\xD6\xC0\x03\x5F\xD6')
    # 填充JNIEnv函数指针
    for i in range(300, 600):
        emu.mem_write(i*8, struct.pack("q",(i-300)*8))
    data = emu.mem_read(300*8, 300*8)
    # 初始化 jnienv 指针
    jnienv_pointer = 600 * 8
    emu.mem_write(jnienv_pointer, struct.pack("q", 300*8))

    ADDRESS = JNIFUNCTION_ADDRESS + JNIFUNCTION_SIZE
    SIZE = 10*0x1000
    emu.mem_map(ADDRESS, SIZE)
    emu.mem_write(ADDRESS, CODE)

    # 写入 JNIEnv
    emu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0, jnienv_pointer)
    emu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X1, 0)
    emu.mem_write(jnienv_pointer + 8, b"hello")
    emu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X2, jnienv_pointer + 8)
    # 将 .__android_log_print patch 为 ret 
    emu.mem_write(ADDRESS+0xE1C, b"\xC0\x03\x5F\xD6")
    SP = ADDRESS + SIZE - 1024
    emu.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, SP)
    emu.hook_add(unicorn.UC_HOOK_CODE, hook_code_jni)

    START_ADDRESS = ADDRESS + 0xACC
    END_ADDRESS = START_ADDRESS + 0xB3C
    emu.emu_start(START_ADDRESS, END_ADDRESS)

def test_arm64_jni_onload():
    with open("so/libuniron.so", "rb") as f:
        CODE = f.read()
    emu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    JNIFUNCTION_ADDRESS = 0x0
    JNIFUNCTION_SIZE = 0x1000*4
    emu.mem_map(JNIFUNCTION_ADDRESS, JNIFUNCTION_SIZE)
    # 设置 JNIEnv 结构
    # 首先填充函数体
    for i in range(0, 300):
        # 写入 ret 指令
        emu.mem_write(i*8, b'\xC0\x03\x5F\xD6\xC0\x03\x5F\xD6')
    # 填充JNIEnv函数指针
    for i in range(300, 600):
        emu.mem_write(i*8, struct.pack("q",(i-300)*8))
    # 初始化 jnienv 指针
    jnienv_pointer = 600 * 8
    emu.mem_write(jnienv_pointer, struct.pack("q", 300*8))

    # 设置 javaVM 结构
    for i in range(700, 710):
        emu.mem_write(i*8, b'\xC0\x03\x5F\xD6\xC0\x03\x5F\xD6')
    for i in range(710, 720):
        emu.mem_write(i*8, struct.pack("q",(i-10)*8))

    javavm_pointer = 720*8
    emu.mem_write(javavm_pointer, struct.pack("q", 710*8))
    ADDRESS = JNIFUNCTION_ADDRESS + JNIFUNCTION_SIZE
    SIZE = 10*0x1000
    emu.mem_map(ADDRESS, SIZE)
    emu.mem_write(ADDRESS, CODE)

    # 写入 javavm
    emu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X0, javavm_pointer)
    emu.reg_write(unicorn.arm64_const.UC_ARM64_REG_X1, 0)

    SP = ADDRESS + SIZE - 1024
    emu.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, SP)
    emu.hook_add(unicorn.UC_HOOK_CODE, hook_code_jni)

    START_ADDRESS = ADDRESS + 0xBEC
    END_ADDRESS = START_ADDRESS + 0xCEC
    emu.emu_start(START_ADDRESS, END_ADDRESS)

if __name__ == '__main__':
    print("JNI emulate start!")
    test_arm64_jni()
    print("JNI emulate DONE!")
    print("Jni_Onload emulate start!")
    test_arm64_jni_onload()
    print("Jni_Onload emulate DONE!")
```
上面的代码就模拟了 jni 函数和 jni_onload 函数的调用。

## 