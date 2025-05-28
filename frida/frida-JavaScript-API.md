# JavaScript API

## 开始使用

为了提高效率，我们强烈推荐使用我们的 TypeScript 绑定。这样可以获得代码补全、类型检查、内联文档、重构工具等功能。

克隆[这个仓库](https://github.com/oleavr/frida-agent-example)以开始使用。

# Runtime information

## Frida

### Frida.version

一个属性，包含当前 Frida 版本的字符串。

### Frida.heapSize

一个动态属性，包含 Frida 私有堆的当前大小，所有脚本和 Frida 的运行时共享这个堆。这个属性有助于监控您的代码在宿主进程中消耗的总内存中，仪器占用了多少内存。

## Script

### Script.runtime

一个字符串属性，包含正在使用的运行时。值可以是 `QJS` 或 `V8`。

### Script.pin()

临时防止当前脚本被卸载。这个操作是引用计数的，因此必须在稍后执行一个匹配的 `unpin()` 操作。通常在 `bindWeak()` 的回调中使用，当您需要在另一个线程上安排清理时。

### Script.unpin()

撤销之前的 `pin()` 操作，使当前脚本可以被卸载。

### Script.bindWeak(value, fn)

监控 `value` 并在 `value` 被垃圾回收或脚本即将被卸载时调用 `fn` 回调。返回一个 `ID`，您可以将其传递给 `Script.unbindWeak()` 进行显式清理。

这个 API 对于构建语言绑定非常有用，当一个 JS 值不再需要时，您需要释放本地资源。

### Script.unbindWeak(id)

停止监控传递给 `Script.bindWeak(value, fn)` 的值，并立即调用 `fn` 回调。

### Script.setGlobalAccessHandler(handler | null)

安装或卸载用于解析访问不存在的全局变量的处理程序。对于实现一个 `REPL` 非常有用，在这个 `REPL` 中，未知标识符可以从数据库中懒加载。

处理程序是一个包含两个属性的对象：

- `enumerate()`: 查询哪些附加的全局变量存在。必须返回一个字符串数组。
- `get(property)`: 检索给定属性的值。

# Process, Thread, Module and Memory

## Process 对象属性和方法

### Process.id

包含当前进程的 PID（进程标识符），类型为数字。

### Process.arch

包含当前进程的架构，可能的值有 `ia32`, `x64`, `arm` 或 `arm64`。

### Process.platform

包含当前进程的操作系统平台，可能的值有 windows, darwin, linux 或 qnx。

### Process.pageSize

包含虚拟内存页的大小（以字节为单位），类型为数字。用于提高脚本的可移植性。

### Process.pointerSize

包含指针的大小（以字节为单位），类型为数字。用于提高脚本的可移植性。

### Process.codeSigningPolicy

包含字符串 `optional` 或 `required`，表示代码签名策略。`required` 表示 Frida 避免修改内存中的现有代码，并且不会尝试运行未签名的代码。当前此属性始终设置为 `optional`，除非使用 `Gadget` 并配置为需要代码签名。该属性允许确定是否可以使用 Interceptor API，以及是否可以安全地修改代码或运行未签名代码。

### Process.mainModule

包含代表进程主可执行文件的 `Module` 对象。

### Process.getCurrentDir()

返回一个字符串，指定当前工作目录的文件系统路径。

### Process.getHomeDir()

返回一个字符串，指定当前用户主目录的文件系统路径。

### Process.getTmpDir()

返回一个字符串，指定用于临时文件的目录的文件系统路径。

### Process.isDebuggerAttached()

返回一个布尔值，指示是否当前有调试器附加。

### Process.getCurrentThreadId()

获取当前线程的 OS 特定 ID，类型为数字。

### Process.enumerateThreads()

枚举所有线程，返回一个对象数组，每个对象包含以下属性：

- `id`: OS 特定的 ID。
- `state`: 一个字符串，可能的值有 running, stopped, waiting, uninterruptible 或 halted。
- `context`: 包含键 pc 和 sp 的对象，它们是 [NativePointer](#nativepointer) 对象，分别指定 `EIP/RIP/PC` 和 `ESP/RSP/SP`，其他处理器特定的键也可用，例如 eax, rax, r0, x0 等。

### Process.xxModuleByxx(address)

- Process.findModuleByAddress(address)
- Process.getModuleByAddress(address)
- Process.findModuleByName(name)
- Process.getModuleByName(name)

返回一个地址或名称匹配的 `Module` 对象。如果找不到这样的模块，`find` 前缀的方法返回 `null`，而 `get` 前缀的方法抛出异常。

### Process.enumerateModules()

枚举当前加载的模块，返回一个 Module 对象数组。

### Process.xxRangeByAddress(address)

- Process.findRangeByAddress(address)
- Process.getRangeByAddress(address)

返回包含地址的内存范围的详细信息对象。如果找不到这样的范围，`findRangeByAddress()` 返回 `null`，而 `getRangeByAddress()` 抛出异常。有关包含的字段的详细信息，请参阅 [Process.enumerateRanges()](#Process.enumerateRanges())。

### Process.enumerateRanges(protection|specifier)

枚举满足保护条件的内存范围，保护条件可以是形如 `rwx` 的字符串，其中 `rw-` 表示“必须至少可读和可写”。或者，可以提供一个包含保护键（其值如上述所述）和合并键（如果您希望将具有相同保护的相邻范围合并，则设置为 `true`，默认值为 `false`，即保持范围分开）的指定符对象。返回一个包含以下属性的对象数组：

- `base`: 基址，类型为 `[NativePointer](#nativepointer)`。
- `size`: 大小，以字节为单位。
- `protection`: 保护字符串（见上文）。
- `file`: （如果可用）文件映射详细信息，包含以下属性的对象：
  - `path`: 完整的文件系统路径，类型为字符串。
  - `offset`: 在磁盘上映射文件中的偏移量，以字节为单位。
  - `size`: 在磁盘上映射文件中的大小，以字节为单位。

### Process.enumerateMallocRanges()

类似于 `enumerateRanges()`，但针对系统堆中已知的各个内存分配。

### Process.setExceptionHandler(callback)

安装一个进程范围的异常处理程序回调，在宿主进程处理之前处理本地异常。回调函数接收一个参数 `details`，它是一个包含以下属性的对象：

- `type`: 一个字符串，可能的值有：
  - `abort`
  - `access-violation`
  - `guard-page`
  - `illegal-instruction`
  - `stack-overflow`
  - `arithmetic`
  - `breakpoint`
  - `single-step`
  - `system`
- `address`: 发生异常的地址，类型为 `[NativePointer](#nativepointer)`。
- `memory`: 如果存在，是一个对象，包含以下属性：
  - `operation`: 触发异常的操作类型，类型为字符串，可能的值有 `read`, `write` 或 `execute`。
  - `address`: 发生异常时访问的地址，类型为 `[NativePointer](#nativepointer)`。
- `context`: 包含键 `pc` 和 `sp` 的对象，它们是 `[NativePointer](#nativepointer)` 对象，分别指定 `EIP/RIP/PC` 和 `ESP/RSP/SP`，其他处理器特定的键也可用，例如 `eax, rax, r0, x0` 等。您还可以通过分配给这些键来更新寄存器值。
- `nativeContext`: OS 和架构特定的 CPU 上下文结构体的地址，类型为 `[NativePointer](#nativepointer)`。这仅在上下文不提供足够细节的边缘情况下作为最后的手段公开。不过，我们不鼓励使用此功能，而是建议提交 pull-request 以添加您的用例所需的缺失部分。

您的回调负责决定如何处理异常。它可以记录问题，通过 `send()` 通知您的应用程序，然后通过阻塞 `recv()` 确认接收到的数据，或者可以修改寄存器和内存以从异常中恢复。如果您确实处理了异常，则应返回 `true`，此时 Frida 将立即恢复线程。如果您不返回 `true`，Frida 将把异常转发给宿主进程的异常处理程序（如果有），或者让操作系统终止进程。

## Thread 对象方法

### Thread.backtrace([context, backtracer])

为当前线程生成一个回溯数组，返回 `[NativePointer](#nativepointer)` 对象数组。

- `context`: 可选参数，如果在 `Interceptor` 的 `onEnter` 或 `onLeave` 回调中调用此方法，应该提供 `this.context` 参数，以获得更准确的回溯。省略 `context` 意味着回溯将从当前堆栈位置生成，这可能由于 JavaScript VM 的堆栈帧而无法提供非常好的回溯。
- `backtracer`: 可选参数，指定要使用的回溯器类型，必须是 `Backtracer.FUZZY` 或 `Backtracer.ACCURATE`，如果未指定，则默认使用后者。准确的回溯器依赖于调试器友好的二进制文件或调试信息，而模糊的回溯器通过对堆栈进行取证来猜测返回地址，这意味着可能会有误报，但适用于任何二进制文件。生成的回溯目前限制为 16 帧，不可调节，除非重新编译 Frida。

```javascript
const f = Module.getExportByName("libcommonCrypto.dylib", "CCCryptorCreate");
Interceptor.attach(f, {
  onEnter(args) {
    console.log(
      "CCCryptorCreate called from:\n" +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
          .map(DebugSymbol.fromAddress)
          .join("\n") +
        "\n"
    );
  },
});
```

### Thread.sleep(delay)

暂停当前线程执行，延迟时间由 `delay` 指定，以秒为单位。例如，0.05 表示暂停 50 毫秒。

## Module 对象

由 `Module.load()` 和 `Process.enumerateModules()` 返回的对象。

### Module.name

模块名称，类型为字符串。

### Module.base

基地址，类型为 [NativePointer](#nativepointer)。

### Module.size

大小，以字节为单位。

### Module.path

完整的文件系统路径，类型为字符串。

### Module.enumerateImports()

枚举模块的导入，返回一个对象数组，每个对象包含以下属性：

- `type`: 字符串，指定导入类型，可以是 `function` 或 `variable`。
- `name`: 导入名称，类型为字符串。
- `module`: 模块名称，类型为字符串。
- `address`: 绝对地址，类型为 `[NativePointer](#nativepointer)`。
- `slot`: 导入存储的位置，类型为 `[NativePointer](#nativepointer)`。

### Module.enumerateExports()

枚举模块的导出，返回一个对象数组，每个对象包含以下属性：

- `type`: 字符串，指定导出类型，可以是 `function` 或 `variable`。
- `name`: 导出名称，类型为字符串。
- `address`: 绝对地址，类型为 `[NativePointer](#nativepointer)`。

### Module.enumerateSymbols()

枚举模块的符号，仅在 macOS 和基于 Linux 的操作系统上可用，返回一个对象数组，每个对象包含以下属性：

- `isGlobal`: 布尔值，指定符号是否全局可见。
- `type`: 字符串，指定符号类型，可以是 `unknown, section, undefined, absolute, prebound-undefined, indirect, object, function, file, common, tls`。
- `section`: 如果存在，是一个对象，包含以下属性：
  - `id`: 字符串，包含节索引、段名（如果适用）和节名。
  - `protection`: 保护类型，类似于 `Process.enumerateRanges()`。
- `name`: 符号名称，类型为字符串。
- `address`: 绝对地址，类型为 `[NativePointer](#nativepointer)`。
- `size`: 如果存在，是一个数字，指定符号的大小，以字节为单位。

### Module.enumerateRanges(protection)

类似于 `Process.enumerateRanges`，但作用域限制为模块。

### Module.enumerateSections()

枚举模块的节，返回一个对象数组，每个对象包含以下属性：

- `id`: 字符串，包含节索引、段名（如果适用）和节名。
- `name`: 节名，类型为字符串。
- `address`: 绝对地址，类型为 `[NativePointer](#nativepointer)`。
- `size`: 大小，以字节为单位。

### Module.enumerateDependencies()

枚举模块的依赖项，返回一个对象数组，每个对象包含以下属性：

- `name`: 模块名称，类型为字符串。
- `type`: 字符串，指定依赖项类型，可以是 `regular, weak, reexport, upward`。

### Module.xxExportByName(exportName)

- findExportByName(exportName)
- getExportByName(exportName)

返回指定导出名称的绝对地址。如果找不到这样的导出，`findExportByName()` 返回 `null`，而 `getExportByName()` 抛出异常。

### Module.load(path)

从文件系统路径加载指定模块并返回一个 `Module` 对象。如果无法加载指定模块，则抛出异常。

### Module.ensureInitialized(name)

确保指定模块的初始化程序已运行。这在早期检测期间非常重要，即在进程生命周期的早期运行代码，以便能够安全地与 API 交互。一个这样的用例是与给定模块提供的 ObjC 类进行交互。

### Module.xxBaseAddress(name)

- Module.findBaseAddress(name)
- Module.getBaseAddress(name)

返回指定模块的基地址。如果找不到这样的模块，`findBaseAddress()` 返回 `null`，而 `getBaseAddress()` 抛出异常。

### Module.xxExportByName()

- Module.findExportByName(moduleName|null, exportName)
- Module.getExportByName(moduleName|null, exportName)

返回模块中指定导出名称的绝对地址。如果模块未知，可以传递 `null` 作为模块名称，但这可能是一种代价高昂的搜索，应该避免。如果找不到这样的模块或导出，`findExportByName()` 返回 `null`，而 `getExportByName()` 抛出异常。

## ModuleMap 对象

ModuleMap 对象用于优化确定给定内存地址属于哪个模块（如果有的话）。在创建时，它会对当前加载的模块进行快照，可以通过调用 update() 方法来刷新。可选的 filter 参数允许传递一个函数，用于过滤模块列表。

### new ModuleMap([filter])

`filter`: 可选参数，传递一个函数用于过滤模块列表。该函数接收一个 `Module` 对象，并对应每个模块返回 `true` 表示保留在映射中。每次更新映射时，都会对每个加载的模块调用该函数。

### ModuleMap.has(address)

检查地址是否属于任何包含的模块，并返回布尔值结果。

```javascript
const isModule = moduleMap.has(ptr("0x12345678"));
```

### ModuleMap.find|get(address)

- find(address)
- get(address)

返回包含地址的模块的详细信息。若未找到相应模块，`find()` 返回 `null`，而 `get()` 抛出异常。

```javascript
const module = moduleMap.find(ptr("0x12345678"));
```

### ModuleMap.find|getName(address),

- findName(address)
- getName(address)

类似于 `find()` 和 `get()`，但仅返回模块的 `name` 字段，减少开销。

```javascript
const moduleName = moduleMap.findName(ptr("0x12345678"));
```

### ModuleMap.find|getPath(address)

- findPath(address)
- getPath(address)

类似于 `find()` 和 `get()`，但仅返回模块的 `path` 字段，减少开销。

```javascript
const modulePath = moduleMap.findPath(ptr("0x12345678"));
```

### ModuleMap.update()

更新映射。在模块加载或卸载后调用此方法以避免操作过时数据。

```javascript
moduleMap.update();
```

### ModuleMap.values()

返回当前映射中的模块对象数组。返回的数组是深拷贝，调用 update() 后不会发生变化。

```javascript
const modules = moduleMap.values();
```

使用示例

```javascript
// 创建一个新的 ModuleMap，只包含应用程序拥有的模块
const appModuleMap = new ModuleMap(
  (module) => module.path.indexOf("/app/") !== -1
);

// 检查某个地址是否属于任何模块
const isInModule = appModuleMap.has(ptr("0x12345678"));

// 获取包含某个地址的模块
const module = appModuleMap.find(ptr("0x12345678"));
if (module !== null) {
  console.log(`Address belongs to module: ${module.name}`);
} else {
  console.log("Address does not belong to any module in the map.");
}

// 更新映射
appModuleMap.update();

// 获取当前映射中的所有模块
const modules = appModuleMap.values();
modules.forEach((module) => {
  console.log(`Module: ${module.name}, Path: ${module.path}`);
});
```

通过上述方法和示例，可以高效地使用 ModuleMap 对象来管理和查询内存地址与模块的关系。

## Memory 对象

Memory 对象提供了内存操作的各种方法，包括扫描、分配、复制、保护等。

### Memory.scan(address, size, pattern, callbacks)

在指定的内存范围内扫描模式的出现。

```javascript
const pattern = "00 00 00 00 ?? 13 37 ?? 42";
Memory.scan(m.base, m.size, pattern, {
  onMatch(address, size) {
    console.log("Memory.scan() found match at", address, "with size", size);
    return "stop"; // 可选：提早停止扫描
  },
  onComplete() {
    console.log("Memory.scan() complete");
  },
});
```

### Memory.scanSync(address, size, pattern)

`scan()` 的同步版本，返回一个包含匹配结果的对象数组。

```javascript
const results = Memory.scanSync(m.base, m.size, pattern);
console.log("Memory.scanSync() result:\n" + JSON.stringify(results));
```

### Memory.alloc(size[, options])

在堆上分配指定大小的内存，或如果大小是 `Process.pageSize` 的倍数，则分配由操作系统管理的一个或多个原始内存页面。

```javascript
const ptr = Memory.alloc(64); // 分配64字节内存
```

### Memory.copy(dst, src, n)

类似于 `memcpy()`。不返回任何值。

```javascript
Memory.copy(ptr("0x1234"), ptr("0x5678"), 16);
```

### Memory.dup(address, size)

`Memory.alloc()` 和 `Memory.copy()` 的简写。返回分配内存的基地址。

```javascript
const newPtr = Memory.dup(ptr("0x1234"), 16);
```

### Memory.protect(address, size, protection)

更新指定内存区域的保护。返回布尔值，表示操作是否成功。

```javascript
const success = Memory.protect(ptr("0x1234"), 4096, "rw-");
```

### Memory.patchCode(address, size, apply)

安全地修改指定地址的 `size` 字节。`apply` 函数获得一个可写指针，在返回前必须写入所需的修改。

```javascript
const getLivesLeft = Module.getExportByName("game-engine.so", "get_lives_left");
const maxPatchSize = 64;
Memory.patchCode(getLivesLeft, maxPatchSize, (code) => {
  const cw = new X86Writer(code, { pc: getLivesLeft });
  cw.putMovRegU32("eax", 9000);
  cw.putRet();
  cw.flush();
});
```

### Memory.allocxxString(str)

- Memory.allocUtf8String(str)
- Memory.allocUtf16String(str)
- Memory.allocAnsiString(str)

分配、编码并写入字符串到堆。返回一个 `[NativePointer](#nativepointer)`。

```javascript
const utf8Str = Memory.allocUtf8String("Hello, world!");
```

使用示例

```javascript
// 创建一个新的 ModuleMap，只包含应用程序拥有的模块
const appModuleMap = new ModuleMap(
  (module) => module.path.indexOf("/app/") !== -1
);

// 检查某个地址是否属于任何模块
const isInModule = appModuleMap.has(ptr("0x12345678"));

// 获取包含某个地址的模块
const module = appModuleMap.find(ptr("0x12345678"));
if (module !== null) {
  console.log(`Address belongs to module: ${module.name}`);
} else {
  console.log("Address does not belong to any module in the map.");
}

// 更新映射
appModuleMap.update();

// 获取当前映射中的所有模块
const modules = appModuleMap.values();
modules.forEach((module) => {
  console.log(`Module: ${module.name}, Path: ${module.path}`);
});

// 内存扫描示例
const pattern = "00 00 00 00 ?? 13 37 ?? 42";
Memory.scan(m.base, m.size, pattern, {
  onMatch(address, size) {
    console.log("Memory.scan() found match at", address, "with size", size);
    return "stop"; // 可选：提早停止扫描
  },
  onComplete() {
    console.log("Memory.scan() complete");
  },
});

const results = Memory.scanSync(m.base, m.size, pattern);
console.log("Memory.scanSync() result:\n" + JSON.stringify(results));

// 内存分配和修改示例
const ptr = Memory.alloc(64);
const success = Memory.protect(ptr, 64, "rw-");
if (success) {
  console.log("Memory protection updated successfully");
}
```

通过上述方法和示例，可以高效地使用 `ModuleMap` 和 `Memory` 对象来管理和操作内存地址与模块的关系。

## MemoryAccessMonitor 对象

`MemoryAccessMonitor` 对象用于监视一个或多个内存范围的访问，并在每个包含的内存页面的第一次访问时通知。
方法

### MemoryAccessMonitor.enable(ranges, callbacks)

监视一个或多个内存范围的访问。

- `ranges`: 单个范围对象或范围对象的数组。每个范围对象包含：

  - `base`: 基地址，类型为 `[NativePointer](#nativepointer)`
  - `size`: 大小，以字节为单位

- `callbacks`: 一个对象，指定以下回调：
  - `onAccess(details)`: 在访问时同步调用，`details` 对象包含：
    - `operation`: 触发访问的操作类型，字符串格式（`read`、`write` 或 `execute`）
    - `from`: 执行访问的指令地址，类型为 `[NativePointer](#nativepointer)`
    - `address`: 被访问的地址，类型为 `[NativePointer](#nativepointer)`
    - `rangeIndex`: 被访问的范围在提供给 `MemoryAccessMonitor.enable()` 的范围中的索引
    - `pageIndex`: 被访问的内存页面在指定范围内的索引
    - `pagesCompleted`: 到目前为止已访问的页面总数（不再被监视）
    - `pagesTotal`: 最初监视的页面总数

```javascript
const ranges = [
  { base: ptr("0x12340000"), size: 0x1000 },
  { base: ptr("0x56780000"), size: 0x2000 },
];

MemoryAccessMonitor.enable(ranges, {
  onAccess(details) {
    console.log("Memory access detected:", details);
  },
  onComplete() {
    console.log("Memory monitoring complete");
  },
});
```

### MemoryAccessMonitor.disable()

停止监视传递给 `MemoryAccessMonitor.enable()` 的剩余内存范围。

```javascript
MemoryAccessMonitor.disable();
```

## CModule 对象

### new CModule(code[, symbols, options])

创建一个新的 C 模块。这个模块可以从提供的 `code` 创建,`code` 可以是包含 C 源代码的字符串,也可以是包含预编译共享库的 `ArrayBuffer`。C 模块会被映射到内存中,并对 JavaScript 完全可访问。

这个功能在实现热回调时很有用,比如用于 `Interceptor` 和 `Stalker`。当需要启动新线程以在紧密循环中调用函数时也很有用,例如用于模糊测试(fuzzing)。

全局函数会自动导出为 `[NativePointer](#nativepointer)` 属性,名称与 C 源代码中完全一致。这意味着你可以将它们传递给 `Interceptor` 和 `Stalker`,或者使用 `[NativePointer](#nativepointer)` 调用它们。

除了访问 Gum、GLib 和标准 C API 的精选子集外,被映射的代码还可以通过暴露给它的 `symbols` 与 JavaScript 通信。这是可选的第二个参数,一个对象,指定额外的符号名称及其 `[NativePointer](#nativepointer)` 值,每个都会在创建时被插入。这可能是使用 `Memory.alloc()` 分配的一个或多个内存块,和/或用于接收来自 C 模块回调的 NativeCallback 值。

要执行初始化和清理,你可以定义具有以下名称和签名的函数:

`void init (void)`
`void finalize (void)`

注意,所有数据都是只读的,所以可写的全局变量应该声明为 extern,使用例如 **Memory.alloc()** 分配,并通过构造函数的第二个参数作为符号传入。

可选的第三个参数 options 是一个对象,可用于指定使用哪个工具链,例如: { toolchain: 'external' }。支持的值有:

- `internal`: 使用 TinyCC,它静态链接到运行时。从不触及文件系统,即使在沙盒进程中也能工作。然而生成的代码没有优化,因为 TinyCC 优化的是小型编译器占用空间和短编译时间。
- `external`: 使用目标系统提供的工具链,假设它对我们执行所在的进程可访问。
- `any`: 如果 Process.arch 被 TinyCC 支持则等同于 internal,否则等同于 external。如果未指定,这是默认行为。

### CModule.dispose()

立即解除模块在内存中的映射。这在模块的生命周期较短且不希望等待垃圾回收时特别有用。

```javascript
cm.dispose();
```

### builtins

`builtins` 是一个对象，用于在从 C 源代码构建 `CModule` 时指定内置项。通常由像 `frida-create` 这样的脚手架工具使用，以设置与 `CModule` 使用的构建环境相匹配的环境。其具体内容依赖于 `Process.arch` 和 `Frida` 版本，但可能包含如下内容：

- `defines`: 一个对象，包含了一些预定义的宏和它们的值。
- `headers`: 一个对象，包含了文件路径和它们的内容，用于在构建时包含必要的头文件。

```c
{
  defines: {
    'GLIB_SIZEOF_VOID_P': '8',
    'G_GINT16_MODIFIER': '"h"',
    'G_GINT32_MODIFIER': '""',
    'G_GINT64_MODIFIER': '"ll"',
    'G_GSIZE_MODIFIER': '"l"',
    'G_GSSIZE_MODIFIER': '"l"',
    'HAVE_I386': true
  },
  headers: {
    'gum/arch-x86/gumx86writer.h': '…',
    'gum/gumdefs.h': '…',
    'gum/guminterceptor.h': '…',
    'gum/gummemory.h': '…',
    'gum/gummetalarray.h': '…',
    'gum/gummetalhash.h': '…',
    'gum/gummodulemap.h': '…',
    'gum/gumprocess.h': '…',
    'gum/gumspinlock.h': '…',
    'gum/gumstalker.h': '…',
    'glib.h': '…',
    'json-glib/json-glib.h': '…',
    'capstone.h': '…'
  }
}
```

以下是如何使用 Frida 创建和使用一个 C 模块（CModule）的示例：

```javascript
const cm = new CModule(`
#include <stdio.h>
void hello(void) {
  printf("Hello World from CModule\\n");
}
`);
// 创建指向 C 函数的 JavaScript 函数
const hello = new NativeFunction(cm.hello, "void", []);
// 调用 C 函数
hello();
```

可以使用 Frida 的 `REPL` 来加载这个脚本：

```bash
$ frida -p 0 -l example.js
```

REPL 会监视文件，并在文件更改时重新加载脚本。

然后，你可以在 REPL 中输入 `hello()` 来调用这个 C 函数。

为了进行原型开发，我们推荐使用 `Frida REPL` 的内置 `CModule` 支持：

```bash
$ frida -p 0 -C example.c
```

你也可以添加 `-l example.js` 来加载一些 JavaScript 代码。JavaScript 代码可以使用全局变量 `cm` 来访问 `CModule` 对象，但只能在 `rpc.exports.init()` 被调用之后。所以，请在此处执行任何依赖于 `CModule` 的初始化。你也可以通过赋值给全局对象 `cs` 来注入符号，但这必须在 `rpc.exports.init()` 被调用之前完成。

![](frida-JavaScript-API/2024-07-30-16-52-53.png)

详细信息可以在 [Frida 12.7 发行说明](https://frida.re/news/2019/09/18/frida-12-7-released/) 中找到。

## ApiResolver 对象

## new ApiResolver(type)

`ApiResolver` 是一个强大的工具，允许你通过名称快速查找 API，并允许使用通配符。具体可用的解析器取决于当前平台和当前进程中加载的运行时环境。当前可用的解析器有：

- `module`: 解析模块的导出、导入和部分内容。总是可用。
- `swift`: 解析 `Swift` 函数。在加载了 `Swift` 运行时的进程中可用。可以使用 `Swift.available` 在运行时检查，或者在 `new ApiResolver('swift')` 调用时使用 `try-catch` 包装。
- `objc`: 解析 `Objective-C` 方法。在 macOS 和 iOS 上，在加载了 `Objective-C` 运行时的进程中可用。可以使用 `ObjC.available` 在运行时检查，或者在 `new ApiResolver('objc')` 调用时使用 `try-catch` 包装。

解析器在创建时会加载所需的最少数据，并根据接收到的查询懒加载其余数据。因此，建议对一批查询使用相同的实例，但对于将来的查询批次，重新创建实例以避免查看陈旧数据。

### ApiResolver.enumerateMatches(query)

`enumerateMatches(query)` 方法执行解析器特定的查询字符串，返回一个包含结果的对象数组。查询字符串可以选择性地以 /i 后缀执行不区分大小写的匹配。返回的对象数组包含以下属性：

- `name`: 找到的 API 的名称
- `address`: API 的地址，作为 `[NativePointer](#nativepointer)`
- `size`: （如果存在）一个指定大小的数字，以字节为单位

```javascript
const resolver = new ApiResolver("module");
const matches = resolver.enumerateMatches("exports:*!open*");
const first = matches[0];
/*
 * first 对象类似于:
 *
 * {
 *   name: '/usr/lib/libSystem.B.dylib!opendir$INODE64',
 *   address: ptr('0x7fff870135c9')
 * }
 */

const resolver = new ApiResolver("module");
const matches = resolver.enumerateMatches("sections:*!*text*");
const first = matches[0];
/*
 * first 对象类似于:
 *
 * {
 *   name: '/usr/lib/libSystem.B.dylib!0.__TEXT.__text',
 *   address: ptr('0x191c1e504'),
 *   size: 1528
 * }
 */

const resolver = new ApiResolver("swift");
const matches = resolver.enumerateMatches(
  "functions:*CoreDevice!*RemoteDevice*"
);
const first = matches[0];
/*
 * first 对象类似于:
 *
 * {
 *   name: '/Library/Developer/PrivateFrameworks/CoreDevice.framework/Versions/A/CoreDevice!dispatch thunk of CoreDevice.RemoteDevice.addDeviceInfoChanged(on: __C.OS_dispatch_queue?, handler: (Foundation.UUID, CoreDeviceProtocols.DeviceInfo) -> ()) -> CoreDevice.Invalidatable',
 *   address: ptr('0x1078c3570')
 * }
 */

const resolver = new ApiResolver("objc");
const matches = resolver.enumerateMatches("-[NSURL* *HTTP*]");
const first = matches[0];
/*
 * first 对象类似于:
 *
 * {
 *   name: '-[NSURLRequest valueForHTTPHeaderField:]',
 *   address: ptr('0x7fff94183e22')
 * }
 */
```

## DebugSymbol 对象

### DebugSymbol.fromxxx(address|name)

`DebugSymbol.fromAddress(address)` 和 `DebugSymbol.fromName(name)` 方法用于查找地址/名称的调试信息，并将其作为一个包含以下属性的对象返回：

- `address`: 该符号的地址，作为 `[NativePointer](#nativepointer)`
- `name`: 符号的名称，作为字符串，如果未知则为 `null`
- `moduleName`: 拥有该符号的模块名称，作为字符串，如果未知则为 `null`
- `fileName`: 拥有该符号的文件名称，作为字符串，如果未知则为 `null`
- `lineNumber`: 文件中的行号，作为数字，如果未知则为 `null`

你还可以对其调用 `toString()` 方法，这在与 `Thread.backtrace()` 结合使用时非常有用。

```javascript
const f = Module.getExportByName("libcommonCrypto.dylib", "CCCryptorCreate");
Interceptor.attach(f, {
  onEnter(args) {
    console.log(
      "CCCryptorCreate called from:\n" +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
          .map(DebugSymbol.fromAddress)
          .join("\n") +
        "\n"
    );
  },
});
```

### DebugSymbol.getFunctionByName(name)

解析函数名并返回其地址作为 `[NativePointer](#nativepointer)`。如果找到多个函数，则返回第一个。如果名称无法解析，则抛出异常。

```javascript
const mallocAddress = DebugSymbol.getFunctionByName("malloc");
console.log(mallocAddress);
```

### DebugSymbol.findFunctionsNamed(name)

解析函数名并返回其地址数组，类型为 `[NativePointer](#nativepointer)` 对象。

```javascript
const mallocAddresses = DebugSymbol.findFunctionsNamed("malloc");
mallocAddresses.forEach((addr) => console.log(addr));
```

### DebugSymbol.findFunctionsMatching(glob)

方法用于解析与给定 `glob` 模式匹配的函数名称，并返回它们的地址，作为 `[NativePointer](#nativepointer)` 对象的数组。

```javascript
const functions = DebugSymbol.findFunctionsMatching("*malloc*");
functions.forEach((addr) => console.log(addr));
```

### DebugSymbol.load(path)

加载特定模块的调试符号。

```javascript
DebugSymbol.load("/path/to/module.dylib");
```

## Kernel 对象

Kernel 对象用于与内核内存交互。

### Kernel.available

一个布尔值，指定内核 API 是否可用。在这种情况下，不要调用任何其他内核属性或方法。

```javascript
if (Kernel.available) {
  console.log("Kernel API is available");
}
```

### Kernel.base

内核的基地址，类型为 `UInt64`。

```javascript
const base = Kernel.base;
console.log(base);
```

### Kernel.pageSize

内核页面的大小，以字节为单位，类型为 `number`.

```javascript
const pageSize = Kernel.pageSize;
console.log(pageSize);
```

### Kernel.enumerateModules()

枚举当前加载的内核模块，返回包含以下属性的对象数组：

- `name`: 模块名称，类型为字符串
- `base`: 基地址，类型为 `[NativePointer](#nativepointer)`
- `size`: 大小，以字节为单位

```javascript
const modules = Kernel.enumerateModules();
modules.forEach((mod) => console.log(mod));
```

### Kernel.enumerateRanges(protection|specifier)

用于枚举符合指定保护条件的内核内存范围。保护条件可以是一个形式为 `rwx` 的字符串，其中 `rw-` 表示“必须至少是可读和可写的”。或者，你可以提供一个包含保护键的说明符对象，其值如上述形式，并且如果你希望合并具有相同保护的相邻范围，可以将 `coalesce` 键设置为 `true`（默认值为 `false`，即保持范围分开）。该方法返回一个包含以下属性的对象数组：

- `base`: 基地址，类型为 `[NativePointer](#nativepointer)`
- `size`: 大小，以字节为单位
- `protection`: 保护字符串（如 `rwx`）

```javascript
const ranges = Kernel.enumerateRanges("rwx");
ranges.forEach((range) => console.log(range));
```

### Kernel.enumerateModuleRanges(name, protection)

类似于 `Kernel.enumerateRanges`，但它限定在指定的模块名称内——该名称可以为 `null` 表示内核本身的模块。每个范围对象还包含一个 `name` 字段，提供一个唯一标识符，作为字符串。

```javascript
const moduleRanges = Kernel.enumerateModuleRanges("kernel", "r-x");
moduleRanges.forEach((range) => console.log(range));
```

### Kernel.alloc(size)

分配大小为 `size` 字节的内核内存，分配大小将向上取整为内核页面大小的倍数。返回值是一个 `UInt64`，指定分配的基址。

```javascript
const address = Kernel.alloc(4096);
console.log(address);
```

### Kernel.protect(address, size, protection)

更新内核内存区域的保护设置，`protection` 是与 `Kernel.enumerateRanges()` 方法中相同格式的字符串。

```javascript
const success = Kernel.protect(UInt64("0x1234"), 4096, "rw-");
console.log(success);
```

### Kernel.readByteArray(address, length)

类似于 `[NativePointer](#nativepointer).readByteArray`，但从内核内存读取数据。读取 `address` 地址开始的 `length` 长度的字节数组。

```javascript
const byteArray = Kernel.readByteArray(UInt64("0x1234"), 16);
console.log(byteArray);
```

### Kernel.writeByteArray(address, bytes)

类似于 `[NativePointer](#nativepointer).writeByteArray`，但向内核内存写入数据。将字节数组 `bytes` 写入到 `address` 地址开始的内核内存中。

```javascript
Kernel.writeByteArray(UInt64("0x1234"), [0x01, 0x02, 0x03, 0x04]);
```

### Kernel.scan(address, size, pattern, callbacks)

类似于 `Memory.scan`，但扫描内核内存。在 `address` 地址开始的 `size` 大小的内存范围内搜索符合 `pattern` 的模式，并使用回调 `callbacks` 处理结果。

```javascript
Kernel.scan(UInt64("0x1234"), 4096, "90 90 90 90", {
  onMatch(address, size) {
    console.log("Pattern found at:", address);
  },
  onComplete() {
    console.log("Scan complete");
  },
});
```

### Kernel.scanSync(address, size, pattern)

`Kernel.scan` 的同步版本，在 `address` 地址开始的 `size` 大小的内存范围内搜索符合 `pattern` 的模式，并返回匹配结果的数组。

```javascript
const matches = Kernel.scanSync(UInt64("0x1234"), 4096, "90 90 90 90");
matches.forEach((match) => console.log("Pattern found at:", match));
```

# Data Types, Function and Callback

## Int64

Int64 对象用于在 JavaScript 中处理 64 位有符号整数。以下是其方法和用法的概述：

### new Int64(v)

从 `v` 创建一个新的 `Int64` 对象，其中 `v` 可以是一个数字或包含十进制或十六进制（前缀为 "0x"）值的字符串。

- 简写：`int64(v)`。

### Int64.add|sub|and|or|xor(rhs)

这些方法对 `Int64` 类型的整数进行加法、减法、按位与、按位或和按位异或操作。操作数 `rhs` 可以是一个数字或另一个 `Int64` 类型的整数。

### Int64.shr|shl(n)

对 `Int64` 类型的整数进行位移操作，生成一个新的 `Int64` 对象。

### Int64.compare(rhs)

比较当前 `Int64` 和 `rhs` 的大小，返回一个整数比较结果，类似于 `String.localeCompare()` 的返回值。

### Int64.toNumber()

将当前 `Int64` 对象转换为数字类型。

### Int64.toString([radix = 10])

将当前 `Int64` 对象转换为字符串，可选地指定进制（默认为 10）。

## UInt64

`UInt64` 对象用于在 JavaScript 中处理 64 位无符号整数。以下是其方法和用法的概述：

### new UInt64(v)

从 `v` 创建一个新的 `UInt64` 对象，其中 v 可以是一个数字或包含十进制或十六进制（前缀为 "0x"）值的字符串。

- 简写：`uint64(v)`。

### UInt64.add|sub|and|or|xor(rhs)

这些方法对 `UInt64` 类型的整数进行加法、减法、按位与、按位或和按位异或操作。操作数 `rhs` 可以是一个数字或另一个 `UInt64` 类型的整数。

### UInt64.shr|shl(n)

对 `UInt64` 类型的整数进行位移操作，生成一个新的 `UInt64` 对象。

### UInt64.compare(rhs)

返回一个整数比较结果，类似于 `String#localeCompare()` 方法。

### UInt64.toNumber()

将当前 `UInt64` 对象转换为数字类型。

### toString([radix = 10])

将当前 `UInt64` 对象转换为字符串，可选地指定进制（默认为 10）。

## NativePointer

`NativePointer` 对象用于在 JavaScript 中处理指针操作，以下是其方法和用法的详细说明：

### new NativePointer(s)

从字符串 `s` 创建一个新的 `NativePointer` 对象。`s` 可以包含十进制或十六进制（前缀为 "0x"）的内存地址。

- 简写：`ptr(s)`。

### isNull()

检查指针是否为空，返回布尔值。

### NativePointer.add|sub|and|or|xor(rhs)

这些方法用于对 `NativePointer` 类型的指针进行算术或位运算，生成一个新的 `NativePointer` 对象。

### NativePointer.shr|shl(n)

这些方法用于对 `NativePointer` 类型的指针进行位移运算，生成一个新的 `NativePointer` 对象。

### NativePointer.not()

返回一个新的 `NativePointer` 对象，其值为当前指针的按位取反结果。

### NativePointer.sign([key, data])

使用指针认证位对当前指针进行签名，返回一个新的 `NativePointer` 对象。如果当前进程不支持指针认证，返回当前指针而不是新值。

- 可选参数 `key` 可以指定为字符串。支持的值为：
  - `ia`: 用于签名代码指针的 `IA` 密钥（默认）。
  - `ib`: 用于签名代码指针的 `IB` 密钥。
  - `da`: 用于签名数据指针的 `DA` 密钥。
  - `db`: 用于签名数据指针的 `DB` 密钥。
- 可选参数 `data` 可以指定为一个 `NativePointer` 或类似数字的值，默认为 0。

### NativePointer.strip([key])

用于移除 `NativePointer` 的指针认证位，生成一个原始指针。如果当前进程不支持指针认证，此操作不执行任何变化，并返回当前 `NativePointer`。

- 可选参数 `key` 用于指定签名指针时使用的密钥，默认为 ia。

### NativePointer.blend(smallInteger)

返回一个新的 `NativePointer` 对象，通过将当前指针与一个常量混合得到。这个常量可以在 `sign()` 中作为 `data` 参数传递。

### NativePointer.equals(rhs)

检查 `rhs` 是否与当前指针相等，返回布尔值。

### NativePointer.compare(rhs)

返回一个整数比较结果，类似于 `String#localeCompare()` 方法。

### NativePointer.toInt32()

将当前指针转换为带符号的 32 位整数。

### NativePointer.toString([radix = 16])

将当前指针转换为字符串，可以指定进制（默认为 16）。

### NativePointer.toMatchPattern()

返回一个字符串，该字符串包含与当前指针的原始值匹配的 `Memory.scan()` 兼容匹配模式。

### NativePointer.readPointer()

从当前内存位置读取一个 `NativePointer`。如果地址不可读，将抛出一个 `JavaScript` 异常。

```javascript
const ptr = new NativePointer("0x1000"); // 创建一个值为 0x1000 的 NativePointer 对象
try {
  const newPtr = ptr.readPointer(); // 从当前内存位置读取一个新的 NativePointer
  console.log(newPtr.toString()); // 输出读取到的指针值
} catch (e) {
  console.error("Failed to read pointer:", e); // 捕获并输出异常信息
}
```

### NativePointer.writePointer(ptr)

将 `ptr` 写入当前内存位置。如果地址不可写，将抛出一个 `JavaScript` 异常。

```javascript
const targetPtr = new NativePointer("0x1000"); // 创建一个值为 0x1000 的 NativePointer 对象
const valuePtr = new NativePointer("0x2000"); // 创建一个值为 0x2000 的 NativePointer 对象
try {
  targetPtr.writePointer(valuePtr); // 将 valuePtr 写入 targetPtr 指向的内存位置
  console.log("Pointer written successfully."); // 输出写入成功信息
} catch (e) {
  console.error("Failed to write pointer:", e); // 捕获并输出异常信息
}
```

### NativePointer.readxx()

- readS8()
- readU8()
- readS16()
- readU16()
- readS32()
- readU32()
- readShort()
- readUShort()
- readInt()
- readUInt()
- readFloat()
- readDouble()
- readS64()
- readU64()
- readLong()
- readULong()

当前内存位置读取不同类型的值，并将其作为数字返回。如果地址不可读，将抛出一个 `JavaScript` 异常。

### NativePointer.writexx(value)

- writeS8(value)
- writeU8(value)
- writeS16(value)
- writeU16(value)
- writeS32(value)
- writeU32(value)
- writeShort(value)
- writeUShort(value)
- writeInt(value)
- writeUInt(value)
- writeFloat(value)
- writeDouble(value)
- writeS64(value)
- writeU64(value)
- writeLong(value)
- writeULong(value)

用于将不同类型的值写入当前内存位置。如果地址不可写，将抛出一个 JavaScript 异常。

### NativePointer.readByteArray(length)

从当前内存位置读取 `length` 字节，并返回一个 `ArrayBuffer`。可以通过 `send()` 的第二个参数将此缓冲区高效地传输到基于 `Frida` 的应用程序。如果从地址读取的任何字节不可读，将抛出 JavaScript 异常。

### NativePointer.writeByteArray(bytes)

将字节写入当前内存位置，其中 `bytes` 可以是一个 `ArrayBuffer`（通常是从` readByteArray()` 返回的）或一个整数数组，每个整数在 0 到 255 之间。例如：`[0x13, 0x37, 0x42]`。如果写入地址的任何字节不可写，将抛出 JavaScript 异常。

### NativePointer.readxxString([size = -1])

- readCString([size = -1])
- readUtf8String([size = -1])
- readUtf16String([length = -1])
- readAnsiString([size = -1])

这些方法用于从当前内存位置读取不同编码格式的字符串。可以指定字符串的字节大小或字符长度，如果字符串是以 `NUL` 结尾的，可以忽略或设置为 -1。如果地址不可读，将抛出一个 JavaScript 异常。

> 注意，`readAnsiString()` 仅在 Windows 上可用且有意义。

### NativePointer.writexxString

- writeUtf8String(str)
- writeUtf16String(str)
- writeAnsiString(str)

这些方法用于将 JavaScript 字符串编码并写入到当前内存位置，并在字符串末尾添加一个 `NUL` 终止符。如果地址不可写，将抛出一个 JavaScript 异常。

> 注意，`writeAnsiString()` 仅在 Windows 上可用且有意义。

## ArrayBuffer

`ArrayBuffer` 对象用于处理内存缓冲区，以下是其方法和用法的详细说明：

### ArrayBuffer.wrap(address, size)

创建一个由现有内存区域支持的 `ArrayBuffer`，其中 `address` 是一个指定内存区域基地址的 `[NativePointer](#nativepointer)`，`size` 是一个指定其大小的数字。与 `[NativePointer](#nativepointer)` 读/写 API 不同，访问时不进行验证，这意味着一个错误的指针将会导致进程崩溃。

### ArrayBuffer.unwrap()

返回一个指定 `ArrayBuffer` 支持存储区基地址的 `[NativePointer](#nativepointer)`。调用者有责任在支持存储区仍在使用时保持缓冲区的有效性。

## NativeFunction

`NativeFunction` 对象用于在 JavaScript 中调用本地函数，以下是其方法和用法的详细说明：

### new NativeFunction(address, returnType, argTypes[, abi])

`new NativeFunction` 用于创建一个新的 `NativeFunction` 对象，可以调用指定地址的函数。该函数的地址由 `[NativePointer](#nativepointer)` 指定，`returnType` 指定返回类型，`argTypes` 数组指定参数类型。如果不是系统默认的调用约定 (ABI)，也可以通过 `abi` 参数指定。对于变参函数，在固定参数和变参之间添加一个 '...' 项。

对于按值传递的结构体或类，用一个包含结构体字段类型的数组代替字符串。可以嵌套数组来表示嵌套的结构体。返回的对象也是一个 `[NativePointer](#nativepointer)`，因此可以传递给 `Interceptor#attach`。

这必须与结构体/类完全匹配，所以如果有一个包含三个 `int` 的结构体，必须传递 `['int', 'int', 'int']`。

对于包含虚函数的类，第一个字段将是指向虚表 (vtable) 的指针。

在涉及返回值大于 `Process.pointerSize` 的 C++ 场景中，通常的 ABI 可能会期望传递一个指向预分配空间的 `[NativePointer](#nativepointer)` 作为第一个参数（例如，这种情况在 WebKit 中很常见）。

**支持的类型:**

`void, pointer, int, uint, long, ulong, char, uchar, size_t, ssize_t, float, double, int8, uint8, int16, uint16, int32, uint32, int64, uint64, bool`

**支持的 ABI：**

- default
- Windows 32-bit: `sysv, stdcall, thiscall, fastcall, mscdecl`
- Windows 64-bit: `win64`
- UNIX x86: `sysv, unix64`
- UNIX ARM: `sysv, vfp`

### new NativeFunction(address, returnType, argTypes[, options])

与之前的构造函数类似，但第四个参数 `options` 是一个对象，可能包含以下键：

- `abi`: 与之前的构造函数相同，用于指定调用约定。
- `scheduling`: 调度行为，支持的值有：
  - `cooperative`: 在调用本地函数时允许其他线程执行 JavaScript 代码，即在调用前释放锁，在调用后重新获取锁。这是默认行为。
  - `exclusive`: 在调用本地函数时不允许其他线程执行 JavaScript 代码，即保持 JavaScript 锁。这更快，但可能导致死锁。
- `exceptions`: 异常行为，支持的值有：
  - `steal`: 如果被调用函数生成本地异常，例如通过解引用无效指针，Frida 将展开堆栈并窃取异常，将其转换为可处理的 JavaScript 异常。这可能会使应用程序处于未定义状态，但在实验时有助于避免进程崩溃。这是默认行为。
  - `propagate`: 让应用程序处理函数调用期间发生的任何本地异常（或通过 `Process.setExceptionHandler()` 安装的处理程序）。
- `traps`: 要启用的代码陷阱，支持的值有：
  - `default`: 如果函数调用触发了任何挂钩，将调用 `Interceptor.attach()` 回调。
  - `all`: 除了 `Interceptor` `回调，Stalker` 还可能在每个函数调用期间暂时重新激活。这对于测量代码覆盖率、指导模糊测试器、在调试器中实现“单步进入”等很有用。注意，当使用 Java 和 ObjC API 时，这也是可能的，因为方法包装器也提供了 `clone(options)` API 以使用自定义的 `NativeFunction` 选项创建新的方法包装器。

```javascript
const address = ptr("0x12345678"); // 函数地址
const returnType = "int"; // 返回类型
const argTypes = ["pointer", "int"]; // 参数类型数组

const options = {
  abi: "win64", // 指定 ABI
  scheduling: "exclusive", // 调度行为
  exceptions: "steal", // 异常行为
  traps: "all", // 启用的代码陷阱
};

const nativeFunction = new NativeFunction(
  address,
  returnType,
  argTypes,
  options
);
```

## NativeCallback

`NativeCallback` 对象用于在 JavaScript 中实现本地回调，以下是其方法和用法的详细说明：

### new NativeCallback(func, returnType, argTypes[, abi])

用于创建一个由 JavaScript 函数 `func` 实现的新的 `NativeCallback`，其中 `returnType` 指定返回类型，`argTypes` 数组指定参数类型。你还可以指定 `abi`，如果没有指定，则使用系统默认的 ABI。有关支持的类型和 ABI 的详细信息，请参见 `NativeFunction`。注意，返回的对象也是一个 `[NativePointer](#nativepointer)`，因此可以传递给 `Interceptor#replace`。当使用 `Interceptor.replace()` 调用生成的回调时，`func` 将在绑定到一个具有一些有用属性的对象上调用，就像 `Interceptor.attach()` 中的对象一样。

## SystemFunction

`SystemFunction` 对象类似于 `NativeFunction`，但还提供线程的最后错误状态的快照。

### new SystemFunction(address, returnType, argTypes[, abi])

和 `NativeFunction` 类似，但还提供线程的最后错误状态快照。返回值是一个对象，包含实际的返回值 `value`，并且还有一个特定于平台的字段：在 UNIX 系统上为 `errno`，在 Windows 系统上为 `lastError`。

### SystemFunction(address, returnType, argTypes[, options])

与上述相同，但接受一个类似于 `NativeFunction` 构造函数的选项对象。

# Network

## Socket

`Socket` 类用于创建和管理网络连接，以下是其方法和用法的详细说明：

### Socket.listen([options]):

打开一个 TCP 或 UNIX 监听套接字。返回一个接收 `SocketListener` 的 Promise。

默认情况下，会在支持的情况下监听 IPv4 和 IPv6，并绑定在随机选择的 TCP 端口上的所有接口。

可选的 `options` 参数是一个对象，可能包含以下键：

- `family`: 地址族，作为字符串。支持的值有：
  - `unix`
  - `ipv4`
  - `ipv6` 如果支持，默认监听 `ipv4` 和 `ipv6`。
- `host`: (IP family) `IP` 地址，作为字符串。默认为 `localhost`。
- `port`: (IP family) `IP` 端口，作为数字。默认为任何可用端口。
- `type`: (UNIX family) UNIX 套接字类型，作为字符串。支持的类型有：
  - `anonymous`
  - `path`
  - `abstract`
  - `abstract-padded` 默认为 path。
- `path`: (UNIX family) UNIX 套接字路径，作为字符串。
- `backlog`: 监听队列长度，作为数字。默认为 10。

### Socket.connect(options):

连接到 TCP 或 UNIX 服务器。返回一个接收 `SocketConnection` 的 Promise。

- `family`: 地址族，作为字符串。支持的值有：
  - `unix`
  - `ipv4`
  - `ipv6` 如果支持，默认监听 `ipv4` 和 `ipv6`。
- `host`: (IP family) `IP` 地址，作为字符串。默认为 `localhost`。
- `port`: (IP family) `IP` 端口，作为数字。默认为任何可用端口。
- `type`: (UNIX family) `UNIX` 套接字类型，作为字符串。支持的类型有：
  - `anonymous`
  - `path`
  - `abstract`
  - `abstract-padded` 默认为 path。
- `path`: (UNIX family) UNIX 套接字路径，作为字符串。

### Socket.type(handle):

检查操作系统的套接字句柄，并返回其类型，作为字符串。类型可以是 `tcp、udp、tcp6、udp6、unix:stream、unix:dgram`，如果无效或未知，则返回 `null`。

### Socket.xxAddress(handle)

`Socket.localAddress(handle)` 和 `Socket.peerAddress(handle)` 用于检查操作系统的 `socket` 句柄，并返回其本地地址或对等地址；如果无效或未知，则返回 `null`。

返回的对象具有以下字段：

- `ip`: (IP 套接字) IP 地址，作为字符串。
- `port`: (IP 套接字) IP 端口，作为数字。
- `path`: (UNIX 套接字) UNIX 路径，作为字符串。

## SocketListener

SocketListener 是一个处理 socket 监听的对象，所有方法都是完全异步的，并返回 Promise 对象。

### SocketListener.path

(UNIX 家族) 正在监听的路径。

### SocketListener.port

(IP 家族) 正在监听的 IP 端口。

### SocketListener.close()

关闭监听器，释放与其相关的资源。监听器关闭后，所有其他操作将失败。多次关闭监听器是允许的，并且不会导致错误。

### SocketListener.accept()

等待下一个客户端连接。返回的 Promise 对象接收一个 SocketConnection。

## SocketConnection

继承自 IOStream。所有方法都是完全异步的，并返回 Promise 对象。

### SocketConnection.setNoDelay(noDelay):

如果 `noDelay` 为 `true`，则禁用 `Nagle` 算法；否则启用它。默认启用 `Nagle` 算法，因此只有在希望优化低延迟而不是高吞吐量时才需要调用此方法。

示例,创建和使用 SocketListener

```javascript
const options = {
  family: "ipv4",
  host: "0.0.0.0",
  port: 8080,
  backlog: 20,
};

Socket.listen(options)
  .then((listener) => {
    console.log("Listening on port", listener.port);

    listener
      .accept()
      .then((connection) => {
        console.log("Accepted connection from", connection.peerAddress());

        // 设置无延迟
        connection
          .setNoDelay(true)
          .then(() => {
            console.log("Nagle algorithm disabled for connection");
          })
          .catch((error) => {
            console.error("Failed to set NoDelay:", error);
          });
      })
      .catch((error) => {
        console.error("Failed to accept connection:", error);
      });
  })
  .catch((error) => {
    console.error("Failed to listen:", error);
  });
```

关闭 SocketListener

```javascript
listener
  .close()
  .then(() => {
    console.log("Listener closed");
  })
  .catch((error) => {
    console.error("Failed to close listener:", error);
  });
```

此 API 提供了一种简便的方法来管理和操作套接字连接，通过 Promise 处理异步操作，并提供多种选项和方法来灵活配置和控制套接字行为。

# File and Stream

## File

### File.readAllBytes(path)：

同步读取指定路径的文件的所有字节，并将它们作为 `ArrayBuffer` 返回。

### File.readAllText(path)：

同步读取指定路径的文件的所有文本，并将其作为字符串返回。文件必须是 `UTF-8` 编码的，如果不是，将抛出异常。

### File.writeAllBytes(path, data)：

同步将数据写入指定路径的文件，`data` 是一个 `ArrayBuffer`。

### File.writeAllText(path, text)：

同步将文本写入指定路径的文件，text 是一个字符串。文件将以 `UTF-8` 编码。

### new File(filePath, mode)：

以指定模式打开或创建文件，`filePath` 是文件路径，`mode` 是打开文件的模式字符串，例如 "wb" 表示以二进制写入模式打开文件（与 C 标准库中的 fopen() 函数格式相同）。

### File.tell()：

返回文件指针在文件中的当前位置。

### File.seek(offset[, whence])：

将文件指针移动到一个新位置。`offset` 是要移动到的位置，`whence` 是偏移的起始点（`File.SEEK_SET` 表示从文件开头，`File.SEEK_CUR` 表示从当前文件位置，`File.SEEK_END` 表示从文件末尾）。

### File.readBytes([size])：

从当前文件指针位置读取并返回 `size` 个字节作为 `ArrayBuffer`。如果未指定 `size`，则读取到文件末尾。

### File.readText([size])：

从当前文件指针位置读取并返回 `size` 个字符作为字符串。如果未指定 `size`，则读取到文件末尾。读取的字节必须是 UTF-8 编码的，如果不是，将抛出异常。

### File.readLine()：

读取并返回下一行作为字符串。从当前文件指针位置开始读取。返回的行不包含换行符。

### File.write(data)：

同步将数据写入文件，`data` 可以是一个字符串或一个 `[NativePointer](#nativepointer)#readByteArray` 返回的缓冲区。

### File.flush()：

将任何缓冲的数据刷新到底层文件。

### File.close()：

关闭文件。使用完文件后应调用此函数，除非你可以接受文件在对象被垃圾回收或脚本卸载时自动关闭。

## IOStream

所有方法都是完全异步的，并返回 Promise 对象。

### IOStream.input

要读取的 InputStream。

### IOStream.output

要写入的 OutputStream。

### IOStream.close():

关闭流，释放与之相关的资源。这也会关闭单独的输入和输出流。一旦流关闭，所有其他操作将失败。允许多次关闭流，并且不会导致错误。

```javascript
iostream
  .close()
  .then(() => {
    console.log("Stream closed");
  })
  .catch((error) => {
    console.error("Failed to close stream:", error);
  });
```

## InputStream

所有方法都是完全异步的，并返回 Promise 对象。

### InputStream.close():

关闭流，释放与之相关的资源。一旦流关闭，所有其他操作将失败。允许多次关闭流，并且不会导致错误。

```javascript
inputStream
  .close()
  .then(() => {
    console.log("Input stream closed");
  })
  .catch((error) => {
    console.error("Failed to close input stream:", error);
  });
```

### InputStream.read(size):

从流中读取最多 `size` 字节。返回的 Promise 接收一个长度最多为 `size` 字节的 ArrayBuffer。通过空缓冲区表示流的结束。

```javascript
inputStream
  .read(1024)
  .then((buffer) => {
    console.log("Read buffer:", buffer);
  })
  .catch((error) => {
    console.error("Failed to read from input stream:", error);
  });
```

### InputStream.readAll(size):

持续从流中读取，直到消耗恰好 `size` 字节。返回的 Promise 接收一个长度恰好为 `size` 字节的 ArrayBuffer。过早的错误或流的结束将导致 Promise 被拒绝，并返回一个带有部分数据的错误对象，其 `partialData` 属性包含不完整的数据。

```javascript
inputStream
  .readAll(2048)
  .then((buffer) => {
    console.log("Read all buffer:", buffer);
  })
  .catch((error) => {
    console.error("Failed to read all from input stream:", error);
  });
```

## OutputStream

所有方法都是完全异步的，并返回 Promise 对象。

### OutputStream.close():

关闭流，释放与之相关的资源。一旦流关闭，所有其他操作将失败。允许多次关闭流，并且不会导致错误。

```javascript
outputStream
  .close()
  .then(() => {
    console.log("Output stream closed");
  })
  .catch((error) => {
    console.error("Failed to close output stream:", error);
  });
```

### OutputStream.write(data):

尝试将数据写入流。`data` 值可以是 ArrayBuffer 或 0 到 255 之间的整数数组。返回的 Promise 接收一个指定写入流的字节数的 Number。

```javascript
const data = new Uint8Array([1, 2, 3, 4]);
outputStream
  .write(data)
  .then((bytesWritten) => {
    console.log("Bytes written:", bytesWritten);
  })
  .catch((error) => {
    console.error("Failed to write to output stream:", error);
  });
```

### OutputStream.writeAll(data):

持续写入流，直到所有 `data` 都被写入。`data` 值可以是 ArrayBuffer 或 0 到 255 之间的整数数组。过早的错误或流的结束将导致错误，其中错误对象的 `partialSize` 属性指定在错误发生前写入流的字节数。

```javascript
const data = new Uint8Array([5, 6, 7, 8]);
outputStream
  .writeAll(data)
  .then(() => {
    console.log("All data written");
  })
  .catch((error) => {
    console.error("Failed to write all data to output stream:", error);
  });
```

### OutputStream.writeMemoryRegion(address, size):

尝试将 `size` 字节写入流，从 `address` 读取这些字节，`address` 是一个 [NativePointer](#nativepointer)。返回的 Promise 接收一个指定写入流的字节数的 `Number`。

```javascript
const address = ptr("0x12345678");
outputStream
  .writeMemoryRegion(address, 4096)
  .then((bytesWritten) => {
    console.log("Bytes written from memory region:", bytesWritten);
  })
  .catch((error) => {
    console.error("Failed to write memory region to output stream:", error);
  });
```

这些 API 提供了对输入和输出流的灵活控制，允许异步处理和错误处理，从而使开发人员能够以现代化的方式管理流操作。

## UnixInputStream

（仅适用于类 UNIX 操作系统。）

### new UnixInputStream(fd[, options])：

从指定的文件描述符 `fd` 创建一个新的 InputStream。

你可以提供一个包含 `autoClose` 选项的对象，将其设置为 `true` 以便在流被关闭或将来垃圾回收时关闭底层文件描述符。

## UnixOutputStream

（仅适用于类 UNIX 操作系统。）

### new UnixOutputStream(fd[, options])：

从指定的文件描述符 `fd` 创建一个新的 OutputStream。

你可以提供一个包含 `autoClose` 选项的对象，将其设置为 `true` 以便在流被关闭或将来垃圾回收时关闭底层文件描述符。

## Win32InputStream

（仅适用于 Windows。）

### new Win32InputStream(handle[, options])：

从指定的句柄创建一个新的 InputStream，该句柄是一个 Windows `HANDLE` 值。

你可以提供一个包含 `autoClose` 选项的对象，将其设置为 `true` 以便在流被关闭或将来垃圾回收时关闭底层句柄。

## Win32OutputStream

（仅适用于 Windows。）

### new Win32OutputStream(handle[, options])：

从指定的句柄创建一个新的 OutputStream，该句柄是一个 Windows `HANDLE` 值。

你可以提供一个包含 `autoClose` 选项的对象，将其设置为 `true` 以便在流被关闭或将来垃圾回收时关闭底层句柄。

# Database

## SqliteDatabase

### SqliteDatabase.open(path[, options]):

打开指定路径的 SQLite v3 数据库，其中 `path` 是包含数据库文件系统路径的字符串。默认情况下，数据库将以读写模式打开，但你可以通过提供一个包含 `flags` 属性的选项对象来自定义此行为，该属性是一个字符串数组，包含以下一个或多个值：`readonly`、`readwrite`、`create`。返回的 SqliteDatabase 对象将允许你对数据库执行查询。

### SqliteDatabase.openInline(encodedContents):

类似于 `open()`，但数据库内容是作为包含数据的字符串提供的，Base64 编码。我们建议在 Base64 编码之前对数据库进行 gzip 压缩，但这是可选的，通过检查 gzip 魔术标记来检测。数据库以读写模式打开，但完全在内存中，不会触及文件系统。这对于需要捆绑预计算数据缓存的代理非常有用，例如用于指导动态分析的静态分析数据。

### SqliteDatabase.close():

关闭数据库。当你完成数据库操作时应该调用此函数，除非你对在对象被垃圾回收或脚本卸载时关闭数据库没有意见。

### SqliteDatabase.exec(sql):

执行一个原始 SQL 查询，其中 sql 是包含查询文本表示的字符串。查询结果被忽略，因此此方法仅应用于设置数据库的查询，例如表创建。

### SqliteDatabase.prepare(sql):

将提供的 SQL 编译成一个 SqliteStatement 对象，其中 sql 是包含查询文本表示的字符串。

例如：

```javascript
const db = SqliteDatabase.open("/path/to/people.db");

const smt = db.prepare("SELECT name, bio FROM people WHERE age = ?");

console.log("People whose age is 42:");
smt.bindInteger(1, 42);
let row;
while ((row = smt.step()) !== null) {
  const [name, bio] = row;
  console.log("Name:", name);
  console.log("Bio:", bio);
}
smt.reset();
```

### SqliteDatabase.dump():

将数据库转储为 gzip 压缩的 Base64 编码 blob，结果作为字符串返回。这对于在代理代码中内联缓存很有用，通过调用 SqliteDatabase.openInline() 加载。

## SqliteStatement

### SqliteStatement.bindInteger(index, value):

绑定整数值到索引 index。

### SqliteStatement.bindFloat(index, value):

绑定浮点值到索引 index。

### SqliteStatement.bindText(index, value):

绑定文本值到索引 index。

### SqliteStatement.bindBlob(index, bytes):

绑定 blob bytes 到索引 index，其中 bytes 是 ArrayBuffer、字节值数组或字符串。

### SqliteStatement.bindNull(index):

绑定 null 值到索引 index。

### SqliteStatement.step():

要么启动一个新查询并获取第一个结果，要么移动到下一个结果。返回一个包含按查询指定顺序排列的值的数组，或者在达到最后一个结果时返回 null。如果你打算再次使用此对象，应该在此时调用 reset()。

### SqliteStatement.reset():

重置内部状态以允许后续查询。

# Instrumentation

## Interceptor

### Interceptor.attach(target, callbacks[, data])

拦截对目标函数的调用。`target` 是一个 [NativePointer](#nativepointer)，指定了要拦截的函数的地址。请注意，在 32 位 ARM 上，ARM 函数的地址的最低有效位必须设置为 0，而 Thumb 函数的地址的最低有效位必须设置为 1。如果你从 Frida API 获取地址（例如 `Module.getExportByName()`），Frida 会为你处理这个细节。

- `callbacks` 参数是一个包含以下一个或多个回调函数的对象：

  - `onEnter(args)`: 在函数进入时调用，参数 `args` 是一个 [NativePointer](#nativepointer) 对象数组，可以用于读取或写入函数参数。
  - `onLeave(retval)`: 在函数离开时调用，参数 `retval` 是一个 [NativePointer](#nativepointer) 派生对象，包含原始返回值。你可以调用 `retval.replace(1337)` 将返回值替换为整数 1337，或者调用 `retval.replace(ptr("0x1234"))` 替换为一个指针。请注意，这个对象在 `onLeave` 调用之间会被回收，因此不要在回调之外存储和使用它。如果需要存储其中的值，请做深拷贝，例如：`ptr(retval.toString())`。

对于非常频繁调用的函数，`onEnter` 和 `onLeave` 可能是指向使用 [CModule](#cmodule-对象) 编译的原生 C 函数的 [NativePointer](#nativepointer) 值。它们的签名如下：

```c
void onEnter (GumInvocationContext * ic)
void onLeave (GumInvocationContext * ic)
```

在这种情况下，可选的第三个参数 `data` 可以是一个 [NativePointer](##nativepointer)，通过 `gum_invocation_context_get_listener_function_data()` 访问。

你也可以通过传递一个函数而不是 `callbacks` 对象来拦截任意指令。此函数具有与 `onEnter` 相同的签名，但只有在拦截的指令位于函数的开头或寄存器/堆栈尚未偏离该点的位置时，`args` 参数才会有意义。

就像上面一样，这个函数也可以通过指定一个 [NativePointer](##nativepointer) 而不是一个函数来在 C 中实现。

返回一个监听器对象，你可以调用 `detach()` 来分离它。

注意，这些函数会在每次调用时将 `this` 绑定到一个每次调用（线程局部）的对象上，你可以在其中存储任意数据，这在你想在 `onEnter` 中读取参数并在 `onLeave` 中对其进行操作时非常有用。

例如：

```javascript
Interceptor.attach(Module.getExportByName("libc.so", "read"), {
  onEnter(args) {
    this.fileDescriptor = args[0].toInt32();
  },
  onLeave(retval) {
    if (retval.toInt32() > 0) {
      /* do something with this.fileDescriptor */
    }
  },
});
```

此外，该对象包含一些有用的属性：

- `returnAddress`: 返回地址，作为 [NativePointer](##nativepointer)。
- `context`: 包含 `pc` 和 `sp` 键的对象，这些键是 [NativePointer](##nativepointer) 对象，分别指定 `ia32/x64/arm` 的 `EIP/RIP/PC` 和 `ESP/RSP/SP`。还可以访问其他处理器特定的键，例如 eax, rax, r0, x0 等。你也可以通过赋值来更新寄存器值。
- `errno`: （UNIX）当前的 `errno` 值（可以替换它）。
- `lastError`: （Windows）当前的 OS 错误值（可以替换它）。
- `threadId`: OS 线程 ID。
- `depth`: 相对于其他调用的调用深度。

例如：

```javascript
Interceptor.attach(Module.getExportByName(null, "read"), {
  onEnter(args) {
    console.log("Context information:");
    console.log("Context  : " + JSON.stringify(this.context));
    console.log("Return   : " + this.returnAddress);
    console.log("ThreadId : " + this.threadId);
    console.log("Depth    : " + this.depth);
    console.log("Errornr  : " + this.err);

    // Save arguments for processing in onLeave.
    this.fd = args[0].toInt32();
    this.buf = args[1];
    this.count = args[2].toInt32();
  },
  onLeave(result) {
    console.log("----------");
    // Show argument 1 (buf), saved during onEnter.
    const numBytes = result.toInt32();
    if (numBytes > 0) {
      console.log(hexdump(this.buf, { length: numBytes, ansi: true }));
    }
    console.log("Result   : " + numBytes);
  },
});
```

**性能考虑**

提供的回调对性能有显著影响。如果你只需要检查参数但不关心返回值，或者反之，确保省略不需要的回调；即避免将逻辑放在 `onEnter` 中而将 `onLeave` 留作空回调。

例如在 iPhone 5S 上，仅提供 `onEnter` 的基础开销可能是 6 微秒，而同时提供 `onEnter` 和 `onLeave` 的开销可能是 11 微秒。

对于每秒调用数十亿次的函数，要谨慎拦截；虽然 `send()` 是异步的，但发送单个消息的总开销并未针对高频率进行优化，这意味着 Frida 留给你批量多个值到单个 `send()` 调用的决定权，基于低延迟或高吞吐量的需求。

然而，当钩住热函数时，你可以使用 Interceptor 与 CModule 结合使用来在 C 中实现回调。

### Interceptor.detachAll()

分离所有先前附加的回调。

### Interceptor.replace(target, replacement[, data])

用于替换指定目标函数的实现的函数。这个函数通常用于完全或部分替换现有函数的实现。

- `target`: 需要替换的目标函数。
- `replacement`: 替换目标函数的实现。
- `data` (可选): 可选的第三个参数，是一个 NativePointer，可以通过 `gum_invocation_context_get_listener_function_data()` 访问。使用 `gum_interceptor_get_current_invocation()` 获取 `GumInvocationContext *`。

为了实现一个替换，可以使用 NativeCallback 在 JavaScript 中实现替换。如果被替换的函数是非常频繁调用的，可以使用 CModule 在 C 语言中实现替换。

替换将一直有效，直到调用 `Interceptor#revert`。

如果想在替换的实现中调用原始实现，可以在实现内部通过 NativeFunction 同步调用 target，这将绕过替换，直接调用原始实现。

例如：

```javascript
const openPtr = Module.getExportByName("libc.so", "open");
const open = new NativeFunction(openPtr, "int", ["pointer", "int"]);
Interceptor.replace(
  openPtr,
  new NativeCallback(
    (pathPtr, flags) => {
      const path = pathPtr.readUtf8String();
      log('Opening "' + path + '"');
      const fd = open(pathPtr, flags);
      log("Got fd: " + fd);
      return fd;
    },
    "int",
    ["pointer", "int"]
  )
);
```

### Interceptor.revert(target)

将目标函数 `target` 恢复为先前的实现。

### Interceptor.flush()

确保所有挂起的更改已提交到内存。这只应在少数情况下进行，例如如果你刚刚 `attach()` 或 `replace()` 了一个函数并打算使用 NativeFunction 调用它。挂起的更改会在当前线程即将离开 JavaScript 运行时或调用 `send()` 时自动刷新。这包括任何基于 `send()` 的 API，例如从 RPC 方法返回时，以及调用控制台 API 上的任何方法时。

### Interceptor.breakpointKind

用于指定非内联钩子使用的断点类型。仅在 Barebone 后端中可用。

- 默认值: 'soft'（软件断点）
- 可选值: 'hard'（硬件断点）

设置此属性可以决定在非内联钩子中使用哪种类型的断点。

```javascript
// 默认使用软件断点
Interceptor.breakpointKind = "soft";
// 更改为使用硬件断点
Interceptor.breakpointKind = "hard";
```

## Stalker

Frida 的 Stalker 模块是一个强大的工具，用于跟踪本地代码的执行。它允许你跟踪线程的执行，监视函数调用，并拦截特定指令。以下是如何使用 Frida Stalker 各种功能的指南。

### Stalker.exclude(range)

用于将指定的内存范围标记为排除范围，这个范围是一个具有 `base` 和 `size` 属性的对象，就像通过 `Process.getModuleByName()` 等方法返回的对象属性。

这意味着当遇到调用该范围内的指令时，Stalker 不会跟踪执行。因此，你将能够观察/修改传入的参数和返回的值，但不会看到两者之间发生的指令执行过程。

这个方法对于提高性能和减少噪音非常有用。

### Stalker.follow([threadId, options])

开始跟踪 `threadId`（如果省略则跟踪当前线程），可以选择性地使用 `options` 来启用事件。

例如：

```javascript
const mainThread = Process.enumerateThreads()[0];

Stalker.follow(mainThread.id, {
  events: {
    call: true, // 跟踪CALL指令
    ret: false, // 不跟踪RET指令
    exec: false, // 不跟踪所有指令
    block: false, // 不跟踪块执行
    compile: false, // 不跟踪块编译
  },

  // 只需指定以下两个回调中的一个
  // onReceive: 接收包含一个或多个GumEvent结构的二进制Blob数据
  //onReceive(events) {},

  // onCallSummary: 接收一个包含调用目标及其调用次数的键值对映射
  onCallSummary(summary) {},

  // 高级用户：可以插入自定义StalkerTransformer
  // transform(iterator) {
  //   let instruction = iterator.next();
  //   const startAddress = instruction.address;
  //   const isAppCode = startAddress.compare(appStart) >= 0 && startAddress.compare(appEnd) === -1;
  //   const canEmitNoisyCode = iterator.memoryAccess === 'open';

  //   do {
  //     if (isAppCode && canEmitNoisyCode && instruction.mnemonic === 'ret') {
  //       iterator.putCmpRegI32('eax', 60);
  //       iterator.putJccShortLabel('jb', 'nope', 'no-hint');
  //       iterator.putCmpRegI32('eax', 90);
  //       iterator.putJccShortLabel('ja', 'nope', 'no-hint');
  //       iterator.putCallout(onMatch);
  //       iterator.putLabel('nope');
  //     }
  //     iterator.keep();
  //   } while ((instruction = iterator.next()) !== null);
  // },
});
```

**性能考虑**

回调对性能有显著影响。如果只需要周期性的调用摘要而不关心原始事件，或反之亦然，请确保省略不需要的回调。例如，不要在 `onCallSummary` 中放置逻辑并留下空的 `onReceive` 回调。

### Stalker.unfollow([threadId])

停止跟踪 `threadId`（如果省略则停止跟踪当前线程）。

### Stalker.parse(events[, options])

解析 `GumEvent` 二进制 Blob，可以选择通过 `options` 自定义输出。例如：

```javascript
  onReceive(events) {
    console.log(Stalker.parse(events, {
      annotate: true, // to display the type of event
      stringify: true
        // to format pointer values as strings instead of `NativePointer`
        // values, i.e. less overhead if you're just going to `send()` the
        // thing not actually parse the data agent-side
    }));
  },
```

### Stalker.flush()

清空任何缓冲的事件。用于在不想等待下一个 `Stalker.queueDrainInterval` 时刻时调用。

### Stalker.garbageCollect()

在 `Stalker#unfollow` 后释放累积的内存，以避免刚刚停止跟踪的线程执行其最后指令时出现的竞争条件。

### Stalker.invalidate(address)

使当前线程对指定基本块的已翻译代码无效。对于提供 `transform` 回调并希望动态调整指定基本块的插桩来说，此方法非常有用。比取消和重新跟踪线程更高效。

### Stalker.invalidate(threadId, address)

使特定线程对指定基本块的已翻译代码无效。比取消和重新跟踪线程更高效。

### Stalker.addCallProbe(address, callback[, data])

在调用 `address` 时同步调用 `callback`，返回一个可以传递给 `Stalker#removeCallProbe` 的 `id`。可以使用 C 实现回调。

### Stalker.removeCallProbe(id)

移除由 `Stalker#addCallProbe` 添加的调用探针。

### Stalker.trustThreshold

指定代码需执行的次数，以便假设它可以被信任而不会改变。默认值为 1。

### Stalker.queueCapacity

指定事件队列的容量，默认为 16384 个事件。

### Stalker.queueDrainInterval

指定事件队列排空的时间间隔，默认为 250ms，即每秒排空 4 次。可以设置为 0 以禁用周期性排空，并在需要时调用 `Stalker.flush()`。

## ObjC

### ObjC.available

一个布尔值，指定当前进程是否加载了 Objective-C 运行时。如果未加载，请勿调用任何其他 ObjC 属性或方法。

### ObjC.api

一个对象，将函数名称映射到 NativeFunction 实例，以直接访问大部分 Objective-C 运行时 API。

### ObjC.classes

一个对象，将类名称映射到当前注册的每个类的 `ObjC.Object` JavaScript 绑定。可以使用点符号与对象进行交互，并将冒号替换为下划线。例如，`[NSString stringWithString:@"Hello World"]` 变为 `const { NSString } = ObjC.classes; NSString.stringWithString_("Hello World");`。注意方法名称后的下划线。请参阅 iOS 示例部分了解更多详细信息。

### ObjC.protocols

一个对象，将协议名称映射到当前注册的每个协议的 `ObjC.Protocol` JavaScript 绑定。

### ObjC.mainQueue

主线程的 GCD 队列。

### ObjC.schedule(queue, work)

在指定的 GCD 队列上调度 JavaScript 函数 `work`。在调用 `work` 之前创建一个 `NSAutoreleasePool`，并在返回时清理。

示例：

```javascript
const { NSSound } = ObjC.classes; /* macOS */
ObjC.schedule(ObjC.mainQueue, () => {
  const sound = NSSound.alloc().initWithContentsOfFile_byReference_(
    "/Users/oleavr/.Trash/test.mp3",
    true
  );
  sound.play();
});
```

### new ObjC.Object(handle[, protocol])

给定现有对象的句柄（[NativePointer](##nativepointer)），创建一个 JavaScript 绑定。如果希望仅将句柄视为实现特定协议的对象，也可以指定 `protocol` 参数。

示例：

```javascript
Interceptor.attach(myFunction.implementation, {
  onEnter(args) {
    const myString = new ObjC.Object(args[2]);
    console.log("String argument: " + myString.toString());
  },
});
```

此对象具有一些特殊属性：

- `$kind`: 字符串，指定实例、类或元类。
- `$super`: 用于向超类方法实现进行链式调用的 `ObjC.Object` 实例。
- `$superClass`: 作为 `ObjC.Object` 实例的超类。
- `$class`: 作为 `ObjC.Object` 实例的类。
- `$className`: 包含此对象类名称的字符串。
- `$moduleName`: 包含此对象模块路径的字符串。
- `$protocols`: 将协议名称映射到此对象符合的每个协议的 `ObjC.Protocol` 实例。
- `$methods`: 包含此对象类及其父类公开的本机方法名称的数组。
- `$ownMethods`: 包含此对象类公开的本机方法名称的数组，不包括父类。
- `$ivars`: 将每个实例变量名称映射到其当前值的对象，允许通过访问和分配读取和写入每个实例变量。

还有一个 `equals(other)` 方法用于检查两个实例是否引用同一个底层对象。

注意：所有方法包装器提供一个 `clone(options)` API，用于使用自定义 NativeFunction 选项创建新的方法包装器。

### new ObjC.Protocol(handle)

给定现有协议的句柄（[NativePointer](##nativepointer)），创建一个 JavaScript 绑定。

### new ObjC.Block(target[, options])

给定现有块的目标（[NativePointer](##nativepointer)），创建一个 JavaScript 绑定；要定义一个新块，目标应该是一个对象，指定类型签名和在调用块时调用的 JavaScript 函数。函数通过 `implementation` 键指定，签名通过 `types` 键或通过 `retType` 和 `argTypes` 键指定。

示例：

```javascript

const pendingBlocks = new Set();

Interceptor.attach(..., {
  onEnter(args) {
    const block = new ObjC.Block(args[4]);
    pendingBlocks.add(block); // 保持它的存活
    const appCallback = block.implementation;
    block.implementation = (error, value) => {
      // 在这里进行日志记录
      const result = appCallback(error, value);
      pendingBlocks.delete(block);
      return result;
    };
  }
});
```

### ObjC.implement(method, fn)

创建一个与方法签名兼容的 JavaScript 实现，其中 JavaScript 函数 fn 用作实现。返回一个可以分配给 ObjC 方法实现属性的 NativeCallback。

示例：

```javascript
const NSSound = ObjC.classes.NSSound; /* macOS */
const oldImpl = NSSound.play.implementation;
NSSound.play.implementation = ObjC.implement(
  NSSound.play,
  (handle, selector) => {
    return oldImpl(handle, selector);
  }
);

const NSView = ObjC.classes.NSView; /* macOS */
const drawRect = NSView["- drawRect:"];
const oldImpl = drawRect.implementation;
drawRect.implementation = ObjC.implement(drawRect, (handle, selector) => {
  oldImpl(handle, selector);
});
```

由于 `implementation` 属性是一个 NativeFunction，因此也是一个 [NativePointer](##nativepointer)，可以使用 Interceptor 来挂钩函数：

示例：

```javascript
const { NSSound } = ObjC.classes; /* macOS */
Interceptor.attach(NSSound.play.implementation, {
  onEnter() {
    send("[NSSound play]");
  },
});
```

### ObjC.registerProxy(properties)

创建一个设计为目标对象代理的新类，其中 `properties` 是一个对象，指定协议、方法和事件的回调。

示例：

```javascript
const MyConnectionDelegateProxy = ObjC.registerProxy({
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    "- connection:didReceiveResponse:": function (conn, resp) {
      /* 记录日志的代码 */
      this.data.target.connection_didReceiveResponse_(conn, resp);
    },
    "- connection:didReceiveData:": function (conn, data) {
      /* 其他记录日志的代码 */
      this.data.target.connection_didReceiveData_(conn, data);
    },
  },
  events: {
    forward(name) {
      console.log("*** forwarding: " + name);
    },
  },
});
```

### ObjC.registerClass(properties)

创建一个新的 Objective-C 类，其中 `properties` 是一个对象，指定类名、超类、协议和方法。

示例：

```javascript
const MyConnectionDelegateProxy = ObjC.registerClass({
  name: "MyConnectionDelegateProxy",
  super: ObjC.classes.NSObject,
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    "- init": function () {
      const self = this.super.init();
      if (self !== null) {
        ObjC.bind(self, {
          foo: 1234,
        });
      }
      return self;
    },
    "- dealloc": function () {
      ObjC.unbind(this.self);
      this.super.dealloc();
    },
    "- connection:didReceiveResponse:": function (conn, resp) {
      /* this.data.foo === 1234 */
    },
    /* 假设超类或我们符合的协议有相同的方法 */
    "- connection:didReceiveResponse:": {
      retType: "void",
      argTypes: ["object", "object"],
      implementation(conn, resp) {},
    },
  },
});
```

### ObjC.registerProtocol(properties)

创建一个新的 Objective-C 协议，其中 `properties` 是一个对象，指定协议名称、包含的协议和方法。

示例：

```javascript
const MyDataDelegate = ObjC.registerProtocol({
  name: "MyDataDelegate",
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    "- connection:didStuff:": {
      retType: "void",
      argTypes: ["object", "object"],
    },
    /* 从现有类的方法中获取签名 */
    "- connection:didStuff:": {
      types: ObjC.classes.Foo["- connection:didReceiveResponse:"].types,
    },
    /* 从现有协议的方法中获取签名 */
    "- connection:didStuff:": {
      types:
        ObjC.protocols.NSURLConnectionDataDelegate.methods[
          "- connection:didReceiveResponse:"
        ].types,
    },
    /* 手动编写签名 */
    "- connection:didStuff:": {
      types: "v32@0:8@16@24",
    },
    /* 将方法设为可选 */
    "- connection:didStuff:": {
      retType: "void",
      argTypes: ["object", "object"],
      optional: true,
    },
  },
});
```

### ObjC.bind(obj, data)

将一些 JavaScript 数据绑定到 Objective-C 实例。

### ObjC.unbind(obj)

解除之前绑定到 Objective-C 实例的 JavaScript 数据。

### ObjC.getBoundData(obj)

查找从 Objective-C 对象之前绑定的数据。

### ObjC.enumerateLoadedClasses([options, ]callbacks)

枚举当前加载的类，其中 `callbacks` 是一个对象，指定匹配时和完成时的回调函数。

示例：

```javascript
ObjC.enumerateLoadedClasses({
  onMatch(name, owner) {
    console.log("onMatch:", name, owner);
  },
  onComplete() {},
});
```

### ObjC.enumerateLoadedClassesSync([options])

枚举当前加载类的同步版本，返回一个将所有者模块映射到类名称数组的对象。

示例：

```javascript
const appModules = new ModuleMap(isAppModule);
const appClasses = ObjC.enumerateLoadedClassesSync({ ownedBy: appModules });
console.log("appClasses:", JSON.stringify(appClasses));

function isAppModule(m) {
  return !/^\/(usr\/lib|System|Developer)\//.test(m.path);
}
```

### ObjC.choose(specifier, callbacks)

通过扫描堆枚举与指定符匹配的类的活动实例。`specifier` 是一个类选择器或指定类选择器和所需选项的对象。

示例：

```javascript
ObjC.choose(
  {
    class: ObjC.classes.UIButton,
    subclasses: true,
  },
  {
    onMatch(instance) {
      console.log(instance);
    },
    onComplete() {
      console.log("done");
    },
  }
);
```

### ObjC.chooseSync(specifier)

`choose()` 的同步版本，返回实例数组。

### ObjC.selector(name)

将 JavaScript 字符串名称转换为选择器。

### ObjC.selectorAsString(sel)

将选择器 `sel` 转换为 JavaScript 字符串。

## Java

### Java.available

当前进程是否加载了 Java 虚拟机（即 Dalvik 或 ART）。除非此值为真，否则不要调用任何其他 Java 属性或方法。

### Java.androidVersion

当前运行的 Android 版本。

### Java.enumerateLoadedClasses(callbacks)

枚举当前加载的类，其中 `callbacks` 是一个对象，指定以下回调函数：

- `onMatch(name, handle)`: 对于每个加载的类调用，其中 `name` 是类名，可以传递给 `use()` 获取 JavaScript 包装器。`handle` 是该类在内存中的引用，代表这个类的句柄，你可以用 `Java.cast()`将 `handle` 转换为 `java.lang.Class` 对象。
- `onComplete()`: 在所有类都被枚举后调用。

示例：

```javascript
Java.perform(function () {
  // 调用 enumerateLoadedClasses 来列举所有已加载的类
  function enumerateLoadedClass() {
    Java.perform(function () {
      Java.enumerateLoadedClasses({
        onMatch: function (name, handle) {
          // 输入类名
          console.log("", name);
          // 转换为 java.lang.Class 对象
          var clazz = Java.cast(handle, Java.use("java.lang.Class"));
          var simpleName = clazz.getSimpleName();
          console.log("cls_name: ", simpleName);
        },
        onComplete: function () {
          console.log("Class enumeration completed");
        },
      });
    });
  }
});
```

### Java.enumerateLoadedClassesSync()

`enumerateLoadedClasses()` 的同步版本，返回类名数组。

### Java.enumerateClassLoaders(callbacks)

枚举 Java 虚拟机中的类加载器，其中 `callbacks` 是一个对象，指定以下回调函数：

- `onMatch(loader)`: 对于每个类加载器调用，其中 `loader` 是特定 `java.lang.ClassLoader` 的包装器。
- `onComplete()`: 在所有类加载器都被枚举后调用。

你可以将这样的加载器传递给 `Java.ClassFactory.get()`，以便能够在指定的类加载器上使用 `.use()` 类。

示例：

```javascript

```

### Java.enumerateClassLoadersSync()

`enumerateClassLoaders()` 的同步版本，返回类加载器数组。

### Java.enumerateMethods(query)

枚举与 `query` 匹配的方法，`query` 的格式为“class!method”，允许使用通配符。可以使用以下修饰符：

- `i`: 大小写不敏感匹配。
- `s`: 包括方法签名，例如"putInt"变为"putInt(java.lang.String, int): void"。
- `u`: 仅用户定义的类，忽略系统类。

示例：

```javascript
Java.perform(() => {
  const groups = Java.enumerateMethods("*youtube*!on*");
  console.log(JSON.stringify(groups, null, 2));
});
```

输出示例：

```
json

[
  {
    "loader": "<instance: java.lang.ClassLoader, $className: dalvik.system.PathClassLoader>",
    "classes": [
      {
        "name": "com.google.android.apps.youtube.app.watch.nextgenwatch.ui.NextGenWatchLayout",
        "methods": [
          "onAttachedToWindow",
          "onDetachedFromWindow",
          "onFinishInflate",
          "onInterceptTouchEvent",
          "onLayout",
          "onMeasure",
          "onSizeChanged",
          "onTouchEvent",
          "onViewRemoved"
        ]
      },
      {
        "name": "com.google.android.apps.youtube.app.search.suggest.YouTubeSuggestionProvider",
        "methods": [
          "onCreate"
        ]
      },
      {
        "name": "com.google.android.libraries.youtube.common.ui.YouTubeButton",
        "methods": [
          "onInitializeAccessibilityNodeInfo"
        ]
      }
    ]
  }
]
```

### Java.scheduleOnMainThread(fn)

在虚拟机的主线程上运行 `fn`。

### Java.perform(fn)

该函数确保当前线程已经正确地附加到 Java 虚拟机上才会调用 `fn`。（如果是从 Java 回调中调用，则不需要这个步骤，因为线程已经自动附加。）如果应用程序的类加载器(ClassLoader)还未就绪，会自动延迟执行 `fn`，这确保了在执行你的代码时能够正确访问到应用程序的类。如果你的代码不需要访问应用程序的类，建议使用 `Java.performNow()`，`performNow()` 会立即执行，不会等待类加载器。

示例：

```javascript
Java.perform(() => {
  // 这里能够正确访问到应用程序的类
  const Activity = Java.use("android.app.Activity");
  Activity.onResume.implementation = function () {
    send("onResume() got called! Let's call the original implementation");
    this.onResume();
  };
});
```

### Java.performNow(fn)

该函数确保当前线程已经正确地附加到 Java 虚拟机并调用 `fn`。（如果是从 Java 回调中调用，则不需要这个步骤，因为线程已经自动附加。）该函数不会等待应用程序的类加载器加载就绪，适合用于基础的 Java 操作或内存操作。当我们的操作不需要访问应用程序的具体类时，优先使用 `performNow()`。


### Java.use(className)

为指定的 Java 类动态创建 JavaScript 包装器，可以通过调用 `$new()` 实例化对象以调用构造函数。调用实例的 `$dispose()` 进行显式清理（或者等待 JavaScript 对象被垃圾回收或脚本被卸载）。可以使用静态和非静态方法，甚至可以替换方法实现并抛出异常。

示例：

```javascript
Java.perform(() => {
  const Activity = Java.use("android.app.Activity");
  const Exception = Java.use("java.lang.Exception");
  Activity.onResume.implementation = function () {
    throw Exception.$new("Oh noes!");
  };
});
```

> 默认使用应用程序的类加载器，但你可以通过将不同的加载器实例分配给 `Java.classFactory.loader` 来自定义这个加载器。 
> 注意，所有方法包装器都提供一个 `clone(options)` API，用于创建一个带有自定义 [NativeFunction](#NativeFunction) 选项的新方法包装器。

### Java.openClassFile(filePath)

打开 `filePath` 处的 `.dex` 文件，返回一个对象，该对象具有以下方法：

- `load()`: 将包含的类加载到虚拟机。
- `getClassNames()`: 获取可用类名的数组。

### Java.choose(className, callbacks)

通过扫描 Java 堆枚举 `className` 类的活动实例，其中 `callbacks` 是一个对象，指定以下回调函数：

- `onMatch(instance)`: 找到的每个活动实例调用，使用现成的实例，就像调用 `Java.cast()` 与此特定实例的原始句柄一样。
- `onComplete()`: 在所有实例都被枚举后调用。

### Java.retain(obj)

复制 JavaScript 包装器 `obj` 以便稍后在替换方法之外使用。

示例：

```javascript
Java.perform(() => {
  const Activity = Java.use("android.app.Activity");
  let lastActivity = null;
  Activity.onResume.implementation = function () {
    lastActivity = Java.retain(this);
    this.onResume();
  };
});
```

### Java.cast(handle, klass)

给定 `handle` 的现有实例创建 JavaScript 包装器，`handle` 属于由 `Java.use()` 返回的 `klass` 类。这样的包装器还有一个 `class` 属性，用于获取其类的包装器，以及一个 `$className` 属性，用于获取其类名的字符串表示。

示例：

```javascript
const Activity = Java.use("android.app.Activity");
const activity = Java.cast(ptr("0x1234"), Activity);
```

### Java.array(type, elements)

从 JavaScript 数组 `elements` 创建指定类型的 Java 数组。生成的 Java 数组表现得像一个 JS 数组，但可以通过引用传递给 Java API，以允许它们修改其内容。

示例：

```javascript
const values = Java.array("int", [1003, 1005, 1007]);

const JString = Java.use("java.lang.String");
const str = JString.$new(Java.array("byte", [0x48, 0x65, 0x69]));
```

### Java.isMainThread()

确定调用者是否在主线程上运行。

### Java.registerClass(spec)

创建一个新 Java 类并返回其包装器，其中 `spec` 是一个对象，包含以下属性：

- `name`: 指定类名的字符串。
- `superClass`: （可选）超类。省略则继承自 `java.lang.Object`。
- `implements`: （可选）实现的接口数组。
- `fields`: （可选）指定要公开的每个字段的名称和类型的对象。
- `methods`: （可选）指定要实现的方法的对象。

示例：

```javascript
const SomeBaseClass = Java.use("com.example.SomeBaseClass");
const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

const MyTrustManager = Java.registerClass({
  name: "com.example.MyTrustManager",
  implements: [X509TrustManager],
  methods: {
    checkClientTrusted(chain, authType) {},
    checkServerTrusted(chain, authType) {},
    getAcceptedIssuers() {
      return [];
    },
  },
});

const MyWeirdTrustManager = Java.registerClass({
  name: "com.example.MyWeirdTrustManager",
  superClass: SomeBaseClass,
  implements: [X509TrustManager],
  fields: {
    description: "java.lang.String",
    limit: "int",
  },
  methods: {
    $init() {
      console.log("Constructor called");
    },
    checkClientTrusted(chain, authType) {
      console.log("checkClientTrusted");
    },
    checkServerTrusted: [
      {
        returnType: "void",
        argumentTypes: [
          "[Ljava.security.cert.X509Certificate;",
          "java.lang.String",
        ],
        implementation(chain, authType) {
          console.log("checkServerTrusted A");
        },
      },
      {
        returnType: "java.util.List",
        argumentTypes: [
          "[Ljava.security.cert.X509Certificate;",
          "java.lang.String",
          "java.lang.String",
        ],
        implementation(chain, authType, host) {
          console.log("checkServerTrusted B");
          return null;
        },
      },
    ],
    getAcceptedIssuers() {
      console.log("getAcceptedIssuers");
      return [];
    },
  },
});
```

### Java.deoptimizeEverything()

强制虚拟机使用其解释器执行所有内容。在某些情况下，这对于防止优化绕过方法挂钩是必要的，并允许使用 ART 的 Instrumentation API 来跟踪运行时。

### Java.deoptimizeBootImage()

类似于 `Java.deoptimizeEverything()`，但仅对引导映像代码进行反优化。使用 `dalvik.vm.dex2oat-flags --inline-max-code-units=0` 可以获得最佳效果。

### Java.vm

一个对象，具有以下方法：

- `perform(fn)`: 确保当前线程已附加到虚拟机并调用 `fn`。
- `getEnv()`: 获取当前线程的 `JNIEnv` 的包装器。如果当前线程未附加到虚拟机，将抛出异常。
- `tryGetEnv()`: 尝试获取当前线程的 `JNIEnv` 的包装器。如果当前线程未附加到虚拟机，则返回 `null`。

### Java.classFactory

用于实现例如 `Java.use()` 的默认类工厂。使用应用程序的主类加载器。

### Java.ClassFactory

一个类，具有以下属性：

- `get(classLoader)`: 获取指定类加载器的类工厂实例。默认类工厂在后台仅与应用程序的主类加载器交互。可以通过 `Java.enumerateClassLoaders()` 发现其他类加载器，并通过此 API 与它们交互。
- `loader`: 提供当前使用的类加载器的包装器的只读属性。对于默认类工厂，这在第一次调用 `Java.perform()` 时更新。
- `cacheDir`: 包含当前使用的缓存目录路径的字符串。对于默认类工厂，这在第一次调用 `Java.perform()` 时更新。
- `tempFileNaming`: 指定临时文件命名约定的对象。默认为`{ prefix: 'frida', suffix: 'dat' }`。
- `use(className)`: 类似于 J`ava.use()`，但针对特定的类加载器。
- `openClassFile(filePath)`: 类似于 `Java.openClassFile()`，但针对特定的类加载器。
- `choose(className, callbacks)`: 类似于 `Java.choose()`，但针对特定的类加载器。
- `retain(obj)`: 类似于 `Java.retain()`，但针对特定的类加载器。
- `cast(handle, klass)`: 类似于 `Java.cast()`，但针对特定的类加载器。
- `array(type, elements)`: 类似于 `Java.array()`，但针对特定的类加载器。
- `registerClass(spec)`: 类似于 `Java.registerClass()`，但针对特定的类加载器。

# CPU Instruction

## Instruction

### Instruction.parse(target)

解析目标地址内存处的指令，目标地址用 [NativePointer](##nativepointer) 表示。注意，在 32 位 ARM 架构上，该地址对于 ARM 函数必须将最低有效位设置为 0，对于 Thumb 函数必须将其设置为 1。如果你从 Frida API（例如 `Module.getExportByName()`）获取地址，Frida 会为你处理这个细节。

返回的对象包含以下字段：

- `address`: 该指令的地址（EIP），作为 [NativePointer](##nativepointer)。
- `next`: 指向下一条指令的指针，因此你可以解析（parse()）它。
- `size`: 该指令的大小。
- `mnemonic`: 指令助记符的字符串表示。
- `opStr`: 指令操作数的字符串表示。
- `operands`: 描述每个操作数的对象数组，每个对象至少指定类型和值，但可能还会根据架构提供其他属性。
- `regsRead`: 该指令隐式读取的寄存器名称数组。
- `regsWritten`: 该指令隐式写入的寄存器名称数组。
- `groups`: 该指令所属的组名称数组。
- `toString()`: 转换为可读字符串。

有关操作数和组的详细信息，请查阅 [Capstone](http://www.capstone-engine.org/) 文档（根据你的架构）。

示例代码

以下是一些如何使用 `Instruction.parse()` 函数的示例代码：
示例 1: 解析单条指令

```javascript
const targetAddress = ptr("0x1000");
const instruction = Instruction.parse(targetAddress);

console.log(instruction.address); // 输出指令地址
console.log(instruction.mnemonic); // 输出指令助记符
console.log(instruction.opStr); // 输出指令操作数字符串
```

示例 2: 解析指令链

```javascript
let currentAddress = ptr("0x1000");

while (true) {
  const instruction = Instruction.parse(currentAddress);
  console.log(instruction.toString());

  currentAddress = instruction.next;
  if (currentAddress.isNull()) {
    break;
  }
}
```

## X86Writer

### new X86Writer(codeAddress[, { pc: ptr('0x1234') }])

创建一个新的代码编写器，用于生成 x86 机器代码并直接写入内存的 `codeAddress` 位置，该位置由 [NativePointer](##nativepointer) 指定。第二个参数是一个可选的选项对象，可以指定初始程序计数器 `pc`，这在生成代码到临时缓冲区时很有用。特别是在 iOS 上使用 `Memory.patchCode()`时，这很关键，因为它可能会提供一个临时位置，稍后映射到预期的内存位置。

### X86Writer.reset(codeAddress[, { pc: ptr('0x1234') }])

重新使用实例。

### X86Writer.dispose()

及时清理内存。

### X86Writer.flush()

解析标签引用并将未完成的数据写入内存。生成代码后应始终调用此方法，在生成多个不相关的代码段时也应这样做。

### X86Writer.base

输出的第一个字节的内存位置，作为 [NativePointer](##nativepointer)。

### X86Writer.code

下一个字节的输出位置，作为 [NativePointer](##nativepointer)。

### X86Writer.pc

下一个字节的程序计数器，作为 [NativePointer](##nativepointer)。

### X86Writer.offset

当前偏移量，作为 JavaScript 的 Number。

### X86Writer.putxxx()

- `putLabel(id)`: 在当前位置放置一个标签，其中 `id` 是一个字符串，可以在过去和未来的 `put*Label()` 调用中引用。
- `putCallAddressWithArguments(func, args)`: 放置调用 C 函数所需的代码，其中 `args` 是一个 JavaScript 数组，每个元素可以是指定寄存器的字符串，或指定立即数值的 Number 或 [NativePointer](##nativepointer)。
- `putCallAddressWithAlignedArguments(func, args)`: 与上面类似，但还确保参数列表按 16 字节边界对齐。
- `putCallRegWithArguments(reg, args)`: 放置调用 C 函数所需的代码，其中 `args` 是一个 JavaScript 数组，每个元素可以是指定寄存器的字符串，或指定立即数值的 Number 或 [NativePointer](##nativepointer)。
- `putCallRegWithAlignedArguments(reg, args)`: 与上面类似，但还确保参数列表按 16 字节边界对齐。
- `putCallRegOffsetPtrWithArguments(reg, offset, args)`: 放置调用 C 函数所需的代码，其中 `args` 是一个 JavaScript 数组，每个元素可以是指定寄存器的字符串，或指定立即数值的 Number 或 [NativePointer](##nativepointer)。
- `putCallAddress(address)`: 放置一个 `CALL` 指令。
- `putCallReg(reg)`: 放置一个 `CALL` 指令。
- `putCallRegOffsetPtr(reg, offset)`: 放置一个 `CALL` 指令。
- `putCallIndirect(addr)`: 放置一个 `CALL` 指令。
- `putCallIndirectLabel(labelId)`: 放置一个引用 `labelId` 的 `CALL` 指令，`labelId` 由过去或未来的 `putLabel()`定义。
- `putCallNearLabel(labelId)`: 放置一个引用 `labelId` 的 `CALL` 指令，`labelId` 由过去或未来的 `putLabel()`定义。
- `putLeave()`: 放置一个 `LEAVE` 指令。
- `putRet()`: 放置一个 `RET` 指令。
- `putRetImm(immValue)`: 放置一个 `RET` 指令。
- `putJmpAddress(address)`: 放置一个 `JMP` 指令。
- `putJmpShortLabel(labelId)`: 放置一个引用 `labelId` 的 `JMP` 指令，`labelId` 由过去或未来的 `putLabel()`定义。
- `putJmpNearLabel(labelId)`: 放置一个引用 `labelId` 的 `JMP` 指令，`labelId` 由过去或未来的 `putLabel()`定义。
- `putJmpReg(reg)`: 放置一个 `JMP` 指令。
- `putJmpRegPtr(reg)`: 放置一个 `JMP` 指令。
- `putJmpRegOffsetPtr(reg, offset)`: 放置一个 `JMP` 指令。
- `putJmpNearPtr(address)`: 放置一个 `JMP` 指令。
- `putJccShort(instructionId, target, hint)`: 放置一个 `JCC` 指令。
- `putJccNear(instructionId, target, hint)`: 放置一个 `JCC` 指令。
- `putJccShortLabel(instructionId, labelId, hint)`: 放置一个引用 `labelId` 的 `JCC` 指令，`labelId` 由过去或未来的 `putLabel()`定义。
- `putJccNearLabel(instructionId, labelId, hint)`: 放置一个引用 `labelId` 的 `JCC` 指令，`labelId` 由过去或未来的 `putLabel()`定义。
- `putAddRegImm(reg, immValue)`: 放置一个 `ADD` 指令。
- `putAddRegReg(dstReg, srcReg)`: 放置一个 `ADD` 指令。
- `putAddRegNearPtr(dstReg, srcAddress)`: 放置一个 `ADD` 指令。
- `putSubRegImm(reg, immValue)`: 放置一个 SUB 指令。
- `putSubRegReg(dstReg, srcReg)`: 放置一个 SUB 指令。
- `putSubRegNearPtr(dstReg, srcAddress)`: 放置一个 SUB 指令。
- `putIncReg(reg)`: 放置一个 INC 指令。
- `putDecReg(reg)`: 放置一个 DEC 指令。
- `putIncRegPtr(target, reg)`: 放置一个 INC 指令。
- `putDecRegPtr(target, reg)`: 放置一个 DEC 指令。
- `putLockXaddRegPtrReg(dstReg, srcReg)`: 放置一个 LOCK XADD 指令。
- `putLockCmpxchgRegPtrReg(dstReg, srcReg)`: 放置一个 LOCK CMPXCHG 指令。
- `putLockIncImm32Ptr(target)`: 放置一个 LOCK INC IMM32 指令。
- `putLockDecImm32Ptr(target)`: 放置一个 LOCK DEC IMM32 指令。
- `putAndRegReg(dstReg, srcReg)`: 放置一个 AND 指令。
- `putAndRegU32(reg, immValue)`: 放置一个 AND 指令。
- `putShlRegU8(reg, immValue)`: 放置一个 SHL 指令。
- `putShrRegU8(reg, immValue)`: 放置一个 SHR 指令。
- `putXorRegReg(dstReg, srcReg)`: 放置一个 XOR 指令。
- `putMovRegReg(dstReg, srcReg)`: 放置一个 MOV 指令。
- `putMovRegU32(dstReg, immValue)`: 放置一个 MOV 指令。
- `putMovRegU64(dstReg, immValue)`: 放置一个 MOV 指令。
- `putMovRegAddress(dstReg, address)`: 放置一个 MOV 指令。
- `putMovRegPtrU32(dstReg, immValue)`: 放置一个 MOV 指令。
- `putMovRegOffsetPtrU32(dstReg, dstOffset, immValue)`: 放置一个 MOV 指令。
- `putMovRegPtrReg(dstReg, srcReg)`: 放置一个 MOV 指令。
- `putMovRegOffsetPtrReg(dstReg, dstOffset, srcReg)`: 放置一个 MOV 指令。
- `putMovRegRegPtr(dstReg, srcReg)`: 放置一个 MOV 指令。
- `putMovRegRegOffsetPtr(dstReg, srcReg, srcOffset)`: 放置一个 MOV 指令。
- `putMovRegBaseIndexScaleOffsetPtr(dstReg, baseReg, indexReg, scale, offset)`: 放置一个 MOV 指令。
- `putMovRegNearPtr(dstReg, srcAddress)`: 放置一个 MOV 指令。
- `putMovNearPtrReg(dstAddress, srcReg)`: 放置一个 MOV 指令。
- `putMovFsU32PtrReg(fsOffset, srcReg)`: 放置一个 MOV FS 指令。
- `putMovRegFsU32Ptr(dstReg, fsOffset)`: 放置一个 MOV FS 指令。
- `putMovFsRegPtrReg(fsOffset, srcReg)`: 放置一个 MOV FS 指令。
- `putMovRegFsRegPtr(dstReg, fsOffset)`: 放置一个 MOV FS 指令。
- `putMovGsU32PtrReg(fsOffset, srcReg)`: 放置一个 MOV GS 指令。
- `putMovRegGsU32Ptr(dstReg, fsOffset)`: 放置一个 MOV GS 指令。
- `putMovGsRegPtrReg(gsOffset, srcReg)`: 放置一个 MOV GS 指令。
- `putMovRegGsRegPtr(dstReg, gsOffset)`: 放置一个 MOV GS 指令。
- `putMovqXmm0EspOffsetPtr(offset)`: 放置一个 MOVQ XMM0 ESP 指令。
- `putMovqEaxOffsetPtrXmm0(offset)`: 放置一个 MOVQ EAX XMM0 指令。
- `putMovdquXmm0EspOffsetPtr(offset)`: 放置一个 MOVDQU XMM0 ESP 指令。
- `putMovdquEaxOffsetPtrXmm0(offset)`: 放置一个 MOVDQU EAX XMM0 指令。
- `putLeaRegRegOffset(dstReg, srcReg, srcOffset)`: 放置一个 LEA 指令。
- `putXchgRegRegPtr(leftReg, rightReg)`: 放置一个 XCHG 指令。
- `putPushU32(immValue)`: 放置一个 PUSH 指令。
- `putPushNearPtr(address)`: 放置一个 PUSH 指令。
- `putPushReg(reg)`: 放置一个 PUSH 指令。
- `putPopReg(reg)`: 放置一个 POP 指令。
- `putPushImmPtr(immPtr)`: 放置一个 PUSH 指令。
- `putPushax()`: 放置一个 PUSHAX 指令。
- `putPopax()`: 放置一个 POPAX 指令。
- `putPushfx()`: 放置一个 PUSHFX 指令。
- `putPopfx()`: 放置一个 POPFX 指令。
- `putSahf()`: 放置一个 SAHF 指令。
- `putLahf()`: 放置一个 LAHF 指令。
- `putTestRegReg(regA, regB)`: 放置一个 TEST 指令。
- `putTestRegU32(reg, immValue)`: 放置一个 TEST 指令。
- `putCmpRegI32(reg, immValue)`: 放置一个 CMP 指令。
- `putCmpRegOffsetPtrReg(regA, offset, regB)`: 放置一个 CMP 指令。
- `putCmpImmPtrImmU32(immPtr, immValue)`: 放置一个 CMP 指令。
- `putCmpRegReg(regA, regB)`: 放置一个 CMP 指令。
- `putClc()`: 放置一个 CLC 指令。
- `putStc()`: 放置一个 STC 指令。
- `putCld()`: 放置一个 CLD 指令。
- `putStd()`: 放置一个 STD 指令。
- `putCpuid()`: 放置一个 CPUID 指令。
- `putLfence()`: 放置一个 LFENCE 指令。
- `putRdtsc()`: 放置一个 RDTSC 指令。
- `putPause()`: 放置一个 PAUSE 指令。
- `putNop()`: 放置一个 NOP 指令。
- `putBreakpoint()`: 放置一个特定于操作系统/架构的断点指令。
- `putPadding(n)`: 放置 n 个保护指令。
- `putNopPadding(n)`: 放置 n 个 NOP 指令。
- `putFxsaveRegPtr(reg)`: 放置一个 FXSAVE 指令。
- `putFxrstorRegPtr(reg)`: 放置一个 FXRSTOR 指令。
- `putU8(value)`: 放置一个 uint8 值。
- `putS8(value)`: 放置一个 int8 值。
- `putBytes(data)`: 从提供的 ArrayBuffer 中放置原始数据。

## X86Relocator

### new X86Relocator(inputCode, output)

创建一个新的代码重定位器，用于将 x86 指令从一个内存位置复制到另一个位置，同时调整位置相关的指令。源地址由 inputCode 指定，为一个 [NativePointer](##nativepointer)。目标地址由 output 指定，为一个指向目标内存地址的 X86Writer。

### X86Relocator.reset(inputCode, output)

重新使用实例。

### X86Relocator.dispose()

及时清理内存。

### X86Relocator.input

到目前为止读取的最新指令。开始时为 null，在每次调用 readOne()时更改。

### X86Relocator.eob

布尔值，表示是否已达到代码块的末尾，即我们已经到达了某种分支，如 CALL、JMP、BL、RET。

### X86Relocator.eoi

布尔值，表示是否已到达输入的末尾，例如我们已经到达 JMP/B/RET，在其后可能有或可能没有有效代码。

### X86Relocator.readOne()

将下一条指令读入重定位器的内部缓冲区，并返回到目前为止读取的字节数，包括之前的调用。可以继续调用此方法继续缓冲，或立即调用 writeOne()或 skipOne()。或者，可以缓冲到所需位置，然后调用 writeAll()。当达到输入末尾时返回零，这意味着 eoi 属性现在为 true。

### peekNextWriteInsn():

查看下一条要写入或跳过的指令。

### peekNextWriteSource()

查看下一条要写入或跳过的指令的地址。

### skipOne()

跳过下一个将被写入的指令。

### skipOneNoLabel()

跳过下一个将被写入的指令，但没有内部使用的标签。这会中断对重新定位范围内位置的分支重定位，是对所有分支都被重写的用例的优化（例如 Frida 的 Stalker）。

### writeOne()

写入下一个缓冲的指令。

### writeOneNoLabel()

写入下一个缓冲的指令，但没有内部使用的标签。这会中断对重新定位范围内位置的分支重定位，是对所有分支都被重写的用例的优化（例如 Frida 的 Stalker）。

### writeAll()

写入所有缓冲的指令。

## x86 枚举类型

**寄存器 (Register)**

x86 和 x86_64 架构中包含许多通用寄存器和指令指针寄存器，这些寄存器在汇编编程中经常使用。以下是对这些寄存器的详细描述：

8 位通用寄存器：

- `al, cl, dl, bl, ah, ch, dh, bh`：低 8 位寄存器。例如，al 是 eax 的低 8 位。

16 位通用寄存器：

- `ax, cx, dx, bx, sp, bp, si, di`：16 位寄存器。例如，ax 是 eax 的低 16 位。

32 位通用寄存器：

- `eax, ecx, edx, ebx, esp, ebp, esi, edi`：32 位寄存器。

64 位通用寄存器（仅适用于 x86_64 架构）：

- `rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi`：64 位寄存器。

扩展的 64 位寄存器（仅适用于 x86_64 架构）：

- `r8, r9, r10, r11, r12, r13, r14, r15`：额外的 64 位寄存器。
- 对应的低 32 位寄存器：`r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d`。

指令指针寄存器：

- `ip`：指令指针寄存器。
- `eip`：扩展指令指针寄存器（32 位）。
- `rip`：扩展指令指针寄存器（64 位）。

**指令 ID (InstructionId)**

这些指令 ID 用于表示条件跳转和循环控制指令：

条件跳转指令：

- jo：溢出时跳转（Jump if Overflow）
- jno：无溢出时跳转（Jump if Not Overflow）
- jb：无符号小于时跳转（Jump if Below）
- jae：无符号大于或等于时跳转（Jump if Above or Equal）
- je：等于时跳转（Jump if Equal）
- jne：不等于时跳转（Jump if Not Equal）
- jbe：无符号小于或等于时跳转（Jump if Below or Equal）
- ja：无符号大于时跳转（Jump if Above）
- js：符号位为 1 时跳转（Jump if Sign）
- jns：符号位为 0 时跳转（Jump if Not Sign）
- jp：奇偶标志位为 1 时跳转（Jump if Parity）
- jnp：奇偶标志位为 0 时跳转（Jump if No Parity）
- jl：有符号小于时跳转（Jump if Less）
- jge：有符号大于或等于时跳转（Jump if Greater or Equal）
- jle：有符号小于或等于时跳转（Jump if Less or Equal）
- jg：有符号大于时跳转（Jump if Greater）

循环控制指令：

- jcxz：当 CX 寄存器为零时跳转（Jump if CX is Zero）
- jecxz：当 ECX 寄存器为零时跳转（Jump if ECX is Zero）
- jrcxz：当 RCX 寄存器为零时跳转（Jump if RCX is Zero）

**分支提示 (BranchHint)**

这些提示用于分支预测，以优化代码执行：

- no-hint：没有分支提示。
- likely：分支很可能会被执行。
- unlikely：分支不太可能会被执行。

**指针目标 (PointerTarget)**

这些指针目标类型用于指示内存访问操作的目标大小：

- byte：一个字节（8 位）
- dword：一个双字（32 位）
- qword：一个四字（64 位）

## ArmWriter

ArmWriter 是用于生成 ARM 机器码并直接写入内存的工具。

### 构造函数:

### new ArmWriter(codeAddress[, { pc: ptr('0x1234') }])

创建一个新的 ARM 代码写入器，codeAddress 指定了写入内存的地址。第二个参数是一个可选的选项对象，可以指定初始程序计数器 (PC)。

### ArmWriter.reset(codeAddress[, { pc: ptr('0x1234') }])

重置实例以重用。

### ArmWriter.dispose()

立即清理内存。

### ArmWriter.flush()

解析标签引用并将未决数据写入内存。完成代码生成后应始终调用此方法。

### ArmWriter.base

输出的第一个字节的内存位置，类型为 [NativePointer](#nativepointer)。

### ArmWriter.code

下一个字节的内存位置，类型为 [NativePointer](#nativepointer)。

### ArmWriter.pc

下一个字节的程序计数器，类型为 [NativePointer](#nativepointer)。

### ArmWriter.offset

当前偏移，类型为 JavaScript 数字。

### ArmWriter.skip(nBytes)

跳过 nBytes 字节。

### ArmWriter.putxxx()

- `putLabel(id)`: 在当前位置放置一个标签，可以在过去和未来的 `put*Label()` 调用中引用。
- `putCallAddressWithArguments(func, args)`: 插入调用指定 C 函数所需的代码，args 是一个 JavaScript 数组，每个元素要么是一个寄存器字符串，要么是一个 Number 或 [NativePointer](#nativepointer)。
- `putCallReg(reg)`: 插入一个 CALL 指令。
- `putCallRegWithArguments(reg, args)`: 插入调用指定寄存器指向的函数所需的代码，args 是一个 JavaScript 数组，每个元素要么是一个寄存器字符串，要么是一个 Number 或 [NativePointer](#nativepointer)。
- `putBranchAddress(address)`: 插入跳转到指定地址的代码。
- `canBranchDirectlyBetween(from, to)`: 确定两个内存位置之间是否可以进行直接跳转。
- `putBImm(target)`: 插入一个 B 指令。
- `putBCondImm(cc, target)`: 插入一个有条件的 B 指令。
- `putBLabel(labelId)`: 插入一个引用 labelId 的 B 指令。
- `putBCondLabel(cc, labelId)`: 插入一个引用 labelId 的有条件的 B 指令。
- `putBlImm(target)`: 插入一个 BL 指令。
- `putBlxImm(target)`: 插入一个 BLX 指令。
- `putBlLabel(labelId)`: 插入一个引用 labelId 的 BL 指令。
- `putBxReg(reg)`: 插入一个 BX 指令。
- `putBlReg(reg)`: 插入一个 BL 指令。
- `putBlxReg(reg)`: 插入一个 BLX 指令。
- `putRet()`: 插入一个 RET 指令。
- `putVpushRange(firstReg, lastReg)`: 插入一个 VPUSH RANGE 指令。
- `putVpopRange(firstReg, lastReg)`: 插入一个 VPOP RANGE 指令。
- `putLdrRegAddress(reg, address)`: 插入一个 LDR 指令。
- `putLdrRegU32(reg, val)`: 插入一个 LDR 指令。
- `putLdrRegReg(dstReg, srcReg)`: 插入一个 LDR 指令。
- `putLdrRegRegOffset(dstReg, srcReg, srcOffset)`: 插入一个 LDR 指令。
- `putLdrCondRegRegOffset(cc, dstReg, srcReg, srcOffset)`: 插入一个有条件的 LDR 指令。
- `putLdmiaRegMask(reg, mask)`: 插入一个 LDMIA MASK 指令。
- `putLdmiaRegMaskWb(reg, mask)`: 插入一个 LDMIA MASK WB 指令。
- `putStrRegReg(srcReg, dstReg)`: 插入一个 STR 指令。
- `putStrRegRegOffset(srcReg, dstReg, dstOffset)`: 插入一个 STR 指令。
- `putStrCondRegRegOffset(cc, srcReg, dstReg, dstOffset)`: 插入一个有条件的 STR 指令。
- `putMovRegReg(dstReg, srcReg)`: 插入一个 MOV 指令。
- `putMovRegRegShift(dstReg, srcReg, shift, shiftValue)`: 插入一个 MOV SHIFT 指令。
- `putMovRegCpsr(reg)`: 插入一个 MOV CPSR 指令。
- `putMovCpsrReg(reg)`: 插入一个 MOV CPSR 指令。
- `putAddRegU16(dstReg, val)`: 插入一个 ADD U16 指令。
- `putAddRegU32(dstReg, val)`: 插入一个 ADD 指令。
- `putAddRegRegImm(dstReg, srcReg, immVal)`: 插入一个 ADD 指令。
- `putAddRegRegReg(dstReg, srcReg1, srcReg2)`: 插入一个 ADD 指令。
- `putAddRegRegRegShift(dstReg, srcReg1, srcReg2, shift, shiftValue)`: 插入一个 ADD SHIFT 指令。
- `putSubRegU16(dstReg, val)`: 插入一个 SUB U16 指令。
- `putSubRegU32(dstReg, val)`: 插入一个 SUB 指令。
- `putSubRegRegImm(dstReg, srcReg, immVal)`: 插入一个 SUB 指令。
- `putSubRegRegReg(dstReg, srcReg1, srcReg2)`: 插入一个 SUB 指令。
- `putRsbRegRegImm(dstReg, srcReg, immVal)`: 插入一个 RSB 指令。
- `putAndsRegRegImm(dstReg, srcReg, immVal)`: 插入一个 ANDS 指令。
- `putCmpRegImm(dstReg, immVal)`: 插入一个 CMP 指令。
- `putNop()`: 插入一个 NOP 指令。
- `putBreakpoint()`: 插入一个特定于操作系统/架构的断点指令。
- `putBrkImm(imm)`: 插入一个 BRK 指令。
- `putInstruction(insn)`: 插入一个原始指令，类型为 JavaScript 数字。
- `putBytes(data)`: 插入提供的 ArrayBuffer 中的原始数据。

## ArmRelocator

ArmRelocator 是用于将 ARM 指令从一个内存位置复制到另一个位置的工具，同时处理位置相关的指令调整。

### 构造函数:

### new ArmRelocator(inputCode, output)

创建一个新的 ARM 代码重定位器，inputCode 是一个指向源地址的 [NativePointer](#nativepointer)，output 是一个指向目标内存地址的 ArmWriter。

### ArmRelocator.reset(inputCode, output)

重置实例以重用。

### ArmRelocator.dispose()

立即清理内存。

### ArmRelocator.input

最近读取的指令，开始时为 null，每次调用 readOne() 后更改。

### ArmRelocator.eob

布尔值，指示是否已到达块的结尾，即是否已到达任何类型的分支（如 CALL、JMP、BL、RET）。

### ArmRelocator.eoi

布尔值，指示是否已到达输入的结尾，例如是否已到达 JMP/B/RET，之后可能有或没有有效代码的指令。

### ArmRelocator.readOne()

读取下一条指令到重定位器的内部缓冲区，并返回到目前为止读取的字节数，包括以前的调用。可以继续调用此方法进行缓冲，或立即调用 writeOne() 或 skipOne()。或者，可以缓冲到所需点然后调用 writeAll()。当到达输入结尾时返回零，这意味着 eoi 属性现在为真。

### ArmRelocator.peekNextWriteInsn()

查看下一条要写入或跳过的指令。

### ArmRelocator.peekNextWriteSource()

查看下一条要写入或跳过的指令的地址。

### ArmRelocator.skipOne()

跳过下一条将被写入的指令。

### ArmRelocator.writeOne()

写入下一条缓冲的指令。

### ArmRelocator.writeAll()

写入所有缓冲的指令。

## ThumbWriter

ThumbWriter 是用于生成 Thumb 机器码并直接写入内存的工具。

### new ThumbWriter(codeAddress[, { pc: ptr('0x1234') }])

创建一个新的 Thumb 代码写入器，codeAddress 指定了写入内存的地址。第二个参数是一个可选的选项对象，可以指定初始程序计数器 (PC)。

### ThumbWriter.reset(codeAddress[, { pc: ptr('0x1234') }])

重置实例以重用。

### ThumbWriter.dispose()

立即清理内存。

### ThumbWriter.flush()

解析标签引用并将未决数据写入内存。完成代码生成后应始终调用此方法。

### ThumbWriter.base

输出的第一个字节的内存位置，类型为 [NativePointer](#nativepointer)。

### ThumbWriter.code

下一个字节的内存位置，类型为 [NativePointer](#nativepointer)。

### ThumbWriter.pc

下一个字节的程序计数器，类型为 [NativePointer](#nativepointer)。

### ThumbWriter.offset

当前偏移，类型为 JavaScript 数字。

### ThumbWriter.skip(nBytes)

跳过 nBytes 字节。

### ThumbWriter.putxxx()

- `putLabel(id)`:在当前位置放置一个标签，可以在过去和未来的 put\*Label() 调用中引用。
- `commitLabel(id)`:提交给定标签的第一个未决引用，成功返回 true。如果给定标签尚未定义，或没有更多的未决引用，返回 false。
- `putCallAddressWithArguments(func, args)`:插入调用指定 C 函数所需的代码，args 是一个 JavaScript 数组，每个元素要么是一个寄存器字符串，要么是一个 Number 或 [NativePointer](#nativepointer)。
- `putCallRegWithArguments(reg, args)`:插入调用指定寄存器指向的函数所需的代码，args 是一个 JavaScript 数组，每个元素要么是一个寄存器字符串，要么是一个 Number 或 [NativePointer](#nativepointer)。
- `putBranchAddress(address)`:插入跳转到指定地址的代码。
- `canBranchDirectlyBetween(from, to)`:确定两个内存位置之间是否可以进行直接跳转。
- `putBImm(target)`:插入一个 B 指令。
- `putBLabel(labelId)`:插入一个引用 labelId 的 B 指令。
- `putBLabelWide(labelId)`:插入一个 B WIDE 指令。
- `putBxReg(reg)`:插入一个 BX 指令。
- `putBlImm(target)`:插入一个 BL 指令。
- `putBlLabel(labelId)`:插入一个引用 labelId 的 BL 指令。
- `putBlxImm(target)`:插入一个 BLX 指令。
- `putBlxReg(reg)`:插入一个 BLX 指令。
- `putCmpRegImm(reg, immValue)`:插入一个 CMP 指令。
- `putBeqLabel(labelId)`:插入一个引用 labelId 的 BEQ 指令。
- `putBneLabel(labelId)`:插入一个引用 labelId 的 BNE 指令。
- `putBCondLabel(cc, labelId)`:插入一个引用 labelId 的条件 B 指令。
- `putBCondLabelWide(cc, labelId)`:插入一个宽条件 B 指令。
- `putCbzRegLabel(reg, labelId)`:插入一个引用 labelId 的 CBZ 指令。
- `putCbnzRegLabel(reg, labelId)`:插入一个引用 labelId 的 CBNZ 指令。
- `putPushRegs(regs)`:插入一个 PUSH 指令，regs 是一个包含寄存器名称字符串的 JavaScript 数组。
- `putPopRegs(regs)`:插入一个 POP 指令，regs 是一个包含寄存器名称字符串的 JavaScript 数组。
- `putVpushRange(firstReg, lastReg)`:插入一个 VPUSH RANGE 指令。
- `putVpopRange(firstReg, lastReg)`:插入一个 VPOP RANGE 指令。
- `putLdrRegAddress(reg, address)`:插入一个 LDR 指令。
- `putLdrRegU32(reg, val)`:插入一个 LDR 指令。
- `putLdrRegReg(dstReg, srcReg)`:插入一个 LDR 指令。
- `putLdrRegRegOffset(dstReg, srcReg, srcOffset)`:插入一个 LDR 指令。
- `putLdrbRegReg(dstReg, srcReg)`:插入一个 LDRB 指令。
- `putVldrRegRegOffset(dstReg, srcReg, srcOffset)`:插入一个 VLDR 指令。
- `putLdmiaRegMask(reg, mask)`:插入一个 LDMIA MASK 指令。
- `putStrRegReg(srcReg, dstReg)`:插入一个 STR 指令。
- `putStrRegRegOffset(srcReg, dstReg, dstOffset)`:插入一个 STR 指令。
- `putMovRegReg(dstReg, srcReg)`:插入一个 MOV 指令。
- `putMovRegU8(dstReg, immValue)`:插入一个 MOV 指令。
- `putMovRegCpsr(reg)`:插入一个 MOV CPSR 指令。
- `putMovCpsrReg(reg)`:插入一个 MOV CPSR 指令。
- `putAddRegImm(dstReg, immValue)`:插入一个 ADD 指令。
- `putAddRegReg(dstReg, srcReg)`:插入一个 ADD 指令。
- `putAddRegRegReg(dstReg, leftReg, rightReg)`:插入一个 ADD 指令。
- `putAddRegRegImm(dstReg, leftReg, rightValue)`:插入一个 ADD 指令。
- `putSubRegImm(dstReg, immValue)`:插入一个 SUB 指令。
- `putSubRegReg(dstReg, srcReg)`:插入一个 SUB 指令。
- `putSubRegRegReg(dstReg, leftReg, rightReg)`:插入一个 SUB 指令。
- `putSubRegRegImm(dstReg, leftReg, rightValue)`:插入一个 SUB 指令。
- `putAndRegRegImm(dstReg, leftReg, rightValue)`:插入一个 AND 指令。
- `putOrRegRegImm(dstReg, leftReg, rightValue)`:插入一个 OR 指令。
- `putLslRegRegImm(dstReg, leftReg, rightValue)`:插入一个 LSL 指令。
- `putLslsRegRegImm(dstReg, leftReg, rightValue)`:插入一个 LSLS 指令。
- `putLsrsRegRegImm(dstReg, leftReg, rightValue)`:插入一个 LSRS 指令。
- `putMrsRegReg(dstReg, srcReg)`:插入一个 MRS 指令。
- `putMsrRegReg(dstReg, srcReg)`:插入一个 MSR 指令。
- `putNop()`:插入一个 NOP 指令。
- `putBkptImm(imm)`:插入一个 BKPT 指令。
- `putBreakpoint()`:插入一个特定于操作系统/架构的断点指令。
- `putInstruction(insn)`:插入一个原始指令，类型为 JavaScript 数字。
- `putInstructionWide(upper, lower)`:插入一个 Thumb-2 指令，由两个 JavaScript 数字值组成。
- `putBytes(data)`:插入提供的 ArrayBuffer 中的原始数据。

## ThumbRelocator

ThumbRelocator 是用于将 Thumb 指令从一个内存位置复制到另一个位置的工具，同时处理位置相关的指令调整。

### 构造函数:

### new ThumbRelocator(inputCode, output)

创建一个新的 Thumb 代码重定位器，inputCode 是一个指向源地址的 [NativePointer](#nativepointer)，output 是一个指向目标内存地址的 ThumbWriter。

### 方法:

### ThumbRelocator.reset(inputCode, output)

重置实例以重用。

### ThumbRelocator.dispose()

立即清理内存。

### ThumbRelocator.input

最近读取的指令，开始时为 null，每次调用 readOne() 后更改。

### ThumbRelocator.eob

布尔值，指示是否已到达块的结尾，即是否已到达任何类型的分支（如 CALL、JMP、BL、RET）。

### ThumbRelocator.eoi

布尔值，指示是否已到达输入的结尾，例如是否已到达 JMP/B/RET，之后可能有或没有有效代码的指令。

### ThumbRelocator.readOne()

读取下一条指令到重定位器的内部缓冲区，并返回到目前为止读取的字节数，包括以前的调用。可以继续调用此方法以继续缓冲，或立即调用 writeOne() 或 skipOne()。或者，可以缓冲到所需点然后调用 writeAll()。当到达输入结束时返回零，这意味着 eoi 属性现在为 true。

### ThumbRelocator.peekNextWriteInsn()

查看下一条要写入或跳过的指令。

### ThumbRelocator.peekNextWriteSource()

查看下一条要写入或跳过的指令的地址。

### ThumbRelocator.skipOne()

跳过下一个要写入的指令。

### ThumbRelocator.writeOne()

写入下一条缓冲的指令。

### ThumbRelocator.copyOne()

复制下一条缓冲的指令而不推进输出光标，允许多次写出相同的指令。

### ThumbRelocator.writeAll()

写出所有缓冲的指令。

## ARM 枚举类型

- 寄存器 (Register)

- 通用寄存器：
- `r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15`
- 别名：
  - `sp`（堆栈指针，对应 r13）
  - `lr`（链接寄存器，对应 r14）
  - `pc`（程序计数器，对应 r15）
  - `sb`（静态基址寄存器，一般是 r9）
  - `sl`（栈限寄存器，一般是 r10）
  - `fp`（帧指针，一般是 r11）
  - `ip`（临时寄存器，一般是 r12）

浮点和向量寄存器：

- 单精度寄存器：`s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31`
- 双精度寄存器：`d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27, d28, d29, d30, d31`
- 四精度寄存器：`q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15`

系统寄存器 (SystemRegister)

- `apsr-nzcvq`：应用程序状态寄存器的 `N、Z、C、V、Q` 位。

条件码 (ConditionCode)

- eq: 等于（Equal）
- ne: 不等于（Not equal）
- hs: 无符号高于或相等（Unsigned higher or same）
- lo: 无符号低于（Unsigned lower）
- mi: 负数（Minus）
- pl: 正数或零（Plus）
- vs: 溢出（Overflow）
- vc: 无溢出（No overflow）
- hi: 无符号高于（Unsigned higher）
- ls: 无符号低于或相等（Unsigned lower or same）
- ge: 有符号大于或相等（Signed greater or equal）
- lt: 有符号小于（Signed less）
- gt: 有符号大于（Signed greater）
- le: 有符号小于或相等（Signed less or equal）
- al: 总是（Always）

移位操作符 (Shifter)

立即数移位：

- asr：算术右移
- lsl：逻辑左移
- lsr：逻辑右移
- ror：循环右移
- rrx：带扩展的右移

寄存器移位：

- asr-reg：算术右移（寄存器）
- lsl-reg：逻辑左移（寄存器）
- lsr-reg：逻辑右移（寄存器）
- ror-reg：循环右移（寄存器）
- rrx-reg：带扩展的右移（寄存器）

## Arm64Writer

Arm64Writer 是一个用于直接在内存中生成 AArch64 机器代码的类。它提供了一组方法，用于放置各种指令和管理代码生成过程。

### new Arm64Writer(codeAddress[, { pc: ptr('0x1234') }]):

创建一个新的代码写入器，用于在指定的 codeAddress 处生成 AArch64 机器代码。可选的 pc 参数指定初始程序计数器，这在生成临时缓冲区中的代码时非常有用。

### Arm64Writer.reset(codeAddress[, { pc: ptr('0x1234') }]):

重置实例以重新使用新代码地址。

### Arm64Writer.dispose():

立即清理内存。

### Arm64Writer.flush():

解析标签引用并将待定数据写入内存。一旦生成代码完成，您应始终调用此方法。

### Arm64Writer.skip(nBytes):

跳过 nBytes 字节。

### Arm64Writer.base:

输出的第一个字节的内存位置，类型为 [NativePointer](#nativepointer)。

### Arm64Writer.code:

输出的下一个字节的内存位置，类型为 [NativePointer](#nativepointer)。

### Arm64Writer.pc:

输出的下一个字节的程序计数器，类型为 [NativePointer](#nativepointer)。

### Arm64Writer.offset:

当前偏移量，类型为 JavaScript Number。

### Arm64Writer.putxxx()

- `putLabel(id)`: 在当前位置放置一个标签。
- `putCallAddressWithArguments(func, args)`:放置调用指定 C 函数所需的代码，参数由 args 指定。
- `putCallRegWithArguments(reg, args)`:放置调用指定寄存器中的 C 函数所需的代码，参数由 args 指定。
- `putBranchAddress(address)`:放置跳转到给定地址所需的代码。
- `canBranchDirectlyBetween(from, to)`:确定在两个给定的内存位置之间是否可以进行直接跳转。
- `putBImm(address)`:放置 B 指令。
- `putBLabel(labelId)`:放置引用标签的 B 指令。
- `putBCondLabel(cc, labelId)`:放置引用标签的条件 B 指令。
- `putBlImm(address)`:放置 BL 指令。
- `putBlLabel(labelId)`:放置引用标签的 BL 指令。
- `putBrReg(reg)`:放置 BR 指令。
- `putBrRegNoAuth(reg)`:放置不需要认证位的原始指针 BR 指令。
- `putBlrReg(reg)`:放置 BLR 指令。
- `putBlrRegNoAuth(reg)`:放置不需要认证位的原始指针 BLR 指令。
- `putRet()`:放置 RET 指令。
- `putRetReg(reg)`:放置使用指定寄存器的 RET 指令。
- `putCbzRegImm(reg, target)`:放置 CBZ 指令。
- `putCbnzRegImm(reg, target)`:放置 CBNZ 指令。
- `putCbzRegLabel(reg, labelId)`:放置引用标签的 CBZ 指令。
- `putCbnzRegLabel(reg, labelId)`:放置引用标签的 CBNZ 指令。
- `putTbzRegImmImm(reg, bit, target)`:放置 TBZ 指令。
- `putTbnzRegImmImm(reg, bit, target)`:放置 TBNZ 指令。
- `putTbzRegImmLabel(reg, bit, labelId)`:放置引用标签的 TBZ 指令。
- `putTbnzRegImmLabel(reg, bit, labelId)`:放置引用标签的 TBNZ 指令。
- `putPushRegReg(regA, regB)`:放置 PUSH 指令。
- `putPopRegReg(regA, regB)`:放置 POP 指令。
- `putPushAllXRegisters()`:放置将所有 X 寄存器压入堆栈的代码。
- `putPopAllXRegisters()`:放置从堆栈中弹出所有 X 寄存器的代码。
- `putPushAllQRegisters()`:放置将所有 Q 寄存器压入堆栈的代码。
- `putPopAllQRegisters()`:放置从堆栈中弹出所有 Q 寄存器的代码。
- `putLdrRegAddress(reg, address)`:放置 LDR 指令。
- `putLdrRegU32(reg, val)`:放置带有 32 位值的 LDR 指令。
- `putLdrRegU64(reg, val)`:放置带有 64 位值的 LDR 指令。
- `putLdrRegU32Ptr(reg, srcAddress)`:放置从指定地址读取 32 位值的 LDR 指令。
- `putLdrRegU64Ptr(reg, srcAddress)`:放置从指定地址读取 64 位值的 LDR 指令。
- `putLdrRegRef(reg)`:放置带有悬空数据引用的 LDR 指令，并返回一个不透明的引用值。

示例代码

以下是使用 Arm64Writer 生成简单 AArch64 指令的示例代码：

```javascript
const writer = new Arm64Writer(ptr("0x1000"));
writer.putLabel("start");
writer.putBImm(ptr("0x2000"));
writer.putRet();
writer.flush();
```

这个示例代码在内存地址 0x1000 处生成一段简单的 AArch64 代码，其中包含一个跳转指令和一个返回指令。

## Arm64Relocator 方法

### new Arm64Relocator(inputCode, output)

### Arm64Relocator.reset(inputCode, output)

重置输入代码和输出目标。

### Arm64Relocator.dispose()

释放资源。

### Arm64Relocator.input: Instruction

当前输入指令。

### Arm64Relocator.eob

是否到达代码结尾。

### Arm64Relocator.eoi

是否到达指令结尾。

### Arm64Relocator.readOne()

读取下一条指令。

### Arm64Relocator.peekNextWriteInsn()

查看下一条要写入的指令。

### Arm64Relocator.peekNextWriteSource()

查看下一条要写入指令的源地址。

### Arm64Relocator.skipOne()

跳过当前指令。

### Arm64Relocator.writeOne()

写入当前指令。

### Arm64Relocator.writeAll()

写入所有指令。

## AArch64 枚举类型

### 寄存器 (Register)

通用寄存器：

- `x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30`
- w 寄存器（32 位）：`w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15, w16, w17, w18, w19, w20, w21, w22, w23, w24, w25, w26, w27, w28, w29, w30`

### 特殊寄存器：

- sp（堆栈指针）
- lr（链接寄存器）
- fp（帧指针）
- wsp（堆栈指针的 32 位版本）
- wzr（32 位零寄存器）
- xzr（64 位零寄存器）
- nzcv（条件标志寄存器）
- ip0, ip1（临时寄存器）

### 浮点和向量寄存器：

- 单精度寄存器：`s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31`
- 双精度寄存器：`d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27, d28, d29, d30, d31`
- 四精度寄存器：`q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15, q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29, q30, q31`

### 条件码 (ConditionCode)

- eq: 等于（Equal）
- ne: 不等于（Not equal）
- hs: 无符号高于或相等（Unsigned higher or same）
- lo: 无符号低于（Unsigned lower）
- mi: 负数（Minus）
- pl: 正数或零（Plus）
- vs: 溢出（Overflow）
- vc: 无溢出（No overflow）
- hi: 无符号高于（Unsigned higher）
- ls: 无符号低于或相等（Unsigned lower or same）
- ge: 有符号大于或相等（Signed greater or equal）
- lt: 有符号小于（Signed less）
- gt: 有符号大于（Signed greater）
- le: 有符号小于或相等（Signed less or equal）
- al: 总是（Always）
- nv: 从不（Never）

### 索引模式 (IndexMode)

- post-adjust: 后调整
- signed-offset: 带符号偏移
- pre-adjust: 前调整

## MipsWriter

### new MipsWriter(codeAddress[, { pc: ptr('0x1234') }])

创建一个新的代码写入器，用于生成直接写入内存的 MIPS 机器码。codeAddress 是一个 [NativePointer](#nativepointer) 类型的内存地址。可选的第二个参数是一个对象，其中可以指定初始程序计数器，这在生成到临时缓冲区时非常有用。对于在 iOS 上使用 Memory.patchCode() 的情况尤其重要，因为它可能会提供一个临时位置，稍后映射到目标内存位置。

### MipsWriter.reset(codeAddress[, { pc: ptr('0x1234') }])

重置实例。

### MipsWriter.dispose()

提前清理内存。

### MipsWriter.flush()

解析标签引用并将待处理的数据写入内存。完成代码生成后应始终调用此方法。在生成多个函数时，在生成不相关的代码段之间调用此方法也是理想的。

### MipsWriter.base: [NativePointer](#nativepointer)

输出的第一个字节的内存位置。

### MipsWriter.code: [NativePointer](#nativepointer)

下一个输出字节的内存位置。

### MipsWriter.pc: [NativePointer](#nativepointer)

下一个输出字节的程序计数器。

### MipsWriter.offset: Number

当前偏移量。

### MipsWriter.skip(nBytes)

跳过 n 个字节。

### MipsWriter.putxxx()

- `putLabel(id)`:在当前位置放置一个标签，id 是一个可以在过去和将来的 `put*Label()` 调用中引用的字符串。
- `putCallAddressWithArguments(func, args)`:生成调用指定 C 函数的代码，args 是一个 JavaScript 数组，其中每个元素要么是一个指定寄存器的字符串，要么是一个指定立即值的数字或 [NativePointer](#nativepointer)。
- `putCallRegWithArguments(reg, args)`:生成调用寄存器指定函数的代码，args 是一个 JavaScript 数组，其中每个元素要么是一个指定寄存器的字符串，要么是一个指定立即值的数字或 [NativePointer](#nativepointer)。
- `putJAddress(address)`:生成 J 指令。
- `putJAddressWithoutNop(address)`:生成不带 NOP 的 J 指令。
- `putJLabel(labelId)`:生成 J 指令并引用标签。
- `putJrReg(reg)`:生成 JR 指令。
- `putJalAddress(address)`:生成 JAL 指令。
- `putJalrReg(reg)`:生成 JALR 指令。
- `putBOffset(offset)`:生成 B 指令。
- `putBeqRegRegLabel(rightReg, leftReg, labelId)`:生成 BEQ 指令并引用标签。
- `putRet()`:生成 RET 指令。
- `putLaRegAddress(reg, address)`:生成 LA 指令。
- `putLuiRegImm(reg, imm)`:生成 LUI 指令。
- `putDsllRegReg(dstReg, srcReg, amount)`:生成 DSLL 指令。
- `putOriRegRegImm(rt, rs, imm)`:生成 ORI 指令。
- `putLdRegRegOffset(dstReg, srcReg, srcOffset)`:生成 LD 指令。
- `putLwRegRegOffset(dstReg, srcReg, srcOffset)`:生成 LW 指令。
- `putSwRegRegOffset(srcReg, dstReg, dstOffset)`:生成 SW 指令。
- `putMoveRegReg(dstReg, srcReg)`:生成 MOVE 指令。
- `putAdduRegRegReg(dstReg, leftReg, rightReg)`:生成 ADDU 指令。
- `putAddiRegRegImm(dstReg, leftReg, imm)`:生成 ADDI 指令。
- `putAddiRegImm(dstReg, imm)`:生成 ADDI 指令。
- `putSubRegRegImm(dstReg, leftReg, imm)`:生成 SUB 指令。
- `putPushReg(reg)`:生成 PUSH 指令。
- `putPopReg(reg)`:生成 POP 指令。
- `putMfhiReg(reg)`:生成 MFHI 指令。
- `putMfloReg(reg)`:生成 MFLO 指令。
- `putMthiReg(reg)`:生成 MTHI 指令。
- `putMtloReg(reg)`:生成 MTLO 指令。
- `putNop()`:生成 NOP 指令。
- `putBreak()`:生成 BREAK 指令。
- `putPrologueTrampoline(reg, address)`:生成一个最小大小的跳板，向量到给定地址。
- `putInstruction(insn)`:直接放置机器指令。
- `putBytes(data)`:从提供的 ArrayBuffer 放置原始数据。

## MipsRelocator

### new MipsRelocator(inputCode, output)

创建一个新的代码重定位器，用于将 MIPS 指令从一个内存位置复制到另一个内存位置，注意调整与位置相关的指令。源地址由 inputCode 指定，目标地址由指向目标内存地址的 MipsWriter 给出。

### MipsRelocator.reset(inputCode, output)

重置实例。

### MipsRelocator.dispose()

提前清理内存。

### MipsRelocator.input: Instruction

到目前为止读取的最新指令。开始为 null，每次调用 readOne() 时更改。

### MipsRelocator.eob: boolean

指示是否到达代码块末尾，例如到达任何类型的分支（如 CALL、JMP、BL、RET）。

### MipsRelocator.eoi: boolean

指示是否到达输入末尾，例如到达 JMP/B/RET，在这些指令之后可能有也可能没有有效代码。

### MipsRelocator.readOne()

将下一条指令读入重定位器的内部缓冲区，并返回到目前为止读取的字节数，包括先前的调用。可以继续调用此方法以继续缓冲，或者立即调用 writeOne() 或 skipOne()。或者，可以缓冲到所需点然后调用 writeAll()。当到达输入末尾时返回零，这意味着 eoi 属性现在为真。

### MipsRelocator.peekNextWriteInsn()

查看下一条要写入或跳过的指令。

### MipsRelocator.peekNextWriteSource()

查看下一条要写入或跳过指令的地址。

### MipsRelocator.skipOne()

跳过将要写入的下一条指令。

### MipsRelocator.writeOne()

写入下一条缓冲的指令。

### MipsRelocator.writeAll()

写入所有缓冲的指令。

## MIPS 枚举类型

### 寄存器

MIPS 架构中使用的寄存器枚举类型如下：

### 通用寄存器：

- v0, v1 - 返回值寄存器。
- a0, a1, a2, a3 - 参数寄存器。
- t0, t1, t2, t3, t4, t5, t6, t7 - 临时寄存器，不保留调用者的值。
- s0, s1, s2, s3, s4, s5, s6, s7 - 保存寄存器，保留调用者的值。
- t8, t9 - 额外的临时寄存器。
- k0, k1 - 保留给操作系统内核使用的寄存器。
- gp - 全局指针寄存器。
- sp - 堆栈指针寄存器。
- fp - 帧指针寄存器（有时也称为 s8）。
- s8 - 保存寄存器（在一些编译器中作为帧指针）。
- ra - 返回地址寄存器。

### 特殊寄存器：

- hi - 乘法和除法操作的高位结果寄存器。
- lo - 乘法和除法操作的低位结果寄存器。

### 零寄存器：

- zero - 常量零寄存器。

### 汇编器临时寄存器：

- at - 汇编器临时寄存器。

### 数字寄存器：

- 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 - 用于索引表示的寄存器。

# Other

## console

### console.log(line), console.warn(line), console.error(line)：

这些方法用于将 line 写入基于 Frida 的应用程序的控制台。
输出的具体行为取决于 frida-core 的集成方式。例如，使用 frida-python 时，输出会进入 stdout 或 stderr；使用 frida-qml 时，会进入 qDebug 等。

参数：

- 如果传入的是 ArrayBuffer 对象，则会被替换为使用默认选项生成的 hexdump 结果。

## hexdump

### hexdump(target[, options])：

从提供的 ArrayBuffer 或 [NativePointer](#nativepointer) `target` 生成十六进制转储，选项 `options` 可用于自定义输出。

- `offset (number, default: 0)`：从目标数据的哪个字节开始转储。
- `length (number, default: data.length - offset)`：要转储的字节数。
- `header (boolean, default: true)`：是否包含偏移量的列头。
- `ansi (boolean, default: false)`：是否使用 ANSI 颜色编码输出。

示例：

```javascript
const libc = Module.findBaseAddress("libc.so");
console.log(
  hexdump(libc, {
    offset: 0,
    length: 64,
    header: true,
    ansi: true,
  })
);
```

```bash
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010  03 00 28 00 01 00 00 00 00 00 00 00 34 00 00 00  ..(.........4...
00000020  34 a8 04 00 00 00 00 05 34 00 20 00 08 00 28 00  4.......4. ...(.
00000030  1e 00 1d 00 06 00 00 00 34 00 00 00 34 00 00 00  ........4...4...
```

## 简写

- `int64(v)`：简写，用于 new Int64(v)
- `uint64(v)`：简写，用于 new UInt64(v)
- `ptr(s)`：简写，用于 new [NativePointer](#nativepointer)(s)
- `NULL`：简写，用于 ptr("0")

## 主机与注入进程之间的通信

### recv([type, ]callback)：

请求在从基于 Frida 的应用程序接收到下一个消息时调用 `callback`。

- `type`（可选）：一个字符串，指定消息类型。
- `callback`：一个函数，当接收到消息时调用。该函数接受两个参数：

  - `message`：接收到的消息，是一个 JavaScript 对象。
  - d`ata`：如果有二进制数据与消息一起传递，则为一个 ArrayBuffer，否则为 null。

这只能接收一个消息，因此需要再次调用 `recv()` 来接收下一个消息。

### send(message[, data])：

发送 JavaScript 对象 `message` 到你的 Frida 应用程序（必须可序列化为 JSON）。如果你有一些原始二进制数据希望一起发送，例如你使用 [NativePointer](#nativepointer)#readByteArray 转储了一些内存，可以通过可选参数 `data` 传递。这个参数必须是 ArrayBuffer 或一个包含 0 到 255 之间整数的数组。

**性能考虑**

虽然 `send()` 是异步的，但发送单个消息的总开销没有针对高频率进行优化，这意味着 Frida 让你决定是否将多个值批处理到一个 `send()` 调用中，取决于是否需要低延迟或高吞吐量。

### rpc.exports：

`rpc.exports` 是一个空对象，可以替换或插入以向应用程序公开 RPC 风格的 API。键指定方法名，值是你导出的函数。这个函数可以返回一个普通值以立即返回给调用者，或者返回一个 Promise 以异步返回。

示例：

```javascript
rpc.exports = {
  add(a, b) {
    return a + b;
  },
  sub(a, b) {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(a - b);
      }, 100);
    });
  },
};
```

在使用 Node.js 绑定的应用程序中，这个 API 将如下使用：

```javascript
const frida = require("frida");
const fs = require("fs");
const path = require("path");
const util = require("util");

const readFile = util.promisify(fs.readFile);

let session, script;
async function run() {
  const source = await readFile(path.join(__dirname, "_agent.js"), "utf8");
  session = await frida.attach("iTunes");
  script = await session.createScript(source);
  script.message.connect(onMessage);
  await script.load();
  console.log(await script.exports.add(2, 3));
  console.log(await script.exports.sub(5, 3));
}

run().catch(onError);

function onError(error) {
  console.error(error.stack);
}

function onMessage(message, data) {
  if (message.type === "send") {
    console.log(message.payload);
  } else if (message.type === "error") {
    console.error(message.stack);
  }
}
```

Python 版本的实现非常相似：

```python

import codecs
import frida

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

session = frida.attach('iTunes')
with codecs.open('./agent.js', 'r', 'utf-8') as f:
    source = f.read()
script = session.create_script(source)
script.on('message', on_message)
script.load()
print(script.exports.add(2, 3))
print(script.exports.sub(5, 3))
session.detach()
```

在上述示例中，我们使用 `script.on('message', on_message)` 监控来自注入进程的任何消息。此外，还可以在 script 和 session 上监控其他通知。如果希望在目标进程退出时收到通知，可以使用 `session.on('detached', your_function)`。

## 计时事件

### setTimeout(func, delay[, ...parameters])：

在 `delay` 毫秒后调用 `func`，可以选择传递一个或多个参数。返回一个 `ID`，可以传递给 `clearTimeout` 来取消它。

### clearTimeout(id)：

取消由 `setTimeout` 调用返回的 `id`。

### setInterval(func, delay[, ...parameters])：

每隔 `delay` 毫秒调用 `func`，可以选择传递一个或多个参数。返回一个 `ID`，可以传递给 `clearInterval` 来取消它。

### clearInterval(id)：

取消由 `setInterval` 调用返回的 `id`。

### setImmediate(func[, ...parameters])：

尽快在 Frida 的 JavaScript 线程上调用 `func`，可以选择传递一个或多个参数。返回一个 ID，可以传递给 `clearImmediate` 来取消它。

### clearImmediate(id)：

取消由 `setImmediate` 调用返回的 `id`。

## 垃圾回收

### gc()：

强制垃圾回收。对于测试特别有用，特别是涉及 `Script.bindWeak(`) 的逻辑。

## Worker

Worker 脚本具有自己的 JavaScript 堆、锁等。

这对于将繁重的处理移到后台线程非常有用，从而允许及时处理钩子。

### new Worker(url[, options])：

创建一个新的 `worker`，在指定的 `url` 处执行脚本。

- `url`: 指定要执行的脚本的 URL。通常通过模块导出其 `import.meta.url` 来获取。
- `options`: 可选的对象，可能包含以下键：
  - `onMessage`: 当工作线程通过 send() 发送消息时调用的函数。回调签名与 `recv()` 相同。

### terminate()：

终止 `worker`。

### post(message[, data])：

向工作线程发送消息。签名与 `send()` 相同。在工作线程内部使用 `recv()` 接收消息。

- `message`: 要发送的消息。
- `data`: 可选的数据。

### exports

用于调用 `worker` 定义的 `rpc.exports` 的魔法代理对象。每个函数返回一个 Promise，你可以在异步函数中等待它。
