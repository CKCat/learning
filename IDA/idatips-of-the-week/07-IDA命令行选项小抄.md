大多数 IDA 用户可能都是将 IDA 作为独立应用运行，并通过 UI 配置各种选项。然而，你也可以通过命令行参数传递选项，从而自动化部分流程。[完整的选项列表](https://hex-rays.com/products/ida/support/idadoc/417.shtml)很长，这里我们只介绍一些更常用、更实用的选项。

在下面的示例中：

- `ida` 可替换为 `ida64`（用于 64 位文件）
- 或 `idat/idat64`（用于控制台/文本模式 UI）

### 直接在 IDA 中打开文件

```bash
ida <filename>
```

`ida <filename>`

`<filename>` 可以是你想反汇编的新文件，也可以是已有的数据库。这种用法基本等同于 `File > Open` 或将文件拖到 IDA 图标上。你仍需手动确认“加载文件”对话框中的选项或其他提示，但会跳过启动画面。

注意：如果使用额外的命令行选项，请务必放在文件名之前，否则会被忽略。

### 打开文件并自动选择加载器

```bash
ida -T<prefix> <filename>
```

`<prefix>` 是“加载文件”对话框中加载器描述的唯一前缀。

例如，加载一个 `.NET` 可执行文件时，IDA 会提供以下选项：

- Microsoft.Net assembly
- Portable executable for AMD64 (PE)
- MS-DOS executable (EXE)

Binary file

对应的 -T 参数可以是：

- `-TMicrosoft`
- `-TPortable`
- `-TMS`
- `-TBinary`

如果前缀中包含空格，请使用引号，例如：

```bash
ida "-TFat Mach-O File, 1" file.macho
```

对于 ZIP 等归档格式，可以在冒号后指定要加载的成员（必要时可嵌套更多加载器名）：

```bash
ida -TZIP:classes.dex:Android file.apk
```

不过，对于 APK（尤其是 multi-dex 文件），通常建议直接在顶层选择 APK 加载器：

```bash
ida -TAPK file.apk
```

使用 `-T` 时，会跳过初始加载对话框，直接用指定加载器加载文件（但可能仍会出现其他提示）。

### 自动接受所有提示、信息或警告

如果你只想加载文件并接受所有默认设置，可以使用 `-A` 开关：

```bash
ida -A <filename>
```

这会以自动（批处理）模式加载文件，IDA 不会显示任何对话框，而是直接使用默认答案。

在此模式下，加载完成后不会出现任何交互式对话框（例如“重命名”或“添加注释”）。如需恢复交互，可在 IDC 或 Python 控制台中执行 `batch(0)` 语句。

### 批处理反汇编

这是前一节的扩展，用 `-B` 开关调用：

```bash
ida -B <filename>
```

IDA 会使用所有默认选项加载文件，等待自动分析结束，将反汇编输出到 `<filename>.asm`，并在保存数据库后退出。

### 二进制文件选项

加载原始二进制文件时，IDA 无法利用 ELF、PE、Mach-O 等高级格式中的元数据。特别是处理器类型和加载地址无法从文件推断，必须由用户提供。

你可以在命令行中指定它们以加快流程：

```bash
ida -p<processor> -b<base> <filename>
```

- `<processor>` 是 IDA 支持的[处理器类型](https://hex-rays.com/products/ida/support/idadoc/618.shtml)，有些处理器在冒号后还支持额外选项
- `<base>` 是十六进制加载基址，以段落（16 字节）为单位
  - 实际上就是去掉完整地址的最后一个零

示例：

加载一个大端 MIPS 固件到线性地址 0xBFC00000：

```bash
ida -pmipsb -bBFC0000 firmware.bin
```

加载映射到 0x4000 的 Cortex-M3 固件：

```bash
ida -parm:ARMv7-M -b400 firmware.bin
```

### 日志记录

在自动模式下，你可能会错过通常显示在“输出”窗口中的信息、错误或警告。可以用 `-L` 开关将这些消息保存到文件：

```bash
ida -B -Lida_batch.log <filename>
```
原文地址：https://hex-rays.com/blog/igor-tip-of-the-week-07-ida-command-line-options-cheatsheet