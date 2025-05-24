Most IDA users probably run IDA as a stand-alone application and use the UI to configure various options. However, it is possible to pass command-line options to it to automate some parts of the process. The [full set of options](https://hex-rays.com/products/ida/support/idadoc/417.shtml) is quite long so we’ll cover the more common and useful ones.  
大多数 IDA 用户可能将 IDA 作为独立应用程序运行，并使用用户界面配置各种选项。不过，也可以向 IDA 传递命令行选项，以自动完成某些部分的操作。全套选项相当长，因此我们将介绍比较常用和有用的选项。

In the examples below, `ida` can be replaced by `ida64` for 64-bit files, or `idat` (`idat64`) for console (text-mode) UI.  
在下面的示例中，对于 64 位文件，可以用 `ida64` 代替 `ida` ；对于控制台（文本模式）用户界面，可以用 `idat` ( `idat64` ) 代替 `ida` 。

### Simply open a file in IDA  
在 IDA 中打开一个文件

`ida <filename>`

`<filename>` can be a new file that you want to disassemble or an existing database. This usage is basically the same as using File > Open or dropping the file onto IDA’s icon. You still need to manually confirm the options in the Load File dialog or any other prompts that IDA displays, but the initial splash screen is skipped.  
`<filename>` 可以是要反汇编的新文件，也可以是现有的数据库。这种用法与使用 "文件">"打开 "或将文件拖放到 IDA 图标上的方法基本相同。你仍然需要手动确认 "加载文件 "对话框或 IDA 显示的任何其他提示中的选项，但跳过了初始闪屏。

If you use any additional command-line options, make sure to put them _before_ the filename or they’ll be ignored.  
如果使用其他命令行选项，请确保将其放在文件名之前，否则会被忽略。

### Open a file and auto-select a loader  
打开文件并自动选择加载器

`ida -T<prefix> <filename>`

Where `<prefix>` is a _unique_ prefix of the loader description shown in the Load file dialog. For example, when loading a .NET executable, IDA proposes the following options:  
其中 `<prefix>` 是加载文件对话框中显示的加载器描述的唯一前缀。例如，加载 .NET 可执行文件时，IDA 会提供以下选项：

-   Microsoft.Net assembly Microsoft.Net 程序集
-   Portable executable for AMD64 (PE)  
    用于 AMD64 的可移植可执行文件 (PE)
-   MS-DOS executable (EXE) MS-DOS 可执行文件 (EXE)
-   Binary file 二进制文件

For each of them, the corresponding`-T` option could be:  
对于每一个文件，相应的 `-T` 选项可以是：

-   `-TMicrosoft`
-   `-TPortable`
-   `-TMS`
-   `-TBinary`

When the prefix contains a space, use quotes. For example, to load the first slice from a fat Mach-O file:  
当前缀包含空格时，使用引号。例如，从胖 Mach-O 文件加载第一个片段：

`ida "-TFat Mach-O File, 1" file.macho`

In case of archive formats like ZIP, you can specify the archive member to load after a colon (and additional loader names nested as needed). For example, to load the main dex file from an .apk (which is a zip file):  
对于 ZIP 等压缩包格式，您可以在冒号后指定要加载的压缩包成员（以及根据需要嵌套的附加加载器名称）。例如，从 .apk（zip 文件）中加载主 dex 文件：

`ida -TZIP:classes.dex:Android file.apk`

However, it is usually better to pick the APK loader at the top level (especially in the case of multi-dex files)  
不过，通常最好在顶层选择 APK 加载器（尤其是在多 dex 文件的情况下）

`ida -TAPK file.apk`

When `-T` is specified, the initial load dialog is skipped and IDA proceeds directly to loading the file using the specified loader (but any additional prompts may still be shown).  
当指定 `-T` 时，将跳过初始加载对话框，IDA 将直接使用指定的加载器加载文件（但仍可能显示任何附加提示）。

### Auto-accept any prompts, informational messages or warnings  
自动接受任何提示、信息或警告

Sometimes you just want to load the file and simply accept all default settings. In such case you can use the -A switch:  
有时，你只想加载文件并接受所有默认设置。在这种情况下，可以使用 -A 开关：

`ida -A <filename>`

This will load the file using _autonomous,_ or _batch,_ mode, where IDA will not display any dialog but accept the default answer in all cases.  
这将使用自主或批处理模式加载文件，在这种情况下，IDA 不会显示任何对话框，而是接受所有情况下的默认答案。

In this mode **no** interactive dialogs will show up after loading is finished (e.g not even “Rename” or “Add comment”). To restore interactivity, execute [`batch(0)`](https://hex-rays.com/products/ida/support/idadoc/287.shtml) statement in the IDC or Python console at the bottom of IDA’s window.  
在此模式下，加载完成后将不会显示交互式对话框（例如，甚至不会显示 "重命名 "或 "添加注释"）。要恢复交互性，请在 IDA 窗口底部的 IDC 或 Python 控制台中执行 `batch(0)` 语句。

### Batch disassembly 批量反汇编

This is an extension of the previous section and is invoked using the -B switch:  
这是上节的扩展，使用 -B 开关调用：

`ida -B <filename>`

IDA will load the file using all default options, wait for the end of auto-analysis, output the disassembly to `<filename>.asm` and exit after saving the database.  
IDA 将使用所有默认选项加载文件，等待自动分析结束，将反汇编输出到 `<filename>.asm` 并在保存数据库后退出。

### Binary file options 二进制文件选项

When loading raw binary files, IDA cannot use any of the metadata that is present in higher-level file formats like ELF, PE or Mach-O. In particular, the _processor type_ and _loading address_ cannot be deduced from the file and have to be provided by the user. To speed up your workflow, you can specify them on the command line:  
加载原始二进制文件时，IDA 无法使用 ELF、PE 或 Mach-O 等高级文件格式中的任何元数据。特别是，处理器类型和加载地址无法从文件中推导出来，必须由用户提供。为加快工作流程，您可以在命令行中指定它们：

`ida -p<processor> -B<base> <filename>`

`<processor>` is one of the [processor types](https://hex-rays.com/products/ida/support/idadoc/618.shtml) supported by IDA.  Some processors also support options after a colon.  
0# 是 IDA 支持的处理器类型之一。有些处理器还支持冒号后的选项。

`<base>` is the hexadecimal load base _in paragraphs_ (16-byte quantities). In practice, it means that you should remove the last zero from the full address.  
`<base>` 是以段落为单位的十六进制加载基数（16 字节量）。在实际操作中，这意味着应从完整地址中去掉最后一个零。

For example, to load a big-endian MIPS firmware at linear address 0xBFC00000:  
例如，要在线性地址 0xBFC00000 加载一个大二进制 MIPS 固件：

`ida -pmipsb -bBFC0000 firmware.bin`

A Cortex-M3 firmware mapped at 0x4000:  
映射到 0x4000 的 Cortex-M3 固件：

`ida -parm:ARMv7-M -b400 firmware.bin`

### Logging 记录

When IDA is running autonomously, you may miss the messages that are usually printed in the Output window but they may contain important informational messages, errors, or warnings. To keep a copy of the messages you can use the `-L` switch:  
当 IDA 自主运行时，您可能会错过通常打印在 "输出 "窗口中的信息，但它们可能包含重要的信息、错误或警告。要保留信息副本，可以使用 `-L` 开关：

`ida -B -Lida_batch.log <filename>`