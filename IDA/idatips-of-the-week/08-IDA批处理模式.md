We’ve briefly covered batch mode [last time](https://hex-rays.com/blog/igor-tip-of-the-week-07-ida-command-line-options-cheatsheet/) but the basic functionality is not always enough so let’s discuss how to customize it.  
上次我们简单介绍了批处理模式，但基本功能并不总是足够的，所以我们来讨论一下如何自定义它。

### Basic usage 基本用法

To recap, batch mode can be invoked with this command line:  
概括地说，批处理模式可以通过此命令行调用：

```
ida -B -Lida.log &lt;other switches&gt; &lt;filename&gt;
```

IDA will load the file, wait for the end of analysis, and write the full disassembly to `<filename>.asm`  
IDA 将加载文件，等待分析结束，并将完整的反汇编写入 `<filename>.asm`

### How it works 如何使用

In fact, `-B` is a shorthand for `-A -Sanalysis.idc:`  
事实上， `-B` 是 `-A -Sanalysis.idc:` 的简称

-   `-A`: enable autonomous mode (answer all queries with the default choice).  
    `-A` : 启用自主模式（使用默认选项回答所有查询）。
-   `-Sanalysis.idc:` run the script `analysis.idc` after loading the file.  
    `-Sanalysis.idc:` 在加载文件后运行脚本 `analysis.idc` 。

You can find `analysis.idc` in the `idc` subdirectory of IDA install. In IDA 7.5 it looks as follows:  
您可以在 IDA install 的 `idc` 子目录中找到 `analysis.idc` 。在 IDA 7.5 中，它看起来如下：

```
static main()
{
// turn on coagulation of data in the final pass of analysis
set_inf_attr(INF_AF, get_inf_attr(INF_AF) | AF_DODATA | AF_FINAL);
// .. and plan the entire address space for the final pass
auto_mark_range(0, BADADDR, AU_FINAL);
msg("Waiting for the end of the auto analysis...\n");
auto_wait();
msg("\n\n------ Creating the output file.... --------\n");
auto file = get_idb_path()[0:-4] + ".asm";
auto fhandle = fopen(file, "w");
gen_file(OFILE_ASM, fhandle, 0, BADADDR, 0); // create the assembler
file
msg("All done, exiting...\n");
qexit(0); // exit to OS, error code 0 - success
}
```

Thus, to modify the behavior of the batch mode you can:  
因此，你可以修改批处理模式的行为：

-   Either modify the standard `analysis.idc`  
    要么修改标准 `analysis.idc`
-   Or specify a different script using `-S<myscript.idc>`  
    或使用 `-S<myscript.idc>` 指定不同的脚本

For example, to output an LST file (it includes address prefixes), change the [gen_file](https://hex-rays.com/products/ida/support/idadoc/244.shtml) call:  
例如，要输出 LST 文件（其中包括地址前缀），请修改 gen_file 调用：

```
gen_file(OFILE_LST, fhandle, 0, BADADDR, 0);
```

### Batch decompilation 批量反编译

If you have the [decompiler](https://hex-rays.com/products/decompiler/) for the target file’s architecture, you can also run it in [batch mode](https://hex-rays.com/products/decompiler/manual/batch.shtml).  
如果你有目标文件架构的反编译器，也可以在批处理模式下运行。

For example, to decompile the whole file:  
例如，反编译整个文件：

```
ida -Ohexrays:outfile.c:ALL -A &lt;filename&gt;
```

To decompile only the function `main`:  
只反编译 `main` 函数：

```
ida -Ohexrays:outfile.c:main -A &lt;filename&gt;
```

This uses the functionality built-in into the decompiler plugin which works similarly to the `analysis.idc` script (wait for the end of autoanalysis, then decompile the specified functions to `outfile.c`).  
这将使用反编译器插件内置的功能，其工作原理与 `analysis.idc` 脚本类似（等待自动分析结束，然后将指定函数反编译为 `outfile.c` ）。

### Customizing batch decompilation  
自定义批量反编译

If the default functionality is not enough, you could write a plugin to drive the decompiler via its [C++ API](https://hex-rays.com/products/decompiler/sdk/). However, for scripting it’s probably more convenient to use Python. Similarly to IDC, Python scripts can be used with the `-S` switch to be run automatically after the file is loaded.  
如果默认功能不够，可以编写一个插件，通过 C++ API 驱动反编译器。不过，要编写脚本，使用 Python 可能更方便。与 IDC 类似，Python 脚本也可以使用 `-S` 开关，在加载文件后自动运行。

A sample script is attached to this post. Use it as follows:  
本帖附有一个示例脚本。使用方法如下：

```
ida -A -Sdecompile_entry_points.py -Llogfile.txt &lt;filename&gt;
```

### Speeding up batch processing  
加快批处理

In the examples so far we’ve been using the `ida` executable which is the full GUI version of IDA. Even though the UI is not actually displayed in batch mode, it still has to load and initialize all the dependent UI libraries which can take non-negligible time. This is why it is often better to use the text-mode executable (`idat`) which uses lightweight text-mode UI. However, it still needs a terminal even in batch mode. In case you need to run it in a situation without a terminal (_e.g._ run it in background or from a daemon), you can use the following approach:  
在迄今为止的示例中，我们一直在使用 `ida` 可执行文件，它是 IDA 的完整图形用户界面版本。尽管在批处理模式下用户界面实际上并不显示，但它仍然需要加载和初始化所有依赖的用户界面库，这可能会花费不可忽略的时间。这就是为什么使用文本模式可执行文件（ `idat` ）通常更好，因为它使用轻量级文本模式用户界面。不过，即使在批处理模式下，它仍然需要终端。如果需要在没有终端的情况下运行（例如在后台运行或从守护进程运行），可以使用以下方法：

1.  set environment variable `TVHEADLESS=1`  
    设置环境变量 `TVHEADLESS=1`
2.  redirect output 重定向输出

For example: 例如

```
TVHEADLESS=1 idat -A -Smyscript.idc file.bin &gt;/dev/null &amp;
```