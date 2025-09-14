
[上次](https://hex-rays.com/blog/igor-tip-of-the-week-07-ida-command-line-options-cheatsheet/)我们简要介绍了批处理模式（batch mode），但基础功能并不总是够用，所以这次我们来讨论如何自定义它。
### 基本用法
回顾一下，批处理模式可以用以下命令行调用：

```bash
ida -B -Lida.log <other switches> <filename>
```

IDA 会加载文件，等待分析结束，并将完整的反汇编输出到 `<filename>.asm`

###工作原理
实际上，`-B` 是 `-A -Sanalysis.idc` 的简写：

- `-A`：启用自动模式（所有提示都用默认选项回答）
- `-Sanalysis.idc`：在加载文件后运行 `analysis.idc` 脚本

你可以在 IDA 安装目录的 idc 子目录中找到 `analysis.idc`。在 IDA 7.5 中，它的内容如下：

```c
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

因此，要修改批处理模式的行为，你可以：

- 修改标准的 `analysis.idc`
- 或使用 `-S<myscript.idc>` 指定其他脚本

例如，要输出带地址前缀的 `.LST` 文件，可以修改 `gen_file` 调用为：
```c
gen_file(OFILE_LST, fhandle, 0, BADADDR, 0);
```

### 批量反编译

If you have the [decompiler](https://hex-rays.com/products/decompiler/) for the target file’s architecture, you can also run it in [batch mode](https://hex-rays.com/products/decompiler/manual/batch.shtml).  
如果你有目标文件架构的反编译器，也可以在批处理模式下运行。

如果你有目标文件架构对应的[反编译器](https://hex-rays.com/products/decompiler)，也可以在[批处理模式](https://hex-rays.com/products/decompiler/manual/batch.shtml)下运行它。

例如，反编译整个文件：

```bash
ida -Ohexrays:outfile.c:ALL -A <filename>
```

仅反编译 `main` 函数：

```bash
ida -Ohexrays:outfile.c:main -A <filename>
```

这利用了反编译器插件内置的功能，工作方式与 `analysis.idc` 类似（等待自动分析结束，然后将指定函数反编译到 `outfile.c`）。

### 自定义批量反编译
如果默认功能不够用，可以编写插件通过 [C++ API](https://hex-rays.com/products/decompiler/sdk/) 控制反编译器。不过，对于脚本化任务，使用 Python 更方便。

与 IDC 类似，Python 脚本也可以通过 `-S` 开关在文件加载后自动运行。本篇附带了一个示例脚本 `decompile_entry_points.py`，用法如下：

```bash
ida -A -Sdecompile_entry_points.py -Llogfile.txt <filename>
```

### 加速批处理
前面的示例中，我们一直使用的是带完整 GUI 的 ida 可执行文件。即使在批处理模式下 UI 不会显示，它仍需加载和初始化所有依赖的 UI 库，这会耗费一定时间。

因此，通常更好用轻量级文本模式 UI 的 `idat` 可执行文件。不过，即使在批处理模式下，`idat` 仍需要终端。

如果需要在没有终端的情况下运行（例如后台或守护进程中），可以这样做：

设置环境变量：

1.  设置环境变量 `TVHEADLESS=1`
2.  重定向输出

例如:
```
TVHEADLESS=1 idat -A -Smyscript.idc file.bin >/dev/null &
```

`decompile_entry_points.py` 文件内容：
```python
from __future__ import print_function

#
# This example tries to load a decompiler plugin corresponding to the current
# architecture (and address size) right after auto-analysis is performed,
# and then tries to decompile the function at the first entrypoint.
#
# It is particularly suited for use with the '-S' flag, for example:
# idat -Ldecompile.log -Sdecompile_entry_points.py -c file
#

import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry

# becsause the -S script runs very early, we need to load the decompiler
# manually if we want to use it
def init_hexrays():
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
        return True
    else:
        print('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False


def decompile_func(ea, outfile):
    print("Decompiling at: %X..." % ea)
    cf = ida_hexrays.decompile(ea)
    if cf:
        print("OK.")
        outfile.write(str(cf) + "\n")
    else:
        print("failed!")
        outfile.write("decompilation failure at %X!\n" % ea)


def main():
    print("Waiting for autoanalysis...")
    ida_auto.auto_wait()
    if init_hexrays():
        eqty = ida_entry.get_entry_qty()
        if eqty:
            idbpath = idc.get_idb_path()
            cpath = idbpath[:-4] + ".c"
            with open(cpath, "w") as outfile:
                print("writing results to '%s'..." % cpath)
                for i in range(eqty):
                    ea = ida_entry.get_entry(ida_entry.get_entry_ordinal(i))
                    decompile_func(ea, outfile)
        else:
            print("No known entrypoint. Cannot decompile.")
    if idaapi.cvar.batch:
        print("All done, exiting.")
        ida_pro.qexit(0)


main()
```

原文地址：https://hex-rays.com/blog/igor-tip-of-the-week-08-batch-mode-under-the-hood