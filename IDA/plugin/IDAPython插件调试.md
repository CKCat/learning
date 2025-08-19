本文是对 scz 前辈 [调试 IDAPython 插件](https://www.52pojie.cn/forum.php?mod=viewthread&tid=2043161) 的实践。

# 背景介绍

约定一下本文中的术语，IDA 中 `Alt-F7` 加载的 `some.py` 称之为「IDAPython 脚本」，"Edit->Plugins" 加载的 `some.py` 称之为「IDAPython 插件」，后者有 `PLUGIN_ENTRY()`。

IDA 有大量 IDAPython 插件，某些插件非常复杂，靠 `print` 理解代码逻辑并不方便，若能在某种 IDE 中调试 IDAPython 插件，对学习、编写插件非常有益。

编写本文时相关组件版本信息如下

```
x64/Win10
IDA 9.1
Python 3.12.10
debugpy 1.8.14
VSCode 1.103.1
```

严格按本文所给示例复现时，一般不会遭遇 `debugpy` 模块的 MyCode 判定问题 (表象是断点不生效)，简略起见，本文未解释此问题的技术原理。

# VSCode

参看

```
Visual Studio Code Portable mode
https://code.visualstudio.com/docs/editor/portable
```

1. 安装 Python Debugger 扩展

```bash
File
  Preferences
    Extensions (Ctrl+Shift+X)
      Python
      Python Debugger
```

2. `launch.json`

```bash
File
  Open Folder (Ctrl+K O)
    X:\work\VSCode\IDAPython (假设用这个目录存放Project相关内容)
```

假设已在 UI 中打开 IDAPython 目录，再做后续操作

```
Run
  Add Configuration
    More Python Debugger options
      Python Debugger: Python File IDAPython (与前面的IDAPython目录名一致)
        编辑 IDAPython 相关的 launch.json
```

`launch.json` 内容如下

```json
{
  "configurations": [
    {
      "name": "Python Debugger: Attach",
      "type": "debugpy",
      "request": "attach",
      "connect": {
        "host": "127.0.0.1",
        "port": 5678
      },
      "justMyCode": true,
      "rules": [
        {
          "path": "X:\\Green\\IDA\\plugins\\**",
          "include": true
        }
      ]
    }
  ]
}
```

在 [VSCode 调试 python 的文档](https://code.visualstudio.com/docs/python/debugging#_justmycode)中显示
`justMyCode` 默认为 `true`，并且没有 `rules` 选项说明。尝试将其修改为下列内容后仍然可以调试：

```json
{
  "configurations": [
    {
      "name": "Python Debugger: Attach",
      "type": "debugpy",
      "request": "attach",
      "connect": {
        "host": "127.0.0.1",
        "port": 5678
      }
    }
  ]
}
```

## debugpy 模块

参看

```
debugpy - a debugger for Python
https://github.com/microsoft/debugpy/
```

过去有个支持 `Debug Adapter Protocol (DAP)` 的 Python 模块 `ptvsd`，现已废弃，官方不建议继续使用，转用 `debugpy` 模块。

向 IDA 安装 `debugpy` 模块

```bash
python.exe -m pip install debugpy
```

## 远程调试 IDAPython 插件

本节演示用 `debugpy` 调试 plugins 目录下的 IDAPython 插件。

### 1 `debugpy_test_2.py`

```python
import os

import debugpy
import ida_idaapi
import idaapi

os.environ["IDE_PROJECT_ROOTS"] = r"D:\ida91\plugins"


def foo():
    print("ckcat is here.")
    print("ok")


class test(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX

    # Required attributes - must be set by subclasses
    wanted_name: str = "test"
    comment: str = "test"
    help: str = "test"

    def init(self) -> int:
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        if not debugpy.is_client_connected():
            debugpy.listen(("127.0.0.1", 5678), in_process_debug_adapter=True)
            debugpy.wait_for_client()
        idaapi.msg("Hit breakpoint\n")
        debugpy.breakpoint()
        foo()

    def term(self) -> None:
        print("Plugin test terminating")


def PLUGIN_ENTRY():
    return test()
```

先在 IDA 中 `Edit->Plugins` 加载插件，命令行中运行 `netstat -na | findstr :5678` 检查侦听端口，再在 VSCode 中用 `launch.json (Ctrl+Shift+D)` 发起调试，会断在 `foo()` 处。插件执行完，不要在 VSCode 中选 `Disconnect (Shift+F5)`，在 IDA 中再次 `Edit->Plugins` 加载，可重新调试，仍断在 `foo()` 处。

经测试，在 VSCode 中选中 Disconnect 后，IDA 插件正常运行，后续在 IDA 中再次 `Edit->Plugins` 运行插件，仍然可以正常调试。 使用 `netstat -na |findstr :5678` 命令查看网络连接信息如下：

```bash
netstat -na |findstr :5678
  TCP    127.0.0.1:4568         127.0.0.1:5678         FIN_WAIT_2
  TCP    127.0.0.1:5678         0.0.0.0:0              LISTENING
  TCP    127.0.0.1:5678         127.0.0.1:4568         CLOSE_WAIT
```

上面信息表明调试服务器未正确关闭旧连接。

### 2 `debugpy_test_3.py`

```python
import os

import debugpy
import ida_idaapi
import idaapi

os.environ["IDE_PROJECT_ROOTS"] = r"D:\ida91\plugins"


def foo():
    print("ckcat")
    print("ok")


class test(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX

    # Required attributes - must be set by subclasses
    wanted_name: str = "test"
    comment: str = "test"
    help: str = "test"

    def init(self) -> int:
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        if not debugpy.is_client_connected() :
            debugpy.configure( python=r"X:\Green\IDA\python.exe" )
            debugpy.listen( ("127.0.0.1", 5678) )
            debugpy.wait_for_client()
        idaapi.msg("Hit breakpoint\n")
        debugpy.breakpoint()
        foo()

    def term(self) -> None:
        print("Plugin test terminating")


def PLUGIN_ENTRY():
    return test()

```

`debugpy_test_3.py` 未显式设置 `in_process_debug_adapter` 为 `True`，但用 `debugpy.configure()` 显式指定 `python.exe` 的路径。

# VSCode IDACode 扩展

参看

```
VSCode IDACode扩展
https://marketplace.visualstudio.com/items?itemName=Layle.idacode
https://github.com/ioncodes/idacode
https://github.com/ioncodes/idacode/releases/download/0.3.1/ida.zip
```

"VSCode IDACode 扩展" 主要用于调试 IDAPython 脚本 (`Alt-F7` 加载的那种)，也可调试 IDAPython 插件 (plugins 目录的那种)。涉及两部分组件；一部分是 C 端的 VSCode 扩展，在 VSCode 中安装、使用；另一部分是 S 端的 IDA 插件，上面那个 `ida.zip` 即是，需放到 plugins 目录。底层依赖 `debugpy`、`tornado` 模块，需配套安装。

整体框架有些复杂，调试 IDAPython 脚本比较方便，调试 IDAPython 插件时没有优势。

感谢「0x 指纹」提供 IDACode 测试记录，否则入门有些困难。

## 1 在 IDA 中安装 IDACode 插件

IDAPython 环境中需安装两个模块

```bash
python.exe -m pip install debugpy tornado
```

从 github 下载 `ida.zip`，展开到 plugins 目录

根据实际情况修改 `idacode_utils\settings.py`，主要是改 `python.exe` 的路径。

## 2 在 VSCode 中安装、配置 IDACode 扩展

启动 VSCode，`Ctrl+Shift+X`，安装 IDACode 扩展，检查配置。

`Ctrl+Shift+P`，有四个与 IDACode 扩展相关的命令

```bash
IDACode: Connect to IDA
IDACode: Attach a debugger to IDA
IDACode: Connect and attach a debugger to IDA
IDACode: Execute script in IDA
```

## 3 用 VSCode IDACode 扩展远程调试 IDAPython 脚本

### 3.1 debugpy_test_4.py

```python
#!/usr/bin/env python
# -*- coding: cp936 -*-

#
# 测试两种加载方式
#
# 1. 在IDA中Alt-F7加载
# 2. 用VSCode IDACode扩展远程加载
#

import idaapi

def foo () :
    print( "scz is here" )
    print( "ok" )

def main () :
    foo()

if "__main__" == __name__ :
    #
    # 可用 debugpy.breakpoint()，此处刻意演示dbg.bp()。
    #
    # 虽然没有"import dbg"，但IDAPython_ExecScript()第二形参env提供了dbg、
    # __idacode__、__name__
    #
    if '__idacode__' in globals() and __idacode__ :
        #
        # 不同于debugpy.breakpoint()，dbg.bp()将断在自身，而非后一条语句
        #
        dbg.bp( __idacode__, 'Hit breakpoint' )
    main()
```

### 3.2 IDAPython 脚本测试记录

初学者欲复现时，请严格遵循下述步骤，勿自作聪明。

IDA 打开 `some.i64`，`Edit->Plugins->IDACode`

在 VSCode 中打开待调试 IDAPython 脚本所在目录

```
File
  Open Folder (Ctrl+K O)
    X:\work\VSCode\other (debugpy_test_4.py位于其中)
```

打开 `debugpy_test_4.py`

`Ctrl+Shift+P`，选择或输入 `IDACode: Connect and attach a debugger to IDA`，UI 正上方有个输入框，检查输入框中路径，回车确认。注意 `set_workspace` 时回车确认，此步易忽略，造成后续出错。

`Ctrl+Shift+P`，选择或输入 `IDACode: Execute script in IDA`，断在 `dbg.bp()` 处，之后可用常规调试动作。

假设修改了 `debugpy_test_4.py`，保存后，再次 `IDACode: Execute script in IDA` ，相当于远程 `Alt-F7`，可立即开始新的调试。不要选 `Disconnect (Shift+F5)`，断开后重连，不是你想要的效果，IDA 报端口占用，只能重启 IDA 恢复。

经测试，在 VSCode 中选中 Disconnect 后，仍然可以正常调试脚本。 

## 用 VSCode IDACode 扩展远程调试 IDAPython 插件

### 4.1 debugpy_test_5.py

```python
import os

import debugpy
import ida_idaapi
import idaapi

os.environ["IDE_PROJECT_ROOTS"] = r"D:\ida91\plugins"


def foo():
    print("ckcat is here.")
    print("ok")


class test(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX

    # Required attributes - must be set by subclasses
    wanted_name: str = "test"
    comment: str = "test"
    help: str = "test"

    def init(self) -> int:
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        if not debugpy.is_client_connected():
            debugpy.listen(("127.0.0.1", 5678), in_process_debug_adapter=True)
            debugpy.wait_for_client()
        idaapi.msg("Hit breakpoint\n")
        debugpy.breakpoint()
        foo()

    def term(self) -> None:
        print("Plugin test terminating")


def PLUGIN_ENTRY():
    return test()
```

若遭遇断点不生效，可设置 `IDE_PROJECT_ROOTS` 环境变量。

### 4.2 IDAPython 插件测试记录

初学者欲复现时，请严格遵循下述步骤，勿自作聪明。

IDA 打开 `some.i64`，`Edit->Plugins->IDACode`

在 VSCode 中打开任意目录

```
File
  Open Folder (Ctrl+K O)
    X:\anywhere (不要求是"X:\Green\IDA\plugins")
```

打开 `dummy.py`，名字无所谓，内容为空无所谓，但必须打开一个。

`Ctrl+Shift+P`，选择或输入 `IDACode: Connect and attach a debugger to IDA`，同样有个 `set_workspace` 回车确认。

这次不要用 `IDACode: Execute script in IDA` ，此操作用于调试 IDAPython 脚本，不用于调试 plugins 目录的 IDAPython 插件。

在 IDA 中 `Edit->Plugins` 加载 `debugpy_test_5.py`。

一切正常的话，VSCode 中将自动打开 `debugpy_test_5.py`，断在 foo() 处，之后可用常规调试动作。

在 IDA 中再次 `Edit->Plugins` 加载插件，可重新调试；不要选 `Disconnect`，不是你想要的效果。
