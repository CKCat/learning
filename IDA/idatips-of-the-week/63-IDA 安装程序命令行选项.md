大多数用户通常以标准的交互模式运行 IDA 安装程序。 不过，它们也可以在 无人值守模式（unattended mode） 下运行（例如用于自动化、非交互式安装）。

### 可用选项

要获取可用选项列表，可以在运行安装程序时加上 --help 参数。

Linux 示例：

```bash
igor@/home/igor$ ./idapronl[...].run --help
IDA Pro and Hex-Rays Decompilers (x86, x64, ARM, ARM64, PPC, PPC64, MIPS) 7.6 7.6
Usage:

 --help                                      Display the list of valid options

 --version                                   Display product information

 --unattendedmodeui <unattendedmodeui>	Unattended Mode UI
                                             Default: none
                                             Allowed: none minimal minimalWithDialogs

 --optionfile <optionfile>                  Installation option file
                                             Default:

 --debuglevel <debuglevel>                   Debug information level of verbosity
                                             Default: 2
                                             Allowed: 0 1 2 3 4

 --mode <mode>                               Installation mode
                                             Default: gtk
                                             Allowed: gtk xwindow text unattended

 --debugtrace <debugtrace>                   Debug filename
                                             Default:

 --installer-language <installer-language>   Language selection
                                             Default: en
                                             Allowed: sq ar es_AR az eu pt_BR bg ca hr cs da nl en et fi fr de el he hu id it ja kk ko lv lt no fa pl pt ro ru sr zh_CN sk sl es sv th zh_TW tr tk uk va vi cy

 --prefix <prefix>                           Installation Directory
                                             Default: /home/igor/idapro-7.6

 --python_version <python_version>           IDAPython Version
                                             Default: 3
                                             Allowed: 2 3

 --installpassword <installpassword>         Installation password
                                             Default:
```

例如，如果想在 文本模式（console） 下运行安装程序，而不是 GUI 模式，可以指定：

```bash
--mode text
```

Windows 下的选项 略有不同（并且会在 GUI 对话框中显示，而不是控制台）：

```
IDA Pro and Hex-Rays Decompilers (x86, x64, ARM, ARM64, PPC, PPC64, MIPS) 7.6 7.6
Usage:

 --help                                      Display the list of valid options

 --version                                   Display product information

 --unattendedmodeui <unattendedmodeui>       Unattended Mode UI
                                             Default: none
                                             Allowed: none minimal minimalWithDialogs

 --optionfile <optionfile>                   Installation option file
                                             Default:

 --debuglevel <debuglevel>                   Debug information level of verbosity
                                             Default: 2
                                             Allowed: 0 1 2 3 4

 --mode <mode>                               Installation mode
                                             Default: win32
                                             Allowed: win32 unattended

 --debugtrace <debugtrace>                   Debug filename
                                             Default:

 --installer-language <installer-language>   Language selection
                                             Default: en
                                             Allowed: sq ar es_AR az eu pt_BR bg ca hr cs da nl en et fi fr de el he hu id it ja kk ko lv lt no fa pl pt ro ru sr zh_CN sk sl es sv th zh_TW tr tk uk va vi cy

 --prefix <prefix>                           Installation Directory
                                             Default: C:\Program Files/idapro-7.6

 --python_version <python_version>           IDAPython Version
                                             Default: 3
                                             Allowed: 2 3

 --installpassword <installpassword>         Installation password
                                             Default:

 --install_python <install_python>           Install Python 3
                                             Default:
```

特别是 `--install_python` 选项，可以启用安装自带的 Python 3（适用于没有预装 Python 的机器）。 在 Linux 和 Mac 上，系统默认假定已有 Python。

### 使用 option file

尤其在无人值守模式下，可能需要指定多个选项（安装路径、Python 版本、安装密码等）。 与其在命令行中全部写出，不如使用 option file：

- 创建一个简单的文本文件，每行写 `option=value`。 （选项名就是 usage 输出中的名字，但去掉前缀 --）
- 使用 `--optionfile <filename>` 参数传递给安装程序。

示例：无人值守安装 Python 3 的配置文件：

```
installpassword=mypassword
prefix=/home/igor/ida-7.6
mode=unattended
python_version=3
```

### 在 Mac 上从命令行运行安装程序

由于 Mac 安装程序是一个 app bundle，而不是单一可执行文件，需要传递参数给 bundle 内部的可执行文件，例如：

```bash
ida[...].app/Contents/MacOS/installbuilder.sh --mode text
```

### 卸载程序选项

卸载程序同样可以带命令行参数运行，例如：

```bash
~/idapro-7.6/uninstall --mode unattended
```

原文地址：https://hex-rays.com/blog/igors-tip-of-the-week-63-ida-installer-command-line-options
