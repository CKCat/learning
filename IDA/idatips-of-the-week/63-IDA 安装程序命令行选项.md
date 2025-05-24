Most users probably run IDA installers in standard, interactive mode. However, they also can be run in unattended mode (e.g. for automatic, non-interactive installation).  
大多数用户可能在标准交互模式下运行 IDA 安装程序。不过，它们也可以在无人值守模式下运行（例如用于自动、非交互式安装）。

### Available options 可用选项

To get the list of available options, run the installer with the `--help` argument. For example, here’s the list on Linux:  
要获取可用选项列表，请使用 `--help` 参数运行安装程序。例如，这里是 Linux 下的列表：

```
igor@/home/igor$ ./idapronl[...].run --help
IDA Pro and Hex-Rays Decompilers (x86, x64, ARM, ARM64, PPC, PPC64, MIPS) 7.6 7.6
Usage:

 --help                                      Display the list of valid options

 --version                                   Display product information

 --unattendedmodeui &lt;unattendedmodeui&gt;Unattended Mode UI
                                             Default: none
                                             Allowed: none minimal minimalWithDialogs

 --optionfile &lt;optionfile&gt;                  Installation option file
                                             Default:

 --debuglevel &lt;debuglevel&gt;                   Debug information level of verbosity
                                             Default: 2
                                             Allowed: 0 1 2 3 4

 --mode &lt;mode&gt;                               Installation mode
                                             Default: gtk
                                             Allowed: gtk xwindow text unattended

 --debugtrace &lt;debugtrace&gt;                   Debug filename
                                             Default:

 --installer-language &lt;installer-language&gt;   Language selection
                                             Default: en
                                             Allowed: sq ar es_AR az eu pt_BR bg ca hr cs da nl en et fi fr de el he hu id it ja kk ko lv lt no fa pl pt ro ru sr zh_CN sk sl es sv th zh_TW tr tk uk va vi cy

 --prefix &lt;prefix&gt;                           Installation Directory
                                             Default: /home/igor/idapro-7.6

 --python_version &lt;python_version&gt;           IDAPython Version
                                             Default: 3
                                             Allowed: 2 3

 --installpassword &lt;installpassword&gt;         Installation password
                                             Default:
```

For example, to run the installer in text (console) instead of GUI mode, specify `--mode text`.  
例如，要以文本（控制台）而非图形用户界面模式运行安装程序，请指定 `--mode text` .

On Windows, the set of options is slightly different (and is shown in a GUI dialog instead of console):  
在 Windows 上，选项集略有不同（显示在图形用户界面对话框中，而不是控制台中）：

```
IDA Pro and Hex-Rays Decompilers (x86, x64, ARM, ARM64, PPC, PPC64, MIPS) 7.6 7.6
Usage:

 --help                                      Display the list of valid options

 --version                                   Display product information

 --unattendedmodeui &lt;unattendedmodeui&gt;       Unattended Mode UI
                                             Default: none
                                             Allowed: none minimal minimalWithDialogs

 --optionfile &lt;optionfile&gt;                   Installation option file
                                             Default: 

 --debuglevel &lt;debuglevel&gt;                   Debug information level of verbosity
                                             Default: 2
                                             Allowed: 0 1 2 3 4

 --mode &lt;mode&gt;                               Installation mode
                                             Default: win32
                                             Allowed: win32 unattended

 --debugtrace &lt;debugtrace&gt;                   Debug filename
                                             Default: 

 --installer-language &lt;installer-language&gt;   Language selection
                                             Default: en
                                             Allowed: sq ar es_AR az eu pt_BR bg ca hr cs da nl en et fi fr de el he hu id it ja kk ko lv lt no fa pl pt ro ru sr zh_CN sk sl es sv th zh_TW tr tk uk va vi cy

 --prefix &lt;prefix&gt;                           Installation Directory
                                             Default: C:\Program Files/idapro-7.6

 --python_version &lt;python_version&gt;           IDAPython Version
                                             Default: 3
                                             Allowed: 2 3

 --installpassword &lt;installpassword&gt;         Installation password
                                             Default: 

 --install_python &lt;install_python&gt;           Install Python 3
                                             Default: 
```

In partcular, `--install_python` option allows to enable installation of the bundled Python 3 (useful for machines without Python preinstalled). On Linux and Mac, the system-wide Python is presumed to be available  
其中， `--install_python` 选项允许启用安装捆绑的 Python 3（对于没有预装 Python 的机器很有用）。在 Linux 和 Mac 上，系统范围内的 Python 假定是可用的。

### Using the option file  
使用选项文件

Especially for unattended mode, you may need to specify multiple options (install path, Python version, installation password etc.). Instead of passing them all on the command line, you can use the _option file:_  
特别是在无人值守模式下，可能需要指定多个选项（安装路径、Python 版本、安装密码等）。与其在命令行中传递所有选项，不如使用选项文件：

1.  Create a simple text file with a list of `option=value` lines. The option names are those from the usage screen without the leading `--`.  
    创建一个包含 `option=value` 行的简单文本文件。选项名称为使用界面中的名称，不含前导 `--` 。
2.  Pass the filename to the installer using the `--optionfile <filename>` switch.  
    使用 `--optionfile <filename>` 开关将文件名传递给安装程序。

For example, here’s a file for unattended install for Python 3:  
例如，下面是 Python 3 的无人值守安装文件：

```
installpassword=mypassword
prefix=/home/igor/ida-7.6
mode=unattended
python_version=3
```

### Running Mac installer from command line  
从命令行运行 Mac 安装程序

Because the Mac installer is not a single binary but an app bundle, you need to pass arguments to the executable inside the bundle, for example:  
由于 Mac 安装程序不是一个二进制文件，而是一个应用程序捆绑包，因此需要向捆绑包内的可执行文件传递参数，例如

```
ida[...].app/Contents/MacOS/installbuilder.sh --mode text
```

### Uninstaller options 卸载程序选项

The uninstaller can also be run with commandline opions:  
卸载程序也可以通过命令行操作运行：

`~/idapro-7.6/uninstall --mode unattended`