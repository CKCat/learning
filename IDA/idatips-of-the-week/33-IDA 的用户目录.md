The _user directory_ is a location where IDA stores some of the global settings and which can be used for some additional customization.  
用户目录是 IDA 存储部分全局设置的位置，可用于一些额外的自定义设置。

### Default location  默认位置

On Windows: %APPDATA%/Hex-Rays/IDA Pro  
在 Windows 上：%APPDATA%/Hex-Rays/IDA Pro

On Linux and Mac: $HOME/.idapro  
在 Linux 和 Mac 上：$HOME/.idapro

For brevity, we’ll refer to this path as `$IDAUSR`in the following text.  
为简洁起见，我们在下文中将此路径称为 `$IDAUSR` 。

### Contents/settings 内容/设置

The directory is used to store the processor module caches (`proccache.lst` and `proccache64.lst`) as well as the trusted database caches (`trusted_i64_list.bin` and `trusted_idb_list.bin`). Trusted databases are those that were authorized by the user to be run under debugger. The cache is used to prevent accidental execution of unknown binaries (for example, a database provided by a third party can contain a malicious executable path so it’s not run without confirmation by default).  
该目录用于存储处理器模块缓存（ `proccache.lst` 和 `proccache64.lst` ）以及可信数据库缓存（ `trusted_i64_list.bin` 和 `trusted_idb_list.bin` ）。受信任数据库是用户授权在调试器下运行的数据库。缓存用于防止意外执行未知二进制文件（例如，第三方提供的数据库可能包含恶意可执行路径，因此默认情况下未经确认不会运行）。

On Linux and Mac, the user directory also contains the pseudo registry file `ida.reg`. It holds global IDA settings which are stored in the registry on Windows (for example, the custom [desktop layouts](https://www.hex-rays.com/blog/igors-tip-of-the-week-22-ida-desktop-layouts/)).  
在 Linux 和 Mac 上，用户目录还包含伪注册表文件 `ida.reg` ，其中保存了 Windows 注册表中的全局 IDA 设置（例如自定义桌面布局）。

If you [modify or add shortcuts](https://www.hex-rays.com/blog/igor-tip-of-the-week-02-ida-ui-actions-and-where-to-find-them/), modifications are stored in `shortcuts.cfg` in this directory.  
如果你修改或添加了快捷方式，修改内容会存储在该目录下的 `shortcuts.cfg` 中。

### Plugins 插件

The user directory (more specifically, `$IDAUSR/plugins`) can be used for installing plugins instead of IDA’s installation directory. This has several advantages:  
用户目录（更具体地说是 `$IDAUSR/plugins` ）可用于安装插件，而不是 IDA 的安装目录。这样做有几个好处

1.  No need for administrative permissions on Windows;  
    不需要 Windows 上的管理权限；
2.  The plugins can be shared by multiple IDA installs or versions, so there’s no need to reinstall plugins in new location when installing a new IDA version;  
    多个 IDA 安装或版本可以共享插件，因此在安装新的 IDA 版本时，无需在新的位置重新安装插件；
3.  plugins in the user directory can override plugins with the same name in IDA’s directory so this feature can be used to replace plugins shipped with IDA.  
    用户目录中的插件可以覆盖 IDA 目录中的同名插件，因此该功能可用于替换 IDA 随附的插件。

Both native (C++) and scripted (Python/IDC) plugins can be used this way.  
本地（C++）和脚本（Python/IDC）插件都可以这样使用。

### Config files 配置文件

To change some default options, you sometimes need to edit configuration files in IDA’s `cfg` subdirectory (for example, `ida.cfg` or `hexrays.cfg`). Instead of editing them in-place, you can extract only the options you need to change and put them into the same-named file in `$IDAUSR/cfg`. Unlike the plugins, the config files don’t override IDA’s files completely but are applied additionally. For example, to enable [synchronization and split view](https://twitter.com/HexRaysSA/status/1341745224037634049) for the decompiler, put the following lines in `$IDAUSR/cfg/hexrays.cfg`:  
要更改某些默认选项，有时需要编辑 IDA `cfg` 子目录（例如 `ida.cfg` 或 `hexrays.cfg` ）中的配置文件。你可以只提取需要更改的选项，然后把它们放到 `$IDAUSR/cfg` 中的同名文件中，而不必就地编辑。与插件不同，配置文件不会完全覆盖 IDA 的文件，而是附加应用。例如，要为反编译器启用同步和分割视图，请在 `$IDAUSR/cfg/hexrays.cfg` ：

```
//--
PSEUDOCODE_SYNCED=YES
PSEUDOCODE_DOCKPOS=DP_RIGHT
//--
```

### Other addons 其他附加组件

The user directory can also be used to provide additional loaders, processor modules, type libraries and signatures. IDA will scan the following directories for them:  
用户目录还可用于提供额外的加载器、处理器模块、类型库和签名。IDA 将扫描以下目录以查找它们：

```
$IDAUSR/loaders
$IDAUSR/procs
$IDAUSR/til/{processor}
$IDAUSR/sig/{processor}
```

### IDAPython

If a file named `idapythonrc.py` is present in the user directory, it will be parsed and executed at the end of IDAPython’s initialization. This allows you, for example, to add custom IDAPython functions, preload some commonly used scripts, or do any other customization that’s more convenient to do in Python code.  
如果用户目录中存在名为 `idapythonrc.py` 的文件，它将在 IDAPython 初始化结束时被解析并执行。这样，您就可以添加自定义的 IDAPython 函数，预加载一些常用脚本，或在 Python 代码中进行其他更方便的自定义操作。

### Overriding the user directory location  
重写用户目录位置

If you prefer to use a custom location for user settings or need several sets of such directories, you can set the `IDAUSR` environment variable to another path (or even a set of paths) before running IDA.  
如果希望使用自定义位置进行用户设置，或者需要多组此类目录，可以在运行 IDA 之前将 `IDAUSR` 环境变量设置为其他路径（甚至一组路径）。

### Debugging 调试

If you copied files to the correct location but IDA does not seem to pick them up, you can use the `-z` [commandline switch](https://www.hex-rays.com/blog/igor-tip-of-the-week-07-ida-command-line-options-cheatsheet/) to confirm that it’s finding your file. For example, the following command line enables debug output of processing of all types of customizations (plugins, processor modules, loaders, FLIRT signatures, config files) and also copies the debug output to a log file:  
如果你将文件复制到了正确的位置，但 IDA 似乎没有找到它们，你可以使用 `-z` 命令行开关来确认它是否找到了你的文件。例如，以下命令行启用了所有类型自定义（插件、处理器模块、加载器、FLIRT 签名、配置文件）处理的调试输出，并将调试输出复制到日志文件中：

`ida -zFC -Lida.log file.bin`

Among the output, you should see lines similar to following:  
在输出结果中，您应该会看到类似下面的行：

```
Scanning plugins directory C:\Users\Igor\AppData\Roaming\Hex-Rays\IDA Pro\plugins, for *.dll.
Scanning plugins directory C:\Users\Igor\AppData\Roaming\Hex-Rays\IDA Pro\plugins, for *.idc.
Scanning plugins directory C:\Program Files\IDA Pro 7.6\plugins, for *.dll.
Scanning plugins directory C:\Program Files\IDA Pro 7.6\plugins, for *.idc.
&lt;...&gt;
Scanning directory 'C:\Users\Igor\AppData\Roaming\Hex-Rays\IDA Pro\loaders' for loaders
```

So you can verify whether IDA is looking in the expected location.  
这样，你就可以验证 IDA 是否正在查找预期的位置。

For even more details on this feature, please check [Environment variables](https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml) (IDAUSR section).  
有关此功能的更多详情，请查看环境变量（IDAUSR 部分）。