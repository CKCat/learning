用户目录是 IDA 用来存储一些全局设置的位置，也可以用于额外的自定义。

### 默认位置

- Windows：`%APPDATA%/Hex-Rays/IDA Pro`
- Linux 和 Mac：`$HOME/.idapro`

在下文中，我们将该路径简称为 `$IDAUSR`。

### 内容/设置

该目录用于存储：

- 处理器模块缓存：`proccache.lst` 和 `proccache64.lst`
- 可信数据库缓存：`trusted_i64_list.bin` 和 `trusted_idb_list.bin`

可信数据库是指用户授权可在调试器下运行的数据库。缓存的作用是防止意外执行未知二进制文件（例如第三方提供的数据库可能包含恶意可执行路径，因此默认不会直接运行，需用户确认）。

在 Linux 和 Mac 上，用户目录还包含一个伪注册表文件 `ida.reg`，它保存了全局 IDA 设置（在 Windows 上这些设置存储在注册表中，例如[自定义桌面布局](https://www.hex-rays.com/blog/igors-tip-of-the-week-22-ida-desktop-layouts/)）。

如果你[修改或添加快捷键](https://www.hex-rays.com/blog/igor-tip-of-the-week-02-ida-ui-actions-and-where-to-find-them/)，这些更改会保存在该目录下的 `shortcuts.cfg` 文件中。

### 插件

用户目录下的 `$IDAUSR/plugins` 可用于安装插件，而不是放在 IDA 的安装目录中，这样有几个好处：

1. Windows 下无需管理员权限
2. 插件可被多个 IDA 安装或版本共享，升级 IDA 时无需重新安装插件
3. 用户目录中的插件可覆盖 IDA 目录中同名插件，可用于替换官方插件

支持原生（C++）和脚本（Python/IDC）插件。

### 配置文件

有些默认选项需要修改 IDA `cfg` 子目录下的配置文件（如 `ida.cfg` 或 `hexrays.cfg`）。 与其直接修改原文件，不如将需要更改的选项提取出来，放到 `$IDAUSR/cfg` 下的同名文件中。

与插件不同，配置文件不会完全覆盖原文件，而是附加应用。 例如，要启用反编译器的同步和分屏视图，可以在 `$IDAUSR/cfg/hexrays.cfg` 中添加：

```
//--
PSEUDOCODE_SYNCED=YES
PSEUDOCODE_DOCKPOS=DP_RIGHT
//--
```

### 其他扩展

用户目录还可用于提供额外的：

- 加载器（`$IDAUSR/loaders`）
- 处理器模块（`$IDAUSR/procs`）
- 类型库（`$IDAUSR/til/{processor}`）
- 签名文件（`$IDAUSR/sig/{processor}`）

### IDAPython
如果用户目录中存在 `idapythonrc.py` 文件，它会在 IDAPython 初始化结束时被解析和执行。 这可以用来：

- 添加自定义 IDAPython 函数
- 预加载常用脚本
- 进行其他更方便用 Python 完成的自定义

### 自定义用户目录位置
如果你想使用自定义位置存放用户设置，或需要多套用户目录，可以在运行 IDA 前设置 `IDAUSR` 环境变量为其他路径（甚至多个路径）。

### 调试
如果文件放在了正确位置但 IDA 没有加载，可以使用 `-z` [命令行开关](https://www.hex-rays.com/blog/igor-tip-of-the-week-07-ida-command-line-options-cheatsheet/) 确认 IDA 是否找到文件。

例如：
```bash
ida -zFC -Lida.log file.bin
```
该命令会：

- 输出所有自定义内容（插件、处理器模块、加载器、FLIRT 签名、配置文件）的处理调试信息
- 将调试输出保存到 `ida.log`

输出中你会看到类似：

```bash
Scanning plugins directory C:\Users\Igor\AppData\Roaming\Hex-Rays\IDA Pro\plugins, for *.dll.
Scanning plugins directory C:\Users\Igor\AppData\Roaming\Hex-Rays\IDA Pro\plugins, for *.idc.
Scanning plugins directory C:\Program Files\IDA Pro 7.6\plugins, for *.dll.
Scanning plugins directory C:\Program Files\IDA Pro 7.6\plugins, for *.idc.
<...>
Scanning directory 'C:\Users\Igor\AppData\Roaming\Hex-Rays\IDA Pro\loaders' for loaders
```

这样你就能确认 IDA 是否在预期位置查找文件。

更多细节可参考 [Environment variables](https://www.hex-rays.com/products/ida/support/idadoc/1375.shtml) 文档中的 `IDAUSR` 部分。


原文地址：https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr
