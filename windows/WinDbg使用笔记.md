原文地址 [web.archive.org](https://web.archive.org/web/20201017055517/https://dbgtech.github.io/Tools/windbg-using.html)

Windbg 是 Windows 上的基础调试器，异常强大，几乎可以用于解决 Windows 系统问题以及 Windows 应用程序问题。本篇是以往学习使用中积累的命令集合，作为今后参考。

### 内置的帮助命令

<table><thead><tr><th>命令</th><th>含义</th></tr></thead><tbody><tr><td>?</td><td>显示常用的命令</td></tr><tr><td>? /D</td><td>显示常用命令和 DML</td></tr><tr><td>.help</td><td>显示. 命令</td></tr><tr><td>.help /D</td><td>以 DML 形式显示'.'命令（顶部会给出链接）</td></tr><tr><td>.help /D a*</td><td>以 DML 形式显示 a 开头的'.'命令 (* 为通配符)</td></tr><tr><td>.hh</td><td>打开帮助文件</td></tr><tr><td>.hh dt</td><td>打开帮助文件，并在索引定位到 dt 命令</td></tr><tr><td>version</td><td>显示调试器以及加载扩展版本信息</td></tr><tr><td>vertarget</td><td>显示目标计算机的版本</td></tr><tr><td>n [8/10/16]</td><td>设置调试器数基，8 进制，10 进制等</td></tr></tbody></table>

### 常用`.`命令

- `.cls` 清空界面
- `.srcpath` 显示或设置源码的检索路径
- `.srcpath+ 目录` 将目录添加到检索到的源码路径
- `.lines [-e|-d|-t]` 切换源码行的支持，可用，禁用，切换
- `.srcnoisy 1` 显示源码的搜索过程 `.srcnoisy 0` 不显示源码的搜索过程。

和源码相关的命令（小写'L'的命令）。

- `l+l`, `l-l` 显示行数
- `l+o`, `l-o` 除了 [s] 隐藏一切
- `l+s`, `l-s` 源码和行数
- `l+t`, `l-t` 源码模式对汇编模式

例如命令`.srcpath C:\Users\Administrator\Desktop\WinDbug\TestDebug1`用于添加源码的路径，模块可以与源码结合，看到源码中的调试过程。`.exepath C:\Users\Administrator\Desktop\exefiles`在调试 dump 文件时才会用得上可执行映像路径。需要将这个路径设置为调试的 exe，dll，sys 等可执行文件的路径。

**调试日志**

- `.logopen /t d:\logs\mylogfile.txt` 打开日志文件
- `.logappend /t d:\logs\mylogfile.txt` 向日志文件中追加 日志
- `.logclose` 关闭日志文件

> 注：在关闭一次调试时，要关闭日志文件。

**调试会话**

- `.attach PID` (在调试一个进程中)，附加到一个进程
- `.detach` 结束调试会话，但是保留用户模式目标程序运行
- `q / qq` 结束调试会话，并终止目标程序
- `.restart` 重启目标程序

### 符号相关

- `ld 模块名` 加载指定模块符号
- `ld *` 加载所有模块的符号
- `!sym` 获取符号加载情况 (!sym noisy 显示搜索符号过程，!sym quiet 默认)

**列举模块中符号**

`x`命令可以列举模块的名字，其通用的命令格式为`x [选项] 模块!符号`。有用的选项如下：

- `/t` 带数据类型
- `/v` 详情，包括符号类型与大小
- `/a` 按照地址分类
- `/n` 按照名称分类
- `/z` 按照大小分类 (函数在内存中的大小)

`x [选项]模块名字!符号匹配表达式`可以查找一些函数名字，以方便下断点，比如：`x user32！GetWindowT*`列举出`USER32.dll`中的`GetWindowT`开头的所有的函数。

```
x /t /v notepad!*  用于列举出notepad模块的public函数以及变量


```

`ln addr`列出 addr 地址最近的符号，显示给出地址附近的符号，用于确定指针指向位置，以及在损坏栈中，确定栈的调用程序。`ln 01001b90`列举出地址 01001b90 附近的符号。

**符号路径**

- `.sympath 路径` 设置符号路径
- `.sympath+ 路径` 添加符号路径
- `.symfix 路径` 设置符号存储路径
- `.symfix+ 保存路径` 附加到现有路径，当作符号下载流存储位置

一旦设置了符号路径或者符号的下载路径，则可以使用命令重新加载模块符号。

- .reload 为所有模块重载符号信息
- .reload [/f|/v] /f 强制立即加载符号， /v 详细模式
- .reload [/f|/v] 模块 同上，只是针对特定模块

`.reload`命令的几个有用选项

- `/d` 重新加载调试器中的所有模块符号
- `/l` 列出所有的模块但是不重新加载符号
- `/n` 重新加载内核符号
- `/user` 重新加载用户模式符号
- `/u` 卸载指定模块和它的符号

例如`.sympath C:\Users\Administrator\Desktop\WinDbug`设置程序的符号路径为`C:\Users\Administrator\Desktop\WinDbug`。命令`.symfix+ D:\Symbols`添加系统模块的符号路径，即微软公共符号的本地存储位置（会被 WinDbg 自动添加为`D:\Symbols;SRV*http://msdl.microsoft.com/download/symbols`）。

```
.reload  /u ntdll.dll          卸载ntdll.dll
.reload  /s /f ntdll.dll    加载ntdll.dll


```

> 注：添加完符号路径后，可以使用 .reload 命令重新加载符号

**命令的扩展**

```
x *!        列出所有的模块
x ntdll!*    列出ntdll的所有符号
x /t /v MyDll!*    列出MyDll的所有符号的数据类型，符号类型和大小

.reload /f @"ntdll.dll"        立刻从ntdll.dll重载符号


```

### 命令窗口

`0:000>`这个提示符号中，第一个 0，表示当前的进程号，冒号后的 000 表示当前的线程号。`*BUSY*`这样的字符串，表示调试器正忙。单核的内核调试为 kd>，而多核的系统以 0:kd> 表示内核调试，0 表示处理器号。

- `Esc` 可以消除当前行
- `Tab`键可以自动补充命令
- 鼠标点击右键，可以将剪切板上的内容粘贴到命令行输入框。
- 直接按 Enter 键，可以重复上一条命令
- `Ctrl-Break`来中断一条没有执行完毕的命令

**伪寄存器**

- $ip = eip / rip x86/x64 上的 ip 寄存器
- $ra = 当前函数的返回地址
- $retreg 返回值 eax - rax - ret0 分别针对 x86/x64/Itanium
- $csp 当前栈指针， esp - rsp - bsp
- $proc 用户态的进程环境块 PEB 地址
- $thread 线程环境块 TEB
- $tpid 当前进程的标识 PID
- $tid 当前线程的标识 TID
- $exentry 当前程序的入口地址

### 反汇编

- u 反汇编当前 IP 寄存器位置的内容
- u $ip 反汇编当前 $ip 上的 8 条命令
- uf $ip 反汇编当前 $ip 地址上的整个函数
- uf addr 反汇编 addr 地址上的整个函数
- ub $ip 反汇编 $ip 之前的 8 条指令
- ub $ip L2a 反汇编 $ip 地址之前的 42 条指令
- u $ip $ip+a 反汇编两个地址之间的指令其中不包括 $ip+a 地址处的指令

### 线程与进程相关

**进程命令**

- `|` 显示所有正在被调试的进程的状态
- `.tlist` 列出系统正运行的所有进程
- `!peb` 显示进程环境块 PEB 的标准视图

线程命令

- ~ 列出线程
- ~\* [命令] 所有线程
- ~. [命令] 当前线程
- ~# [命令] 当前时间或异常引发的线程
- ~ns 转到线程 n，n 为线程 id
- ~n f|u|n|m 将线程 n 冻结 | 解冻 | 挂起 | 恢复 可以用于线程调试中，暂停某些线程的执行

例如`~1 n`命令将一号线程挂起计数增加 1，`~1 m`将一号线程的挂起计数减少 1。

例如`~`字符用于查看被调试进程中的线程信息。`0 Id: 1998.1358 Suspend: 1 Teb: 7ffde000 Unfrozen`表示一条线程的信息，0 表示该线程的编号（区分所有列出的）；1998.1358，前者是进程进程 ID，后者是线程 ID。再后面的信息室线程的状态和 Teb 地址。在 0 之前的一个点号”.” 表示是当前线程。

一旦 WinDbg 中`Ctrl+Break`之后，会在调试目标的进程中创建一个远线程，并在远线程中执行`ntdll!DbgBreakPoint`函数，在目标进程中产生一次`int3`异常，中断到调试器中。

`~tid s`可以在线程之间进行切换。 `~0s`则切换到当前进程的 0 号线程中。 `|pid s`可以再进程之间切换。 `|1s`则切换到 1 号进程中去。

- !teb 显示线程环境块 TEB 的标准视图
- !peb 显示进程环境块的信息，PEB 的标准视图
- !gle 当前线程的最终错误 GetLastError() 值
- !gle -all 所有线程的最终错误
- !error 错误值 解码并显示一个错误值的信息
- !error 错误值 l 将错误值作为 NTSTATUS 代码处理

**死锁调试**

- !runaway 列举出当前所有线程的执行时间
- !runaway 7 列举出执行时间的详细信息
- !locks 列举出死锁的信息

`~*kb`查看当前在进程中运行的所有的线程堆栈，结合`!cs`命令就可以查到那些线程死锁了。`!cs addr`可以显示内存处临界区的内容。

- !cs -s 显示每个临界区的初始堆栈回溯
- !cs -l 仅显示锁定的临界区
- !cs -? 显示 !cs 的帮助信息

`!handle f`列举出句柄的信息，参数 f 表示列举详细信息。`!handle`命令的详细内容可以参考帮助文档。

### 控制命令

**调试源码或汇编**

`F5`运行或运行到断点，`F10`逐过程单步执行，`F11`逐语句单步。汇编模式和源码模式的单步执行不同，汇编模式，每次执行一条汇编语句，源码模式，每次执行一句源码。`l-t`来启用汇编模式，`l+t`启用源码模式。

`g*`类的命令：直接运行目标程序。

- g 与 F5 同等，
- gu 执行到当前函数完成
- gc 条件断点之后恢复运行
- gh 当前异常当做已处理，继续执行
- gn 当前异常当做未处理，继续执行

`p*`类的命令：单步执行，

- p step over，等同于 F10
- pa 执行到制定的地址
- pc 执行到遇到下一条 call 指令
- pct 执行到遇到一条 call 指令或一个 return 指令
- ph 执行到一条分支指令：条件分支，call 调用，函数返回，系统调用等
- p 计数 计数为走过的指令或源代码的数量

`t*`类的命令： 类似 p \* 类的命令，但是遇到 call 时会跟踪进去。

- t 等同于 F11
- ta 执行到制定地址，本函数和被调用函数的每一步都会显示
- tb 执行到下一条分支指令
- tct 执行到下一条 call 或 return 指令
- th 类似 ph
- tt 遇到 return 指令
- wt 目标执行，直到制定的函数执行完成，显示统计信息

### 断点

`bp`命令设置一个断点。

```
    0:000> bp TestDebug!main 叹号前面指明了模块，main为模块内的函数名，指明模块可以减少符号的搜索时间。


```

设置断点的通用命令形式，`bp [ID] [Options] [Address [Passes]] ["CommandString"]`。如`bp MSVCR80D!printf+3 2 "kv; da poi(ebp+8)"`命令在`MSVCR80D!printf`设置一个断点，加入执行命令 “回溯栈，并显示参数值”。

在源码窗口，可以使用 F9 设置断点（同 VS 中）。

`bl`命令列出当前的所有断点。如`1 e 0040105d[TestDebug1.cpp@27]`断点信息中，1 表示断点 id，e 表示断点启用，如果是 d 表示断点禁用，u 表示断点未定。后面是断点的地址，以及断点的文件以及行数。

- bd id 禁用编号为 id 的断点
- be id 重新启用编号为 id 的断点
- bu 与 bp 一样，用于在一些没有被加载的模块中设置断点，一旦模块加载即可断到断点处。
- bc id 删除编号为 id 的断点

`bp`给 C++ 类成员函数加断点：

- bp TestDebug1.exe!CTestClass::SetChar
- bp TestDebug1.exe!CTestClass\_\_SetChar
- bp @@C++(TestDebug1.exe!CTestClass::SetChar)

两种语法表达式 @@C++ 表示 C++ 语法，@@masm 表示 MASM 语法，默认使用的是 MASM 语法。

`ba`用于给某个内存地址设断点，当这个内存地址被执行，读取，或写入时中断下来。通用命令形式为`ba [r|w|e] [大小] 地址`，此类断点在访问时会中断，r 为读写，w 为写入，e 为执行。大小可设置`1|2|4`三个值（64 位机器可以设置为 8）。

例如：

`ba w4 @@C++(&i)`命令中`&i`是表示变量 i 的地址，w 表示写入，4 表示只处理 & i 地址处的 4 个字节的写入。

`bm 符号型`设置符号断点，符号型可包含通配符。这个命令可以设置一些列的断点，例如：

- bp '模块! source.c:12' 在指定源码处设置断点
- bm myprogram!mem\* 符号型等同使用 x，在所有 mem 开头符号加断点
- bu mymodule!func ".dump C:\dump.dmp;g" 触发断点后执行指令 属于 bu [地址] ["命令串"]

`~0 bp sample!main` 针对 0 号线程，设置断点

条件断点，后续再学习使用，太庞大了有木有？？？

DLL 调试的断点，在调试 dll 时，需要断在 dll 加载或卸载时加断点，中断下来。

- sxe ld:[dll name] 加载某个 DLL 的时候中断
- sxe ud:[dll name] 卸载某个 dll 时中断下来

例如：

`sxe ld：wininet` 表示在 wininet.dll 被装载的时候断点。`bu wininet!DllMain` 表示在 wininet 模块的 DllMain 上断下来。

> 在编程代码中设置一个断点： kernel32!DebugBreak ntdll!DbgBreakPoint \_\_asm int 3 仅用于 x86

### 访问内存和寄存器

以 d 开头的命令用于查看内存值:

```
d[a|u|b|w|W|d|c|q|f|D] [/c #] [地址]
    a    Ascii字符
    u    unicode字符
    b    字节+ASCII
    w    字(两个字节)
    W    字(2字节)+ASCII
    d    双字 4字节
    c    双字 + ASCII
    q    四字 8字节

    f    浮点，单精度 4字节
    D    浮点，双精度 8字节

    yb    二进制和字节的值
    yd    二进制和双字节值

    s    查看String，ANSI_STRING的内容，非da查看的0结尾
    S    查看一个UNICODE_STRING的内容，非du的0结尾的字符串


```

`db addr`按照 BYTE 类型查看，`dd addr`按照 DWORD 类型查看。`d`不带地址会按照上一次`d*`命令的方式，接着上一次的显示继续显示。

例如：

```
dd 0046c6b0        显示0046c6b0处的双字
dd 0046c6b0    L3    显示0046c6b0处的三个双字
du 0046c6b0        显示0046c6b0处的Unicode字符


```

`dt`用于将内存按照指定格式解析。

- dt nt!\_PEB 7ffda000 用于显示结构体，数组，和类对象的内容
- dt argv 可以显示 argv 的内容
- dt -v 结构名称 用于显示结构体的信息内容。

`dv`显示当前作用域下的局部变量的类型和值。

```
dd*，dq*，dp*:
    第二位表示指针大小
    dd*     使用32位指针
    dq*        使用64位指针
    dp*        标准大小，32位或64位，取决于CPU
    第三位表示如何解引用内存：
    d*a        以ASCII字符形式显示解引用内存
    d*u        以Unicode字符形式显示解引用内存
    d*p        双字或四字显示解引用内存

    dds        查看四字节地址处的符号（dqs，dps）


```

`？ 表达式` ： 表达式求值命令，用来查看符号所代表的值 比如 ？ i 显示 i 的值是多少

`e*`命令可以将值写入内存，和`d*`类似。

- e[b|w|d|q|f|D] addr value 同 d\*，修改 addr 处的内存，值为 value
- e[a|u|za|zu] addr "chars" 修改 addr 处内存，值为 chars

例如`eb 0012ff78 'a' 'b' 'c' 'd'` 从地址开始一次写入后面的数值。

**寄存器**

`r`命令用于查看或修改寄存器和伪寄存器的值

- r 显示所有寄存器值
- r reg1，reg2 显示寄存器 reg1，寄存器 reg2 的值
- r reg1=value 设置寄存器 reg1 为 value
- ~0 r 显示 0 号线程的寄存器
- ~\* r 显示所有线程的寄存器

`!eflags`以可读方式显示 EFLAGS 寄存器内容

`rm`用于修改`r`命令的掩码，表示要输出那些寄存器的信息:

- rm 0x3 将 r 命令设置为输出 32 位 / 64 位寄存器的内容
- rm 0x1 | 0x2 | 0x8 同时显示段寄存器 / 32 位整数寄存器 / 64 位整数寄存器内容

**杂项**

- `!address addr` 用于显示指定的内存地址的信息。
- `!address -?` 显示帮助信息
- `!address -summary` 显示进程的摘要信息

例如：

```
!address 400000 用于显示当前进程模块的PE文件头。

!address -f:stack  ： 查看栈的使用情况

!vprot     addr    显示addr地址处的内存的属性

poi(esp)    取 esp所指向的值（相当于解析指针）

@eax         取寄存器的值。

!d / !e    读写物理内存


```

### 进程模块的查看命令

`lm[v|l|k|u|f] [m 模式]`命令用于列出模块：详细 | 带加载符号 | 进内核符号信息 | 仅用户符号信息 | 映像路径（m 模式 匹配）

```
lm  列举当前进程加载的模块，其实地址，模块名称等

lmf  显示每个DLL/EXE的具体路径

lm命令列表比较长，如果过滤出自己感兴趣的模块，使用lm m 表达式 命令
    lm m *theme* 列举出包含了 theme字符串的模块

lm vm *theme*  列举出模块的详细信息，比如版本，日期等

lm a addr  显示addr地址所在的模块

!lmi 模块    模块详细信息，包括准确符号信息
    !lmi uxtheme 列举出 uxtheme.dll的详细调试信息

!dlls    列出所有加载的的模块
    -i  按照初始化顺序
    -l  按照加载顺序
    -m  按照内存数序
    -v  显示详细信息
    -c 模块地址  仅显示地址处的模块

例如：
    lmv m kernel32  显示kernel32.dll的详细信息
    lmD              DML型的lm

!dh    显示pe文件的头信息
    -a  显示所有的信息
    -f  文件头，不显示区块信息
    -s  显示区块信息


```

### 堆栈的查看命令

`k`查看堆栈的内容

```
kp 能看到各个函数的输入参数，kp 5 显示5个函数的调用栈 （前提是有私有符号，微软的公有符号不行）

kP 比kp看起来更加舒服，所有项格式化

kn（callstack with index number）显示调用栈的栈号

kb 5 显示前5个函数以及他们的前三个参数

kf 5 显示前五个函数栈，以及他们所使用的栈大小

kv FPO信息，调用协议


```

`.frame`命令用于栈帧操作，不用任何参数则显示当前帧。

`.frame id` 切换到堆栈 id 处，可以查看这个地方的一些值与变量。在`.frame n`命令后，切换到指定栈帧，使用 `x`可以显示当前函数里面的局部变量值。

`!frame` 用 module!function 的方式设置栈帧，例如`!frame apphelp!ApphelpQueryExe`

用 X64 Windbg 调试 X86 程序时会涉及到 X64 堆栈和 X86 堆栈的切换：

```
!wow64exts.sw       在X64和X86堆栈之间进行切换
.effmach            设置当前调试的CPU架构


```

`~~[TID]` 显示线程 ID（TID）所指向的线程信息，`~~[TID]s`则切换到 TID 标识的线程上。TID 指示线程的 ID，并非调试器中线程序号。

`!findstack Symbol [displaylevel]`在栈中查找具有指定符号的线程。例如`!findstack explorer!` 查找那些调用栈上有 explorer.exe 的信息`displaylevel`指定显示线程信息级别，默认值 0 只显示线程的 ID 信息（即几号线程），2 则显示详细信息。

`!imports notepad` 显示 notepad.exe 导入的函数

`!inframe 0018df8c` 找出指定地址所在栈帧范围，例如`!inmodule 7586d9d11`找出指定地址所在模块

### 使用 Windbug 分析 dump 文件

```
!analyze -v  分析命令，自动分析dump

!analyze    !analyze -v  显示当前异常或故障检查信息：详细
            !analyze -hang 用户模式：分析线程栈，以确认是否那个线程正阻塞其他线程
            !analyze -f  查看异常分析，即便是调试器没有检测到异常

.lastevent    显示最近的事件或异常，可以看到发生异常的线程

!heap 分析出错的堆栈

!for_each_frame  dv  /t 显示每一个堆栈函数处的所有变量。

.opendump 文件名  打开dump文件

.dump 文件名      生成dump文件
.dump -?     显示dump的帮助命令
    .dump /mf 或 .dump /ma 将创建一个比.dump /f 更大更完整的文件

windbg -z C:\Awdbin\dumfile.dmp 来启动一个dump调试分析

.ecxr   定位当前异常的上下文信息，并显示重要的寄存器。 !analyze -v 命令后，可以使用这个命令查看异常发生位置的信息。显示异常上下文记录

.exr    显示异常记录
    .exr Address    Address 指示异常记录的地址
    .exr -1         表示显示最近的一次异常记录

.cxr    显示上下文记录
    .cxr Address 显示地址指定的上下文结构体中的信息


```

### 变量信息

- dt -h 显示 dt 帮助
- dt [模块!] 名称 显示变量信息
- dt [模块!] 名称 字段 [字段] 仅显示 "字段" 的值，结构或集合
- dt [模块!] 名称 [字段] 地址 显示的结构的地址
- dt [模块!] 名称 \* 列出符号（通配符）
- dv 显示本地变量与参数
- dv 样式 变量匹配样式
- dv [/i /t /V] [样式] i 为类型（本地，全局，参数） t 为数值类型 V 为内存位置或寄存器地址
- dv /i /t /v 可以显示当前栈帧上的 局部变量，全局变量，以及参数的值

例如：

```
dt ntdll!_PEB*        列出所有包含_PEB的变量
dt ntdll!_PEB* -v    以详细输出方式列出，包含地址与大小


```

`?? ("Evaluate C++ Expression")`，例如`?? Irp->Size`用来显示 C++ 表达式的值。

### 内存操作

**对比内存**

**搜索内存**

`s –a 00400000 L53000 "Wrong"`从`0x0040000`地址开始，向后`L53000`范围内搜索 “Wrong” 字符串。`s`命令后需要跟着选项，除了`n`和`l`两个参数必须和参数挨着，其他的如果指定了多个选项，需要用`[]`括起来。

类型：（类型前面加上 - 符号）

- b Byte
- w Word
- d DWORD
- q QWORD
- a ascii 字符串
- u Unicode 字符串

**移动内存**

### 调试子进程

- `.childdbg 1` 开启子进程调试（从主进程中启动的子进程被调试）
- `.childdbg 0` 关闭子进程调试

### 遍历链表

`dt`命令可以用于遍历链表，`dt -l List`的`-l`用于帮助`dt`寻找下一个`LIST_ENTRY`结构。比如`dt nt!_EPROCESS -l ActiveProcessLinks.Flink -y Ima -yoi Uni poi(PsInitialSystemProcess)`命令。

- `-o` 省略结构成员的偏移值
- `-i` 不要缩进子类型
- `-p` 地址值为物理地址，而不是虚拟地址
- `-r[depth]` 递归深度，显示几层子类型
- `-y` 列举以 - y 后参数指定 字符串开始的成员
- `-n` 双向列表为 LIST_ENTRY 的 Flink 或 Blink，单向列表为 SINGLE_LIST_ENTRY 的 Next 域

`dl`命令系列，`dlb`沿着 Blinks 成员遍历，比如：`dl nt!PsActiveProcessHead 1000`列举出`nt!PsActiveProcessHead`指向的列表一千个元素。

`!list`命令的通用形式如下：

`!list -t [Module!]Type.Field -x "Commands" [-a "Arguments"] [Options] StartAddress`

`!list -h`列出帮助内容。

- -x 要执行的命令
- -t 指定要遍历的列表，如何寻找下一个表项

### 内核调试

内核调试下，大部分应用程序调试的技巧与命令都是可以使用的，如下列举内核调试中一些特殊的内容。

**0. 内核下的断点**

`bp`设置断点，在指定的进程上下文下断，并断到指定的函数，如下的方法。

```
bp /p fffffa800295d060 nt!NtWriteFile "da poi(@rsp+30); g"


```

**1. 查看模块信息**

`!lmi mdlname`查看模块的详细信息，例如

```
!lmi nt 查看内核模块的信息


```

**2. 查看进程和线程的信息**

进程相关：

- !dml_proc 显示进程的列表，包括 EPROCESS 地址 / PID/Image Name 等
- !process 显示当前进程信息，包括 EPROCESS / ETHREAD 的地址，PEB/TEB 的地址
- !process 0 0 以摘要形式列举出当前系统中的所有的进程。第一个参数为要显示的进程 ID，第二个参数指定要显示属性，0 表示基本属性
- !process 0n132 0 查找 PID 为 132 的进程
- !process 0 0 notepad.exe 查找 notepad.exe 进程的详细信息
- !process -1 0 查看当前进程

`!process EPROCESS Addr No`显示某个进程的详细信息，例如

```
!process 826af478 3  显示EPROCESS地址为0x826af478的进程的信息


```

`.process`用于切换进程。`.process /r /p xxxxxxxx`切换到指定的进程，并且后面的再执行调试命令将在该进程中执行。

线程相关：

- !thread / !thread -1 显示当前线程
- !thread ETHREAD addr 0xFF 显示某个线程的详细信息
- !thread -t tid 显示指定线程 tid 的信息
- .thread 显示当前的线程
- .thread /p /r ETHREAD 切换到指定的线程上去

**3. IRP/IRQL / 设备堆栈**

- !irql 显示处理器当前的 IRQL 级别
- !irp 显示 IRP 的 I/O 堆栈
- !drvobj 显示设备对象
- !devstack 显示设备栈

**4. d\* 命令**

`dg @cs`显示选择子的内容

**5. !pcr / !prcb**

- !pcr 显示处理器控制域信息
- !pcr 1 显示 1 号处理器的控制域的信息
- !prcb 显示处理器控制块信息

**6. !idt**

`!idt`命令用于显示终端服务表。例如：

```
!idt  3     显示3号中断的中断服务函数

!idt -a        显示中断服务表中所有的中断例程


```

**7. !running**

`!running`命令显示当前正在运行的所有线程

**8. !gflag 显示，设置系统全局标志**

`!gflag -?`查看帮助信息，了解 gflag 设置。

**9. !vm 显示虚拟内存信息**

**10. !memusage 显示物理内存使用情况**

`!pfn` 显示物理内存页的详细信息，指定页面帧编号为参数

`!db/!eb`用来显示和修改物理内存，类似命令还有`!dd / !dc / !dq / !ed`

**11. !pte 显示指定的页表项和页目录项**

确定指定虚拟地址的内存信息

**12. !object 显示对象信息**

- !object xxxxxxxx 显示 指定地址 对象的信息
- !object \ 显示指定路径的对象的信息

**13. `!Token`**

`!Token e1ec21d8`显示指定的 Token 地址的\_TOKEN 结构体的内容。

**14. !lpc**

`!lpc`命令用于查看 LPC 的信息。例如：

```
!lpc port 0xe1366760  查看 LPC 端口的信息


```

### 调试专题

**1. 内存错误调试一栈**

1.  通过 dc 将指针的内容打印出来，如果看到了字符串，则可以通过 da 或 du 打印出来
2.  通过! address 收集关于内存的信息。其中包括了内存的类型（比如私有内存），保护级别（读取，写入与执行），状态（提交或保留）以及用途（堆或是栈）
3.  dds 命令将内存转储位双字或者字符。有助于将内存与特定的类型联系起来。
4.  dpp 命令对指针解引用，以双字形式转储内存的内容，如果有一个双字匹配了某个符号，这个符号将被显示。如果指针指向的内存包含了一个虚函数表，那么它将非常有用。
5.  dpa 和 dpu 命令将指向的内存分别显示为 ASCII 码和 Unicode 格式
6.  如果内存的内容是一个很小的数值（4 的倍数），那么它可能是一个句柄，通过扩展命令 !handle 来转储这个句柄的信息。
7.  如果没有任何结果，可以在整个地址空间中搜索这块内存的地址。

内存破坏的检测工具：

- 针对栈内存的破坏，编译器是比较好的工具，编译器可以在程序中添加对栈进行验证的代码
- 对于堆内存破坏，最好的工具就是应用程序验证器，Application Verifier。

栈结构：

```
|函数参数s        |
|函数调用返回地址 |
------------------
|保存ebp          |
|函数内的局部变量 |


```

前导指令：

```
8bff    mov edi, edi
55      push ebp
8bec    mov ebp, esp


```

后继指令：

```
8be5    mov esp, ebp
5d      pop ebp
c3      ret                // 函数调用方式不同，ret 指令也不同


```

`8bff mov edi, edi`这条指令很奇怪，似乎没有用。一般情况下，这条指令就是一条 NOP 操作，在特定情况下实现动态修补 Hot Patching。即对运行中的代码打补丁，这样就无需停机，额可以降低系统的停机时间。

动态修补的基本原理是用一个 jmp 指令来替代 mov edi, edi 指令，从而使得程序跳转到执行新的代码。这个指令就有两个字节，因此是一个短跳转，可以向前或向后跳转 127 个字节。而在该指令之前，有 5 个 Nop 指令，因此可以将该指令替换为一个短跳转，而将 5 个 Nop 指令替换为一个长跳转，突破了跳转的限制。

栈溢出：

当线程覆盖了为其他用途所保留的栈空间时，就是发生了栈溢出（Overflow，也称为上溢）。栈溢出的种类：

1.  数据复制，造成返回地址等栈信息被覆盖，造成错误。 strcpy 函数，在给栈上一个有限大小的字符数组复制字符串时就会发生
2.  局部变量无效：一个函数栈上申请的局部变量被传递给一个线程或函数，当该函数返回后，局部变量无效，其他函数或线程写该局部变量造成其他的函数崩溃。
3.  调用约定不匹配：调用函数和被调用函数定义的一组规则，双方都需遵守。

    - `__cdecl` C/C++ 的一种调用约定，可以支持变长数量的参数。由调用方清理栈。在函数名字前面加 "\_"
    - `__stdcall` 被调用方清理参数，函数名字前加 "\_", 在后面加 "@" 以及栈空间所需字节数
    - `__fastcall` 快速调用。被调用函数清理栈。前两个参数由 ECX，EDX 传递，在函数名前面加 "@"，函数名后面也加 "@" 以及所需栈空间字节数
    - `__thiscall` this 指针通过 ecx 传递，其余参数通过栈传递。被调用函数清理栈。

4.  当栈遭到毁灭性破坏时，通过如下的方式手动分析栈：栈回溯

    1.  dd esp esp+100 显示当前的栈帧（所有的，如果栈太深，可以用更大数字。）
    2.  查看其中的有效地址（在我们程序模块的地址中，lm 可以查看我们模块地址范围，然后将在这个范围的地址使用 ln 查看附近的符号）
    3.  ln addr 来查看这些有效地址附近的一些符号，用于寻找有用的函数调用过程。

这样可以分析出一些有意义的函数调用过程。同时要查找是什么原因造成了栈的破坏。

`u eip`查看当前执行代码是什么 `r` 查看当前所执行的代码的位置。eip，esp，ebp

**2. 内存错误调试一堆**

堆的管理是由堆管理器完成的，堆管理器分为前端和后端两部分，前端负责分配小的内存块，当前端没有时，再调用后端分配。如果分配内存较大，则直接放入虚拟分配块列表中，直接分配。堆的一些信息被放入了`_PEB`进程信息结构体中，其中的`ProcessHeaps`项是一个指针数组，其中包含了堆的地址。

堆破坏：

扩展命令`!heap`可以有效调试堆破坏情况。堆破坏的种类：

1.  使用未初始化的状态，例如一个指针未分配内存便使用，造成访问违规。
2.  堆的上溢或下溢：错误的代码覆盖了元数据，堆的完整性被破坏，程序出错。最好的例子就是字符串复制，将一个字符串复制到有限堆空间上。 `!heap -s`给出了进程的堆的分配情况。`!heap -a addr`显示指定堆的信息，堆列表的信息中可以找到被破坏堆的一些信息。

    比较简单的方法是使用 应用程序验证器，它会跟中堆破坏时将使用 Heaps 测试设置。也称为页堆。页堆的工作机制是在堆块的周围加上保护层，用来将各个堆块分开，如果堆块被覆盖了，那么它可以在尽量接近破坏的地方中断程序。普通堆块和页堆块的区别在于页堆元数据，页堆元数据包含了一定信息，堆块的大小，时机大小，以及栈回溯。通过这个栈回溯，可以得到该栈分配的操作的完整栈回溯，可以缩小代码搜索范围。 比如`HeapAlloc`分配了指针，`0019e260`转储页堆元数据内容，首先要减去`32(0x20)`字节，才能得到元数据。

    ```
     元数据在内存中设置：    32字节
     常规元数据    前置填充     页堆元数据         填充模式
     常规元数据    ABCDAAAA    页堆元数据        DCBAAAA            // 已分配堆块
     常规元数据    ABCDAAA9    页堆元数据        DCBAAA9            // 空闲堆块

     页堆元数据`_DPH_BLOCK_INFORMATION`
     堆    请求大小    实际大小    空闲队列    跟踪索引    栈回溯
     使用 dds 命令，可以将"栈回溯" 指向的地址中的栈信息显示出来。


    ```

3.  堆句柄不匹配

    从两块不同的堆块上分配的内存，释放时，将不同的内存释放到了非分配堆块上，造成错误。

4.  重用已删除的堆块

    两次释放同一个堆块，会造成堆管理器的前端的 旁视列表 出现链表循环，造成访问错误。这种错误只有在再次访问堆管理器前端时，才会出现。

    ```
     !heap -p -a <heap block addr>    通过这个命令查看页堆块的详细信息，找出释放两次的堆块地址。


    ```

**3. 进程间通信**

本地通信分析： 本地通信是通过 LPC 通信协议实现的。 LPC 通信的调试时通过内核调试实现的。内核态调试器的扩展命令`!lpc`可以使用这个标识来跟踪调用路径。通过`!thread`扩展命令获取正在处理的 LPC 请求，与当前请求相对应的消息标识。

`!lpc`获取与消息相关的信息。

- `!lpc message addr`
- `!lpc port <port_id>` 获取端口信息
- `!lpc thread` 获取系统上的所有 LPC 行为

LPC 协议的调试功能很强大，当服务器线程处理消息时，客户端线程将被阻塞，可以通过扩展命令 !lpc 分析内核结构发现

**4. 资源泄漏**

跟踪资源泄漏的工具：任务管理器，性能监视器。

任务管理器打开后，选择多列：内存使用，内存使用增量，内存使用高峰值，虚拟内存大小，句柄计数，线程计数，GDI 对象，`Process Explorer`可以查看进程中打开的资源类型，以及名称，对应的句柄值。

`!htrace`命令通过操作系统来跟踪所有打开句柄或者关闭句柄的调用，以及相应的栈回溯。

- !htrace -?
- !htrace [handle [max_traces]]
- !htrace [-enable [max_traces]]
- !htrace -disable
- !htrace -snapshot
- !htrace -diff

内存泄漏：

```
LeakDiag工具可以监控内存泄漏
!address  命令显示当前进程的内存使用情况。

!heap -s  显示进程的堆使用统计信息
!heap -s addr 显示指定的堆的情况，分配，使用等。

!heap -l  检测泄漏，-l 选项可以让命令以内存回收的形式列举出进程中处于活跃状态，但是没有被引用的内存。
    !heap -p -a  addr  可以看到堆分配操作的栈回溯。


```

**5. 同步**

同步的基础知识如下，

事件 (Event)，使用`!handle`命令可以查看当前进程的 Handle，以及其对应的类型。

```
0:001> !handle
Handle 4
  Type             Directory
Handle 8
  Type             File


```

`!handle id f`命令来查看句柄的详细信息，`id`为`!handle`所列举的句柄的值，比如 4，8 等。

临界区 (Critical_section)，临界区的内存布局为 RTL_CRITICAL_SECTION 结构体。

```
dt RTL_CRITICAL_SECTION   可以查看结构体的成员。
0:001> dt RTL_CRITICAL_SECTION
uxtheme!RTL_CRITICAL_SECTION
   +0x000 DebugInfo        : Ptr32 _RTL_CRITICAL_SECTION_DEBUG
   +0x004 LockCount        : Int4B
   +0x008 RecursionCount   : Int4B
   +0x00c OwningThread     : Ptr32 Void
   +0x010 LockSemaphore    : Ptr32 Void
   +0x014 SpinCount        : Uint4B


```

- DebugInfo 是系统分配的结构，包含临界区的信息。
- LockCount 表示有多少个线程正在等待进入临界区
- RecursionCount 表示统一线程进入临界区多少次
- OwningThread 标识拥有该 临界区的线程
- LockSemaphore 表示临界区是否空闲，是否可以进入
- SpinCount 多 CPU 系统中，等待进入临界区时会进行 spin 操作，这个是进入之前进行操作的次数

`!cs`命令可以列举出当前进程的所有临界区的信息。

互斥体 (Mutex)。

信号量 (Semaphore)。

死锁调试：

- !runaway 列举出当前所有线程的执行时间
- !runaway 7 列举出执行时间的详细信息
- !locks 列举出死锁的信息

`~*kb` 查看当前在进程中运行的所有的线程堆栈

```
0:002> ~*kb
       0  Id: c9c.131c Suspend: 1 Teb: 7ffde000 Unfrozen
    ChildEBP RetAddr  Args to Child
    002dfe04 77486a64 77472278 00000474 00000000 ntdll!KiFastSystemCallRet
    002dfe08 77472278 00000474 00000000 00000000 ntdll!ZwWaitForSingleObject+0xc    //等待锁
    002dfe6c 7747215c 00000000 00000000 00a7336c ntdll!RtlpWaitOnCriticalSection+0x13e
    002dfe94 6ffbc20c 00a7336c 7720c326 0000046c ntdll!RtlEnterCriticalSection+0x150
    002dfeac 00a710fd 00a7336c 00a733a4 002dff0c vfbasics!AVrfpRtlEnterCriticalSection2+0x4d
    002dfec8 00a712b0 00000001 0307bfd0 0302df68 memory1!main+0x9d [c:\users\guotao\desktop\memory1\main.cpp @ 58]
    002dff0c 7720ee1c 7ffdf000 002dff58 774a37eb memory1!__tmainCRTStartup+0x10f [f:\dd\vctools\crt_bld\self_x86\crt\src\crtexe.c @ 582]
    002dff18 774a37eb 7ffdf000 760d4651 00000000 kernel32!BaseThreadInitThunk+0xe
    002dff58 774a37be 00a713f8 7ffdf000 00000000 ntdll!__RtlUserThreadStart+0x70
    002dff70 00000000 00a713f8 7ffdf000 00000000 ntdll!_RtlUserThreadStart+0x1b

       1  Id: c9c.63c Suspend: 1 Teb: 7ffdd000 Unfrozen
    ChildEBP RetAddr  Args to Child
    032efb34 77486a64 77472278 00000470 00000000 ntdll!KiFastSystemCallRet
    032efb38 77472278 00000470 00000000 00000000 ntdll!ZwWaitForSingleObject+0xc    //等待锁
    032efb9c 7747215c 00000000 00000000 00a73384 ntdll!RtlpWaitOnCriticalSection+0x13e
    032efbc4 6ffbc20c 00a73384 6e5561a2 6ffbc290 ntdll!RtlEnterCriticalSection+0x150
    032efbdc 00a71031 00a73384 00000000 02e68fe0 vfbasics!AVrfpRtlEnterCriticalSection2+0x4d
    032efbec 6ffc42f7 00000000 6da35f20 00000000 memory1!ThreadProc+0x31 [c:\users\guotao\desktop\memory1\main.cpp @ 19]
    032efc24 7720ee1c 02e68fe0 032efc70 774a37eb vfbasics!AVrfpStandardThreadFunction+0x2f
    032efc30 774a37eb 02e68fe0 750e4579 00000000 kernel32!BaseThreadInitThunk+0xe
    032efc70 774a37be 6ffc42c8 02e68fe0 00000000 ntdll!__RtlUserThreadStart+0x70
    032efc88 00000000 6ffc42c8 02e68fe0 00000000 ntdll!_RtlUserThreadStart+0x1b


```

很明显两个线程都在等待事件对象，而停止运行了。

`!cs addr`可以显示内存处临界区的内容

```
0:002> !cs 0x00a73384
-----------------------------------------
Critical section   = 0x00a73384 (memory1!cs_DB2+0x0)
DebugInfo          = 0x02b3afe0
LOCKED
LockCount          = 0x1
WaiterWoken        = No
OwningThread       = 0x0000131c
RecursionCount     = 0x1
LockSemaphore      = 0x470
SpinCount          = 0x00000fa0


```

该临界区被锁住了，所属的线程 id 是`131c`。

- !cs -s 显示每个临界区的初始堆栈回溯
- !cs -l 仅显示锁定的临界区
- !cs -? 显示 !cs 的帮助信息

`~~[tid]` 查看当前线程等待的锁是什么，tid 为线程 id。

会产生死锁的集中情况：

1.  孤立临界区的情况 —— 异常

    临界区被放入 try 中，在临界区中的代码发生了异常，这直接导致执行 catch 代码，而不会执行 LeaveCriticalSection 的代码因此调用其他接口时，需要注意是否会出现这种异常而直接跳出的情况。 比较好的解决办法是将进入和离开临界区的代码封装成类对象，声明局部变量，从而实现跳出作用域即解锁。因此发生异常，出现栈回退时，该局部变量即被销毁，从而解锁。

2.  孤立临界区的情况 —— 线程结束

    在线程过程中，进入临界区后，直接调用 TerminateThread，退出了线程，而没有机会执行 LeaveCriticalSection

3.  动态库

    动态库在加载时，Windows 为了确保 DLL 的加载过程与卸载过程的完整性，使用了一个加载器锁来将所有对 DLLMain 函数的访问串行化。这么做的目的是防止并发执行 DllMain 函数可能出现的问题。 这样如果在 DllMain 函数中调用了线程创建，并等待线程结束，就会出现问题。当前线程在调用 DllMain 时，会对加载器锁进行加锁，而当线程创建时，会再一次调用到本 DllMain 中，这时就会等待加载器锁的释放，而前一个线程正在等待这个线程结束的事件。造成了死锁。因此在 DllMain 中应该做尽量少的工作，尽快返回。

4.  竞争锁

    出现 "锁护送" 的问题。解决的方法就是使用自旋计数。

管理临界区：

- 使用临界区之前没有初始化
- 在临界区删除之后，仍然使用它
- 过度释放临界区
- 没有充分释放临界区

**6. 64 位调试**

64 位和 32 位的转换：`!wow64exts.sw`命令在 X64 和 X86 之间切换。新的调试命令为`.effmach x86`转到兼容模式调试，即 32 位模式调试。

64 位函数调用方式：一种是类似 x86 的 fastcall 调用，rcx，rdx，r8，r9 四个寄存器分别保存前四个参数，剩余参数通过压栈传递

`!straddr`列举出当前线程的 PEB，在兼容模式进程中，每个线程都有两个 TEB，64 位和 32 位的。

当前执行指令 依旧 在 $ip 中。

x64 的栈，依旧是向低地址方向增长，但是在调用函数之前要按照 16 字节对齐的。调用者依旧会给这些通过寄存器传递的参数分配空间，但是不会去初始化它，也不会用它。而被调用函数，可以使用这些参数空间。比如被调用函数中要使用传参寄存器，可以将寄存器值放入这些分配的参数空间中

By Andy @2018-06-18 12:26:29
