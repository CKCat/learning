原文地址 [web.archive.org](https://web.archive.org/web/20201017055517/https://dbgtech.github.io/Tools/gdb-using-note.html)



### GDB 调试器原理

gdb 调试器是使用 Linux 上提供的`ptrace`系统调用来实现的，`ptrace`系统调用的原型如下所示。

```
long ptrace(enum __ptrace_request request,  // 定义要执行动作
            pid_t pid,                      // Linux进程的ID
            void *addr,                     // 要拷贝地址值
            void *data);                    // 存放要拷贝数据


```

系统调用`ptrace`提供了一种方法来让调用进程可以观察和控制其他进程的执行，检查和改变其内存以及寄存器。它主要用于实现断点调试和系统调用追踪。

当进程被追踪后，被追踪进程接收到除了`SIGKILL`之外的其他任何信号都将停止，跟踪进程会在下一次调用`wait*`函数时收到通知（函数返回值中会有状态值包含被跟踪进程停止原因）。当被跟踪进程停止后，跟踪者进程就可以使用各种`ptrace`请求来查看和修改被跟踪进程。

`reqeust`参数可取的几个典型参数：`PTRACE_TRACEME`表示本进程将被其父进程跟踪，交付给这个进程的所有信号（除`SIGKILL`之外）都将使其停止，父进程将通过`wait()`获知这一情况。`PTRACE_ATTACH`表示挂到一个指定的进程，使其成为当前进程跟踪的子进程，子进程的行为等同于它进行了一次`PTRACE_TRACEME`操作。`PTRACE_CONT`表示继续运行之前停止的子进程，可同时向子进程交付指定的信号。

例如，运行 gdb，输入`attach pid`，`gdb`对指定进程执行下述操作：

```
ptrace(PTRACE_ATTACH, pid, 0, 0);


```

如果通过 gdb 中启动指定的可执行程序，即`gdb`中输入`run`命令，`gdb`执行下述操作：

*   通过`fork()`系统调用创建一个新进程。
*   在新创建的子进程中执行下述操作：`ptrace(PTRACE_TRACEME, 0, 0, 0);`。
*   在子进程中通过`execv()`系统调用加载用户指定的可执行文件。

**信号**

gdb 的调试基础其实就是 Linux 中的信号，整个调试过程都是建立在信号基础上的。

*   在使用参数为`PTRACE_TRACEME`或`PTRACE_ATTACH`的`ptrace`系统调用建立调试关系之后，交付给目标程序的任何信号（除`SIGKILL`之外）都将被 gdb 先行截获，或在远程调试中被 gdbserver 截获并通知 gdb。
*   gdb 因此有机会对信号进行相应处理，并根据信号的属性决定在继续目标程序运行时是否将之前截获的信号实际交付给目标程序。
*   信号是实现断点功能的基础。以 x86 为例，向某个地址打入断点，实际上就是往该地址写入断点指令`INT 3`，即`0xCC`。目标程序运行到这条指令之后就会触发`SIGTRAP`信号，gdb 捕获到这个信号，根据目标程序当前停止位置查询 gdb 维护的断点链表，若发现在该地址确实存在断点，则可判定为断点命中。
*   gdb 暂停目标程序运行的方法是向其发送`SIGSTOP`信号。`kill_lwp(process->head.id, SIGSTOP);`

调试中其他的操作其实就和其他的调试器大同小异了，比如设置断点，单步，源码单步（step/next），指令单步（stepi/nexti），完成当前函数（finish）等，不再一一列举。这块后面可以尝试编写一个调试器，来熟悉一下编程过程。

### GDB 文档笔记

GDB 文档是学习 GDB 最好的材料，但是它是英文的资料，不太容易看！这里将看过的内容做个笔记，方便以后使用中遇到问题来查看。

**启动 gdb**

最简单的形式就是在 shell 命令中执行`gdb`即启动了。

```
gdb program            // 指定可执行程序
gdb program core       // 指定可执行程序和转储文件
gdb program 1234       // 指定可执行程序和进程ID，调试正在运行程序


```

注意这里对于对第二个参数，gdb 优先当作核心转储文件，如果找不到该名字文件时，才将它当作进程 ID 号处理。其实可执行程序和后面两个参数可以添加额外的选项来明确它们。`-e file/-exec file`来指定可执行文件为 file，`-se file`则用来指定可执行文件和符号文件源自同一文件，`-c file/-core file`使用文件 file 作为转储文件，`-p number/-pid number`将 number 作为要挂入的进程 ID，这样就很明确指出了各个文件，不会出现上面的二义性。

如果在用 gdb 启动调试程序时就想给程序指定参数，可以使用选项`--args`，如下调试 gcc 编译程序的过程。

```
gdb --args gcc -O2 -c foo.c


```

```
gdb -q/--quiet
gdb --silent       用于指定gdb不要输出版本和版权信息

gdb -h/-help       显示gdb启动的帮助，不包括gdb内部命令。

-s file/-symbols file 从文件file中读取符号

-x file/-command file 执行文件file中的命令。

-ex command/-eval-command command 执行一条GDB命令，即command。

-ix file/-init-command file 从文件file中执行命令，这个命令执行在加载子进程之前。

-d directory/-directory directory 将directory目录添加到源码和脚本文件搜索路径中。

-r/-readnow 立即读取每一个符号文件的整个符号表

-tui 用于启动GDB的GUI窗口形式


```

gdb 在启动时会加载初始化文件，首先会加载系统范围的初始化文件，它的路径使用`--with-system-gdbinit`配置选项指定，如果指定了 gdb 会先加载它。其次为 home 目录的`.gdbinit`文件，最后会加载当前工作目录的`.gdbinit`文件。

退出 GDB 则使用如下的两种命令：

```
q/quit   // 退出GDB

Ctrl-D   // 文件结尾符号也可以退出。


```

快捷键`Ctrl-C`并不退出 GDB，它是将正在执行的被调试程序中断下来。

在 GDB 中可以直接执行 shell 命令而不用退出 GDB，对于 make 是特特利，它可以直接执行，如同在 shell 中执行一样，而不需额外的修饰。

```
shell command-string  //可以直接执行`command-string`所指定的命令而不需退出gdb。
!command-string

// 比如
(gdb) !ls
Desktop  Downloads


```

**gdb 日志**

其实 gdb 的调试调试过程是可以被记录下来的，直接将屏幕上显示的内容记录到文件中。

```
set logging on                    开启日志功能
set logging off                   关闭日志功能
set logging file filename         设置日志记录的文件名称
set logging overwrite [on|off]    设置日志文件覆写的开启与关闭，默认是追加到日志文件
set logging redirect [on|off]     默认重定向，即进入终端也进入日志文件，设置重定向开启后，则只进入文件

show logging                      显示当前的日志功能设置


```

**gdb 命令**

gdb 命令还是比较随意的，它可以简写，即指使用命令起始的几个字符，只需要不出现歧义即可（二义性）。输入命令的一部分后，可以使用两次`TAB`键来将命令补充完整或显示所有可选的命令。不输入任何内容直接回车则是重复上一条命令，对于`list`和`x`等命令则不是简单重复，gdb 会重新组织参数。

gdb 命令语法也比较简单，以命令起始，后面跟着命令的参数，命令的长度不受限制。符号`#`后的内容是注释，这对于命令文件比较有用。

两次`Tab`键不但可以不全 gdb 的命令，还可以不全调试文件中的符号信息，对于输入部分符号，gdb 可以搜索符号表，进行不全或显示可选的所有符号。对于`C++`中的重载符号，则需要在符号前输入`'`单引号，提示 gdb 这是`C++`重载函数，比如`b 'buble(`会提示出`bubble(double, double)和bubble(int, int)`符号。

```
set max-completions limit    // 设置tab补全时，满足条件符号最多显示个数
show max-completions


```

**gdb 获取帮助**

`(gdb) h / help`可以显示 gdb 的帮助内容，显示内容为命令的类别，如下列举一下帮助内容：

```
(gdb) help
List of classes of commands:

aliases -- Aliases of other commands                    // 别名
breakpoints -- Making program stop at certain points    // 断点
data -- Examining data                                  // 查看数据
files -- Specifying and examining files                 // 指定和检查文件
internals -- Maintenance commands                       // gdb维护命令
obscure -- Obscure features                             // 隐晦功能
running -- Running the program                          // 运行程序
stack -- Examining the stack                            // 查看栈内容
status -- Status inquiries                              // 状态查询
support -- Support facilities                           // 支持设施
tracepoints -- Tracing of program execution without stopping the program // 不暂停程序来追踪程序
user-defined -- User-defined commands                   // 用户定义命令

Type "help" followed by a class name for a list of commands in that class.
Type "help all" for the list of all commands.
Type "help" followed by command name for full documentation.
Type "apropos word" to search for commands related to "word".
Command name abbreviations are allowed if unambiguous.


```

下面注释有几行，第一行为输入`help`加上一个类别名字来列举该类别中的命令；`help all`列举所有的命令；`help`加命令名字显示命令的完整文档；`apropos word`用于搜索和`word`相关的命令。

gdb 有一个`compelte`命令可以用来将一个命令补充完整，比如`complete i`会列举出如下内容：

```
if
ignore
inferior
info
init-if-undefined
interpreter-exec
interrupt


```

有几个命令需要额外说明一下，`info`，`set`，`show`三个命令。`info`用于描述被调试程序的状态，例如`info args`显示当前执行程序的参数，`info registers`显示当前程序暂停状态的寄存器内容，使用`help info`可以看到 info 子命令的完整列表。`show`命令与 info 命令相对应，它用于显示 gdb 本身的状态，比如`show radix`显示 gdb 当前显示数字使用的数基，十六进制，还是十进制，直接输入 show 命令显示 gdb 中可修改的参数，以及这些参数当前的值。`set`命令既可以用来设置被调试程序状态，比如`set $rax = 10`修改寄存器，还可以修改程序变量的值等，同时还可以修改 gdb 本身的状态值，比如设置 gdb 的提示符为`$`可以用`set prompt $`。

如下几个 show 的杂项子命令是没办法用 set 命令进行设置，如下：

```
show version         显示GDB的版本信息

show copying
info copying          显示GDB的复制许可

show warranty
info warranty          显示GDB的授权信息

show configuration     GDB的编译配置，报告GDB的bug时有用。


```

**GDB 运行程序**

gcc 编译时，`-g`选项为编译程序保留调试信息，`-g3`选项可以保留宏定义，以便在 gdb 中调试宏定义。GCC 编译的调试信息都是以`DWARF`格式保存，使用最新版本的 DWARF 格式调试信息可以获得比较好的调试体验，它是 GDB 目前最具表达力，并且支持最好的调试信息格式。

> `info macro` 查看宏在那些文件被引用，宏定义什么样子，`macro` 可以查看宏展开的样子。

在 gdb 中执行`r/run`命令可以运行程序，gdb 会创建一个 inferior 进程（老雷起名字为下程，这里总结也用这个名字吧，但是也不太准确）来运行程序。

程序运行时有四类信息会影响到程序，分别是参数，环境变量，工作目录，标准输入输出。

可以使用`run`命令来指定程序运行的参数，`info args`可以查看当前设置的参数值；环境变量通常从 GDB 的环境变量中继承，`set environment`和`unset environment`命令可以修改程序执行的环境变量；工作目录也从 GDB 的继承，可以使用`cd`命令在 GDB 中修改工作目录；标准输入输出也使用 GDB 相同值，可以在`run`命令行进行重定向，或者使用`tty`命令设置不同设备作为输入输出。

`start`命令是另外一个运行程序的命令，它对于`C/C++`程序比较有用。`C\C++`程序执行时，会以`main`函数作为起点，在 gdb 中使用`start`命令可以让程序开始运行后停在`main`函数。如果不设置断点，`run`命令执行后直接让程序完整运行起来。但是对于`C/C++`程序中的全局变量或对象初始化，`start`命令则直接执行完毕。

几个有用设置：

```
set disable-randomization on/off  // 将程序的虚拟地址空间随机化关闭，有助于调试
show disable-randomization

set args        // 指定下一次程序执行参数，如果args后没有参数，则run命令执行程序时不传入参数
show args

path directory  // 将directory字符串指定的路径添加到程序执行 PATH中
show paths

show environment [varname]  // 打印环境变量`varname`的值
set environment varname [=value] // 设置环境变量varname值为value
unset environment varname   // 删除环境变量 varname，不同于`set environment varname=`

cd [directory]   // 设置GDB工作路径为directory，如果不指定directory参数，默认为`~`
pwd              // 打印GDB工作目录

info terminal    // 显示GDB记录的终端模式的信息
run > outfile    // 对程序的标准输出重定向到文件 outfile 中

tty /dev/ttyb    // 使用/dev/ttyb作为输入输出的默认终端


```

对于已经运行程序，可以使用`attach pid`命令来挂到`pid`所指定的进程上。`info files`可以显示活动的目标。使用`ps`或`jobs -l`命令行命令可以找到要挂的程序的进程 ID。`attach`命令只能执行在支持进程的环境，对于裸板目标，则无法使用该方法。

```
(gdb) info files
Symbols from "/opt/360/browser360-beta/browser360".
Local exec file:
    `/opt/360/browser360-beta/browser360', file type elf64-x86-64.
    Entry point: 0x555557b50000
    0x00005555555542a8 - 0x00005555555542c4 is .interp
    0x00005555555542c4 - 0x00005555555542e4 is .note.ABI-tag
    ......


```

一旦`attach`命令执行挂上目标进程，那么 gdb 会首先尝试在当前目录查找可执行程序，其次在源文件搜索路径查找。使用`file`命令可以直接加载进程对应的程序。

`detach`可以将已经挂接进程直接释放掉对程序的控制，一旦执行命令，可执行程序就再次独立执行了。如果是使用`run`命令执行的进程，使用`attach`命令则会直接杀死进程。`kill`命令直接杀死正在 GDB 中调试子进程。

**多进程调试**

在一个 gdb 会话中可以运行和调试多个程序，此外，一些系统上的 gdb 可以让你同时运行几个程序。通常情况下，可以从多个可执行程序启动进程，并且多个进程中的每一个进程都可以是多线程进程。

gdb 使用一个对象，叫做下程，来表示每个程序执行的状态。通常一个下程对应于一个进程，但是对于没有进程概念的系统也适用。下程一般在进程执行之前已经存在，在进程退出后依然在 gdb 中保留。gdb 中每一个下程都有自己的 ID，这个 ID 不同于进程的 ID。通常下程有自己独立的地址空间，尽管对于嵌入式目标来说可能几个下程执行在一个地址空间的不同位置。每一个下程也同样有多个线程在其中执行。

```
info inferiors      // 显示GDB当前管理的所有下程，包括ID，下程标识和运行的可执行程序名称
(gdb) info inferiors
  Num  Description       Executable
  1    <null>            /bin/ls
* 2    <null>            /bin/myls

inferior infno     // 切换当前下程为infno的下程，如上ID=2的下程为当前下程

add-inferios [-copies n] [-exec executable]
    // 为gdb添加管理的下程，-copies n为添加几个副本，-exec指定可执行程序，否则为null

clone-inferior [-copies n] [infno] // 拷贝ID为infno的下程n份，默认为1份。

remove-inferior infno   //删除ID为infno的下程

detach inferior infno   // 从下程infno分离，仅仅是不调试对应进程，但是下程依然存在
                        // Description字段值为 null
kill inferior infno     // 杀死下程，但是下程记录依然存在于gdb中


```

如下为与下程相关的一些设置：

```
set print inferior-events  on/off     // 设置是否打印下程启动与退出或分离的时间信息
show print inferior-events


```

在调试器中对进程调试时，被调试的进程会有继续启动子进程的问题。默认情况下，如果被调试进程使用`fork`等命令创建了子进程时，调试器不会对被调试进程进行调试，但是如果在父进程中设置断点地址被子进程中执行到了，那么子进程会收到`SIGTRAP`信号，这会导致子进程终止。

这种情况下要调试子进程，可以使用一种方法是在子进程中`fork`返回时执行`sleep`函数来暂停子进程，然后可以在 gdb 中挂入子进程进行调试。其他方法就是可以通过设置 gdb 的设置来调试子进程。

```
set follow-fork-mode parent/child  // 对于调用fork/vfork的程序调用，设置跟随模式
        // 即调用fork等函数时，是调试子进程还是调试父进程，默认为调试父进程
show follow-fork-mode

set detach-on-fork on/off  // 执行fork时是否自动detach，默认为on
        // 默认值为on，即执行到fork时，是否进行detach操作，具体操作要依赖于follow-fork-mode
        // 如果设置为off，gdb会保持控制所有fork的进程，这样同时调试 父子进程
show detach-on-fork

set follow-exec-mode new/same // 设置调试器对程序调用exec的反应，exec会替换进程的程序映像
        // new 表示执行exec时创建新的下程
        // same 表示依然使用原来的下程，新的程序映像替代原来映像加载到内存


```

调试多进程时另外一个好用命令为`checkpoint`，它是 gdb 保存的进程状态的快照，称作检验点，在之后的程序运行时可以回到这点。

```
checkpoint       // 保存一个当前执行程序状态的快照，该命令没参数

info checkpoints // 列举出当前调试会话中已经保存的检查点

restart checkpoint-id // 恢复程序状态到检查点ID `checkpoint-id`上。包括程序变量，寄存器和栈帧。

delete checkpoint checkpoint-id 删除`checkpoint-id`指定的检查点


```

虽然 gdb 回到检查点设置位置重新执行，但是已经发送给打印机的数据无法回退，只能再次发送，传送给串行管道的数据无法在删除。虽然有这些问题，检查点还是比较好用的功能，比如 linux 上由于地址空间随机化不能复现问题，使用检查点就可以在问题复现时设置检查点，反复调试有问题的代码。

**多线程调试**

在一些系统中，比如 Linux，Solaris，单一进程也会有多个执行线程。线程在不同操作系统中有不同的具体语义。gdb 提供了调试多线程程序的功能。

```
info thread  // 查看当前调试的所有进程中所有线程。

thread <ID>  // 切换调试的线程为指定ID的线程。

thread apply [thread-id-list | all -[ascending]] args // 应用命令到多个线程上。

set print thread-events       // 控制线程启动和退出的消息输出。

break 'file.c':100 thread all //  在file.c文件100行处为所有的线程设置断点


```

`set scheduler-locking off|on|step` 用`step`和 c`ontinue`命令调试当前被调试线程时，其他线程也是同时执行的，怎么只让被调试程序执行呢？`off`不锁定任何线程，所有线程都执行，默认值为`off`。`on`只有当前被调试程序会执行，`step`在单步时，除了`next`过一个函数情况外，只有当前线程会执行。

在下程中要指定线程可以使用`inferior-num.thread-num`的语法，两个参数分别为下程的 ID，以及下程中的线程 id。如果 gdb 中只有一个下程，那么 gdb 不会显示`inferior-num`。

gdb 调试中有两个方便变量`$_thread`和`$_gthread`分别用于表示当前线程的线程标识和全局的线程标识。

在多线程调试中有两种模式，`All-Stop`和`Non-Stop`。`All-Stop`模式下，如果暂停程序执行，所有的线程都暂停执行，这可以方便检查整个程序的状态；当继续执行程序时，所有线程都开始执行。gdb 无法以单步方式执行所有的线程，这主要是因为线程调度依赖于调试目标的操作系统。

一些系统上可以使用如下命令来实现锁定调度器，从而只允许一个线程执行。

```
set scheduler-locking on/off   // 设置调度器锁定模式
show scheduler-locking


```

对于多线程调试的另外一个问题：如果调试多个下程，在当前下程中执行单步或继续执行时，默认其他下程是处于暂停状态的，可以通过如下命令设置其他下程的动作。

```
set schedule-multiple on/off   // 指定单步或继续执行时，是否允许所有下程执行，默认off
show schedule-multiple


```

对于`Non-Stop`模式，gdb 只暂停当前调试线程，其他的线程可以继续运行。使用如下连续执行命令可以设置非暂停模式。

```
# If using the CLI, pagination breaks non-stop.
set pagination off

# Finally, turn it on!
set non-stop on


```

```
set non-stop on/off   // 操作非暂停模式的设置，on表示开启非暂停模式
show non-stop


```

在`Non-Stop`模式下，`continue`就只是操作当前线程，要继续执行所有线程可以使用`continue -a/c -a`，如果要中断执行`interrupt`或`Ctrl-C`只暂停当前的线程，中断所有线程使用`interrupt -a`。

在多线程调试中有一个问题，由于调试器中断的方式是使用信号，这回影响到应用程序的系统调用，比如`sleep`函数等。一种方法是使用 GDB 的观察模式来调试，它不会影响到程序执行，关于观察模式的详细使用可以参考 gdb 的文档。

**断点**

`info program` 显示程序状态信息，是否在执行，进程是什么，暂停原因等。

断点使得程序在执行到特定点时暂停，可以为断点添加条件，用来更加精细控制程序暂停。断点可以用源代码行号，函数名字或精确的程序地址来设置。一些系统上在程序执行前可以在共享库上设置断点。观察点（watchpoint）是一类特殊断点，当表达式变化时暂停程序执行，表达式可以是变量值，或者是用操作符组合的多个变量形成的表达式。除了设置断点使用特殊的命令，其余的开启，关闭或删除观察点都和普通断点使用相同命令。捕捉点（catchpoint）是另外一类特殊断点，当某种特定的事件发生时暂停程序执行，比如`C++`异常，加载动态库等（当程序接收到信号时暂停需要使用 handle 命令）。捕捉点类似观察点，除了设置需要特殊命令外，其他的管理都类似普通断点。

普通断点：

与捕捉点和观察点相区分，使用`break`命令设置的都是普通断点。

```
break location      // 在给定的位置location上设置断点，可以是函数名，行号或指令地址

break            // 没有参数的命令，在当前栈帧设置断点，当下一次再进入当前栈帧时即暂停

break ... if cond   // 设置条件断点，在每次到达断点时计算表达式cond的值，只有当值非0时暂停

tbread args         // 临时断点，只使用一次

hbreak args         // 硬件断点

thbreak args        // 设置硬件临时断点

rbreak regex        // 使用正则表达式匹配位置

rbreak file:regex   // 在指定的文件中匹配函数名字
    (gdb) rbreak file.c:.  // 将file.c中所有函数都设置断点

info breakpoints [list...] // 打印所有的断点，观察点和捕捉点的列表
info break [list...]


```

设置断点可以设置在没有加载的动态链接库上，断点设置后会显示`PENDING`，当动态链接库加载后会落实这个断点。如果动态链接库卸载了，那么对应的断点又变为未决的状态。

断点设置也有几个配置项，如下：

```
set breakpoint pending auto/on/off // 对于找不到位置断点，是否设置为未决
show breakpoint pending

set breakpoint auto-hw on/off      // 设置断点，对于符合条件是否自动转为硬件断点
                                   // 比如只读内存
show breakpoint auto-hw

set breakpoint always-inserted off/on // 通常程序暂停，断点被取消，运行时才被设置
show breakpoint always-inserted       // 默认off，如果设置为on，程序暂停也设置断点

set breakpoint condition-evaluation host/target/auto
show breakpoint condition-evaluation  // 对于条件计算的位置，在主机，目标机，自动选择
                                      // 这对于远程调试有效


```

观察点：

观察点有时也被称为数据断点，当表达式值变化时程序会暂停，表达式可以是简单变量（`*global_ptr`），或特定类型地址（`*(int*)0x12345678`）或任意复杂的表达式（`a*b + c/d`）等。

数据断点的实现依赖于系统，如果系统支持硬件断点，那么数据断点使用硬件断点，否则 gdb 设置软件观察点，它是通过单步执行程序，并且每次单步时间差变量值。软件观察点比正常执行的速度慢几百倍。

`watch [-l|-location] expr [thread thread-id] [mask maskvalue]` 设置一个表达式的观察点。当表达式`expr`被写入，值发生变化时则暂停程序。最简单的方式是`(gdb) watch foo`。`[thread thread-id]`用于指定在特定的线程上数据发生变化时才暂停；

`rwatch`设置读数据断点，`awatch`设置读写数据断点。`info watchpoints [list...]`打印观察点，类似于`info break`。

```
set can-use-hw-watchpoints 0/1  // 设置是否可以使用硬件观察点，如果为0，即使支持硬件也不使用
show can-use-hw-watchpoints


```

有时无法设置硬件断点，这主要是由于观察表达式的数据类型比目标机器上硬件断点可以处理的类型更宽。这时其实可以设置为一系列小的区域，对他们分别设置数据断点。如果已经设置了太多的硬件断点，GDB 再设置硬件断点也会失败。

在程序执行越过了表达式的可见范围，观察点会自动删除，比如对局部变量设置观察点。

捕捉点：

当特定的程序事件发生时暂停程序，例如`C++`异常，加载共享库等。

`catch event` 当事件发生时暂停程序，`event`可以取如下的参数：

1.  throw [regexp]/rethrow [regexp]/catch [regexp] `C++`异常，如果指定了`regexp`则只有异常类型满足正则表达式时才捕获。方便变量`$_exception`在一些系统上包含了抛出的异常。
2.  exception 对 Ada 异常调试有用
3.  exception unhandled 抛出了异常，但是程序没有处理的异常
4.  assert Ada 断言失败
5.  exec 对 exec 的调用
6.  syscall / syscall [name | number | group:groupname | g:groupname]... 对系统调用的调用或从系统调用返回时会暂停。name 为系统上任意系统调用名字，在`/usr/include/asm/unistd.h`可以找到全部名称，number 为系统调用的 ID 号。group 其实是将系统调用进行分类，比如 netword，process 等。
7.  fork/vfork 对创建进程系统调用的调用
8.  load [regexp] 加载动态库，匹配正则表达式`[regexp]`。
9.  unload [regexp] 卸载动态库
10.  signal [signal...|'all'] 传递信号。

`tcatch`设置一个临时的捕捉点，在出现一次之后自动删除。

断点相关的其他命令：

```
clear   // 删除下一条指令上的任意断点，如果由于断点停止，那么此命令正好删除当前断点

clear location  删除在指定位置设置的任意断点
    clear function
    clear filename:function
    clear linenum
    clear filename:linenum

d [breakpoints] [list...]/delete [breakpoints] [list...]
        // 删除断点，如果不指定参数，则删除所有断点。

disable [breakpoints] [list...]/dis [breakpoints] [list...]

enable [breakpoints] [list...]
enable [breakpoints] once list..
enable [breakpoints] count n list...  // 使断点有效n次
enable [breakpoints] delete list...   // 让断点有效一次，然后删除


```

断点条件可以在设置断点时使用`break ... if expr`类进行设置，也可以在设置断点后使用`condition`命令针对断点 ID 进行设置。`watch`命令可以使用`if`关键字，而`catch`命令不识别`if`关键字，则只能使用`condition`设置条件。

```
condition bunm expression // 指定expression作为断点条件

condition bnum  // 从断点bnum上移除条件

ignore bnum count  // 设置忽略断点的次数，三种类型断点都可以使用


```

断点命令列表，即可以为任意一种断点设置一系列执行命令，当程序暂停时，该断点的这一系列命令就会执行。比如在一个断点上想要打印某个变量或开启另外一个断点等。

```
commands [list...]
...command-list...
end


```

上述命令为一个指定的断点设置一系列命令。如果要移除断点上的所有命令，只需`commands`命令后立即输入`end`。如果不指定断点编号，则命令指最后一个断点。可以在 command 列表起始加入`silent`命令用于禁止输出断点消息。

动态`printf`是一种断点式的信息打印，好像是往代码中加入了`printf`代码一样。

```
dprintf location,template,expression[,expression...] // 设置动态printf
    // 当代码执行到location位置时会按照printf形式打印后面数据

set dprintf-style style      // 动态printf的类型
    // style的值可取 gdb（由GDB printf命令打印），call（调用程序中的printf），agent（gdbserver处理数据）

set dprintf-function function // 设置dprintf使用的函数，比如printf


```

`save breakpoints [filename]`将断点保存到文件中，下次可以使用`source filename`来读取保存的断点。

最后，gdb 中的断点信息是可以保存在文件中的，`save breakpoints [filename]`将当前所有断点的定义以及他们的命令和忽略次数保存到文件`filename`中。在下一次要从文件中读取断点信息时，可以使用`source`命令重新加载断点信息。（其实保存的信息就是一系列重建断点的命令，可以在文本编辑器中编辑这个文件。）

**单步与继续执行**

在遇到断点或执行单步命令时，程序会停下来，这时就需要继续执行或继续单步执行。当继续或单步时，程序可能因为信号再次停下来，如果是因为信号暂停，则需要使用`handle`命令或`signal 0`来恢复执行。

```
continue [ignore-count]/c [ignore-count]/fg [ignore-count]
    // 继续执行，[ignore-count]参数表示要跳过当前的断点几次

step       // 源码单步，跳入函数调用
step count // 源码单步n次

next       // 源码单步，跳过函数调用
next count // 源码单步n次

set step-mode  on/off  // 在经过没有符号的函数时是暂停还是跳过，on为暂停。默认为off，
show step-mode         // 没有符号的函数直接跳过

stepi/si   // 指令单步，跳入函数调用
stepi arg  // arg是单步数，类似step，常常和`display /i $pc`配合使用调试汇编代码

nexti/ni   // 指令单步，跳过函数调用
nexti arg  // arg为单步数


```

在单步中 gdb 有一个命令可以跳过函数和文件，如下例子。如果在`foo`函数调用行上执行单步跳入，则会跳到`boring`函数，如果执行单步跳过，则会跳过整行代码，错过`foo`函数调用。

```
int func()
{
    foo(boring());
    bar(boring());
}


```

gdb 中有`skip`命令可以跳过单个函数，文件等，可以通过函数名，行号，正则表达式匹配函数名的方式来设置跳过对象。

```
skip [options] // 设置跳过某个对象
    // -file file/-fi file 在file中的函数都会被单步跳过
    // -gfile file-glob-pattern/-gfi file-glob-patern 满足正则式的文件都会被跳过
    // (gdb) skip -gfi utils/*.c
    // -function linespec / -fu linespec 函数名包含linespec
    // -rfunction regexp / -rfu regexp 跳过满足正则表达式的函数名

skip function [linespec]
    // linespec命名的函数或包含行名linespec的函数在但不执行时会被跳过
skip file [filename]
    // 在文件filename中包含的函数都会在单步时被跳过

info skip [range]
    // 显示指定的skip的信息，如果不指定参数 range，则显示所有跳过的函数和文件

skip delete [range]  // 删除指定范围的跳过

skip enable [range]  // 开启跳过
skip disable [range] // 关闭跳过


```

```
finish    // 继续运行，直到当前函数栈帧结束

until / u // 继续执行，直到源码行越过当前行，其实在循环中用于越过循环

until location / u location
    // 继续运行直到指定的位置或当前栈帧返回了，方便跳过递归调用
advance location  // 类似于until，但是它不会跳过递归函数


```

> 在 gdb 中有程序反向执行的概念，与之相关的的另一个话题是下程的执行以及重放。这其实就是在 gdb 中将执行过程记录，然后恢复到某个状态，读取记录的内容，重新走过记录的内容。

**信号**

信号是程序执行期间的异步事件，操作系统定义了所有种类的信号，每一种信号都有名字和编号。一些信号是应用程序正常功能的一部分，比如`SIGALARM`；另外一些则是异常信息了，比如`SIGSEGV`暗示发生了错误，这些信号会导致程序退出；还有一些，比如`SIGINT`，并不意味着错误，但是它也会导致程序退出。

通常情况下，类似`SIGALARM`的非错误信号会被设置为静默传递给程序，但是对于错误信号，则会暂停程序，使用如下的命令可以修改设置。

```
info signals
info handle       // 列表形式显示所有的信号，以及GDB处理每一个信号的方式

info signals sig  // 显示特定信号的信息

catch signal [signal... | 'all'] // 设置信号的捕捉点

handle sig [keywords] // 设置GDB处理信号sig方式，sig可以是信号名或信号编号
    // nostop  遇到sig信号时gdb不应该暂停程序，打印一条提醒消息
    // stop    遇到信号时暂停程序
    // print   信号发生时打印一条信息
    // noprint 信号发生时不打印信息
    // pass/noignore 信号发生时传递给程序
    // nopass/ignore 信号发生时不传递给程序


```

默认为非错误信息好比如`SIGALARM`，`SIGWINCH`，`SIGCHLD`等设置`nostop`，`noprint`，`pass`；为错误信号设置`stop`，`print`，`pass`。调试中可以使用`signal`命令来让程序接收到信号或接收不到信号，也可以给程序发送信号。为了不让程序接收到信号，可以使用`signal 0`来继续程序执行。

在一些调试目标上，GDB 可以查看接收到的信号信息，信号信息通过方便变量`$_siginfo`导出，这个变量中包含了内核传递给信号处理函数的信息。使用`ptype $_siginfo`命令查看变量类型，如下例子：

```
(gdb) continue
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400766 in main ()
69 *(int *)p = 0;
(gdb) ptype $_siginfo
type = struct {
    int si_signo;
    int si_errno;
    int si_code;
    union {
        int _pad[28];
        struct {...} _kill;
        struct {...} _timer;
        struct {...} _rt;
        struct {...} _sigchld;
        struct {...} _sigfault;
        struct {...} _sigpoll;
    } _sifields;
}
(gdb) ptype $_siginfo._sifields._sigfault
type = struct {
    void *si_addr;
}
(gdb) p $_siginfo._sifields._sigfault.si_addr
$1 = (void *) 0x7ffff7ff7000


```

**逆向执行与下程执行的记录与重放**

逆向执行是程序反向执行代码，这个需要程序执行记录的功能。而下程执行的记录与重放对于调试一些不易复现问题比较有帮助，这里不详细总结，有需要可以参考 gdb 的文档。

**查看栈**

当程序暂停执行时，首先要关注的事情就是程序停在了那里以及它如何执行到现在的位置。这时就需要查看调用栈，`frame`命令可以查看当前栈帧的信息，`backtrace`命令可以回溯整个栈帧。

```
backtrace / bt  // 打印整个栈，每个栈帧一行。

backtrace n
bt n            // 类似bt，但是只打印最内层的n帧

backtrace -n
bt -n           // 类似bt，但是只打印最外层的n帧

backtrace full
bt full
bt full n
bt full -n      // full参数表示显示完整栈帧，包括局部变量值

backtrace no-filters
bt no-filters
bt no-filters n
bt no-filters full n // 在回溯栈时不要执行Python栈帧过滤

where / info stack   // 其实是backtrace 的别名


```

命令`bt`默认值打印当前线程的栈，`thread apply thread-id bt`打印指定线程的栈回溯信息。`thread apply all backtrace`打印当前进程中所有线程的栈回溯信息。

在栈回溯中也有一些设置选项：

```
set print address off/on   // on表示打印栈帧时将参数地址显示出来，off表示不显示
show print address         // 默认值为on

set print frame-arguments  // 设置栈回溯中栈帧参数的显示
show print frame-arguments

set backtrace post-main on/off // 设置栈回溯是否越过main函数，默认为off
show backtrace post-main

set backtrace past-entry on/off // 栈回溯越过应用程序内部入口点
show backtrace past-entry

set backtrace limit 0/n/unlimited // 限制栈回溯的深度，0和unlimited表示不限制
show backtrace limit   // 默认不限制上限

set filename-display relative/basename/absolute // 栈回溯中文件名显示形式
show filename-display


```

在调试中会需要查看深层栈帧中的某些局部变量，可以使用栈帧选择命令：

```
(gdb) frame // 显示当前栈帧的简单信息
#0  main (argc=argc@entry=1, argv=argv@entry=0x7fffffffdd78) at src/ls.c:1249
1249    in src/ls.c

(gdb) info frame // 显示当前栈帧的详细信息
Stack level 0, frame at 0x7fffffffdca0:
 rip = 0x402a00 in main (src/ls.c:1249); saved rip = 0x7ffff780b830
 called by frame at 0x7fffffffdd60
 source language c.
 Arglist at 0x7fffffffdc90, args: argc=argc@entry=1, argv=argv@entry=0x7fffffffdd78
 Locals at 0x7fffffffdc90, Previous frame's sp is 0x7fffffffdca0
 Saved registers:
  rip at 0x7fffffffdc98

info frame addr
info f addr      // 在不选择栈帧前提下，查看addr所在栈帧的详细信息

info args        // 显示选择栈帧的参数，每个参数一行
info locals      // 显示选择栈帧的局部变量


```

`frame`命令还可以用于选择栈帧，如下。

```
frame n
f n      // 将当前栈帧切换为编号为n的栈帧

frame stack-addr [pc-addr]
f stack-addr [pc-addr] // 选择地址stack-addr出的栈帧
    // 在栈帧链被破坏时，这个命令比较有用

up n    // 将当前栈帧向上调n层，默认为1
down n  // 将当前栈向下调n层，如果为正数则是向内层栈帧调整，如果为负数则是往外层栈帧调整


```

有几个用于命令脚本的栈帧选择命令：

```
select-frame   // 类似 frame n命令，但它不输出选择的栈帧信息

up-silently n
down-silently n // 静默上下设置栈帧，不输出信息


```

栈帧过滤器是基于 Python 的工具，用于管理和修饰栈帧输出，这块内容不常用，用到时可以参考 gdb 文档。

```
info frame-filter    // 显示当前gdb中设置的所有栈帧过滤器


```

**源文件**

在程序中或者独立文件中的调试信息告诉了 gdb 构建程序所使用的源码，所以在调试时如果有源码文件，gdb 就可以输出当前调试源码内容。

```
list
l         // 打印当前位置后的10行源码

list linenum  // 打印行号linenum周围的源码内容

list function // 打印函数function开始的源码

list -        // 打印上次输出最后一行代码前面的代码（默认10行）

list location // 打印location附近的源码

list first,last // 显示first行到last行的源码
list ,last      // 打印源码，到last行结束
list first,     // 显示源码从first到文件结束

list +          // 显示上一次打印源码结束行之后代码
list -          // 显示上一次打印源码结束行之前代码


```

```
set listsize count/unlimited // 设置一次打印代码行数，默认为10
show listsize


```

gdb 是源码调试器，如果当前调试当前系统中编译出来的程序或模块，则不需指定源码路径。而如果调试其他机器上编译的程序，则需要设置源码路径，gdb 才能找到对应源码。

```
directory dirname
dir dirname    // 将目录dirname添加到源码路径前面。

directory      // 不带参数，将源码路径设置为默认值

setdirectories path-list  // 设置源码路径为 path-list，如果没有参数则设置为`$cdir:$cwd`

show directories // 打印当前的源码路径

set substitute-path from to // 设置源码子路径替代，即搜索源码时使用路径进行替代
unset substitute-path [path] // 取消路径path的子路径替代
show substitute-path


```

命令`info line location`可以显示`location`位置代码行对应的汇编代码。

在 gdb 中还可以对源码文件进行编辑，如下命令。要对源码编辑，单纯 gdb 是不行的，它需要借助外部的编辑器，比如`vim`等，编辑器可以通过命令进行设置。

```
edit location     // 编辑指定位置 location处源码
    edit number
    edit function


```

**GDB 命令中的 location 参数**

一些 GDB 命令接受程序代码位置的参数，在 GDB 中位置参数有三种不同格式：指定行位置，详细的位置或地址位置。

特定行位置是冒号分隔的源码位置列表，可以使用文件名，函数名，行号等。

```
linenum    // 指定当前源码中的行号 linenum

-offset
+offset    // 指定为相对于当前行的偏移。当前行是最后输出的行。

filename:linenum // 指定源码文件中的行号

filename:function // 指定源码中的函数

label      // 函数中的标签 label


```

详细的位置指定可以使用参数，使用如下的多个参数指定详细位置。

```
-source filename   // 指定源码文件名字，如果会出现歧义，请指定尽可能详细目录

-function function // 指定一个函数名字

-label label       // 指定标签名 label

-line number       // 指定行号


```

比如`break -s main.c -li 3`例子，使用参数指定源码文件名以及要设置断点位置的行号。

地址位置表示一个特定的程序地址，有通用的形式`*address`。

对于面向行的命令，比如`list`和`edit`，这会指定包含地址的源码行作为参数。对于可以使用地址的命令，比如`break`，则可以在没有调试信息的地址上设置断点。

这里的地址`address`其实可以是任何指定了代码地址的有效表达式。

```
expresion  当前GDB调试程序所用语言中的有效表达式

funcaddr   函数或过程的地址，比如C语言中函数名就代表此函数地址

`filename`:funcaddr  // 类似funcaddr，但是可以显示指定源码文件


```

**查看变量**

查看程序数据通常使用`print/p`命令，或者它的同义词`inspect`。

```
print expr
print /f expr  // expr是源码中的表达式，可以指定/f来为输出值设置格式

print
print /f  // 如果不指定参数，则再次输出上一次输出的值


```

`print`命令后面的`/f`表示要按照什么格式打印数据，可选类型如下：

```
x   将打印值当作数字，输出数字十六进制形式
d   有符号十进制
u   无符号十进制
o   八进制打印数据
t   二进制形式打印数据，t=two
a   打印地址值，即将参数处按照地址值打印
    // (gdb) p/a 0x54320
    // $3 = 0x54320 <_initialize_vx+396>
c   当作整数，打印它的字符常量
f   将打印值做为浮点数
s   当作字符串打印，这个格式是单字节字符串数据，null结尾
z   类似x，但是对于不满足长度的会用0在前面补全
r   raw格式，默认gdb使用基于Python的完美打印方式


```

`print`命令打印表达式的值，如果对类型，结构体组成以及类组成感兴趣，使用`ptype exp`命令，显示类型信息。

`explore`命令可以进入一个子命令模式，用于探索一个结构体或类的各个成员的值或类型。它还有两个子命令，如下。两个命令要求它们的参数在当前的调试环境下是有效的。

```
explore value expr // 浏览表达式expr的值，

explore type arg   // 浏览arg的类型，


```

在 print 和其他的命令中接受表达式作为参数，并且计算它的值。表达式可以包括编程语言中的常量，变量或操作符等。这些形成表达式包括条件表达式，函数调用，类型转换和字符串常量。

表达式中常用的运算符如下：

```
@  二进制操作符，将一部分内存作为数组

:: 允许指定按照文件或函数指定的变量

{type} addr  将内存地址addr处的对象当作类型type。addr参数可以是表达式


```

表达式在一些语言中，比如`C++`，`Ada`，`Object-C++`，会出现二义性，gdb 通常可以处理这种情况，默认情况下将所有情况列举出。

```
set multiple-symbols mode // 设置具有多个相同符号时的处理方式
    // mode的默认取值为 all，即列举出所有满足条件符号，或设置所有满足条件的点
    // mode=ask 调试器使用菜单让你选择
    // mode=cancel 调试器会报告错误，出现了二义性，然后退出
show multiple-symbols     // 显示多符号的处理方式


```

最常用的表达式就是程序中的变量名字，它们必须要满足两个条件，变量或者是全局的变量，所有范围均可见，或者是当前栈帧可见的变量才可以作为命令的表达式。一个例外情况是文件或函数中的静态变量，可以使用如下的方式进行引用。还有一种使用到符号`::`的地方是如果同一变量名出现在嵌套作用域，内层变量会覆盖外层同名变量。

```
'file'::variable      // 文件名容易出现.c等形式，可以使用引号引起来
function::variable


```

如果要将地址值打印为数组，可以使用如下形式：

```
// int *array = (int *) malloc (len * sizeof (int));
(gdb) print *array@len    // 就可以将数组内容全部显示

(gdb) p/x (short[2])0x12345678    // 设置地址的数据类型，将地址处内容按照数组打印
$1 = {0x1234, 0x5678}

// 对于数组结构体，可以循环打印内容
(gdb) set $i = 0        // 设置gdb变量，
(gdb) p dtab[$i++]->fv
(gdb) RET               // 重复命令，i自增


```

栈帧中的变量有时打印出来是错误值，这和栈帧的建立与撤销有关，建立栈帧不是一条指令，如果刚进入函数，输出变量内容可能就是错误值；此外，对于程序代码的优化也会导致这个问题。

自动显示：

如果想要经常打印表达式，查看表达式的值如何变化，那么使用自动显示命令会比较方便。

```
display expr   // 将表达式expr加入到自动显示列表，每次程序暂停会自动打印值

display /fmt expr // fmt设置显示格式
display /fmt addr // 同上


```

比如常用的自动显示命令`display /i $pc`，汇编调试中单步时会自动显示下一条要执行汇编指令。

```
undisplay dnums
delete display dnums  // 删除自动显示列表中的值

disable display dnums // 关闭自动显示中的第dnums条
enable display dnums  // 开启自动显示中的第dnums条

display  // 显示自动列表中所有表达式的值

info display  // 打印设置的自动显示表达式的列表


```

对于局部变量，一旦代码执行超出了变量的作用域，那么自动显示将被自动删除。

GDB 提供了设置打印格式等 print 命令的设置命令，如下：

```
set print address on/off  // on表示在显示栈回溯，结构体变量等时显示地址值。
    (gdb) f
    #0 set_quotes (lq=0x34c78 "<<", rq=0x34c88 ">>")
    at input.c:530
    530     if (lquote != def_lquote)

show print address       // 显示设置值


set print symbol-filename on/off  // 显示符号和文件名，默认为off
show print symbol-filename

set print max-symbolic-offset max-offset // 符号和地址值的偏移小于max-offset才显示符号
show print max-symbolic-offset

set print symbol on/off  // on表示如果对应地址有符号，则打印符号信息
show print symbol

set print array on/off   // 打印整齐格式的数组，默认值为off
show print array

set print array-indexes on/off // on表示打印数组的索引值
show print array-indexes

set print elements number-of-elements/unlimited // 打印数组元素数的最大限制
show print elements

set print frame-arguments value  // 显示栈帧参数的输出设置
    // all 显示所有参数值
    // scalars 仅显示数量形式的参数，默认值
    // none  不打印栈帧中的参数
show print frame-arguments

set print raw frame-arguments on/off  // 显示栈帧参数原始形式，而非整理过的可读性是
show print raw frame-arguments

set print pretty on/off  // on表示以易于阅读形式打印
show print pretty

set print union on/off   // on表示打印包含在结构体或其他枚举类型中的共合体
show print union

set print demangle on/off // on表示以源码形式打印C++中的名字，而非改名的
show print demangle

set demangle-style style  // 设置C++改名模式
    // auto 自动选择
    // gnu 依据GNU C++编译器形式解析
    // hp 一句HP ANSI C++编码形式
    // lucid 一句Lucid C++编译器
    // arm
show demangle-style

set print object on/off  // 显示执行对象指针时，标识出对象的实际类型而不是声明类型
show print object

set print static-members on/off  // on表示显示C++对象时，打印静态成员
show print static-members

set print vtbl on/off    // on表示以可阅读形式打印C++的虚函数表
show print vtbl


```

**查看内存**

查看数据更加底层的方式是使用`x`命令，检查内存中指定地址的数据，按照特定格式打印它们。使用命令`x`（`examine`）来查看内存，可以定义显示数据的格式。如下为使用 x 命令的形式：

```
x /nfu addr
x addr
x


```

打印`addr`处的内存内容，n 表示重复次数，f 表示显示格式，u 表示打印内存单元的尺寸。

`f`的默认值为`x`，其他取值类型有如下几种：

*   x 十六进制形式显示
*   d 十进制有符号形式显示
*   u 无符号十进制形式
*   o 八进制形式
*   t 二进制形式
*   a 地址形式
*   c 字符形式
*   f 浮点形式
*   s 单字节字符串
*   i 二进制指令形式

`u`的默认值为`w`，其他的几类取值如下：

*   b (Bytes) 字节
*   h (Halfwords) 半字，即两个字节
*   w （Words） 字，四个字节
*   g （Giant） 大字，8 个字节

例如如下的显示内存例子：

```
(gdb) x/3uh 0x54320

(gdb) x/4xw $sp

(gdb) x/-3uh 0x54320  // 使用负数，打印反向内容

(gdb) x/5i $pc-6      // 打印当前指令地址前的6字节数据


```

对于打印格式`s`和`i`两种情况，内存单元大小`u`被省略了，`n`依然可用，表示打印几条指令等。`$_`方便变量中保存了 x 执行后的地址值。

内存区块属性：

GDB 使用内存属性确定某种类型内存访问是否允许。

```
mem lower upper attribuites // 以lower/upper为参数，attributes为属性定义内存块

mem auto   // 丢弃用户修改的内存区块，使用目标支持区块

delete mem nums  // 从GDB监控的区块列表中删除内存区块 nums
disable mem nums //

enable mem nums  //

info mem    // 打印所有定义内存区块的列表


```

更多信息可以参考 gdb 的说明文档。

内存搜索：

可以使用 find 命令搜索内存中特定序列的字节。

```
find [/sn] start_addr, +len, val1[, val2...]
find [/sn] start_addr, end_addr, val1[, val2...]
    // 搜索内存中由val1，val2...指定的值，搜索开始于start_addr
    // s 表示搜索的大小，可取值为b（Byte），h（halfwords），w（word），g（giant words）
    // n 打印满足条件的最大数量，默认打印所有匹配项


```

例如如下搜索例子，代码和 gdb 调试时的搜索方法：

```
void
hello ()
{
    static char hello[] = "hello-hello";
    static struct { char c; short s; int i; }
    __attribute__ ((packed)) mixed = { ’c’, 0x1234, 0x87654321 };
    printf ("%s\n", hello);
}


```

```
(gdb) find &hello[0], +sizeof(hello), "hello"
0x804956d <hello.1620+6>
1 pattern found
(gdb) find &hello[0], +sizeof(hello), ’h’, ’e’, ’l’, ’l’, ’o’
0x8049567 <hello.1620>
0x804956d <hello.1620+6>
2 patterns found
(gdb) find /b1 &hello[0], +sizeof(hello), ’h’, 0x65, ’l’
0x8049567 <hello.1620>
1 pattern found
(gdb) find &mixed, +sizeof(mixed), (char) ’c’, (short) 0x1234, (int) 0x87654321
0x8049560 <mixed.1625>
1 pattern found
(gdb) print $numfound
$1 = 1
(gdb) print $_
$2 = (void *) 0x8049560


```

**方便变量和函数**

在 GDB 中提供了方便变量来保存值，在之后可以访问这个值。方便变量完全是 gdb 内部的变量，不会影响到程序后续的执行。方便变量都是以前缀`$`开始，`$n`用于表示 gdb 中的值历史，即打印变量值时会看到。

```
show convenience  // 打印当前使用的方便变量的列表
show conv

init-if-undefined $variable=expression // 如果没有定义方便变量，则定义它


```

如下为一些有用的方便变量，它们是 gdb 自动创建的：

```
$_   // 由x命令自动设置最后检查的地址值，info line和info breakpoint也会设置这个值

$__  // x命令检查的最后一个内存地址中值设置给该方便变量

$_exitcode  // 如果程序正常退出，GDB自动设置退出代码到方便变量，并且重置$_exitsignal

$_exitsignal // 保存导致程序非正常退出的未捕捉信号

$_exception  // 设置为异常相关捕捉点上抛出的异常对象

$_sdata      // 包含了额外收集的静态追踪点数据。

$_siginfo    // 信号额外信息，如果程序没有接收过信号，这个变量可能是空

$_tlb        // Windows上调试时包含 TIB地址

$_inferior   // 当前的下程的编号

$_thread     // 当前线程的编号

$_gthread    // 当前线程的全局编号


```

除了方便变量外，还有方便函数，即使没有配置`Python`支持，这些函数也可用。

```
$_isvoid(expr)   // 判断表达式expr是否是void类型，如果是返回 1

$_memeq(buf1, buf2, lenght) // buf1和buf2处length长的内存是否相等，相等返回1，否则返回0

$_regex(str, regex) // 字符串str是否满足正则表达式 regex

$_streq(str1, str2) // 字符串 str1 和字符串str2是否相等，相等返回 1

$_strlen(str)       // 返回字符串 str 的长度

$_caller_is(name[, number_of_frames]) // 调用函数名字是否等于name

$_caller_matches(regexp[,number_of_frames]) //

$_any_caller_is(name[,number_of_frames])  // 调用栈深度中是否有调用者名字为 name

$_any_caller_matches(regexp[,number_of_frames]) // 

$_as_string(value)  // 返回值value的字符串表达


```

**显示寄存器**

要访问机器寄存器内容，可以类似方便变量的形式，以`$`开始。

```
info registers    // 显示所有寄存器的名字和值

info all-registers // 显示所有寄存器

info registers regname // 显示寄存器 regname的内容


```

在 GDB 中有四个标准寄存器名字可用：

```
$pc    // 程序计数寄存器  p/x $pc  或 x/i $pc
$sp    // 程序栈寄存器    set $sp += 4
$fp    // 栈帧寄存器
$ps    // 处理器状态寄存器 X86上它是 EFLAGS寄存器


```

其他寄存器：

```
info float   // 显示依赖于硬件的浮点指针单元信息

info vector  // 显示向量单元的状态


```

**操作系统辅助信息**

在 GDB 中提供了非常有用的 OS 辅助信息，这些信息可以辅助调试程序。

```
info auxv    // 显示下程的辅助向量，可以是活进程或core文件


```

在一些调试目标中，GDB 可以访问操作系统信息，并且显示出来。不同系统可显示的信息也不同。

```
info os infotype   // 显示请求类型的操作的信息，在Linux上有如下的类型：
    // cpus  显示CPU或核心的列表
    // files 显示目标中打开的文件描述符列表
    // modules 目标上内核加载的内核模块的列表
    // msg  SystemV消息队列列表
    // processes  目标上进程列表
    // procgroups 目标上进程组的列表
    // semaphores 显示SystemV信号量集
    // shm  显示共享内存区域的列表
    // sockets 目标机器上sockets列表
    // threas 在目标机器上执行线程列表

info os   // 不设置参数，则显示所有可用参数。


```

**创建核心转储文件**

```
dump [format] memory filename start_addr end_addr
dump [format] value filename expr //将内存start_addr到end_addr转储到文件中
                                  // 将表达式expr的值转储到文件中
    // format值
    // binary  原始二进制
    // ihex    Intel十六进制格式
    // srec    Motorola S记录格式
    // tekhex  Tektronix 十六进制形式
    // verilog Verilog十六进制形式

append [binary] memory filename start_addr end_addr
append [binary] value filename expr // 函数意思dump，只是它是追加内容

restore filename [binary] bias start end // 恢复文件filename中内容到内存中


```

核心文件或核心转储记录了执行进程的内存映像和进程状态，主要用于事后调试。

```
generate-core-file [file]
gcore [file]  // 生成下程进程的一个核心转储，默认名字为 core.pid

set use-coredump-filter on/off // 生成dump时开启或关闭/proc/pid/coredump_filter的使用
show use-coredump-filter


```

**优化程序调试**

内联函数，通过优化的内联函数会被替换到函数调用出，gdb 中可以对其进行调试，前提是使用调试符号。

尾调用优化，对于一部分函数调用在调用者的`return`指令之前的被优化为直接`jmp`到这些函数，而不是执行`call`指令。这会导致栈帧中看不到调用者。GCC 编译的`DWARF 2.0`以后的调试信息版本文件可以处理这种，并在栈帧信息中显示类似`tail call frame, caller of frame at 0x7fffffffda30`的信息。

**调试 C/C++ 宏定义**

在`C/C++`语言中提供了一种定义和调用预处理宏的方式，GDB 可以计算包含宏的表达式，显示宏表达式的结果。要调试宏，在编译代码时需要使用`-g3`编译选项。

```
macro expand expression
macro exp expression  // 显示expression中扩展所有预处理宏调用后的结果

macro expand-once expression // 只扩展一层宏定义
macro exp1 expression

info macro [-a | -all] [--] macro
    // 显示名字macro宏的当前定义或所有定义，双横线是参数结束，
info macros location  // 在位置location处的所有宏定义

macro define macroname replacement-list // 定义一个宏macroname
macro define macroname(arglist) replacement-list // 定义一个宏macroname

macro undef macroname  // 删除用户提供的宏定义macroname
macro list             // 显示所有macro define命令定义宏


```

**追踪点（TracePoints）**

追踪点主要是用于不适合调试器长时间中断程序执行的情况，这时它就比较适合于用追踪点来调试程序。使用 GDB 的`trace`和`collect`命令，可以指定程序中的位置，即追踪点，当到达追踪点时计算表达式值，显示变量值等。

追踪点功能目前只对远程调试支持，远程目标还必须知道如何收集追踪数据。这个功能是在远程的 stub 中实现的。

这个功能较复杂，目前使用不上，后面有机会才详细学习。

**调试符号**

在调试信息中描述了变量名，函数名，类型信息以及源码行信息等，这些信息或者内置到可执行程序文件中，或者单独剥离为符号文件。GDB 在加载程序时会自动从特定的文件或目录查找符号信息，在使用 GDB 的打印命令查看变量值时也需要搜索符号。

```
set case-sensitive on/off/auto  // 匹配符号时是否大小写
show case-sensitive

set print type methods on/off   // 打印一个类时，是否打印方法
show print type methods

set print type typedefs on/off  // 是否打印类型定义
show print type typedefs

info address symbol             // 显示符号symbol存储的地址

    (gdb) info address main
    Symbol "main" is a function at address 0x402a00.

info symbol addr                // 打印地址addr处的符号名字，如果没有符号，则显示周围最近符号

    (gdb) info symbol 0x402a00
    main in section .text of /bin/ls

demangle [-l language] [--] name // 符号重组

whatis [/flags] [arg]           // 打印arg的数据类型，如果没有arg参数则显示最近的一条数据

    (gdb) whatis main
    type = int (int, char **)

ptype [/flags] [arg]  // 同 whatis 命令

info types regexp   // 打印一个简单所有名字符合正则表达式的符号的描述
info types          // 打印所有符号信息

info scope location  // 列举出局部于特定范围中的所有变量

info source   // 显示当前源码文件的信息
info sources  // 显示程序的所有源码文件名字

info functions     // 打印所有定义的函数的名字和数据类型
info functions regexp  // 打印满足特定正则表达式的函数名字和数据类型

    (gdb) info functions main
    All functions matching regular expression "main":

    File ../csu/libc-start.c:
    int __libc_start_main(int (*)(int, char **, char **), int, char **, int (*)(int, 
        char **, char **), void (*)(void), void (*)(void), void *);

    File src/ls.c:
    int main(int, char **);
    ......

info variables
info variables regexp  // 打印所有满足正则表达式的，函数外的变量名字和数据类型

info classes
info classes regexp    // 显示所有满足正则表达式的类类型


set print symbol-loading full/brief/off
    // 打印符号加载信息 full 显示完整信息，brief显示简要信息，off关闭符号信息显示
show print symbol-loading


```

**修改程序执行**

**TUI**

TUI 的全称为`Text User Interface`，它是 gdb 使用`curses`库在不同的窗口显示源码，汇编，寄存器和 gdb 命令的方式。

`gdb -tui`在启动 gdb 时可以指定使用 TUI，gdb 启动后即开启 TUI。

```
tui enable       // 激活TUI模式
tui disable      // 关闭TUI模式，返回到控制台命令行

info win         // 列举显示窗口的尺寸
layout name      // 改变显示的TUI窗口
    // name可取值：
    // next 显示下一个布局
    // prev 显示上一个布局
    // src 显示源码和命令行窗口
    // asm 显示汇编和命令行窗口
    // split 显示源码，汇编和命令行窗口
    // regs 如果在src布局，则显示寄存器，源码和命令行；
    //      如果在汇编或split布局，显示寄存器，汇编和命令行

focus name / fs name  // 切换焦点到指定的窗口
    // name取值：
    // next 下一个活动窗口可以滚动
    // prev 上一个活动窗口可以滚动
    // src 源码窗口变为活动窗口并且可滚动
    // asm 源码窗口变为活动窗口并且可滚动
    // regs 源码窗口变为活动窗口并且可滚动
    // cmd 源码窗口变为活动窗口并且可滚动

tui reg group  // 修改在寄存器窗口显示的寄存器组，如果寄存器窗口不显示，则会显示该窗口
    // group取值如下:
    // next 循环已经选择的组，找下一个选择的组
    // prev 循环已经选择组，找上一个
    // general  通用寄存器
    // float 浮点寄存器
    // system 系统寄存器
    // vector 向量寄存器
    // all 显示所有的寄存器

update      // 更新源码窗口和当前的执行位置 PC

refresh     // 刷新窗口

winheight name +count / wh name +count
winheight name -count / wh name -count
    // 修改指定窗口的高度，以行为单位
    // src / cmd / asm / regs

tabset nchars     // 设置tab字符的宽度，影响源码和汇编窗口


```

关于 TUI 有如下的几个变量可以设置：

```
set tui border-kind kind   // 设置TUI窗口边界显示种类
    // kind取值：
    // space  使用空格画边界
    // ascii  使用ascii码画边界，+ - | 等符号
    // acs    使用可选字符集画边界
show tui border-kind

set tui border-mode mode
set tui active-border-mode mode  // 为活动窗口选择显示属性
    // mode取值如下：
    // normal  使用正常的属性显示边界
    // standout 使用标准模式
    // reverse 是哦那个逆向视频模式
    // half 使用半高亮模式
    // half-standout 使用半高亮和标准输出模式
    // bold 使用额外粗体模式
    // bold-stadout 使用高亮或粗体的标准输出模式
show tui border-mode
show tui active-border-mode


```

> 在源码调试时，有时窗口容易出现混乱，可以通过鼠标滚轮上下滚动源码使得它整齐。

**调试不同语言**

GDB 可以调试不同的语言，不同的语言尽管有很多相同之处，还是有一些不同的，比如 C 语言的指针引用和`Modula-2`就不同。GDB 已经将部分语言的特定的信息构建进自身之中了。

要切换源码语言有两种方式，一种是 GDB 自动检测；另外一种方式是使用`set language`命令。

```
(gdb) set language // 不设置参数，显示所有可用的设置值
Requires an argument. Valid arguments are auto, local, unknown, ada, c, c++, asm, minimal, d, fortran, objective-c, go, java, modula-2, opencl, pascal.

    // 设置语言为 local 或auto，意味着让GDB推测源码语言

(gdb) show language // 显示当前设置的语言
The current source language is "auto; currently c".

(gdb) info language       // 显示当前设置语言

(gdb) info frame          // 调试中，显示当前的栈帧信息，其中会列举栈帧出源码语言
Stack level 0, frame at 0x7fffffffdca0:
 rip = 0x402a00 in main (src/ls.c:1249); saved rip = 0x7ffff780b830
 source language c.       // 源码语言
 Arglist at 0x7fffffffdc90, args: argc=1, argv=0x7fffffffdd78
 Locals at 0x7fffffffdc90, Previous frame's sp is 0x7fffffffdca0
 Saved registers:
  rip at 0x7fffffffdc98

(gdb) info source        // 显示源码信息，
Current source file is src/ls.c
Compilation directory is /build/coreutils-sUxpXE/coreutils-8.25
Source language is c.    // 源码语言
Producer is GNU C11 5.4.0 20160609 -mtune=generic -march=x86-64 -g -O2 -fstack-protector-strong -fstack-protector-strong.
Compiled with DWARF 2 debugging format.
Does not include preprocessor macro info.


```

对于 GDB 支持的每一种语言有一些特殊的设置，比如打印数据等。具体的可以参考 GDB 的文档参考对应语言信息。

**修改程序执行**

一旦发现了程序中的错误，可能想要修改程序中内容以验证结果是否正确。

修改程序中的变量可以使用`set`命令：

```
set x=4         // 设置程序中变量 x为4
set ariable x=4
set var x=4     // 有时变量名会和set的子命令同名，可以添加var表明是修改程序变量

    (gdb) set {int}0x83040 = 4 // 使用{}标明类型


```

gdb 提供了修改程序执行位置的命令：

```
jump location   // 跳转到目标 location继续执行
j location

set $pc = 0x485 // 一些平台上可以通过修改 $pc 寄存器的方式来达到相同目的


```

其实这种直接跳转应用并不多，无法确保两个位置所需的变量以及寄存器能够满足要求，所以用的比较多的地方是向已经执行过代码的某个位置跳转，用于反复调试一段代码的执行。

```
signal signal    // 给被调试程序传递信号 signal，可以是信号编号，或信号名字
signal 0         // 继续执行程序，不传递任何信号给被调试程序

queue-signal signal // 为被调试程序排队一个信号signal
queue-signal        // 删除所有已经排队的信号


```

注意这里两个命令的区别，以及他们与`kill`程序的区别，`signal`直接将信号发送给被调试程序，而`queue-signal`命令和`kill`程序所发送的信号首先要达到 gdb，如果 gdb 设置了该信号的`handler`为`nopass`，被调试程序则不会接收到该信号。

`return`是另外一个改变程序执行的命令，它将当前函数栈帧弹出，回到上一栈帧。

```
return
return expression      // 设置返回值


```

这个命令是将当前栈帧后续代码略过不再执行，请注意它与`finish`命令的区别。

gdb 中可以直接调用程序的函数，比如前面说过的`dprnitf`中调用过`printf`函数：

```
print expr
call expr    // 计算表达式 expr，不显示void返回值

set unwindonsignal on/off  // 如果调用函数时出现信号，如何展开栈
show unwindonsignal

set unwind-on-terminating-exception on/off // 执行函数期间发生终止异常，如何进行展开
show unwind-on-terminating-exception // on表示展开，将gdb调用的函数栈清除，返回正常调用栈
                                     // off表示分发默认C++异常，并终止下程


```

在 GDB 中改变程序执行的最后一种是进行代码 Patch。

```
set write on/off    // 开启或关闭调试程序和core转储的写属性
show write


```

还可以进行代码编译和注入，直接在 GDB 命令行编译源码语句或源码文件，并且执行。这块内容很少使用，请参考 gdb 文档中关于它们的介绍。

**GDB 使用文件**

为了调试程序和读取程序的符号，需要指定要调试程序文件，可以使用`file*`命令来指定文件：

```
file filename    // 指定 filename为要调试文件
file             // 不带参数则表示删除已经设置的调试文件

exec-file [ filename ]   // 指定调试中要执行的程序名字 filename
symbol-file [ filename ] // 指定符号文件


symbol-file [ -readnow ] filename  // -readnow参数表示要立即加载符号
file [ -readnow ] filename

core-file [filename]     // 指定要调试的核心转储文件

add-symbol-file filename address     // 从内存中加载符号文件
add-symbol-file filename address [ -readnow ]
add-symbol-file filename address -s section address ...

remove-symbol-file filename // 删除符号文件
remove-symbol-file -a address

info files
info target         // 显示当前的调试目标

maint info sections // 显示当前调试目标在内存中的各个区块

info share regex          // 查看当前已经加载的共享库
info sharedlibrary regex
info dll regex

sharedlibrary regex  // 加载符合正则表达式的动态库的符号
share regex

nosharedlibrary      // 卸载所有动态库的符号

set stop-on-solib-events // 加载动态库时暂停，已经过时，不再使用
show stop-on-solib-events

set solib-search-path path // 设置so库的搜索路径 path
show solib-search-path

set debug-file-directory directories // 设置独立调试符号文件路径为 directories
show debug-file-directory


```

在这一节中，gdb 对于独立的调试符号文件进行了详细论述，如何生成独立文件的调试符号，调试器如何匹配独立调试符号和程序等概念，如果需要详细了解，可以参考 gdb 文档。

对于调试符号很多的应用程序，加载和搜索调试符号都是非常费时的，可以为调试符号建立索引文件，以加快调试。详细内容参考 gdb 文档的`gdb files`一章。

**指定调试目标**

调试目标是程序所处的执行环境，通常在同一个机器上调试程序，作为`file`或`core`命令的副产物已经制定了调试目标环境。但是当 GDB 运行在独立的主机上，则需要使用`target`命令指定调试的程序的目标环境类型。

```
set architecture arch  // 将当前调试目标架构设置为arch，默认值为auto

show architecture      // 显示当前的目标架构

set processor          // set architecture arch的别名命令
processor              // show architecture的别名命令


```

管理目标可以使用`target`命令：

```
target type parameters   // 链接GDB到目标机器或进程

info target/info files   // 显示当前选择的目标名称

help target              // 显示所有可用目标环境的名字列表
help target name         // 描述特定目标，包括任何必要的参数


target exec program      // 指定执行文件，同exec-file program
target core filename     // 同core-file filename，指定核心转储文件

target remote medium     // 指定连接远程调试目标的媒介

target native            // 指定本地进程调试，


```

对于远程调试有如下几个设置可以帮助调试：

```
set hash      // 当下载文件到远程监控器上 时是否显示哈希标识`#`
show hash

set debug monitor  // 开启或关闭GDB和远程监控器上的通信信息
show debug monitor


```

选择调试目标上的字节序：

```
set endian big/little/auto     // 假设调试目标为大字节序
show endian


```

**远程调试**

远程调试常用于操作系统内核调试或者无法支持全功能调试器的小型系统。但是远程调试需要编写远程的`stubs`，它用于执行在远程系统并且与 GDB 进行通信。

远程连接有两种方式，一种是`target remote`，另外一种是`target extended-remote`。区别在于当调试的程序退出时，`gdbserver`是否退出，以及和 GDB 的连接是否断开。许多远程目标只支持`target remote`。

可以使用如下命令连接远程调试目标：

```
target remote serial-device      // 使用串口设备serial-device连接调试目标
    (gdb) arget remote /dev/ttyb --baud xxx
    // 也可以通过 set serial baud 命令设置波特率

target remote host:port
target remote tcp:host:port      // 通过TCP连接到调试目标
    (gdb) target remote manyfarms:2828

    (gdb) target remote :1234
    (gdb) target remote localhost:1234  // 连接到本地

target remote udp:host:port      // 通过UDP连接调试目标


```

有一些远程目标支持文件传输：

```
remote put hostfile targetfile // 将本地的文件hostfile传递到远程目标上的targetfile

remote get targetfile hostfile // 将远程目标的文件targetfile拷贝到本地hostfile

remote delete targetfile       // 删除远程目标系统中的文件 targetfile


```

远程目标上启动`gdbserver`用于 GDB 连接：

```
sh> gdbserver comm program [ args ... ] // comm为通信方式，其后为调试程序以及其参数

    sh> gdbserver /dev/com1 emacs foo.txt
    sh> gdbserver host:2345 emacs foo.txt

sh> gdbserver --attach comm pid


```

关于 GDB 远程调试的`stubs`还有很多内容，比如设置远程目标中的`gdbserver`，远程调试中`Tracepoint`的支持，`gdbserver`的监控命令，编写`stubs`等；以后用到了再详细研究即可。

**GDB 配置与扩展**

GDB 是跨平台的调试器，可以调试 Linux 程序，Windows 程序，Unix 程序，MacOS 程序以及更多的嵌入式系统程序，每一个平台都有自己的特点，它们需要特殊设置。比如调试 DJGPP 程序，以及调试 Windows PE 程序的功能就是为调试 Windows 上的程序而添加，如果涉及到特殊平台调试，详细内容可以参考对应平台的特殊设置。

在 gdb 中可以使用`set`命令配置 gdb。

```
set prompt newprompt   // 设置gdb提示符为 newprompt
show prompt

set history filename fname // 设置gdb命令执行历史放到 fname文件中
set history save on/off    // 开启gdb命令执行历史记录

set history size size      // 设置历史记录大小为 size
set history size unlimited // 不限制历史大小

set height lpp             // 设置gdb屏幕大小，高度
set height unlimited
show height

set width cpl              // 宽度
set width unlimited
show width

set pagination on/off      // 设置页码标记
show pagination

set input-radix base       // 设置输入数字的数基为base，默认十进制
show input-radix
set output-radix base
show output-radix

set radix [base]           // 设置输入与输出的数基为base
show radix

show osabi                 // 显示当前的 OS ABI
set osabi abi              // 设置OS ABI为abi

set auto-load off          // 关闭自动加载相关文件
show auto-load
info auto-load             // 显示自动加载的文件

set auto-load local-gdbinit // 自动加载工作目录的 gdbinit文件
info auto-load local-gdbinit

set verbose on/off         // 开启或关闭打印详细的信息
show verbose

set confirm off/on         // 关闭或开启 请求确认，
show confirm


```

对 GDB 的扩展分为两部分，一部分是使用 GDB 脚本，另外一部分是 GDB 的`Python`扩展，编写 Python 脚本来扩展 GDB 的功能。

GDB 的命令文件就是 GDB 命令组成的文本文件，以`#`起始的行为注释，空行则不做任何动作。使用`source`命令来执行命令文件。

```
sources [-s] [-v] filename


```

命令文件的编写可以参考 gdb 文档中详细描述。

编写 GDB 的 Python 扩展也可以参考 gdb 文档，目前用不到，不再阅读相关内容。

### 代码反汇编

`disas/disassemble`命令可以对代码进行反汇编，如果由符号可以直接使用符号名进行反汇编；否则如果使用地址就需要两个参数。

```
// disas start,end / disas start,+length两种形式，start为起始地址，end为结束地址，+length为反汇编长度
(gdb) disas 0x32c4, 0x32e4
Dump of assembler code from 0x32c4 to 0x32e4:
   0x32c4 <main+204>:      addil 0,dp
   0x32c8 <main+208>:      ldw 0x22c(sr0,r1),r26
   0x32cc <main+212>:      ldil 0x3000,r31
   0x32d0 <main+216>:      ble 0x3f8(sr4,r31)
   0x32d4 <main+220>:      ldo 0(r31),rp
   0x32d8 <main+224>:      addil -0x800,dp
   0x32dc <main+228>:      ldo 0x588(r1),r26
   0x32e0 <main+232>:      ldil 0x3000,r31

// disas /m XXXXX    反汇编XXXXX函数，同时将源码列出
(dbg) disas /m main
Dump of assembler code for function main:
5       {
   0x08048330 <+0>:    push   %ebp
   0x08048331 <+1>:    mov    %esp,%ebp
   0x08048333 <+3>:    sub    $0x8,%esp
   0x08048336 <+6>:    and    $0xfffffff0,%esp
   0x08048339 <+9>:    sub    $0x10,%esp

6         printf ("Hello.\n");
=> 0x0804833c <+12>:   movl   $0x8048440,(%esp)
   0x08048343 <+19>:   call   0x8048284 <puts@plt>

7         return 0;
8       }
   0x08048348 <+24>:   mov    $0x0,%eax
   0x0804834d <+29>:   leave
   0x0804834e <+30>:   ret


```

`disas`具有三个参数，`\r`表示将原始代码的十六进制打印出来；`/s`和`/m`表示如果有源代码可用，则将汇编对应的源代码也打印出来，`/m`参数不如`/s`打印信息详细，已经被废掉了。

对于打印指定文件内的函数汇编，比如`foo.c`中的`bar()`函数，需要使用`disassemble 'foo.c'::bar`形式，而不能使用`disassemble foo.c:bar`形式。

还有一种查看汇编代码的方法是使用`x`命令，它用于查看内存中数据，也可以将内存数据显示为汇编代码。

```
// x /ni address  反汇编address处的n条汇编指令
(gdb) x /5i 0x0000555559544474
   0x555559544474:    mov    %r12,%rdi
   0x555559544477:    mov    %r14,%rsi
   0x55555954447a:    mov    %rax,%rdx
   0x55555954447d:    callq  0x555557c7e330
   0x555559544482:    mov    %r15,%rdi
// x /ni $rip - 30 从rip地址向后30条指令开始反汇编n条指令


```

GDB 汇编有几个参数，如下：

```
set disassembler-options option1[,option2…]
show disassembler-options    // 用于定义给反汇编器传入的指定信息，默认为空

set disassembly-flavor instruction-set
show disassembly-flavor        // 通过disas或x/i命令反汇编时，选择指令集，仅对X86家族有效

set disassemble-next-line    // 当执行停止时，是否反汇编以一行源码或指令 ON/OFF/AUTO，默认值是OFF
show disassemble-next-line


```

### GDB 调试汇编代码

gdb 是 GNU 的源码级调试器，它是 Linux 上的标准调试器。gdb 既可用于高级语言，像 C 和`C++`，的调试，也可以用于汇编语言的调试。

`gdb [program]`，启动程序`program`，如果`program`需要参数可以使用`gdb --args program param1 param2 ...`形式来启动程序。

```
h[elp] [keyword]  // 显示帮助信息。

r[un] [args]
    // 开始执行程序，如果程序需要命令行参数（比如 foo hi 3），你应该在这里指定程序参数（即run hi 3）

b[reak] [address]
    // 在指定的地址处设置断点，如果不指定地址则是在当前地址处设置断点。
    // `address`参数可以给定符号化地址，比如`main`，
    // 或者给定数字化地址，比如`*0x10a38`（这里的`*`是必须的）。

c[ontinue]       // 在遇到断点停止后，使用该命令继续执行程序。

i[nfo] b[reak]   // 显示当前设置的所有断点，按照序号排列。

d[elete] b[reakpoints] number // 删除指定编号的断点。

p[rint][/format] expr
    // 使用指定的格式打印表达式的值，默认打印十进制数。表达式可以包括程序变量或寄存器，
    // 打印寄存器时要在寄存器前加`$`而不是`%`符号。比较有用的格式有如下几种：
    // d decimal    十进制
    // x hex       十六进制
    // t binary    二进制
    // f floating point 浮点数
    // i instruction 指令
    // c character 字符
    //例如，要显示寄存器%rdi的十进制数，则输入p/d $rdi。
    // 注意需要使用64位格式的寄存器名字，当前指令寄存器值`p/x $rip`。

i[nfo] r[egisters] register
    // 一种可选方式来打印寄存器值，如果不指定寄存器则打印所有寄存器值。指定寄存器不需要指定`$`或`%`。

x/[count][format] [address]
    // 检查指定内存地址的内容，如果不指定地址值，则检查当前地址的内容。
    // 如果指定了count，则显示指定数量的值。地址可以是符号化（即main）或数字化的形式（即0x10a44）)。
    // 格式和print命令类似，对于打印程序指令特别有用，比如 x/100i foo反汇编出foo处的100条指令

disas[semble] address    // 符号化地址
disas[semble] address ,address
disas[semble] address [+number]

set var = expr
    // 设置指定寄存器或内存地址的内容为表达式expr的值，
    // 例如: set $rdi=0x456789AB or set myVar=myVar*2.

s[tep]i // 执行一条指令，然后回调gdb中停下来。
n[ext]i // 类似stepi，如果指令函数调用，nexti会跳过函数，而stepi会跳入函数

whe[re]       // 显示当前的活动栈。
backtrace/bt  // 显示当前栈帧。

q[uit]        // 退出gdb


```

汇编调试时一个比较有用的命令`x/20i $ip-40`，它可以打印当前执行指令前后二十条指令，用于上下文观察。

### Ubuntu 中命令程序源码与符号下载

**命令所属源码包下载**

这里以 Ubuntu 常用的`ls`命令为例。首先查看 ls 命令本身的信息。

```
~$ which ls
/bin/ls


```

搜索`/bin/ls`程序所属的程序包，用于找到对应源码包名称：

```
$ dpkg -S /bin/ls
coreutils: /bin/ls


```

使用`apt-get`命令获取源码包。首先查看下载源码的源是否已经设置，比如在 Ubuntu 16.04 版本上，默认的源码源是被注释的（如下），需要将对应的`deb-src`行的注释去掉。

```
$ cat /etc/apt/sources.list
#deb cdrom:[Ubuntu 16.04.4 LTS _Xenial Xerus_ - Release amd64 (20180228)]/ xenial main restricted

# See http://help.ubuntu.com/community/UpgradeNotes for how to upgrade to
# newer versions of the distribution.
deb http://cn.archive.ubuntu.com/ubuntu/ xenial main restricted
#deb-src http://cn.archive.ubuntu.com/ubuntu/ xenial main restricted

......


```

如果不放开这些源，会造成如下的错误：

```
$ sudo apt-get source coreutils
正在读取软件包列表... 完成
E: 您必须在 sources.list 中指定代码源(deb-src) URI


```

修改后，首先取回更新的软件包列表信息，然后执行获取源码的命令。

```
$ sudo apt-get source coreutils
正在读取软件包列表... 完成
需要下载 5,755 kB 的源代码包。
获取:1 http://cn.archive.ubuntu.com/ubuntu xenial-updates/main coreutils 8.25-2ubuntu3~16.04 (dsc) [2,095 B]
获取:2 http://cn.archive.ubuntu.com/ubuntu xenial-updates/main coreutils 8.25-2ubuntu3~16.04 (tar) [5,725 kB]
获取:3 http://cn.archive.ubuntu.com/ubuntu xenial-updates/main coreutils 8.25-2ubuntu3~16.04 (diff) [28.3 kB]
已下载 5,755 kB，耗时 21秒 (263 kB/s)

gpgv: 于 2017年02月28日 星期二 17时24分15秒 CST 创建的签名，使用 RSA，钥匙号 778FA6F5
gpgv: 无法检查签名：找不到公钥
dpkg-source: 警告: 对 ./coreutils_8.25-2ubuntu3~16.04.dsc 校验签名失败
dpkg-source: info: extracting coreutils in coreutils-8.25
dpkg-source: info: unpacking coreutils_8.25.orig.tar.xz
dpkg-source: info: unpacking coreutils_8.25-2ubuntu3~16.04.debian.tar.xz
dpkg-source: info: applying no_ls_quoting.patch
dpkg-source: info: applying 61_whoips.patch
dpkg-source: info: applying 63_dd-appenderrors.patch
dpkg-source: info: applying 72_id_checkngroups.patch
dpkg-source: info: applying 80_fedora_sysinfo.patch
dpkg-source: info: applying 85_timer_settime.patch
dpkg-source: info: applying 99_kfbsd_fstat_patch.patch
dpkg-source: info: applying 99_hppa_longlong.patch
dpkg-source: info: applying 99_float_endian_detection.patch
dpkg-source: info: applying ppc_sha256_flags.patch
W: 文件'coreutils_8.25-2ubuntu3~16.04.dsc'无法被用户'_apt'访问，无法降低权限以进行下载。 - pkgAcquire::Run (13: 权限不够)


```

搜索`keyring`，查找要用到的公钥。

```
$ aptitude search keyring
p   debian-archive-keyring                     - Debian 档案文件的 GnuPG 存档密钥
v   debian-archive-keyring:i386                -
p   debian-keyring                             - GnuPG keys of Debian Developers and Maintainers
p   debian-ports-archive-keyring               - GnuPG archive keys of the debian-ports archive
......


```

下载公钥，可执行如下命令：

```
$ sudo aptitude install debian-keyring
下列“新”软件包将被安装。
  debian-keyring
0 个软件包被升级，新安装 1 个， 0 个将被删除， 同时 44 个将不升级。
需要获取 32.2 MB 的存档。 解包后将要使用 34.4 MB。
读取： 1 http://cn.archive.ubuntu.com/ubuntu xenial/universe amd64 debian-keyring all 2016.01.20 [32.2 MB]
已下载 32.2 MB，耗时 1分 57秒 (273 kB/s)
正在选中未选择的软件包 debian-keyring。
(正在读取数据库 ... 系统当前共安装有 226574 个文件和目录。)
正准备解包 .../debian-keyring_2016.01.20_all.deb  ...
正在解包 debian-keyring (2016.01.20) ...
正在设置 debian-keyring (2016.01.20) ...


```

再重新下载源码包即可：

```
$ apt-get source coreutils
正在读取软件包列表... 完成
需要下载 5,755 kB 的源代码包。
获取:1 http://cn.archive.ubuntu.com/ubuntu xenial-updates/main coreutils 8.25-2ubuntu3~16.04 (dsc) [2,095 B]
获取:2 http://cn.archive.ubuntu.com/ubuntu xenial-updates/main coreutils 8.25-2ubuntu3~16.04 (tar) [5,725 kB]
获取:3 http://cn.archive.ubuntu.com/ubuntu xenial-updates/main coreutils 8.25-2ubuntu3~16.04 (diff) [28.3 kB]
已下载 5,755 kB，耗时 21秒 (262 kB/s)
dpkg-source: info: extracting coreutils in coreutils-8.25
dpkg-source: info: unpacking coreutils_8.25.orig.tar.xz
dpkg-source: info: unpacking coreutils_8.25-2ubuntu3~16.04.debian.tar.xz
dpkg-source: info: applying no_ls_quoting.patch
dpkg-source: info: applying 61_whoips.patch
dpkg-source: info: applying 63_dd-appenderrors.patch
dpkg-source: info: applying 72_id_checkngroups.patch
dpkg-source: info: applying 80_fedora_sysinfo.patch
dpkg-source: info: applying 85_timer_settime.patch
dpkg-source: info: applying 99_kfbsd_fstat_patch.patch
dpkg-source: info: applying 99_hppa_longlong.patch
dpkg-source: info: applying 99_float_endian_detection.patch
dpkg-source: info: applying ppc_sha256_flags.patch


```

在当前目录中下载如下的程序包，`coreutils-8.25`即为对应的源码包，其中包含了`/bin/ls`程序的源码。

```
$ ll
总用量 5636
drwxrwxr-x  3 andy andy    4096 12月  9 15:17 ./
drwxrwxr-x  3 andy andy    4096 12月  9 14:53 ../
drwxrwxr-x 14 andy andy    4096 12月  9 15:17 coreutils-8.25/
-rw-r--r--  1 andy andy   28336 3月   3  2017 coreutils_8.25-2ubuntu3~16.04.debian.tar.xz
-rw-r--r--  1 andy andy    2095 3月   3  2017 coreutils_8.25-2ubuntu3~16.04.dsc
-rw-r--r--  1 andy andy 5725008 2月  18  2016 coreutils_8.25.orig.tar.xz


```

**命令符号下载**

与程序和源码源不同，符号源一般都不在系统中预配置，这需要手动进行配置。使用如下的步骤一次进行操作。

1.  使用如下命令，创建一个`/etc/apt/sources.list.d/ddebs.list`文件。
    
    ```
     echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse" | sudo tee -a /etc/apt/sources.list.d/ddebs.list
    
    
    ```
    
2.  稳定发布版本（并非开发，alpha 或 beta 版本）要求额外的两行信息，这个信息也要添加到 1 中的文件之中。
    
    ```
     echo -e "deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse\ndeb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | sudo tee -a /etc/apt/sources.list.d/ddebs.list
    
    
    ```
    
    其实就是在`/etc/apt/sources.list.d/`目录下创建`ddebs.list`文件，内容如下：
    
    ```
     $ cat  /etc/apt/sources.list.d/ddebs.list
     deb http://ddebs.ubuntu.com xenial main restricted universe multiverse
     deb http://ddebs.ubuntu.com xenial-updates main restricted universe multiverse
     deb http://ddebs.ubuntu.com xenial-proposed main restricted universe multiverse
    
    
    ```
    
3.  导入调试符号包的签名信息，在 Ubuntu 18.04 以及之后系统中使用`sudo apt install ubuntu-dbgsym-keyring`命令，在早些发布的系统中使用`sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622`
    
    在 Ubuntu 16.04 上执行结果如下：
    
    ```
     $ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622
     Executing: /tmp/tmp.5ENUbmxwm4/gpg.1.sh --keyserver
     keyserver.ubuntu.com
     --recv-keys
     F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622
     gpg: 下载密钥‘5FDFF622’，从 hkp 服务器 keyserver.ubuntu.com
     gpg: 密钥 5FDFF622：公钥“Ubuntu Debug Symbol Archive Automatic Signing Key (2016) <ubuntu-archive@lists.ubuntu.com>”已导入
     gpg: 合计被处理的数量：1
     gpg:               已导入：1  (RSA: 1)
    
    
    ```
    
4.  执行`sudo apt-get update`更新软件包列表。
    
5.  调试符号包有`-dbgsym`后缀附加，因此在安装调试符号包之前要先运行：
    
    ```
     apt-cache policy coretuils
    
    
    ```
    
    这个命令会显示当前安装软件包的版本号，用于找到要下载的符号包的版本号。
    
    对于要下载的`coreutils`软件包的调试符号包信息如下：
    
    ```
     $ apt-cache policy coreutils
     coreutils:
       已安装：8.25-2ubuntu3~16.04
       候选： 8.25-2ubuntu3~16.04
       版本列表：
      *** 8.25-2ubuntu3~16.04 500
             500 http://cn.archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages
             100 /var/lib/dpkg/status
          8.25-2ubuntu2 500
             500 http://cn.archive.ubuntu.com/ubuntu xenial/main amd64 Packages
    
    
    ```
    
6.  安装符号包：
    
    这里要使用到第五步中所获得的版本信息`8.25-2ubuntu3~16.04`，执行如下的命令获取对应的调试符号包。
    
    ```
     $ sudo apt-get install coreutils-dbgsym=8.25-2ubuntu3~16.04
     正在读取软件包列表... 完成
     正在分析软件包的依赖关系树
     正在读取状态信息... 完成
     下列【新】软件包将被安装：
       coreutils-dbgsym
     升级了 0 个软件包，新安装了 1 个软件包，要卸载 0 个软件包，有 44 个软件包未被升级。
     需要下载 2,127 kB 的归档。
     解压缩后会消耗 19.9 MB 的额外空间。
     获取:1 http://ddebs.ubuntu.com xenial-updates/main amd64 coreutils-dbgsym amd64 8.25-2ubuntu3~16.04 [2,127 kB]
     已下载 2,127 kB，耗时 29秒 (71.8 kB/s)
     正在选中未选择的软件包 coreutils-dbgsym。
     (正在读取数据库 ... 系统当前共安装有 226584 个文件和目录。)
     正准备解包 .../coreutils-dbgsym_8.25-2ubuntu3~16.04_amd64.ddeb  ...
     正在解包 coreutils-dbgsym (8.25-2ubuntu3~16.04) ...
     正在设置 coreutils-dbgsym (8.25-2ubuntu3~16.04) ...
    
    
    ```
    

至此就将`/bin/ls`程序的符号下载完成了，用 gdb 调试`/bin/ls`程序有如下的输出。进入 gdb 调试程序时可以发现调试器已经能够读取到调试符号了。在将之前下载的源码路径配置到 gdb 的源码搜索路径中，列举源码可以发现已经能够得到对应的源码了。

```
$ gdb -q /bin/ls
Reading symbols from /bin/ls...Reading symbols from /usr/lib/debug/.build-id/d0/bc0fb9b3f60f72bbad3c5a1d24c9e2a1fde775.debug...done.
done.
(gdb) b main
Breakpoint 1 at 0x402a00: file src/ls.c, line 1249.
(gdb) run
Starting program: /bin/ls
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, main (argc=1, argv=0x7fffffffdd68) at src/ls.c:1249
1249    src/ls.c: 没有那个文件或目录.
(gdb) bt
#0  main (argc=1, argv=0x7fffffffdd68) at src/ls.c:1249
(gdb) directory /home/XXXX/GDB/coreutils/coreutils-8.25
Source directories searched: /home/XXXX/GDB/coreutils/coreutils-8.25:$cdir:$cwd
(gdb) list
1280    #if ! SA_NOCLDSTOP
1281      bool caught_sig[nsigs];
1282    #endif
1283
1284      initialize_main (&argc, &argv);
1285      set_program_name (argv[0]);
1286      setlocale (LC_ALL, "");
1287      bindtextdomain (PACKAGE, LOCALEDIR);
1288      textdomain (PACKAGE);


```

By Andy@2018-12-04 20:46:23