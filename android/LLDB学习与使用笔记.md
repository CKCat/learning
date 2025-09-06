原文地址 [web.archive.org](https://web.archive.org/web/20201017055517/https://dbgtech.github.io/Tools/lldb-using.html)


LLDB 官方的文档还是比较容易理解的，且其他的自来多来自于它，所以直接看官方文档是个不错的选择，如下引用块中给出官方地址。

> [http://lldb.llvm.org/tutorial.html](https://web.archive.org/web/20201017055517/http://lldb.llvm.org/tutorial.html)

与 GDB 调试器命令集不同，LLDB 的设计尽量使得命令的语法结构化，所有命令按照如下的形式组织：

```
<noun> <verb> [-options [option-value]] [argument [argument…]]


```

命令执行之前就已经做了解析，所以所有命令都以统一的方式进行执行。基础命令语法非常简单，其中的参数，选项和选项值都是用空格分隔。对于需要在参数中使用空格的情况，可以用双引号保护参数中的空格，这样空格就不被当作分隔符解析。如果需要在命令中使用反斜线或双引号，需要使用反斜线进行转义。这些设计使得语法更加整齐有规则，但是也意味着 GDB 不需要引号的命令在 LLDB 中需要用引号进行特殊处理。

命令行中，选项可以放到任何地方。但是如果选项是由`-`开始，则需要通过在选项末尾添加`--`符号表示选项结束。例如如果想要启动一个进程，并且想要启动的进程使用`--stop-at-entry`选项，同时也想要让启动的进程使用参数`--program_arg value`，可以按照如下的方式编写命令：

```
(lldb) process launch --stop-at-entry -- -program_arg value


```

### 内置帮助命令

help 命令显示所有的调试器命令列表，或者给出指定命令的详细说明，如下所示。

```
(lldb) help             // 默认显示所有的命令
Debugger commands:
  apropos           -- 查找与指定的词或主题相关的调试器命令
  breakpoint        -- 一组操作断点的命令
  command           -- 一组管理和自定义调试器命令的命令。
  disassemble       -- 反汇编当前函数的字节，或反汇编用户指定的可执行程序。
  expression        -- 在当前程序上下文环境中，使用用户定义的变量计算表达式(ObjC++ or Swift)。
  frame             -- 操作当前线程栈帧的一组命令。
  gdb-remote        -- 连接到远程的GDB服务器。如果不提供主机名，则默认是localhost。
  gui               -- Switch into the curses based GUI mode.
  help              -- 显示调试器所有命令的列表，或者给出指定命令的详细信息。
  kdp-remote        -- 链接远程的KDP服务器，默认的udp端口是41139。
  log               -- 操作log的一组命令。
  memory            -- 操作内存的一组命令，包括内存搜索，读，写。
  platform          -- 管理和创建平台的命令集合。
  plugin            -- 管理和自定义插件命令的一组命令集合。
  process           -- 操作进程的一组命令。
  quit              -- 退出LLDB调试器。
  register          -- 访问线程寄存器的一组命令。
  script            -- 将一个表达式传递给脚本解释器计算，返回结果。如果没有给出表达式，则进入交互解释器中。
  settings          -- 一组操作调试器内部可设置的调试器变量。
  source            -- 一组接受源文件信息的命令。
  target            -- 一组操作调试器目标的命令。
  thread            -- 一组操作正调试进程中一个或多个线程的命令。
  type              -- 一组操作类型系统的命令。
  version           -- 显示LLDB调试器的版本。
  watchpoint        -- 一组操作观察点的命令。

Current command abbreviations (type 'help command alias' for more info):
  add-dsym  -- ('target symbols add') 通过指定调试符号文件路径或使用选项指定下载符号的文件，给当前调试目标的模块添加调试符号文件。
  attach    -- ('_regexp-attach') 附加到一个进程ID，或者进程名字
  b         -- ('_regexp-break') 使用正则表达式指定设置断点位置，其中<linenum>是十进制，<address>是十六进制。
  bt        -- ('_regexp-bt') 显示栈回溯。可以添加可选的参数，如果参数是个数字，它指定了要显示的栈帧的层数。如果参数是all，就显示完整栈帧。
  c         -- ('process continue') 在当前进程中继续执行所有线程。
  call      -- ('expression --') 在当前进程上线问中，使用用户定义变量和值范围内的变量，计算表达式值(ObjC++ or Swift)。
  continue  -- ('process continue')  在当前进程中继续执行所有的线程，同`c`。
  detach    -- ('process detach')  从正在调试的进程上分离。
  di        -- ('disassemble') 反汇编当前函数的字节，或者用户指定的可执行程序。
  dis       -- ('disassemble') 反汇编当前函数，或用户指定的可执行文件的其他部分代码。
  display   -- ('_regexp-display') 添加一个表达式计算 stop-hook。
  down      -- ('_regexp-down') 向下走“n”层栈帧，默认情况下是一个栈帧。
  env       -- ('_regexp-env')  快捷方式，查看和设置环境变量。
  exit      -- ('quit')  退出LLDB调试器。
  f         -- ('frame select') 在当前线程中通过一个索引值选择栈帧为当前栈帧。
  file      -- ('target create') 选择一个文件作为主执行文件。
  finish    -- ('thread step-out') 结束当前选择的栈帧的函数执行，返回到调用点。
  image     -- ('target modules') 一组访问目标模块信息的命令。
  j         -- ('_regexp-jump') 将PC设置为一个新的地址。
  jump      -- ('_regexp-jump') 将PC设置为一个新的地址。
  kill      -- ('process kill') 终止当前被调试的进程。
  l         -- ('_regexp-list') 实现了GDB的“list”命令，但是并没有显示FILE:FUNCTION，也没有将它映射到适当的“source list”命令上。
  list      -- ('_regexp-list') 同上
  n         -- ('thread step-over') 源码级别的单步执行。(如果没有指定，就是当前线程), 跳过调用。
  next      -- ('thread step-over') 同 n。
  nexti     -- ('thread step-inst-over') 指令级指定线程的单步执行。(如果没有指定线程，则是当前线程)，跳过函数调用。               
  ni        -- ('thread step-inst-over') 指令级别单步(如果不指定线程，就是当前线程的但不执行)，跳过函数调用。
  p         -- ('expression --') 当前进程的上下文中计算表达式(ObjC++ or Swift)。
  po        -- ('expression -O  -- ') 同上，针对ObjC++或Swift对象。
  print     -- ('expression --') 同上。
  q         -- ('quit') 退出LLDB调试器。
  r         -- ('process launch -c /bin/sh --') 在调试器中启动可执行文件。
  rbreak    -- ('breakpoint set -r %1') 在可执行文件上设置一个或一组断点。
  repl      -- ('expression -r  -- ') 同 print等命令
  run       -- ('process launch -c /bin/sh --') 同 r。
  s         -- ('thread step-in') 源码级别的 单步执行
  si        -- ('thread step-inst') 指令级别的但不执行。
  step      -- ('thread step-in') 源码级别的但不执行。
  stepi     -- ('thread step-inst') 指令级别的但不执行。
  t         -- ('thread select') 选择一个线程当作当前活动线程。
  tbreak    -- ('_regexp-tbreak') 使用正则表达式指定断点位置，设置单次的断点，<linenum>是十进制，<address>是十六进制
  undisplay -- ('_regexp-undisplay') 移除表达式值计算的 stop-hook。
  up        -- ('_regexp-up') 向上移动N帧，默认是1层栈帧。
  x         -- ('memory read') 从被调试进程中读取内存。

For more information on any command, type 'help <command-name>'.


```

查看命令更多的信息，可以输入`hep <command-name>`来查看特定命令的详细说明，如下就看一下`help`命令的帮助信息。

```
(lldb) help help        // 显示help命令的说明

     Show a list of all debugger commands, or give details about specific commands.

Syntax: help [<cmd-name>]

Command Options Usage:
  help [-ahu] [<cmd-name> [<cmd-name> [...]]]

       -a ( --hide-aliases )
            Hide aliases in the command list.

       -h ( --show-hidden-commands )
            Include commands prefixed with an underscore.

       -u ( --hide-user-commands )
            Hide user-defined commands from the list.

     This command takes options and free-form arguments.  If your arguments resemble option specifiers (i.e., they start with a - or --), you must use ' -- '
     between the end of the command options and the beginning of the arguments.


```

命令比较简单，没啥可说，直接 help 即可

`apropos`查找和特定的词或主题相关的调试器命令列表

这个命令其实也比较简单，在只知道一个命令的一部分关键字时，直接用这个命令匹配 / 搜索，可以列出相关的命令 方便查找是否有需要的命令。

```
(lldb) apropos stop     // 列举出和 stop相关的所有命令的解释

The following built-in commands may relate to 'stop':
  _regexp-display          -- Add an expression evaluation stop-hook.
  _regexp-undisplay        -- Remove an expression evaluation stop-hook.
  breakpoint command add   -- Add a set of commands to a breakpoint, to be executed whenever the breakpoint is hit.  If no breakpoint is specified, adds the
                              commands to the last created breakpoint.
  breakpoint modify        -- Modify the options on a breakpoint or set of breakpoints in the executable.  If no breakpoint is specified, acts on the last created breakpoint.  With the exception of -e, -d and -i, passing an empty argument clears the modification.
  breakpoint set           -- Sets a breakpoint or set of breakpoints in the executable.
  command history          -- Dump the history of commands in this session.
  command source           -- Read in debugger commands from the file <filename> and execute them.
  expression               -- Evaluate an expression (ObjC++ or Swift) in the current program context, using user defined variables and variables currently in
scope.
  frame variable           -- Show frame variables. All argument and local variables that are in scope will be shown when no arguments are given. If any arguments are specified, they can be names of argument, local, file static and file global variables. Children of aggregate variables can be specified such as 'var->child.x'.
  memory read              -- Read from the memory of the process being debugged.
  platform process launch  -- Launch a new process on a remote platform.
  process detach           -- Detach from the current process being debugged.
  process handle           -- Show or update what the process and debugger should do with various signals received from the OS.
  process launch           -- Launch the executable in the debugger.
  target stop-hook         -- A set of commands for operating on debugger target stop-hooks.
  target stop-hook add     -- Add a hook to be executed when the target stops.
  target stop-hook delete  -- Delete a stop-hook.
  target stop-hook disable -- Disable a stop-hook.
  target stop-hook enable  -- Enable a stop-hook.
  target stop-hook list    -- List all stop-hooks.
  target variable          -- Read global variable(s) prior to, or while running your binary.
  thread info              -- Show an extended summary of information about thread(s) in a process.
  thread step-in           -- Source level single step in specified thread (current thread, if none specified).
  thread step-inst         -- Single step one instruction in specified thread (current thread, if none specified).
  thread step-inst-over    -- Single step one instruction in specified thread (current thread, if none specified), stepping over calls.
  thread step-out          -- Finish executing the function of the currently selected frame and return to its call site in specified thread (current thread, if none specified).
  thread step-over         -- Source level single step in specified thread (current thread, if none specified), stepping over calls.
  thread step-scripted     -- Step as instructed by the script class passed in the -C option.
  watchpoint command add   -- Add a set of commands to a watchpoint, to be executed whenever the watchpoint is hit.
  watchpoint ignore        -- Set ignore count on the specified watchpoint(s).  If no watchpoints are specified, set them all.
  watchpoint modify        -- Modify the options on a watchpoint or set of watchpoints in the executable.  If no watchpoint is specified, act on the last created watchpoint.  Passing an empty argument clears the modification.

The following settings variables may relate to 'stop': 

  stop-disassembly-count -- The number of disassembly lines to show when displaying a stopped context.
  stop-disassembly-display -- Control when to display disassembly when displaying a stopped context.
  stop-line-count-after -- The number of sources lines to display that come after the current source line when displaying a stopped context.
  stop-line-count-before -- The number of sources lines to display that come before the current source line when displaying a stopped context.
  target.process.stop-on-sharedlibrary-events -- If true, stop when a shared library is loaded or unloaded.
  target.process.detach-keeps-stopped -- If true, detach will attempt to keep the process stopped.
  target.process.thread.step-in-avoid-nodebug -- If true, step-in will not stop in functions with no debug information.
  target.process.thread.step-avoid-regexp -- A regular expression defining functions step-in won't stop in.
  target.process.thread.step-avoid-libraries -- A list of libraries that source stepping won't stop in.
  interpreter.stop-command-source-on-error -- If true, LLDB will stop running a 'command source' script upon encountering an error.


```

其中的一条比较引人注目：`target.process.stop-on-sharedlibrary-events -- If true, stop when a shared library is loaded or unloaded.`即如果`target.process.stop-on-sharedlibrary-evetns`配置项为 true，一个共享库加载或卸载时进程就会暂停下来。

### 进程相关

启动进程，`(lldb) lldb DebugTest`将 DebugTest 当作调试目标文件加载，进入 lldb 调试器。注意这两个命令并没有开始调试程序，就仅仅是指定了调试对象而已

lldb 本身也是带有一些参数的。

```
$ lldb -v           // 输出调试器版本

$ lldb -h           // 输出调试器程序 lldb使用帮助


```

其他的比较有用的参数如下（其他的参数可以自己参考帮助文档）：

*   `-f` 指定要调试的程序 名称
*   `-p` 附加到指定 PID 的进程上
*   `-n` 附加到给定名字的进程上
*   `-w` 指定调试器等待进程启动
*   `-s` 指定 lldb 读取文件内容，并执行其中命令

另外一种指定调试目标的方法进入 lldb 后，使用 file 命令指定。

```
(lldb) file DebugTest   指定要调试的文件（映像）


```

`file`命令其实是`target create`命令的别名，使用参数创建一个作为主可执行程序的调试目标。target 下的命令有好多，比较简单的：

*   `(lldb) target create`
*   `(lldb) target delete` // 删除可作为调试目标的 主程序信息
*   `(lldb) target list` // 列举所有加入到当前调试器的 调试目标信息
*   `(lldb) target select` // 选择另外一个可执行程序作为调试目标

`modules/stop-hook/symbols`等三个在后面模块操作中详述其中`-d`参数在分析崩溃日志时可能有用，意思是在构建目标文件时，不加载依赖的库文件。

下面命令用于启动进程:

```
(lldb) process launch       // 启动当前选定的调试目标
(lldb) run


```

其中 run/r 两个命令是 process launch 的别名，功能等价。其中比较有用的参数有如下几个：

*   `-w` 设定当前进程的工作目录
*   `-s` (--stop-at-entry) 启动进程时，停止在进程入口点（这点比较重要，与 Windbg 默认的停止点相同）

**附加进程**

除了直接用调试器启动进程外，还可以附加到指定的进程上，以调试正在运行的进程。可以通过进程 ID 或进程名字 附加到进程上来调试进程。

```
    (lldb) process attach --pid 123                 // 附加到PID为123的进程上
    (lldb) process attach --name Sketch             // 附加到名字为 Sketch 的进程
    (lldb) process attach -n Sketch --waitfor       // 附加到名字为Sketch进程，如果进程没有，在进程启动时附加


```

当通过名字附加到进程上时，lldb 支持`--waitfor`选项等待下一个指定名字进程出现时附加上去。和 attach 相对应的就是 detach，detach 比较简单，不再详述，可以参考帮助文档。最后给出 process 命令的几个子命令，作为参考用。

```
(lldb) help process
The following subcommands are supported:

      attach    -- Attach to a process.   // 附加进程
      connect   -- Connect to a remote debug service. // 链接远程调试服务
      continue  -- Continue execution of all threads in the current process. // 继续执行进程中的所有线程
      detach    -- Detach from the current process being debugged. // 从当前被调试进程上分离
      handle    -- Show or update what the process and debugger should do with various signals received from the OS. // 显示或更新当从OS接受到信号时，进程和调试器如何处理
      interrupt -- Interrupt the current process being debugged. // 中断被调试进程
      kill      -- Terminate the current process being debugged. // 结束被调试进程
      launch    -- Launch the executable in the debugger. // 在调试器中启动可执行文件
      load      -- Load a shared library into the current process. // 向当前进程中加载共享库
      plugin    -- Send a custom command to the current process plug-in. // 向当前进程插件发送自定义命令
      save-core -- Save the current process as a core file using an appropriate file type.  //
      signal    -- Send a UNIX signal to the current process being debugged. // 向被调试进程发送UNIX信号
      status    -- Show the current status and location of executing process. // 显示进程的当前执行位置和状态
      unload    -- Unload a shared library from the current process using the index returned by a previous call to "process load". // 用之前的load中返回的索引卸载一个共享模块


```

1.  基本设置命令

`type`命令用于设置变量显示方式的命令，具体内容没有详细研究，可以参考文档`http://lldb.llvm.org/varformats.html`。

`settting`用于设置调试环境，包括的面比较广，无法言语叙述。命令就是追加 / 清除 / 在之后插入 / 在之前插入 / 移除 / 替代 / 设置等对其中的变量进行操作的命令

```
(lldb) settings show        // 显示当前已经设置的所有变量的值

(lldb) settings list        // 显示所有可设置变量，及其函数描述


```

> 参考文档：[http://lldb.llvm.org/formats.html。](https://web.archive.org/web/20201017055517/http://lldb.llvm.org/formats.html%E3%80%82)

### 反汇编

反汇编命令比较简单，即反汇编当前函数的内存字节，或是反汇编用户指的可执行文件中某个地址的字节.

```
(lldb) disassembly
(lldb) dis


```

比较有用的参数：

*   `-C` 要显示的上下文源码的行数
*   `-a` 反汇编包含这个地址的函数
*   `-b` (--bytes) 反汇编时显示 opcode 字节码
*   `-c` 要显示的指令行数
*   `-e` 反汇编结束的地址
*   `-f` (--frame) 从当前栈帧的起始开始反汇编
*   `-m` (--mixed) 混合源码和汇编指令
*   `-n` 反汇编给定函数名称的整个函数内容
*   `-p` (--pc) 反汇编当前 pc 周围的汇编
*   `-s` 开始反汇编的起始地址

### 线程命令

线程命令，主要是和线程相关的命令，thread 命令本身包含的比较多。这一节只介绍和线程相关的命令。

```
(lldb) thread list              // 显示当前进程的所有线程信息

(lldb) thread info              // 显示特定线程/或当前线程的信息

(lldb) thread select            // 将特定线程选为活动线程，切换线程


```

其他的命令在其他的节会介绍，这里给出 thread 命令完整的内容：

```
(lldb) help thread
The following subcommands are supported:

      backtrace      -- Show the stack for one or more threads.  If no threads are specified, show the currently selected thread.  Use the thread-index "all" to see all threads.  // 显示一个或多个线程的堆栈；不指定线程，则显示当前线程；指定all，则显示所有线程堆栈
      continue       -- Continue execution of one or more threads in an active process. // 继续执行当前进程中的一个或多个线程，注意与process continue区分
      info           -- Show an extended summary of information about thread(s) in a process. // 显示进程中的线程信息
      jump           -- Sets the program counter to a new address. // 将PC值设置为新的地址，无条件跳转
      list           -- Show a summary of all current threads in a process. // 显示当前进程中的所有线程
      plan           -- A set of subcommands for accessing the thread plans controlling execution control on one or more threads. // 一组用于访问线程计划，控制执行的命令
      return         -- Return from the currently selected frame, short-circuiting execution of the frames below it, with an optional return value, or with the -x
                        option from the innermost function evaluation.  This command takes 'raw' input (no need to quote stuff). // 直接从选定的栈帧返回
      select         -- Select a thread as the currently active thread. // 将指定线程切换为活动线程
      step-in        -- Source level single step in specified thread (current thread, if none specified). // 源码级别的单步执行
      step-inst      -- Single step one instruction in specified thread (current thread, if none specified). // 指令级别的单步执行
      step-inst-over -- Single step one instruction in specified thread (current thread, if none specified), stepping over calls. // 指令级别的跳过，不进入调用中，直接跳过
      step-out       -- Finish executing the function of the currently selected frame and return to its call site in specified thread (current thread, if none specified). // 结束当前函数执行，返回掉调用它的函数中，跳出
      step-over      -- Source level single step in specified thread (current thread, if none specified), stepping over calls. // 源码级别的单步跳过
      step-scripted  -- Step as instructed by the script class passed in the -C option.
      until          -- Run the current or specified thread until it reaches a given line number or leaves the current function. // 一直运行到指定行，或离开当前函数


```

1.  设置断点

先把和 breakpoint 相关的命令列举一下：

```
(lldb) help breakpoint
The following subcommands are supported:

      clear   -- Clears a breakpoint or set of breakpoints in the executable. // 清除一个或一组断点
      command -- A set of commands for adding, removing and examining bits of code to be executed when the breakpoint is hit (breakpoint 'commands'). // 给一个断点添加/删除一组可执行的命令
      delete  -- Delete the specified breakpoint(s).  If no breakpoints are specified, delete them all. // 删除断点，如果不指定断点，则删除所有的断点。
      disable -- Disable the specified breakpoint(s) without removing it/them.  If no breakpoints are specified, disable them all. // 使断点不生效，而不需要移除。如果不指定断点，则使得所有断点都不生效。
      enable  -- Enable the specified disabled breakpoint(s). If no breakpoints are specified, enable all of them. // 
      list    -- List some or all breakpoints at configurable levels of detail.
      modify  -- Modify the options on a breakpoint or set of breakpoints in the executable.  If no breakpoint is specified, acts on the last created breakpoint. With the exception of -e, -d and -i, passing an empty argument clears the modification.
      name    -- A set of commands to manage name tags for breakpoints
      set     -- Sets a breakpoint or set of breakpoints in the executable.


```

设置断点比较复杂，在文件的某行设置断点，可以按照如下形式输入命令：

```
(lldb) breakpoint set -file foo.c -line 12
(lldb) breakpoint set -f foo.c -l 12


```

在函数名上设置断点，可以输入如下的命令：

```
(lldb) breakpoint set -name foo
(lldb) breakpoint set -n foo


```

可以使用`--name`选项多次来设置一组函数的断点。这也是比较方便的，lldb 允许设置共同的条件或命令，而不需要指定多次。

```
(lldb) breakpoint set -name foo -name bar


```

注意 lldb 的断点设置，例如在 main 函数设置断点`breakpoint set -name main`，这里会搜索当前进程中所有的 main 函数，进行断点设置，结果如下所示：

```
3: name = 'main', locations = 13
  3.1: where = DebugTest`main + 22 at main.m:12, address = DebugTest[0x0000000100000e96], unresolved, hit count = 0 
  3.2: where = Foundation`-[NSThread main], address = Foundation[0x000000000003f090], unresolved, hit count = 0 
  3.3: where = Foundation`-[NSBlockOperation main], address = Foundation[0x000000000005a624], unresolved, hit count = 0 
  3.4: where = Foundation`-[NSFilesystemItemRemoveOperation main], address = Foundation[0x0000000000092452], unresolved, hit count = 0 
  3.5: where = Foundation`-[NSInvocationOperation main], address = Foundation[0x00000000000acb77], unresolved, hit count = 0 
  3.6: where = Foundation`-[NSFilesystemItemMoveOperation main], address = Foundation[0x00000000000f08a4], unresolved, hit count = 0 
  3.7: where = Foundation`-[NSDirectoryTraversalOperation main], address = Foundation[0x0000000000101d0e], unresolved, hit count = 0 
  3.8: where = Foundation`-[NSOperation main], address = Foundation[0x000000000017a160], unresolved, hit count = 0 
  3.9: where = Security`Security::OSXCode::main(), address = Security[0x00000000001bc5a6], unresolved, hit count = 0 
  3.10: where = CoreData`-[_PFUbiquityRecordImportOperation main], address = CoreData[0x00000000001738f0], unresolved, hit count = 0 
  3.11: where = CoreData`-[PFUbiquityBaselineRollOperation main], address = CoreData[0x00000000001b2510], unresolved, hit count = 0 
  3.12: where = CoreData`-[PFUbiquityBaselineRecoveryOperation main], address = CoreData[0x00000000001bdce0], unresolved, hit count = 0 
  3.13: where = CoreData`-[PFUbiquityBaselineRollResponseOperation main], address = CoreData[0x00000000001c70c0], unresolved, hit count = 0 

(lldb) br set -f main.m -n main     则只会对main.m中的main函数进行设置，断点列表如下所示。

(lldb) br list
Current breakpoints:
1: name = 'main', locations = 1
  1.1: where = DebugTest`main + 22 at main.m:12, address = DebugTest[0x0000000100000e96], unresolved, hit count = 0 

(lldb) break set -a 0xXXXXXXXX   // 在某一地址上设置断点，如下示例在main函数地址上设置断点。

4: address = 0x0000000100000e96, locations = 1, resolved = 1, hit count = 0
  4.1: address = 0x0000000100000e96, resolved, hit count = 0 

(lldb) br set -c $rax==10 -a 0x0000000100000f35
(lldb) br list
Current breakpoints:
1: name = 'main', locations = 1, resolved = 1, hit count = 2
  1.1: where = ConditionTest`main + 29 at main.c:13, address = 0x0000000100000f0d, resolved, hit count = 2 

3: address = 0x0000000100000f35, locations = 1, resolved = 1, hit count = 1
Condition: $rax==10


```

**设置观察点**

观察点没发现和断点有什么区别，实现机制可能不同。不过对于 Windows 调试习惯了，观察点也不晓得怎么用。这一部分内容不再详细分析和演示，详细内容参考文档。

```
(lldb) help watchpoint
The following subcommands are supported:

      command -- A set of commands for adding, removing and examining bits of code to be executed when the watchpoint is hit (watchpoint 'commmands').
      delete  -- Delete the specified watchpoint(s).  If no watchpoints are specified, delete them all.
      disable -- Disable the specified watchpoint(s) without removing it/them.  If no watchpoints are specified, disable them all.
      enable  -- Enable the specified disabled watchpoint(s). If no watchpoints are specified, enable all of them.
      ignore  -- Set ignore count on the specified watchpoint(s).  If no watchpoints are specified, set them all.
      list    -- List all watchpoints at configurable levels of detail.
      modify  -- Modify the options on a watchpoint or set of watchpoints in the executable.  If no watchpoint is specified, act on the last created watchpoint. Passing an empty argument clears the modification.
      set     -- A set of commands for setting a watchpoint.

For more help on any particular subcommand, type 'help <command> <subcommand>'.
(lldb) help watchpoint set
The following subcommands are supported:

      expression -- Set a watchpoint on an address by supplying an expression. Use the '-w' option to specify the type of watchpoint and the '-x' option to specify the byte size to watch for. If no '-w' option is specified, it defaults to write. If no '-x' option is specified, it defaults to the target's pointer byte size. Note that there are limited hardware resources for watchpoints. If watchpoint setting fails, consider disable/delete existing ones to free up resources.  This command takes 'raw' input (no need to quote stuff).
      variable   -- Set a watchpoint on a variable. Use the '-w' option to specify the type of watchpoint and the '-x' option to specify the byte size to watch for. If no '-w' option is specified, it defaults to write. If no '-x' option is specified, it defaults to the variable's byte size. Note that there are limited hardware resources for watchpoints. If watchpoint setting fails, consider disable/delete existing ones to free up resources.

For more help on any particular subcommand, type 'help <command> <subcommand>'.


```

### 寄存器与内存读写

```
(lldb) help memory
The following subcommands are supported:

      find  -- Find a value in the memory of the process being debugged.    // 调试进程中在内存中查找值
      read  -- Read from the memory of the process being debugged.          // 从调试的进程的内存中读取内容
      write -- Write to the memory of the process being debugged.

For more help on any particular subcommand, type 'help <command> <subcommand>'.


```

`memory read`比较有用的参数：

*   `-s` 读出的字节数
*   `-f` 读取格式
*   `-o` 将内存写入文件中
*   `-l` 每一行显示的数据条目数
*   `-Terminate` 显示变量类型
*   `-c` 要显示的总条目数，默认值各类型不同
*   `-b` 按照可执行二进制读取内存
*   `-P` 显示要解析的指针的深度
*   `-L` 显示变量位置信息 // 不知道什么意思

如下例子，直接按照二进制格式读取。

```
(lldb) mem r -b 0x00007fff5fbffbe0
0x7fff5fbffbe0: f8 fc bf 5f ff 7f 00 00 00 00 00 00 00 00 00 00  ???_?...........
0x7fff5fbffbf0: 37 fd bf 5f ff 7f 00 00 53 fd bf 5f ff 7f 00 00  7??_?...S??_?...


```

读取字符串:

```
(lldb) mem r -f s 0x00007fff5fbffcf8
0x7fff5fbffcf8: "/Users/andyguo/ObjCSrc/ConditionTest/build/Debug/ConditionTest"


```

读取数组:

```
(lldb) mem r -f char[] -s 16 0x00007fff5fbffcf8
0x7fff5fbffcf8: {/Users/andyguo/O}
0x7fff5fbffd08: {bjCSrc/Condition}
0x7fff5fbffd18: {Test/build/Debug}
0x7fff5fbffd28: {/ConditionTest\0T}

(lldb) mem r -f int8_t[] -s 16 0x00007fff5fbffcf8
0x7fff5fbffcf8: {47 85 115 101 114 115 47 97 110 100 121 103 117 111 47 79}
0x7fff5fbffd08: {98 106 67 83 114 99 47 67 111 110 100 105 116 105 111 110}
0x7fff5fbffd18: {84 101 115 116 47 98 117 105 108 100 47 68 101 98 117 103}
0x7fff5fbffd28: {47 67 111 110 100 105 116 105 111 110 84 101 115 116 0 84}


```

按照 QWORD 数据读取内存:

```
(lldb) mem r -f x -s 8 0x00007fff5fbffbe0
0x7fff5fbffbe0: 0x00007fff5fbffcf8 0x0000000000000000
0x7fff5fbffbf0: 0x00007fff5fbffd37 0x00007fff5fbffd53
0x7fff5fbffc00: 0x00007fff5fbffd67 0x00007fff5fbffd77
0x7fff5fbffc10: 0x00007fff5fbffdb0 0x00007fff5fbffdfc
(lldb) mem r -f x -s 8 -l 3 0x00007fff5fbffbe0
0x7fff5fbffbe0: 0x00007fff5fbffcf8 0x0000000000000000 0x00007fff5fbffd37
0x7fff5fbffbf8: 0x00007fff5fbffd53 0x00007fff5fbffd67 0x00007fff5fbffd77
0x7fff5fbffc10: 0x00007fff5fbffdb0 0x00007fff5fbffdfc


```

将 0x1000 到 0x1200 的内存数据输出到文件中

```
(lldb) memory read -outfile /tmp/mem.bin -binary 0x1000 0x1200


```

memory write 的参数：

```
Command Options Usage:
  memory write [-f <format>] [-s <byte-size>] <address> <value> [<value> [...]]
  memory write -i <filename> [-s <byte-size>] [-o <offset>] <address> <value> [<value> [...]]


```

写入数据到指定地址：

```
(lldb) memory read -f x -s 4 0xBFFFF3C0   // 以16进制格式显示地址处内存，4个字节一个单位


```

读出和写入的内存显示格式：

*   "default" // 默认同 - b
*   'B' or "boolean"
*   'b' or "binary"
*   'y' or "bytes"
*   'Y' or "bytes with ASCII"
*   'c' or "character"
*   'C' or "printable character"
*   'F' or "complex float"
*   's' or "c-string"
*   'd' or "decimal"
*   'E' or "enumeration"
*   'x' or "hex"
*   'X' or "uppercase hex"
*   'f' or "float"
*   'o' or "octal"
*   'O' or "OSType"
*   'U' or "unicode16"
*   "unicode32" // unicode32 格式
*   'u' or "unsigned decimal"
*   'p' or "pointer"
*   "char[]"
*   "int8_t[]"
*   "uint8_t[]"
*   "int16_t[]"
*   "uint16_t[]"
*   "int32_t[]"
*   "uint32_t[]"
*   "int64_t[]"
*   "uint64_t[]"
*   "float32[]"
*   "float64[]"
*   "uint128_t[]"
*   'I' or "complex integer"
*   'a' or "character array"
*   'A' or "address"
*   "hex float" // 16 进制 浮点数
*   'i' or "instruction" // 指令（反汇编）
*   'v' or "void" // void 指针

**寄存器读写**

官方给的教程比较简单： (lldb) help reg The following subcommands are supported: read -- Dump the contents of one or more register values from the current frame. If no register is specified, dumps them all. write -- Modify a single register value.

示例：

```
(lldb) reg read rax
     rax = 0x0000000000000005
(lldb) reg wr rax 6
(lldb) reg re
General Purpose Registers:
       rax = 0x0000000000000006


```

读取时，如果不指定寄存器名称，则直接给出所有寄存器的内容。

### 堆栈查看命令

`thread backtrace`命令格式如下：

```
    Syntax: bt [<digit>|all]


```

```
(lldb) thread backtrace 1 / bt 1

(lldb) thread backtrace 1
* thread #1: tid = 0x414e, 0x0000000100000f35 ConditionTest`main(argc=1, argv=0x00007fff5fbffbe0) + 69 at main.c:17, queue = 'com.apple.main-thread', stop reason = breakpoint 3.1
    frame #0: 0x0000000100000f35 ConditionTest`main(argc=1, argv=0x00007fff5fbffbe0) + 69 at main.c:17

(lldb) bt all
* thread #1: tid = 0x414e, 0x0000000100000f35 ConditionTest`main(argc=1, argv=0x00007fff5fbffbe0) + 69 at main.c:17, queue = 'com.apple.main-thread', stop reason = breakpoint 3.1
  * frame #0: 0x0000000100000f35 ConditionTest`main(argc=1, argv=0x00007fff5fbffbe0) + 69 at main.c:17
    frame #1: 0x00007fff9c31a5c9 libdyld.dylib`start + 1


```

`thread list/thread select/thread info`命令

```
(lldb) thread list      // 列出所有线程

(lldb) thread select    // 选择线程为活动线程

(lldb) thread info      // 显示线程信息


```

显示变量值，查看某一栈帧内容的命令是 frame，这个命令也比较简单：

```
(lldb) help frame
The following subcommands are supported:
      info     -- 列举当前线程中当前被选中的栈帧的信息。
      select   -- 按照索引从当前线程选择一个栈帧，作为当前栈帧。
      variable -- 显示帧变量，所有范围内的参数和本地变量都会显示。如果指定了变量名称，无论参数，本地变量，文件的静态变量，文件的全局变量都可以显示。
                  Children of aggregate variables can be specified such as 'var->child.x'.


```

`(lldb) frame var argc`查看 main 函数中的 argc 参数的值。执行 “frame variable” 命令可以非常方便地查看栈帧的参数和本地变量。`(lldb) frame variable`如果不指定任何变量名字，命令会显示所有的参数和本地变量。

```
(lldb) frame var
    (int) argc = 1
    (const char **) argv = 0x00007fff5fbffbe0
    (int) i = 10

// 指定了变量名字，则只显示变量内容
(lldb) frame variable self 
    (SKTGraphicView *) self = 0x0000000100208b40


```

如果给 frame var 命令传递一个本地变量子元素的路径，那么子元素会被打印出来，例如：

```
(lldb) frame variable self.isa
    (struct objc_class *) self.isa = 0x0000000100023730


```

`frame variable`命令不是完整的表达时解析器，但是它支持少量的简单操作符，例如 `&`，`*`，`->`，`[]`（没有重载的操作符）。

```
(lldb) frame variable *self
    (SKTGraphicView *) self = 0x0000000100208b40

(lldb) frame variable &self 
    (SKTGraphicView **) &self = 0x0000000100304ab 

(lldb) frame variable argv[0] 
    (char const *) argv[0] = 0x00007fff5fbffaf8 "/Projects/Sketch/build/Debug/Sketch.app/Contents/MacOS/Sketch"


```

`frame variable`命令会在变量上执行`object printing`操作（当前只支持 ObjC 对象的打印，使用对象的`description`方法，在命令中传`-o`标记）

```
(lldb) frame variable -o self
    (SKTGraphicView *) self = 0x0000000100208b40 <SKTGraphicView: 0x100208b40>


```

可以选择另外的帧来查看，使用`frame select`命令进行帧切换，如下所示。

```
(lldb) frame select 1
frame #1: 0x00007fff9c31a5c9 libdyld.dylib`start + 1
libdyld.dylib`start:
    0x7fff9c31a5c9 <+1>: movl   %eax, %edi
    0x7fff9c31a5cb <+3>: callq  0x7fff9c31a5fc            ; symbol stub for: exit
    0x7fff9c31a5d0 <+8>: hlt
    0x7fff9c31a5d1:      nop


```

如果需要查看更佳复杂的数据或修改程序数据，可以使用`expression`命令。命令会将一个表达式在当前选择的帧中计算值。

```
(lldb) expr self
$0 = (SKTGraphicView *) 0x0000000100135430

(lldb) expr self = 0x00
$1 = (SKTGraphicView *) 0x0000000000000000
(lldb) frame var self
(SKTGraphicView *) self = 0x0000000000000000


```

也可以调用函数，如下例子所示：

```
(lldb) expr (int) printf ("I have a pointer 0x%llx.\n", self) 
$2 = (int) 22
I have a pointer 0x0.


```

`expression`命令是一种 “原始” 命令，所以你不需要用引号引住整个表达式，即使反斜线也不需要。

最后，表达式的结果存储在持久变量（$[0-9]+）中，可以用于以后的表达式中。例如：

```
(lldb) expr self = $0
$4 = (SKTGraphicView *) 0x0000000100135430


```

> type 命令可以修改 frame var 的输出形式。 详细参考文档: [http://lldb.llvm.org/varformats.html](https://web.archive.org/web/20201017055517/http://lldb.llvm.org/varformats.html)

### 控制程序执行

进程启动见前面关于进程启动相关的小节。在启动了进程之后，程序一直运行到我们设置的断点。或者设置的停止点，进程就会停止，这样就可以进入进程控制中。

```
(lldb) process continue / c     // 继续执行当前进程（所有的线程都开始执行）

(lldb) process interrupt        // 无参数，直接中止（非kill）当前进程的执行，断下来。


```

`interrupt`命令相当于 Windbg 的`Ctrl-Break`，其他的控制相关都是线程控制了，下面看一下线程的控制：

```
(lldb) thread continue <thread-id> // 指定线程索引ID的线程继续执行


```

目前在一个时间点只能操作一个线程，但是 lldb 的设计最终支持 “在线程 1 的函数上跳过，在线程 2 上进入函数，在线程 3 上继续执行” 等。最终支持保持一些线程运行但是其他的停止，这种情景特别有用。方便起见，所有的步进命令都有别名。例如 “thread continue” 的别名为 “c” 等。

源码级别的单步命令如下所示：

```
(lldb) thread step-in    // 和gdb的 step 或 s 相同
(lldb) thread step-over  // 和gdb的 next 或 n 相同
(lldb) thread step-out   // 和gdb的 finish 或 f 相同


```

指令级别的单步命令：

```
(lldb) thread step-inst         // 和gdb的 stepi 或 si 相同
(lldb) thread step-inst-over    // 和gdb的 nexti 或 ni 相同


```

```
(lldb) thread until 100         // 这条命令会将当前线程在当前帧中运行100行代码或离开当前帧时停止，这和gdb的until命令等价


```

进程默认情况下和之前的进程共享 lldb 终端。这种模式下，和 gdb 中调试很像，当进程执行时你输入会进入先前进程的 STDIN 中。终止先前进程，输入`Ctrl+C`。

**线程状态**

如果停止了进程运行，lldb 会选择一个当前线程，通常是由于某个原因停止执行的线程。并且当前的栈帧也是这个线程的（停止时，这个通常是栈底的帧）。有许多命令用于查看当前线程和栈帧的工作状态。

```
(lldb) thread list
Process 46915 state is Stopped
* thread #1: tid = 0x2c03, 0x00007fff85cac76a, where = libSystem.B.dylib`__getdirentries64 + 10, stop reason = signal = SIGSTOP, queue = com.apple.main-thread
  thread #2: tid = 0x2e03, 0x00007fff85cbb08a, where = libSystem.B.dylib`kevent + 10, queue = com.apple.libdispatch-manager
  thread #3: tid = 0x2f03, 0x00007fff85cbbeaa, where = libSystem.B.dylib`__workq_kernreturn + 10


```

符号`*`表示线程 1 时当前线程，查看当前线程的 backtrace（栈回溯），使用`thread backtrace`命令可以提供一个线程列表来查看它们的栈回溯，或者关键字 “all” 来查看所有的线程：

```
(lldb) thread backtrace all


```

可以选择当前线程，这个命令会在下面一部分中作为默认命令使用。使用`thread select`命令：

```
(lldb) thread select 2


```

索引 2 就是在”thread list” 中列举出来的线程标示 id。

### 映像相关

和映像相关的命令就是`target`，上面看到 target 相关的选择调试目标的内容。下面先给一下 target 命令的完整信息：

```
(lldb) help target
The following subcommands are supported:
      create    -- 创建目标，作为主可执行文件，即调试进程。
      delete    -- 删除一个或多个调试目标。
      list      -- 列出当前调试会话中的所有的当前目标。
      modules   -- 一组用于访问目标进程模块信息的命令。
      select    -- 使用目标索引，选择一个调试目标作为当前目标。
      stop-hook -- 一组命令用于操作调试器目标的stop-hooks。
      symbols   -- 一组添加和管理调试符号文件的命令。
      variable  -- 读取全局变量

For more help on any particular subcommand, type 'help <command> <subcommand>'.


```

其中 create/delete/list/select 作为启动进程的命令，前面已经简单说过了。modules/`stop-hook`/`symbols`三个命令作为查看模块信息，或设置类断点的钩子使用。

`target module`命令，用于查看进程的模块信息，别名 image。

```
(lldb) target module list / image list          // 显示当前的进程的模块列表


```

其中较有用的参数如下：

*   `-a` // 显示指定地址模块的信息
*   `-b` [] // 显示模块的基础名字（就是名字，不带后缀）
*   `-d` [] // 显示模块的目录
*   `-f` [] // 显示模块的完整路径
*   `-g` [] // 只显示来自于全局模块列表的模块
*   `-r` [] // 显示模块被引用计数
*   `-s` [] // 显示完整的符号文件路径
*   `-u` // 列举模块时，显示 UUID

```
(lldb) target module dump / image dump          // dump当前的进程中模块的信息

The following subcommands are supported:

      line-table -- Dump the line table for one or more compilation units.
      sections   -- Dump the sections from one or more target modules.
      symfile    -- Dump the debug symbol file for one or more target modules.
      symtab     -- Dump the symbol table from one or more target modules.

For more help on any particular subcommand, type 'help <command> <subcommand>'.


```

```
(lldb) target module load / image load          // 加载模块

(lldb) help target modules load
     Set the load addresses for one or more sections in a target module.

Syntax: target modules load [--file <module> --uuid <uuid>] <sect-name> <address> [<sect-name> <address> ....]

Command Options Usage:
  target modules load [-u <none>] [-f <name>] [-s <offset>] [<filename> [<filename> [...]]]

       -f <name> ( --file <name> )
            Fullpath or basename for module to load.

       -s <offset> ( --slide <offset> )
            Set the load address for all sections to be the virtual address in the file plus the offset.
            // 设置加载地址为虚拟地址加上offset，也即 offset的基础上，再去按照模块原有偏移加载？？？？
       -u <none> ( --uuid <none> )
            A module UUID value.

     This command takes options and free-form arguments.  If your arguments resemble option specifiers
     (i.e., they start with a - or --), you must use ' -- ' between the end of the command options and the
     beginning of the arguments.


```

`target modules lookup(image lookup)`在模块中查找信息，查看地址所在模块（这个在查看 crash 比较有用）。

```
(lldb) image lookup -a 0x0000000100000f35
          Address: ConditionTest[0x0000000100000f35] (ConditionTest.__TEXT.__text + 69)
          Summary: ConditionTest`main + 69 at main.c:17


```

查找一个方法或符号的信息，比如文件位置

```
(lldb) image lookup -n main
    1 match found in /Users/andyguo/ObjCSrc/ConditionTest/build/Debug/ConditionTest:
            Address: ConditionTest[0x0000000100000ef0] (ConditionTest.__TEXT.__text + 0)
            Summary: ConditionTest`main at main.c:11


```

比较有用的参数有：

*   `-F` 在一个或多个模块中用函数名查找函数信息
*   `-a`
*   `-f` 在模块中，查找一个文件完整路径
*   `-n` 查找函数或符号
*   `-s` 符号
*   `-v` 显示完整信息

```
(lldb) target modules show-unwind               // 给出函数或地址对应的展开信息

(lldb) help target modules show-unwind
     Show synthesized unwind instructions for a function.

Syntax: target modules show-unwind <cmd-options>

Command Options Usage:
  target modules show-unwind [-n <function-name>]
  target modules show-unwind [-a <address-expression>]

       -a <address-expression> ( --address <address-expression> )
            Show unwind instructions for a function or symbol containing an address

       -n <function-name> ( --name <function-name> )
            Show unwind instructions for a function or symbol name.


```

### 源码

```
(lldb) help source list
     Display source code (as specified) based on the current executable's debug info.

Syntax: source list <cmd-options>

Command Options Usage:
  source list [-b] [-c <count>] [-s <shlib-name>] [-f <filename>] [-l <linenum>]
  source list [-b] [-c <count>] [-s <shlib-name>] [-n <symbol>]
  source list [-b] [-c <count>] [-a <address-expression>]
  source list [-br] [-c <count>]

       -a <address-expression> ( --address <address-expression> )
            Lookup the address and display the source information for the corresponding file and line.
            查找地址，显示对应文件和行的源码信息
       -b ( --show-breakpoints )
            Show the line table locations from the debug information that indicate valid places to set
            source level breakpoints.

       -c <count> ( --count <count> )
            The number of source lines to display.要显示的源码行数

       -f <filename> ( --file <filename> )
            The file from which to display source.
            从那个文件中显示源码
       -l <linenum> ( --line <linenum> )
            The line number at which to start the display source.
            开始显示源码的行数
       -n <symbol> ( --name <symbol> )
            The name of a function whose source to display.
            要显示源码的函数名称
       -r ( --reverse )
            Reverse the listing to look backwards from the last displayed block of source.
       -s <shlib-name> ( --shlib <shlib-name> )
            Look up the source file in the given shared library.


```

例如

```
(lldb) source list -f main.c -c 20 -l 11
   11      int main(int argc, const char * argv[]) {
   12          // insert code here...
   13          printf("Hello, World!\n");
   14
   15          for (int i = 0; i < 100; i++) //>
   16          {
   17              printf("Index: %d\n", i);
   18          }
   19
   20          return 0;
   21      }


```

### LLDB 符号加载

LLDB 分为共享库（包含了调试器的核心），实现调适的驱动和一个命令解释器。LLDB 可以用于符号化 crash 日志，比其他的符号程序提供更多信息。

```
(lldb) target create --no-dependents --arch x86_64 /tmp/a.out


```

`--no-dependents`意思是不加载所有的依赖共享库。

```
(lldb) target symbols add  / add-dsym   // 添加符号信息


```

> 崩溃日志分析：[http://lldb.llvm.org/symbolication.html](https://web.archive.org/web/20201017055517/http://lldb.llvm.org/symbolication.html)

By Andy @2018-06-18 10:33:21