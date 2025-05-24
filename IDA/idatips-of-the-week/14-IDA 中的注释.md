The “I” in IDA stands for _interactive_, and one of the most common interactive actions you can perform is adding comments to the disassembly listing (or decompiler pseudocode). There are different types of comments you can add or see in IDA.  
IDA 中的 "I "代表交互式，而最常见的交互式操作之一就是在反汇编列表（或反编译器伪代码）中添加注释。您可以在 IDA 中添加或查看不同类型的注释。

### Regular comments 常规注释

These comments are placed at the end of the disassembly line, delimited by an assembler-specific comment character (semicolon, hash, at-sign etc.). A multi-line comment shifts the following listing lines down and is printed aligned with the first line which is why they can also be called _indented comments_.  
这些注释位于反汇编行的末尾，用汇编程序专用的注释字符（分号、散列、at-符号等）分隔。多行注释会将后面的列表行向下移动，并与第一行对齐打印，因此也称为缩进注释。

![](assets/2020/11/comm_regular.png)

Shortcut: : (colon)  快捷方式： : （冒号）

### Repeatable comments 可重复注释

Basically equivalent to regular comments with one small distinction: they are _repeated_ in any location which refers to the original comment location. For example, if you add a repeatable comment to a global variable, it will be printed at any place the variable is referenced.  
基本等同于普通注释，但有一个小区别：它们会在任何引用原始注释位置的地方重复出现。例如，如果在全局变量中添加可重复注释，那么在引用该变量的任何位置都会打印该注释。

![](assets/2020/11/comm_repeatable.png)

Shortcut: ; (semicolon)  
快捷方式： ; （分号）

### Function comments 函数注释

A repeatable comment added at the first instruction of a function is considered a _function comment._ It is printed before the function header and — since it’s a repeatable comment — at any place the function is called from. They’re good for describing what the function does in more detail than can be inferred from the function’s name.  
添加在函数第一条指令上的可重复注释被视为函数注释。该注释打印在函数头之前，由于是可重复注释，因此可以在函数被调用的任何地方打印。这些注释可以更详细地描述函数的功能，而不是从函数名称中推断出来。

![](assets/2020/11/comm_function.png)

Shortcut: ; (semicolon)  
快捷方式： ; （分号）

### Anterior and posterior comments  
前注释和后注释

These are printed before (_anterior_) or after (_posterior_) the current address as separate lines of text, shifting all other listing lines. They are suitable for extended explanations, ASCII art and other freestanding text. Unlike regular comments, no assembler comment characters are added automatically.  
这些注释作为单独的文本行打印在当前地址之前（前）或之后（后），并移除所有其他列表行。它们适用于扩展说明、ASCII 艺术和其他独立文本。与普通注释不同，不会自动添加汇编注释字符。

![](assets/2020/11/comm_anterior.png)

Shortcuts: Ins, Shift–Ins (I and Shift–I on Mac)  
快捷键 Ins , Shift - Ins ( Mac 上为 I 和 Shift - I )

Trivia: the comment with file details that is usually added at the beginning of the listing is an anterior comment so you can use Ins to edit it.  
小知识：通常在列表开头添加的包含文件详细信息的注释是前置注释，因此可以使用 Ins 对其进行编辑。

### Pseudocode comments 伪代码注释

In the decompiler pseudocode you can also add [_indented_](https://www.hex-rays.com/products/decompiler/manual/cmd_comments.shtml) comments using the shortcut / (slash) and [_block_](https://www.hex-rays.com/products/decompiler/manual/cmd_block_cmts.shtml) comments using Ins (I on Mac). They are stored separately from the disassembly comments, however _function comments_ are shared with those in disassembly.  
在反编译器伪代码中，您还可以使用快捷键 / （斜线）添加缩进注释，使用 Ins （Mac 上为 I ）添加块注释。这些注释与反汇编注释分开存储，但函数注释与反汇编注释共享。

![](assets/2020/11/comm_pseudo.png)

### Automatic comments 自动注释

In some situations IDA itself can add comments to disassembly. A few examples:  
在某些情况下，IDA 本身可以为反汇编添加注释。举几个例子：

“Auto comments” in Option > General.., Disassembly tab enables **instruction comments**.  
选项 > 常规...，反汇编选项卡中的 "自动注释 "可启用指令注释。

![](assets/2020/11/comm_auto1.png)  
![](assets/2020/11/comm_auto2.png)

**Demangled names** are shown as auto comments by default. Use the Options > Demangled names… dialog if you prefer to replace the mangled symbol directly in the listing.  
更改后的名称默认显示为自动注释。如果希望在列表中直接替换被混淆的符号，请使用选项 > 被混淆的名称...对话框。

![](assets/2020/11/comm_auto4-1.png)

**String literals** work similarly to repeatable comments: the string contents shows up as a comment in the place it’s referenced from.  
字符串文字的工作原理与可重复注释类似：字符串内容在引用处显示为注释。

![](assets/2020/11/comm_auto4.png)