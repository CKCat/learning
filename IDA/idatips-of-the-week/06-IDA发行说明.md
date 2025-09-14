每次 IDA 发布新版本时，我们都会附上详细的发布说明，描述各种新功能、改进以及错误修复。其中有些新增功能会被重点介绍，因此很容易被注意到；但也有一些并不那么显眼，需要仔细阅读才能发现。

如果你认真查看这些发布说明，你会惊讶地发现，在不同版本的 IDA 中，增加了许多小而实用的功能。

下面是几个很好的例子：

### 寄存器定义与使用（Register definition and use）

在 IDA 7.5 中新增了搜索寄存器定义或使用的操作，这些操作可以让你快速在寄存器的不同使用位置之间跳转。

- `Shift+Alt+↑`：查找所选寄存器上一次被定义（写入）的位置。
- `Shift+Alt+↓`：查找所选寄存器下一次被使用（读取或部分覆盖）的位置。

这些操作在经过高度优化的大型函数中尤其有用，因为寄存器定义与使用之间的距离可能很大，仅靠[标准高亮](https://hex-rays.com/blog/igor-tip-of-the-week-05-highlight/)来跟踪寄存器并不总是可行。

![](assets/2020/09/regdefuse.png)

在上面的截图中，你可以看到：

- `Alt+↑` 会跳转到最近的高亮子串匹配位置
- `Shift+Alt+↑` 则会找到 rbx 被修改的位置（ebx 是 rbx 的低位部分，因此 xor 指令会改变 rbx）

目前，这些操作仅在部分处理器架构上实现（x86/x64、ARM、MIPS），但如果收到更多请求，可能会扩展到其他架构。

### 跳转到上一个或下一个函数（Jump to previous or next function）

在 IDA 7.2 中新增了 `Ctrl+Shift+↑`/`Ctrl+Shift+↓` 快捷键，用于跳转到上一个/下一个函数的起始位置。

这是一个很小但非常实用的快捷键，尤其是在包含大量大型函数的二进制文件中。

顺便提一句，如果默认快捷键不方便使用，你可以随时[设置](https://hex-rays.com/blog/igor-tip-of-the-week-02-ida-ui-actions-and-where-to-find-them/)自己喜欢的组合键。

原文地址：https://hex-rays.com/blog/igor-tip-of-the-week-06-release-notes
