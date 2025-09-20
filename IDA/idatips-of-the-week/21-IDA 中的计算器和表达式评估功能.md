在逆向工程时，你经常需要做一些简单的计算。虽然可以使用外部计算器，但 IDA 内置了一个计算器：

- 调出方式：按下 `?` 键，或通过菜单 `View > Calculator`。
- 计算结果会同时显示为 十六进制、十进制、八进制、二进制 以及 字符常量。
- 这些结果也会复制到 Output 窗口，方便粘贴到其他地方。

![](assets/2021/01/calc_simple.png)

### 支持的输入

不仅可以输入普通数字，还能使用 数据库中的符号名，以及在调试时的 寄存器值。

类似于前一篇技巧中提到的 “[跳转到地址](https://www.hex-rays.com/blog/igors-tip-of-the-week-20-going-places/)” 对话框。

小贴士：当你按下 `?` 时，光标下的数字、地址或标识符会被自动填入计算器，无需手动复制。

### 表达式求值

计算器功能实际上由 IDA 内置的 IDC 语言解释器 提供。

因此，你几乎可以在 IDA 中任何接受数字的地方使用表达式：

- `Jump to address`（跳转到地址）
- `Make array`（创建数组）
- `User-defined offset`（用户自定义偏移）
- 等等。

你还可以调用任何可用的 IDC 函数。

![](assets/2021/01/calc_useroff.png)

在调试时，可以写出类似这样的表达式：

```c
get_qword(__security_cookie)^RSP
```

这会取出全局变量 `__security_cookie` 的值，并与当前栈指针 `RSP` 做异或运算。

👉 总结：IDA 的计算器不仅是一个多进制转换工具，更是一个强大的 表达式求值引擎。它能结合符号、寄存器和 IDC 函数，大幅提升逆向分析时的效率。

原文地址：https://hex-rays.com/blog/igors-tip-of-the-week-21-calculator-and-expression-evaluation-feature-in-ida
