We covered how to search for things in [choosers (list views)](https://hex-rays.com/blog/igors-tip-of-the-week-36-working-with-list-views-in-ida/),  but what if you need to look for something elsewhere in IDA?  
我们介绍了如何在选择器（列表视图）中搜索内容，但如果您需要在 IDA 的其他地方搜索内容，该怎么办呢？

## Text search 文本搜索

When searching for textual content, the same shortcut pair (Alt–T to start, Ctrl–T to continue) works almost anywhere IDA shows text:  
在搜索文本内容时，相同的快捷键对（ Alt - T 开始， Ctrl - T 继续）几乎在 IDA 显示文本的任何地方都有效：

-   Disassembly (IDA View) 反汇编（IDA 视图）
-   Hex View 十六进制视图
-   Decompiler output (Pseudocode)  
    反编译器输出（伪代码）
-   Output window 输出窗口
-   Structures and Enums windows  
    结构和枚举窗口
-   Choosers (list views) 选择器（列表视图）

This search matches text anywhere in the current view, for example both the instructions and comments, if present.  
该搜索可匹配当前视图中任何位置的文本，例如说明和注释（如果有的话）。

For the main windows, the action is also accessible via the Search > Text… menu.  
对于主窗口，也可以通过搜索 > 文本...菜单访问该操作。

![](assets/2021/07/search_text.png)

The notice “(slow!)” refers to the fact that for text searching, IDA has to render **all** text lines in the range being searched, which can get quite slow, especially for big binaries. However, if you need the features like regexp matching, or searching for text in comments, the wait could be worth it.  
通知中的"（慢！）"指的是在进行文本搜索时，IDA 必须渲染搜索范围内的所有文本行，这可能会变得相当慢，尤其是对于大型二进制文件。不过，如果你需要 regexp 匹配或搜索注释中的文本等功能，那么等待也是值得的。

## Binary search 二进制搜索

Available as the shortcut pair Alt–B/Ctrl–B, or Search > Sequence of bytes…, this feature allows searching for byte sequences (including string literals) and patterns in the database (including process memory during debugging).   
可使用 Alt - B / Ctrl - B 或 Search > Sequence of bytes...（搜索 > 字节序列...）快捷键对数据库（包括调试期间的进程内存）中的字节序列（包括字符串字面量）和模式进行搜索。

![](assets/2021/07/search_binary-300x212.png)

The input line accepts the following inputs:  
输入行接受以下输入：

1.  byte sequence (space-delimited): `01 02 03 04`  
    字节序列（空格分隔）： `01 02 03 04`
2.  byte sequence with wildcard bytes represented by question marks:  `68 ? ? ? 0` will match both  `68 C4 1A 48 00` and `68 D8 1A 48 00`.  
    以问号代表通配符的字节序列： `68 ? ? ? 0` 将同时匹配 `68 C4 1A 48 00` 和 `68 D8 1A 48 00` 。
3.  one or more numbers in the selected radix (hexadecimal, decimal or octal). The number will be converted to the minimal necessary number of bytes according to the current processor endianness. For example, `04469E0` will be converted to `E0 69 44` on x86 (a little-endian processor). This feature is useful for finding values in data areas or embedded in instructions (immediates).  
    一个或多个选定弧度（十六进制、十进制或八进制）的数字。该数字将根据当前处理器的内位数转换为所需的最小字节数。例如，在 x86（一种小端位处理器）上， `04469E0` 将转换为 `E0 69 44` 。这一功能对于查找数据区中的值或嵌入在指令（直接指令）中的值非常有用。
4.  Quoted string literals, for example `"Error"`. The string will be converted to bytes using the encoding specified in the encoding selector. If “All Encodings” is selected, search will be performed using [all configured encodings](https://hex-rays.com/blog/igor-tip-of-the-week-13-string-literals-and-custom-encodings/).  
    引号字符串，例如 `"Error"` 。字符串将使用编码选择器中指定的编码转换为字节。如果选择 "所有编码"，则将使用所有配置的编码进行搜索。  
    ![](assets/2021/07/search_binarystr.png)
5.  Wide-character string constant (e.g. `L"test"`). Only UTF-16 is used convert such strings to raw bytes.  
    宽字符串常量（如 `L"test"` ）。仅使用 UTF-16 将此类字符串转换为原始字节。

## Immediate search 立即搜索

As mentioned previously, the same instruction operand can be [represented in different ways](https://hex-rays.com/blog/igors-tip-of-the-week-46-disassembly-operand-representation/) in IDA. For example, an instruction like  
如前所述，同一条指令的操作数在 IDA 中可以用不同的方式表示。例如，像

`test dword ptr [eax], 10000h`

can be also displayed as  
这样的指令也可以显示为

`test dword ptr [eax], 65536`

or even 甚至

`test dword ptr [eax], AW_HIDE`

So if you do the text search for `10000h`, IDA will find the first variation but not the other two. On x86, you can use binary search for `10000` hex (will be converted to byte sequence `00 00 01`), but this will not work for processors which use instruction encodings on non-byte boundary, or may give many false positives if unrelated instructions happen to match the byte sequence. So here’s why the immediate search is preferable:  
因此，如果对 `10000h` 进行文本搜索，IDA 将找到第一个变体，但找不到其他两个变体。在 x86 处理器上，可以使用二进制搜索 `10000` 十六进制（将转换为字节序列 `00 00 01` ），但这对使用非字节边界指令编码的处理器不起作用，如果不相关的指令恰好与字节序列匹配，则可能会产生许多误报。因此，以下是立即搜索更可取的原因：

1.  it only checks instructions with numerical operands or data items, improving search speed and reducing false positives;  
    它只检查带有数字操作数或数据项的指令，从而提高搜索速度并减少误报；
2.  it compares the **numerical value** of the operand, so any change in representation does not prevent the match, meaning it will find any of the three variations above  
    它比较操作数的数值，因此表示法的任何变化都不会妨碍匹配，这意味着它可以找到上述三种变体中的任何一种

Available as the shortcut pair Alt–I/Ctrl–I, or Search  > Immediate value…  
可使用快捷键对 Alt - I / Ctrl - I 或 Search > Immediate value...

![](assets/2021/07/search_imm.png)

The value can be entered in any numerical base using the C syntax (decimal, hex, octal).  
数值可以使用 C 语法（十进制、十六进制、八进制）以任何数值基数输入。

## Search direction 搜索方向

By default, all searches are performed “down” from the current position, i.e. toward increasing addresses. You can change it by checking “Search Up” in the individual search dialogs or beforehand  via Search  > Search direction. The currently set value is displayed in the menu item as well as IDA’s status bar.  
默认情况下，所有搜索都是从当前位置开始 "向下 "搜索，即向增加的地址搜索。您可以在各个搜索对话框中勾选 "向上搜索 "或事先通过搜索 > 搜索方向进行更改。当前设置值会显示在菜单项和 IDA 的状态栏中。

![](assets/2021/07/search_direction.png)

The “search next” commands and shortcuts (Ctrl–T, Ctrl–B, Ctrl–I) also use this setting.  
下一步搜索 "命令和快捷键（ Ctrl - T , Ctrl - B , Ctrl - I ）也使用此设置。

### Find all occurrences 查找所有搜索结果

## ![](assets/2021/07/search_findalld.png)

This checkbox allows you to get results of the search over whole database or view in a list which you can then inspect at your leisure instead of looking at every search hit one by one.  
通过该复选框，您可以获得整个数据库的搜索结果，或在列表中查看，然后可以随意检查，而不必逐个查看每个搜索结果。

![](assets/2021/07/search_findall.png)

## Picking the search type  
选择搜索类型

This is not a definitive guide but here are some suggestions:  
这不是一个权威指南，但这里有一些建议：

1.  text (e.g. prompt or error message) displayed by the program: binary search for the quoted substring (NB: this will not work if the string is not hardcoded but is in an external file or resource stream not loaded by IDA).  
    程序显示的文本（如提示或错误信息）：二进制搜索引号子串（注意：如果字符串不是硬编码，而是在 IDA 未加载的外部文件或资源流中，则搜索无效）。
2.  magic constant or error code: immediate search (in some cases binary search for the value can work too).  
    魔法常数或错误代码：立即搜索（在某些情况下，也可对数值进行二进制搜索）。
3.  an address to which there are no apparent cross references: binary search for the address value (will only succeed if the reference actually uses the value directly without calculating it in some way).  
    没有明显交叉引用的地址：对地址值进行二进制搜索（只有当引用实际直接使用该值而没有以某种方式计算该值时才会成功）。
4.  specific instruction opcode pattern: binary search for byte sequence (possibly with wildcard bytes).  
    特定指令操作码模式：二进制搜索字节序列（可能包含通配符字节）。
5.  instruction not having a fixed encoding: text search for mnemonic and/or operands (possibly as regexp).  
    无固定编码的指令：对助记符和/或操作数（可能作为 regexp）进行文本搜索。

More info: [Search submenu](https://hex-rays.com/products/ida/support/idadoc/568.shtml)  
更多信息：搜索子菜单


原文地址：