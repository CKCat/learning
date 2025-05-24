Many features of IDA and other disassemblers are taken for granted nowadays but it’s not always been the case. As one example, let’s consider automatic variable naming.  
IDA 和其他反汇编程序的许多功能如今已被视为理所当然，但事实并非总是如此。例如，让我们来看看自动变量命名。

### A little bit of history  
一点历史

In the [first versions](https://hex-rays.com/about-us/our-journey/), IDA did not differ much from a dumb disassembler with comments and renaming and showed pretty much raw instructions with numerical offsets. To keep track of them users often had to add manual comments.  
在最初的版本中，IDA 与带有注释和重命名的傻瓜反汇编器并无太大区别，显示的几乎都是带有数字偏移的原始指令。为了跟踪这些指令，用户往往需要手动添加注释。

A few versions later, support for stack variables appeared. They initially had dummy names (`var_4`, `var_C` etc.) but could be renamed by the user which eased the reverse engineering process. However, this could still be tedious in big programs.  
几个版本之后，出现了对堆栈变量的支持。堆栈变量最初只有一个虚拟名称（ `var_4` 、 `var_C` 等），但用户可以对其进行重命名，从而简化了逆向工程过程。不过，这在大型程序中仍然很繁琐。

Next, [FLIRT](https://hex-rays.com/products/ida/tech/flirt/) was added, which helped identify standard library functions. Now the user did not need to analyze boilerplate code from the compiler runtime libraries but only the code written by the programmer. Having identified library functions also helped in picking names for variables: most library functions had known prototypes so the variables used for their arguments could be renamed accordingly.  
接下来，FLIRT 的加入有助于识别标准库函数。现在，用户无需分析编译器运行库中的模板代码，只需分析程序员编写的代码即可。识别库函数还有助于为变量取名：大多数库函数都有已知的原型，因此可以对用于参数的变量进行相应的重命名。

However, this process was still manual, could it not be automated?  
然而，这个过程仍然是人工操作，难道不能自动化吗？

And indeed, this is what happened in [IDA 4.10](https://hex-rays.com/products/ida/news/4_x/), with the addition of the type system and [standard type libraries](https://hex-rays.com/blog/igors-tip-of-the-week-60-type-libraries/). Now the identified library or imported functions could be matched to their prototypes in the type library and their arguments commented and/or renamed. For the arguments using a complex type (e.g. a structure), the stack variable could also be changed to use that type.  
事实上，随着类型系统和标准类型库的加入，IDA 4.10 就实现了这一点。现在，已识别的库函数或导入的函数可以与类型库中的原型相匹配，并对其参数进行注释和/或重命名。对于使用复杂类型（如结构体）的参数，堆栈变量也可更改为使用该类型。

### In practice 实际应用

As a current example, let’s have a look at a Win32 program which calls `CreateWindowExA`.  
举个例子，我们来看一个调用 `CreateWindowExA` 的 Win32 程序。

First, with everything disabled:  
首先，关闭所有功能：  
![](assets/2022/01/pit_cfg_none.png)

```
mov     eax, [ebp-20h]
push    dword ptr [ebp+8]
sub     eax, [ebp-28h]
push    dword ptr [ebx+1Ch]
push    eax
mov     eax, [ebp-24h]
sub     eax, [ebp-2Ch]
push    eax
push    dword ptr [ebp-28h]
push    dword ptr [ebp-2Ch]
push    dword ptr [ebp-8]
push    edi
push    offset aEdit    ; "edit"
push    edi
call    ds:CreateWindowExA
```

Next, with stack variables:  
接下来是堆栈变量：  
![](assets/2022/01/pit_cfg_stkvar.png)

```
mov     eax, [ebp+var_20]
push    [ebp+arg_0]
sub     eax, [ebp+var_28]
push    dword ptr [ebx+1Ch]
push    eax
mov     eax, [ebp+var_24]
sub     eax, [ebp+var_2C]
push    eax
push    [ebp+var_28]
push    [ebp+var_2C]
push    [ebp+var_8]
push    edi
push    offset aEdit    ; "edit"
push    edi
call    ds:CreateWindowExA
```

Stack variables are created but use dummy names. We could consult the [function’s documentation](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowexa) and rename and retype them manually. But instead we can enable argument propagation and [reanalyze the function](https://hex-rays.com/blog/igor-tip-of-the-week-17-cross-references-2/):  
堆栈变量已经创建，但使用的是假名。我们可以查阅函数文档，手动重命名并重新输入。不过，我们可以启用参数传播，然后重新分析函数：  
![](assets/2022/01/pit_cfg_all.png)

```
mov     eax, [ebp+Rect.bottom]
push    [ebp+hMenu]     ; hMenu
sub     eax, [ebp+Rect.top]
push    dword ptr [ebx+1Ch] ; hWndParent
push    eax             ; nHeight
mov     eax, [ebp+Rect.right]
sub     eax, [ebp+Rect.left]
push    eax             ; nWidth
push    [ebp+Rect.top]  ; Y
push    [ebp+Rect.left] ; X
push    [ebp+dwStyle]   ; dwStyle
push    edi             ; lpWindowName
push    offset aEdit    ; "edit"
push    edi             ; dwExStyle
call    ds:CreateWindowExA
```

Now, all arguments are renamed and all instructions initializing them are commented.  The `Rect` variable was renamed and typed thanks to another place in the same function:   
现在，所有参数都已重命名，所有初始化参数的指令都已注释。 `Rect` 变量的重命名和键入归功于同一函数中的另一处：

```
lea     eax, [ebp+Rect]
push    eax             ; lpRect
push    ebx             ; hWnd
call    ds:GetClientRect
```

Here, IDA recognized that the `lea` instruction effectively takes an address of a struct so the stack variable should be the struct itself and not just a pointer. Thanks to this, the field references are clearly identified in the other snippet.  
在这里，IDA 意识到 `lea` 指令有效地获取了一个结构体的地址，因此堆栈变量应该是结构体本身，而不仅仅是一个指针。正因为如此，另一个代码段中的字段引用才得以清晰识别。

### Recursive propagation 递归传播

In fact, PIT is not limited to single functions: if any of the function’s own arguments are renamed or retyped thanks to the type information, this information is propagated up the call tree. For example, `arg_0` from the second snippet is a function argument which was renamed to `hMenu`, so this information is used by the caller:  
事实上，PIT 并不局限于单个函数：如果函数自身的参数因类型信息而重命名或重打，这些信息就会在调用树中向上传播。例如，第二个代码段中的 `arg_0` 是一个函数参数，它被重命名为 `hMenu` ，因此调用者会使用这一信息：

![](assets/2022/01/pit_propagate.png)