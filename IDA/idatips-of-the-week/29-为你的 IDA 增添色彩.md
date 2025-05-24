For better readability, IDA highlights various parts of the disassembly listing using different colors; however these are not set in stone and you can modify most of them to suit your taste or situation. Let’s have a look at the different options available for changing colors in IDA.  
为了提高可读性，IDA 使用不同的颜色来突出显示反汇编列表的各个部分；但这些颜色并不是一成不变的，你可以根据自己的喜好或情况来修改它们。让我们来看看在 IDA 中更改颜色的不同选项。

### Themes 主题

In case you are not aware, IDA supports changing the color scheme used for the UI (windows, controls, views and listings). The default theme uses light background but there are also two dark themes available. You can change the theme used via Options > Colors… (“Current theme” selector). Each theme then can be customized further by editing the colors in the tabs below. In the Disassembly tab, you can either select items from the dropdown, or click on them in the listing, then change the color by clicking the corresponding button.  
如果您不知道，IDA 支持更改用户界面（窗口、控件、视图和列表）的配色方案。默认主题使用浅色背景，但也有两种深色主题可供选择。您可以通过 "选项">"颜色..."（"当前主题 "选择器）更改所使用的主题。然后，可以通过编辑下面选项卡中的颜色进一步自定义每个主题。在 "拆卸 "选项卡中，可以从下拉菜单中选择项目，也可以在列表中点击项目，然后点击相应按钮更改颜色。

![](assets/2021/03/colors_disasm.png)

If you prefer editing color values directly, you can update many of them at once or even create a complete custom theme by following the directions on the [“CSS-based styling”](https://www.hex-rays.com/products/ida/support/tutorials/themes/) page.  
如果你喜欢直接编辑颜色值，可以一次更新多个颜色值，甚至可以按照 "基于 CSS 的样式 "页面上的说明创建一个完整的自定义主题。

### Coloring items 为项目着色

In addition to changing the whole theme or colors of individual listing components, you can also color whole lines (instructions or data) in the disassembly. This can be done using the menu Edit  > Other  > Color instruction…   
除了更改整个主题或单个列表组件的颜色外，您还可以为反汇编中的整行（指令或数据）着色。可以使用菜单 "编辑">"其他">"给指令着色...

![](assets/2021/03/colors_insn.png)

This command changes the background of the lines assigned to the current address (you can also select several lines to color them all together).  
该命令可更改分配给当前地址的行的背景（也可选择多行一起着色）。

![](assets/2021/03/colors_items.png)

### Coloring graph nodes 为图表节点着色

In the Graph View, you can color whole nodes (basic blocks) by clicking the first icon (Set node color) in the node’s header.  
在图表视图中，点击节点标题中的第一个图标（设置节点颜色），可以为整个节点（基本图块）着色。

![](assets/2021/03/colors_node.png)

After choosing the color, all instructions in the block will be colored and it will also be shown with the corresponding color in the graph overview.  
选择颜色后，块中的所有指令都将着色，并在图表概览中显示相应的颜色。

![](assets/2021/03/colors_node_ovrw.png)

### Coloring functions 为函数着色

Instead of (or in addition to) marking up single instructions or basic blocks you can also color whole functions. This can be done in the Edit Function (Alt+P) dialog by clicking the corresponding button.  
除了标记单条指令或基本模块外，您还可以为整个函数着色。您可以在编辑函数 ( Alt + P ) 对话框中单击相应的按钮为整个函数着色。

![](assets/2021/03/colors_func.png)

Changing the color of a function colors all instructions contained in it (except those colored individually), as well as its entry in the [Functions list](https://www.hex-rays.com/blog/igors-tip-of-the-week-28-functions-list/).  
更改一个函数的颜色后，该函数中包含的所有指令都会着色（单独着色的指令除外），函数列表中的条目也会着色。

![](assets/2021/03/colors_funclist.png)