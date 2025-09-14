## 本周技巧：在 IDA 中使用键盘

如今，虽然大多数操作都可以用鼠标完成，但使用键盘往往会更快、更高效。IDA 最初是作为一个 DOS 程序开发的，那时图形界面和鼠标还不普及，这也是为什么你现在仍然可以在不碰鼠标的情况下完成大部分工作！

常用的快捷键可以在速查表中找到([HTML](https://www.hex-rays.com/wp-content/static/products/ida/idapro_cheatsheet.html), [PDF](https://www.hex-rays.com/wp-content/static/products/ida/support/freefiles/IDA_Pro_Shortcuts.pdf))，但仍有一些不太显眼却非常有用的快捷键。

### 文本输入对话框

例如 “输入注释” 或 “编辑本地类型”

- `Ctrl + Enter`：确认（OK）。
- `Esc`：取消（Cancel）。

![use ctrl-enter](assets/2020/07/dlg_textedit.png)

### Quick menu navigation  快速菜单导航

- 在 Windows 上按住 `Alt`（或启用系统选项）时，菜单项名称下会出现下划线。
- 按住 `Alt` 的同时，按下带下划线的字母（即“加速键”）即可打开该菜单，然后再按下具体菜单项的下划线字母即可执行。
- 第二步即使松开 `Alt` 也能生效。

示例：执行 `Search -> Not function`（没有默认快捷键）时，可以按 `Alt–H, F`。

![IDA menu with underlined accelerator keys](assets/2020/07/menu_accel.png)

在 Linux 或 Mac 上可能没有下划线，但相同的按键顺序依然有效。如果你没有 Windows 版 IDA，也不想手动试探加速键，可以查看 `cfg/idagui.cfg` 文件，其中描述了 IDA 默认的菜单布局和所有分配的加速键（以 `&` 前缀标记）。

### 对话框导航

除了 `OK/Cancel` 按钮，IDA 的许多对话框还有复选框、单选按钮或编辑框。

- `Tab`：在控件之间切换。
- 空格键：切换复选框或单选按钮。

与菜单类似，大多数对话框控件也有加速键。在 Windows 上可以用 `Alt` 显示它们，但与菜单不同的是，即使不按 `Alt`，它们也能使用。

示例：快速退出 IDA 且不保存自打开数据库以来的任何更改：

- `Alt–X` (或者 `Alt–F4`) 显示 `Save database` 对话框。
- `D` 切换 `DON’T SAVE the database` 复选框。
- `Enter` 或 `Alt–K` (或 `K`) 确认 (OK)。

![dialog exit](assets/2020/07/dlg_exit.png)

注意：少数对话框不支持此功能，例如 `Options –> General…` 对话框，以及 `Script Command`（`Shift–F2`）或其他带文本编辑框的对话框。在这些对话框中，必须按住 `Alt` 才能使用加速键。

原文地址：https://hex-rays.com/blog/igor-tip-of-the-week-01-lesser-known-keyboard-shortcuts-in-ida
