在上一篇文章中，我们介绍了如何使用键盘快速调用 IDA 的一些命令。然而，有时你可能需要多次执行某个特定操作，如果它没有默认的快捷键，就会很麻烦，需要不断地通过菜单点击。即使有加速键（accelerator keys）也只能帮上一点忙。另外，有些操作甚至没有菜单项，第一次找到它们就很困难。

这里有两个 IDA 功能可以帮到你：

### 快捷键编辑器（Shortcut Editor）

通过 `Options > Shortcuts…` 打开快捷键编辑器，你可以查看、添加和修改几乎所有 IDA 界面动作的快捷键。

![shortcut editor](assets/2020/08/shotcut_editor.png)

该对话框是非模态的，并会显示当前视图可用的动作（当前不可用的会被划掉）。你可以在 IDA 中点击不同位置，观察可用动作列表如何随上下文变化。

**分配快捷键的方法：**

- 在列表中选择一个动作。
- 在 `Shortcut:` 输入框中输入组合键（Windows 下也可以点击 `Record` 按钮，然后按下想要的快捷键）。
- 点击 `Set` 保存新快捷键，它会在当前和未来的 IDA 会话中生效。

**恢复与重置：**

- `Restore` 仅恢复当前动作的默认快捷键。
- `Reset` 会将所有动作恢复到默认状态（默认配置在 `idagui.cfg` 中）。

### 命令面板（Command Palette）

命令面板（默认快捷键 `Ctrl–Shift–P`）与快捷键编辑器类似，也会显示所有 IDA 动作的列表，但它不是用来修改快捷键，而是直接执行动作。

![palette jump](assets/2020/08/palette_jump.png)

底部的过滤框会使用模糊匹配（fuzzy matching）过滤包含输入文本的动作，并在面板打开时自动获得焦点。你只需输入动作的大致名称，然后按 `Enter` 即可执行最佳匹配的动作。

原文地址：https://hex-rays.com/blog/igor-tip-of-the-week-02-ida-ui-actions-and-where-to-find-them