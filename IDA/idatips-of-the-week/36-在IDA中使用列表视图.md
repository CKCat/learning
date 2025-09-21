列表视图（List views，也称为 choosers 或 table views）在 IDA 中被广泛用于显示各种信息列表。 例如，我们之前介绍过的 [函数列表](https://www.hex-rays.com/blog/igors-tip-of-the-week-28-functions-list/) 就是一个列表视图。

通过 `View > Open subviews` 菜单打开的许多窗口都是列表视图，例如：

- Exports（导出）
- Imports（导入）
- Names（名称）
- Strings（字符串）
- Segments（段）
- Segment registers（段寄存器）
- Selectors（选择器）
- Signatures（签名）
- Type libraries（类型库）
- Local types（本地类型）
- Problems（问题）
- Patched bytes（已修改字节）

`Jump` 菜单中的许多模态对话框（例如列出交叉引用的窗口）也是列表视图。 因为它们常用于从多个条目中选择一个，所以也被称为 `choosers`。

列表视图还可以嵌入到其他对话框或控件中，例如快捷键编辑器中的快捷键列表。 在 IDA SDK 中，这类被称为 `embedded choosers`（嵌入式选择器）。

## 搜索（Searching）

### 文本搜索（Text search）

你可以在列表视图的内容中搜索任意文本：

- `Alt + T`：输入搜索字符串
- `Ctrl + T`：查找下一个匹配项

![](assets/2021/04/chooser_search.png)

#### 增量搜索（Incremental search）

- 直接开始输入即可跳转到以输入文本开头的最近条目
- 输入的文本会显示在状态栏
- `Backspace`：删除错误输入的字符
- `Ctrl + Enter`：跳到下一个具有相同前缀的匹配项（如果有）

![](assets/2021/04/chooser_incr.png)

### 列（Columns）

- 每个列表视图顶部都有列标题
- 在大多数（但不是全部）列表视图中，可以通过右键菜单的 `Hide column` 或 `Columns…` 隐藏特定列
- 与大多数操作系统的标准列表视图类似，可以拖动列之间的分隔线调整列宽
- 双击右侧分隔线可自动调整列宽以适应该列中最长的字符串

### 排序（Sorting）

- 点击列标题可按该列排序
- 排序指示器显示排序方向（再次点击可切换方向）
- 由于 IDA 需要获取整个列表来进行排序，在大型列表中可能会很慢
- 每次列表更新并重新排序时，输出窗口会显示 `Caching <window>…` 提示
- 为了提高性能，可以通过右键菜单的 Unsort 禁用排序

![](assets/2021/04/chooser_sort.png)

### 过滤（Filtering）

- `Ctrl + F`：打开快速过滤框
- 输入文本后，只显示包含该子串的条目
- 默认情况下，匹配是大小写不敏感的，并且会匹配所有列
- 可以通过右键菜单修改选项，例如：
  - 启用区分大小写匹配
  - 仅匹配整个单词而不是任意子串
  - 启用模糊匹配
  - 将输入解释为正则表达式
  - 选择特定列进行匹配

![](assets/2021/04/chooser_quickfilter.png)

除了快速过滤，还可以使用更复杂的过滤（右键菜单 `Modify Filters` 或 `Ctrl + Shift + F`）：

在该对话框中，你不仅可以包含匹配项，还可以排除它们，或仅用自定义颜色高亮显示。

![](assets/2021/04/chooser_fullfilter.png)

与排序类似，过滤需要获取整个列表，这可能会减慢 IDA 的速度，尤其是在自动分析期间，要移除所有过滤器，请在右键菜单中选择 `Reset filters`

另请参阅：如何在 IDA 中使用[列表查看器](https://www.hex-rays.com/products/ida/support/idadoc/427.shtml)

原文地址：https://hex-rays.com/blog/igors-tip-of-the-week-36-working-with-list-views-in-ida
