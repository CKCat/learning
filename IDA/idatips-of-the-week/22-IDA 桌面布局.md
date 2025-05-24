IDA’s default windows layout is sufficient to perform most standard analysis tasks, however it may not always be the best fit for all situations. For example, you may prefer to open additional views or to modify existing ones depending on your monitor size, specific tasks, or the binary being analyzed.  
IDA 的默认窗口布局足以执行大多数标准分析任务，但并不总是最适合所有情况。例如，您可能更喜欢打开其他视图或修改现有视图，这取决于您的显示器大小、特定任务或正在分析的二进制文件。

### Rearranging windows 重新排列窗口

The standard operation is mostly intuitive – click and drag the window title to dock the window elsewhere. While dragging, you will see the drop markers which can be used to dock the window next to another or as a tab. You can also release the mouse without picking any marker to make the window float independently.  
标准操作非常直观--单击并拖动窗口标题即可将窗口停靠到其他位置。拖动时，您会看到下拉标记，可用于将窗口停靠在另一个窗口旁边或作为标签页。您也可以在不选中任何标记的情况下松开鼠标，使窗口独立浮动。

![](assets/2021/01/desktop_dock-e1610619932258.png)

### Docking a floating window  
停靠浮动窗口

Once a window is floating, you can’t dock it again by dragging the title. Instead, hover the mouse just below to expose the drag handle which can be used to dock it again.  
一旦窗口浮动，就不能通过拖动标题再次将其停靠。相反，只要将鼠标悬停在窗口下方，就会显示拖动手柄，可以再次将其停靠。

![](assets/2021/01/desktop_float-e1610619770712.png)

### Reset layout 重置布局

If you want to start over, use Windows > Reset desktop to go back to the default layout.  
如果想重新开始，可使用 Windows > 重置桌面返回默认布局。

### Saving and using custom layouts  
保存和使用自定义布局

The layout is saved automatically in the database, but if you want to reuse it later with a different one, use Windows > Save desktop… to save it under a custom name and later Windows > Load desktop… to apply it in another database or session. Alternatively, check the “Default” checkbox to make this layout default for all new databases.  
布局会自动保存在数据库中，但如果以后想用不同的布局重复使用，可使用 Windows > 保存桌面... 将其保存为自定义名称，然后再使用 Windows > 加载桌面... 将其应用于其他数据库或会话。或者，选中 "默认 "复选框，将此布局设为所有新数据库的默认布局。

![](assets/2021/01/desktop_save1-300x127.png)

### Debugger desktop 调试器桌面

When debugging, the windows layout changes to add views which are useful for the debugger (e.g. debug registers, Modules, Threads). This can lead to crowded display on small monitors so rearranging them can become a frequent task.  
调试时，窗口布局会发生变化，以添加对调试器有用的视图（如调试寄存器、模块、线程）。这可能会导致在小显示器上显示拥挤，因此经常需要重新排列。

![](assets/2021/01/desktop_debug.png)

This layout is separate from the disassembly-time one so if you want to persist a custom debugger layout, you need to save it during the debug session.  
这种布局与反汇编时的布局是分开的，因此如果要持续使用自定义调试器布局，需要在调试会话期间保存。

![](assets/2021/01/desktop_save2-1.png)

More info: [Desktops](https://hex-rays.com/products/ida/support/idadoc/1418.shtml) in the IDA Help.  
更多信息：IDA 帮助中的桌面。