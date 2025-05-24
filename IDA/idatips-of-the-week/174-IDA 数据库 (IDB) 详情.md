When you work in IDA, it saves the results of your analysis in the _IDA Database_, so that you can pause and continue at a later time. You can recognize the database files by their file extension `.idb` (for legacy, 32-bit IDA) or `.i64` (for 64-bit IDA or IDA64). Thus they’re also often called just **IDB**. But what do they contain?  
当您在 IDA 中工作时，它会将您的分析结果保存在 IDA 数据库中，这样您就可以暂停并在以后继续工作。您可以通过数据库文件的扩展名 `.idb` （用于传统的 32 位 IDA）或 `.i64` （用于 64 位 IDA 或 IDA64）来识别数据库文件。因此，它们通常也只被称为 IDB。但它们包含什么内容呢？

You can get a hint by looking at the working directory when the IDB is open in IDA:  
当 IDB 在 IDA 中打开时，您可以通过查看工作目录获得提示：

![](assets/2024/02/idb1.png)

So, IDB is a container which contains several sub-files:  
因此，IDB 是一个包含多个子文件的容器：

1.  `filename.id0` is the actual database (implemented using B-tree), which contains all the metadata extracted from the input file and/or added by the user (names, comments, function boundaries and much more);  
    `filename.id0` 是实际数据库（使用 B 树实现），其中包含从输入文件中提取和/或由用户添加的所有元数据（名称、注释、函数边界等）；
2.  `filename.id1` stores the _virtual array_, containing a copy of all data loaded from the input file plus internal flags needed by IDA. Due to that it is usually 4-5 times as big as the original file but may grow or shrink if you [add](https://hex-rays.com/blog/igors-tip-of-the-week-96-loading-additional-files/) or remove data from the database;  
    0# 存储虚拟数组，其中包含从输入文件加载的所有数据的副本，以及 IDA 所需的内部标志。因此，它的大小通常是原始文件的 4-5 倍，但如果从数据库中添加或删除数据，它可能会增大或缩小；
3.  `filename.id2`(if present) stores the data for _sparse_ memory areas (e.g. mostly zero-filled segments) used in some situations;  
    0#（如果存在）用于存储某些情况下使用的稀疏内存区域（如大部分为零填充的区段）的数据；
4.  `filename.nam` is a special cache for names used in the database;  
    `filename.nam` 是数据库中使用的名称的特殊缓存；
5.  `filename.til` is the type library containing [Local Types](https://hex-rays.com//products/ida/support/idadoc/1259.shtml) for the database.  
    `filename.til` 是包含数据库本地类型的类型库。

When you close the database, IDA gives you a choice what to do with these files:  
关闭数据库时，IDA 会让您选择如何处理这些文件：

![](assets/2024/02/idb2.png)

-   _Don’t pack database_ leaves the individual sub-files on disk as-is. It is the fastest option but also can be dangerous because there are no integrity checks so any corruption may go undetected until much later;  
    不打包数据库，将各个子文件原封不动地留在磁盘上。这是最快的选择，但也可能是危险的，因为没有完整性检查，任何损坏都可能在很久之后才被发现；
-   _Pack database (Store)_ simply combines the sub-files into an `.idb` or `.i64` container, adding checksums so that file corruption can be detected. Because no compression is used, the IDB size is roughly equal to the total size of the sub-files;  
    打包数据库（存储）只是将子文件合并到一个 `.idb` 或 `.i64` 容器中，并添加校验和，以便检测文件是否损坏。由于没有使用压缩，IDB 的大小大致等于子文件的总大小；
-   _Pack database (Deflate)_ compresses sub-files using zlib compression which can significantly decrease the disk space compared to the Store option at the cost of more time spent saving and unpacking the IDB.  
    打包数据库（Deflate）使用 zlib 压缩技术压缩子文件，与存储选项相比，可以显著减少磁盘空间，但代价是需要花费更多时间保存和解压缩 IDB。

See also: 另请参见：

[IDA Help: Exit IDA  
IDA 帮助：退出 IDA](https://hex-rays.com//products/ida/support/idadoc/450.shtml)

[Igor’s tip of the week #58: Keyboard modifiers  
伊戈尔的每周提示 #58：键盘修饰符](https://hex-rays.com/blog/igors-tip-of-the-week-58-keyboard-modifiers/)