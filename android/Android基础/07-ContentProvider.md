## ContentProvider 简介

`ContentProvider` 主要用于在不同的应用程序之间实现数据共享的功能，它提供了一套完整的机制，允许一个程序访问另一个程序中的数据，同时还能保证被访问数据的安全性。目前，使用 `ContentProvider` 是 Android 实现跨程序共享数据的标准方式。

## 运行时权限

运行时权限的核心就是在程序运行过程中由用户授权我们去执行某些危险操作，程序是不可以擅自做主去执行这些危险操作的。不仅需要在 `AndroidManifest.xml` 文件中声明权限，还要在应用运行过程中使用相关操作时再次申请相应的权限。

例如：

```kotlin
class ContactsView:AppCompatActivity() {
    private val contactsList = ArrayList<String>()
    private lateinit var adapter: ArrayAdapter<String>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.contacts_layout)

        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, contactsList)
        contactsView.adapter = adapter
        // 判断是否已经授权
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CONTACTS)
        != PackageManager.PERMISSION_GRANTED){
            // 如果没有授权，需要向用户申请
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.READ_CONTACTS), 1)
        }else{
            readContacts()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) { // checkSelfPermission 的回调函数，判断用户是否同意授权
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when(requestCode){
            1 -> {
                // 判断是否同意授权
                if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED){
                    readContacts()
                }else {
                    Toast.makeText(this, "You denied the permission",
                        Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    @SuppressLint("Range")
    private fun readContacts(){
        // 查询联系人
        contentResolver.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            null, null, null, null)?.apply {
                while (moveToNext()){
                    val displayName = getString(getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME))
                    val number = getString(getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER))

                    contactsList.add("$displayName\n$number")
                }
            adapter.notifyDataSetChanged()
            close()
        }
    }
}
```

`checkSelfPermission()` 方法判断用户是否授权了某个权限，第一个参数是 `Context`；第二个参数是具体的权限名。

`requestPermissions()` 方法向用户申请授权，第一个参数要求是 `Activity` 的实例；第二个参数是一个 `String`（申请的权限名） 数组；第三个参数是请求码。

调用完 `requestPermissions()` 方法之后，系统会弹出一个权限申请的对话框，用户可以选择同意或拒绝我们的权限申请。最终都会回调到 `onRequestPermissionsResult()` 方法中，而授权的结果则会封装在 `grantResults` 参数当中。

## 访问其他程序中的数据

`ContentProvider` 的用法一般有两种：一种是使用现有的 `ContentProvider` 读取和操作相应程序中的数据；另一种是创建自己的 `ContentProvider`，给程序的数据提供外部访问接口。

### ContentResolver 的基本用法

对于每一个应用程序来说，如果想要访问 `ContentProvider` 中共享的数据，就一定要借助 `ContentResolver` 类，可以通过 `Context` 中的 `getContentResolver()` 方法获取该类的实例。

`ContentResolver` 中的增删改查方法的表名参数是一个 `Uri` ，它主要由两部分组成：`authority` 和 `path`。`authority` 是用于对不同的应用程序做区分的；`path` 则是用于对同一应用程序中不同的表做区分的，通常会添加到 `authority` 的后面。同时还需要加上协议声明， `ContentProvider URI` 最标准的格式如下：

```bash
协议        authority                path
content://com.example.app.provider/table1
content://com.example.app.provider/table2
```

使用 Content URI 需要将它解析成 `Uri` 对象才可以作为参数传入。解析的方法如下：

```kotlin
val uri = Uri.parse("content://com.example.app.provider/table1")
```

然后就可以使用 `ContentResolver` 类的 `query()` 方法来获取数据了，查询完成后返回的仍然是一个 `Cursor` 对象。`ContentResolver.query()` 方法的参数说明

| query() 方法参数 | 对应 SQL 部分             | 描述                             |
| ---------------- | ------------------------- | -------------------------------- |
| uri              | from table_name           | 指定查询某个应用程序下的某一张表 |
| projection       | select column1, column2   | 指定查询的列名                   |
| selection        | where column = value      | 指定 where 的约束条件            |
| selectionArgs    | -                         | 为 where 中的占位符提供具体的值  |
| sortOrder        | order by column1, column2 | 指定查询结果的排序方式           |

例如：

```kotlin
private fun readContacts() {
    // 查询联系人数据
    contentResolver.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            null, null, null, null)?.apply {
        while (moveToNext()) {
            // 获取联系人姓名
            val displayName = getString(getColumnIndex(
            ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME))
            // 获取联系人手机号
            val number = getString(getColumnIndex(
            ContactsContract.CommonDataKinds.Phone.NUMBER))
            contactsList.add("$displayName\n$number")
        }
        adapter.notifyDataSetChanged()
        close()
    }
}
```

`ContentResolver` 中的增删改查方法与 `SQLiteDatabase` 中的增删改查方法类似，都是通过 `ContentValues` 来构造 SQL 语句。

## 创建自己的 ContentProvider

### 创建 ContentProvider 的步骤

如果想要实现跨程序共享数据的功能，可以通过新建一个类去继承 `ContentProvider` 的方式来实现。`ContentProvider` 类中有 6 个抽象方法，我们在使用子类继承它的时候，需要将这 6 个方法全部重写。如下所示：

```kotlin
class Myprovide:ContentProvider() {
    private val table1Dir = 0
    private val table1Item = 1
    private val table2Dir = 2
    private val table2Item = 3
    private val uriMatcher = UriMatcher(UriMatcher.NO_MATCH)
    init {
        // 期望访问的时 com.example.app.provider/table1 表中所有的数据
        uriMatcher.addURI("com.example.app.provider", "table1", table1Dir)
        // 期望访问的时 com.example.app.provider/table1 表中单条数据
        uriMatcher.addURI("com.example.app.provider", "table1/#", table1Item)
        // 期望访问的时 com.example.app.provider/table2 表中所有的数据
        uriMatcher.addURI("com.example.app.provider", "table2", table2Dir)
        // 期望访问的时 com.example.app.provider/table2 表中单条数据
        uriMatcher.addURI("com.example.app.provider", "table2/#", table2Item)
    }
    override fun onCreate(): Boolean {
        // 初始化 ContentProvider 的时候调用。通常会在这里完成对数据库的创建和升级等操作，
        // 返回 true 表示 ContentProvider 初始化成功，返回 false 则表示失败。
        TODO("Not yet implemented")
    }
    override fun query(
        uri: Uri,                           // 用于确定查询哪张表
        projection: Array<out String>?,     // 用于确定查询哪些列
        selection: String?, selectionArgs: Array<out String>?,  // 这两个参数用于确定查询条件
        sortOrder: String?                  // 对结果进行排序
    ): Cursor? {
        // 从 ContentProvider 中查询数据
        when(uriMatcher.match(uri)){ // 返回相应的自定义代码
            table1Dir -> {
                // 查询 table1 表中所有的数据
            }
            table1Item -> {
                // 查询 table1 表中所有的单条数据
            }
            table2Dir -> {
                // 查询 table2 表中所有的数据
            }
            table2Item -> {
                // 查询 table2 表中所有的单条数据
            }
        }
    }
    override fun getType(uri: Uri) = when(uriMatcher.match(uri)){
        // 根据传入的内容 URI 返回相应的 MIME 类型
        table1Dir -> "vnd.android.cursor.dir/vnd.com.example.app.provider.table1"
        table1Item -> "vnd.android.cursor.item/vnd.com.example.app.provider.table1"
        table2Dir -> "vnd.android.cursor.dir/vnd.com.example.app.provider.table2"
        table2Item -> "vnd.android.cursor.item/vnd.com.example.app.provider.table2"
        else -> null
    }
    override fun insert(uri: Uri,
        values: ContentValues? // 待添加的数据保
    ): Uri? {
        // 向 ContentProvider 中添加一条数据。
    }
    override fun delete(uri: Uri,
        selection: String?, selectionArgs: Array<out String>? // 这两个参数用于约束删除哪些行
    ): Int {
        // 从 ContentProvider 中删除数据。
    }
    override fun update(uri: Uri,
        values: ContentValues?, // 新数据
        selection: String?, selectionArgs: Array<out String>? // 这两个参数用于约束更新哪些行
    ): Int {
        // 更新 ContentProvider 中已有的数据。
    }
}
```

`ContentProvider URI` 的格式主要有两种，以路径结尾表示期望访问该表中所有的数据，以 `id` 结尾表示期望访问该表中拥有相应 `id` 的数据。如下所示：

```
// 以路径结尾
content://com.example.app.provider/table1
// 以id结尾
content://com.example.app.provider/table1/1
```

同时还可以使用通配符分别匹配这两种格式的内容 `ContentProvider URI`，规则如下。

- `*` 表示匹配任意长度的任意字符。
- `#` 表示匹配任意长度的数字。

```
// 匹配任意表的内容
content://com.example.app.provider/*
// 匹配table1表中任意一行数据的内容
content://com.example.app.provider/table1/#
```

`getType()` 方法用于获取 `Uri` 对象所对应的 `MIME` 类型。一个内容 `URI` 所对应的 `MIME` 字符串主要由 3 部分组成，`Android` 对这 3 个部分做了如下格式规定。

- 必须以 `vnd` 开头。
- 如果内容 `URI` 以路径结尾，则后接 `android.cursor.dir/`；如果内容 `URI` 以 `id` 结尾，则后接 `android.cursor.item/`。
- 最后接上`vnd.<authority>.<path>`。

例如：

```
content://com.example.app.provider/table1
对应的MIME类型
vnd.android.cursor.dir/vnd.com.example.app.provider.table1

content://com.example.app.provider/table1/1
对应的MIME类型
vnd.android.cursor.item/vnd.com.example.app.provider.table1
```

### 实现跨程序数据共享

在之前的数据库应用中创建 `DatabaseProvider` 类，并修改代码，如下所示：

```kotlin
class DatabaseProvider : ContentProvider() {
    private val TAG = "DatabaseProvider"
    private val bookDir = 0
    private val bookItem = 1
    private val categoryDir = 2
    private val categoryItem = 3
    private val authority = "com.example.androidfiles.provider"
    private var dbHelper: MyDatabaseHelper? = null

    private val uriMatcher by lazy {
        // by lazy 代码块是 Kotlin 提供的一种懒加载技术，代码块中的代码一开始并不会执行，
        // 只有当 uriMatcher 变量首次被调用的时候才会执行，并且会将代码块中最后一行代码的返回值赋给 uriMatcher。
        val matcher = UriMatcher(UriMatcher.NO_MATCH)
        matcher.addURI(authority, "book", bookDir)
        matcher.addURI(authority, "book/#", bookItem)
        matcher.addURI(authority, "category", categoryDir)
        matcher.addURI(authority, "category/#", categoryItem)
        matcher
    }

    override fun onCreate() = context?.let {
        dbHelper = MyDatabaseHelper(it, "bookstore.db", 2)
        true
    }?:false

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    )= dbHelper?.let {
        // 查询数据
        val db = it.readableDatabase
        val cursor = when(uriMatcher.match(uri)){
            bookDir -> db.query("Book", projection, selection, selectionArgs, null, null, sortOrder)
            bookItem -> {
                // getPathSegments()方法，它会将内容URI权限之后的部分以“/”符号进行分割，并把分割后
                //的结果放入一个字符串列表中，那这个列表的第0个位置存放的就是路径，第1个位置存放的就是id了
                val bookId = uri.pathSegments[1]
                db.query("Book", projection, "id = ?", arrayOf(bookId), null, null, sortOrder)
            }
            categoryDir -> db.query("Category", projection, selection, selectionArgs,
                null, null, sortOrder)
            categoryItem -> {
                val categoryId = uri.pathSegments[1]
                db.query("Category", projection, "id = ?", arrayOf(categoryId),
                    null, null, sortOrder)
            }
            else -> null
        }
        cursor
    }

    override fun getType(uri: Uri)= when(uriMatcher.match(uri)){
        // 如果内容 URI 以路径结尾，则后接 android.cursor.dir/
        // 如果内容 URI 以 id 结尾，则后接 android.cursor.item/
        // content://com.example.androidfiles.provider/book => vnd.android.cursor.dir/vnd.com.example.androidfiles.provider.book
        // content://com.example.androidfiles.provider/book/# => nd.android.cursor.item/vnd.com.example.androidfiles.provider.book
        bookDir -> "vnd.android.cursor.dir/vnd.com.example.androidfiles.provider.book"
        bookItem -> "vnd.android.cursor.item/vnd.com.example.androidfiles.provider.book"
        categoryDir -> "vnd.android.cursor.dir/vnd.com.example.androidfiles.provider.category"
        categoryItem -> "vnd.android.cursor.item/vnd.com.example.androidfiles.provider.category"
        else -> null
    }

    override fun insert(uri: Uri, values: ContentValues?)= dbHelper?.let {
        val db = it.writableDatabase
        val uriReturn = when(uriMatcher.match(uri)){
            bookDir, bookItem ->{
                val newBookId = db.insert("Book", null, values)
                Log.d(TAG, "insert: $newBookId")
                Uri.parse("content:/$authority/book/$newBookId")
            }
            categoryDir, categoryItem ->{
                val newCatagoryId = db .insert("Category", null, values)
                Uri.parse("content://$authority/category/$newCatagoryId")
            }
            else -> null
        }
        uriReturn
    }
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = dbHelper?.let {
        val db = it.writableDatabase
        val deletedRows = when(uriMatcher.match(uri)){
            bookDir -> db.delete("Book", selection, selectionArgs)
            bookItem -> {
                val bookId = uri.pathSegments[1]
                db.delete("Book", "id = ?", arrayOf(bookId))
            }
            categoryDir -> db.delete("Category", selection, selectionArgs)
            categoryItem -> {
                val categoryId = uri.pathSegments[1]
                db.delete("Category", "id = ?", arrayOf(categoryId))
            }
            else -> 0
        }
        deletedRows
    }?:0

    override fun update(uri: Uri, values: ContentValues?, selection: String?,
                        selectionArgs: Array<String>?) = dbHelper?.let {
        // 更新数据
        val db = it.writableDatabase
        val updatedRows = when (uriMatcher.match(uri)) {
            bookDir -> db.update("Book", values, selection, selectionArgs)
            bookItem -> {
                val bookId = uri.pathSegments[1]
                db.update("Book", values, "id = ?", arrayOf(bookId))
            }
            categoryDir -> db.update("Category", values, selection, selectionArgs)
            categoryItem -> {
                val categoryId = uri.pathSegments[1]
                db.update("Category", values, "id = ?", arrayOf(categoryId))
            }
            else -> 0
        }
        updatedRows
    } ?: 0
}
```

修改数据库程序的 `AndroidManifest.xml`，添加如下内容：

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.androidfiles">

    <application
        ...
        <!-- android:authorities 属性指定了 DatabaseProvider 的 authority -->
        <provider
            android:name=".DatabaseProvider"
            android:authorities="com.example.androidfiles.provider"
            android:exported="true"
            android:enabled="true"/>
    </application>

</manifest>
```

`android:exported` 和 `android:enabled` 属性指定了这个 `Provider` 是否可以被外部访问，需要设置为 `true`。

然后在当前应用中实现跨进程操作数据，如下所示：

```kotlin
class MainActivity : AppCompatActivity() {
    private val TAG = "MainActivity"
    var bookId:String? = null

    @SuppressLint("Range")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btn_show_contacts.setOnClickListener {
            val intent = Intent(this, ContactsView::class.java)
            startActivity(intent)
        }
        btn_add_data.setOnClickListener {
            // 添加数据
            val uri = Uri.parse("content://com.example.androidfiles.provider/book")
            val values = contentValuesOf("name" to "Hello World",
                "author" to "George Martin", "pages" to 1040, "price" to 22.85)
            val newUri = contentResolver.insert(uri, values)
            bookId = newUri?.pathSegments?.get(2)
            Log.d(TAG, "onCreate: $bookId")
        }
        btn_query_data.setOnClickListener {
            // 查询数据
            val uri = Uri.parse("content://com.example.androidfiles.provider/book")
            contentResolver.query(uri, null, null, null, null)?.apply {
                while (moveToNext()){
                    val name = getString(getColumnIndex("name"))
                    val author = getString(getColumnIndex("author"))
                    val pages = getString(getColumnIndex("pages"))
                    val price = getString(getColumnIndex("price"))
                    Log.d(TAG, "onCreate: BookInfo $name, $author, $pages, $price")
                }
                close()
            }
        }
        btn_update_data.setOnClickListener {
            // 更新数据
            bookId?.let {
                Log.d(TAG, "onCreate: $it")
                val uri = Uri.parse("content://com.example.androidfiles.provider/book/$it")
                val values = contentValuesOf("name" to "A Storm of Swords",
                    "pages" to 1216, "price" to 24.05)
                contentResolver.update(uri, values, null, null)
            }
        }
        btn_delete_data.setOnClickListener {
            // 删除数据
            bookId?.let {
                val uri = Uri.parse("content://com.example.androidfiles.provider/book/$it")
                contentResolver.delete(uri, null, null)
            }
        }
    }
}
```

这样就实现了跨进程操作数据。
