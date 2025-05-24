# 变量和函数

## 变量

kotlin 中定义一个变量，只允许在变量前声明两种关键字：`val` 和 `var`。

- `val` 用来声明一个不可变的变量，对应 java 中的 `final` 变量。
- `var` 用来声明一个可变的变量，对应 java 中的非 `final` 变量。

例如：

```kotlin
val a = 10; // val 定义常量, 等价 java 中的 final 变量，优先使用 val 声明变量。
var b = 10; // var 定义变量
b= 20;
println("Hello World! a = $a, b= $b");
```

通常情况下我们不需要指定变量的类型，kotlin 类型推导机制可以自动推导变量类型。我们也可以显式地声明变量的类型，Kotlin 完全抛弃了 Java 中的基本数据类型，全部使用了对象数据类型。下表列出了 Java 中的每一个基本数据类型在 Kotlin 中对应的对象数据类型。

| Java    | Kotlin  | 类型说明     |
| ------- | ------- | ------------ |
| int     | Int     | 整型         |
| long    | Long    | 长整型       |
| short   | Short   | 短整型       |
| float   | Float   | 单精度浮点型 |
| double  | Double  | 双精度浮点型 |
| boolean | Boolean | 布尔型       |
| char    | Char    | 字符型       |
| byte    | Byte    | 字节型       |

例如：

```kotlin
// 显式地声明变量类型
val a: Int = 30;
```

Kotlin 中的 `javaClass` 表示获取当前实例的 `Class` 对象，相当于在 Java 中调用 `getClass()`方法；而 Kotlin 中的 `T::class.java` 表示获取 `T` 类的 `Class` 对象，相当于在 Java 中调用 `T.class` 。

## 函数

Kotlin 定义函数语法规则如下：

```kotlin
fun methodName(param1:Int, param2:Int):Int{
    return 0
}
```

这就是定义一个函数最标准的方式了，当一个函数中只有一行代码时，Kotlin 允许我们不必编写函数体，可以直接将唯一的一行代码写在函数定义的尾部，中间用等号连接即可。甚至可以不用显式地声明返回值类型。

例如：

```kotlin
fun main() {
    val a = 37
    val b = 40
    val value = largerNumber1(a, b)
    println("call largerNumber1 return value = " + value)

    val value = largerNumber2(a, b)
    println("call largerNumber2 return value = " + value)

    val value = largerNumber3(a, b)
    println("call largerNumber3 return value = " + value)
}

fun largerNumber1(num1: Int, num2: Int): Int{
    return max(num1, num2);
}

fun largerNumber2(num1: Int, num2:Int):Int = max(num1, num2)

fun largerNumber3(num1: Int, num2:Int) = max(num1, num2)
```

# 逻辑控制

## if 条件语句

Kotlin 中的 `if` 语句和 Java 中的 `if` 语句几乎没有任何区别 。Kotlin 中的 `if` 语句相比于 Java 有一个额外的功能，它是可以有返回值的，返回值就是 `if` 语句每一个条件中最后一行代码的返回值。

例如：

```kotlin
fun main() {
    val a = 37
    val b = 40
    val value = largerNumber1(a, b)
    println("call largerNumber1 return value = " + value)

    val value = largerNumber2(a, b)
    println("call largerNumber2 return value = " + value)

    val value = largerNumber3(a, b)
    println("call largerNumber3 return value = " + value)
}

fun largerNumber1(num1: Int, num2: Int):Int{
    // if 语句每一个条件中最后一行代码的返回值。
    val value = if (num1 > num2){
        num1
    }else{
        num2
    }
    return value
}

fun largerNumber2(num1: Int, num2: Int):Int{
    // 直接将 if 语句返回。
    return if (num1 > num2){
        num1
    }else{
        num2
    }
}

// 结合前面函数的知识，可以将整个函数简化成一行代码。
fun largerNumber2(num1: Int, num2: Int) = if (num1 > num2) num1 else num2
```

## when 条件语句

Kotlin 中的 `when` 语句有点类似于 Java 中的 `switch` 语句，但它又远比 `switch` 语句强大得多。

`when` 语句允许传入一个任意类型的参数，然后可以在 `when` 的结构体中定义一系列的条件，格式是：

```kotlin
when(param){ // param 可选。
    匹配值 -> { 执行逻辑 }
}
```

当你的执行逻辑只有一行代码时，`{ }` 可以省略。

例如：

```kotlin
fun getScore1(name:String) = when(name){ // when带参数
    // 匹配值 -> {执行逻辑}
    "Tom" -> 86
    "Jim" -> 77
    "jack" -> 95
    else -> 0
}

fun getScore2(name:String) = when{ // when不带参数
    // 匹配值 -> {执行逻辑}
    name.startsWith("Tom") -> 86
    name == "Jim" -> 77
    name == "jack" -> 95
    else -> 0
}
```

除了精确匹配之外，`when` 语句还允许进行类型匹配。例如：

```bash
fun checkNumber(num:Number){
    when(num){ // when 也可以不带参数。
        is Int -> println("num is Int")     // is 相当与java中的 instanceof
        is Double -> println("num is Double")
        else -> println("num not support")
    }
}
```

## 循环语句

而 Kotlin 也提供了 `while` 循环和 `for` 循环，其中 `while` 循环不管是在语法还是使用技巧上都和 Java 中的 `while` 循环没有任何区别；Kotlin 在 `for` 循环方面做了很大幅度的修改，变成了 `for-in` 循环。

在学习 `for-in` 循环前，需要了解区间的语法。

- `..`是创建两端闭区间的关键字 `[ ]`。
- `until` 关键字来创建一个左闭右开的区间 `[ )` 。
- `downTo` 关键字创建一个降序的区间 `[ ]` 。

区间操作可以使用 `step` 关键字设置步长。

例如：

```kotlin
// 两端闭区间
for (i in 0..10){
    println(i)    // 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
}

// 左闭右开的区间
for (i in 0 until 10){
    println(i)    // 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
}

// step 设置步长
for(i in 0..10 step 2){
    println(i)    // 0, 2, 4, 6, 8, 10
}
for (i in 0 until 10 step 2){
    println(i)    // 0, 2, 4, 6, 8
}

// 降序的区间
for (i in 10 downTo 1){
    println(i)    // 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
}

for(i in 10 downTo 1 step 2){
    println(i)    // 10, 8, 6, 4, 2
}
```

# 面向对象编程

## 类与对象

Kotlin 中也是使用 `class` 关键字来声明一个类的，这一点和 Java 一致。Kotlin 中实例化一个类的方式和 Java 是基本类似的，只是去掉了 `new` 关键字而已。

Java 和 Kotlin 函数可见性修饰符对照表

| 修饰符    | Java                               | Kotlin             |
| --------- | ---------------------------------- | ------------------ |
| public    | 所有类可见                         | 所有类可见（默认） |
| private   | 当前类可见                         | 当前类可见         |
| protected | 当前类、子类、同一包路径下的类可见 | 当前类、子类可见   |
| default   | 同一包路径下的类可见（默认）       | 无                 |
| internal  | 无                                 | 同一模块中的类可见 |

例如：

```kotlin
class Person{
    var name = ""
    var age = 0
    fun eat(){
        println(name + " is eating. He is " + age + " years old.")
    }
}

fun main() {
    // 实例化对象不需要new关键字
    val p = Person()
    p.name = "Jack"
    p.age = 19
    p.eat()     // Jack is eating. He is 19 years old.
}
```

## 继承与构造函数

在 Kotlin 中任何一个非抽象类默认都是不可以被继承的，相当于 Java 中给类声明了 `final` 关键字。定义一个可被继承的类，只需要在前面加上 `open` 关键字就可以了；要让子类继承父类，在 Java 中继承的关键字是 `extends`，而在 Kotlin 中变成了一个冒号。

Kotlin 将构造函数分成了两种：主构造函数和次构造函数。

- 主构造函数的特点是没有函数体，直接定义在类名的后面即可，一个类只能有一个主构造函数。
- 次构造函数是通过 `constructor` 关键字来定义的，一个类可以有多个次构造函数。

每个非抽象类没有显示的定义构造函数时，默认都会有一个无参的主构造函数。主构造函数的特点是没有函数体，直接定义在类名的后面即可，所有主构造函数中的逻辑都可以写在里面 `init` 结构体中。也可以在类体内声明的属性初始化器中使用。

例如：

```kotlin
// 加上 open 关键字让 Person 可以被继承。
open class Person {
    var name = ""
    var age = 0

    fun eat() {
        println("Person ==> $name is eating. He is $age years old.")
    }
}

// : 表示继承，等价 Java 中的 extends
// Student 类默认有一个无参的主构造函数。
class Student : Person() { // 调用 Person 类中的主构造函数
    var no = ""
    var grade = 0

    fun info() {
        println("No = $no, grade=$grade")
    }
}

// 给 Teacher 类主构造函数显式地给它指明参数。
class Teacher(val selary: Double) : Person() { // 调用 Person 类中的主构造函数
    fun info() {
        println("selary = $selary.")
    }
}

// Employer 类定义了一个有两个参数的主构造函数，并在 init 里面编写相应的逻辑。
open class Employer(val name:String, val selary:Double){
    init {
        // 所有主构造函数中的逻辑都可以写在 init 里面
        println("调用主构造函数。")
    }
    fun info() {
        println("employer ==> name = $name, selary=$selary.")
    }
}

// name 和 selary 不加参数，表示让它的作用域仅限定在主构造函数中。
class Programer(val No: Int, name:String, selary:Double)
    : Employer(name, selary) { // 调用 Employer 类中主构造函数

    fun print() {
        println("No = $No.")
    }
}

fun main() {
    val st = Student()
    st.name = "Jack"
    st.age = 19
    st.no = "123"
    st.grade = 90
    st.eat()     // Person ==> Jack is eating. He is 19 years old.
    st.info()    // No = 123, grade=90

    val t = Teacher(4000.0);
    t.name = "Tom"
    t.age = 25
    t.eat()     // Person ==> Tom is eating. He is 25 years old.
    t.info()    // selary = 4000.0

    val p = Programer(1, "Jone", 10000.0)   // 调用主构造函数。
    p.info()    // employer ==> name = Jone, selary=10000.0.
    p.print()   // No = 1.
}
```

次构造函数是通过 `constructor` 关键字来定义的。Kotlin 规定，当一个类既有主构造函数又有次构造函数时，所有的次构造函数都必须调用主构造函数（包括间接调用）。当一个类没有显式地定义主构造函数且定义了次构造函数时，它就是没有主构造函数的。

例如：

```kotlin
open class Animal(val kind:String){

    fun info(){
        println("Kind is $kind.")
    }
}

class Dog(val age:Int, kind: String):Animal(kind){
    // 当一个类既有主构造函数又有次构造函数时，所有的次构造函数都必须调用主构造函数。
    constructor(kind: String):this(0, kind){}

    // 调用次构造函数，间接调用主构造函数。
    constructor():this("Normal"){}
}

// 类中只有次构造函数，没有主构造函数，继承Animal类时不需要再加上括号。
class Cat:Animal{
    // 使用 super 调用父类的主构造函数。
    constructor(kind: String):super(kind){}
}

fun main() {
    val dog = Dog( 1, "哈士奇")
    dog.info()  // Kind is 哈士奇.
    val dog1 = Dog("金毛")
    dog1.info() // Kind is 金毛.
    val cat = Cat("加菲猫")
    cat.info()  // Kind is 加菲猫.
}
```

## 接口

Java 是单继承结构的语言，任何一个类最多只能继承一个父类，但是却可以实现任意多个接口，Kotlin 也是如此。

Java 中继承使用的关键字是 `extends`，实现接口使用的关键字是 `implements`，而 Kotlin 中统一使用冒号，中间用逗号进行分隔。例如：

```kotlin


open class Person(val name:String, val age:Int) {

    fun eat() {
        println("Person ==> $name is eating. He is $age years old.")
    }
}

// 接口类
interface Study{
    fun readBooks()
    fun doHomework()
}

class Student(name:String, age:Int):Person(name, age), Study{
    override fun readBooks() {
        println("$name is reading.")
    }

    override fun doHomework() {
        println("$name is do homework.")
    }
}

// 多态
fun doStudy(su:Study){
    su.readBooks()
    su.doHomework()
}

fun main(){
    val st = Student("jack", 19)
    doStudy(st)
}
```

## 数据类与单例类

数据类通常需要重写 `equals()`、`hashCode()`、`toString()`这几个方法。当在一个类前面声明了 `data` 关键字时，就表明你希望这个类是一个数据类，Kotlin 会根据主构造函数中的参数帮你将 `equals()`、`hashCode()`、`toString()`等固定且无实际逻辑意义的方法自动生成，从而大大减少了开发的工作量。例如：

```kotlin
// 声明了 data 关键字时，就表明这个类是一个数据类，当一个类中没有任何代码时，还可以将尾部的大括号省略。
data class CellPhone(val brand: String, val price:Double)

fun main(){
    val cp1 = CellPhone("Samsung", 1229.99)
    val cp2 = CellPhone("Samsung", 1229.99)
    val cp3 = CellPhone("xiaomi", 999.99)
    println(cp1)        // CellPhone(brand=Samsung, price=1229.99)
    println(cp1 == cp2) // true
    println(cp1 == cp3) // false
}
```

在 Kotlin 中创建一个单例类的方式极其简单，只需要将 `class` 关键字改成 `object` 关键字即可。

```kotlin
object Singleton{
    fun singletonTest(){
        println("singletonTest is called.")
    }
}

fun main(){
    Singleton.singletonTest()   // singletonTest is called.
}
```

# Lambda 编程

## 集合的创建与遍历

集合的函数式 API 是用来入门 Lambda 编程的绝佳示例，不过在此之前，我们得先学习创建集合的方式才行。例如：

```kotlin
fun main(){
    // listOf() 函数创建的是一个不可变的集合
    println("list: ")
    val list = listOf("Apple", "Banana", "Orange", "Pear", "Grape")
    for (fruit in list){
        println(fruit)
    }
    println("\nmutableList: ")
    // mutableListOf() 函数创建一个可变的集合
    val mutlist = mutableListOf("Apple", "Banana", "Orange", "Pear", "Grape")
    mutlist.add("Watermelon")
    for (fruit in mutlist){
        println(fruit)
    }

    println("\nset:")
    // setOf() 函数创建的是一个不可变的集合
    val set = setOf("Apple", "Apple", "Banana", "Orange", "Pear", "Grape")
    for (fruit in set){
        println(fruit)
    }
    println("\nmutableSet:")
    // mutableSetOf() 函数创建一个可变的集合
    val mutSet = mutableSetOf("Apple", "Banana", "Orange", "Pear", "Grape")
    mutSet.add("Grape")
    mutSet.add("Grape")
    for (fruit in mutSet){
        println(fruit)
    }

    println()
    // HashMap 传统的初始化方法
    val map = HashMap<String, Int>()
    map.put("Apple", 1)
    map.put("Banana", 2)
    map.put("Orange", 3)
    map.put("Pear", 4)
    map.put("Grape", 5)

    // HashMap 现代的初始化方法
    map["Watermelon"] = 6

    // HashMap 最简单的初始化方法
    val m = mapOf("One" to 1, "Two" to 2, "Three" to 3)
    for ((k, v) in m){
        println("key=$k, value=$v")
    }
}
```

## 集合的函数式 API

Lambda 表达式的语法结构：

```kotlin
{参数名1: 参数类型, 参数名2: 参数类型 -> 函数体}
```

这是 Lambda 表达式最完整的语法结构定义。首先最外层是一对大括号，如果有参数传入到 Lambda 表达式中的话，我们还需要声明参数列表，参数列表的结尾使用一个 `->` 符号，表示参数列表的结束以及函数体的开始，函数体中可以编写任意行代码，并且最后一行代码会自动作为 Lambda 表达式的返回值。

在很多情况下，我们并不需要使用 Lambda 表达式完整的语法结构，而是有很多种简化的写法。例如：

```kotlin
fun main() {
    val list = listOf("Apple", "Banana", "Orange", "Pear", "Grape", "Watermelon")

    // lambda 返回字符串长度
    val lambda = {fruit:String -> fruit.length }
    // maxBy 函数接收的是一个 Lambda 类型的参数，并且会在遍历集合时将每次遍历的值作为参数传递给 Lambda 表达式。
    var maxLengthFruit = list.maxBy(lambda)
    println(maxLengthFruit)

    // 第一步简化
    maxLengthFruit = list.maxBy({fruit:String -> fruit.length})

    // 当 Lambda 参数是函数的最后一个参数时，可以将 Lambda 表达式移到函数括号的外面
    maxLengthFruit = list.maxBy(){fruit:String -> fruit.length}

    // 如果 Lambda 参数是函数的唯一一个参数的话，还可以将函数的括号省略
    maxLengthFruit = list.maxBy{fruit:String -> fruit.length}

    // 由于 Kotlin 拥有出色的类型推导机制，Lambda 表达式中的参数列表在大多数情况下不必声明参数类型
    maxLengthFruit = list.maxBy{fruit -> fruit.length}

    // 当 Lambda 表达式的参数列表中只有一个参数时，也不必声明参数名，而是可以使用 it 关键字来代替
    maxLengthFruit = list.maxBy{it.length}

    // 常用的函数式 API
    var newlist = list.map{ it.uppercase(Locale.getDefault()) }
    for (fruit in newlist){
        println(fruit)
    }

    newlist = list.filter { it.length <= 5 }
        .map { it.uppercase(Locale.getDefault()) }

    // any 函数用于判断集合中是否至少存在一个元素满足指定条件。
    val anyResult = list.any{it.length <= 5}

    // all 函数用于判断集合中是否所有元素都满足指定条件。
    val allResult = list.all{it.length <= 5}
    println("anyResult is $anyResult, allResult is $allResult") // anyResult is true, allResult is false

}
```

## Java 函数式 API 的使用

如果我们在 Kotlin 代码中调用了一个 Java 方法，并且该方法接收一个 Java 单抽象方法接口参数，就可以使用函数式 API。Java 单抽象方法接口指的是接口中只有一个待实现方法，如果接口中有多个待实现方法，则无法使用函数式 API。例如：

```kotlin
fun main() {

//    new Thread(new Runnable() {
//        @Override
//        public void run() {
//            System.out.println("Thread is running");
//        }
//    }).start();

    // Kotlin 使用 Thread，object 关键字表示创建匿名类实例
    Thread(object : Runnable{
        override fun run() {
            println("thread 1 is running.")
        }
    }).start()

    // Thread 类的构造方法是符合 Java 函数式 API 的使用条件，初步简化
    Thread(Runnable{
        println("thread 2 is running.")
    }).start()

    // 如果一个 Java 方法的参数列表中有且仅有一个 Java 单抽象方法接口参数，我们还可以将接口名进行省略
    Thread({
        println("thread 3 is running.")
    }).start()

    // 当 Lambda 表达式是方法的最后一个参数时，可以将 Lambda 表达式移到方法括号的外面。
    // 同时，如果 Lambda 表达式还是方法的唯一一个参数，还可以将方法的括号省略。
    Thread{
        println("thread 4 is running.")
    }.start()
}
```

在 Android 程序开发中实现注册常用的点击事件接口 `OnClickListener`，就可以使用函数式 API 的写法来对代码进行简化。例如：

```kotlin
button.setOnClickListener{
    // 点击事件对应的逻辑
}
```

# 空指针检查

## 可空类型系统

Kotlin 将空指针异常的检查提前到了编译时期，如果我们的程序存在空指针异常的风险，那么在编译的时候会直接报错，修正之后才能成功运行，这样就可以保证程序在运行时期不会出现空指针异常了。

Kotlin 提供了另外一套可为空的类型系统，只不过在使用可为空的类型系统时，我们需要在编译时期就将所有潜在的空指针异常都处理掉，否则代码将无法编译通过。在类名的后面加上一个 `?`，即可表示参数可为空的类型。

如果类型为可空类型，那么后续使用其实例对象调用方法前，就需要进行判空处理，Kotlin 提供了 `?.` 操作符进行判空辅助。

还有一个非常常用的 `?:` 操作符（三目运算符），这个操作符的左右两边都接收一个表达式，如果左边表达式的结果不为空就返回左边表达式的结果，否则就返回右边表达式的结果。

例如：

```kotlin
// String? 表示参数可以为 null
fun getTextLength(text:String?):Int{
    if (text != null) // 需要进行判断对象是否为null
        return text.length
    return 0
}

// 将 ?. 和 ?: 操作符结合到了一起使用，?. 进行判空，如果 text 为 null,
// text?.length 会返回一个 null 值，这个时候我们再借助 ?: 操作符让它返回 0。
fun getLength(text:String?) = text?.length ?: 0

fun main() {
    val str = "hello"
    println(getTextLength(str))
    println(getLength(str))
    println(getTextLength(null))
    println(getLength(null))
}
```

不过 Kotlin 的空指针检查机制也并非总是那么智能，有的时候我们可能从逻辑上已经将空指针异常处理了，但是 Kotlin 的编译器并不知道。在这种情况下，如果我们想要强行通过编译，可以使用非空断言工具，写法是在对象的后面加上`!!`操作符。

例如：

```kotlin
val content:String? = "hello"

fun printUpperCase(){
    // content 是一个可空对象，必须使用 !! 操作符编译通过，可能会发生异常
    println(content!!.uppercase(Locale.getDefault()))
}
fun main() {
    printUpperCase()
}
```

## let 函数

`let` 既不是操作符，也不是什么关键字，而是一个函数。这个函数提供了函数式 API 的编程接口，并将原始调用对象作为参数传递到 Lambda 表达式中。使用方法如下：

```kotlin
obj.let{ obj ->
    // 具体的业务逻辑
}
```

这里调用了 `obj` 对象的 `let` 函数，然后 Lambda 表达式中的代码就会立即执行，并且这个 `obj` 对象本身还会作为参数传递到 Lambda 表达式中。

`let` 函数的特性配合 `?.` 操作符可以在空指针检查的时候起到很大的作用。

例如：

```kotlin
class Human{
    fun eat(){
        println("Human eat.")
    }
    fun sleep(){
        println("Human sleep.")
    }
}

fun behavior(human:Human?){
    // 对象不为空时就调用let函数
    human?.let { human ->
        // 此时可以放心的调用对象的函数，不需要才进行检查了
        human.eat()
        human.sleep()
    }
}

fun main() {
    behavior(null)
    behavior(Human())
}
```

# Kotlin 中的小魔术

## 字符串内嵌表达式

Kotlin 允许我们在字符串里嵌入 `${}` 这种语法结构的表达式，并在运行时使用表达式执行的结果替代这一部分内容。当表达式中仅有一个变量的时候，还可以将两边的大括号省略。例如：

```kotlin
    val name = "CKCat"
    println("name: $name, char length: ${name.length}")
```

## 函数的参数默认值

我们可以在定义函数的时候给任意参数设定一个默认值，这样当调用此函数时就不会强制要求调用方为此参数传值，在没有传值的情况下会自动使用参数的默认值。

Kotlin 提供了另外一种神奇的机制，就是可以通过键值对的方式来传参，从而不必像传统写法那样按照参数定义的顺序来传参。

例如：

```kotlin
class Rectangle(val length: Int =1, val width: Int =1){

    fun area():Int{
        return length * width
    }
}

fun printParams(num:Int=10, str:String){
    println("num is $num, str is $str.")
}
fun main() {
    printParams(100, "hello")
    // 通过键值对的方式来传参
    printParams(str="hello")
    printParams(str="hello", num = 1000)

    println("area is ${Rectangle().area()}")
    println("area is ${Rectangle(2, 3).area()}")
}
```

# 标准函数和静态方法

## 标准函数 with、run 和 apply

Kotlin 的标准函数指的是 `Standard.kt` 文件中定义的函数，任何 Kotlin 代码都可以自由地调用所有的标准函数。

`with` 函数接收两个参数：

- 第一个参数可以是一个任意类型的对象；
- 第二个参数是一个 Lambda 表达式。

`with` 函数会在 Lambda 表达式中提供第一个参数对象的上下文，并使用 Lambda 表达式中的最后一行代码作为返回值返回。

例子：

```kotlin
fun normalAppend(){
    val list = listOf("Apple", "Banana", "Orange", "Pear", "Grape")
    val builder = StringBuilder()
    builder.append("Start eating fruits.\n")
    for (fruit in list){
        builder.append(fruit).append("\n")
    }
    builder.append("Ate all fruits.")
    val result = builder.toString()
    println(result)
}

fun withAppend(){
    val list = listOf("Apple", "Banana", "Orange", "Pear", "Grape")
    val result = with(StringBuilder()){
        // 接下来整个Lambda表达式的上下文就会是这个 StringBuilder 对象。
        append("Start eating fruits.\n")
        for (fruit in list)
            append(fruit).append("\n")
        toString()
    }
    println(result)
}
```

`run` 函数的用法和使用场景其实和 `with` 函数是非常类似的，只是稍微做了一些语法改动而已。首先 `run` 函数通常不会直接调用，而是要在某个对象的基础上调用；其次 `run` 函数只接收一个 Lambda 参数，并且会在 Lambda 表达式中提供调用对象的上下文。其他方面和 `with` 函数是一样的，包括也会使用 Lambda 表达式中的最后一行代码作为返回值返回。

例子：

```kotlin
fun runAppend(){
    val list = listOf("Apple", "Banana", "Orange", "Pear", "Grape")
    val result = StringBuilder().run{
        // 接下来整个Lambda表达式的上下文就会是这个 StringBuilder 对象。
        append("Start eating fruits.\n")
        for (fruit in list)
            append(fruit).append("\n")
        toString()
    }
    println(result)
}
```

`apply` 函数和 `run` 函数也是极其类似的，都要在某个对象上调用，并且只接收一个 Lambda 参数，也会在 Lambda 表达式中提供调用对象的上下文，但是 `apply` 函数无法指定返回值，而是会自动返回调用对象本身。

例子：

```kotlin
fun applyAppend(){
    val list = listOf("Apple", "Banana", "Orange", "Pear", "Grape")
    val result = StringBuilder().apply{
        // 接下来整个Lambda表达式的上下文就会是这个 StringBuilder 对象。
        append("Start eating fruits.\n")
        for (fruit in list)
            append(fruit).append("\n")
    }
    println(result.toString())
}
```

## 定义静态方法

静态方法在某些编程语言里面又叫作类方法，指的就是那种不需要创建实例就能调用的方法，所有主流的编程语言都会支持静态方法这个特性。

但是和绝大多数主流编程语言不同的是，Kotlin 却极度弱化了静态方法这个概念，想要在 Kotlin 中定义一个静态方法反倒不是一件容易的事。

可以使用单例类实现静态方法的语法特性。

例如：

```kotlin
object Util {
    fun doAction() {
        println("do action")
    }
}
```

虽然这里的 `doAction()`方法并不是静态方法，但是我们仍然可以使用 `Util.doAction()`的方式来调用，这就是单例类所带来的便利性。

不过，使用单例类的写法会将整个类中的所有方法全部变成类似于静态方法的调用方式，而如果我们只是希望让类中的某一个方法变成静态方法的调用方式,就可以使用 `companion object` 了。

例如：

```kotlin
class Util {
    fun doAction1() {
        println("do action1")
    }
    companion object {
        fun doAction2() {
            println("do action2")
        }
    }
}
```

不过，`doAction2()`方法其实也并不是静态方法，**`companion object` 这个关键字实际上会在 Util 类的内部创建一个伴生类**，而 `doAction2()`方法就是定义在这个伴生类里面的实例方法。只是 Kotlin 会保证 Util 类始终只会存在一个伴生类对象，因此调用 `Util.doAction2()`方法实际上就是调用了 Util 类中伴生对象的 `doAction2()`方法。

由此可以看出，Kotlin 确实没有直接定义静态方法的关键字，但是提供了一些语法特性来支持类似于静态方法调用的写法，这些语法特性基本可以满足我们平时的开发需求了。

然而如果你确确实实需要定义真正的静态方法， Kotlin 仍然提供了两种实现方式：注解和顶层方法。

**给单例类或 `companion object` 中的方法加上 `@JvmStatic` 注解，那么 Kotlin 编译器就会将这些方法编译成真正的静态方法。**

顶层方法指的是那些没有定义在任何类中的方法，Kotlin 编译器会将所有的顶层方法全部编译成静态方法，因此只要你定义了一个顶层方法，那么它就一定是静态方法。

例如：

```kotlin
// 单列类实现类似静态方法的语法
object Util{
    fun doAction(){
        println("do action.")
    }
}

class CompanionObject{
    fun doAction1(){
        println("do action1.")
    }
    companion object{
        fun doAction2(){ // 伴生类里面的实例方法
            println("do action2.")
        }

        @JvmStatic
        fun doAction3(){// 静态方法
            println("do action3.")
        }
    }
}

// 顶层方法
fun doSomething(){
    println("do something")
}

fun main() {
    Util.doAction()
    CompanionObject.doAction2()
    CompanionObject.doAction3()
    doSomething()
}
```

# 延迟初始化和密封类

## 对变量延迟初始化

延迟初始化使用的是 `lateinit` 关键字，它可以告诉 Kotlin 编译器，我会在晚些时候对这个变量进行初始化，这样就不用在一开始的时候将它赋值为 `null` 了。

当然，使用 `lateinit` 关键字也不是没有任何风险，如果我们在没有初始化的情况下就直接使用它，那么程序就一定会崩溃，并且抛出一个 `UninitializedPropertyAccessException` 异常。

我们还可以通过代码 `::variable.isInitialized` 来判断一个全局变量是否已经完成了初始化，这样在某些时候能够有效地避免重复对某一个变量进行初始化操作。

例子：

```kotlin
class A(val a:Int)

class Test{
    private lateinit var a:A
    fun init(){
        a = A(10)
    }
    fun uninit(){
        println(a.a)
    }
    fun print(){
        // 判断是否为null
        if (::a.isInitialized)
            println(a.a)
        else
            println("未初始化")
    }
}
fun main() {
    val test = Test()
    try {
        test.uninit()
    }catch (e:UninitializedPropertyAccessException){
        println("未初始化: ${e.message}")
    }
    test.print()
    test.init()
    test.print()
}
```

## 使用密封类优化代码

密封类的关键字是 `sealed class` ，密封类是一个可继承的类。密封类及其所有子类只能定义在同一个文件的顶层位置，不能嵌套在其他类中，这是被密封类底层的实现机制所限制的。

当在 `when` 语句中传入一个密封类变量作为条件时，Kotlin 编译器会自动检查该密封类有哪些子类，并强制要求你将每一个子类所对应的条件全部处理。这样就可以保证，即使没有编写 `else` 条件，也不可能会出现漏写条件分支的情况。

例子：

```kotlin
sealed class Result

class Success(val msg: String):Result()
class Failure(val error: Exception):Result()

fun getResultMsg(result: Result) = when(result){
    is Success -> result.msg
    is Failure -> "Error is ${result.error.message}"
    // 如果不使用密封类，则需要编写else条件
}

fun main() {

    val success = getResultMsg(Success("OK"))
    println(success)
    val failure = getResultMsg(Failure(Exception("Failure")))
    println(failure)
}
```

# 扩展函数和运算符重载

## 扩展函数

扩展函数表示即使在不修改某个类的源码的情况下，仍然可以打开这个类，向该类添加新的函数。

定义扩展函数的语法结构，其实非常简单，如下所示：

```kotlin
fun ClassName.methodName(param1: Int, param2: Int): Int {
    return 0
}
```

相比于定义一个普通的函数，定义扩展函数只需要在函数名的前面加上一个 `ClassName.`的语法结构，就表示将该函数添加到指定类当中了。

例如向 `String` 类中添加一个扩展函数实现统计某个字符串中的字母数量：

```kotlin
fun String.lettersCount():Int{
    var count = 0
    for (ch in this)
        if (ch.isLetter())
            count++
    return count
}
fun main() {
    val count = "ABC123xyz!@#".lettersCount()
    println(count)
}
```

扩展函数在很多情况下可以让 API 变得更加简洁、丰富，更加面向对象。

## 运算符重载

运算符重载是 Kotlin 提供的一个比较有趣的语法糖，Kotlin 允许我们将所有的运算符甚至其他的关键字进行重载，从而拓展这些运算符和关键字的用法。

运算符重载使用的是 `operator` 关键字，只要在指定函数的前面加上 `operator` 关键字，就可以实现运算符重载的功能了。

例如：

```kotlin
class Money(val value:Int){
    // Money对象相加
    operator fun plus(money: Money):Money{
        val sum = value + money.value
        return Money(sum)
    }
    // Money对象能够直接和数字相加
    operator fun  plus(newValue:Int):Money{
        val sum = value + newValue
        return Money(sum)
    }
}

fun main() {
    val money1 = Money(5)
    val money2 = Money(10)
    val money3 = money1 + money2
    println(money3.value)
    val money4 = money1 + 20
    println(money4.value)
}
```

语法糖表达式和实际调用函数对照表

| 语法糖表达式 | 实际调用函数   |
| ------------ | -------------- |
| a + b        | a.plus(b)      |
| a - b        | a.minus(b)     |
| a \* b       | a.times(b)     |
| a / b        | a.div(b)       |
| a % b        | a.rem(b)       |
| a++          | a.inc()        |
| a--          | a.dec()        |
| +a           | a.unaryPlus()  |
| -a           | a.unaryMinus() |
| !a           | a.not()        |
| a == b       | a.equals(b)    |
| a > b        | a.equals(b)    |
| a < b        | a.equals(b)    |
| a >= b       | a.equals(b)    |
| a <= b       | a.compareTo(b) |
| a..b         | a.rangeTo(b)   |
| a[b]         | a.get(b)       |
| a[b] = c     | a.set(b, c)    |
| a in b       | b.contains(a)  |

# 高阶函数详解

## 定义高阶函数

如果一个函数接收另一个函数作为参数，或者返回值的类型是另一个函数，那么该函数就称为高阶函数。

函数类型的语法规则是有点特殊的，基本规则如下：

```kotlin
(String, Int) -> Unit
```

`->` 左边的部分就是用来声明该函数接收什么参数的，多个参数之间使用逗号隔开；`->` 右边的部分用于声明该函数的返回值是什么类型，如果没有返回值就使用 `Unit` 。

将函数类型添加到某个函数的参数声明或者返回值声明上，那么这个函数就是一个高阶函数了，如下所示：

```kotlin
// 定义高阶函数
fun example(func: (String, Int) -> Unit){
    func("hello", 123)
}
fun num1AndNum2(num1: Int, num2: Int, operation: (Int, Int) -> Int): Int {
    return operation(num1, num2)
}

fun plus(num1: Int, num2: Int):Int{
    return num1 + num2
}

fun main() {
    // ::plus这是一种函数引用方式的写法，表示将 plus() 函数作为参数传递高阶函数
    var result = num1AndNum2(100, 80, ::plus)
    println(result)

    // 高阶函数配合Lambda表达式
    example(){str, n ->
        println(str)
        println(n)
    }
    // 高阶函数配合 Lambda 表达式
    result = num1AndNum2(100, 20){
        n1, n2 -> n1 - n2
    }
    println(result)
}
```

高阶函数允许让函数类型的参数来决定函数的执行逻辑。即使是同一个高阶函数，只要传入不同的函数类型参数，那么它的执行逻辑和最终的返回结果就可能是完全不同的。

使用高阶函数和扩展函数给 `StringBuilder` 类模仿实现一个类似 `apply` 函数的功能。

```kotlin
// StringBuilder. 表示这是一个扩展函数
fun StringBuilder.build(block:StringBuilder.()->Unit): StringBuilder{
    block()
    return this
}
```

在函数类型的前面加上 `ClassName.` 就表示这个函数类型是定义在哪个类当中的。这里我们给 `StringBuilder` 类定义了一个 `build` 扩展函数，这个扩展函数接收一个函数类型参数，并且返回值类型也是 `StringBuilder`。

例如：

```kotlin
fun StringBuilder.build(block:StringBuilder.()->Unit): StringBuilder{
    block()
    return this
}

fun main() {
    val list = listOf("Apple", "Banana", "Orange", "Pear", "Grape")
    val stringBuilder = StringBuilder().build {
        append("Start eating fruits.\n")
        for (fruit in list) {
            append(fruit).append("\n")
        }
        append("Ate all fruits.")
    }
    println(stringBuilder.toString())
}
```

`build` 函数的用法和 `apply` 函数基本上是一模一样的，只不过我们编写的 `build` 函数目前只能作用在 `StringBuilder` 类上面，而 `apply` 函数是可以作用在所有类上面的。

## 内联函数的作用

高阶函数的原理就是 Kotlin 强大的编译器将我们一直使用的 `Lambda` 表达式在底层被转换成了匿名类的实现方式。

下面为高阶函数反编译的代码：

```java
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

final class Kt$main$1 extends Lambda implements Function2<String, Integer, Unit> {
    public static final Kt$main$1 INSTANCE = new Kt$main$1();

    Kt$main$1() {
        super(2);
    }

    public /* bridge */ /* synthetic */ Object invoke(Object p1, Object p2) {
        invoke((String) p1, ((Number) p2).intValue());
        return Unit.INSTANCE;
    }

    public final void invoke(@NotNull String str, int n) {
        Intrinsics.checkNotNullParameter(str, "str");
        System.out.println((Object) str);
        System.out.println(n);
    }
}

final class Kt$main$2 extends Lambda implements Function2<Integer, Integer, Integer> {
    public static final Kt$main$2 INSTANCE = new Kt$main$2();

    Kt$main$2() {
        super(2);
    }

    public /* bridge */ /* synthetic */ Object invoke(Object p1, Object p2) {
        return invoke(((Number) p1).intValue(), ((Number) p2).intValue());
    }

    @NotNull
    public final Integer invoke(int n1, int n2) {
        return Integer.valueOf(n1 - n2);
    }
}

public final class example {
    public static final void example(@NotNull Function2<? super String, ? super Integer, Unit> function2) {
        Intrinsics.checkNotNullParameter(function2, "func");
        function2.invoke("hello", 123);
    }

    public static final int num1AndNum2(int num1, int num2, @NotNull Function2<? super Integer, ? super Integer, Integer> function2) {
        Intrinsics.checkNotNullParameter(function2, "operation");
        return ((Number) function2.invoke(Integer.valueOf(num1), Integer.valueOf(num2))).intValue();
    }

    public static final void main() {
        example(Kt$main$1.INSTANCE);
        int result = num1AndNum2(100, 20, Kt$main$2.INSTANCE);
        System.out.println(result);
    }
}
```

这就表明，我们每调用一次 `Lambda` 表达式，都会创建一个新的匿名类实例，当然也会造成额外的内存和性能开销。为了解决这个问题，Kotlin 提供了内联函数的功能，它可以将使用 `Lambda` 表达式带来的运行时开销完全消除。

内联函数的用法非常简单，只需要在定义高阶函数时加上 `inline` 关键字的声明即可，如下所示：

```kotlin

inline fun num1AndNum2(num1: Int, num2: Int, operation: (Int, Int) -> Int): Int {
    return operation(num1, num2)
}

fun main() {

    var result = num1AndNum2(100, 20){
        n1, n2 -> n1 - n2
    }
    println(result)
}
```

使用内联函数后对应的反编译代码如下所示：

```java
public final class example {

    public static final int num1AndNum2(int num1, int num2, @NotNull Function2<? super Integer, ? super Integer, Integer> function2) {
        Intrinsics.checkNotNullParameter(function2, "operation");
        return ((Number) function2.invoke(Integer.valueOf(num1), Integer.valueOf(num2))).intValue();
    }

    public static final void main() {
        int result = 100 - 20;
        System.out.println(result);
    }
}
```

可以发现内联函数完全消除 `Lambda` 表达式所带来的运行时开销。

## noinline 与 crossinline

一个高阶函数中如果接收了两个或者更多函数类型的参数，这时我们给函数加上了 `inline` 关键字，那么 Kotlin 编译器会自动将所有引用的 `Lambda` 表达式全部进行内联。

如果我们只想内联其中的一个 `Lambda` 表达式，这时就可以使用 `noinline` 关键字了，如下所示：

```kotlin
inline fun inlineTest(block1: () -> Unit, noinline block2: () -> Unit) {
}
```

内联的函数类型参数在编译的时候会被进行代码替换，因此它没有真正的参数属性。非内联的函数类型参数可以自由地传递给其他任何函数，因为它就是一个真实的参数，而内联的函数类型参数只允许传递给另外一个内联函数，这也是它最大的局限性。

内联函数和非内联函数还有一个重要的区别，那就是内联函数所引用的 `Lambda` 表达式中是可以使用 `return` 关键字来进行函数返回的，而非内联函数只能进行局部返回。

例子：

```kotlin
fun printString(str: String, block: (String) -> Unit){
    println("printString begin")
    block(str)
    println("printString end")
}
inline fun printStr(str: String, block: (String) -> Unit){
    println("printStr begin")
    block(str)
    println("printStr end")
}

fun main() {

    println("main start")
    val str = ""
    printString(str){ s->
       println("lambda start")
        // Lambda 表达式中是不允许直接使用 return 关键字
        // return@printString 进行局部返回，并且不再执行 Lambda 表达式的剩余部分代码。
        if (s.isEmpty()) return@printString
        println(s)
        println("lambda end")
    }
    println("main end")

    println("main start")
    printStr(str){ s->
        println("lambda start")
        // 内联高级函数，可以在 Lambda 表达式中使用 return 关键字
        // 此时的 return 代表的是返回外层的调用函数
        if (s.isEmpty()) return
        println(s)
        println("lambda end")
    }
    println("main end")
}
```

将高阶函数声明成内联函数是一种良好的编程习惯，事实上，绝大多数高阶函数是可以直接声明成内联函数的，但是也有少部分例外的情况。如果我们在高阶函数中创建了另外的 `Lambda` 或者匿名类的实现，并且在这些实现中调用函数类型参数，此时再将高阶函数声明成内联函数，就一定会提示错误。此时可以借助 `crossinline` 关键字就可以很好地解决这个问题，例如：

```kotlin
fun runRunnable1(block: () -> Unit){
    val runnable = Runnable{
        block()
    }
    runnable.run()
}

inline fun runRunnable2(crossinline block: () -> Unit) {
    val runnable = Runnable {
        block()
    }
    runnable.run()
}
fun main() {
    runRunnable1(){
        println("runRunnable1")
    }

    runRunnable2(){
        println("runRunnable2")
    }
}
```

因为内联函数的 `Lambda` 表达式中允许使用 `return` 关键字，和高阶函数的匿名类实现中不允许使用 `return` 关键字之间造成了冲突。而 `crossinline` 关键字就像一个契约，它用于保证在内联函数的 `Lambda` 表达式中一定不会使用 `return` 关键字，这样冲突就不存在了，问题也就巧妙地解决了。

声明了 `crossinline` 之后，我们就无法在调用 runRunnable 函数时的 `Lambda` 表达式中使用 `return` 关键字进行函数返回了，但是仍然可以使用 `return@runRunnable` 的写法进行局部返回。总体来说，除了在 `return` 关键字的使用上有所区别之外，`crossinline` 保留了内联函数的其他所有特性。

# 高阶函数的应用

## 简化 SharedPreferences 的用法

```kotlin
fun SharedPreferences.open(block: SharedPreferences.Editor.() -> Unit) {
    val editor = edit()
    editor.block()
    editor.apply()
}

getSharedPreferences("data", Context.MODE_PRIVATE).open {
    putString("name", "Tom")
    putInt("age", 28)
    putBoolean("married", false)
}
```

## 简化 ContentValues 的用法

```kotlin
// vararg对应的就是Java中的可变参数列表
fun cvOf(vararg pairs: Pair<String, Any?>) = ContentValues().apply {
    for (pair in pairs) {
        val key = pair.first
        val value = pair.second
        when (value) {
            is Int -> put(key, value)
            is Long -> put(key, value)
            is Short -> put(key, value)
            is Float -> put(key, value)
            is Double -> put(key, value)
            is Boolean -> put(key, value)
            is String -> put(key, value)
            is Byte -> put(key, value)
            is ByteArray -> put(key, value)
            null -> putNull(key)
        }
    }
}

val values = cvOf("name" to "Game of Thrones", "author" to "George Martin", "pages" to 720, "price" to 20.85)
db.insert("Book", null, values)
```

# 泛型和委托

## 泛型的基本用法

在一般的编程模式下，我们需要给任何一个变量指定一个具体的类型，而泛型允许我们在不指定具体类型的情况下进行编程，这样编写出来的代码将会拥有更好的扩展性。

泛型主要有两种定义方式：一种是定义泛型类，另一种是定义泛型方法，使用的语法结构都是 `<T>`。

例如：

```kotlin
// 泛型类
class MyClass<T> {
    fun method(param: T): T {
        return param
    }
}

// 泛型方法
class MyClass {
    fun <T> method(param: T): T {
        return param
    }
}
```

在默认情况下，所有的泛型都是可以指定成可空类型的，这是因为在不手动指定上界的时候，泛型的上界默认是 `Any?`。而如果想要让泛型的类型不可为空，只需要将泛型的上界手动指定成 `Any` 就可以了。

`build` 函数进行扩展，让它实现和 `apply` 函数完全一样的功能。

```kotlin
// 利用泛型和高阶函数实现 apply 功能
fun <T> T.build(block: T.() -> Unit):T{
    block()
    return this
}

fun main() {
    val ret = StringBuilder().build {
        append("Hello World")
    }
    println(ret.toString())
}
```

## 类委托和委托属性

委托是一种设计模式，它的基本理念是：操作对象自己不会去处理某段逻辑，而是会把工作委托给另外一个辅助对象去处理。

Kotlin 中也是支持委托功能的，并且将委托功能分为了两种：类委托和委托属性。

类委托的核心思想是将一个类的具体实现委托给另一个类去完成。

Kotlin 中委托使用的关键字是 `by`，我们只需要在接口声明的后面使用 `by` 关键字，再接上受委托的辅助对象，就可以免去之前所写的一大堆模板式的代码了，如下所示：

```kotlin
class MySet<T>(val helperSet: HashSet<T>):Set<T>{
    // 委托模式调用了辅助对象中相应的方法实现。
    override val size: Int
        get() = helperSet.size
    override fun contains(element: T) = helperSet.contains(element)
    override fun containsAll(elements: Collection<T>) = helperSet.containsAll(elements)
    override fun isEmpty() = helperSet.isEmpty()
    override fun iterator() = helperSet.iterator()
}

// 使用 by 关键字，再接上受委托的辅助对象，就可以免去之前所写的一大堆模板式的代码了
class MySet1<T>(val helperSet: HashSet<T>):Set<T> by helperSet{

    // 只有需要重写的方法才需要实现
    override fun isEmpty() = false
    // 新增方法
    fun hello() = println("hello")

}
```

委托属性的核心思想是将一个属性（字段）的具体实现委托给另一个类去完成。

例如：

```kotlin
import kotlin.reflect.KProperty;

class MyClass{
    var p by Delegate()
}

class Delegate{
    var propValue:Any? = null
    // KProperty<*> 是Kotlin中的一个属性操作类，可用于获取各种属性相关的值
    // <*> 这种泛型的写法表示你不知道或者不关心泛型的具体类型，只是为了通过语法编译而已
    operator fun getValue(myClass: MyClass, property: KProperty<*>): Any? {
        println("getValue $propValue")
        return propValue
    }
    operator fun setValue(myClass: MyClass, property: KProperty<*>, value:Any?){
        println("setValue $value")
        propValue = value
    }
}
fun main() {
    val mycls = MyClass()
    mycls.p = 10;
    println(mycls.p)
}
```

整个委托属性的工作流程就是这样实现的，现在当我们给 `MyClass` 的 `p` 属性赋值时，就会调用 `Delegate` 类的 `setValue()`方法，当获取 `MyClass` 中 `p` 属性的值时，就会调 `Delegate` 类的 `getValue()`方法。

`by lazy` 代码块是 Kotlin 提供的一种懒加载技术，代码块中的代码一开始并不会执行，只有当变量首次被调用的时候才会执行，并且会将代码块中最后一行代码的返回值赋给变量。

例如：

```kotlin
    private val uriMatcher by lazy {
        // 只有当 uriMatcher 变量首次被调用的时候才会执行，并且会将代码块中最后一行代码的返回值赋给 uriMatcher。
        val matcher = UriMatcher(UriMatcher.NO_MATCH)
        matcher.addURI(authority, "book", bookDir)
        matcher.addURI(authority, "book/#", bookItem)
        matcher.addURI(authority, "category", categoryDir)
        matcher.addURI(authority, "category/#", categoryItem)
        matcher // 返回值赋值给变量
    }
```

## 实现一个自己的 lazy 函数

`by lazy` 并不是连在一起的关键字，只有 `by` 才是 Kotlin 中的关键字，`lazy` 在这里只是一个高阶函数而已。

下面实现一个自己的 `lazy` 函数。

```kotlin
class Later<T>(val block: () -> T){
    var value:Any? = null
    operator fun getValue(any: Any?, prop:KProperty<*>) :T {
        if (value == null){
            value = block()
        }
        return value as T
    }
}

// 高阶函数
fun <T> later(block: () -> T) = Later(block)

fun main() {
    // 将p属性的具体实现委托给了later函数去完成
    val p by later {
        println("start later")
        "test later"
    }
    // 使用 p 的时候，才会调用
    println(p)
}
```

# 使用 infix 函数构建更可读的语法

`infix` 函数由于其语法糖格式的特殊性，有两个比较严格的限制：

- `infix` 函数是不能定义成顶层函数的，它必须是某个类的成员函数，可以使用扩展函数的方式将它定义到某个类当中；
- `infix` 函数必须接收且只能接收一个参数，至于参数类型是没有限制的。

例子：

```kotlin
infix fun String.beginWith(prefix: String) = startsWith(prefix)

infix fun <T> Collection<T>.has(element: T) = contains(element)

infix fun <A, B> A.with(that:B):Pair<A, B> = Pair(this, that)

fun main() {

    if ("HelloWorld" beginWith "Hello")
        println("HelloWorld")
    val list = listOf("Apple", "Banana", "Orange", "Pear", "Grape")
    if (list has "Banana")
        println("Banana")
    val map = mapOf("Apple" with 1, "Banana" with 2, "Orange" with 3, "Pear" with 4,
        "Grape" with 5)
    println(map)
}
```

# 泛型的高级特性

## 对泛型进行实化

泛型实化功能允许我们在泛型函数当中获得泛型的实际类型，这也就使得类似于 `a is T`、`T::class.java` 这样的语法成为了可能。

首先，该函数必须是内联函数才行，也就是要用 `inline` 关键字来修饰该函数。其次，在声明泛型的地方必须加上 `reified` 关键字来表示该泛型要进行实化。示例代码如下：

```kotlin
inline fun <reified T> getGenericType() {
}
```

在 Kotlin 中，借助泛型实化功能就可以使用 `T::class.java` 这样的语法了。

```kotlin
// 借助泛型实化功能就可以使用 T::class.java 这样的语法，这样就可以获得 T 类型
inline fun <reified T> getGenericType() = T::class.java

fun main() {
    println(getGenericType<String>()) // java.lang.String
    println(getGenericType<Int>())    // java.lang.Integer
}
```

## 泛型实化的应用

泛型实化和高阶函数简化启动 Activity。

```kotlin
inline fun <reified T> startActivity(context: Context, block: Intent.() -> Unit){
    val intent = Intent(context, T::class.java)
    intent.block()
    context.startActivity(intent)
}
fun main() {
    startActivity<TestActivity>(context) {
        putExtra("param1", "data")
        putExtra("param2", 123)
    }
}
```

## 泛型的协变

一个泛型类或者泛型接口中的方法，它的参数列表是接收数据的地方，因此可以称它为 `in` 位置，而它的返回值是输出数据的地方，因此可以称它为 `out` 位置。

假如定义了一个 `MyClass<T>` 的泛型类，其中 `A` 是 `B` 的子类型，同时 `MyClass<A>` 又是 `MyClass<B>` 的子类型，那么我们就可以称 `MyClass` 在 `T` 这个泛型上是协变的。

如果一个泛型类在其泛型类型的数据上是只读的话，那么它是没有类型转换安全隐患的。而要实现这一点，则需要让 `MyClass<T>` 类中的所有方法都不能接收 `T` 类型的参数。这样才能让 `MyClass<A>` 成为 `MyClass<B>` 的子类型。换句话说，`T` 只能出现在 `out` 位置上，而不能出现在 `in` 位置上。

在 Kotlin 中已经默认给许多内置的 API 加上了协变声明，其中就包括了各种集合的类与接口。

在泛型 `E` 的前面又加上了一个 `@UnsafeVariance` 注解，这样编译器就会允许泛型 `E` 出现在 `in` 位置上了。

例子：

```kotlin
// 在泛型 T 的声明前面加上了一个 out 关键字，这就意味着现在 T 只能出现在 out 位置上
class SimpleData<out T>(val data: T){ // 使用 val 关键字保证T仍然是只读的，也可以加上 private 修饰符
    fun get():T?{
        return data
    }
}

// SimpleData<Student> 是 SimpleData<Person> 的子类
fun handleMyData(data: SimpleData<Person>) {
    val personData = data.get()
}


// List简化版的源码
// List在泛型E的前面加上了out关键字，说明List在泛型E上是协变的。
public interface List<out E> : Collection<E> {
    override val size: Int
    override fun isEmpty(): Boolean
    // @UnsafeVariance注解，向编译器说明并不会修改当前集合中的内容，滥用这个功能，导致运行时出现了类型转换异常
    override fun contains(element: @UnsafeVariance E): Boolean
    override fun iterator(): Iterator<E>
    public operator fun get(index: Int): E
}

fun main() {
    val student = Student()
    val data = SimpleData<Student>(student)
    handleMyData(data)
    val studentData = data.get()
}
```

## 泛型的逆变

假如定义了一个 `MyClass<T>`的泛型类，其中 `A` 是 `B` 的子类型，同时 `MyClass<B>`又是 `MyClass<A>`的子类型，那么我们就可以称 `MyClass` 在 `T` 这个泛型上是逆变的。

例子：

```kotlin
// 在泛型T的声明前面加上了一个in关键字，这就意味着现在T只能出现在in位置上
interface Transformer<in T>{
    fun transform(t: T):String
}

fun main() {
    val trans = object :Transformer<Person>{
        override fun transform(t: Person): String {
            return "${t.name} ${t.age}"
        }
    }
    handleTransformer(trans)
}

fun handleTransformer(trans: Transformer<Student>) {
    val student = Student()
    student.name = "Tom"
    student.age = 19
    val result = trans.transform(student)
    println(result)
}
```

Kotlin 在提供协变和逆变功能时，就已经把各种潜在的类型转换安全隐患全部考虑进去了。只要我们严格按照其语法规则，让泛型在协变时只出现在 out 位置上，逆变时只出现在 in 位置上，就不会存在类型转换异常的情况。虽然 `@UnsafeVariance` 注解可以打破这一语法规则，但同时也会带来额外的风险，所以你在使用 `@UnsafeVariance` 注解时，必须很清楚自己在干什么才行。

在 Kotlin 内置 API 中的应用，比较典型的例子就是 `Comparable` 的使用。`Comparable` 是一个用于比较两个对象大小的接口，其源码定义如下：

```kotlin
interface Comparable<in T> {
    operator fun compareTo(other: T): Int
}
```

# 使用协程编写高效的并发程序

协程和线程是有点类似的，可以简单地将它理解成一种轻量级的线程。使用协程却可以仅在编程语言的层面就能实现不同协程之间的切换，从而大大提升了并发编程的运行效率。

## 协程的基本用法

Kotlin 并没有将协程纳入标准库的 API 当中，而是以依赖库的形式提供的。所以如果我们想要使用协程功能，需要先在 `app/build.gradle` 文件当中添加如下依赖库：

```bash
dependencies {
    ...
    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-core:1.1.1"
    // Android 中才会用到下面的库
    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.1.1"
}
```

`Global.launch` 函数每次创建的都是一个顶层协程，这种协程当应用程序运行结束时也会跟着一起结束。

```kotlin
import kotlinx.coroutines.*

fun main() {
    // Global.launch 函数每次创建的都是一个顶层协程，这种协程当应用程序运行结束时也会跟着一起结束。
    GlobalScope.launch {
        println("codes run in coroutine scope")
        delay(1500)
        // 下面语句将不会执行
        println("codes run in coroutine scope finished")
    }
    // 让主线程阻塞1秒钟
    Thread.sleep(1000)
}
```

`delay()` 函数是一个非阻塞式的挂起函数，它只会挂起当前协程，并不会影响其他协程的运行。而 `Thread.sleep()` 方法会阻塞当前的线程，这样运行在该线程下的所有协程都会被阻塞。

`runBlocking` 函数同样会创建一个协程的作用域，但是它可以保证在协程作用域内的所有代码和子协程没有全部执行完之前一直阻塞当前线程。需要注意的是，`runBlocking` 函数通常只应该在测试环境下使用，在正式环境中使用容易产生一些性能上的问题。

```kotlin
fun main() {
    runBlocking {
        println("codes run in coroutine scope")
        delay(1500)
        println("codes run in coroutine scope finished")
    }
    println("codes run in main thread")
}
```

运行结果：

```bash
codes run in coroutine scope
codes run in coroutine scope finished
codes run in main thread
```

`launch` 函数和 `GlobalScope.launch` 函数不同。首先它必须在协程的作用域中才能调用，其次它会在当前协程的作用域下创建子协程。子协程的特点是如果外层作用域的协程结束了，该作用域下的所有子协程也会一同结束。

```kotlin
fun main() {
    runBlocking {
        // launch 必须在协程的作用域中才能调用，它会在当前协程的作用域下创建子协程。
        launch {
            println("launch1")
            delay(1000)
            println("launch1 finished")
        }
        launch {
            println("launch2")
            delay(1000)
            println("launch2 finished")
        }
    }
}
```

输入结果：

```bash
launch1
launch2
launch1 finished
launch2 finished
```

协程由编程语言来决定如何在多个协程之间进行调度，让谁运行，让谁挂起。调度的过程完全不需要操作系统参与，这也就使得协程的并发效率会出奇得高。下面创建了 10 万个协程的示例：

```kotlin
fun main() {
    val start = System.currentTimeMillis()
    runBlocking {
        // 循环创建了10万个协程
        repeat(100000){
            launch {
                println(".")
            }
        }
    }
    val end = System.currentTimeMillis()
    println(end - start)
}
```

我们在 `launch` 函数中编写的代码是拥有协程作用域的，但是提取到一个单独的函数中就没有协程作用域了。

Kotlin 提供了一个 `suspend` 关键字，使用它可以将任意函数声明成挂起函数，而挂起函数之间都是可以互相调用的，如下所示：

```kotlin
suspend fun printDot() {
    println(".")
    delay(1000)
}
```

`suspend` 关键字只能将一个函数声明成挂起函数，是无法给它提供协程作用域的。

可以借助 `coroutineScope` 函数来解决 `suspend` 关键字只能将一个函数声明成挂起函数，无法给它提供协程作用域的问题，**`coroutineScope` 函数也是一个挂起函数，因此可以在任何其他挂起函数中调用。它的特点是会继承外部的协程的作用域并创建一个子协程，借助这个特性，我们就可以给任意挂起函数提供协程作用域了。**示例写法如下：

```kotlin
suspend fun printDot() = coroutineScope {
    // launch函数要求必须在协程作用域当中才能调用。
    launch {
        println(".")
        delay(1000)
    }
}
```

另外，`coroutineScope` 函数和 `runBlocking` 函数还有点类似，它可以保证其作用域内的所有代码和子协程在全部执行完之前，外部的协程会一直被挂起。

```kotlin
fun main() {
    runBlocking {
        launch { // 启动第一个子协程
            coroutineScope {
                println("coroutineScope start.")
                delay(1000) // 延迟 1000毫秒

            }
            println("coroutineScope finished.")
        }
        launch { // 启动第二个子协程
            println("Coroutine 2 starts.")
            delay(500) // 延迟 500 毫秒
            println("Coroutine 2 ends.")
        }
    }
    println("runBlocking finished")
}
```

运行输出：

```bash
coroutineScope start.
Coroutine 2 starts.
Coroutine 2 ends.
coroutineScope finished.
runBlocking finished
```

`coroutineScope` 函数只会阻塞当前协程，既不影响其他协程，也不影响任何线程，因此是不会造成任何性能上的问题的。而 `runBlocking` 函数由于会挂起外部线程，如果你恰好又在主线程中当中调用它的话，那么就有可能会导致界面卡死的情况，所以不太推荐在实际项目中使用。

## 更多的作用域构建器

不管是 `GlobalScope.launch` 函数还是 `launch` 函数，它们都会返回一个 `Job` 对象，只需要调用 `Job` 对象的 `cancel()` 方法就可以取消协程了，如下所示：

```kotlin
val job = GlobalScope.launch {
    // 处理具体的逻辑
}
job.cancel()
```

实际项目中比较常用的写法：

```kotlin
val job = Job()
val scope = CoroutineScope(job)
// 可以随时调用它的launch函数来创建一个协程
scope.launch {
    // 处理具体的逻辑
}
job.cancel()
```

现在所有调用 `CoroutineScope` 的 `launch` 函数所创建的协程，都会被关联在 `Job` 对象的作用域下面。这样只需要调用一次 `cancel()` 方法，就可以将同一作用域内的所有协程全部取消，从而大大降低了协程管理的成本。

调用 `launch` 函数可以创建一个新的协程，但是 `launch` 函数只能用于执行一段逻辑，却不能获取执行的结果，因为它的返回值永远是一个 `Job` 对象。**使用 `async` 函数就可以实现创建一个协程并获取它的执行结果。**

`async` 函数必须在协程作用域当中才能调用，它会创建一个新的子协程并返回一个 `Deferred` 对象，如果我们想要获取 `async` 函数代码块的执行结果，只需要调用 `Deferred` 对象的 `await()` 方法即可，代码如下所示：

```kotlin
fun main() {
    runBlocking {
        val result = async {
            5 + 5
        }.await()
        println(result)
    }
}
```

在调用了 `async` 函数之后，代码块中的代码就会立刻开始执行。当调用 `await()` 方法时，如果代码块中的代码还没执行完，那么 `await()` 方法会将当前协程阻塞住，直到可以获得 `async` 函数的执行结果。

```kotlin
fun main() {
    runBlocking {
        val start = System.currentTimeMillis()
        val result1 = async {
            delay(1000)
            5+5
        }.await()
        val result2 = async {
            delay(1000)
            4 + 6
        }.await()
        println("分别执行await: ${result1 + result2}.")
        val end = System.currentTimeMillis()
        println("分别执行await耗时: ${end - start} ms.")
    }
    runBlocking {
        val start = System.currentTimeMillis()
        val result1 = async {
            delay(1000)
            5+5
        }
        val result2 = async {
            delay(1000)
            4 + 6
        }
        println("同时执行await ${result1.await() + result2.await()}.")
        val end = System.currentTimeMillis()
        println("同时执行await耗时 ${end - start} ms.")
    }
}
```

`await()` 方法在 `async` 函数代码块中的代码执行完之前会一直将当前协程阻塞住，我们不在每次调用 `async` 函数之后就立刻使用 `await()` 方法获取结果了，而是仅在需要用到 `async` 函数的执行结果时才调用 `await()` 方法进行获取，这样两个 `async` 函数就变成一种并行关系了。

`withContext()` 函数是一个挂起函数，大体可以将它理解成 `async` 函数的一种简化版写法，示例写法如下：

```kotlin
fun main() {
    runBlocking {
        val result = withContext(Dispatchers.Default) {
            5 + 5
        }
        println(result)
    }
}
```

调用 `withContext()` 函数之后，会立即执行代码块中的代码，同时将外部协程挂起。当代码块中的代码全部执行完之后，会将最后一行的执行结果作为 `withContext()` 函数的返回值返回。

`withContext()` 函数强制要求我们指定一个线程参数，线程参数主要有以下 3 种值可选：`Dispatchers.Default`、`Dispatchers.IO` 和 `Dispatchers.Main`。

- `Dispatchers.Default` 表示会使用一种默认低并发的线程策略，适合计算密集型任务。
- `Dispatchers.IO` 表示会使用一种较高并发的线程策略，适合执行大多数时间是在阻塞和等待中的任务。
- `Dispatchers.Main` 则表示不会开启子线程，而是在 Android 主线程中执行代码，仅适用于 Android。

除了 `coroutineScope` 函数之外，其他所有的函数都是可以指定这样一个线程参数的。

## 使用协程简化回调的写法

借助 `suspendCoroutine` 函数就能将传统回调机制的写法大幅简化，`suspendCoroutine` 函数必须在协程作用域或挂起函数中才能调用，它接收一个 Lambda 表达式参数，主要作用是将当前协程立即挂起，然后在一个普通的线程中执行 Lambda 表达式中的代码。Lambda 表达式的参数列表上会传入一个 `Continuation` 参数，调用它的 `resume()` 方法或 `resumeWithException()` 可以让协程恢复执行。

```kotlin
// request()函数是一个挂起函数
suspend fun request(address: String): String {
    // 执行 suspendCoroutine 函数当前协程就会被立刻挂起
    return suspendCoroutine { continuation ->
    // Lambda表达式中的代码则会在普通线程中执行
    HttpUtil.sendHttpRequest(address, object : HttpCallbackListener {
            override fun onFinish(response: String) {
                // resume()方法恢复被挂起的协程
                continuation.resume(response)
            }
            override fun onError(e: Exception) {
                // resumeWithException()恢复被挂起的协程，并传入具体的异常原因
                continuation.resumeWithException(e)
            }
        })
    }
}
```

# 编写好用的工具方法

## 求 N 个数的最大最小值

Java 中规定，所有类型的数字都是可比较的，因此必须实现 Comparable 接口，这个规则在 Kotlin 中也同样成立。那么我们就可以借助泛型，将 max()函数修改成接收任意多个实现 Comparable 接口的参数，代码如下所示：

```kotlin
// 这里将泛型T的上界指定成了Comparable<T>，那么参数T就必然是Comparable<T>的子类型了。
fun <T: Comparable<T>> max(vararg nums: T): T {
    if (nums.isEmpty()) throw RuntimeException("Params can not be empty.")
        var maxNum = nums[0]
        for (num in nums) {
            if (num > maxNum) {
                maxNum = num
        }
    }
    return maxNum
}
```

## 简化 Toast 的用法

```kotlin
fun String.showToast(context: Context, duration: Int = Toast.LENGTH_SHORT) {
    Toast.makeText(context, this, duration).show()
}
fun Int.showToast(context: Context, duration: Int = Toast.LENGTH_SHORT) {
    Toast.makeText(context, this, duration).show()
}
"This is Toast".showToast(context)
R.string.app_name.showToast(context)
```

## 简化 Snackbar 的用法

```kotlin
fun View.showSnackbar(text: String, actionText: String? = null,
    duration: Int = Snackbar.LENGTH_SHORT, block: (() -> Unit)? = null) {
    val snackbar = Snackbar.make(this, text, duration)
    if (actionText != null && block != null) {
        snackbar.setAction(actionText) {
            block()
        }
    }
    snackbar.show()
}
fun View.showSnackbar(resId: Int, actionResId: Int? = null,
    duration: Int = Snackbar.LENGTH_SHORT, block: (() -> Unit)? = null) {
    val snackbar = Snackbar.make(this, resId, duration)
    if (actionResId != null && block != null) {
        snackbar.setAction(actionResId) {
            block()
        }
    }
    snackbar.show()
}

view.showSnackbar("This is Snackbar", "Action") {
    // 处理具体的逻辑
}
```

# 使用 DSL 构建专有的语法结构

DSL 的全称是领域特定语言（Domain Specific Language），它是编程语言赋予开发者的一种特殊能力，通过它我们可以编写出一些看似脱离其原始语法结构的代码，从而构建出一种专有的语法结构。

Gradle 是一种基于 Groovy 语言的构建工具，因此上述的语法结构其实就是 Groovy 提供的 DSL 功能。借助 Kotlin 的 DSL，我们也可以实现类似的语法结构，如下所示：

```kotlin
class Dependency{
    // 保存所有的依赖库
    val libraries = ArrayList<String>()
    fun implementation(lib: String){
        libraries.add(lib)
    }
}

// 定义一个dependencies高阶函数，接收一个Dependency类的成员函数
fun dependencies(bolck:Dependency.()->Unit):List<String>{
    val dependency = Dependency()
    // 首先创建一个Dependency的实例，然后再通过该实例调用函数类型参数
    dependency.bolck()
    return dependency.libraries
}

fun main() {
    // 使用DSL语法结构添加依赖库
    val libraries = dependencies {
        implementation("com.squareup.retrofit2:retrofit:2.6.1")
        implementation("com.squareup.retrofit2:converter-gson:2.6.1")
    }
    for (lib in libraries) {
        println(lib)
    }
}
```

在实现了一个较为简单的 DSL 之后，接下来我们再尝试编写一个复杂一点的 DSL。

```kotlin
class Td {
    // 存储单元格中显示的内容
    var content = ""
    // 返回一段<td>标签的HTML代码
    fun html() = "\n\t\t<td>$content</td>"
}

class Tr {
    // 存储当前Tr所包含的Td对象
    private val children = ArrayList<Td>()
    fun td(block: Td.() -> String) {
        val td = Td()
        td.content = td.block()
        children.add(td)
    }

    fun html(): String {
        val builder = StringBuilder()
        builder.append("\n\t<tr>")
        for (childTag in children)
            builder.append(childTag.html())
        return builder.toString()
    }
}

class Table {
    // 存储当前Table所包含的Tr对象
    private val children = ArrayList<Tr>()
    fun tr(block: Tr.() -> Unit) {
        val tr = Tr()
        tr.block()
        children.add(tr)
    }

    fun html(): String {
        val builder = StringBuilder()
        builder.append("<table>")
        for (childTag in children) {
            builder.append(childTag.html())
        }
        builder.append("\n</table>")
        return builder.toString()
    }
}

// 使用高阶函数对语法结构进行精简
fun table(block: Table.() -> Unit): String {
    val table = Table()
    table.block()
    return table.html()
}

fun main() {

    // 不使用高阶函数的用法
    val table = Table()
    table.tr {
        td { "Apple" }
        td { "Grape" }
        td { "Orange" }
    }
    table.tr {
        td { "Pear" }
        td { "Banana" }
        td { "Watermelon" }
    }
    println(table.html())
    // 使用高阶函数的用法
    val html = table {
        tr {
            td { "Apple" }
            td { "Grape" }
            td { "Orange" }
        }
        tr {
            td { "Pear" }
            td { "Banana" }
            td { "Watermelon" }
        }
    }
    println(html)
}
```
