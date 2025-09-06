# CSS 选择器

## 基本标签选择器

针对一类标签，例如：

```css
p {
  font-size: 14px;
}

<p>标签选择器，当前标签内容为14号字体。</p>
```

上面的选择器针对所有的 `p` 标签里的内容都将显示 14 号字体。

### ID 选择器

针对某一个特定的标签使用，只能使用一次，CSS 中以 `#` 来定义。例如：

```css
#mytitle{
    border:3px dashed green;
}

<h2 id="mytitle">当前标题的内容在一个绿色的矩形方框，方框为虚线。</h2>
```

### class 选择器

针对你想要的所有标签使用，使用原点 `.` 来定义。例如：

```css
.box{
    width: 100px;
    height: 100px;
    border: 1px solid red;
    padding: 20px;
    margin: 30px;
}

<div class="box1">类选择器</div>
```

- 类选择器可以被多种标签使用。
- 同一个标签可以使用多个类选择器，使用空格隔开。

### 通用选择器：

通用选择器，将匹配任何标签，使用 `*` 定义。例如：

```css
* {
  margin-left: 0px;
  margin-top: 0px;
}
```

上面选择器针对所有的标签，不推荐使用。

## 高级选择器

### 后代选择器

对于 `E F {}` 这种格式，表示所有属于 E 元素后代的 F 元素，有这个样式。

这两个标签不一定是连续紧挨着的，只要保持一个后代的关联即可。例如：

```css
.box1{
    width: 100px;
    height: 100px;
    border: 1px solid red;
    padding: 20px;
    margin: 30px;
}
.box1 p{
    color: red;
}

h3 b i{
    color: blue;
}

h3 .box1{
    border: yellow 3px solid;
}

<div class="box1"><p>这是box1的后代。</p></div>
<h3>后代使用class选择器<div class="box1">class后代选择器</div></h3>
<h3><b>后台选择器不一定是连续的<i>只需要保持一个后代的关系即可</i></b></h3>
<h3>多个后代选择器<b>强调<div class="box1">这是.box1代选择器<i>这是i后代选择器</i></div></b></h3>
```

### 交集选择器

定义交集选择器的时候，两个选择器之前使用 `.`紧密相连，一般以标签名开头。

```css
h3.special{
    color:red;
}

<h3 class="special">交集选择器</3>
```

### 并集选择器

定义的时候用逗号隔开，例如：

```css
p, h1, .title1, #one{
    color:red;
}


<p>p标签选择器并集</p>
<h1>h1标签选择器并集</h1>
<div class="title1">class选择器并集</div>
<div id="one">id 选择器并集</div>
```

## CSS3 选择器

### 子代选择器

用符号 `>` 表示，例如：

```css
div > p {
  color: red;
}
<div>
    <p>可以选择我是div的儿子</p>
</div>

<div>
    <ul>
        <li>
            <p>不能选择我是div的重孙子</p>
        </li>
    </ul>
</div>
```

`div` 的儿子 `p`。和 `div` 的后代 `p` 的截然不同。

### 序选择器

设置无序列表 `<ul>` 中的第一个 `<li>` 为红色：

```css
ul li:first-child {
  color: red;
}
```

设置无序列表 `<ul>` 中的最后一个 `<li>` 为红色：

```css
ul li:last-child {
  color: blue;
}
```

### 下一个兄弟选择器

`+` 表示选择下一个兄弟，例如：

```css
h3 + p {
    color: red;
}

<h3>我是一个标题</h3>
<p>选择紧挨着的第一个兄弟我是一个段落</p>
<p>我是一个段落</p>
<p>我是一个段落</p>
```

## 伪类选择器

同一个标签，根据其不同的种状态，有不同的样式，这就叫做“伪类”。伪类用冒号来表示。

### 静态伪类

只能用于超链接的样式。如下：

- `:link` 超链接点击之前。
- `:visited` 链接被访问过之后。

### 动态伪类

针对所有标签都适用的样式。如下：

- `:hover` “悬停”：鼠标放到标签上的时候
- `:active` “激活”： 鼠标点击标签，但是不松手时。
- `:focus` 是某个标签获得焦点时的样式（比如某个输入框获得焦点）

### 超链接 a 标签

超链接 `a` 标有 4 种伪类，如下：

- `:link` “链接”：超链接点击之前
- `:visited` “访问过的”：链接被访问过之后
- `:hover` “悬停”：鼠标放到标签上的时候
- `:active` “激活”： 鼠标点击标签，但是不松手时。

```css
/*让超链接点击之前是红色*/
a:link {
  color: red;
}

/*让超链接点击之后是绿色*/
a:visited {
  color: orange;
}

/*鼠标悬停，放到标签上的时候*/
a:hover {
  color: green;
}

/*鼠标点击链接，但是不松手的时候*/
a:active {
  color: black;
}
```

在 CSS 中，这四种状态必须按照上面固定的顺序写。

`a{}` 和 `a:link{}` 的区别：

- `a{}` 定义的样式针对所有的超链接(包括锚点)
- `a:link{}` 定义的样式针对所有写了 `href` 属性的超链接(不包括锚点)

伪类选择器例子：

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>导航栏</title>
    <style>
        * {
            margin: 0;
            padding: 0;
        }

        .nav {
            width: 960px;
            height: 50px;
            border: 1px solid red;
            margin: 100px auto;
        }

        .nav ul {
            /* 去掉默认的列表样式 */
            list-style: none;
        }

        .nav ul li {
            float: left;
            width: 120px;
            height: 50px;
            /* 让内容水平居中 */
            text-align: center;
            /* 让行高等于 nav 的高度，就可以保证内容垂直居中*/
            line-height: 50px;
        }

        .nav ul li a {
            display: block;
            width: 120px;
            height: 50px;
        }

        /* 两个伪类的属性，可以用逗号隔开 */
        .nav ul li a:link,
        .nav ul li a:visited {
            text-decoration: none;
            background-color: purple;
            color: white;
        
        }

        .nav ul li a:hover {
            background-color: orange;
        }

        /* 让文本框获取焦点时 */
        input:focus {
            border: 2px solid rgb(106, 0, 255);
            color: white;
            background-color: blueviolet;
        }

        /* 让标签被点击没有松开时显示红色 */
        label:active {
            color: red;
            background-color: blueviolet;
        }

        /* 整个表格的样式*/
        table {
            width: 300px;
            height: 200px;
            border: 1px solid black;
            /* 对表格的线进行折叠 */
            border-collapse: collapse;
        }

        /*鼠标悬停时，让当前行显示#868686这种灰色*/
        table tr:hover {
            background: #868686;
        }

        /*每个单元格的样式*/
        table td {
            border: 1px solid red;
        }
    </style>
</head>

<body>
    <div class="nav">
        <ul>
            <li><a href="#">首页</a></li>
            <li><a href="#">新闻</a></li>
            <li><a href="#">体育</a></li>
            <li><a href="#">娱乐</a></li>
            <li><a href="#">财经</a></li>
            <li><a href="#">科技</a></li>
            <li><a href="#">汽车</a></li>
            <li><a href="#">房产</a></li>
        </ul>
    </div>

    <label>用户名: </label>
    <input type="text", name=""><br><br>

    <table>
        <tr>
            <td></td>
            <td></td>
            <td></td>
            <td></td>
        </tr>
        <tr>
            <td></td>
            <td></td>
            <td></td>
            <td></td>
        </tr>
        <tr>
            <td></td>
            <td></td>
            <td></td>
            <td></td>
        </tr>
    </table>
</body>

</html>
```

前端开发工程师在大量的实践中，发现不写 `:link`、`:visited` 也挺兼容。在写 `a:link`、`a:visited` 这两个伪类的时候，要么同时写，要么同时不写。


