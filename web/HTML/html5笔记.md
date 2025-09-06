HTML5 代表浏览器端技术的一个发展阶段。在这个阶段，浏览器的呈现技术得到了飞跃发展和广泛支持，它包括：HTML5、CSS3、Javascript API 在内的一套技术组合。

## H5 中新增的语义标签

- `<section>` 表示区块
- `<article>` 表示文章。如文章、评论、帖子、博客
- `<header>` 表示页眉
- `<footer>` 表示页脚
- `<nav>` 表示导航
- `<aside>` 表示侧边栏。如文章的侧栏
- `<figure>` 表示媒介内容分组。
- `<mark>` 表示标记 (用得少)
- `<progress>` 表示进度 (用得少)
- `<time>` 表示日期

## H5 中新增的表单类型

- `email` 只能输入 `email` 格式。自动带有验证功能。
- `tel` 手机号码。
- `url` 只能输入 `url` 格式。
- `number` 只能输入数字。
- `search` 搜索框
- `range` 滑动条
- `color` 拾色器
- `time` 时间
- `date` 日期
- `datetime` 时间日期
- `month` 月份
- `week` 星期

## 表单元素

### `<datalist>` 数据列表

```html
<input type="text" list="myData" />
<datalist id="myData">
  <option>本科</option>
  <option>研究生</option>
  <option>不明</option>
</datalist>
```

`input` 里的 `list` 属性和 `datalist` 进行了绑定,可以自动提示。

### `<keygen>` 元素

`keygen` 元素是密钥对生成器（key-pair generator）。当提交表单时，会生成两个键：一个公钥，一个私钥。

私钥（private key）存储于客户端，公钥（public key）则被发送到服务器。公钥可用于之后验证用户的客户端证书（client certificate）。

### `<meter>` 度量器

- `low`：低于该值后警告
- `high`：高于该值后警告
- `value`：当前值
- `max`：最大值
- `min`：最小值。

### 表单属性

- `placeholder` 占位符（提示文字）
- `autofocus` 自动获取焦点
- `multiple` 文件上传多选或多个邮箱地址
- `autocomplete` 自动完成（填充的）。`on` 开启（默认），`off` 取消。
- `form` 指定表单项属于哪个 `form`，处理复杂表单时会需要
- `novalidate` 关闭默认的验证功能（只能加给 `form`）
- `required` 表示必填项
- `pattern` 自定义正则，验证表单。

### 表单事件

`oninput()`：用户输入内容时触发，可用于输入字数统计。

`oninvalid()`：验证不通过时触发。比如，如果验证不通过时，想弹出一段提示文字，就可以用到它。

## 多媒体

### `<audio>` 音频

属性：

- `autoplay` 自动播放。写成 `autoplay` 或者 `autoplay = ""`，都可以。
- `controls` 控制条。
- `loop` 循环播放。
- `preload` 预加载 同时设置 `autoplay` 时，此属性将失效。

### `<video>` 视频

属性：

- `autoplay` 自动播放。写成 `autoplay` 或者 `autoplay = ""`，都可以。
- `controls` 控制条。
- `loop` 循环播放。
- `preload` 预加载 同时设置 `autoplay` 时，此属性将失效。
- `width`：设置播放窗口宽度。
- `height`：设置播放窗口的高度。

## DOM 操作

### 获取元素

`document.querySelector("selector")` 通过 CSS 选择器获取符合条件的第一个元素。

`document.querySelectorAll("selector")` 通过 CSS 选择器获取符合条件的所有元素，以类数组形式存在。

### 类名操作

`Node.classList.add("class")` 添加 class

`Node.classList.remove("class")` 移除 class

`Node.classList.toggle("class")` 切换 class，有则移除，无则添加

`Node.classList.contains("class")` 检测是否存在 class

### 自定义属性

js 里可以通过 `box1.index=100; box1.title` 来自定义属性和获取属性。

H5 可以直接在标签里添加自定义属性，但必须以 `data-` 开头。

## 拖拽

在 HTML5 的规范中，我们可以通过为元素增加 `draggable="true"` 来设置此元素是否可以进行拖拽操作，其中图片、链接默认是开启拖拽的。

拖拽元素的事件监听：

- `ondragstart` 当拖拽开始时调用
- `ondragleave` 当鼠标离开拖拽元素时调用
- `ondragend` 当拖拽结束时调用
- `ondrag` 整个拖拽过程都会调用

把元素 A 拖拽到元素 B 里，那么元素 B 就是目标元素。页面中任何一个元素都可以成为目标元素。

目标元素的事件监听：

- `ondragenter` 当拖拽元素进入时调用
- `ondragover` 当拖拽元素停留在目标元素上时，就会连续一直触发（不管拖拽元素此时是移动还是不动的状态）
- `ondrop` 当在目标元素上松开鼠标时调用
- `ondragleave` 当鼠标离开目标元素时调用

如果想让拖拽元素在目标元素里做点事情，就必须要在 `ondragover()` 里加 `event.preventDefault()` 这一行代码。

## 历史

在 HTML5 中可以通过 `window.history` 操作访问历史状态，让一个页面可以有多个历史状态

- `window.history.forward();` // 前进
- `window.history.back();` // 后退
- `window.history.go();` // 刷新
- `window.history.go(n);` //n=1 表示前进；n=-1 后退；n=0s 刷新。如果移动的位置超出了访问历史的边界，会静默失败，但不会报错。
- 通过 JS 可以加入一个访问状态
- `history.pushState;` //放入历史中的状态数据, 设置 title(现在浏览器不支持改变历史状态)

## 地理定位

HTML5 Geolocation(地理位置定位) 规范提供了一套保护用户隐私的机制。必须先得到用户明确许可，才能获取用户的位置信息。

- `navigator.getCurrentPosition(successCallback, errorCallback, options)` 获取当前地理信息

- `navigator.watchPosition(successCallback, errorCallback, options)` 重复获取当前地理信息

1、当成功获取地理信息后，会调用 `succssCallback`，并返回一个包含位置信息的对象 `position`：（Coords 即坐标）

- `position.coords.latitude` 纬度

- `position.coords.longitude` 经度

2、当获取地理信息失败后，会调用 `errorCallback`，并返回错误信息 `error`。

3、可选参数 `options` 对象可以调整位置信息数据收集方式

## 全屏

HTML5 规范允许用户自定义网页上任一元素全屏显示。

```js
requestFullscreen(); //让元素开启全屏显示
cancleFullscreen(); //让元素关闭全屏显示
```

全屏的伪类

- `:full-screen .box {}`
- `:-webkit-full-screen {}`
- `:moz-full-screen {}`

## Web 存储

1. `window.sessionStorage` 会话存储：

- 保存在内存中。
- 生命周期为关闭浏览器窗口。也就是说，当窗口关闭时数据销毁。
- 在同一个窗口下数据可以共享。

2. `window.localStorage` 本地存储：

- 有可能保存在浏览器内存里，有可能在硬盘里。
- 永久生效，除非手动删除（比如清理垃圾的时候）。
- 可以多窗口共享。

常见 API

```js
setItem(key, value); //设置存储内容
getItem(key); // 读取存储内容
removeItem(key); // 删除存储内容
clear(); // 清空所有存储内容
key(n); // 根据索引值来获取存储内容
```

`sessionStorage` 的 API 举例：

```html
<!DOCTYPE html>
<html>
  <head lang="en">
    <meta charset="UTF-8" />
    <title></title>
  </head>
  <body>
    <input type="text" />
    <button>sesssionStorage存储</button>
    <button>sesssionStorage获取</button>
    <button>sesssionStorage更新</button>
    <button>sesssionStorage删除</button>
    <button>sesssionStorage清除</button>
    <script>
      //在h5中提供两种web存储方式

      // sessionStorage  session（会话，会议） 5M  当窗口关闭是数据销毁  内存
      // localStorage    20M 永久生效 ，除非手动删除  清理垃圾  硬盘上

      var txt = document.querySelector("input");

      var btns = document.querySelectorAll("button");
      //        sessionStorage存储数据
      btns[0].onclick = function () {
        window.sessionStorage.setItem("userName", txt.value);
        window.sessionStorage.setItem("pwd", "123456");
        window.sessionStorage.setItem("age", 18);
      };

      //        sessionStorage获取数据
      btns[1].onclick = function () {
        txt.value = window.sessionStorage.getItem("userName");
      };

      //        sessionStorage更新数据
      btns[2].onclick = function () {
        window.sessionStorage.setItem("userName", txt.value);
      };

      //        sessionStorage删除数据
      btns[3].onclick = function () {
        window.sessionStorage.removeItem("userName");
      };

      //        sessionStorage清空数据
      btns[4].onclick = function () {
        window.sessionStorage.clear();
      };
    </script>
  </body>
</html>
```

`localStorage` 的 API 举例：

```html
<!DOCTYPE html>
<html>
  <head lang="en">
    <meta charset="UTF-8" />
    <title></title>
  </head>
  <body>
    <input type="text" />
    <button>localStorage存储</button>
    <button>localStorage获取</button>
    <button>localStorage更新</button>
    <button>localStorage删除</button>
    <button>localStorage清除</button>

    <script>
      /*
       *  localStorage
       *  数据存在硬盘上
       *  永久生效
       *  20M
       * */

      var txt = document.querySelector("input");
      var btns = document.querySelectorAll("button");

      // localStorage存储数据
      btns[0].onclick = function () {
        window.localStorage.setItem("userName", txt.value);
      };

      // localStorage获取数据
      btns[1].onclick = function () {
        txt.value = window.localStorage.getItem("userName");
      };

      // localStorage删除数据
      btns[3].onclick = function () {
        window.localStorage.removeItem("userName");
      };
    </script>
  </body>
</html>
```
