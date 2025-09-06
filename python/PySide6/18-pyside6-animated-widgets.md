
在之前的教程中，我们了解了如何[使用 PySide6 构建自定义控件](https://www.pythonguis.com/tutorials/pyside6-creating-your-own-custom-widgets/)。我们构建的控件使用了布局、嵌套控件和一个简单的 `QPainter` 画布的组合，创建了一个可以放入任何应用程序的自定义控件。

但这仅仅触及了 PySide6 中自定义控件可能性的皮毛。在本教程中，我们将探讨如何使用 Qt 的 `QPropertyAnimation` 来通过视觉效果和动画增强您的自定义控件。

`QPropertyAnimation` 允许您在一定时间内，将一个对象的属性值从一个*起始值*更改为*结束值*，并且可以选择遵循一个自定义的*缓动曲线*（easingCurve）。

为了实现这一点，您想要更改的属性必须被定义为 Qt 属性（Property）。在继续深入 `QPropertyAnimation` 之前，让我们先了解一下 Python 和 Qt 中的*属性*概念。

### 属性 (Properties)

Python 中的对象具有*属性*，您可以从中设置和获取值。这些属性可以定义在类本身上（使其成为*类属性*）或在对象实例上（使其成为*对象属性*）。对象属性的默认值通常在类的 `__init__` 方法中设置，通过赋值给 `self.<属性名>`。

```python
class MyObject:

    def __init__(self):
        self.my_attribute = 1
        self.my_attribute2 = 2

obj = MyObject()
print(obj.my_attribute)
print(obj.my_attribute2)
obj.my_attribute = 'hello'
print(obj.my_attribute)
```

如果您运行这个示例，您将看到以下输出。

当我们创建 `MyObject` 类的一个实例时，`__init__` 方法设置了两个属性 `my_attribute` 和 `my_attribute2`。我们可以通过 `obj.my_attribute` 从实例访问它们，或者通过 `obj.my_attribute = <value>` 赋值给该属性来设置它们。

虽然简单的属性对于大多数用例来说很棒，但有时能够执行额外的步骤来获取和设置值是很有用的。例如，您可能希望在响应更改时发送通知，或者在设置值时执行某种计算。在这些情况下，您可以使用*属性*（properties）。

#### Python 属性 (Python Properties)

Python 的*属性*在外部行为上与属性完全一样——您可以像设置和获取普通属性一样设置和获取它们。然而，在内部，每个*属性*都使用*getter*和（可选地）*setter*方法来分别处理获取和设置操作。

*getter*和*setter*方法是相互独立的。*getter*是必需的。如果您不定义*setter*，则该属性是只读的。

您可以使用 [property 内置函数](https://docs.python.org/3/library/functions.html#property)来定义属性。您可以通过两种方式来定义一个属性——

1.  使用 `property()` 作为*函数*。
2.  使用 `@property` 作为*装饰器*。

下面的示例展示了如何使用这两种方法在简单类上定义自定义属性。

*   装饰器方式
*   函数方式

```python
class MyCustomClass:

    def __init__(self):
        self._value = None

    @property
    def value(self):
        print("正在获取值", self._value)
        return self._value

    @value.setter
    def value(self, value):
        print("正在设置值", value)
        self._value = value


obj = MyCustomClass()

a = obj.value       # 访问值
print(a)            # 打印值
obj.value = 'hello' # 设置值
b = obj.value       # 访问值
print(b)            # 打印值
```

```python
class MyCustomClass:

    def __init__(self):
        self._value = None

    def getValue(self):
        print("正在获取值", self._value)
        return self._value

    def setValue(self, value):
        print("正在设置值", value)
        self._value = value

    value = property(getValue, setValue)


obj = MyCustomClass()

a = obj.value       # 访问值
print(a)            # 打印值
obj.value = 'hello' # 设置值
b = obj.value       # 访问值
print(b)            # 打印值
```

我更喜欢 `@decorator` 语法，因为它使得方法名称与您通过属性设置/获取的值保持一致——但您可以选择您喜欢的方式。如果您运行任一示例，您将看到相同的输出。

```python
正在获取值 None
None
正在设置值 hello
正在获取值 hello
hello
```

当我们访问 `obj.value` 属性时，被 `@property` 装饰的 `value` 方法会运行，打印“正在获取值”的消息。该值会像任何其他对象属性一样被返回。当我们设置值时，被 `@value.setter` 装饰的方法会运行，打印“正在设置值”的消息。

实际的值内部存储在一个*私有*属性 `self._value` 中，我们在对象的 `__init__` 中为其提供了一个默认值。

#### Qt 属性 (Qt Properties)

[Qt 属性](https://doc.qt.io/qt-5/properties.html)的工作方式类似，允许我们在 Qt 类上定义属性，并实现*getter*和*setter*方法来执行其他功能。然而，定义 Qt 属性也允许我们与 Qt 的其他组件集成。

要在 PySide 中定义一个属性，我们使用 `Property`，它可以从 _QtCore_ 模块导入。与 Python 属性一样，两者都可以作为*函数*或*装饰器*使用。

与 Python 方法唯一的区别是，对于 Qt，我们还必须为属性提供一个*类型*——在下面的示例中是 `int`——这样 Qt 就知道它可以从/向该属性接收/发送什么类型的数据。

*   PySide6 @decorator 方式
*   PySide6 函数方式

```python
from PySide6.QtCore import QObject, Property

class CustomObject(QObject):
    def __init__(self):
        super().__init__()
        self._value = 0        # 默认值

    @Property(int)
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value
```

```python
from PySide6.QtCore import QObject, Property

class CustomObject(QObject):
    def __init__(self):
        super().__init__()
        self._value = 0        # 默认值

    def getValue(self):
        return self._value

    def setValue(self, value):
        self._value = value

    value = Property(int, getValue, setValue)
```

和以前一样，如果我们创建这个类的一个实例，我们现在可以像访问一个普通属性一样获取和设置它的 `value` 成员，例如：

```python
obj = CustomObject()
obj.value = 7
print(obj.value)
```

在 PySide 应用程序中，getter/setter 方法的一个简单用途是在某些属性更改时发出信号。例如，在下面的代码片段中，我们向类添加了一个自定义 `Signal`，并在 _value_ 更改时发出新值。

```python
from PySide6.QtCore import QObject, Property, Signal

class CustomObject(QObject):

    valueChanged = Signal(int)

    def __init__(self):
        super().__init__()
        self._value = 0        # 默认值

    # 更改 setter 函数为：
    @value.setter
    def value(self, value):
        # 这里的检查非常重要...
        # 以防止不必要的信号传播。
        if value != self._value:
            self._value = value
            self.valueChanged.emit(value)
```

现在我们熟悉了在 PySide（和 Python）中使用属性，接下来我们将看看如何使用 `QPropertyAnimation` 来*动画化*属性，并用它来创建自定义控件动画。

### `QPropertyAnimation`

到目前为止，我们已经定义了带有*setter*和*getter*方法的简单属性，它们的行为类似于简单属性。我们还为 setter 方法添加了一个副作用，以发出通知更改的信号。

`QPropertyAnimation` 是一个建立在属性之上的接口，可用于动画化——或*插值*——给定属性的*起始*值和*结束*值之间。使用它，我们可以触发一个更改，并自动设置一系列定时值。

如果更改此属性触发了控件的刷新（或者我们在 `paintEvent()` 中使用了动画值），控件就会显得被动画化了。

下面是一个示例，使用 `QPropertyAnimation` 来动画化窗口中一个简单 `QWidget`（一个红色填充的方块）的位置。动画通过 `.pos` 更新控件的*位置*，这会自动触发 Qt 的重绘。

```python
from PySide6.QtWidgets import QWidget
from PySide6.QtCore import QPropertyAnimation, QPoint, QEasingCurve

class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.resize(600, 600)
        self.child = QWidget(self)
        self.child.setStyleSheet("background-color:red;border-radius:15px;")
        self.child.resize(100, 100)
        # 注意属性名必须是 bytes 类型，所以是 b"pos"
        self.anim = QPropertyAnimation(self.child, b"pos")
        self.anim.setEndValue(QPoint(400, 400))
        self.anim.setDuration(1500)
        self.anim.start()
```

这将产生以下动画。默认情况下，动画是*线性的*，`QWidget`以恒定的速率向结束位置移动。

要使用 `QPropertyAnimation` 创建动画，您需要提供以下内容——

1.  告诉 `QPropertyAnimation` 我们要动画化的*对象*，这里是 `self.child`
2.  提供一个*属性名*，这里是 `b"pos"`（必须指定为 *bytes* `b"value"`）
3.  *\[可选]* *起始*值。
4.  *结束*值。
5.  *\[可选]* 插值的*持续时间* *\[以毫秒为单位]*，默认为 250 毫秒。

您正在动画化的属性*必须*有一个*setter*——内置控件上的默认属性有 setter，但对于自定义控件，您需要实现它。

您通常希望为动画添加加速和减速，而不是一个简单的*线性*动画。这对于创建感觉*逼真*和*物理化*的控件，或添加有趣的引人注目的效果非常有用。要为动画添加加速和减速，您可以使用 `QEasingCurve` 提供的*缓动曲线*。

### `QEasingCurve`

`QEasingCurve` 是一个 Qt 对象，它描述了两个点之间的过渡——或插值。我们可以将这种过渡应用于我们的动画属性，以改变它们的行为方式。

在物理对象中，变化很少以恒定速度发生，而是有一个*加速*和*减速*阶段。例如，一个下落物体的速度会因为重力而随着时间从慢开始增加。一个被踢的球会迅速（但不是瞬间）加速到全速，然后由于空气阻力而减速。如果您用手移动一个物体，您会逐渐加速它，然后在到达目的地时为了精确而减速。

在现实生活中试试吧！随便抓起附近的东西，观察您的手是如何移动的。

当移动一个 GUI 组件时，如果它以恒定速度移动，可能会显得*不自然*。为了让我们能够定义看起来更自然的的行为，Qt 为我们提供了几种*常见*的预定义曲线。

如果您不熟悉过渡曲线，这些图表可能看起来有点奇怪，所以我们将更详细地了解它们。

每条曲线都代表一种*值*与*时间*的关系，即它们显示了一个值将*随时间*如何变化。如果线条上升，则值增加；如果线条下降，则值减少。在任何给定点的*斜率*或*梯度*代表变化*速率*（值变化的速度）。更陡峭的斜率表示更快的变化，而*水平*线表示值在该点没有变化，或*恒定*。

#### 常见的曲线

默认的“曲线”根本不是曲线，而是一条直线。这种 **Linear** 缓动曲线以规则、一致的步骤在两个值之间进行插值。

接下来是 UI 中最常用的过渡曲线之一——**_InOutCubic_**。它从一个低斜率开始，增加到中点，然后再次减小。这条曲线的效果是：一个渐进的变化，加速到中点，然后减速到终点停止。

还有一些变体，只在一个方向（In 或 Out）应用这种过渡。

**OutInCubic** 与 _InOutCubic_ 相反，它在开始时迅速加速，在中点减速，然后加速到终点。这可能对幻灯片或无限移动和变化的组件有用，在这些组件中，您希望元素快速进入视图，然后暂停再退出。

最后一个 **_OutBounce_**，显示有趣的框外动画，请参阅下面的动画演示。

理解这些过渡的最佳方式是看它们的实际运行效果。下面是一系列完整的示例，您可以用来试验并改编成其他过渡效果。

*   InOutCubic
*   OutInCubic
*   OutBounce

```python
from PySide6.QtWidgets import QWidget
from PySide6.QtCore import QPropertyAnimation, QPoint, QEasingCurve

class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.resize(600, 600)
        self.child = QWidget(self)
        self.child.setStyleSheet("background-color:red;border-radius:15px;")
        self.child.resize(100, 100)
        self.anim = QPropertyAnimation(self.child, b"pos")
        self.anim.setEasingCurve(QEasingCurve.InOutCubic)
        self.anim.setEndValue(QPoint(400, 400))
        self.anim.setDuration(1500)
        self.anim.start()
```

```python
from PySide6.QtWidgets import QWidget
from PySide6.QtCore import QPropertyAnimation, QPoint, QEasingCurve

class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.resize(600, 600)
        self.child = QWidget(self)
        self.child.setStyleSheet("background-color:red;border-radius:15px;")
        self.child.resize(100, 100)
        self.anim = QPropertyAnimation(self.child, b"pos")
        self.anim.setEasingCurve(QEasingCurve.OutInCubic)
        self.anim.setEndValue(QPoint(400, 400))
        self.anim.setDuration(1500)
        self.anim.start()
```

```python
from PySide6.QtWidgets import QWidget
from PySide6.QtCore import QPropertyAnimation, QPoint, QEasingCurve

class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.resize(600, 600)
        self.child = QWidget(self)
        self.child.setStyleSheet("background-color:red;border-radius:15px;")
        self.child.resize(100, 100)
        self.anim = QPropertyAnimation(self.child, b"pos")
        self.anim.setEasingCurve(QEasingCurve.OutBounce)
        self.anim.setEndValue(QPoint(400, 400))
        self.anim.setDuration(1500)
        self.anim.start()
```

这些动画的计时是相同的（1.5秒），动画的差异是由于记录造成的。在Qt应用中，每个动画将花费完全相同的时间。

我们只看了最常见的缓动曲线。有关完整列表，请参阅 Qt 的 [`QEasingCurve` 文档](https://doc.qt.io/qt-5/qeasingcurve.html)并进行试验！您会在文档中找到几个图表来可视化它们的行为。

#### 组合多个 `QPropertyAnimation` 动画

这些单一动画曲线本身很有用，但有时您可能希望将多个动画组合在一起以构建更复杂的行为。为了支持这一点，Qt 提供了 `QAnimationGroup`，我们可以用它来组合多个动画并控制它们的*开始*和*停止*时间。动画组有两种类型，它们以特定的方式对动画进行分组——

*   `QParallelAnimationGroup` 将动画分组以同时运行
*   `QSequentialAnimationGroup` 将动画分组以按顺序运行

`QAnimationGroup` 是一个*抽象*类，因此不能直接使用。

下面是一个使用两个*顺序*动画移动控件的示例。第一个像以前一样移动块，第二个在水平方向上展开块的大小。

```python
from PySide6.QtWidgets import QWidget
from PySide6.QtCore import (
    QPropertyAnimation, QSequentialAnimationGroup, QPoint, QSize)


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.resize(600, 600)
        self.child = QWidget(self)
        self.child.setStyleSheet("background-color:red;border-radius:15px;")
        self.child.resize(100, 100)
        self.anim = QPropertyAnimation(self.child, b"pos")
        self.anim.setEndValue(QPoint(200, 200))
        self.anim.setDuration(1500)
        self.anim_2 = QPropertyAnimation(self.child, b"size")
        self.anim_2.setEndValue(QSize(250, 150))
        self.anim_2.setDuration(2000)
        # 创建顺序动画组
        self.anim_group = QSequentialAnimationGroup()
        self.anim_group.addAnimation(self.anim)
        self.anim_group.addAnimation(self.anim_2)
        self.anim_group.start()
```

或者，您可以并发运行多个动画。下面的示例应用了两个并行运行的动画。第一个像以前一样移动块，第二个使块淡入。

```python
from PySide6.QtWidgets import QWidget, QGraphicsOpacityEffect
from PySide6.QtCore import QPropertyAnimation, QParallelAnimationGroup, QPoint


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.resize(600, 600)
        self.child = QWidget(self)
        # 为淡入效果创建 QGraphicsOpacityEffect
        effect = QGraphicsOpacityEffect(self.child)
        self.child.setGraphicsEffect(effect)
        self.child.setStyleSheet("background-color:red;border-radius:15px;")
        self.child.resize(100, 100)
        self.anim = QPropertyAnimation(self.child, b"pos")
        self.anim.setEndValue(QPoint(200, 200))
        self.anim.setDuration(1500)
        # 为透明度效果创建 QPropertyAnimation
        self.anim_2 = QPropertyAnimation(effect, b"opacity")
        self.anim_2.setStartValue(0)
        self.anim_2.setEndValue(1)
        self.anim_2.setDuration(2500)
        # 创建并行动画组
        self.anim_group = QParallelAnimationGroup()
        self.anim_group.addAnimation(self.anim)
        self.anim_group.addAnimation(self.anim_2)
        self.anim_group.start()
```

### 动画切换开关（“QCheckBox的替代品”）

有了这些简单的构建块，我们拥有了将复杂 UI 行为构建到我们自定义控件中所需的一切。在下一部分中，我们将利用所学知识来构建一个功能齐全的自定义“切换开关”（Toggle）控件，它具有动画行为。

我们正在构建的控件继承自 `QCheckBox`，并为其提供了一个直接替代品，添加了一个带动画滑块和一些吸引眼球的视觉效果来高亮状态变化的动画切换开关。通过继承 `QCheckBox`，我们免费获得了所有内置的复选框行为，所以我们只需要处理视觉部分。

为了实现我们的设计，我们——

*   使用参数定义我们的颜色（`QPen` 和 `QBrush`），并将它们作为对象属性存储。*这不是必需的，但可以节省我们在每一帧都构造它们的开销。*
*   重写 `paintEvent(self, e)`，它接收一个 `QPaintEvent`。
*   定义 `QPropertyAnimation` 和 `QAnimationGroup` 对象，以控制我们想要动画化的属性。
*   选择正确的信号来触发动画。

下面是我们的自定义动画切换开关的完整代码。

```python
from PySide6.QtCore import (
    Qt, QSize, QPoint, QPointF, QRectF,
    QEasingCurve, QPropertyAnimation, QSequentialAnimationGroup,
    Slot, Property)

from PySide6.QtWidgets import QCheckBox
from PySide6.QtGui import QColor, QBrush, QPaintEvent, QPen, QPainter


class AnimatedToggle(QCheckBox):

    _transparent_pen = QPen(Qt.transparent)
    _light_grey_pen = QPen(Qt.GlobalColor.lightGray)

    def __init__(self,
        parent=None,
        bar_color=Qt.GlobalColor.gray,
        checked_color="#00B0FF",
        handle_color=Qt.GlobalColor.white,
        pulse_unchecked_color="#44999999",
        pulse_checked_color="#4400B0EE"
        ):
        super().__init__(parent)

        # 将我们的属性保存在对象上，以便稍后在 paintEvent 中访问。
        self._bar_brush = QBrush(bar_color)
        self._bar_checked_brush = QBrush(QColor(checked_color).lighter())

        self._handle_brush = QBrush(handle_color)
        self._handle_checked_brush = QBrush(QColor(checked_color))

        # 注意：此处使用的 QBrush 可能需要 QColor 实例，具体取决于 Qt 版本
        self._pulse_unchecked_animation = QBrush(QColor(pulse_unchecked_color))
        self._pulse_checked_animation = QBrush(QColor(pulse_checked_color))

        # 设置控件的其余部分。

        self.setContentsMargins(8, 0, 8, 0)
        self._handle_position = 0.0 # 0.0 表示未选中，1.0表示选中

        self._pulse_radius = 0.0

        # 创建手柄位置动画
        self.animation = QPropertyAnimation(self, b"handle_position", self)
        self.animation.setEasingCurve(QEasingCurve.InOutCubic)
        self.animation.setDuration(200)  # 动画时间 (ms)

        # 创建脉冲动画
        self.pulse_anim = QPropertyAnimation(self, b"pulse_radius", self)
        self.pulse_anim.setDuration(350)  # 脉冲动画时间 (ms)
        self.pulse_anim.setStartValue(10.0)
        self.pulse_anim.setEndValue(20.0)

        # 创建顺序动画组，先移动手柄，再播放脉冲
        self.animations_group = QSequentialAnimationGroup()
        self.animations_group.addAnimation(self.animation)
        self.animations_group.addAnimation(self.pulse_anim)

        # 连接状态变化信号到设置动画槽
        self.stateChanged.connect(self.setup_animation)

    def sizeHint(self):
        # 推荐尺寸
        return QSize(58, 45)

    def hitButton(self, pos: QPoint):
        # 扩大可点击区域到整个内容矩形
        return self.contentsRect().contains(pos)

    @Slot(int)
    def setup_animation(self, value):
        # 停止当前动画组（如果正在运行）
        self.animations_group.stop()
        # 根据状态设置动画的结束值
        if value:
            self.animation.setEndValue(1.0) # 选中状态
        else:
            self.animation.setEndValue(0.0) # 未选中状态
        # 启动动画组
        self.animations_group.start()

    def paintEvent(self, e: QPaintEvent):

        contRect = self.contentsRect()
        handleRadius = round(0.24 * contRect.height()) # 手柄半径

        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing) # 开启抗锯齿

        p.setPen(self._transparent_pen)
        
        # 定义滑轨的矩形
        barRect = QRectF(
            0.0, 0.0,
            contRect.width() - 2 * handleRadius, 0.40 * contRect.height()
        )
        barRect.moveCenter(contRect.center()) # 移动到中心
        rounding = barRect.height() / 2 # 圆角半径

        # 手柄移动的轨迹长度
        trailLength = contRect.width() - 2 * handleRadius

        # 计算手柄的 X 位置 (0.0 到 1.0 的插值)
        xPos = contRect.x() + handleRadius + trailLength * self._handle_position

        # 绘制脉冲效果 (如果脉冲动画正在运行)
        if self.pulse_anim.state() == QPropertyAnimation.State.Running:
            pulse_brush = self._pulse_checked_animation if self.isChecked() else self._pulse_unchecked_animation
            p.setBrush(pulse_brush)
            p.drawEllipse(QPointF(xPos, barRect.center().y()),
                          self._pulse_radius, self._pulse_radius)

        # 根据状态设置滑轨和手柄的颜色/画刷
        if self.isChecked():
            # 选中状态
            p.setBrush(self._bar_checked_brush)
            p.drawRoundedRect(barRect, rounding, rounding)
            p.setBrush(self._handle_checked_brush)
        else:
            # 未选中状态
            p.setBrush(self._bar_brush)
            p.drawRoundedRect(barRect, rounding, rounding)
            p.setPen(self._light_grey_pen)
            p.setBrush(self._handle_brush)

        # 绘制手柄
        p.drawEllipse(
            QPointF(xPos, barRect.center().y()),
            handleRadius, handleRadius)

        p.end()

    # 属性的 Getter 和 Setter
    @Property(float)
    def handle_position(self):
        return self._handle_position

    @handle_position.setter
    def handle_position(self, pos):
        """更改属性
        我们需要触发 QWidget.update() 方法，可以通过:
            1- 在这里调用它 [ 我们正在做的事 ].
            2- 将 QPropertyAnimation.valueChanged() 信号连接到它。
        """
        self._handle_position = pos
        self.update()

    @Property(float)
    def pulse_radius(self):
        return self._pulse_radius

    @pulse_radius.setter
    def pulse_radius(self, pos):
        self._pulse_radius = pos
        self.update()

```

`AnimatedToggle` 类相当复杂。有几个关键点需要注意。

1.  因为我们继承自 `QCheckBox`，所以重写 `hitButton()` 至关重要。这定义了我们控件的可点击区域，默认情况下，`QCheckBox` 仅在复选框区域内可点击。在这里，我们使用 `self.contentsRect()` 将可点击区域扩展到整个控件，以便在控件上的任何点击都会切换状态。
2.  同样，重写 `sizeHint()` 至关重要，这样当我们向布局中添加控件时，它们就知道可以使用的可接受的默认尺寸。
3.  您必须设置 `p.setRenderHint(QPainter.Antialiasing)` 来平滑您绘制的边缘，否则轮廓将是锯齿状的。
4.  在这个例子中，我们使用 `self.stateChanged` 信号触发动画，该信号由 `QCheckBox` 提供。每当控件的状态（*选中*或*未选中*）改变时，它就会触发。选择正确的触发器来启动动画很重要，以便让控件感觉直观。
5.  由于我们使用 `stateChanged` 来*启动*动画，因此如果您在点击后立即检查切换开关的状态，它将给出正确的值——即使动画尚未完成。

**不要**尝试在 `paintEvent` 内部或从 `QPropertyAnimation` 中更改逻辑状态。

将上述代码保存到名为 `animated_toggle.py` 的文件中，并在同一文件夹中保存以下简单的骨架应用程序（例如，保存为 `app.py`），它导入 `AnimatedToggle` 类并创建一个小演示。

```python
import sys
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel
# 确保 animated_toggle.py 文件在同一目录下
from animated_toggle import AnimatedToggle

app = QApplication(sys.argv)

window = QWidget()

mainToggle = AnimatedToggle()
secondaryToggle = AnimatedToggle(
        checked_color="#FFB000",
        pulse_checked_color="#44FFB000"
)
# 设置固定尺寸以便更好地控制布局
mainToggle.setFixedSize(mainToggle.sizeHint())
secondaryToggle.setFixedSize(secondaryToggle.sizeHint())

window.setLayout(QVBoxLayout())
window.layout().addWidget(QLabel("Main Toggle"))
window.layout().addWidget(mainToggle)

window.layout().addWidget(QLabel("Secondary Toggle"))
window.layout().addWidget(secondaryToggle)

# 演示信号连接：当主切换开关状态改变时，设置辅助切换开关的状态
mainToggle.stateChanged.connect(secondaryToggle.setChecked)

window.show()
app.exec()
```

运行代码，您应该会在窗口中看到以下演示。

尝试使用 `AnimatedToggle` 类进行试验，使用替代的缓动曲线并构建不同的动画序列。看看您能创造出什么！