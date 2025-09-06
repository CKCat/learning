
在之前的教程中，我们已经介绍了如何打开_对话框_窗口。这些是特殊的窗口，它们（默认情况下）会抢占用户的焦点，并运行它们自己的事件循环，从而有效地阻塞你应用其余部分的执行。

然而，你通常会希望在应用程序中打开第二个窗口，而不会中断主窗口——例如，显示一些长时间运行的进程的输出，或者显示图表或其他可视化内容。或者，你可能想创建一个允许你同时在各自的窗口中处理多个文档的应用程序。

打开新窗口相对简单，但有几件事需要记住，以确保它们能正常工作。在本教程中，我们将逐步介绍如何创建一个新窗口，以及如何根据需要显示和隐藏外部窗口。

创建一个新窗口
---------------------

在 Qt 中，任何没有父窗口的部件都是一个窗口。这意味着，要显示一个新窗口，你只需要创建一个新的部件实例。这可以是任何部件类型（技术上讲是 `QWidget` 的任何子类），如果你愿意，也可以是另一个 `QMainWindow`。

你可以拥有的 `QMainWindow` 实例数量没有限制。如果你的第二个窗口需要工具栏或菜单，你就必须使用一个 `QMainWindow` 来实现这一点。然而，这可能会让用户感到困惑，所以请确保这是必要的。

与你的主窗口一样，仅仅*创建*一个窗口是不够的，你还必须显示它：

python

```python
import sys

from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class AnotherWindow(QWidget):
    """
    这个“窗口”是一个 QWidget。如果它没有父窗口，
    它就会像我们希望的那样，作为一个自由浮动的窗口出现。
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.label = QLabel("Another Window")
        layout.addWidget(self.label)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.button = QPushButton("Push for Window")
        self.button.clicked.connect(self.show_new_window)
        self.setCentralWidget(self.button)

    def show_new_window(self, checked):
        w = AnotherWindow()
        w.show()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()
```

![](assets/window1.jpg) _一个带有一个按钮来启动子窗口的主窗口。_

如果你运行这个程序，你会看到主窗口。点击按钮*可能*会显示第二个窗口，但如果你看到了，它也只会显示一瞬间。发生了什么事？

在 `show_new_window()` 方法内部，我们创建了我们的窗口（部件）对象，将它存储在变量 `w` 中并显示它。然而，一旦我们离开这个方法，我们就不再有对 `w` 变量的引用了（它是一个*局部*变量），因此它会被清理掉——窗口也会被销毁。为了解决这个问题，我们需要在*某个地方*保留对窗口的引用，例如在 `self` 对象上：

python

```python
    def show_new_window(self, checked):
        self.w = AnotherWindow()
        self.w.show()
```

现在，当你点击按钮显示新窗口时，它就会一直存在。

然而，如果你再次点击按钮会发生什么？窗口会被重新创建！这个新窗口会替换 `self.w` 变量中的旧窗口，并且——因为现在没有对它的引用了——之前的窗口会被销毁。

如果你将窗口定义更改为每次创建时都在标签中显示一个随机数，你就可以看到这个过程：

python

```python
from random import randint


class AnotherWindow(QWidget):
    """
    这个“窗口”是一个 QWidget。如果它没有父窗口，
    它就会像我们希望的那样，作为一个自由浮动的窗口出现。
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.label = QLabel("Another Window % d" % randint(0,100))
        layout.addWidget(self.label)
        self.setLayout(layout)
```

`__init__()` 方法只在*创建*窗口时运行。如果你一直点击按钮，数字会改变，这表明窗口正在被重新创建。

一个解决方案是在创建窗口之前简单地检查它是否已经被创建。下面的例子演示了这一点：

python

```python
import sys

from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class AnotherWindow(QWidget):
    """
    这个“窗口”是一个 QWidget。如果它没有父窗口，
    它就会像我们希望的那样，作为一个自由浮动的窗口出现。
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.label = QLabel("Another Window")
        layout.addWidget(self.label)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.w = None  # 还没有外部窗口。
        self.button = QPushButton("Push for Window")
        self.button.clicked.connect(self.show_new_window)
        self.setCentralWidget(self.button)

    def show_new_window(self, checked):
        if self.w is None:
            self.w = AnotherWindow()
        self.w.show()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()
```

![](assets/window2.jpg) _子窗口，其标签在创建时随机生成。_

你可以使用按钮弹出窗口，并使用窗口控件来关闭它。如果你再次点击按钮，同一个窗口会重新出现。

对于你临时创建的窗口来说，这种方法很好——例如，如果你想弹出一个窗口来显示某个特定的图表或日志输出。然而，对于许多应用程序来说，你有一些标准的窗口，你希望能够根据需要显示/隐藏它们。

在下一部分，我们将看看如何处理这些类型的窗口。

切换窗口
-----------------

通常，你会希望使用工具栏或菜单上的操作来切换窗口的显示。正如我们之前看到的，如果没有保留对窗口的引用，它将被丢弃（并关闭）。我们可以利用这种行为来关闭一个窗口，用以下代码替换前面例子中的 `show_new_window` 方法：

python

```python
    def show_new_window(self, checked):
        if self.w is None:
            self.w = AnotherWindow()
            self.w.show()
        else:
            self.w = None  # 丢弃引用，关闭窗口。
```

通过将 `self.w` 设置为 `None`，对窗口的引用将丢失，窗口将关闭。

如果你将它设置为 `None` 以外的任何其他值，窗口仍然会关闭，但下次我们点击按钮时 `if self.w is None` 的测试将不会通过，因此我们将无法重新创建一个窗口。

这只在你没有在其他地方保留对这个窗口的引用的情况下才有效。为了确保无论如何窗口都会关闭，你可能想在它上面显式调用 `.close()`。完整的例子如下所示：

python

```python
import sys
from random import randint

from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class AnotherWindow(QWidget):
    """
    这个“窗口”是一个 QWidget。如果它没有父窗口，
    它就会像我们希望的那样，作为一个自由浮动的窗口出现。
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.label = QLabel("Another Window % d" % randint(0, 100))
        layout.addWidget(self.label)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.w = None  # 还没有外部窗口。
        self.button = QPushButton("Push for Window")
        self.button.clicked.connect(self.show_new_window)
        self.setCentralWidget(self.button)

    def show_new_window(self, checked):
        if self.w is None:
            self.w = AnotherWindow()
            self.w.show()
        else:
            self.w.close()  # 关闭窗口。
            self.w = None  # 丢弃引用。


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()
```

持久化窗口
------------------

到目前为止，我们已经了解了如何根据需要创建新窗口。然而，有时你有一些标准的应用程序窗口。在这种情况下，与其在想要显示它们时才创建窗口，不如在启动时创建它们，然后在需要时使用 `.show()` 来显示它们，这通常更有意义。

在下面的例子中，我们在主窗口的 `__init__` 块中创建我们的外部窗口，然后我们的 `show_new_window` 方法只需调用 `self.w.show()` 来显示它：

python

```python
import sys
from random import randint

from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class AnotherWindow(QWidget):
    """
    这个“窗口”是一个 QWidget。如果它没有父窗口，
    它就会像我们希望的那样，作为一个自由浮动的窗口出现。
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.label = QLabel("Another Window % d" % randint(0, 100))
        layout.addWidget(self.label)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.w = AnotherWindow()
        self.button = QPushButton("Push for Window")
        self.button.clicked.connect(self.show_new_window)
        self.setCentralWidget(self.button)

    def show_new_window(self, checked):
        self.w.show()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()
```

如果你运行这个程序，点击按钮会像以前一样显示窗口。然而，请注意，窗口只创建一次，在一个已经可见的窗口上调用 `.show()` 没有效果。

### 显示和隐藏持久化窗口

一旦你创建了一个持久化窗口，你就可以显示和隐藏它，而无需重新创建它。一旦隐藏，窗口仍然存在，但将不可见，也不接受鼠标或其他输入。然而，你可以继续调用窗口上的方法并更新其状态——包括改变其外观。一旦重新显示，任何更改都将可见。

下面我们更新我们的主窗口，创建一个 `toggle_window` 方法，它使用 `.isVisible()` 来检查窗口当前是否可见。如果不可见，就用 `.show()` 显示它，如果已经可见，我们就用 `.hide()` 方法隐藏它：

python

```python
class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.w = AnotherWindow()
        self.button = QPushButton("Push for Window")
        self.button.clicked.connect(self.toggle_window)
        self.setCentralWidget(self.button)

    def toggle_window(self, checked):
        if self.w.isVisible():
            self.w.hide()
        else:
            self.w.show()
```

下面是这个持久化窗口和切换显示/隐藏状态的完整工作示例：

python

```python
import sys
from random import randint

from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class AnotherWindow(QWidget):
    """
    这个“窗口”是一个 QWidget。如果它没有父窗口，
    它就会像我们希望的那样，作为一个自由浮动的窗口出现。
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.label = QLabel("Another Window % d" % randint(0, 100))
        layout.addWidget(self.label)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.w = AnotherWindow()
        self.button = QPushButton("Push for Window")
        self.button.clicked.connect(self.toggle_window)
        self.setCentralWidget(self.button)

    def toggle_window(self, checked):
        if self.w.isVisible():
            self.w.hide()
        else:
            self.w.show()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()
```

请再次注意，窗口只创建一次——每次重新显示窗口时，窗口的 `__init__()` 方法不会重新运行（所以标签中的数字不会改变）。

多个窗口
----------------

你可以使用相同的原则来创建多个窗口——只要你保留对窗口的引用，事情就会按预期工作。最简单的方法是为每个窗口的显示切换创建一个单独的方法：

python

```python
import sys
from random import randint

from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class AnotherWindow(QWidget):
    """
    这个“窗口”是一个 QWidget。如果它没有父窗口，
    它就会像我们希望的那样，作为一个自由浮动的窗口出现。
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.label = QLabel("Another Window % d" % randint(0, 100))
        layout.addWidget(self.label)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.window1 = AnotherWindow()
        self.window2 = AnotherWindow()

        layout = QVBoxLayout()
        button1 = QPushButton("Push for Window 1")
        button1.clicked.connect(self.toggle_window1)
        layout.addWidget(button1)

        button2 = QPushButton("Push for Window 2")
        button2.clicked.connect(self.toggle_window2)
        layout.addWidget(button2)

        w = QWidget()
        w.setLayout(layout)
        self.setCentralWidget(w)

    def toggle_window1(self, checked):
        if self.window1.isVisible():
            self.window1.hide()
        else:
            self.window1.show()

    def toggle_window2(self, checked):
        if self.window2.isVisible():
            self.window2.hide()
        else:
            self.window2.show()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()
```

![](assets/window7.jpg) _一个带两个子窗口的主窗口。_

然而，你也可以创建一个通用的方法来处理所有窗口的切换——有关其工作原理的详细解释，请参阅[使用 Qt 信号传输额外数据](https://www.pythonguis.com/tutorials/pyside6-transmitting-extra-data-qt-signals/)。下面的例子演示了这一点，使用 `lambda` 函数来拦截每个按钮的信号并传递相应的窗口。我们也可以丢弃 `checked` 值，因为我们没有使用它：

python

```python
import sys
from random import randint

from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class AnotherWindow(QWidget):
    """
    这个“窗口”是一个 QWidget。如果它没有父窗口，
    它就会像我们希望的那樣，作為一個自由浮動的窗口出現。
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.label = QLabel("Another Window % d" % randint(0, 100))
        layout.addWidget(self.label)
        self.setLayout(layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.window1 = AnotherWindow()
        self.window2 = AnotherWindow()

        layout = QVBoxLayout()
        button1 = QPushButton("Push for Window 1")
        button1.clicked.connect(
            lambda checked: self.toggle_window(self.window1),
        )
        layout.addWidget(button1)

        button2 = QPushButton("Push for Window 2")
        button2.clicked.connect(
            lambda checked: self.toggle_window(self.window2),
        )
        layout.addWidget(button2)

        w = QWidget()
        w.setLayout(layout)
        self.setCentralWidget(w)

    def toggle_window(self, window):
        if window.isVisible():
            window.hide()
        else:
            window.show()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()
```

