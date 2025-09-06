

构建Python GUI应用程序时，一个常见的问题是在尝试执行耗时的后台任务时界面会“卡死”。在本教程中，我们将介绍在PySide6中实现并发执行的几种快捷方法。

如果您想从您的应用程序中运行外部程序（例如命令行工具），请查阅[使用 `QProcess` 运行外部程序](https://www.pythonguis.com/tutorials/pyside6-qprocess-external-programs/)教程。

### 背景：GUI冻结问题

基于Qt的应用程序（像大多数GUI应用程序一样）是基于*事件*的。这意味着程序的执行是由用户交互、信号和定时器来驱动的。在一个事件驱动的应用程序中，点击一个按钮会创建一个*事件*，您的应用程序随后会*处理*这个事件以产生一些预期的输出。事件被推入一个事件队列，然后被依次取出并处理。

在PySide6中，我们使用以下代码创建一个应用：

```python
app = QApplication([])
window = MainWindow()
app.exec()
```

当您调用`QApplication`对象的`.exec()`方法时，事件循环就开始了，并且它与您的Python代码在同一个线程中运行。运行这个事件循环的线程——通常被称为*GUI线程*——也负责处理所有窗口与宿主操作系统的通信。

默认情况下，由事件循环触发的任何执行也将在该线程内同步运行。在实践中，这意味着当您的PySide6应用程序在*做某件事*时，与窗口的通信以及与GUI的交互都会被冻结。

如果您正在做的事情很简单，并且能很快将控制权交还给GUI循环，那么用户将察觉不到GUI的冻结。然而，如果您需要执行*耗时较长的任务*，例如，打开并写入一个大文件、下载一些数据或渲染一张高分辨率图像，那么问题就会出现。

对于您的用户来说，应用程序会显得没有响应（因为它确实没有响应）。由于您的应用不再与操作系统通信，在macOS上，如果您点击您的应用，您会看到“死亡之轮”在旋转。而且，*没人*希望看到那个。

解决方案是将您的耗时任务从GUI线程移到另一个线程中。PySide6为此提供了一个直接的接口。

### 准备工作：一个最小的应用存根

为了演示多线程执行，我们需要一个可供操作的应用程序。下面是一个用于PySide6的最小应用存根，它将让我们能够演示多线程并亲眼看到结果。只需将此代码复制并粘贴到一个新文件中，并以适当的文件名保存，比如`multithread.py`。本教程的其余代码将添加到这个文件中。如果您等不及了，文末还有一个完整的可用示例：

```python
import time

from PySide6.QtCore import (
    QTimer,
)
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.counter = 0

        layout = QVBoxLayout()

        self.label = QLabel("Start")
        button = QPushButton("DANGER!")
        button.pressed.connect(self.oh_no)

        layout.addWidget(self.label)
        layout.addWidget(button)

        w = QWidget()
        w.setLayout(layout)
        self.setCentralWidget(w)

        self.show()

        self.timer = QTimer()
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.recurring_timer)
        self.timer.start()

    def oh_no(self):
        time.sleep(5)

    def recurring_timer(self):
        self.counter += 1
        self.label.setText(f"Counter: {self.counter}")

app = QApplication([])
window = MainWindow()
app.exec()
```

像运行任何其他Python应用程序一样运行这个应用：

```sh
$ python multithread.py
```

您会看到一个演示窗口，其中有一个数字在向上计数。这个计数是由一个简单的循环定时器生成的，每秒触发一次。您可以把这个看作是我们的*事件循环指示器*（或*GUI线程指示器*），它是一种简单的方式，让我们知道我们的应用程序正在正常运行。还有一个标有*“DANGER!”*的按钮。按下它。

您会注意到，每次您按下按钮，计数器就会停止跳动，您的应用程序会完全冻结。在Windows上，您可能会看到窗口变白，表示它没有响应；而在macOS上，您会得到“死亡之轮”。

### *错误*的方法

请避免在您的代码中这样做。

看起来像是界面*冻结*的现象，实际上是主Qt事件循环被阻塞，无法处理（和响应）窗口事件。您对窗口的点击仍然被宿主操作系统注册并发送到您的应用程序，但是因为程序正卡在您那一大块代码里（调用`time.sleep()`），它无法接受或响应这些点击。它们必须等到您的代码将控制权交还给Qt。

解决这个问题最快、也许也最符合逻辑的方法是在您的代码内部接受事件。这允许Qt继续响应宿主操作系统，您的应用程序将保持响应。您可以通过使用`QApplication`类上的静态方法`processEvents()`来轻松实现这一点。

例如，我们那个*耗时*的代码`time.sleep()`可以被分解成五个1秒的休眠，并在它们之间插入`processEvents()`。代码如下：

```python
def oh_no(self):
    for n in range(5):
        QApplication.processEvents()
        time.sleep(1)
```

现在，当您按下*DANGER!*按钮时，您的应用会像之前一样运行。然而，现在`QApplication.processEvents()`会间歇性地将控制权交还给Qt，并允许它正常响应事件。Qt会接受事件*并处理它们*，然后再返回继续运行您代码的其余部分。

这种方法虽然可行，但非常糟糕，原因有以下几点：

1.  当您将控制权交还给Qt时，您的代码就不再运行了。这意味着您试图做的任何耗时任务都会花费*更长*的时间。这绝对不是您想要的。
2.  当您的应用程序中有多个耗时任务，每个都调用`QApplication.processEvents()`来保持程序运行，您的应用程序的行为可能会变得不可预测。
3.  在主事件循环（`app.exec()`）之外处理事件会导致您的应用程序在您的循环内部跳转到处理代码（例如，用于被触发的槽或事件）。如果您的代码依赖于或响应外部状态，这可能会导致未定义的行为。

下面的代码演示了最后一点的实际情况：

```python
import time

from PySide6.QtCore import (
    QTimer,
)
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.counter = 0

        layout = QVBoxLayout()

        self.label = QLabel("Start")
        button = QPushButton("DANGER!")
        button.pressed.connect(self.oh_no)

        c = QPushButton("?")
        c.pressed.connect(self.change_message)

        layout.addWidget(self.label)
        layout.addWidget(button)
        layout.addWidget(c)

        w = QWidget()
        w.setLayout(layout)
        self.setCentralWidget(w)

        self.show()

        self.timer = QTimer()
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.recurring_timer)
        self.timer.start()

    def change_message(self):
        self.message = "OH NO"

    def oh_no(self):
        self.message = "Pressed"

        for n in range(100):
            time.sleep(0.1)
            self.label.setText(self.message)
            QApplication.processEvents()

    def recurring_timer(self):
        self.counter += 1
        self.label.setText(f"Counter: {self.counter}")

app = QApplication([])
window = MainWindow()
app.exec()
```

如果您运行这段代码，您会看到和之前一样的计数器。按下*DANGER!*会将显示的文本更改为`"Pressed"`，这是在`oh_no()`方法的入口点定义的。但是，如果您在`oh_no()`仍在运行时按下*"?"*按钮，您会看到消息发生了变化。状态正从您的事件循环外部被改变。

### 使用线程和进程

如果您退一步思考一下您希望应用程序中发生什么，那么您很可能会将其总结为“一些事情与其他事情同时发生”。

在PySide6应用程序中运行独立任务主要有两种方法：

1.  线程
2.  进程

**线程**共享相同的内存空间，因此它们启动速度快，消耗的资源最少。共享内存使得在线程之间传递数据变得微不足道。然而，从不同线程读取或写入内存可能会导致竞争条件或段错误。

在Python中，还有一个额外的问题，即多个线程受到全局解释器锁（GIL）的约束——这意味着非释放GIL的Python代码一次只能在一个线程中执行。然而，这对于PySide6来说不是一个主要问题，因为大部分时间都花在Python之外。

**进程**使用独立的内存空间和一个完全独立的Python解释器。它们避开了Python GIL的任何潜在问题，但代价是启动时间较慢、内存开销较大以及发送和接收数据的复杂性。

在Qt中，进程非常适合运行外部程序并与之通信。然而，为了简单起见，除非您有充分的理由使用进程（请参阅后面的[注意事项](#注意事项)），线程通常是最佳选择。

没有什么能阻止您在PySide6应用程序中使用纯Python的线程或基于进程的方法。不过，在接下来的部分中，您将依赖Qt的线程类。

#### `QRunnable` 和 `QThreadPool`

在您的代码中，请优先使用这种方法。

Qt为在其他线程中运行作业或任务提供了一个直接的接口，这在PySide6中得到了很好的支持。该接口围绕两个类构建：

1.  `QRunnable`：您想要执行的工作的容器。
2.  `QThreadPool`：您将该工作传递给备用线程的方法。

使用`QThreadPool`的巧妙之处在于，它为您处理了工作线程的排队和执行。除了将作业排队和检索结果之外，几乎没有什么需要做的。

要定义一个自定义的`QRunnable`，您可以子类化基类`QRunnable`。然后，将您希望执行的代码放在`run()`方法中。以下是我们那个耗时的`time.sleep()`作业作为`QRunnable`的实现。

请继续并将以下代码添加到`multithread.py`中，放在`MainWindow`类定义之上，并且不要忘记从`PySide6.QtCore`导入`QRunnable`和`Slot`：

```python
class Worker(QRunnable):
    """工作线程。"""

    @Slot()
    def run(self):
        """您耗时的工作应放在此方法中。"""
        print("线程开始")
        time.sleep(5)
        print("线程完成")
```

在另一个线程中执行我们耗时的工作，只需创建一个`Worker`的实例并将其传递给我们的`QThreadPool`实例。它将自动被执行。

接下来，从`PySide6.QtCore`导入`QThreadPool`，并将以下代码添加到`__init__()`方法中以设置我们的线程池：

```python
self.threadpool = QThreadPool()
thread_count = self.threadpool.maxThreadCount()
print(f"使用最多 {thread_count} 个线程进行多线程处理")
```

最后，按如下方式更新`oh_no()`方法：

```python
def oh_no(self):
    worker = Worker()
    self.threadpool.start(worker)
```

现在，点击*DANGER!*按钮将创建一个工作线程来处理（耗时的）作业，并通过线程池将其分派到另一个线程中。如果没有足够的可用线程来处理传入的工作线程，它们将被排队并在稍后按顺序执行。

试一试，您会发现您的应用程序现在可以毫无问题地处理您猛击按钮的情况。

检查一下如果您多次点击按钮会发生什么。您应该看到您的线程立即被执行，*最多*达到`maxThreadCount()`报告的数量。如果在已经有这个数量的活动工作线程之后您再次按下按钮，那么后续的工作线程将被排队，直到有线程可用为止。

### 改进的 `QRunnable`

如果您想将自定义数据传递给运行函数，您可以通过`__init__()`来实现，然后在`run()`槽内部通过`self`访问这些数据：

```python
class Worker(QRunnable):
    """工作线程。

    :param args: 提供给运行代码的参数
    :param kwargs: 提供给运行代码的关键字参数
    """

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.args = args
        self.kwargs = kwargs

    @Slot()
    def run(self):
        """使用传入的 self.args, self.kwargs 初始化运行函数。"""
        print(self.args, self.kwargs)
```

我们可以利用Python中函数是对象的这一事实，传入要执行的函数，而不是为每个运行函数都子类化`QRunnable`。在下面的构造中，我们只需要一个`Worker`类来处理我们所有的作业：

```python
class Worker(QRunnable):
    """工作线程。

    继承自 QRunnable 以处理工作线程的设置、信号和收尾工作。

    :param callback: 在此工作线程上运行的函数回调。
                     提供的 args 和 kwargs 将被传递给运行函数。
    :type callback: function
    :param args: 传递给回调函数的参数
    :param kwargs: 传递给回调函数的关键字参数
    """

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    @Slot()
    def run(self):
        """使用传入的 args, kwargs 初始化运行函数。"""
        self.fn(*self.args, **self.kwargs)
```

您现在可以传入任何Python函数，并让它在一个单独的线程中执行。请继续并用以下代码更新`MainWindow`：

```python
def execute_this_fn(self):
    print("Hello!")

def oh_no(self):
    # 传入要执行的函数
    worker = Worker(
        self.execute_this_fn
    )  # 任何其他的 args, kwargs 都会被传递给 run 函数
    # 执行
    self.threadpool.start(worker)
```

现在，当您点击*DANGER!*时，应用程序将在您的终端打印`Hello!`而不会影响计数器。

### 线程的输入/输出

有时，能够从正在运行的工作线程中传回*状态*和*数据*是很有帮助的。这可能包括计算的结果、引发的异常或进行中的进度（也许用于进度条）。Qt提供了*信号和槽*框架，让您能够做到这一点。Qt的信号和槽是线程安全的，允许从正在运行的线程直接安全地通信到您的GUI线程。

*信号*允许您发出值，这些值随后会被您代码中其他地方通过`connect()`方法连接的*槽*函数接收。

下面是一个自定义的`WorkerSignals`类，定义了包含多个示例信号。请注意，自定义信号只能在派生自`QObject`的对象上定义。由于`QRunnable`不是派生自`QObject`，我们不能直接在那里定义信号。一个自定义的`QObject`来持有这些信号是一个快速的解决方案：

```python
class WorkerSignals(QObject):
    """来自正在运行的工作线程的信号。

    finished
        无数据

    error
        元组 (exctype, value, traceback.format_exc())

    result
        从处理中返回的对象数据，可以是任何类型
    """

    finished = Signal()
    error = Signal(tuple)
    result = Signal(object)
```

在这段代码中，我们定义了三个自定义信号：

1.  `finished`，它不接收数据，旨在指示任务何时完成。
2.  `error`，它接收一个`tuple`，包含`Exception`类型、`Exception`值和格式化的回溯信息。
3.  `result`，它接收从执行的函数返回的任何`object`类型。

您可能不需要所有这些信号，但包含它们是为了展示可能性。在下面的代码中，我们将实现一个利用这些信号来为用户提供有用信息的耗时任务：

```python
class Worker(QRunnable):
    """工作线程。

    继承自 QRunnable 以处理工作线程的设置、信号和收尾工作。

    :param callback: 在此工作线程上运行的函数回调。
                     提供的 args 和
                     kwargs 将被传递给运行函数。
    :type callback: function
    :param args: 传递给回调函数的参数
    :param kwargs: 传递给回调函数的关键字参数
    """

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @Slot()
    def run(self):
        """使用传入的 args, kwargs 初始化运行函数。"""

        # 在这里检索 args/kwargs；并使用它们触发处理
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)  # 返回处理结果
        finally:
            self.signals.finished.emit()  # 完成
```

您可以将自己的处理函数连接到这些信号，以接收线程完成（或结果）的通知：

```python
def execute_this_fn(self):
    for n in range(0, 5):
        time.sleep(1)
    return "Done."

def print_output(self, s):
    print(s)

def thread_complete(self):
    print("线程完成！")

def oh_no(self):
    # 传入要执行的函数
    worker = Worker(
        self.execute_this_fn
    ) # 任何其他的 args, kwargs 都会被传递给 run 函数
    worker.signals.result.connect(self.print_output)
    worker.signals.finished.connect(self.thread_complete)
    # 执行
    self.threadpool.start(worker)
```

您通常还希望从耗时线程接收状态信息。这可以通过传入*回调*函数来实现，您正在运行的代码可以向这些回调函数发送信息。您这里有两个选择：

1.  定义新的信号，允许使用事件循环进行处理
2.  使用常规的Python函数

在这两种情况下，您都需要将这些回调函数传入您的目标函数才能使用它们。基于信号的方法在下面的完整代码中使用，我们传回一个`float`作为线程进度的百分比指示器。

### 完整的代码

下面给出了一个完整的可用示例，展示了自定义的`QRunnable`工作线程以及工作线程和进度信号。您应该能够轻松地将此代码改编到您开发的任何多线程应用程序中：

```python
import sys
import time
import traceback

from PySide6.QtCore import (
    QObject,
    QRunnable,
    QThreadPool,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

class WorkerSignals(QObject):
    """来自正在运行的工作线程的信号。

    finished
        无数据

    error
        元组 (exctype, value, traceback.format_exc())

    result
        从处理中返回的对象数据，任何类型

    progress
        浮点数，表示进度百分比
    """

    finished = Signal()
    error = Signal(tuple)
    result = Signal(object)
    progress = Signal(float)

class Worker(QRunnable):
    """工作线程。

    继承自 QRunnable 以处理工作线程的设置、信号和收尾工作。

    :param callback: 在此工作线程上运行的函数回调。
                     提供的 args 和
                     kwargs 将被传递给运行函数。
    :type callback: function
    :param args: 传递给回调函数的参数
    :param kwargs: 传递给回调函数的关键字参数
    """

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        # 将回调添加到我们的 kwargs 中
        self.kwargs["progress_callback"] = self.signals.progress

    @Slot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()

class MainWindow(QMainWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.counter = 0

        layout = QVBoxLayout()

        self.label = QLabel("Start")
        button = QPushButton("DANGER!")
        button.pressed.connect(self.oh_no)

        layout.addWidget(self.label)
        layout.addWidget(button)

        w = QWidget()
        w.setLayout(layout)
        self.setCentralWidget(w)

        self.show()

        self.threadpool = QThreadPool()
        thread_count = self.threadpool.maxThreadCount()
        print(f"使用最多 {thread_count} 个线程进行多线程处理")

        self.timer = QTimer()
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.recurring_timer)
        self.timer.start()

    def progress_fn(self, n):
        print(f"{n:.1f}% 完成")

    def execute_this_fn(self, progress_callback):
        for n in range(0, 5):
            time.sleep(1)
            progress_callback.emit(n * 100 / 4)

        return "Done."

    def print_output(self, s):
        print(s)

    def thread_complete(self):
        print("线程完成！")

    def oh_no(self):
        # 传入要执行的函数
        worker = Worker(
            self.execute_this_fn
        )  # 任何其他的 args, kwargs 都会被传递给 run 函数
        worker.signals.result.connect(self.print_output)
        worker.signals.finished.connect(self.thread_complete)
        worker.signals.progress.connect(self.progress_fn)
        # 执行
        self.threadpool.start(worker)

    def recurring_timer(self):
        self.counter += 1
        self.label.setText(f"Counter: {self.counter}")

app = QApplication([])
window = MainWindow()
app.exec()
```

### 注意事项

您可能已经发现了这个宏伟计划中的一个小小缺陷——我们仍然在使用事件循环（和GUI线程）来处理我们工作线程的输出。

当我们只是跟踪进度、完成情况或返回元数据时，这不是问题。但是，如果您的工作线程返回大量数据——例如，加载大文件、执行复杂分析并需要（大量）结果，或查询数据库——通过GUI线程传回这些数据可能会导致性能问题，最好避免这样做。

同样，如果您的应用程序使用大量线程和Python结果处理程序，您可能会遇到GIL的限制。如前所述，当使用线程时，Python代码的执行一次仅限于一个线程。处理来自您线程的信号的Python代码可能会被您的工作线程阻塞，反之亦然。由于阻塞您的槽函数会阻塞事件循环，这会直接影响GUI的响应性。

在这些情况下，研究使用纯Python的线程池（例如 concurrent futures）来使您的处理和线程事件处理与您的GUI进一步隔离通常会更好。但是，请注意，*任何*Python GUI代码都可能阻塞其他Python代码，除非它在一个单独的进程中。