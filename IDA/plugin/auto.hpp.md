
# auto.hpp 文件参考

Functions that work with the autoanalyzer queue.
用于自动分析队列的函数。

The autoanalyzer works when IDA is not busy processing the user keystrokes. It has several queues, each queue having its own priority. The analyzer stops when all queues are empty.
自动分析器在 IDA 不忙于处理用户按键时工作。它有多个队列，每个队列都有自己的优先级。当所有队列都清空时，分析器停止工作。

A queue contains addresses or address ranges. The addresses are kept sorted by their values. The analyzer will process all addresses from the first queue, then switch to the second queue and so on. There are no limitations on the size of the queues.
队列包含地址或地址范围。地址按其值排序。分析仪将处理第一个队列中的所有地址，然后切换到第二个队列，依此类推。队列的大小没有限制。

This file also contains functions that deal with the IDA status indicator and the autoanalysis indicator. You may use these functions to change the indicator value.
该文件还包含处理 IDA 状态指示器和自动分析指示器的函数。您可以使用这些函数来更改指示器值。
