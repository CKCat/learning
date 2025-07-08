# idatips

## ida 直接将某一条指令强行解释为函数调用

操作方法

1. 选中 syscall 指令
2. 菜单：`Edit -> Other -> Decompile as call` 输入如下定义:

```c
int __usercall mycall@<rax>(int num@<rax>);
```

## 修复枚举值

选中数字，安快捷键 `M` 选中对应的枚举。

## positive sp value

菜单：`Options -> General -> Stack pointor`，勾选该选项。

选中汇编代码最右侧的堆栈值，点击工具栏的 A 菜单，锁住当前的高亮值，找到值不同的地方，
分析是否为垃圾指令，如果是垃圾指令，NOP 掉相应的指令，然后使用快捷键 u 取消定义，使用
快捷键 c 重新定义为代码，最后使用快捷键 p 重新创建为函数。

## switch 跳转表

菜单：`Edit -> Other -> Specify switch idiom`，修改 Address of jump talbe 为实际位置，
修改 Number of elements 、 Size of table element 、Element base value 、Start of the switch idiom 为相应的值即可。

## IDA Python 脚本编程

添加 PYTHONPATH 环境变量，值为 ida 安装路径下 python 目录的完整路径，如： `D:\ida91\python` 。

或者在 vscode 中创建 `.vscode/settings.json` 文件，写入下列内容：

```json
{
  "python.analysis.extraPaths": ["D:/ida91/python"]
}
```

### 寄存器接口

```python
idc.get_reg_value("rax")
idaapi.set_reg_val("rax", 1234)
```

命中断点时才可以操作

## 调试内存/本地内存接口

调试内存：

```python
idc.read_dbg_byte(addr)
idc.read_dbg_memory(addr, size)
idc.read_dbg_dword(addr)
idc.read_dbg_qword(addr)
idc.patch_dbg_byte(addr, val)
```

调试内存读写封装

```python
def patch_dbg_mem(addr, data):
    for i in range(len(data)):
        idc.patch_dbg_byte(addr + i, data[i])
def read_dbg_mem(addr, size):
    dd =[]
    for i in range(size):
        dd.append(idc.read_dg_byte(addr + i))
    return bytes(dd)
```

本地内存操作(会修改 idb 数据库)

```python
idc.get_qword(addr)
idc.patch_qword(addr, val)
idc.patch_dword(addr, val)
idc.patch_word(addr, val)
idc.patch_byte(addr, val)
idc.get_db_byte(addr)
idc.get_bytes(addr, size)
```

反汇编操作

```python
GetDisasm(addr)#获取反汇编文本
idc.next head(ea)#获取下一条指令地址
```

交叉引用分析

```python
for ref in idautils.XrefsTo(ea):
    print(hex(ref.frm))
```

交叉引用批量设置 o-1lvm 断点

批量断点设置

```python
fn = 0x401F60
ollvmhtail =0x405D4B#ollvm 真实块的汇集点
f_blocks = idaapi.Flowchart(idaapi.get func(fn), flags=idaapi.FC_PREDS)
for block in f_blocks:
    for succ in block.succs():
        if succ.start_ea= ollvm_tail:
            print(hex(block.start_ea))
            idc.add* bpt(block.start_ea)
```

注意:判断真实块的依据是查找 o11vm 汇集点基本块的交叉引用，不一定准确
提示:批量断点可以用 IDA 的断点分组管理

杂项常用接口

```python
idc.add_bpt(0x409437)添加断点
idaapi.get_imagebase()获取基地址
idc.create_insn(addr)# c, Make Code
ida_funcs.add_func(addr)#p,create function
ida_bytes.create_strlit(addr)#创建字符串，A 键效果
```

函数遍历

```python
for func in idautils.Functions():
    print("0x%x，%s"%(func,idc.get func_name(func)))
```

基本块遍历

```python
fn= 目标函数地址
f blocks = idaapi.Flowchart(idaapi.get_func(fn),flags=idaapi.FC_PREDS)
    for block in f blocks:
        print hex(block.start_ea)
# 基本块的前驱
for pred in block.preds(:
    print hex(pred.start_ea)
#基本块的后继
for succ in block.succs():
    print hex(succ.start_ea)
```

指令遍历

```python
for ins in idautils.FuncItems(0x401000):
    print(hex(ins))
```

调试接口
条件断点脚本

```python
def bp():
    rax =idc.get_reg_value('rax')
    if rax == 1234:
        return True
```

条件断点脚本编写 0.编写断点函数脚本，并在 IDA 底部导入该函数 
1. 设置普通断点，在 call rand 之后设置(此时能获取 rand 的返回值) 
1. 点击断点位置，右键 -> Edit Breakpoint 
1. 点击 Condition -> [...]
1. 输入 bp()，并选择语言为 Python

条件断点函数返回 False，IDA 不会命中该断点，利用这个特性提取运行时数据

```python
def bp():
    print(idc.get_reg_value('rax'))
    return False
```

## Microcode 原理与例子

Microcode 快速上手，手动调用 microcode 生成

```python
class udc_exit_t(ida_hexrays.udc_filter_t):
    def init (self, code, name):
        ida_hexrays.udc_filter_t. init (self)
        if not self.init("int usercall %s@<R0>(int status@<R1>);"% name):
        raise Exception("Couldn't initialize udc exit t instance")
        self.code = code
        self.installed = False
    def match(self, cdg):
        return cdg.insn.itype == ida_allins.ARM_svc and cdg.insn.Op1.value == self.code
    def install(self):
        ida_hexrays.install_microcode filter(self, True);
        self.installed = True
    def uninstall(self):
        ida_hexrays.install_microcode filter(self, False);
        self.installed = False
    def toggle_install(self):
        if self.installed:
            self.uninstall()
        else:
            self.install()
```

实现 svc0x900001 与 svc 0x9000F8 指令反编译成一条 ca1l 指令

`install_microcode_filter` 注册 `microcode_filter` 实现拦截指令翻译

`microcode_filter` 是一种可以拦截 microcode 指令生成的机制，开发者需要继承
`microcode_filter_t` 类并实现 match 与 apply 两个数。

ida 在生成某一条指令的 microcode 之前会调用所有已经注册的 filter 的 match 函数，若
match 函数返回 True，则调用对应的 apply 函数实现指令替换。

我们需要将 svc 指令替换成 cal1 指令，ida 已经为我们实现了替换类 `udc_filter_t`，这个类
继承于 `microcode_filter_t` 并实现了 apply 方法(即替换 ca11 指令)，我们需要继承
`udc_filter_t` 并实现它的 match 方法用于判断拦截的指令。

## Hexrays Hooks

实现 IDA 的回调类的不同事件的回调方法，获得不同事件

```python
class MicrocodeCallback(ida_hexrays.Hexrays_Hooks):
    def init (self,*args)
        super()._init_(*args)
    def microcode(self,mba: ida_hexrays.mba_t) ->"int":
        print("microcode generated.")
        return 0
r= Microcodecallback()
r.hook()
```

上面的例子是获取 Microcode 生成成功的回调，此时可以修改
调试时，可以直接复制到 ida 底部运行，再次调试时先调用 r.unhook()卸载
其余回调可以参考文档中 Hexrays_Hooks 的方法

## stl
### std::string
- 固定长度32字节，4个dq
- 第一个指针字段指向数据地址
- 第二个sizet字段存储字符串长度

std::string内存布局
```c

struct basic_string{
    char *begin_;// actual string data
    size_t size_; // actual size
    union{
        size_t capacity_;// used if larger than 15 bytes
        char sso_buffer[16];// used if smaller than 16 bytes
    }
}
```
std::string IDA dump 脚本
```python
def dbg_read_cppstr_64(objectAddr):
    # A easy function for read std::string
    strPtr = idc.read_dbg_qword(objectAddr
    result = ''
    i =0
    while True:
        onebyte =idc.read_dbg_byte(strPtr + i)
        if onebyte=0:
            break
        else:
            result += chr(onebyte)
            i += 1
    return result
```
### std::stringsteam
- 字符串流(理解成文件流，有读写指针)
- 输入流/输出流

std::stringsteam内存布局
```c
struct stringsteam{
    void *vtable1;//std::basic stringstream
    int64 pad;
    void *vtable2;// std::basic_stringstream
    void * vtable3;// std::stringbuf
    char *_M_in_beg; // 输入流开始
    char *_M_in_cur;
    char *_M_in_end;
    char *_M_out_beg;// 输出流开始
    char *_M_out_cur;
    char *_M_out_end;
    //...其余字段不关心
}
```

### std::vector
- 固定长度24字节，3个dq
- 第一个指针字段指向数组起始地址
- 第二个指针字段指向数组最后元素地址
- 第三个指针字段指向最大内存地址

std::vector 内存布局
```c
// Stores Point objects
struct vector{
    void* start;
    void* end;
    void* max;
};
```
std::vector IDA dump 脚本
```python
def dump_vector(addr):
    """Dump a vector of type std::vector<type> GNU C++ x64"""
    ELEMENT SIZE =8
    data_addr =[]
    vector_base = idc.read_dbg_qword(addr + 0x0)
    vector_end = idc.read_dbg_qword(addr + 0x8)
    for i in range(vector_base, vector_end, ELEMENT_SIZE):
        data_addr.append(i)
    return data_addr
```

### std::list
- 双向循环链表存储
- 头结构+节点结构
- 遍历长度可以用size字段确定

```c
std::list 内存布局
struct List_node{
    List_node* next;
    List _node* prev;
    // 数据区域

};

struct List_node_header{
    List_node* next;
    List_node* prev;
    size_t SIZE;
};

```
std::list IDA dump 脚本
```python
import idc
def dump_stl list(p_list_header):
    """Dump a list of type std::list<type> GNu C++ x64"""
    data_addr =[]
    list_size = idc,read_dbg_qword(p_list_header + 0x10)
    cur_node =p_list_header
    for i in range(list_size):
        cur_node =idc.read_dbg_qword(cur_node + 0x0)
        data_addr.append(cur_node + 0x10)
    return data_addr
```

### std::deque
- 头结构+迭代器结构
- 适用 std::deque/std::stack
- stl_deque.start.node 确定first map 项位置
- stl_deque.start.last - stl_deque.start.first 确定缓冲区大小
- stl_deque.finish.node 确定last map 项位置
- 对于每一个 map 项:
    - start项，解析cur，last区间
    - finish项，解析 start，cur 区间
    - 其余项，解析 start，last区间

std::deque 内存布局
```c
struct stl_deque_iterator {
    void * cur;
    void * first;
    void * last;
    void * node;    // 指向 map 数组的中地址，可以用来索引到下一个数组
};
struct stl_deque {
    void * map;    //连续数组的起始地址数组
    size_t map_size;
    stl_deque_iterator start;
    stl_deque_iterator finish;
};
```
std::deque IDA dump 脚本
```python
from collections import namedtuple
deque_iter = namedtuple('deque_iter',['cur', 'first', 'last', 'node'])
def parse_iter(addr):
    """Parse a deque iterator"""
    cur =idc.read_dbg_qword(addr +0x0)
    first = idc.read_dbg_qword(addr + 0x8)
    last = idc.read_dbg_qword(addr + 0x10)
    node = idc.read_dbg_qword(addr + 0x18)
    return deque_iter(cur, first, last, node)

def dump_deque(addr):
    ELEMENT_SIZE=4 #std::deque<xx> xx 的类型大小来指定
    data_addr=[]
    start_iter = parse_iter(addr + 0x10)
    finish_iter = parse_iter(addr + 0x30)
    buf_size =start_iter.last- start_iter.first
    map_start = start_iter.node
    map_finish = finish_iter.node
    #parse first buffer data
    for i in range(start_iter.cur, start_iter.last, ELEMENT SIZE):
        data_addr.append(i)
    # parse last buffer data
    for i in range(finish_iter.finst  finish_iter.cur, ELEMENT_SIZE):
        data_addr.append(i)
    #parse middle buffer data
    for b in range(map_start +8,map finish-8,8):
        buf_start = idc.read_dbg qword(b)
    for i in range(buf_start, buf_start + buf_size, ELEMENT_SIZE):
        data_addr.append(i)
    return data_addr
```

### std::map
- 底层采用Rb-Tree 实现(红黑二叉树)
- 头结构+节点结构
- 用二叉树遍历可提取数据
- 适用 std::map /std::set /std::multimap / std::multiset

std::map 内存布局
```c
struct std::map {
    void* allocator; // ignore
    _Rb_tree_color _M_color; // ignore
    node * root;
    node * leftmost;//ignore
    node *rightmost;//ignore
    size_t node_count;
};
struct node {
    _Rb_tree_color color;
    node* parent;
    node* left;
    node* right;
    TypeKey key; // data area
    TypeValue value;
}
```
std::map IDA dump 脚本
```python
# parse gnu c+ stlmap
def parse_gnu_map_header(address):
    root = idc,read_dbg_qword(address + 0x10)
    return root

def parse_gnu_map_node(address):
    left = idc.read_dbg_qword(address + 0x10)
    right = idc.read_dbg_qword(address + 0x18)
    data = address + 0x20
    return left, right, data

def parse_gnu_map_travel(address):
    # address<std::map struct address
    result =[]
    worklist =[parse_gnu_map_header(address)]
    while len(worklist)>0:
        addr = worklist.pop()
        (left,right,data)= parse_gnu_map_node(addr)
        if left >0:worklist.append(left)
        if right >0:worklist.append(right)
        result.append(data)
    return result
```

### std:.unsorted map
- 底层采用 HashTable 实现
- 头结构+Bucket 数组+节点结构
- 所有节点结构用单链表串联(dump只需要遍历单链表)
- 头结构的第三个字段为单链表头
- 适用 std::unsorted_map /std::unsorted_set 

std::unsorted map 内存布局
```c
strcut bucket {
    bucket *next;// 最后一个node为null
    valtype val;
    size_t hash;
};
struct hashmap {
    bucket * buckets;
    size_t buckets_count;    // 桶的数量
    bucket * first; //M_before_begin
    size_t elements_count;// 元素的个数
};
```

std::unsorted map IDA dump 脚本
```python
def dump_stl_hashmap(addr):
    """dump stl hashmap gnu c+ x64"""
    data_addr = []
    bucket_addr = idc.read_dbg_qword(addr + 0x10)
    node_addr = bucket_addr
    while node_addr ≠0:
        data_addr.append(node_addr + 0x8)
        node_addr = idc.read_dbg_qword(node_addr)
    return data_addr
```
### std::shared ptr
第一个指针就是数据指针
std::shared ptr 内存布局
```c

struct Sp_counted {
    void *vt;// 指向虚表，Sp_counted
    int use_count;
    int weak_count;
}
struct shared_ptr {
    void * ptr;
    Sp_counted * refcount;
}
```


调试 fork 时，将进入子进程的代码改成无限循环，然后进入里面恢复原来的指令进行调试。

调试修改过的标准算法时，和标准算法对比每一轮的输出，从而判断修改的逻辑。