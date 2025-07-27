# IDAPython cheatsheet

## Important links

* [Porting IDAPython plugins to IDA 7.4](https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml)
* [Hex-Rays IDAPython official documentation](https://www.hex-rays.com/products/ida/support/idapython_docs/)

## Basic commands

### Get informations on the binary

```python
info = idaapi.get_inf_structure()
filename = idaapi.get_input_file_path()
entrypoint = info.start_ip
imagebase = ida_nalt.get_imagebase()
is_64bits = info.is_64bit()
is_dll = info.is_dll()
proc_name = ida_ida.inf_get_procname()
```

### List adresses of the instructions

```python
for ea in idautils.Heads():
  print(hex(ea))
```

### Cross-references from address

```python
for ref in idautils.XrefsTo(ea):
  print(hex(ref.frm))
```

### Address name

```python
idaapi.get_name(0, ea)
idaapi.get_name_ea(0, name) # name = "main" for example

for ea, name in idautils.Names():
  print("%x: %s" % (ea, name))
```
  
### Read/Write bytes

```python
# check the return value with the constant ida_idaapi.BADADDR
idaapi.get_byte(ea)
idaapi.get_bytes(ea, size)
```

```python
idaapi.patch_byte(ea, byte)
idaapi.patch_bytes(ea, bytes)
```

### Read address referenced by a pointer

```python
def read_ptr(ea):
  if idaapi.get_inf_structure().is_64bit():
    return idaapi.get_qword(ea)
  return idaapi.get_dword(ea)

print("%x" % read_ptr(ea))
```

### Read string

```python
ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C)
ida_bytes.get_strlit_contents(ea, size, ida_nalt.STRTYPE_C_16)
for c in idautils.Strings()
  print s.ea, s.length, s.strtype
```

### Get current widget 

```python
widget = idaapi.get_current_widget()
widget_type = idaapi.get_widget_type(widget) # can be any of ida_kernwin.BWN_*
vdui = idaapi.get_widget_vdui(widget)
```

### Comments

```python
# set non-repeatable comment
idc.get_cmt(ea, False)
# get repeatable comment
idc.get_cmt(ea, True)
# get func cmt
idc.get_func_cmt(ea, repeatable)
```

```python
# set non-repeatable comment
idc.set_cmt(ea, comment, 0)
# set repeatable comment
idc.set_cmt(ea, comment, 1)
# set func cmt
idc.set_func_cmt(ea, comment, repeatable)
```

## Play with segments

### List segments

```python
for s in idautils.Segments():
    start = idc.get_segm_start(s)
    end = idc.get_segm_end(s)
    name = idc.get_segm_name(s)
    data = ida_bytes.get_bytes(start, end-start)
```

### Add segment

```python
max_ea = idaapi.inf_get_max_ea() # get last segment end address
idaapi.add_segm(0, start_ea, end_ea, name, sclass) # sclass can be one of "CODE", "DATA", "BSS", "STACK", "XTRN", "CONST", "ABS" or "COMM"
```

## Play with structures and types

### Create a structure

```python
name = "my_super_structure"
struct_id = idc.add_struc(0, name, 0)
```

### Get a structure from its name

```python
struct_id = idaapi.get_struc_id(name)
if struct_id == idaapi.BADADDR:
    print("Structure {} does not exist".format(name))
```

### Get structure from structure id

```python
struct = idaapi.get_struc(struct_id)
```

### Add member to structure

```python
# add dword
idc.add_struc_member(struct_id, member_name, member_offset, idaapi.FF_DWORD, -1, 4) 
```

### Set type of structure member

```python
# define type
tinfo = idaapi.tinfo_t()
[...]
member = idaapi.get_member_by_name(struct, member_name)
if idaapi.set_member_tinfo(struct, member, 0, tinfo, 0) == idaapi.SMT_OK:
    print("Member type successfully modified !")
```

### Apply a structure on a specific EA

```python
idaapi.apply_tinfo(ea, tinfo, idaapi.TINFO_DEFINITE)
```

## Play with functions

### Get a function

```python
f = ida_funcs.get_func(ea)
print("%x %x" % (f.start_ea, f.end_ea))
print(ida_funcs.get_func_name(ea)) # not necessarily the start ea

for ea in Functions():
  print("%x" % ea)
```

### Search a mnemonic in a function

```python
f = ida_funcs.get_func(ea)
for ea in Heads(f.start_ea, f_end_ea):
  insn = idaapi.insn_t()
  length = idaapi.decode_insn(insn, ea)
  if insn.itype == ida_allins.NN_call:
    print("Call at %x" % ea)
  # also works to search for call instructions
  if ida_idp.is_call_insn(insn):
    print("Call at %x" % ea)
```

### Get the type and the value of an operand

```python
# Get mov instructions to memory adresses
f = ida_funcs.get_func(ea)
for ea in Heads(f.start_ea, f_end_ea):
  insn = idaapi.insn_t()
  length = idaapi.decode_insn(insn, ea)
  if insn.itype != ida_allins.NN_mov:
    continue
  if insn.ops[1].type == ida_ua.o_mem:
    print("Data is moved at addr %x" % insn.ops[1].value)
```

Types returned by GetOpType:
* o_void: no operand
* o_reg: register
* o_mem: known address
* o_phrase, o_displ: pointers to adresses
* o_imm: constant value

### Look for assembly code

```python
f = ida_funcs.get_func(ea)
for ea in idautils.Heads(f.start_ea, f_end_ea):
  insn = idaapi.insn_t()
  length = idaapi.decode_insn(insn, ea)
  if insn.itype != ida_allins.NN_xor and insn.ops[0].reg == idautils.procregs.ecx and insn.ops[1].reg == idautils.procregs.ecx:
    print("Found at addr %x" % ea)
```

### Get prototype of an imported function

```python
# get import function prototype
import_prototype = idaapi.get_named_type(None, 'WriteFile', 0)

# deserialize import function prototype
import_tif = idaapi.tinfo_t()
import_tif.deserialize(None, import_prototype[1], import_prototype[2])

# create a pointer to the import function type
ptr_import_tif = idaapi.tinfo_t()
ptr_import_tif.create_ptr(import_tif)
```

## GUI

### Read selected code

```python
_, start, end = idaapi.read_range_selection(None)
for ea in idautils.Heads(start, end):
    insn = idaapi.insn_t()
    length = idaapi.decode_insn(insn, ea)
```

## Debugger

### Launch the debugger

```python
ida_dbg.add_bpt(ea, 1, ida_idd.BPT_DEFAULT)
ida_dbg.start_process("/path/to/exe", "-q 1", "/path/to")
# bp reached
ida_dbg.continue_process()
ida_dbg.exit_process()
```

Breakpoint types:
* BPT_WRITE = 1
* BPT_READ = 2
* BPT_RDWD = 3
* BPT_SOFT = 4
* BPT_EXEC = 8
* BPT_DEFAULT = BPT_SOFT|BPT_EXEC

### Get a memory value

```python
rv = ida_idd.regval_t()
ida_dbg.get_reg_val("ECX", rv)
print(hex(rv.ival))
print(hex(idautils.cpu.ecx))
```

### Add a script in a breakpoint

1. Add a breakpoint 
2. Right click > Edit breakpoint
3. Click on the button at the right of Condition
4. Change the scripting language to Python
5. Write the code in the text zone

### Call a function of the debuggee

```python
# test check_passwd(char *passwd) -> int
passwd = ida_idd.Appcall.byref("MyFirstGuess")
res = ida_idd.Appcall.check_passwd(passwd)
if res.value == 0:
  print("Good passwd !")
else:
  print("Bad passwd...")
```

Other examples: http://www.hexblog.com/?p=113

https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c