# Frida高级逆向

## Trace

```js
function main(){
var base hello jni = Module.findBaseAddress("libhello-jni.so");
var sub 1CFF0=base hello jni.add(0x1CFF0);
Interceptor.attach(sub 1CFF，{
onEnter :function(args)f
this.arg0 = args[0];
this.argl = args[1];
this.arg2 = args[2];
onLeave :function(retval)f
，
co log(...data: any[l):void xdump(this.arg0, {length : parseInt(this.arg1)})
“\Hy)
setImmediate(main);
```

定位到关键算法，使用 frida 调用，只需要分析这个函数。将函数的结尾地址写到调用它的后面地址

IDA 附加进程

如果有多个线程，则先挂起其他线程，然后在执行start_hook

首先找到写入返回值的地址，