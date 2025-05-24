**AIDL（Android Interface Definition Language）是一种 IDL 语言，用于生成可以在 Android 设备上两个进程之间进行进程间通信（IPC）的代码。** 通过 AIDL，可以在一个进程中获取另一个进程的数据和调用其暴露出来的方法，从而满足进程间通信的需求。通常，暴露方法给其他应用进行调用的应用称为服务端，调用其他应用的方法的应用称为客户端，客户端通过绑定服务端的 Service 来进行交互。

# 定义 AIDL 接口

使用 Java 编程语言语法在 `.aidl` 文件中定义 AIDL 接口，然后将其保存在服务端应用以及任何使用该服务的客户端应用的源代码（在 `src/` 目录中）内。

在构建每个包含 `.aidl` 文件的应用时，Android SDK 工具会生成基于该 `.aidl` 文件的 `IBinder` 接口，并将其保存到项目的 `gen/` 目录中。服务端应用必须视情况实现 `IBinder` 接口。然后，客户端应用便可绑定到该服务，并调用 `IBinder` 中的方法来执行 IPC。

## 创建 `.aidl` 文件

在 Android Studio 中创建一个 Android 项目，修改 `build.gradle.kts` 文件，添加下列内容：

```kotlin
android {
    ...
    buildFeatures{
        aidl=true
    }
    ...
}
```

这样才能右键点击新建一个 AIDL 文件，如图所示：

![](16-AIDL/create_aidl_file.png)

创建完成后，系统就会默认创建一个 aidl 文件夹，文件夹下的目录结构即是工程的包名，AIDL 文件就在其中。如图所示：

![](16-AIDL/aidl_file_sample.png)

文件中会有一个默认方法，可以删除掉，也可以新增其他方法。每个 `.aidl` 文件都必须定义一个接口，并且只需要接口声明和方法签名。

默认情况下，AIDL 支持下列数据类型：

- Java 编程语言中的所有基元类型（如 `int、long、char、boolean` 等）
- 任何类型的数组，例如 `int[]` 或 `MyParcelable[]`
- `String` 类型。
- `CharSequence` 类型。
- `List` 类型，`List` 中的所有元素都必须是以上列表中支持的数据类型。
- `Map` 类型，`Map` 中的所有元素都必须属于此列表支持的数据类型。实际客户端和服务端接收的数据类型都为 `HashMap` 。

## 实现接口
当构建应用时，Android SDK 工具会生成一个以 `.aidl` 文件命名的 `.java` 接口文件。生成的接口包含一个名为 `Stub` 的子类，该子类是其父接口（例如 `IRemoteService.Stub`）的抽象实现，并且会声明 `.aidl` 文件中的所有方法。

# 参考

https://developer.android.com/develop/background-work/services/aidl?hl=zh-cn#kotlin
