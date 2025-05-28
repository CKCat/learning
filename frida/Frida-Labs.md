https://github.com/DERE-ad2001/Frida-Labs

# Frida 0x1

使用 jadx 反编译 `MainActivity` 类的代码如下：

```java
public class MainActivity extends AppCompatActivity {
    TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        final EditText editText = (EditText) findViewById(R.id.editTextTextPassword);
        Button button = (Button) findViewById(R.id.button);
        this.t1 = (TextView) findViewById(R.id.textview1);
        final int i = get_random();
        button.setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.frida0x1.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                String obj = editText.getText().toString();
                if (TextUtils.isDigitsOnly(obj)) { // isDigitsOnly 参数是空字符串也会返回 true，下面的 parseInt 就会异常。
                    MainActivity.this.check(i, Integer.parseInt(obj));
                } else {
                    Toast.makeText(MainActivity.this.getApplicationContext(), "Enter a valid number !!", 1).show();
                }
            }
        });
    }

    int get_random() {
        return new Random().nextInt(100); // 生成一个介于 0 (包含) 到 100 (不包含) 之间的随机整数。
    }

    void check(int i, int i2) {
        if ((i * 2) + 4 == i2) { // 随机数 *2 +4 == 输入的值
            Toast.makeText(getApplicationContext(), "Yey you guessed it right", 1).show();
            StringBuilder sb = new StringBuilder();
            for (int i3 = 0; i3 < 20; i3++) {
                char charAt = "AMDYV{WVWT_CJJF_0s1}".charAt(i3);
                if (charAt < 'a' || charAt > 'z') {
                    if (charAt >= 'A') {
                        if (charAt <= 'Z') {
                            charAt = (char) (charAt - 21);
                            if (charAt >= 'A') {
                            }
                            charAt = (char) (charAt + 26);
                        }
                    }
                    sb.append(charAt);
                } else {
                    charAt = (char) (charAt - 21);
                    if (charAt >= 'a') {
                        sb.append(charAt);
                    }
                    charAt = (char) (charAt + 26);
                    sb.append(charAt);
                }
            }
            this.t1.setText(sb.toString());
            return;
        }
        Toast.makeText(getApplicationContext(), "Try again", 1).show();
    }
}
```

这里有两种方法实现获取 Flag ，第一种是 hook get_random 方法，使其返回一个确定的值，第二种是 hook check 方法，修改参数，使其满足条件。

```javascript
function main() {
  Java.perform(() => {
    let MainActivity = Java.use("com.ad2001.frida0x1.MainActivity");
    // hook get_random 方法，使其返回 1 然后输入 6 就可以了
    MainActivity.get_random.implementation = function () {
      let result = this.get_random();
      console.log("get_random: " + result);
      return 1;
    };
    // 或者 hook check 方法使 (i * 2) + 4 == i2
    MainActivity.check.implementation = function (i, i2) {
      console.log("i: " + i + ", i2: " + i2);
      this.check(1, 6);
    };
    // 测试 isDigitsOnly 参数是空字符串的返回值
    let TextUtils = Java.use("android.text.TextUtils");
    let str = Java.use("java.lang.String").$new("");
    let isDigitsOnly = TextUtils.isDigitsOnly(str);
    console.log(isDigitsOnly);
  });
}

setImmediate(main);
```

# Frida 0x2

使用 jadx 反编译 `MainActivity` 类的代码如下：

```java
public class MainActivity extends AppCompatActivity {
    static TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        t1 = (TextView) findViewById(R.id.textview);
    }

    public static void get_flag(int a) {
        if (a == 4919) { // 这里需要调用 get_flag 并传值为 4919
            try {
                SecretKeySpec secretKeySpec = new SecretKeySpec("HILLBILLWILLBINN".getBytes(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec iv = new IvParameterSpec(new byte[16]);
                cipher.init(2, secretKeySpec, iv);
                byte[] decryptedBytes = cipher.doFinal(Base64.decode("q7mBQegjhpfIAr0OgfLvH0t/D0Xi0ieG0vd+8ZVW+b4=", 0));
                String decryptedText = new String(decryptedBytes);
                t1.setText(decryptedText);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
```

这里需要调用 get_flag 并传值为 4919，下面为 hook 代码：

```javascript
function main() {
  Java.perform(() => {
    let MainActivity = Java.use("com.ad2001.frida0x2.MainActivity");
    MainActivity.onCreate.implementation = function (Bundle) {
      this.onCreate(Bundle); // 确保 t1 已经被初始化。
      MainActivity.get_flag(4919);
    };
  });
}

setImmediate(main);
```

# Frida 0x3

使用 jadx 反编译 `MainActivity` 类的代码如下：

```java
public class MainActivity extends AppCompatActivity {
    TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button btn = (Button) findViewById(R.id.button);
        this.t1 = (TextView) findViewById(R.id.textView);
        btn.setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.frida0x3.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (Checker.code == 512) {
                    byte[] bArr = new byte[0];
                    Toast.makeText(MainActivity.this.getApplicationContext(), "YOU WON!!!", 1).show();
                    byte[] KeyData = "glass123".getBytes();
                    SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
                    byte[] ecryptedtexttobytes = Base64.getDecoder().decode("MKxsZsY9Usw3ozXKKzTF0ymIaC8rs0AY74GnaKqkUrk=");
                    try {
                        Cipher cipher = Cipher.getInstance("Blowfish");
                        cipher.init(2, KS);
                        byte[] decrypted = cipher.doFinal(ecryptedtexttobytes);
                        String decryptedString = new String(decrypted, Charset.forName("UTF-8"));
                        MainActivity.this.t1.setText(decryptedString);
                        return;
                    } catch (InvalidKeyException e) {
                    ...
                    }
                }
                Toast.makeText(MainActivity.this.getApplicationContext(), "TRY AGAIN", 1).show();
            }
        });
    }
}
```

这里需要将 Checker.code 值修改为 512 ，看一下 Checker 的代码：

```java
public class Checker {
    static int code = 0;

    public static void increase() {
        code += 2;
    }
}
```

code 是一个静态成员变量，可以直接使用下面方法进行修改：

```javascript
function main() {
  Java.perform(() => {
    let Checker = Java.use("com.ad2001.frida0x3.Checker");
    console.log("Checker.code: " + Checker.code.value);
    Checker.code.value = 512;
  });
}

setImmediate(main);
```

# Frida 0x4

使用 jadx 反编译 `MainActivity` 类的代码如下：

```java
public class MainActivity extends AppCompatActivity {
    TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.t1 = (TextView) findViewById(R.id.txtview);
    }
}
```

对应的 Check 类如下：

```java
public class Check {
    public String get_flag(int a) {
        if (a == 1337) {
            byte[] decoded = new byte["I]FKNtW@]JKPFA\\[NALJr".getBytes().length];
            for (int i = 0; i < "I]FKNtW@]JKPFA\\[NALJr".getBytes().length; i++) {
                decoded[i] = (byte) ("I]FKNtW@]JKPFA\\[NALJr".getBytes()[i] ^ 15);
            }
            return new String(decoded);
        }
        return "";
    }
}
```

这需要调用 check 的 get_flag 方法获取 flag，然后使用 t1 进行设置，对应的脚本如下：

```javascript
function main() {
  Java.perform(() => {
    let MainActivity = Java.use("com.ad2001.frida0x4.MainActivity");
    let Check = Java.use("com.ad2001.frida0x4.Check");
    MainActivity.onCreate.implementation = function (Bundle) {
      let flag = Check.$new().get_flag(1337);
      this.onCreate(Bundle);
      let text = Java.use("java.lang.String").$new(flag);
      console.log(flag);
      this.t1.value.setText(text);
    };
  });
}

setImmediate(main);
```

# Frida 0x5

使用 jadx 反编译 `MainActivity` 类的代码如下：
```java
public class MainActivity extends AppCompatActivity {
    TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.t1 = (TextView) findViewById(R.id.textview);
    }

    public void flag(int code) {
        if (code == 1337) {
            try {
                SecretKeySpec secretKeySpec = new SecretKeySpec("WILLIWOMNKESAWEL".getBytes(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec iv = new IvParameterSpec(new byte[16]);
                cipher.init(2, secretKeySpec, iv);
                byte[] decodedEnc = Base64.getDecoder().decode("2Y2YINP9PtJCS/7oq189VzFynmpG8swQDmH4IC9wKAY=");
                byte[] decryptedBytes = cipher.doFinal(decodedEnc);
                String decryptedText = new String(decryptedBytes);
                this.t1.setText(decryptedText);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
```
这里需要调用 flag 方法既可，相应的代码如下：
```javascript
function main() {
  Java.perform(() => {
    let MainActivity = Java.use("com.ad2001.frida0x5.MainActivity");
    MainActivity.onCreate.implementation = function (Bundle) {
      this.onCreate(Bundle);
      this.flag(1337);
    };
  });
}

setImmediate(main);
```

# Frida 0x6
MainActivity代码如下：
```java
public class MainActivity extends AppCompatActivity {
    TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.t1 = (TextView) findViewById(R.id.textview);
    }

    public void get_flag(Checker A) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (1234 == A.num1 && 4321 == A.num2) {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec("MySecureKey12345".getBytes(), "AES");
            cipher.init(2, secretKeySpec);
            byte[] decryptedBytes = Base64.getDecoder().decode("QQzMj/JNaTblEHnIzgJAQkvWJV2oK9G2/UmrCs85fog=");
            String decrypted = new String(cipher.doFinal(decryptedBytes));
            this.t1.setText(decrypted);
        }
    }
}
```
Checker 类代码如下：
```java
public class Checker {
    int num1;
    int num2;
}
```
这里首先要创建一个 Checker 对象，然后再调用get_flag，相应的代码如下：
```javascript
function main() {
  Java.perform(() => {
    let MainActivity = Java.use("com.ad2001.frida0x6.MainActivity");
    let Checker = Java.use("com.ad2001.frida0x6.Checker");
    MainActivity.onCreate.implementation = function (Bundle) {
      this.onCreate(Bundle);
      let A = Checker.$new()
      A.num1.value = 1234;
      A.num2.value = 4321;
      this.get_flag(A);
    };
  });
}

setImmediate(main);
```
# Frida 0x7
MainActivity代码如下：
```java
public class MainActivity extends AppCompatActivity {
    TextView t1;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.t1 = (TextView) findViewById(R.id.textview);
        Checker ch = new Checker(123, 321);
        try {
            flag(ch);
        } catch (InvalidKeyException e) {
        ...
        }
    }

    public void flag(Checker A) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (A.num1 > 512 && 512 < A.num2) {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec("MySecureKey12345".getBytes(), "AES");
            cipher.init(2, secretKeySpec);
            byte[] decryptedBytes = Base64.getDecoder().decode("cL/bBqDmfO0IXXJCVFwYLeHp1k3mQr+SP6rlQGUPZTY=");
            String decrypted = new String(cipher.doFinal(decryptedBytes));
            this.t1.setText(decrypted);
        }
    }
}
```
Checker 类代码如下：
```java
public class Checker {
    int num1;
    int num2;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Checker(int a, int b) {
        this.num1 = a;
        this.num2 = b;
    }
}
```
这里只需要hook Checker 的构造函数，相关代码如下：
```javascript
function main() {
  Java.perform(() => {
    let Checker = Java.use("com.ad2001.frida0x7.Checker");
    Checker.$init.implementation = function (a, b) {
        console.log(`Checker.$init is called: a=${a}, b=${b}`);
        this["$init"](555, 555);
    };
  });
}

setImmediate(main);
```

# Frida 0x8

```java
public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;
    Button btn;
    EditText edt;

    public native int cmpstr(String str);

    static {
        System.loadLibrary("frida0x8");
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        this.binding = inflate;
        setContentView(inflate.getRoot());
        this.edt = (EditText) findViewById(R.id.editTextText);
        Button button = (Button) findViewById(R.id.button);
        this.btn = button;
        button.setOnClickListener(new View.OnClickListener() { // from class: com.ad2001.frida0x8.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                String ip = MainActivity.this.edt.getText().toString();
                int res = MainActivity.this.cmpstr(ip);
                if (res == 1) {
                    Toast.makeText(MainActivity.this, "YEY YOU GOT THE FLAG " + ip, 1).show();
                } else {
                    Toast.makeText(MainActivity.this, "TRY AGAIN", 1).show();
                }
            }
        });
    }
}
```
