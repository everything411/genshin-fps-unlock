# 原神解锁FPS限制

**！重要：原git已经不再维护，3.7失效，简单的维护了一下 3.7可用。这小东西我挺喜欢的**

**感谢Euphony_Facetious以及34736384两位作者的开源**

 - 工作原理通过**WriteProcessMemory**把FPS数值写进游戏
 - 不需要通过驱动进行读写操作
 - 支持国服和外服
 - 理论上支持后续版本，不需要更新源码
 - 如果需要更新我会尽快更新
 - [下载](https://github.com/xiaonian233/genshin-fps-unlock/releases/)

## 编译

 - 用VS2019编译，其他版本的也应该可以，没测试过
## 食用指南
 - 第一次运行的话先以管理员运行，然后手动打开游戏，这样解锁器能够获取到游戏路经并保存在配置文件里，这只需要执行一次，以后就可以直接用解锁器启动游戏了
 - 解锁器放哪都行
 - 运行之前确保游戏是关闭的
 - 用管理员运行解锁器
 - 解锁器不能关掉
>使用管理员运行是因为游戏必须由解锁器启动，游戏本身就需要管理员权限了，所以负责启动的也是需要的
### 默认热键           PS:按键要按一次改一次，不是长按
- **END** 开/关
- **右ctrl + 上方向键** 增大FPS上限 （+20）
- **右ctrl + 右方向键** 增大FPS上限 （+2）
- **右ctrl + 下方向键** 减少FPS上限 （-20）
- **右ctrl + 左方向键** 减少FPS上限 （-2）
- 源里默认的FPS数值是120

## 注意
- 已经在新号上测试了两星期，目前并没有任何异常，冒险等级30
- 使用未认证的第三方软件修改游戏数据是违反了协议条款的，后果自负
- 想要更改热键的话，修改下源里开头的定义 （[热键码](http://cherrytree.at/misc/vk.htm)）
- 至于为啥我没写成能在和游戏同一个目录下运行是因为游戏登录的时候会进行文件完整性检测，如果游戏目录内有其他文件也会当做是游戏的文件进行检测。如果把解锁器和游戏放一起的话游戏会把解锁器当成游戏文件检测，从而导致报错（31-4302）
- 要转载的话随便，毕竟开源，可以的话就注明下出处
- 这么个破工具请不要拿去倒卖
