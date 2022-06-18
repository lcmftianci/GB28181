# gb28181相机接入

### 想用visual studio直接打开编译的check到v0.1版本，携带的第三方库是用vs2013编译的
```
git checkout v0.1
```
### 全源码编译 ，用cmake构建的
```
mkdir build
cd build 
cmake ..
cmake --build .
```
### 运行
拷贝执行程序与GB28181.ini配置文件到相同目录运行即可
```
gbexecer
```
