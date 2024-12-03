# Remote-Switch

> 此项目不依赖gpio实现控制，需要windows电脑支持wake on lan功能

## 依赖软件

```bash
# 依赖软件
apt update && apt install etherwake samba
```



## 调用方法

- Shutdown: http://localhost:8888/?cmd=shutdown
- Wake-on-LAN: http://localhost:8888/?cmd=wakeup&interface=eth0&mac=00:11:22:33:44:55
- Turn off PC: http://localhost:8888/?cmd=turnoffpc&ip=192.168.1.100&user=username&passwd=password



## 编译

1. 下载 libmicrohttpd 源代码

```bash
# 如果还没有下载源代码
wget https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-0.9.75.tar.gz

# 解压
tar -xzvf libmicrohttpd-0.9.75.tar.gz

# 进入源代码目录
cd libmicrohttpd-0.9.75
```

2. 配置编译选项

```bash
# 配置时禁用 HTTPS
./configure --disable-https
```

3. 编译和安装

```bash
# 编译
make

# 安装
sudo make install

# 更新库缓存
sudo ldconfig
```

4. 进行静态链接编译

```bash
gcc -o server server.c -lmicrohttpd -lpthread -lgnutls -static
```
