# OpenSSL VPN Demo
## 简介
面向Linux操作系统设计的轻量级SSL VPN

一个vpn_server与多个vpn_client之间构成一个虚拟子网，vpn_client与vpn_server建立连接时，vpn_server会自动给vpn_client分配一个虚拟IPv4地址，之后便可按照局域网通信的方式访问虚拟子网内所有主机

vpn_server与vpn_client间采用TLS加密通信，超过一定时间加密链路上无数据传输，则对应连接关闭并释放资源（暂定2000秒）
## 实现目标
- 基础目标：虚拟子网内的加密通信
- 扩展目标：代理功能
## 实现阶段
- $\checkmark$ 子网内通信 (已测试icmp echo, ssh)
- $\square$ 代理功能
## 架构图
待补充（
## 编译
```
./build.sh
```
## 运行
注：tun设备需要超管权限
### server
```
sudo ./build/bin/vpn_server <vpn_subnet_address>/<prefix_len>  (default: 192.168.20.0/24)
```
### client
```
sudo ./build/bin/vpn_client <server_public_address>
```
## 参考资料
- [OpenSSL github仓库](https://github.com/openssl/openssl)