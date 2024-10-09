# OpenSSL VPN Demo
目前预期实现虚拟子网内的加密通信，暂不准备添加代理功能扩展
## 编译
```
./build.sh
```
## 运行
注：tun设备需要超管权限
### server
```
sudo ./build/bin/vpn_server <subnet_address>/<prefix_len>  (default: 192.168.20.0/24)
```
### client
```
sudo ./build/bin/vpn_client
```