# OpenSSL VPN Demo
- 基础目标：虚拟子网内的加密通信
- 扩展目标：代理功能
# 实现阶段
- $\square$ 子网内通信
- $\square$ 代理功能
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