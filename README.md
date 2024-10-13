# OpenSSL VPN

## 简介

- 面向Linux/MacOS的轻量级SSL VPN

- 一个vpn_server与多个vpn_client之间构成一个虚拟子网，vpn_client与vpn_server建立连接时，vpn_server会自动给vpn_client分配一个虚拟IPv4地址，之后便可按照局域网通信的方式访问虚拟子网内所有主机，以实现不同NAT内两个client的端到端直接通信

## 架构

![OpenSSL VPN架构](images/openssl-vpn-architecture.png)

- 蓝色箭头1到13表示client间通信的报文流向，蓝色箭头1到7和红色箭头8到9表示client往server发送报文的流向（为简单起见，图中并没有包含使用VPN的应用，仅体现了内核协议栈间的通信），翻转箭头朝向即是反向通信的报文流向，原理相同。实体网卡间的通信（蓝色箭头5和9）均采用SSL/TLS加密。

- 在本项目实现中，vpn_server实质上担任了client间的网关，在应用层实现路由功能。各主机均创建了一块网络层虚拟网卡tun，并修改路由表表项使目的地址在VPN子网内的报文均被定向到tun中，以供vpn_server, vpn_client监听tun流量并将劫持到的IP报文作为负载送入SSL/TLS连接中。同时，当vpn_server, vpn_client在SSL/TLS连接上收到目的地址为自己VPN内网地址的报文后，通过tun写入内核协议栈，以实现VPN内网通信。vpn_server和vpn_client在发送报文时进行加密，接收报文后进行解密，从而实现安全性。

## 使用

### 依赖

确保本机中已预安装CMake，且版本≧3.28.3 (Ubuntu 24.04LTS 默认安装版本)

### 下载

```
git clone https://github.com/ArtisticFantasy/OpenSSL-VPN.git
```

### 构建

```
./scripts/build.sh
```

### 认证准备

1.&nbsp;检查项目目录下```certs/```中是否存在```host.key```和```host.crt```文件，如果没有，执行

```
./scripts/gen_certs.sh
```

2.&nbsp;获取peer的自签名证书(物理拷贝peer的```certs/host.crt```)，假设为```/path/to/peer.crt```，执行

```
./scripts/add_trusted.sh /path/to/peer.crt
```

### 运行

#### server

启动server（监听端口54433）并配置VPN子网地址，执行

```
sudo ./build/bin/vpn_server <vpn_subnet_address>/<prefix_len>  (default: 192.168.20.0/24)
```

指定子网地址时请使用local address，子网前缀长度不得小于16位

#### client

连接server，执行

```
sudo ./build/bin/vpn_client <server_public_address>
```

## 参考资料

- [OpenSSL github仓库](https://github.com/openssl/openssl)
