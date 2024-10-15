# OpenSSL VPN

## 简介

- 面向Linux/MacOS的轻量级SSL VPN

- 采用client-server架构设计，一个vpn_server与多个vpn_client之间构成一个虚拟子网，vpn_client与vpn_server建立连接时，vpn_server会自动给vpn_client分配一个虚拟IPv4地址，之后便可按照局域网通信的方式访问虚拟子网内所有主机，并使用OpenSSL库对通信加密，可以实现不同NAT下两个client的端到端直接通信

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
cd /path/to/OpenSSL-VPN && ./scripts/build.sh
```

### 认证准备

1.&nbsp;检查项目目录下```certs/```中是否存在```host.key```和```host.crt```文件，如果没有，执行

```
cd /path/to/OpenSSL-VPN && ./scripts/gen_certs.sh
```

2.&nbsp;获取peer的自签名证书(物理拷贝peer的```certs/host.crt```)，假设为```/path/to/peer.crt```，执行

```
cd /path/to/OpenSSL-VPN && ./scripts/add_trusted.sh /path/to/peer.crt
```

### 编写配置

编写配置文件，配置文件格式如下，文件中可使用"#"作为注释符

```
SERVER_IP = <SERVER_REAL_WORLD_ADDRESS> #只有vpn_client需要指定
PORT = <SERVER_PORT_NUMBER>
EXPECTED_HOST_ID = <EXPECTED_HOST_ID>
```

- 对于vpn_server，```PORT```表示监听端口号(默认值54433)，```EXPECTED_HOST_ID```表示其在VPN子网内的主机号(默认值1)

- 对于vpn_client，```SERVER_IP```表示连接到vpn_server的实际地址（必须指定），```PORT```表示连接到vpn_server所在主机对应端口(需要与vpn_server的配置相同，默认值54433)，```EXPECTED_HOST_ID```表示其期望被分配的主机号（不指定时由vpn_server决定分配主机号），vpn_server会尽量满足vpn_client的主机号请求，除非对应主机号已被分配

配置文件示例可参考```config/config.sample```，如果在启动vpn_server和vpn_client时不通过参数显式指定配置文件位置，则会默认使用项目文件夹下的```config/config```作为配置文件(需要手动创建)

### 运行

#### server

启动server（可指定配置文件），并设置VPN子网地址，执行

```
cd /path/to/OpenSSL-VPN && sudo ./vpn_server [-c <config_file>] <vpn_subnet_address/prefix_len>
```

这里子网地址可以不显式指定，vpn_server会使用默认地址192.168.20.0/24

显式指定子网地址时请使用local address，子网前缀长度不得小于16位

#### client

连接server，执行

```
cd /path/to/OpenSSL-VPN && sudo ./vpn_client [-c <config_file>]
```

## 参考资料

- [OpenSSL github仓库](https://github.com/openssl/openssl)
