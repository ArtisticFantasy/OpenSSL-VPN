#ifndef VPN_NET_COMMON_H
#define VPN_NET_COMMON_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#ifdef __linux__
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#elif __APPLE__
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <net/if_dl.h>
#include <net/route.h>
#endif

#endif
/* VPN_NET_COMMON_H */