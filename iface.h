#pragma once

#include <sys/socket.h>
#include <stdint.h>
#include <linux/ethtool.h>

#define DEBUG

struct net_device_stats {
	unsigned long long rx_packets;	/* total packets received       */
	unsigned long long tx_packets;	/* total packets transmitted    */
	unsigned long long rx_bytes;	/* total bytes received         */
	unsigned long long tx_bytes;	/* total bytes transmitted      */
	unsigned long rx_errors;	    /* bad packets received         */
	unsigned long tx_errors;	    /* packet transmit problems     */
	unsigned long rx_dropped;	    /* no space in linux buffers    */
	unsigned long tx_dropped;	    /* no space available in linux  */
	unsigned long rx_multicast;	    /* multicast packets received   */
	unsigned long rx_compressed;
	unsigned long tx_compressed;
	unsigned long collisions;

	/* detailed rx_errors: */
	unsigned long rx_length_errors;
	unsigned long rx_over_errors;	/* receiver ring buff overflow  */
	unsigned long rx_crc_errors;	/* recved pkt with crc error    */
	unsigned long rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long rx_fifo_errors;	/* recv'r fifo overrun          */
	unsigned long rx_missed_errors;	/* receiver missed packet       */
	/* detailed tx_errors */
	unsigned long tx_aborted_errors;
	unsigned long tx_carrier_errors;
	unsigned long tx_fifo_errors;
	unsigned long tx_heartbeat_errors;
	unsigned long tx_window_errors;
};

struct net_iface {
	char name[IFNAMSIZ];                    /* interface name        */
	short type;                             /* if type. linux/if.h   */
	short flags;                            /* various flags         */
	uint8_t hwaddr[32];                     /* HW address            */
	int metric;                             /* routing metric        */
	int mtu;                                /* MTU value             */
	int tx_queue_len;                       /* transmit queue length */
	struct sockaddr addr;                   /* IP address            */
	struct sockaddr dstaddr;                /* P-P IP address        */
	struct sockaddr broadaddr;              /* IP broadcast address  */
	struct sockaddr netmask;                /* IP network mask       */
	struct net_device_stats stats;          /* statistics            */
	char bus_info[ETHTOOL_BUSINFO_LEN];     /* bus information       */
};

/*
 * get the name of interface specified by index.
 * @idx: interface index. start from 1.
 * @name: store the result of interface name.
 * @len: lenght of @name. At least IFNAMSIZ.
 * @return: NULL when error. otherwise return the pointer of @name
 */
char *iface_get_ifname_by_idx(int idx, char *name, int len);

/*
 * get interface list, and store in @iface_array.
 * if succeed, filed .name and .stat will set.
 * if @size is smamller than real value, will return failed(-2)
 * @return: if succeed, return the actual number of iface
 */
int iface_get_list(struct net_iface *iface_array, int size);

/*
 * get interface's information from kernel.
 * before call this function, @iface's filed name must be set properly
 *
 * information includes:
 * flags, hwaddr, metric, mtu, tx_queue_len, IP, broadcast address,
 * netmask, P-P IP address.
 *
 * @return: 0, ok. otherwise, fails.
 */
int iface_get_info(struct net_iface *iface);

/*
 * print information in @iface to @fp
 */
void iface_print_info(struct net_iface *iface, FILE *fp);

/*
 * change the name of an interface.
 * @oldname: the current name of the interface
 * @newname: change to this name
 * @return: 0, OK; others, fail.
 */
int iface_set_ifname(const char *oldname, const char *newname);

/* 
 * get flags of @ifname. 
 * flag refer to linux/if.h, e.g. IFF_UP
 *
 * @return: flags. < 0, failed.
 */
short iface_get_flags(const char *ifname);

/*
 * set @flags to interface @ifname.
 * flag refer to linux/if.h, e.g. IFF_UP
 *
 * @return: 0 ok. other failed.
 */
int iface_set_flags(const char *ifname, short flags);

/*
 * just set one bit in interface's flag.
 * flag refer to linux/if.h, e.g. IFF_UP
 *
 * @return: 0 ok. other failed.
 */
int iface_set_flag(const char *ifname, short flagbit);

/*
 * just clear one bit in interface's flag.
 * flag refer to linux/if.h, e.g. IFF_UP
 *
 * @return: 0 ok. other failed.
 */
int iface_clear_flag(const char *ifname, short flagbit);

// for debug
void iface_print_flags(FILE *fp, short flags);

// the format or byte order of content in @hwaddr depends on returned type.
// normally if type is ARPHRD_ETHER, it is the ethernet MAC address.
//
// @hwaddr_str, stored the return value of hwaddr string, ended with '\0'.
// @len: length of @hwaddr_str,  must not less than 18
// @return: sa_family of hardware address if succeed, otherwise < 0.
short iface_get_hwaddr(const char *ifname, char *hwaddr_str, int len);

int iface_set_hwaddr(const char *ifname, char *hwaddr_str);

/*
 * transform numberic ether hardware addrecc (MAC) into string
 * @ptr: contain numberic address, which for ipv4 is 6 bytes.
 * @str: store the string results
 * @len: lenght of @str
 * @return: pointer of @str.
 */
char *iface_hwaddr_bin2str(uint8_t *ptr, char *str, int len);

/*
 * transform ether hardware address from string into struct sockaddr
 * @str: string containing the hardware address
 * @ptr: store the numberic result, which is 6 bytes in lenght for ipv4.
 * @return: 0, OK; else, failed.
 */
int iface_hwaddr_str2bin(char *str, uint8_t *ptr);

/*
 * get metric of @ifname
 *
 * @return: metric, < 0 if fails.
 */
int iface_get_metric(const char *ifname);

/*
 * set metric of @ifname
 *
 * @return: 0 i ok, < 0 if fails.
 */
int iface_set_metric(const char *ifname, int metric);

/*
 * get mtu of @ifname
 *
 * @return: mtu, < 0 if fails.
 */
int iface_get_mtu(const char *ifname);
/*
 * set mtu of @ifname
 *
 * @return: 0 i ok, < 0 if fails.
 */
int iface_set_mtu(const char *ifname, int mtu);

/*
 * get tx queue lenght of @ifname
 *
 * @return: tx queue lenght, < 0 if fails.
 */
int iface_get_txqlen(const char *ifname);
/*
 * set tx queue lenght of @ifname
 *
 * @return: 0 i ok, < 0 if fails.
 */
int iface_set_txqlen(const char *ifname, int txqlen);

/*
 * get ip address of @ifname
 *
 * @return: ip address, < 0 if fails.
 */
int iface_get_ip(const char *ifname, uint32_t *ip);
/*
 * set ip address of @ifname
 *
 * @return: 0 i ok, < 0 if fails.
 */
int iface_set_ip(const char *ifname, uint32_t ip);

/*
 * get broadcast address of @ifname
 *
 * @return: broadcast address, < 0 if fails.
 */
int iface_get_broadaddr(const char *ifname, uint32_t *baddr);
/*
 * set broadcast address of @ifname
 *
 * @return: 0 i ok, < 0 if fails.
 */
int iface_set_broadaddr(const char *ifname, uint32_t baddr);

/*
 * get netmask of @ifname
 *
 * @return: netmask, < 0 if fails.
 */
int iface_get_netmask(const char *ifname, uint32_t *mask);
/*
 * set netmask of @ifname
 *
 * @return: 0 i ok, < 0 if fails.
 */
int iface_set_netmask(const char *ifname, uint32_t mask);
