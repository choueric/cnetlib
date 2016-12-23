#include <sys/ioctl.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <linux/tcp.h>
#include <errno.h>
#include <linux/ethtool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "address.h"
#include "iface.h"
#include "log.h"

/*
 * - SIOCETHTOOL：refer to kernel net/core/ethtool.c and ethtool.h
 * - sockios.h， if.h: define socket ioctl commands。
*/

/*
 * modified from source code of net-tools_1.60
 */

#define PATH_PROCNET_DEV "/proc/net/dev"

static int open_socket()
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        err("open socket DGRAM failed: %m\n");
        return -1;
    }

    return fd;
}

static int ethtool_get_drvinfo(int fd, const char *ifname,
		struct ethtool_drvinfo *drvinfo)
{
	int err;
	struct ifreq ifr;

	drvinfo->cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (char *)drvinfo;
    strcpy(ifr.ifr_name, ifname);
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err < 0) {
		err("Cannot get driver information: %m\n");
	}
	return err;
}

static int ethtool_get_businfo(int fd, const char *ifname, char *businfo, int len)
{
    int ret = 0;
    struct ethtool_drvinfo info;

    ret = ethtool_get_drvinfo(fd, ifname, &info);
    if (ret < 0) {
        err("'%s' get drvinfo failed %m\n", ifname);
        return ret;
    }

    strncpy(businfo, info.bus_info, len);

    return 0;
}

/* get iface name from @p to @name */
static char *_proc_parse_iface_name(char *name, char *p)
{
    while (isspace(*p))
	p++;
    while (*p) {
        if (isspace(*p))
            break;
        if (*p == ':') {	/* could be an alias */
            char *dot = p, *dotname = name;
            *name++ = *p++;
            while (isdigit(*p))
                *name++ = *p++;
            if (*p != ':') {	/* it wasn't, backup */
                p = dot;
                name = dotname;
            }
            if (*p == '\0')
                return NULL;
            p++;
            break;
        }
        *name++ = *p++;
    }
    *name++ = '\0';
    return p;
}

static int _proc_parse_iface_status(char *bp, struct net_iface *iface, int version)
{
    switch (version) {
    case 3:
	sscanf(bp,
	"%llu %llu %lu %lu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu %lu",
	       &iface->stats.rx_bytes,
	       &iface->stats.rx_packets,
	       &iface->stats.rx_errors,
	       &iface->stats.rx_dropped,
	       &iface->stats.rx_fifo_errors,
	       &iface->stats.rx_frame_errors,
	       &iface->stats.rx_compressed,
	       &iface->stats.rx_multicast,

	       &iface->stats.tx_bytes,
	       &iface->stats.tx_packets,
	       &iface->stats.tx_errors,
	       &iface->stats.tx_dropped,
	       &iface->stats.tx_fifo_errors,
	       &iface->stats.collisions,
	       &iface->stats.tx_carrier_errors,
	       &iface->stats.tx_compressed);
	break;
    case 2:
	sscanf(bp, "%llu %llu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu",
	       &iface->stats.rx_bytes,
	       &iface->stats.rx_packets,
	       &iface->stats.rx_errors,
	       &iface->stats.rx_dropped,
	       &iface->stats.rx_fifo_errors,
	       &iface->stats.rx_frame_errors,

	       &iface->stats.tx_bytes,
	       &iface->stats.tx_packets,
	       &iface->stats.tx_errors,
	       &iface->stats.tx_dropped,
	       &iface->stats.tx_fifo_errors,
	       &iface->stats.collisions,
	       &iface->stats.tx_carrier_errors);
	iface->stats.rx_multicast = 0;
	break;
    case 1:
	sscanf(bp, "%llu %lu %lu %lu %lu %llu %lu %lu %lu %lu %lu",
	       &iface->stats.rx_packets,
	       &iface->stats.rx_errors,
	       &iface->stats.rx_dropped,
	       &iface->stats.rx_fifo_errors,
	       &iface->stats.rx_frame_errors,

	       &iface->stats.tx_packets,
	       &iface->stats.tx_errors,
	       &iface->stats.tx_dropped,
	       &iface->stats.tx_fifo_errors,
	       &iface->stats.collisions,
	       &iface->stats.tx_carrier_errors);
	iface->stats.rx_bytes = 0;
	iface->stats.tx_bytes = 0;
	iface->stats.rx_multicast = 0;
	break;
    }
    return 0;
}

static int _proc_parse_netdev_version(char *buf)
{
    if (strstr(buf, "compressed"))
        return 3;
    if (strstr(buf, "bytes"))
        return 2;
    return 1;
}

/*
 * read interface from PROC file, and parse interface's infomation then store
 * into @iface_array. Information of interface includes:
 * - interface name
 * - statistic data
 * - bus information
 */
static int parse_proc_nedev_list(struct net_iface *iface_array, int size)
{
    FILE *fh = NULL;
    char buf[512];
    struct net_iface *iface = NULL;
    int version = 0, i = 0;
    char *s;

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    fh = fopen(PATH_PROCNET_DEV, "r");
    if (!fh) {
		err("cannot open %s (%s). Limited output.\n",
			PATH_PROCNET_DEV, strerror(errno)); 
		return -1;
	}	
    s = fgets(buf, sizeof(buf), fh);	/* eat line */
    s = fgets(buf, sizeof(buf), fh);

    i = 0;
    version = _proc_parse_netdev_version(buf);

    while (fgets(buf, sizeof(buf) - 1, fh)) {
        if (i >= size) {
            info("over MM_IFACE_MAX %d\n", size);
            fclose(fh);
            return -2;
        }

        iface = iface_array + i;
        s = _proc_parse_iface_name(iface->name, buf);    
        _proc_parse_iface_status(s, iface, version);
        ethtool_get_businfo(fd, iface->name, iface->bus_info, ETHTOOL_BUSINFO_LEN);
        i++;
    }

    fclose(fh);
    close(fd);
    return i;
}

////////////////////////////////////////////////////////////////////////////////

int iface_set_ifname(const char *oldname, const char *newname)
{
	struct ifreq ifr;
	int fd, err;

    if (oldname == NULL || newname == NULL) {
        return -1;
    }

	fd = open_socket();
    if (fd < 0) {
        return -1;
    }

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, oldname, IFNAMSIZ); 
	strncpy(ifr.ifr_newname, newname, IFNAMSIZ);

	err = ioctl(fd, SIOCSIFNAME, &ifr);
	if (err) {
        err("%s: SIOCSIFNAME: %s\n", oldname, strerror(errno));
        close(fd);
		return -1;
	}

    close(fd);
    return 0;
}

void iface_print_flags(FILE *fp, short flags)
{
	if (fp == NULL) {
		err("Invalid parameters\n");
		return;
	}

    if (flags == 0)
        fprintf(fp, "[NO FLAGS] ");
    if (flags & IFF_UP)
        fprintf(fp, "UP ");
    if (flags & IFF_BROADCAST)
        fprintf(fp, "BROADCAST ");
    if (flags & IFF_DEBUG)
        fprintf(fp, "DEBUG ");
    if (flags & IFF_LOOPBACK)
        fprintf(fp, "LOOPBACK ");
    if (flags & IFF_POINTOPOINT)
        fprintf(fp, "POINTOPOINT");
    if (flags & IFF_NOTRAILERS)
        fprintf(fp, "NOTRAILERS ");
    if (flags & IFF_RUNNING)
        fprintf(fp, "RUNNING ");
    if (flags & IFF_NOARP)
        fprintf(fp, "NOARP ");
    if (flags & IFF_PROMISC)
        fprintf(fp, "PROMISC ");
    if (flags & IFF_ALLMULTI)
        fprintf(fp, "ALLMULTI ");
    if (flags & IFF_SLAVE)
        fprintf(fp, "SLAVE ");
    if (flags & IFF_MASTER)
        fprintf(fp, "MASTER ");
    if (flags & IFF_MULTICAST)
        fprintf(fp, "MULTICAST ");
    fprintf(fp, "\n");
}

static short _iface_get_flags(int skfd, const char *ifname)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        err("%s: SIOCGIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }
    return ifr.ifr_flags;
}

short iface_get_flags(const char *ifname)
{
    if (ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    short flags = 0;
    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    flags = _iface_get_flags(fd, ifname);
    close(fd);

    return flags;
}

static int _iface_set_flags(int skfd, const char *ifname, short flags)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags = flags;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        err("%s: SIOCSIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

int iface_set_flags(const char *ifname, short flags)
{
    if (ifname == NULL || flags < 0) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    int ret = _iface_set_flags(fd, ifname, flags);
    close(fd);

    return ret;
}

/* set one bit of flag */
static int _iface_set_flag(int skfd, const char *ifname, short flag)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        err("%s: SIOCGIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags |= flag;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        err("%s: SIOCSIFFLAGS: %s\n", ifname, strerror(errno));
        return -2;
    }
    return 0;
}

int iface_set_flag(const char *ifname, short flagbit)
{
    if (ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

	int ret = _iface_set_flag(fd, ifname, flagbit);
    close(fd);

    return ret;
}

/* set one bit of flag */
static int _iface_clear_flag(int skfd, const char *ifname, short flag)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        err("%s: SIOCGIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags &= ~flag;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        err("%s: SIOCSIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

int iface_clear_flag(const char *ifname, short flagbit)
{
    if (ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

	int ret = _iface_clear_flag(fd, ifname, flagbit);
    close(fd);

    return ret;
}

/*
 * @hwaddr is binary format
 * type is in if_arp.h
 */
static short _iface_get_hwaddr(int skfd, const char *ifname, uint8_t *hwaddr)
{
    struct ifreq ifr;
    int type = 0;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        type = -1;
        err("%s: SIOCGIFHWADDR: %s\n", ifname, strerror(errno));
    } else {
        memmove(hwaddr, ifr.ifr_hwaddr.sa_data, 8);
        type = ifr.ifr_hwaddr.sa_family;
    }

    return type;
}

short iface_get_hwaddr(const char *ifname, char *hwaddr_str, int len)
{
    if (ifname == NULL || hwaddr_str == NULL || len < 18) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    uint8_t data[32] = {0};
    short type = _iface_get_hwaddr(fd, ifname, data);
    close(fd);
    iface_hwaddr_bin2str(data, hwaddr_str, len);

    return type;
}

static int _iface_set_hwaddr(int skfd, const char *ifname, struct sockaddr *sa)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy((char *)&ifr.ifr_hwaddr, (char *)sa, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFHWADDR, &ifr) < 0) {
        err("%s: SIOCSIFHWADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * @hwaddr is string, format is "74:FE:48:05:44:CB", with '\0' ended.
 */
int iface_set_hwaddr(const char *ifname, char *hwaddr_str)
{
    if (ifname == NULL || hwaddr_str == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    struct sockaddr sa;
    if (iface_hwaddr_str2bin(hwaddr_str, (uint8_t *)sa.sa_data) < 0) {
        err("transfer hwaddr string failed\n");
        return -3;
    }
    sa_set_family(&sa, ARPHRD_ETHER); // see if_arp.h

    int ret = _iface_set_hwaddr(fd, ifname, &sa);
    close(fd);

    return ret;
}

static int _iface_get_metric(int skfd, const char *ifname)
{
    struct ifreq ifr;
    int metric = 0;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFMETRIC, &ifr) < 0) {
        err("%s: SIOCGIFMETRIC: %s\n", ifname, strerror(errno));
        metric = 0;
    } else {
        metric = ifr.ifr_metric;
    }

    return metric;
}

int iface_get_metric(const char *ifname)
{
    if (ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    int metric = _iface_get_metric(fd, ifname);
    close(fd);
    return metric;
}

static int _iface_set_metric(int skfd, const char *ifname, int metric)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_metric = metric;
    if (ioctl(skfd, SIOCSIFMETRIC, &ifr) < 0) {
        err("%s: SIOCSIFMETRIC: %s\n", ifname, strerror(errno));
        return -1;
    }

    return 0;
}

int iface_set_metric(const char *ifname, int metric)
{
    // TODO metric validation
    if (ifname == NULL || metric <= 0) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    int ret = _iface_set_metric(fd, ifname, metric);
    close(fd);
    return ret;
}

static int _iface_get_mtu(int skfd, const char *ifname)
{
    struct ifreq ifr;
    int mtu = 0;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFMTU, &ifr) < 0) {
        err("%s: SIOCGIFMTU: %s\n", ifname, strerror(errno));
        mtu = 0;
    } else {
        mtu = ifr.ifr_mtu;
    }

    return mtu;
}

int iface_get_mtu(const char *ifname)
{
    if (ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    int mtu = _iface_get_mtu(fd, ifname);
    close(fd);
    return mtu;
}

static int _iface_set_mtu(int skfd, const char *ifname, int mtu)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_mtu = mtu;
    if (ioctl(skfd, SIOCSIFMTU, &ifr) < 0) {
        err("%s: SIOCSIFMTU: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

int iface_set_mtu(const char *ifname, int mtu)
{
    // TODO mtu validation
    if (ifname == NULL || mtu < 0) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    int ret = _iface_set_mtu(fd, ifname, mtu);
    close(fd);
    return ret;
}

static int _iface_get_txqlen(int skfd, const char *ifname)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFTXQLEN, &ifr) < 0) {
        err("%s: SIOCGIFTXQLEN: %s\n", ifname, strerror(errno));
        return -1;	/* unknown value */
    } else
        return ifr.ifr_qlen;
}

int iface_get_txqlen(const char *ifname)
{
    if (ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    int len = _iface_get_txqlen(fd, ifname);
    close(fd);
    return len;
}

static int _iface_set_txqlen(int skfd, const char *ifname, int len)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_qlen = len;
    if (ioctl(skfd, SIOCSIFTXQLEN, &ifr) < 0) {
        err("%s: SIOCSIFTXQLEN: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

int iface_set_txqlen(const char *ifname, int txqlen)
{
    // TODO validation
    if (ifname == NULL || txqlen < 0) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    int ret = _iface_set_txqlen(fd, ifname, txqlen);
    close(fd);
    return ret;
}

/* IPv4 address */
static int _iface_get_addr(int skfd, const char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(skfd, SIOCGIFADDR, &ifr) != 0) {
        bzero(saddr, sizeof(struct sockaddr));
        err("%s: SIOCGIFADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    memcpy(saddr, &ifr.ifr_addr, sizeof(struct sockaddr));

    return 0;
}

int iface_get_ip(const char *ifname, uint32_t *ip)
{
    if (ifname == NULL || ip == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    struct sockaddr sa;
    int ret = _iface_get_addr(fd, ifname, &sa);
    close(fd);

    if (ret < 0) {
        return ret;
    }
    *ip = sa_get_addr(&sa);
    return 0;
}

static int _iface_set_addr(int skfd, const char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, saddr, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFADDR, &ifr) < 0) {
        err("%s: SIOCSIFADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

int iface_set_ip(const char *ifname, uint32_t ip)
{
    if (ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    struct sockaddr sa;
    sa_set_addr(&sa, ip);
    sa_set_family(&sa, AF_INET);
    sa_set_port(&sa, 0);
    int ret = _iface_set_addr(fd, ifname, &sa);
    close(fd);
    return ret;
}

/* P-P IP address */
static int _iface_get_dstaddr(int skfd, const char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(skfd, SIOCGIFDSTADDR, &ifr) < 0) {
        memset(saddr, 0, sizeof(struct sockaddr));
        err("%s: SIOCGIFDSTADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    memcpy(saddr, &ifr.ifr_dstaddr, sizeof(struct sockaddr));
    return 0;
}

static int _iface_get_broadaddr(int skfd, const char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(skfd, SIOCGIFBRDADDR, &ifr) < 0) {
        memset(saddr, 0, sizeof(struct sockaddr));
        err("%s: SIOCGIFBRDADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
        
    memcpy(saddr, &ifr.ifr_broadaddr, sizeof(struct sockaddr));
    return 0;
}

int iface_get_broadaddr(const char *ifname, uint32_t *baddr)
{
    if (ifname == NULL || baddr == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    struct sockaddr sa;
    int ret = _iface_get_broadaddr(fd, ifname, &sa);
    close(fd);

    if (ret < 0) {
        return ret;
    }
    *baddr = sa_get_addr(&sa);
    return 0;
}

static int _iface_set_broadaddr(int skfd, const char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, saddr, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFBRDADDR, &ifr) < 0) {
        err("%s: SIOCSIFBRDADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    _iface_set_flag(skfd, ifname, IFF_BROADCAST);
    return 0;
}

int iface_set_broadaddr(const char *ifname, uint32_t baddr)
{
    if (ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    struct sockaddr sa;
    sa_set_addr(&sa, baddr);
    sa_set_family(&sa, AF_INET);
    int ret = _iface_set_broadaddr(fd, ifname, &sa);
    close(fd);
    return ret;
}

static int _iface_get_netmask(int skfd, const char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(skfd, SIOCGIFNETMASK, &ifr) < 0) {
        memset(saddr, 0, sizeof(struct sockaddr));
        err("%s: SIOCGIFNETMASK: %s\n", ifname, strerror(errno));
        return -1;
    }
        
    memcpy(saddr, &ifr.ifr_netmask, sizeof(struct sockaddr));
    return 0;
}

int iface_get_netmask(const char *ifname, uint32_t *mask)
{
    if (ifname == NULL || mask == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    struct sockaddr sa;
    int ret = _iface_get_netmask(fd, ifname, &sa);
    close(fd);

    if (ret < 0) {
        return ret;
    }
    *mask = sa_get_addr(&sa);
    return 0;
}

static int _iface_set_netmask(int skfd, const char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, saddr, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFNETMASK, &ifr) < 0) {
        err("%s: SIOCSIFNETMASK: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

int iface_set_netmask(const char *ifname, uint32_t mask)
{
    if (ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    struct sockaddr sa;
    sa_set_addr(&sa, mask);
    sa_set_family(&sa, AF_INET);
    int ret = _iface_set_netmask(fd, ifname, &sa);
    close(fd);
    return ret;
}

int iface_get_info(struct net_iface *iface)
{
    if (iface == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    char *ifname = iface->name; 
    int skfd = open_socket();
    if (skfd < 0)
        return skfd;

    iface->flags = _iface_get_flags(skfd, ifname);
    iface->type = _iface_get_hwaddr(skfd, ifname, iface->hwaddr);
    iface->metric = _iface_get_metric(skfd, ifname);
    iface->mtu = _iface_get_mtu(skfd, ifname);
    iface->tx_queue_len = _iface_get_txqlen(skfd, ifname);
    _iface_get_addr(skfd, ifname, &iface->addr);
    _iface_get_broadaddr(skfd, ifname, &iface->broadaddr);
    _iface_get_netmask(skfd, ifname, &iface->netmask);
    _iface_get_dstaddr(skfd, ifname, &iface->dstaddr);

    close(skfd);
    return 0;
}

void iface_print_info(struct net_iface *iface, FILE *fp)
{
    if (iface == NULL || fp == NULL) {
        err("invalid parameters\n");
        return;
    }

    char str[32];
    fprintf(fp, "[%s]\n", iface->name);
    fprintf(fp, "\ttype = 0x%x, flags = 0x%x\n", iface->type, iface->flags);
    fprintf(fp, "\thwaddr = %s\n", iface_hwaddr_bin2str(iface->hwaddr, str, sizeof(str)));
    fprintf(fp, "\tmetric = %d, MTU = %d, txqlen = %d\n", iface->metric, 
            iface->mtu, iface->tx_queue_len);
    fprintf(fp, "\tIP = %s\n",  sa_ntop(&iface->addr, str, sizeof(str)));
    fprintf(fp, "\tnetmask = %s\n", sa_ntop(&iface->netmask, str, sizeof(str)));
    fprintf(fp, "\tbroadcast address = %s\n", sa_ntop(&iface->broadaddr, str, sizeof(str)));
    fprintf(fp, "\tbus info = %s\n", iface->bus_info);
}

////////////////////////////////////////////////////////////////////////////////

char *iface_hwaddr_bin2str(uint8_t *ptr, char *str, int len)
{
    memset(str, 0, len);
    snprintf(str, len, "%02X:%02X:%02X:%02X:%02X:%02X",
	     (ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
	     (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377)
	);
    return str;
}

// TODO:
// 1. improve
// 2. write more details
int iface_hwaddr_str2bin(char *str, uint8_t *ptr)
{
    char c, *orig;
    int i;
    unsigned val;

    i = 0;
    orig = str;
    while ((*str != '\0') && (i < ETH_ALEN)) {
        val = 0;
        c = *str++;
        if (isdigit(c))
            val = c - '0';
        else if (c >= 'a' && c <= 'f')
            val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            val = c - 'A' + 10;
        else {
#ifdef DEBUG
            err("in_ether(%s): invalid ether address!\n", orig);
#endif
            errno = EINVAL;
            return (-1);
        }
        val <<= 4;
        c = *str;
        if (isdigit(c))
            val |= c - '0';
        else if (c >= 'a' && c <= 'f')
            val |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            val |= c - 'A' + 10;
        else if (c == ':' || c == 0)
            val >>= 4;
        else {
#ifdef DEBUG
            err("in_ether(%s): invalid ether address!\n", orig);
#endif
            errno = EINVAL;
            return (-1);
        }
        if (c != 0)
            str++;
        *ptr++ = (uint8_t ) (val & 0377);
        i++;

        /* We might get a semicolon here - not required. */
        if (*str == ':') {
            if (i == ETH_ALEN) {
#ifdef DEBUG
                err("in_ether(%s): trailing : ignored!\n", orig)
#endif
                             ;		/* nothing */
            }
            str++;
        }
    }

    /* That's it.  Any trailing junk? */
    if ((i == ETH_ALEN) && (*str != '\0')) {
#ifdef DEBUG
        err("in_ether(%s): trailing junk!\n", orig);
        errno = EINVAL;
        return (-1);
#endif
    }

    return (0);
}

int iface_get_list(struct net_iface *iface_array, int size)
{
    if (iface_array == NULL || size <= 0) {
        return -1;
    }

    bzero(iface_array, sizeof(struct net_iface) * size);
    return parse_proc_nedev_list(iface_array, size);
}

int iface_get_businfo(const char *ifname, char *businfo, int len)
{
    if (ifname == NULL || businfo == NULL || len <= 0) {
        err("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -2;
    }

    int ret = ethtool_get_businfo(fd, ifname, businfo, len);
    close(fd);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////

void ethtool_dump_drvinfo(struct ethtool_drvinfo *info)
{
	fprintf(stdout,
		"driver: %s\n"
		"version: %s\n"
		"firmware-version: %s\n"
		"bus-info: %s\n"
		"supports-statistics: %s\n"
		"supports-test: %s\n"
		"supports-eeprom-access: %s\n"
		"supports-register-dump: %s\n"
		"supports-priv-flags: %s\n",
		info->driver,
		info->version,
		info->fw_version,
		info->bus_info,
		info->n_stats ? "yes" : "no",
		info->testinfo_len ? "yes" : "no",
		info->eedump_len ? "yes" : "no",
		info->regdump_len ? "yes" : "no",
		info->n_priv_flags ? "yes" : "no");
}

char *iface_get_ifname_by_idx(int idx, char *name, int len)
{
	struct ifreq ifr;
	int fd;
	int err;

	fd = open_socket();
    if (fd < 0) {
        return NULL;
    }

	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_ifindex = idx;
	err = ioctl(fd, SIOCGIFNAME, &ifr);
	if (err) {
        err("index %d, SIOCGIFNAME: %s\n", idx, strerror(errno));
        close(fd);
		return NULL;
	}
	close(fd);

    strncpy(name, ifr.ifr_name, len);
	return name;
}

/*
 * struct ifmap {
 *     mem_start;
 *     mem_end;
 *     base_addr;
 *     irq;
 *     dma;
 *     port;
 * }
 */
int iface_get_map(int skfd, const char *ifname, struct ifmap *map)
{
    struct ifreq ifr;
    int ret = 0;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
        memset(map, 0, sizeof(struct ifmap));
        ret = -1;
        err("%s: SIOCGIFMAP: %s\n", ifname, strerror(errno));
    } else {
        memcpy(map, &ifr.ifr_map, sizeof(struct ifmap));
        ret = 0;
    }

    return ret;
}
