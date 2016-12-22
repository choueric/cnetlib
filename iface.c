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

/*
 * - SIOCETHTOOL：refer to kernel net/core/ethtool.c and ethtool.h
 * - sockios.h， if.h: define socket ioctl commands。
*/

/*
 * modified from source code of net-tools_1.60
 */

#define PATH_PROCNET_DEV		"/proc/net/dev"

static int open_socket()
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("open socket DGRAM failed");
        return -1;
    }

    return fd;
}

////////////////////////////////////////////////////////////////////////////////

static int ethtool_get_drvinfo(int fd, char *ifname,
		struct ethtool_drvinfo *drvinfo)
{
	int err;
	struct ifreq ifr;

	drvinfo->cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (char *)drvinfo;
    strcpy(ifr.ifr_name, ifname);
	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err < 0) {
		perror("Cannot get driver information");
	}
	return err;
}

static int ethtool_get_businfo(int fd, char *ifname, char *businfo, int len)
{
    int ret = 0;
    struct ethtool_drvinfo info;

    ret = ethtool_get_drvinfo(fd, ifname, &info);
    if (ret < 0) {
        printf("get drvinfo failed: %m\n");
        return ret;
    }

    strncpy(businfo, info.bus_info, len);

    return 0;
}

////////////////////////////////////////////////////////////////////////////////

static char *ether_hwaddr_bin2str(uint8_t *ptr, char *str, int len)
{
    memset(str, 0, len);
    snprintf(str, len, "%02X:%02X:%02X:%02X:%02X:%02X",
	     (ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
	     (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377)
	);
    return str;
}

/* Input an Ethernet MAC address @bufp and convert to binary @sap. */
static int ether_hwaddr_str2bin(char *bufp, struct sockaddr *sap)
{
    char *ptr;
    char c, *orig;
    int i;
    unsigned val;

    sap->sa_family = ARPHRD_ETHER;
    ptr = sap->sa_data;

    i = 0;
    orig = bufp;
    while ((*bufp != '\0') && (i < ETH_ALEN)) {
        val = 0;
        c = *bufp++;
        if (isdigit(c))
            val = c - '0';
        else if (c >= 'a' && c <= 'f')
            val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            val = c - 'A' + 10;
        else {
#ifdef DEBUG
            fprintf(stderr, "in_ether(%s): invalid ether address!\n", orig);
#endif
            errno = EINVAL;
            return (-1);
        }
        val <<= 4;
        c = *bufp;
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
            fprintf(stderr, "in_ether(%s): invalid ether address!\n", orig);
#endif
            errno = EINVAL;
            return (-1);
        }
        if (c != 0)
            bufp++;
        *ptr++ = (uint8_t ) (val & 0377);
        i++;

        /* We might get a semicolon here - not required. */
        if (*bufp == ':') {
            if (i == ETH_ALEN) {
#ifdef DEBUG
                fprintf(stderr, "in_ether(%s): trailing : ignored!\n", orig)
#endif
                             ;		/* nothing */
            }
            bufp++;
        }
    }

    /* That's it.  Any trailing junk? */
    if ((i == ETH_ALEN) && (*bufp != '\0')) {
#ifdef DEBUG
        fprintf(stderr, "in_ether(%s): trailing junk!\n", orig);
        errno = EINVAL;
        return (-1);
#endif
    }

    return (0);
}

/* get iface name from @p to @name */
static char *if_proc_get_name(char *name, char *p)
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

static int get_dev_stats(char *bp, struct net_iface *iface, int version)
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

static int proc_netdev_version(char *buf)
{
    if (strstr(buf, "compressed"))
        return 3;
    if (strstr(buf, "bytes"))
        return 2;
    return 1;
}

/*
 * read interface from PROC file, and parse interface's infomation including
 * interface name and statistic data, then store into a static global interface 
 * array
 */
static int if_readlist_proc(struct net_iface *iface_array, int size)
{
    FILE *fh = NULL;
    char buf[512];
    struct net_iface *iface = NULL;
    int version = 0, i = 0;
    char *s, name[IFNAMSIZ];

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    fh = fopen(PATH_PROCNET_DEV, "r");
    if (!fh) {
		fprintf(stderr, "Warning: cannot open %s (%s). Limited output.\n",
			PATH_PROCNET_DEV, strerror(errno)); 
		return -1;
	}	
    s = fgets(buf, sizeof(buf), fh);	/* eat line */
    s = fgets(buf, sizeof(buf), fh);

    i = 0;
    version = proc_netdev_version(buf);

    while (fgets(buf, sizeof(buf) - 1, fh)) {
        if (i >= size) {
            printf("over MM_IFACE_MAX %d\n", size);
            fclose(fh);
            return -2;
        }

        s = if_proc_get_name(name, buf);    
        iface = iface_array + i;
        strncpy(iface->name, name, IFNAMSIZ);
        get_dev_stats(s, iface, version);
        ethtool_get_businfo(fd, name, iface->bus_info, ETHTOOL_BUSINFO_LEN);
        i++;
    }

    fclose(fh);
    close(fd);
    return i;
}

////////////////////////////////////////////////////////////////////////////////

static int iface_set_ifname(char *oldname, char *newname)
{
	struct ifreq ifr;
	int fd, err;

	fd = open_socket();
    if (fd < 0) {
        return -1;
    }

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, oldname, IFNAMSIZ); 
	strncpy(ifr.ifr_newname, newname, IFNAMSIZ);

	err = ioctl(fd, SIOCSIFNAME, &ifr);
	if (err) {
        fprintf(stderr, "%s: SIOCSIFNAME: %s\n", oldname, strerror(errno));
        close(fd);
		return -1;
	}

    close(fd);
    return 0;
}

#if 0 
  
// Standard interface flags (netdevice->flags).
// for more flags' definition, refer to kernel source include/uapi/linux/if.h.

#define	IFF_UP		    0x1		    /* interface is up		*/
#define	IFF_BROADCAST	0x2		    /* broadcast address valid	*/
#define	IFF_DEBUG	    0x4		    /* turn on debugging		*/
#define	IFF_LOOPBACK	0x8		    /* is a loopback net		*/
#define	IFF_POintOPOint	0x10		/* interface is has p-p link	*/
#define	IFF_NOTRAILERS	0x20		/* avoid use of trailers	*/
#define	IFF_RUNNING	    0x40		/* interface RFC2863 OPER_UP	*/
#define	IFF_NOARP	    0x80		/* no ARP protocol		*/
#define	IFF_PROMISC	    0x100		/* receive all packets		*/
#define	IFF_ALLMULTI	0x200		/* receive all multicast packets*/
#define IFF_MASTER	    0x400		/* master of a load balancer 	*/
#define IFF_SLAVE	    0x800		/* slave of a load balancer	*/
#define IFF_MULTICAST	0x1000		/* Supports multicast		*/

#endif

/* for debug */
static void iface_print_flags(FILE *fp, short flags)
{
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

static short iface_get_flags(int skfd, char *ifname)
{
    struct ifreq ifr;
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCGIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }
    return ifr.ifr_flags;
}

static int iface_set_flags(int skfd, char *ifname, short flags)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags = flags;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

static int iface_set_flag(int skfd, char *ifname, short flag)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCGIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags |= flag;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

static int iface_clear_flag(int skfd, char *ifname, short flag)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCGIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags &= ~flag;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFFLAGS: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * @hwaddr is binary format
 * type is in if_arp.h
 * TODO: @len must no less than 8 ?
 */
static short iface_get_hwaddr(int skfd, char *ifname, uint8_t *hwaddr, int len)
{
    struct ifreq ifr;
    int type = 0;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        memset(hwaddr, 0, len);
        type = -1;
        fprintf(stderr, "%s: SIOCGIFHWADDR: %s\n", ifname, strerror(errno));
    } else {
        memmove(hwaddr, ifr.ifr_hwaddr.sa_data, 8);  // TODO
        type = ifr.ifr_hwaddr.sa_family;
    }

    return type;
}

static int iface_set_hwaddr(int skfd, char *ifname, struct sockaddr *sa)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy((char *)&ifr.ifr_hwaddr, (char *)sa, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFHWADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

static int iface_get_metric(int skfd, char *ifname)
{
    struct ifreq ifr;
    int metric = 0;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFMETRIC, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCGIFMETRIC: %s\n", ifname, strerror(errno));
        metric = 0;
    } else {
        metric = ifr.ifr_metric;
    }

    return metric;
}

static int iface_set_metric(int skfd, char *ifname, int metric)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_metric = metric;
    if (ioctl(skfd, SIOCSIFMETRIC, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFMETRIC: %s\n", ifname, strerror(errno));
        return -1;
    }

    return 0;
}

static int iface_get_mtu(int skfd, char *ifname)
{
    struct ifreq ifr;
    int mtu = 0;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFMTU, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCGIFMTU: %s\n", ifname, strerror(errno));
        mtu = 0;
    } else {
        mtu = ifr.ifr_mtu;
    }

    return mtu;
}

static int iface_set_mtu(int skfd, char *ifname, int mtu)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_mtu = mtu;
    if (ioctl(skfd, SIOCSIFMTU, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFMTU: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

static int iface_get_txqlen(int skfd, char *ifname)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFTXQLEN, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCGIFTXQLEN: %s\n", ifname, strerror(errno));
        return -1;	/* unknown value */
    } else
        return ifr.ifr_qlen;
}

static int iface_set_txqlen(int skfd, char *ifname, int len)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_qlen = len;
    if (ioctl(skfd, SIOCSIFTXQLEN, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFTXQLEN: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

/* IPv4 address */
static int iface_get_addr(int skfd, char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(skfd, SIOCGIFADDR, &ifr) != 0) {
        bzero(saddr, sizeof(struct sockaddr));
        fprintf(stderr, "%s: SIOCGIFADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    memcpy(saddr, &ifr.ifr_addr, sizeof(struct sockaddr));

    return 0;
}

static int iface_set_addr(int skfd, char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, saddr, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFADDR, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

/* P-P IP address */
static int iface_get_dstaddr(int skfd, char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(skfd, SIOCGIFDSTADDR, &ifr) < 0) {
        memset(saddr, 0, sizeof(struct sockaddr));
        fprintf(stderr, "%s: SIOCGIFDSTADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    memcpy(saddr, &ifr.ifr_dstaddr, sizeof(struct sockaddr));
    return 0;
}

static int iface_get_broadaddr(int skfd, char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(skfd, SIOCGIFBRDADDR, &ifr) < 0) {
        memset(saddr, 0, sizeof(struct sockaddr));
        fprintf(stderr, "%s: SIOCGIFBRDADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
        
    memcpy(saddr, &ifr.ifr_broadaddr, sizeof(struct sockaddr));
    return 0;
}

static int iface_set_broadaddr(int skfd, char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, saddr, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFBRDADDR, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFBRDADDR: %s\n", ifname, strerror(errno));
        return -1;
    }
    iface_set_flag(skfd, ifname, IFF_BROADCAST);
    return 0;
}

static int iface_get_netmask(int skfd, char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(skfd, SIOCGIFNETMASK, &ifr) < 0) {
        memset(saddr, 0, sizeof(struct sockaddr));
        fprintf(stderr, "%s: SIOCGIFNETMASK: %s\n", ifname, strerror(errno));
        return -1;
    }
        
    memcpy(saddr, &ifr.ifr_netmask, sizeof(struct sockaddr));
    return 0;
}

static int iface_set_netmask(int skfd, char *ifname, struct sockaddr *saddr)
{
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy(&ifr.ifr_addr, saddr, sizeof(struct sockaddr));
    if (ioctl(skfd, SIOCSIFNETMASK, &ifr) < 0) {
        fprintf(stderr, "%s: SIOCSIFNETMASK: %s\n", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

/* Fetch the interface configuration from the kernel. */
static int iface_fetch_cfg(struct net_iface *iface)
{
    char *ifname = iface->name; 
    int skfd = open_socket();
    if (skfd < 0)
        return skfd;

    iface->flags = iface_get_flags(skfd, ifname);
    iface->type = iface_get_hwaddr(skfd, ifname, iface->hwaddr, 32);
    iface->metric = iface_get_metric(skfd, ifname);
    iface->mtu = iface_get_mtu(skfd, ifname);
    iface->tx_queue_len = iface_get_txqlen(skfd, ifname);
    iface_get_addr(skfd, ifname, &iface->addr);
    iface_get_broadaddr(skfd, ifname, &iface->broadaddr);
    iface_get_netmask(skfd, ifname, &iface->netmask);
    iface_get_dstaddr(skfd, ifname, &iface->dstaddr);
    //iface_get_map(skfd, ifname, &iface->map);

    close(skfd);
    return 0;
}

static void iface_print(struct net_iface *iface, FILE *fp)
{
    char str[32];
    fprintf(fp, "[%s]\n", iface->name);
    fprintf(fp, "\ttype = 0x%x, flags = 0x%x\n", iface->type, iface->flags);
    fprintf(fp, "\thwaddr = %s\n", ether_hwaddr_bin2str(iface->hwaddr, str, sizeof(str)));
    fprintf(fp, "\tmetric = %d, MTU = %d, txqlen = %d\n", iface->metric, 
            iface->mtu, iface->tx_queue_len);
    fprintf(fp, "\tIP = %s\n",  sa_ntop(&iface->addr, str, sizeof(str)));
    fprintf(fp, "\tnetmask = %s\n", sa_ntop(&iface->netmask, str, sizeof(str)));
    fprintf(fp, "\tbroadcast address = %s\n", sa_ntop(&iface->broadaddr, str, sizeof(str)));
    fprintf(fp, "\tbus info = %s\n", iface->bus_info);
}

////////////////////////////////////////////////////////////////////////////////

/*
 * get interface list, and store in @iface_array.
 * if succeed, filed .name and .stat will set.
 * if @size is smamller than real value, will return failed(-2)
 * @return: if succeed, return the actual number of iface
 */
int MM_iface_get_list(struct net_iface *iface_array, int size)
{
    if (iface_array == NULL || size <= 0) {
        return -1;
    }

    bzero(iface_array, sizeof(struct net_iface) * size);
    return if_readlist_proc(iface_array, size);
}

/*
 * get interface's configuration from kernel, including
 * flags, hwaddr, metric, mtu, tx_queue_len, IP, broadcast address,
 * netmask, P-P IP address, map.
 *
 * before call this function, @iface's filed name must be set properly
 */
int MM_iface_get_cfg(struct net_iface *iface)
{
    if (iface == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    return iface_fetch_cfg(iface);
}

void MM_iface_print(struct net_iface *iface, FILE *fp)
{
    if (iface == NULL || fp == NULL) {
        printf("invalid parameters\n");
        return;
    }

    iface_print(iface, fp);
}

void MM_iface_print_flags(short flags, FILE *fp)
{
	if (fp == NULL) {
		printf("Invalid parameters\n");
		return;
	}
    iface_print_flags(fp, flags);
}

int MM_iface_set_ifname(char *oldname, char *newname)
{
    if (oldname == NULL || newname == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    return iface_set_ifname(oldname, newname);
}

short MM_iface_get_flags(char *ifname)
{
    if (ifname == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    short flags = 0;
    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    flags = iface_get_flags(fd, ifname);
    close(fd);

    return flags;
}

int MM_iface_set_flags(char *ifname, short flags)
{
    if (ifname == NULL || flags < 0) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    int ret = iface_set_flags(fd, ifname, flags);
    close(fd);

    return ret;
}

// TODO: @cfg should be platform independent ?
// actually, @cfg is IFF_xxx (flags)
int MM_iface_config(char *ifname, short cfg, bool is_enable)
{
    if (ifname == NULL || cfg < 0) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    int ret = 0;
    if (is_enable) {
        ret = iface_set_flag(fd, ifname, cfg);
    } else {
        ret = iface_clear_flag(fd, ifname, cfg);
    }
    close(fd);

    return ret;
}

// TODO: what's the format or byte order of content in @hwaddr
// @hwaddr_str, stored the return value of hwaddr string, ended with '\0',
// so @len must not less than 18
// @return: sa_family of hardware address if succeed, otherwise < 0
short MM_iface_get_hwaddr(char *ifname, char *hwaddr_str, int len)
{
    if (ifname == NULL || hwaddr_str == NULL || len < 18) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    uint8_t data[32] = {0};
    short type = iface_get_hwaddr(fd, ifname, data, sizeof(data));
    close(fd);
    ether_hwaddr_bin2str(data, hwaddr_str, len);

    return type;
}

/*
 * @hwaddr is string, format is "74:FE:48:05:44:CB"
 */
int MM_iface_set_hwaddr(char *ifname, char *hwaddr_str, int len)
{
    if (ifname == NULL || hwaddr_str == NULL || len <= 0) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    struct sockaddr sa;
    if (ether_hwaddr_str2bin(hwaddr_str, &sa) < 0) {
        printf("transfer hwaddr string failed\n");
        return -1;
    }
    sa_set_family(&sa, ARPHRD_ETHER); // see if_arp.h

    int ret = iface_set_hwaddr(fd, ifname, &sa);
    close(fd);

    return ret;
}

int MM_iface_get_metric(char *ifname)
{
    if (ifname == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    int metric = iface_get_metric(fd, ifname);
    close(fd);
    return metric;
}

int MM_iface_set_metric(char *ifname, int metric)
{
    // TODO metric validation
    if (ifname == NULL || metric <= 0) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    int ret = iface_set_metric(fd, ifname, metric);
    close(fd);
    return ret;
}

int MM_iface_get_mtu(char *ifname)
{
    if (ifname == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    int mtu = iface_get_mtu(fd, ifname);
    close(fd);
    return mtu;
}

int MM_iface_set_mtu(char *ifname, int mtu)
{
    // TODO mtu validation
    if (ifname == NULL || mtu < 0) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    int ret = iface_set_mtu(fd, ifname, mtu);
    close(fd);
    return ret;
}

int MM_iface_get_txqlen(char *ifname)
{
    if (ifname == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    int len = iface_get_txqlen(fd, ifname);
    close(fd);
    return len;
}

int MM_iface_set_txqlen(char *ifname, int txqlen)
{
    // TODO validation
    if (ifname == NULL || txqlen < 0) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    int ret = iface_set_txqlen(fd, ifname, txqlen);
    close(fd);
    return ret;
}

int MM_iface_get_IP(char *ifname, uint32_t *ip)
{
    if (ifname == NULL || ip == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    struct sockaddr sa;
    int ret = iface_get_addr(fd, ifname, &sa);
    close(fd);

    if (ret < 0) {
        return ret;
    }
    *ip = sa_get_addr(&sa);
    return 0;
}

int MM_iface_set_IP(char *ifname, uint32_t ip)
{
    if (ifname == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    struct sockaddr sa;
    sa_set_addr(&sa, ip);
    sa_set_family(&sa, AF_INET);
    sa_set_port(&sa, 0);
    int ret = iface_set_addr(fd, ifname, &sa);
    close(fd);
    return ret;
}

int MM_iface_get_broadaddr(char *ifname, uint32_t *baddr)
{
    if (ifname == NULL || baddr == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    struct sockaddr sa;
    int ret = iface_get_broadaddr(fd, ifname, &sa);
    close(fd);

    if (ret < 0) {
        return ret;
    }
    *baddr = sa_get_addr(&sa);
    return 0;
}

int MM_iface_set_broadaddr(char *ifname, uint32_t baddr)
{
    if (ifname == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    struct sockaddr sa;
    sa_set_addr(&sa, baddr);
    sa_set_family(&sa, AF_INET);
    int ret = iface_set_broadaddr(fd, ifname, &sa);
    close(fd);
    return ret;
}

int MM_iface_get_netmask(char *ifname, uint32_t *mask)
{
    if (ifname == NULL || mask == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    struct sockaddr sa;
    int ret = iface_get_netmask(fd, ifname, &sa);
    close(fd);

    if (ret < 0) {
        return ret;
    }
    *mask = sa_get_addr(&sa);
    return 0;
}

int MM_iface_set_netmask(char *ifname, uint32_t mask)
{
    if (ifname == NULL) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    struct sockaddr sa;
    sa_set_addr(&sa, mask);
    sa_set_family(&sa, AF_INET);
    int ret = iface_set_netmask(fd, ifname, &sa);
    close(fd);
    return ret;
}

int MM_iface_get_businfo(char *ifname, char *businfo, int len)
{
    if (ifname == NULL || businfo == NULL || len <= 0) {
        printf("invalid parameters\n");
        return -1;
    }

    int fd = open_socket();
    if (fd < 0) {
        return -1;
    }

    int ret = ethtool_get_businfo(fd, ifname, businfo, len);
    close(fd);
    return ret;
}

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
        fprintf(stderr, "%d: SIOCGIFNAME: %s\n", idx, strerror(errno));
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
int iface_get_map(int skfd, char *ifname, struct ifmap *map)
{
    struct ifreq ifr;
    int ret = 0;

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0) {
        memset(map, 0, sizeof(struct ifmap));
        ret = -1;
        fprintf(stderr, "%s: SIOCGIFMAP: %s\n", ifname, strerror(errno));
    } else {
        memcpy(map, &ifr.ifr_map, sizeof(struct ifmap));
        ret = 0;
    }

    return ret;
}

