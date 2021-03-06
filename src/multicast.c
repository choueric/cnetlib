#include <netinet/in.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/ioctl.h>

#include "multicast.h"
#include "address.h"
#include "log.h"

// modified from source code of net-tools_1.60, ipmaddr.c
// NOTE: ONLY support IPv4

#define PATH_PROCNET_IGMP		"/proc/net/igmp"      /* net/core/igmp.c */
#define PATH_PROCNET_DEV_MCAST  "/proc/net/dev_mcast" /* net/core/dev_addr_lists.c */

// parse hex number in string format form @str and store in @addr.
// @return: the number of byte stored in @addr.
// e.g. "c0a80001" -> addr[4] = {1, 0, 168, 192}
static int parse_hex(char *str, unsigned char *addr)
{
	int len = 0;

	while (*str) {
		int tmp;
		if (str[1] == '\0')
			return -1;
		if (sscanf(str, "%02x", &tmp) != 1)
			return -1;
		addr[len] = tmp;
		len++;
		str += 2;
	}
	return len;
}

/*
 * for AF_PACKET, i.e. ether hwaddr
 * seq format: "index, name, refcount, global_use, address"
 */
static int read_dev_mcast(struct mcast_info *array, int num)
{
    int i = 0;
	char buf[256];
    struct mcast_info *m = NULL;
    char hexa[32];

	FILE *fp = fopen(PATH_PROCNET_DEV_MCAST, "r");
	if (!fp) {
        err("fopen %s failed: %m\n", PATH_PROCNET_DEV_MCAST);
		return -1;
    }

    i = 0;
    bzero(array, sizeof(struct mcast_info) * num);

	while (fgets(buf, sizeof(buf), fp)) {
        m = array + i;
		int len;

		sscanf(buf, "%d%s%d%d%s", &m->index, m->name, &m->users, &m->st, hexa);
		len = parse_hex(hexa, (unsigned char*)m->addr);
        if (len < 0) {
            err("parse hex failed\n");
            return -1;
        }

		m->family = AF_PACKET;
        i++;
        if (i >= num) {
            err("over num %d\n", num);
            fclose(fp);
            return -1;
        }
	}
	fclose(fp);

    return i;
}

/* 
 * for AF_INET
 * idx, name, count, querier, \n\t, multiaddr, users, Timer(runing:clock), reporter
 * just read idx, name, multiaddr, users
 */
static int read_igmp(struct mcast_info *array, int num)
{
	struct mcast_info *m;
    struct mcast_info *head = NULL;
	char buf[256];
    int i = 0;

	FILE *fp = fopen(PATH_PROCNET_IGMP, "r");
	if (!fp) {
        err("fopen %s failed: %m\n", PATH_PROCNET_IGMP);
		return -1;
    }
	if (fgets(buf, sizeof(buf), fp) == NULL)  // eat first line
		err("fgets failed\n");

    i = 0;
    bzero(array, sizeof(struct mcast_info) * num);

	while (fgets(buf, sizeof(buf), fp)) {
		m = array + i;
        m->family = AF_INET;
		if (buf[0] != '\t') {
			sscanf(buf, "%d%s", &m->index, m->name);
            head = m;
			continue;
		}
        if (head != m) {
            m->index = head->index;
            strncpy(m->name, head->name, IFNAMSIZ);
        }
		sscanf(buf, "%08x%d", (unsigned int*)m->addr, &m->users);
        i++;
        if (i >= num) {
            err("over num %d\n", num);
            fclose(fp);
            return -1;
        }
	}
	fclose(fp);

    return i;
}

// normal group, non-source group
static int mcast_join_leave_inet(int skfd, char *ifname, struct sockaddr *grp, int join)
{
    if (grp->sa_family != AF_INET) {
        err("Not support non-AF_INET mcast ops\n");
        return -1;
    }

    int ret = 0;
    struct ip_mreq mreq;
    int cmd = (join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP);

    memcpy(&mreq.imr_multiaddr, &((struct sockaddr_in *)grp)->sin_addr,
            sizeof(struct in_addr));

    struct ifreq ifreq;
    strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFADDR, &ifreq) < 0) {
        err("get ifaddr failed: %m");
        return -1;
    }
    memcpy(&mreq.imr_interface, &((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr,
            sizeof(struct in_addr));

    ret = setsockopt(skfd, IPPROTO_IP, cmd, &mreq, sizeof(mreq));
    if (ret < 0) {
        err("%s multicast ioctl failed: %m", join ? "join": "leave");
        return -1;
    }
    return 0;
}


static int mcast_set_ttl_inet(int skfd, int val)
{
    unsigned char ttl = val;
    int ret = setsockopt(skfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (ret < 0) {
        err("set multicast TTL failed: %m");
        return -1;
    }
    return 0;
}

static int mcast_get_ttl_inet(int skfd)
{
    unsigned char ttl;
    socklen_t len;

    len = sizeof(ttl);
    if (getsockopt(skfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, &len) < 0) {
        err("get multicast TTL failed: %m\n");
        return -1;
    }
    return ttl;
}

static int mcast_set_iface_inet(int skfd, char *ifname)
{
    struct in_addr inaddr;
    struct ifreq ifreq;

    strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(skfd, SIOCGIFADDR, &ifreq) < 0) {
        err("get iface addr ioctl failed: %m\n");
        return -1;
    }
    memcpy(&inaddr, &((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr,
            sizeof(struct in_addr));

    int ret = setsockopt(skfd, IPPROTO_IP, IP_MULTICAST_IF,
                &inaddr, sizeof(struct in_addr));
    if (ret < 0) {
        err("set multicast iface failed: %m\n");
        return -1;
    }
    return 0;
}

static int mcast_get_iface_inet(int skfd, uint32_t *ip)
{
    struct in_addr inaddr;
    socklen_t len;

    int ret = getsockopt(skfd, IPPROTO_IP, IP_MULTICAST_IF,
                &inaddr, &len);
    if (ret < 0) {
        *ip = 0;
        err("set multicast iface failed: %m\n");
        return -1;
    }
    info("ip = %08x\n", inaddr.s_addr);
    *ip = ntohl(inaddr.s_addr);
    return 0;
}

////////////////////////////////////////////////////////////////////////////////

int mcast_get_list(struct mcast_info *array, int size, int family)
{
    int n = 0;
	int ret;

	if (family == AF_PACKET || family == AF_UNSPEC) {
		ret = read_dev_mcast(array, size);
		if (ret < 0) {
			err("read_dev_mcast failed\n");
			return -1;
		}
		n += ret;
	}

	if (family == AF_INET || family == AF_UNSPEC) {
		ret = read_igmp(array + n, size - n);
		if (ret < 0) {
			err("read_igmp failed\n");
			return -2;
		}
		n += ret;
	}

    return n;
}

void mcast_print(struct mcast_info *m, FILE *fp)
{
    if (m == NULL || fp == NULL) {
        err("Invliad parameters\n");
        return;
    }

    char str[32] = {0};
    const char *type = NULL;

    if (m->family == AF_INET) {
        snprintf(str, sizeof(str), "%d.%d.%d.%d", m->addr[0], m->addr[1], m->addr[2], m->addr[3]);
    } else {
        snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",
                m->addr[0], m->addr[1], m->addr[2], m->addr[3], 
                m->addr[4], m->addr[5]);
    }

    if (m->family == AF_INET)
        type = "inet";
    else if (m->family == AF_PACKET)
        type = "link";
    else
        type = "?";

    fprintf(fp, "%3d %-6s: %4s %-18s [%d]\n", m->index, m->name, type, str, m->users);
}

int mcast_join(int skfd, char *ifname, uint32_t ip)
{
    if (skfd <= 0 || ifname == NULL || ip == 0) {
        err("invalid parameters\n");
        return -1;
    }

    struct sockaddr grp;
    sa_set_addr(&grp, ip);
    sa_set_family(&grp, AF_INET);

    return mcast_join_leave_inet(skfd, ifname, &grp, true);
}

int mcast_leave(int skfd, char *ifname, uint32_t ip)
{
    if (skfd <= 0 || ifname == NULL || ip == 0) {
        err("invalid parameters\n");
        return -1;
    }

    struct sockaddr grp;
    sa_set_addr(&grp, ip);
    sa_set_family(&grp, AF_INET);

    return mcast_join_leave_inet(skfd, ifname, &grp, false);
}

/*
 * actually, in IPv4, @ttl's type is u_char
 */
int mcast_set_ttl(int skfd, int ttl)
{
    if (skfd <= 0 || ttl < 0) {
        err("invalid parameters\n");
        return -1;
    }

    return mcast_set_ttl_inet(skfd, ttl);
}

int mcast_get_ttl(int skfd)
{
    if (skfd <= 0) {
        err("invalid parameters\n");
        return -1;
    }

    return mcast_get_ttl_inet(skfd);
}

int mcast_set_iface(int skfd, char *ifname)
{
    if (skfd <= 0 || ifname == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    return mcast_set_iface_inet(skfd, ifname);
}

int mcast_get_iface(int skfd, uint32_t *ip)
{
    if (skfd <= 0 || ip == NULL) {
        err("invalid parameters\n");
        return -1;
    }

    return  mcast_get_iface_inet(skfd, ip);
}

/*
 * modify ether link layer multicast address
 */
int mcast_modify_ether(char *ifname, int is_add, char *hwaddr, int len)
{
    struct ifreq ifr;
    int fd;
    int cmd = 0;

    memset(&ifr, 0, sizeof(ifr));
    cmd = is_add ? SIOCADDMULTI : SIOCDELMULTI;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memcpy(ifr.ifr_hwaddr.sa_data, hwaddr, len);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("Cannot create socket");
        return -1;
    }
    if (ioctl(fd, cmd, (char*)&ifr) != 0) {
        perror("modify lla mcast failed");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
