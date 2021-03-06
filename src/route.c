#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <linux/tcp.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include "route.h"
#include "address.h"
#include "log.h"

/*
 * modified from source code of net-tools_1.60, route.c
 */

#define PATH_PROCNET_ROUTE "/proc/net/route"
    
#define ROUTE_LIST_FMT "%16s\t%128s\t%128s\t%X\t%d\t%d\t%d\t%128s\t%d\t%d\t%d\n"

#define genmask_in_addr(x) (((struct sockaddr_in *)&((x).rt_genmask))->sin_addr.s_addr)

#define RT_ACTION_ADD 1
#define RT_ACTION_DEL 0

static inline void set_addr_family(struct sockaddr *sa, uint32_t addr, sa_family_t f)
{
    sa_set_family(sa, f);
    sa_set_addr(sa, addr);
}

static void _set_entry(struct nl_rtentry *ent, char *iface, 
        uint32_t dst, uint32_t gw, unsigned short flags,
        short metric, uint32_t mask, unsigned long mtu,
        unsigned long window, unsigned long irtt)
{
    strncpy(ent->rt_dev, iface, IFNAMSIZ);
    ent->rt_dst = dst;
    ent->rt_gateway = gw;
    ent->rt_genmask = mask;
    ent->rt_flags = flags;
    ent->rt_metric = metric;
    ent->rt_mtu = mtu;
    ent->rt_window = window;
    ent->rt_irtt = irtt;
}

static uint32_t _str2u32(const char *str)
{
    uint32_t i = 0;
    int ret = sscanf(str, "%08x", &i);
    if (ret != 1) {
        err("sscanf for IP address failed\n");
        return 0;
    }
    return ntohl(i);
}

////////////////////////////////////////////////////////////////////////////////

/* fib_route_seq_show() in net/ipv4/fib_trie.c */
static int _route_get_list(struct nl_rtentry *array, int size)
{
    char buff[512], iface[IFNAMSIZ];
    char gate_addr[32], net_addr[32], mask_addr[32];
    int ret = 0, iflags = 0, metric = 0, refcnt = 0, use = 0;
    int mtu = 0, window = 0, irtt = 0;
    uint32_t snet_target, snet_gateway, snet_mask;
    int i = 0;

    FILE *fp = fopen(PATH_PROCNET_ROUTE, "r");
    if (!fp) {
        err("open %s failed: %m\n", PATH_PROCNET_ROUTE);
        return -1;
    }

    bzero(array, sizeof(struct nl_rtentry) * size);

    if (!fgets(buff, sizeof(buff) - 1, fp)) {
        err("eat first line failed\n");
        return -1;
    }

    i = 0;
    while (fgets(buff, sizeof(buff) - 1, fp)) {
        ret = sscanf(buff, ROUTE_LIST_FMT,
                iface, net_addr, gate_addr,
                &iflags, &refcnt, &use, &metric, mask_addr,
                &mtu, &window, &irtt);
        if (ret < 10 || !(iflags & RTF_UP)) {
            err("warning: faile to parse or unusable route entry: %s\n", buff);
            continue;
        }

        snet_target = _str2u32(net_addr);
        snet_gateway = _str2u32(gate_addr);
        snet_mask = _str2u32(mask_addr);

        _set_entry(array + i, iface, snet_target, snet_gateway, 
                iflags, metric, snet_mask, mtu, window, irtt);
        i++;
        if (i >= size) {
            err("over %d max rt entry number\n", size);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return i;
}

static int do_route_modify(struct rtentry *rt, int action)
{
    int ret = 0;
    int skfd = 0;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        err("create socket fail: %m\n");
        return -1;
    }

    int cmd = ((action == RT_ACTION_DEL) ? SIOCDELRT : SIOCADDRT);
    if (ioctl(skfd, cmd, rt) < 0) {
        err("rt ioctl failed: %m\n");
        ret = -1;
    }
    close(skfd);

    return ret;
}

/*
 * "route add -net 192.56.76.0 netmask 255.255.255.0 dev eth0"
 * "route add -net 127.0.0.0 netmask 255.0.0.0 dev lo"
 * "route del default"
 * "route add default gw 192.168.0.254"
 * "route del -net 172.0.0.0 netmask 255.255.255.0 dev eth0"
 *
 * default means destination is 0.0.0.0 
 *
 * if @gateway is 0.0.0.0, it means the packet for @dst is sent through @dev 
 * directly. default value of @gateway is 0.0.0.0
 *
 * @metric, @mtu, @window can be default value
 *
 * @is_net: is net or host, TRUE(1) is net, FALSE(0) is host
 */
static int route_modify(int action, int is_net, 
        uint32_t dst, uint32_t *gateway, uint32_t *netmask, char *dev,
        short *metric, unsigned long *mtu, unsigned long *window)
{
    struct rtentry rt;

    memset((char *)&rt, 0, sizeof(struct rtentry));

    /* Fill in flags. */
    rt.rt_flags = (RTF_UP | RTF_HOST);
    if (is_net)
        rt.rt_flags &= ~RTF_HOST;

    set_addr_family(&rt.rt_dst, dst, AF_INET);

    if (gateway != NULL) {
        set_addr_family(&rt.rt_gateway, *gateway, AF_INET);
        rt.rt_flags |= RTF_GATEWAY;
    }

    if (netmask != NULL)
        set_addr_family(&rt.rt_genmask, *netmask, AF_INET);

    if (dev != NULL)
        rt.rt_dev = dev;
    if (metric != NULL)
        rt.rt_metric = *metric + 1;

    if (mtu != NULL) {
        if (*mtu < 64 || *mtu > 65536) {
            err("route: Invalid MSS/MTU.\n");
            return -1;
        }
        rt.rt_mss = *mtu;
        rt.rt_flags |= RTF_MSS;
    }
    if (window != NULL) {
        if (*window < 128) {
            err("route: Invalid window.\n");
            return -1;
        }
        rt.rt_flags |= RTF_WINDOW;
        rt.rt_window = *window;
    }

    /* sanity checks.. */
    if (genmask_in_addr(rt)) {
        uint32_t mask = ~ntohl(genmask_in_addr(rt));
        if ((rt.rt_flags & RTF_HOST) && mask != 0xffffffff) {
            err("netmask %.8x doesn't useful when set host route\n", mask);
            return -1;
        }
        if (mask & (mask + 1)) {
            err("route: invalid netmask 0x%x\n", *netmask);
            return -1;
        }
        uint32_t dst_net = ((struct sockaddr_in *) &rt.rt_dst)->sin_addr.s_addr;
        if (dst_net & ~genmask_in_addr(rt)) {
            err("route: netmask doesn't match route address\n");
            return -1;
        }
    }

    /* Fill out netmask if still unset */
    if ((action == RT_ACTION_ADD) && rt.rt_flags & RTF_HOST)
        genmask_in_addr(rt) = 0xffffffff;

    return do_route_modify(&rt, action);
}

// flags of route entry. from kernel, include/uapi/linux/route.h
// #define RTF_UP	    	0x0001		/* route usable		  	*/
// #define RTF_GATEWAY 	0x0002		/* destination is a gateway	*/
// #define RTF_HOST    	0x0004		/* host entry (net otherwise)	*/
// #define RTF_REINSTATE	0x0008		/* reinstate route after tmout	*/
// #define RTF_DYNAMIC 	0x0010		/* created dyn. (by redirect)	*/
// #define RTF_MODIFIED	0x0020		/* modified dyn. (by redirect)	*/
// #define RTF_MTU	    	0x0040		/* specific MTU for this route	*/
// #define RTF_MSS	    	RTF_MTU		/* Compatibility :-(		*/
// #define RTF_WINDOW  	0x0080		/* per route window clamping	*/
// #define RTF_IRTT    	0x0100		/* Initial round trip time	*/
// #define RTF_REJECT  	0x0200		/* Reject route			*/
static void print_flags(FILE *fp, uint16_t flags)
{
    if (flags == 0)
        fprintf(fp, "[NO FLAGS] ");
	if (flags & RTF_UP)
		fprintf(fp, "UP ");
	if (flags & RTF_GATEWAY)
		fprintf(fp, "GATEWAY ");
	if (flags & RTF_HOST)
		fprintf(fp, "HOST ");
	if (flags & RTF_REINSTATE)
		fprintf(fp, "REINSTATE ");
	if (flags & RTF_DYNAMIC)
		fprintf(fp, "DYNAMIC ");
	if (flags & RTF_MODIFIED)
		fprintf(fp, "MODIFIED ");
	if (flags & RTF_MTU)
		fprintf(fp, "MTU ");
	if (flags & RTF_MSS)
		fprintf(fp, "MSS ");
	if (flags & RTF_WINDOW)
		fprintf(fp, "WINDOW ");
	if (flags & RTF_IRTT)
		fprintf(fp, "IRTT ");
	if (flags & RTF_REJECT)
		fprintf(fp, "REJECT ");
}



static void _route_print_entry(FILE *fp, struct nl_rtentry *ent)
{
    char str[32];
    fprintf(fp, "dst: %-16s ", sa_itos(ent->rt_dst, str, sizeof(str)));
    fprintf(fp, "gw: %-16s ", sa_itos(ent->rt_gateway, str, sizeof(str)));
    fprintf(fp, "genmask: %-16s ", sa_itos(ent->rt_genmask, str, sizeof(str)));
    fprintf(fp, "iface: %s,  flags: ", ent->rt_dev);
	print_flags(fp, ent->rt_flags);
	fprintf(fp, "metric: %d,  mtu: %lu.\n", ent->rt_metric, ent->rt_mtu);
}

////////////////////////////////////////////////////////////////////////////////

int route_get_list(struct nl_rtentry *array, int size)
{
    if (array == NULL || size <= 0) {
        err("invalid parameters\n");
        return -1;
    }

    return _route_get_list(array, size);
}

void route_print_entry(struct nl_rtentry *rt, FILE *fp)
{
    if (rt == NULL || fp == NULL) {
        err("invalid parameter\n");
        return;
    }
    _route_print_entry(fp, rt);
}

int route_add(int is_net, uint32_t dst, uint32_t *gw, uint32_t *mask, char *dev)
{
    return route_modify(RT_ACTION_ADD, is_net, dst, gw, mask, dev, NULL, NULL, NULL);
}

int route_del(int is_net, uint32_t dst, uint32_t *gw, uint32_t *mask, char *dev)
{
    return route_modify(RT_ACTION_DEL, is_net, dst, gw, mask, dev, NULL, NULL, NULL);
}

