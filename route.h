#pragma once

#include <net/if.h>

struct nl_rtentry {
    char rt_dev[IFNAMSIZ];
    uint32_t rt_dst;
    uint32_t rt_gateway;
    uint32_t rt_genmask;
    uint16_t rt_flags;
    short rt_metric;
    unsigned long rt_mtu;
    unsigned long rt_window;
    unsigned long rt_irtt;
};

/*
 * get list of route entries.
 *
 * @array, @size: array to store route entries.
 * @return: <0, fail; others, the number of route entries, 
 */
int route_get_list(struct nl_rtentry *array, int size);

void route_print_entry(struct nl_rtentry *rt, FILE *fp);

/*
 * add route entry.
 * "route add -net 192.56.76.0 netmask 255.255.255.0 dev eth0"
 * "route add -net 127.0.0.0 netmask 255.0.0.0 dev lo"
 * "route del default"
 * "route add default gw 192.168.0.254"
 * "route del -net 172.0.0.0 netmask 255.255.255.0 dev eth0"
 *
 * if @gw is 0.0.0.0, it means the packet for @dst is sent through @dev 
 * directly. default value of @gateway is 0.0.0.0
 *
 * @is_net: 1, @dst is subnet address; 0, @dst is host address.
 * @dst: destination IP address. default is 0.0.0.0
 * @gw: gateway for this route.
 * @mask: network of the destination network.
 * @dev: interface name.
 *
 * @gw, @mask, @dev: if use default value, just pass NULL.
 *
 * @return: 0, success; < 0, fail.
 */
int route_add(int is_net, uint32_t dst, uint32_t *gw, uint32_t *mask, char *dev);

/*
 * add route entry. see 'route_add'.
 */
int route_del(int is_net, uint32_t dst, uint32_t *gw, uint32_t *mask, char *dev);
