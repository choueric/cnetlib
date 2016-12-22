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
