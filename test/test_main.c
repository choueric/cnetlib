#include <string.h>
#include "test_parse_args.h"

#include "address.h"
#include "iface.h"
#include "multicast.h"
#include "route.h"

#define CHECK_TEST(no, func, ret_check, val_check, print_val) do {\
	if (ret_check) {\
		if (val_check) {\
			ok("["#no"]: OK. "#func"(): ");\
			print_val;\
		} else {\
			err("["#no"]: FAIL. "#func"(): ");\
			print_val;\
		}\
	} else {\
		fatal("["#no"]: "#func"() return value invalid.\n");\
	}\
}while(0)\

static int testAddr()
{
	uint32_t n_ip = 0xc0a80001; // 192.168.0.1
	const char *s_ip = "192.168.0.1";

	{ // [1]
	char str[30] = {0};
	const char *ret = sa_itos(n_ip, str, 30);
	CHECK_TEST(1, sa_itos, ret != NULL, !strcmp(ret, s_ip),
			printf("0x%08x -> %s\n", n_ip, ret));
	}

	{ // [2]
	uint32_t ip = 0;
	int ret = sa_stoi(s_ip, &ip);
	CHECK_TEST(2, sa_stoi, ret == 0, ip == n_ip,
			printf("%s -> 0x%08x\n", s_ip, ip));
	}

	{ // [3] [5] [4]
	struct sockaddr addr = {0};
	sa_set_addr(&addr, n_ip);
	sa_set_port(&addr, 80);
	sa_set_family(&addr, AF_INET);

	char str[30] = {0};
	const char *ret = sa_ntop(&addr, str, 30);
	CHECK_TEST(3, sa_ntop_sa_set_all, ret != NULL, !strcmp(ret, s_ip),
			printf("0x%08x -> %s\n", n_ip, ret));
	printf("     port: %d, family = %d\n", sa_get_port(&addr), sa_get_family(&addr));
	}

	{ // [6]
	struct sockaddr addr = {0};
	int ret = sa_pton(s_ip, &addr);
	uint32_t ip = sa_get_addr(&addr);
	CHECK_TEST(4, sa_pton_sa_get_addr, ret == 0, ip == n_ip,
			printf("%s -> 0x%08x\n", s_ip, ip));
	}

	return 0;
}

static int testIface()
{
	const char *ifname = "eth0";

	{
	int n;
	for (int i = 1;1; i++) {
		char name[IFNAMSIZ] = {0};
		if (iface_get_ifname_by_idx(i, name, IFNAMSIZ) != NULL) {
			printf("%d: %s\n", i, name);
		} else {
			n = i - 1;
			break;
		}
	}
	CHECK_TEST(1, iface_get_ifname_by_idx, 1, 1, printf("there are %d iface(s)\n", n));
	}

	{
	struct net_iface ifarray[4];
	int ret = iface_get_list(ifarray, 4);
	CHECK_TEST(2, iface_get_list, ret > 0, 1, printf("there are %d iface(s)\n", ret));
	if (ret > 0) {
		for (int i = 0; i < ret; i++) {
			int r = iface_get_info(&ifarray[i]);
			CHECK_TEST(2, iface_get_info, r == 0, 1, iface_print_info(&ifarray[i], stdout));
		}
	}
	}

	{
	short ret = iface_get_flags(ifname);
	CHECK_TEST(3, iface_get_flags, ret > 0, 1, iface_print_flags(stdout, ret));
	ret = iface_get_flags("lo");
	CHECK_TEST(3, iface_get_flags, ret > 0, 1, iface_print_flags(stdout, ret));
	}

	{
	char str[20] = {0};
	short ret = iface_get_hwaddr(ifname, str, 20);
	CHECK_TEST(4, iface_get_hwaddr, ret >= 0, 1, printf("%s: %s\n", ifname, str));
	}

	{
	int ret = 0;
	ret = iface_get_metric(ifname);
	CHECK_TEST(5, iface_get_metric, ret >= 0, 1, printf("%s: metric = %d\n", ifname, ret));

	ret = iface_get_mtu(ifname);
	CHECK_TEST(5, iface_get_mtu, ret >= 0, 1, printf("%s: mtu = %d\n", ifname, ret));

	ret = iface_get_txqlen(ifname);
	CHECK_TEST(5, iface_get_txqlen, ret >= 0, 1, printf("%s: txqlen = %d\n", ifname, ret));

	uint32_t ip;
	ret = iface_get_ip(ifname, &ip);
	char str[30] = {0};
	CHECK_TEST(5, iface_get_ip, ret == 0, 1, printf("%s: ip = %s\n", ifname, sa_itos(ip, str, 30)));

	ret = iface_get_broadaddr(ifname, &ip);
	CHECK_TEST(5, iface_get_broadaddr, ret == 0, 1, printf("%s: broadcast = %s\n", ifname, sa_itos(ip, str, 30)));

	ret = iface_get_netmask(ifname, &ip);
	CHECK_TEST(5, iface_get_netmask, ret == 0, 1, printf("%s: netmask = %s\n", ifname, sa_itos(ip, str, 30)));
	}

	return 0;
}

static int testMulticast()
{
	{
	struct mcast_info info[10];
	int ret = mcast_get_list(info, 10, AF_UNSPEC);
	CHECK_TEST(1, mcast_get_list, ret >= 0, 1, printf("entry number = %d\n", ret));
	for (int i = 0; i < ret; i++)
		mcast_print(&info[i], stdout);
	}
	return 0;
}

static int testRoute()
{
	{
	struct nl_rtentry entries[10];
	int ret = route_get_list(entries, 10);
	CHECK_TEST(1, route_get_list, ret >= 0, 1, printf("entry number = %d\n", ret));
	for (int i = 0; i < ret; i++)
		route_print_entry(&entries[i], stdout);
	}
	return 0;
}

int main(int argc, char **argv)
{
	parse_args(argc, argv);
	print_options();

	if (optTestCase == TEST_ADDR)
		return testAddr();

	if (optTestCase == TEST_IFACE)
		return testIface();

	if (optTestCase == TEST_MULTICAST)
		return testMulticast();

	if (optTestCase == TEST_ROUTE)
		return testRoute();

	return 0;
}
