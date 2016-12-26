#pragma once

#include <sys/socket.h>

struct mcast_info {
	char name[20];
	int users;
	int st;
	int index;
	unsigned char addr[6];
	sa_family_t family;
};

/*
 * get the multicast list for IPv4 and/or Link layer
 *
 * @array, @size: to store the restults.
 * @family: AF_INET for IPv4; AF_PACKET for Link; AF_UNSPEC for both.
 * @return: >= 0, the number of entries returned; < 0, failed.
 */
int mcast_get_list(struct mcast_info *array, int size, int family);

/*
 * print a mcast_info entry.
 * format: "iface index, iface name: type, address, users"
 */
void mcast_print(struct mcast_info *m, FILE *fp);

/*
 * join a multicast group
 *
 * @skfd: socket fd
 * @ifname: interface name
 * @ip: group IP
 * @return: 0, success; <0 fail.
 */
int mcast_join(int skfd, char *ifname, uint32_t ip);

/*
 * leave a multicast group
 *
 * @skfd: socket fd
 * @ifname: interface name
 * @ip: group IP
 * @return: 0, success; <0 fail.
 */
int mcast_leave(int skfd, char *ifname, uint32_t ip);

/*
 * set TTL
 *
 * in IPv4, type of TTL is u_char
 *
 * @skfd: socket fd
 * @ttl: TLL value to set
 * @return: 0, success; others, fail.
 */
int mcast_set_ttl(int skfd, int ttl);

/*
 * return TLL.
 *
 * @skfd: socket fd
 * @return: value TTL; < 0, fail.
 */
int mcast_get_ttl(int skfd);
