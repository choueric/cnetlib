#include <sys/ioctl.h>
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

#include "address.h"

const char *sa_itos(uint32_t ip, char *str, uint32_t size)
{
    struct in_addr addr = {0};
    addr.s_addr = htonl(ip);
    return inet_ntop(AF_INET, &addr, str, (socklen_t)size);
}

int sa_stoi(const char *str, uint32_t *ip)
{
    struct in_addr addr = {0};
    int ret = 0;

    ret = inet_pton(AF_INET, str, &addr);
    *ip = ntohl(addr.s_addr);

	if (ret == 1)
		return 0;
	else if (ret == 0)
		return -2;
	else
		return ret;
}

void sa_set_addr(struct sockaddr *saddr, uint32_t ip)
{
    struct sockaddr_in *s = (struct sockaddr_in *)saddr;
    s->sin_addr.s_addr = htonl(ip);
}

void sa_set_port(struct sockaddr *saddr, uint16_t port)
{
    struct sockaddr_in *s = (struct sockaddr_in *)saddr;
    s->sin_port = htons(port);
}

void sa_set_family(struct sockaddr *saddr, sa_family_t f)
{
    saddr->sa_family = f;
}

uint32_t sa_get_addr(struct sockaddr *saddr)
{
    struct sockaddr_in *s = (struct sockaddr_in *)saddr;
    return ntohl(s->sin_addr.s_addr);
}

uint16_t sa_get_port(struct sockaddr *saddr)
{
    struct sockaddr_in *s = (struct sockaddr_in *)saddr;
    return ntohs(s->sin_port);
}

sa_family_t sa_get_family(struct sockaddr *saddr)
{
    return saddr->sa_family;
}

const char *sa_ntop(struct sockaddr *saddr, char *str, socklen_t size)
{
    struct sockaddr_in *s = (struct sockaddr_in *)saddr;
    return inet_ntop(AF_INET, &(s->sin_addr), str, size);
}

int sa_pton(const char *str, struct sockaddr *saddr)
{
    struct sockaddr_in *s = (struct sockaddr_in *)saddr;
    int ret = inet_pton(AF_INET, str, &(s->sin_addr));

	if (ret == 1)
		return 0;
	else if (ret == 0)
		return -2;
	else
		return ret;
}
