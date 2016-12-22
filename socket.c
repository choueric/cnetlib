/*
 * encapsulation of socket functions for BigDipper.
 * communication and options setting.
 */

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
#include <fcntl.h>
#include <strings.h>

#include "address.h"

int sock_set_block(int sockfd, int is_block)
{
    int flags = 0;

    if ( (flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
        fprintf(stderr, "fcntl get flag fail\n");
        return -1;
    }

    is_block ?  (flags |= O_NONBLOCK) : (flags &= ~O_NONBLOCK);
    if (fcntl(sockfd, F_SETFL, flags) < 0) {
        fprintf(stderr, "fcntl set flag failed.\n");
        return -1;
    }

    return 0;
}

// NAGLE algorythm
int sock_set_nodelay(int sockfd, int is_nodelay)
{
    int ret = 0;
    int optval = is_nodelay ? 1: 0;

	ret = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
	if (ret != 0) {
		printf("setsockopt IPPROTO_TCP TCP_NODELAY failed: %m\n");
		return -1;
	}

    return ret;
}

// close socket and discard buffer data
int sock_set_linger(int sockfd, int is_linger)
{
	struct linger so_linger;
    int ret = 0;

    bzero(&so_linger, sizeof(so_linger));
	so_linger.l_onoff = is_linger ? 1: 0;
	so_linger.l_linger = 0;

	ret = setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger)); 
	if (-1 == ret) {
		printf("setsockopt SOL_SOCKET SO_LINGER failed: %m\n");
		return -1;
	}

    return ret;
}

static int sock_set_tos(int skfd, int tos)
{
    int ret = 0;

    ret = setsockopt(skfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    if (ret < 0) {
		printf("setsockopt IPPROTO_IP, IP_TOS failed: %m\n");
		return -1;
    }

    return ret;
}

static int sock_get_tos(int skfd, int *tos)
{
    int ret = 0;
    int opt = 0;
    socklen_t optlen = sizeof(int);

    ret = getsockopt(skfd, IPPROTO_IP, IP_TOS, &opt, &optlen);
    if (ret < 0) {
		printf("getsockopt IPPROTO_IP, IP_TOS failed: %m\n");
        *tos = 0;
		return -1;
    }
    *tos = opt;

    return ret;
}

int MM_sock_set_tos(int skfd, int tos)
{
    return sock_set_tos(skfd, tos);
}

int MM_sock_get_tos(int skfd, int *tos)
{
    if (tos == NULL) {
        printf("Invalid parameters\n");
        return -1;
    }

    return sock_get_tos(skfd, tos);
}
