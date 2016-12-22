#pragma once

#include <sys/socket.h>

struct mcast_info {
	char name[20];
	int users;
	int st;
	int index;
	int addr[6];
	sa_family_t family;
};
