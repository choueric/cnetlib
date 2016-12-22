#include <string.h>
#include "test_parse_args.h"

#include "address.h"

#define CHECK_TEST(no, func, ret_check, val_check, print_val) do {\
	if (ret_check) {\
		if (val_check) {\
			ok("["#no"]: OK."#func"(): ");\
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


int main(int argc, char **argv)
{
	parse_args(argc, argv);
	print_options();

	if (optTestCase == TEST_ADDR)
		return testAddr();

	return 0;
}
