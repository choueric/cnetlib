#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>

#include "test_parse_args.h"

TestCase_t optTestCase = TEST_INVALID;

#if 0
static const char *def(bool val)
{
	return val ? "enabled": "disabled";
}
#endif

static const char *testCaseName(TestCase_t c)
{
	switch (c) {
		case TEST_ADDR: return "addr";
		case TEST_IFACE: return "iface";
		case TEST_MULTICAST: return "multicast";
		case TEST_ROUTE: return "route";
		default: return "unknow";
	}
}

void print_usage(char *p)
{
	fprintf(stderr, "Usage: %s <-t> [-h]\n", p);
	fprintf(stderr, "    -t: choose Test Case. Default is [%s]\n", testCaseName(optTestCase));
	fprintf(stderr, "        value: [addr, iface, multicast, route].\n");
	fprintf(stderr, "    -h: help message\n");
}

static TestCase_t parseTestCase(char *arg)
{
	if (!strcmp(arg, "addr"))
		return TEST_ADDR;
	if (!strcmp(arg, "iface"))
		return TEST_IFACE;
	if (!strcmp(arg, "multicast"))
		return TEST_MULTICAST;
	if (!strcmp(arg, "route"))
		return TEST_ROUTE;

	fatal("invalid test case\n");
	return -1;
}

void parse_args(int argc, char **argv)
{
	int opt;
	
	while ( (opt = getopt(argc, argv, "t:h")) != -1) {
		switch (opt) {
			case 't': optTestCase = parseTestCase(optarg); break;
			case 'h':
			default:
				print_usage(argv[0]);
				exit(0);
		}
	}

	if (optTestCase == TEST_INVALID) {
		print_usage("invalid test case");
		exit(0);
	}
}

void print_options()
{
	printf("\n=========================================================\n");
	printf("  test case: %s\n", testCaseName(optTestCase));
	printf("=========================================================\n");
}
