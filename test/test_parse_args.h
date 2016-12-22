#pragma once

#define fatal(fmt, args...) {\
  printf("\n\E[32;31m%s:%d fatal:\E[32;00m " fmt, __FILE__, __LINE__, ##args);\
  exit(1);\
}

#define err(fmt, args...) {\
  printf("\n\E[32;31m%s:%d error:\E[32;00m " fmt, __FILE__, __LINE__, ##args);\
}

#define ok(fmt, args...) {\
  printf("\E[32;32m" fmt "\E[32;00m", ##args);\
}

typedef enum {
	TEST_INVALID,
	TEST_ADDR,
	TEST_IFACE,
	TEST_MULTICAST,
	TEST_ROUTE,
} TestCase_t;

extern TestCase_t optTestCase;

void parse_args(int argc, char **argv);
void print_options();
void print_usage(char *p);
