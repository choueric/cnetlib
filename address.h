#pragma once

#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <stddef.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

/*
 * byte order of data stored in struct sockaddr is in BigEndian format, ie. 
 * network byte order.
 * so we need a set of functions to deal with the difference from host apect.
 * Besides, these functions can encapsulate the detailed structure
 * of struct sockaddr and other socket address stuffs.
 *
 * By now, they only support IPv4 protocol.
 */

/*
   for IP, PORT and FAMILY

  +---------------+           [1]                 +---------------+
  | numeric       | ----------------------------> | presentation  |
  | uint32_t      | <---------------------------- | string        |
  | 0xc0a80001    |           [2]                 | "192.168.0.1" |
  +---------------+ <------+           +--------> +---------------+
       |                   |           |                  |
       |                   |           |                  |
       | [3]           [4] |           | [5]          [6] |
       |                   |           |                  |
       |              +--------------------+              |
       |              | linux native net   |              |
       +------------> | struct sockaddr    | <------------+
                      | network byte order |
                      +--------------------+
*/


/*
 * [1]
 * numeric to presentation
 * integer to string
 * transfer @IP address (host byte order) to ascii format and store in @str
 * @return: non-NULL pointer to @str when ok; NULL when fail.
 */
const char *sa_itos(uint32_t ip, char *str, uint32_t size);

/*
 * [2]
 * presentaion to numeric format
 * string to integer
 * transfer IP in @str to numeric format and store in @ip
 * @ip is already in host's endian
 * @return: 1, ok; 0, @str is valid; -1, failed, errno is set.
 */
int sa_stoi(const char *str, uint32_t *ip);

/*
 * [3]
 * @ip: ip address to set, in host's endian format
 */
void sa_set_addr(struct sockaddr *saddr, uint32_t ip);

/*
 * [3]
 * @port: port to set, in host's endian format
 */
void sa_set_port(struct sockaddr *saddr, uint16_t port);

/* [3]*/
void sa_set_family(struct sockaddr *saddr, sa_family_t f);

/* [4] */
uint32_t sa_get_addr(struct sockaddr *saddr);

/* [4] */
uint16_t sa_get_port(struct sockaddr *saddr);

/* [4] */
sa_family_t sa_get_family(struct sockaddr *saddr);

/*
 * [5]
 * native to presentation
 * transfer IP address (network byte order) in @saddr to ascii format and store in @str
 * @return: non-NULL pointer to @str when ok; NULL when fail.
 */
const char *sa_ntop(struct sockaddr *saddr, char *str, socklen_t size);

/*
 * [6]
 * presentaion to native
 * transfer IP in @str to numeric format and store in @saddr
 * IP in @saddr is network byte order.
 * @return: 1, ok; 0, @str is valid; -1, failed, errno is set.
 */
int sa_pton(const char *str, struct sockaddr *saddr);
