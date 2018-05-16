#ifndef MY_ROUTE_H
#define MY_ROUTE_H

#include "core.h"

#define CONNS_SIZE 32

struct ip {
	LIST_ENTRY(ip) list;
	ipaddr_t addr;
	int nr_used_ports;
	uint16_t used_ports[CONNS_SIZE];
};

LIST_HEAD(ip_head, ip);

struct if_dev {
	char ifname[IFNAMSIZ];
	struct eth_addr hwaddr;
	int is_loopback;
	int ifindex;
	int nr_ips;
	struct ip **ips;
};

enum route_msg_type {
	ROUTE_MSG_LINK,
	ROUTE_MSG_ADDR,
	ROUTE_MSG_ROUTE
};

enum route_msg_cmd {
	ROUTE_CMD_ADD,
	ROUTE_CMD_DEL,
};

struct route_entry {
	int af;
	struct if_dev *dev;
	ipaddr_t dst;
	ipaddr_t next_hop;
	struct ip *src;
};

struct route_msg_link {
	int flags;
	int mtu;
	struct eth_addr hwaddr;
	char name[IFNAMSIZ];
};

struct route_msg_route {
	unsigned int pfx;
	ipaddr_t dst;
	ipaddr_t next_hop;
};

struct route_msg {
	enum route_msg_cmd cmd;
	enum route_msg_type type;
	int af;
	int dev_id;

	union {
		struct route_msg_link link;
		ipaddr_t addr;
		struct route_msg_route route;
	};
};

typedef void (*route_on_msg_t)(struct route_msg *msg, void *udata);

int route_dump(route_on_msg_t cb, void *udata);

int route_open_fd();

int route_read(int fd, route_on_msg_t cb, void *udata);

void route_init(struct if_dev *dev);

struct ip *ip_get4(be32_t addr_ip4);

int route_get4(struct route_entry *route);

int  get_arp_cache(be32_t next_hop, struct eth_addr *addr);
void set_arp_cache(be32_t next_hop, struct eth_addr *addr);

#endif
