#include "route.h"


struct route_entry_long {
	LIST_ENTRY(route_entry_long) list;
	int af;
	int pfx;
	struct if_dev *dev;
	ipaddr_t dst;
	ipaddr_t next_hop;
};

LIST_HEAD(route_entry_long_head, route_entry_long);

struct arp_cache_entry {
	LIST_ENTRY(arp_cache_entry) list;
	be32_t next_hop;
	struct eth_addr addr;
};

LIST_HEAD(arp_cache_entry_head, arp_cache_entry);

static struct route_entry_long_head route_entries;
static struct arp_cache_entry_head arp_cache;
static struct ip_head ips;
static struct if_dev *loopback;

static void
on_msg_addr_add(struct if_dev *dev, ipaddr_t *addr)
{
	struct ip *ip;

	ip = ip_get4(addr->ipv4);
	if (ip == NULL) {
		ip = xmalloc(sizeof(*ip));
		memset(ip, 0, sizeof(*ip));
		ip->addr = *addr;
	}

	LIST_INSERT_HEAD(&ips, ip, list);

	dev->ips = xrealloc(dev->ips, sizeof(*ip) * (dev->nr_ips + 1));
	dev->ips[dev->nr_ips] = ip;
	dev->nr_ips++;
}

static void
on_msg_addr(struct if_dev *dev, struct route_msg *msg)
{
	if (msg->af == AF_INET && msg->cmd == ROUTE_CMD_ADD) {
		on_msg_addr_add(dev, &msg->addr);
	}
}

static void
on_msg_route_add(struct if_dev *dev, struct route_msg_route *msg)
{
	struct route_entry_long *route;

	assert(msg->pfx <= 32);

	LIST_FOREACH(route, &route_entries, list) {
		if (route->dst.ipv4 == msg->dst.ipv4 &&
			route->pfx == msg->pfx) {

			route->next_hop = msg->next_hop;
			return;
		}
	}

	route = xmalloc(sizeof(*route));
	memset(route, 0, sizeof(*route));

	route->af = AF_INET;
	route->dst = msg->dst;
	route->dev = dev;
	route->pfx = msg->pfx;
	route->next_hop = msg->next_hop;

	LIST_INSERT_HEAD(&route_entries, route, list);
}

static void
on_msg_route(struct if_dev *dev, struct route_msg *msg)
{
	if (msg->af != AF_INET)
		return;

	if (msg->cmd == ROUTE_CMD_ADD)
		on_msg_route_add(dev, &msg->route);
}

static void
on_msg(struct route_msg *msg, void *udata)
{
	struct if_dev *dev;

	dev = udata;

	if (dev->ifindex != msg->dev_id) {
		return;
	}

	switch (msg->type) {
	case ROUTE_MSG_LINK:
		if (msg->link.flags & IFF_LOOPBACK) {
			dev->is_loopback = 1;
			loopback = dev;
		}
		dev->hwaddr = msg->link.hwaddr;
		break;

	case ROUTE_MSG_ADDR:
		on_msg_addr(dev, msg);
		break;

	case ROUTE_MSG_ROUTE:
		on_msg_route(dev, msg);
		break;
	}
}

void
route_init(struct if_dev *dev)
{
	LIST_INIT(&route_entries);
	LIST_INIT(&ips);
	route_dump(on_msg, dev);
}

struct ip *
select_src(ipaddr_t *dst, struct ip **srcs, size_t nr_srcs)
{
	int i;
	uint32_t dst_ipv4, d, x;
	struct ip *ip;

	dst_ipv4 = BE32_TO_CPU(dst->ipv4);
	ip = NULL;
	d = UINT32_MAX;

	for (i = 0; i < nr_srcs; ++i) {
		x = BE32_TO_CPU(srcs[i]->addr.ipv4) - dst_ipv4;
		if (d >= x) {
			d = x;
			ip = srcs[i];
		}
	}

	return ip;
}

struct ip *
ip_get4(uint32_t x)
{
	struct ip *ip;
	
	ip = NULL;

	LIST_FOREACH(ip, &ips, list) {
		if (ip->addr.ipv4 == x) {
			break;
		}
	}

	return ip;
}

int
route_get4(struct route_entry *out)
{
	int pfx, max_pfx, netmask;
	uint32_t dst_ipv4, route_dst_ipv4, a, b;
	struct ip *ip;
	struct route_entry_long *route, *best_route;

	out->af = AF_INET;

	ip = ip_get4(out->dst.ipv4);
	if (ip != NULL) {
		// local traffic
		if (loopback == NULL) {
			return -1;
		} else {
			out->next_hop = ipaddr_zero;
			out->dev = loopback;
			out->src = ip;
			return 0;
		}
	}

	dst_ipv4 = BE32_TO_CPU(out->dst.ipv4);

	max_pfx = -1;
	best_route = NULL;

	LIST_FOREACH(route, &route_entries, list) {
		route_dst_ipv4 = BE32_TO_CPU(route->dst.ipv4);
		pfx = route->pfx;

		if (pfx == 0) {
			netmask = 0;
		} else {
			netmask = 0xFFFFFFFF << (32 - pfx);
		}

		a = dst_ipv4 & netmask;
		b = route_dst_ipv4 & netmask;

		if (a == b) {
			if (max_pfx <= pfx) {
				max_pfx = pfx;
				best_route = route;
			}
		}
	}

	if (best_route == NULL) {
		return -1;
	}

	route = best_route;

	if (route->dev->nr_ips == 0) {
		return -1;
	}

	out->next_hop = route->next_hop;
	out->dev = route->dev;
	out->src = select_src(&out->dst, out->dev->ips, out->dev->nr_ips);

	return 0;
}

struct arp_cache_entry *
get_arp_cache_entry(be32_t next_hop)
{
	struct arp_cache_entry *entry;

	LIST_FOREACH(entry, &arp_cache, list) {
		if (entry->next_hop == next_hop) 
			return entry;
	}

	return NULL;
}

int
get_arp_cache(be32_t next_hop, struct eth_addr *addr)
{
	struct arp_cache_entry *entry;

	if ((entry = get_arp_cache_entry(next_hop)) == NULL) {
		return 0;
	}

	*addr = entry->addr;
	return 1;
}

void
set_arp_cache(be32_t next_hop, struct eth_addr *addr)
{
	struct arp_cache_entry *entry;

	if ((entry = get_arp_cache_entry(next_hop)) == NULL) {
		entry = xmalloc(sizeof(*entry));
		entry->next_hop = next_hop;
		LIST_INSERT_HEAD(&arp_cache, entry, list);
	}

	entry->addr = *addr;
}
