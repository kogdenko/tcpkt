#include "route.h"

static int
ipaddr_from_sockaddr(ipaddr_t *dst, struct sockaddr *sa)
{
	struct sockaddr_in *sa_in;
	struct sockaddr_in6 *sa_in6;

	switch (sa->sa_family) {
	case AF_INET:
		sa_in = (struct sockaddr_in *)sa;
		dst->ipv4 = sa_in->sin_addr.s_addr;
		return 0;

	case AF_INET6:
		sa_in6 = (struct sockaddr_in6 *)sa;
		memcpy(dst->ipv6, sa_in6->sin6_addr.s6_addr, 16);
		return 0;

	default:
		return -1;

	}
}

/*static void
print_sockaddr(struct sockaddr *sa)
{
	struct sockaddr_dl *sa_dl;
	ipaddr_t addr;

	if (sa == NULL) {
		printf("(null)");
	} else if (sa->sa_family == AF_INET || sa->sa_family == AF_INET6) {
		ipaddr_from_sockaddr(&addr, sa);
		print_ip(sa->sa_family, &addr);
	} else if (sa->sa_family == AF_LINK) {
		sa_dl = (struct sockaddr_dl *)sa;
		printf("link#%d", sa_dl->sdl_index);
	} else {
		assert(!"bad family");
	}
}*/

static void
print_route(int id, struct sockaddr *sa)
{
/*	switch (id) {
	case RTAX_DST: printf("dst"); break;
	case RTAX_GATEWAY: printf("gateway"); break;
	case RTAX_NETMASK: printf("netmask"); break;
	case RTAX_GENMASK: printf("genmask"); break;
	case RTAX_IFP: printf("ifp"); break;
	case RTAX_IFA: printf("ifa"); break;
	case RTAX_AUTHOR: printf("author"); break;
	case RTAX_BRD: printf("brd"); break;
	default: printf("%d", id); break;
	}

	printf(": ");
	print_sockaddr(sa);
	printf("\n");*/
}

static int
get_route_addrs(void *buf, size_t count, int flags,
                struct sockaddr **addrs, int verbose)
{
	int i, size, sa_size;
	struct sockaddr *sa;

	size = 0;

	for (i = 0; i < RTAX_MAX; ++i) {
		if (flags & (1 << i)) {
			sa = (struct sockaddr *)((uint8_t *)buf + size);
			addrs[i] = sa;
			sa_size = SA_SIZE(sa);
			if (size + sa_size > count)
				return -1;
			if (verbose) {
				print_route(i, sa);
			}
			size += sa_size;
		} else {
			addrs[i] = NULL;
		}
	}

	return 0;
}

static int
get_mtu(const char *ifname)
{
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		lerr(errno, "socket(AF_INET, SOCK_DGRAM) failed");
		return -1;
	}	

	ifr.ifr_addr.sa_family = AF_INET;
	strzcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFMTU, (caddr_t)&ifr) == -1) {
		lerr(errno, "ioctl(SIOCGIFMTU, %s) failed", ifname);
		close(fd);
		return -1;
	}

	close(fd);

	return ifr.ifr_mtu;
}

static void
ifa_dl(struct route_msg_link *link, struct ifaddrs *ifa)
{
	struct sockaddr_dl *addr;

	addr = (struct sockaddr_dl *)ifa->ifa_addr;
	memcpy(link->hwaddr.bytes, LLADDR(addr), 6);
	link->flags = ifa->ifa_flags;
}

static int
handle_link(route_on_msg_t cb, void *udata, int is_add, int ifindex)
{
	struct ifaddrs *ifap, *ifa;
	struct route_msg msg;

	memset(&link, 0, sizeof(link));

	msg.cmd = is_add ? ROUTE_CMD_ADD : ROUTE_CMD_DEL;
	msg.type = ROUTE_MSG_LINK;
	msg.dev_id = ifindex;
	if (if_indextoname(ifindex, msg.link.name) == NULL) {
		lerr(errno, "if_indextoname(%d) failed", ifindex);
		return -1;
	}

	if (getifaddrs(&ifap) == -1) {
		lerr(errno, "getifaddrs() failed");
		return -1;
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_LINK &&
			!strcmp(ifa->ifa_name, msg.link.name)) {

			ifa_dl(&msg.link, ifa);
			break;
		}
	}

	freeifaddrs(ifap);

	if (ifa == NULL) {
		lerr(errno, "getifaddrs(): interface %s does not exist", msg.link.name);
		return -1;
	}

	if ((msg.link.mtu = get_mtu(msg.link.name)) == -1) {
		return -1;
	}

	(*cb)(&msg, udata);

	return 1;
}

static int
handle_addr(route_on_msg_t cb, void *udata,
            int is_add, struct ifa_msghdr *ifam)
{
	struct sockaddr *addrs[RTAX_MAX];
	struct sockaddr *ifa, *ifp;
	struct sockaddr_dl *ifp_dl;
	struct route_msg msg;

	if (get_route_addrs(ifam + 1, ifam->ifam_msglen - sizeof(*ifam),
	                    ifam->ifam_addrs, addrs, 0) == -1) {

		return -1;
	}

	ifa = addrs[RTAX_IFA];
	ifp = addrs[RTAX_IFP];

	if (ifa == NULL || ifp == NULL) {
		return -1;
	}

	if (ifp->sa_family != AF_LINK) {
		return -1;
	}

	ifp_dl = (struct sockaddr_dl *)ifp;

	memset(&msg, 0, sizeof(msg));
	msg.cmd = is_add ? ROUTE_CMD_ADD : ROUTE_CMD_DEL;
	msg.type = ROUTE_MSG_ADDR;
	msg.dev_id = ifp_dl->sdl_index;

	if (ifa->sa_family != AF_INET && ifa->sa_family != AF_INET6) {
		return -1;
	}

	msg.af = ifa->sa_family;
	ipaddr_from_sockaddr(&msg.addr, ifa);

	if (cb != NULL) {
		(*cb)(&msg, udata);
	}

	return 1;
} 

static int
handle_route(route_on_msg_t cb, void *udata,
             int is_add, struct rt_msghdr *rtm)
{
	struct sockaddr *addrs[RTAX_MAX];
	struct sockaddr *dst, *netmask, *gateway;
	struct sockaddr_dl *gateway_dl;
	struct route_msg msg;
	ipaddr_t tmp;

	if (get_route_addrs(rtm + 1, rtm->rtm_msglen - sizeof(*rtm),
	                    rtm->rtm_addrs, addrs, 0)) {

		return -1;
	}

	dst = addrs[RTAX_DST];
	netmask = addrs[RTAX_NETMASK];
	gateway = addrs[RTAX_GATEWAY];

	if (dst == NULL || netmask == NULL || gateway == NULL) {
		return -1;
	}

	if (dst->sa_family != AF_INET && dst->sa_family != AF_INET6) {
		return -1;
	}

	memset(&msg, 0, sizeof(msg));
	msg.cmd = is_add ? ROUTE_CMD_ADD : ROUTE_CMD_DEL;
	msg.type = ROUTE_MSG_ROUTE;
	msg.af = dst->sa_family;
	msg.dev_id = rtm->rtm_index;
	ipaddr_from_sockaddr(&msg.route.dst, dst);

	if (gateway->sa_family == AF_LINK) {
		gateway_dl = (struct sockaddr_dl *)gateway;
		if (msg.dev_id != gateway_dl->sdl_index) {
			return -1;
		}
	} else if (gateway->sa_family == msg.af) {
		ipaddr_from_sockaddr(&msg.route.next_hop, gateway);
	} else {
		return -1;
	}

	if (netmask->sa_family != msg.af) {
		return -1;
	}

	ipaddr_from_sockaddr(&tmp, netmask);

	msg.route.pfx = ipaddr_prefix(msg.af, &tmp);

	if (cb != NULL) {
		(*cb)(&msg, udata);
	}

	return 0;
}

#define REQUIRE(type) \
	if (msg_len < sizeof(type)) { \
		return -1; \
	}

static int
handle_rtmsg(route_on_msg_t cb, void *udata,
             struct rt_msghdr *rtm, size_t msg_len)
{
	int is_add;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;

	if (rtm->rtm_version != RTM_VERSION) {
		return -1;
	}

	is_add = 0;

	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		REQUIRE(struct if_msghdr);
		ifm = (struct if_msghdr *)rtm;
		if (ifm->ifm_msglen > msg_len) {
			return -1;
		}
		return handle_link(cb, udata, 1, ifm->ifm_index);

	case RTM_NEWADDR:
		is_add = 1;
	case RTM_DELADDR:
		REQUIRE(struct ifa_msghdr);
		ifam = (struct ifa_msghdr *)rtm;
		if (ifam->ifam_msglen > msg_len) {
			return -1;
		}

		return handle_addr(cb, udata, is_add, ifam);

	case RTM_ADD:
		is_add = 1;
	case RTM_DELETE:
		if (rtm->rtm_msglen > msg_len) {
			return -1;
		}

		return handle_route(cb, udata, is_add, rtm);

	default:
		break;
	}

	return 0;
}

static int
route_dump_ifaddrs(route_on_msg_t cb, void *udata)
{
	int dev_id;
	struct ifaddrs *ifap, *ifa;
	struct route_msg msg;

	if (getifaddrs(&ifap) == -1) {
		lerr(errno, "getifaddrs() failed");
		return -1;
	}

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		dev_id = if_nametoindex(ifa->ifa_name);
		if (dev_id == 0 && errno) {
			continue;
		}

		msg.cmd = ROUTE_CMD_ADD;
		msg.dev_id = dev_id;

		switch (ifa->ifa_addr->sa_family) {
		case AF_LINK:
			msg.type = ROUTE_MSG_LINK;
			strzcpy(msg.link.name, ifa->ifa_name, sizeof(msg.link.name));
			ifa_dl(&msg.link, ifa);
			if ((msg.link.mtu = get_mtu(msg.link.name)) == -1) {
				return -1;
			}

			if (cb != NULL) {
				(*cb)(&msg, udata);
			}
			break;

		case AF_INET:
		case AF_INET6:
			msg.type = ROUTE_MSG_ADDR;
			msg.af = ifa->ifa_addr->sa_family;
			ipaddr_from_sockaddr(&msg.addr, ifa->ifa_addr);

			if (cb != NULL) {
				(*cb)(&msg, udata);
			}
			break;
		}
	}

	freeifaddrs(ifap);

	return 0;
}

int
route_dump(route_on_msg_t cb, void *udata)
{
	int mib[7];
	uint8_t *buf;
	size_t i, len;
	unsigned int net_fibs, net_my_fibnum;
	size_t net_fibs_size, net_my_fib_num_size;
	struct rt_msghdr *rtm;

	if (route_dump_ifaddrs(cb, udata)) {
		return -1;
	}

	net_fibs_size = sizeof(net_fibs);

	 if (sysctlbyname("net.fibs", &net_fibs,
	                  &net_fibs_size, NULL, 0) == -1) {

		net_fibs = -1;
	}

	if (sysctlbyname("net.my_fibnum", &net_my_fibnum,
	                 &net_my_fib_num_size, NULL, 0) == -1) {

		net_my_fibnum = 0;
	}

	if (net_my_fibnum >= net_fibs) {
		return -1;
	}

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_UNSPEC;
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;
	mib[6] = net_my_fibnum;

	if (sysctl(mib, ARRAY_SIZE(mib), NULL, &len, NULL, 0) == -1) {
		return -1;
	}

	buf = malloc(len);

	if (sysctl(mib, ARRAY_SIZE(mib), buf, &len, NULL, 0) == -1) {
		return -1;
	}

	for (i = 0; i < len; i += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)(buf + i);
		if (rtm->rtm_version != RTM_VERSION) {
			continue;
		}
		if (rtm->rtm_type != RTM_GET) {
			continue;
		}
		handle_route(cb, udata, 1, rtm);
	}

	free(buf);

	return 0; 
}

int
route_open_fd()
{
	int fd;

	if ((fd = socket(PF_ROUTE, SOCK_RAW, 0)) == -1) {
		lerr(errno, "socket(PF_ROUTE, SOCK_RAW) failed");
	}

	return fd;
}

int
route_read(int fd, route_on_msg_t cb, void *udata)
{
	char msg[2048];
	int n;

	n = read(fd, msg, sizeof(msg));

	if (n <= 0) {
		return n;
	}
	
	handle_rtmsg(cb, udata, (struct rt_msghdr *)msg, n);
	return n;
}
