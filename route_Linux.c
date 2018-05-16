#include "route.h"

static int netlink_ok_log;

#define RET_ERR(e) \
	do { \
		lerr(0, "netlink error: " #e); \
		return -1; \
	} while (0)

#define RET_OK(m) \
	do { \
		if (netlink_ok_log) \
			lerr(0, "netlink skip: " #m); \
		return 0; \
	} while (0)

static int
is_attr_u32(struct rtattr *attr)
{
	return RTA_PAYLOAD(attr) == sizeof(uint32_t);
}

static uint32_t
get_attr_u32(struct rtattr *attr)
{
	return *(uint32_t *)RTA_DATA(attr);
}

static int
rtnl_open(unsigned int nl_groups)
{
	int fd, sndbuf, rcvbuf;
	struct sockaddr_nl addr;

	sndbuf = 32768;
	rcvbuf = 1024 * 1024;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd == -1) {
		lerr(errno, "socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) failed");
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
	               &sndbuf, sizeof(sndbuf)) == -1) {

		lerr(errno, "setsockopt(fd, SOL_SOCKET, SO_SNDBUF, %d) failed", sndbuf);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
	               &rcvbuf, sizeof(rcvbuf)) == -1) {

		lerr(errno, "setsockopt(fd, SOL_SOCKET, SO_RCVBUF, %d) failed", rcvbuf);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = nl_groups;

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		lerr(errno, "bind({AF_NETLINK, nl_groups=%x}) failed", nl_groups);
		return -1;
	}

	return fd;
}

static void
get_route_attrs(struct rtattr *attr, int len,
                struct rtattr **attrs, int nr_attrs_max)
{
	memset(attrs, 0, sizeof(struct rtattr *) * nr_attrs_max);

	while (RTA_OK(attr, len)) {
		if (attr->rta_type < nr_attrs_max &&
			attrs[attr->rta_type] == NULL) {

			attrs[attr->rta_type] = attr;
		}

		attr = RTA_NEXT(attr, len);
	}
}

static int
handle_link(struct nlmsghdr *h, struct route_msg *msg)
{
	int len, name_len;
	struct ifinfomsg *ifi;
	struct rtattr *attrs[IFLA_MAX + 1], *attr;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		RET_ERR(LINK_BAD_MSGHDR_LEN);

	ifi = NLMSG_DATA(h);

	attr = IFLA_RTA(ifi);

	get_route_attrs(attr, len, attrs, ARRAY_SIZE(attrs));

	msg->dev_id = ifi->ifi_index;
	msg->link.flags = ifi->ifi_flags;

	attr = attrs[IFLA_IFNAME];
	if (attr == NULL)
		RET_ERR(LINK_NO_IFLA_IFNAME);

	name_len = RTA_PAYLOAD(attr);
	if (name_len >= IFNAMSIZ)
		RET_ERR(LINK_TOO_LONG_NAME);

	memcpy(msg->link.name, RTA_DATA(attr), name_len);
	msg->link.name[name_len] = '\0';

	attr = attrs[IFLA_ADDRESS];
	if (attr != NULL) {
		if (RTA_PAYLOAD(attr) != 6)
			RET_ERR(LINK_BAD_IFLA_ADDRESS);
		memcpy(msg->link.hwaddr.bytes, RTA_DATA(attr), 6);
	}

	attr = attrs[IFLA_MTU];
	if (attr == NULL)
		RET_ERR(LINK_NO_IFLA_MTU);

	if (!is_attr_u32(attr))
		RET_ERR(LINK_BAD_IFLA_MTU);

	msg->link.mtu = get_attr_u32(attr);

	return 1;
}

static int
handle_addr(struct nlmsghdr *h, struct route_msg *msg)
{
	int len, addr_len;
	struct ifaddrmsg *ifa;
	struct rtattr *attrs[IFA_MAX + 1], *attr;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
	if (len < 0)
		RET_ERR(ADDR_BAD_MSGHDR_LEN);

	ifa = NLMSG_DATA(h);

	attr = IFA_RTA(ifa);

	if (ifa->ifa_family == AF_INET) {
		addr_len = 4;
	} else if (ifa->ifa_family == AF_INET6) {
		addr_len = 16;
	} else {
		RET_OK(ADDR_NOT_INET_FAMILY);
	}

	msg->af = ifa->ifa_family;

	get_route_attrs(attr, len, attrs, ARRAY_SIZE(attrs));

	attr = attrs[IFA_LOCAL];
	if (attr == NULL)
		attr = attrs[IFA_ADDRESS];

	if (attr == NULL)
		RET_ERR(ADDR_NO_IFA_ADDRESS);

	if (RTA_PAYLOAD(attr) != addr_len)
		RET_ERR(ADDR_BAD_IFA_ADDRESS);

	memcpy(msg->addr.data, RTA_DATA(attr), addr_len);

	msg->dev_id = ifa->ifa_index;

	return 1;
}

static int
handle_route(struct nlmsghdr *h, struct route_msg *msg)
{
	int len, table, addr_len;
	struct rtmsg *rtm;
	struct rtattr *attrs[RTA_MAX + 1], *attr;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
	if (len < 0)
		RET_ERR(ROUTE_BAD_MSGHDR_LEN);

	rtm = NLMSG_DATA(h);

	if (rtm->rtm_flags & RTM_F_CLONED) {
		RET_OK(ROUTE_CLONED);
	}

	if (rtm->rtm_type != RTN_UNICAST) {
		RET_OK(ROUTE_NOT_UNICAST);
	}

	if (rtm->rtm_family == AF_INET) {
		addr_len = 4;
	} else if (rtm->rtm_family == AF_INET6) {
		addr_len = 16;
	} else {
		RET_OK(ROUTE_NOT_INET_FAMILY);
	}

	msg->af = rtm->rtm_family;

	attr = RTM_RTA(rtm);

	get_route_attrs(attr, len, attrs, ARRAY_SIZE(attrs));

	attr = attrs[RTA_TABLE];
	if (attr != NULL) {
		if (!is_attr_u32(attr)) {
			RET_ERR(ROUTE_BAD_RTA_TABLE);
		}

		table = get_attr_u32(attr);
	} else {
		table = rtm->rtm_table;
	}

	if (table != RT_TABLE_MAIN)
		RET_OK(ROUTE_NOT_MAIN_TABLE);

	attr = attrs[RTA_DST];
	if (attr == NULL) {
		msg->route.dst = ipaddr_zero;
	} else {
		if (RTA_PAYLOAD(attr) != addr_len)
			RET_ERR(ROUTE_BAD_RTA_DST);

		memcpy(msg->route.dst.data, RTA_DATA(attr), addr_len);
	}

	if (rtm->rtm_dst_len > addr_len * 8) {
		RET_ERR(ROUTE_BAD_DST_LEN);
	}
		
	msg->route.pfx = rtm->rtm_dst_len;

	attr = attrs[RTA_OIF];
	if (attr == NULL) {
		RET_ERR(ROUTE_NO_RTA_OIF);
	}

	if (!is_attr_u32(attr)) {
		RET_ERR(ROUTE_BAD_RTA_OIF);
	}

	msg->dev_id = get_attr_u32(attr);

	attr = attrs[RTA_GATEWAY];
	if (attr != NULL) {
		if (RTA_PAYLOAD(attr) != addr_len)
			RET_ERR(ROUTE_BAD_RTA_PAYLOAD);

		memcpy(msg->route.next_hop.data, RTA_DATA(attr), addr_len);
	}

	return 1;
}

static int
rtnl_handler(struct nlmsghdr *h, route_on_msg_t cb, void *udata)
{
	int rc;
	struct route_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.cmd = ROUTE_CMD_DEL;

	switch (h->nlmsg_type) {
	case RTM_NEWLINK:
		msg.cmd = ROUTE_CMD_ADD;
	case RTM_DELLINK:
		msg.type = ROUTE_MSG_LINK;
		rc = handle_link(h, &msg);
		break;

	case RTM_NEWADDR:
		msg.cmd = ROUTE_CMD_ADD;
	case RTM_DELADDR:
		msg.type = ROUTE_MSG_ADDR;
		rc = handle_addr(h, &msg);
		break;

	case RTM_NEWROUTE:
		msg.cmd = ROUTE_CMD_ADD;
	case RTM_DELROUTE:
		msg.type = ROUTE_MSG_ROUTE;
		rc = handle_route(h, &msg);
		break;

	default:
		return 0;
	}

	if (rc == 1)
		(*cb)(&msg, udata);

	return rc;
}

int
route_read(int fd, route_on_msg_t cb, void *udata)
{
	uint8_t buf[32768];
	int rc;
	struct msghdr msg;
	struct nlmsghdr *h;
	struct sockaddr_nl addr;
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1; 

	rc = recvmsg(fd, &msg, 0);

	if (rc == 0) 
		return rc;

	if (rc == -1) {
		rc = errno;	
		if (rc != EINTR && rc != EAGAIN)
			lerr(errno, "route: recvmsg() failed");

		return -rc;
	}

	for (h = (struct nlmsghdr *)buf;
		NLMSG_OK(h, rc);
		h = NLMSG_NEXT(h, rc)) {

		switch (h->nlmsg_type) {
		case NLMSG_ERROR:
			break;
		case NLMSG_DONE:
			return 0;
		default:
			if (rtnl_handler(h, cb, udata) == -1)
				return -1;
			break;
		}
	}

	if (msg.msg_flags & MSG_TRUNC) {
		RET_ERR(READ_MSG_TRUNC);
	}

	return 1;
}

int
route_open_fd()
{
	int fd, nl_groups;

	nl_groups =
		RTMGRP_LINK|
		RTMGRP_IPV4_IFADDR|
		RTMGRP_IPV4_ROUTE|
		RTMGRP_IPV6_IFADDR|
		RTMGRP_IPV6_ROUTE;

	fd = rtnl_open(nl_groups);

	return fd;
}

struct dump_req {
	struct nlmsghdr nlh;
	struct ifinfomsg ifm;
	struct rtattr ext_req __attribute__((aligned(NLMSG_ALIGNTO)));
	uint32_t ext_filter_mask;
};

static int
send_dump_req(int fd, int type)
{
	int rc;
	struct dump_req req;

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0; 
	req.nlh.nlmsg_seq = 1;
	req.ifm.ifi_family = AF_UNSPEC;
	req.ext_req.rta_type = IFLA_EXT_MASK;
	req.ext_req.rta_len = RTA_LENGTH(sizeof(uint32_t));
	req.ext_filter_mask = RTEXT_FILTER_VF;

	rc = send(fd, &req, sizeof(req), 0);
	if (rc == -1) { 
		lerr(errno, "send() failed");
	}

	return rc;
}

int
route_dump(route_on_msg_t cb, void *udata)
{
	static int types[3] = { RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE };
	int i, rc, fd;

	fd = rtnl_open(0);
	if (fd == -1)
		return -1;

	for (i = 0; i < ARRAY_SIZE(types); ++i) {
		if (send_dump_req(fd, types[i]) == -1)
			goto err;

		while ((rc = route_read(fd, cb, udata)) == 1) {
			if (rc == -1) {
				lerr(errno, "recvmsg() failed");
				goto err;
			}
		}
	}

	close(fd);
	return 0;

err:
	close(fd);
	return -1;
}
