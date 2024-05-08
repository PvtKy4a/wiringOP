/*
 * wiringPiCAN.c:
 *	Simplified CAN access routines
 *	Copyright (c) 2024 Vladislav Pavlov
 ***********************************************************************
 * This file is part of wiringPi:
 *	https://projects.drogon.net/raspberry-pi/wiringpi/
 *
 *    wiringPi is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU Lesser General Public License as
 *    published by the Free Software Foundation, either version 3 of the
 *    License, or (at your option) any later version.
 *
 *    wiringPi is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General Public
 *    License along with wiringPi.
 *    If not, see <http://www.gnu.org/licenses/>.
 ***********************************************************************
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <net/if.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/can/netlink.h>

#include "wiringPi.h"

#include "wiringPiCAN.h"

#define IF_UP 1
#define IF_DOWN 2

#define NLMSG_TAIL(nmsg) ((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

struct req_info
{
	__u8 restart;
	__u8 disable_autorestart;
	__u32 restart_ms;
	struct can_ctrlmode *ctrlmode;
	struct can_bittiming *bittiming;
};

struct set_req
{
	struct nlmsghdr n;
	struct ifinfomsg i;
	char buf[1024];
};

static int open_nl_sock(void)
{
	int fd;
	int sndbuf = 32768;
	int rcvbuf = 32768;
	unsigned int addr_len;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0)
	{
		perror("Cannot open netlink socket");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&sndbuf, sizeof(sndbuf));

	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&rcvbuf, sizeof(rcvbuf));

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = 0;

	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
	{
		perror("Cannot bind netlink socket");
		return -1;
	}

	addr_len = sizeof(local);
	if (getsockname(fd, (struct sockaddr *)&local, &addr_len) < 0)
	{
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(local))
	{
		fprintf(stderr, "Wrong address length %u\n", addr_len);
		return -1;
	}
	if (local.nl_family != AF_NETLINK)
	{
		fprintf(stderr, "Wrong address family %d\n", local.nl_family);
		return -1;
	}
	return fd;
}

static int addattr32(struct nlmsghdr *n, size_t maxlen, int type, __u32 data)
{
	int len = RTA_LENGTH(4);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
	{
		fprintf(stderr,
				"addattr32: Error! max allowed bound %zu exceeded\n",
				maxlen);
		return -1;
	}

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), &data, 4);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

	return 0;
}

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type,
					 const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
	{
		fprintf(stderr,
				"addattr_l ERROR: message exceeded bound of %zu\n",
				maxlen);
		return -1;
	}

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

static int send_mod_request(int fd, struct nlmsghdr *n)
{
	int status;
	struct sockaddr_nl nladdr;
	struct nlmsghdr *h;

	struct iovec iov = {
		.iov_base = (void *)n,
		.iov_len = n->nlmsg_len};

	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[16384];

	memset(&nladdr, 0, sizeof(nladdr));

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	n->nlmsg_seq = 0;
	n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(fd, &msg, 0);

	if (status < 0)
	{
		perror("Cannot talk to rtnetlink");
		return -1;
	}

	iov.iov_base = buf;
	while (1)
	{
		iov.iov_len = sizeof(buf);
		status = recvmsg(fd, &msg, 0);
		for (h = (struct nlmsghdr *)buf; (size_t)status >= sizeof(*h);)
		{
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);
			if (l < 0 || len > status)
			{
				if (msg.msg_flags & MSG_TRUNC)
				{
					fprintf(stderr, "Truncated message\n");
					return -1;
				}
				fprintf(stderr, "!!!malformed message: len=%d\n", len);
				return -1;
			}

			if (h->nlmsg_type == NLMSG_ERROR)
			{
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
				if ((size_t)l < sizeof(struct nlmsgerr))
				{
					fprintf(stderr, "ERROR truncated\n");
				}
				else
				{
					errno = -err->error;
					if (errno == 0)
					{
						return 0;
					}
					perror("RTNETLINK answers");
				}
				return -1;
			}
			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
	}

	return 0;
}

static int set_nl_link(int fd, __u8 if_state, const char *name, struct req_info *req_info)
{
	struct set_req req;

	const char *type = "can";

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = 0;

	req.i.ifi_index = if_nametoindex(name);
	if (req.i.ifi_index == 0)
	{
		fprintf(stderr, "Cannot find device \"%s\"\n", name);
		return -1;
	}

	if (if_state)
	{
		switch (if_state)
		{
		case IF_DOWN:
			req.i.ifi_change |= IFF_UP;
			req.i.ifi_flags &= ~IFF_UP;
			break;
		case IF_UP:
			req.i.ifi_change |= IFF_UP;
			req.i.ifi_flags |= IFF_UP;
			break;
		default:
			fprintf(stderr, "unknown state\n");
			return -1;
		}
	}

	if (req_info != NULL)
	{
		/* setup linkinfo section */
		struct rtattr *linkinfo = NLMSG_TAIL(&req.n);
		addattr_l(&req.n, sizeof(req), IFLA_LINKINFO, NULL, 0);
		addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, type, strlen(type));
		/* setup data section */
		struct rtattr *data = NLMSG_TAIL(&req.n);
		addattr_l(&req.n, sizeof(req), IFLA_INFO_DATA, NULL, 0);

		if (req_info->restart_ms > 0 || req_info->disable_autorestart)
		{
			addattr32(&req.n, 1024, IFLA_CAN_RESTART_MS, req_info->restart_ms);
		}

		if (req_info->restart)
		{
			addattr32(&req.n, 1024, IFLA_CAN_RESTART, 1);
		}

		if (req_info->bittiming != NULL)
		{
			addattr_l(&req.n, 1024, IFLA_CAN_BITTIMING, req_info->bittiming,
					  sizeof(struct can_bittiming));
		}

		if (req_info->ctrlmode != NULL)
		{
			addattr_l(&req.n, 1024, IFLA_CAN_CTRLMODE, req_info->ctrlmode,
					  sizeof(struct can_ctrlmode));
		}

		/* mark end of data section */
		data->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)data;

		/* mark end of link info section */
		linkinfo->rta_len = (void *)NLMSG_TAIL(&req.n) - (void *)linkinfo;
	}

	return send_mod_request(fd, &req.n);
}

static int set_link(const char *name, __u8 if_state, struct req_info *req_info)
{
	int s;
	int ret;

	s = open_nl_sock();
	if (s < 0)
	{
		return -1;
	}

	ret = set_nl_link(s, if_state, name, req_info);
	close(s);

	return ret;
}

static int can_start(const char *name)
{
	return set_link(name, IF_UP, NULL);
}

static int can_stop(const char *name)
{
	return set_link(name, IF_DOWN, NULL);
}

int wiringPiCANWrite(int s, unsigned int id, const unsigned char *data, int length)
{
	struct can_frame frame;

	if (length > CAN_MAX_DLEN)
	{
		return -1;
	}

	frame.can_id = id;
	frame.len = length;

	memcpy(frame.data, data, length);

	return write(s, &frame, sizeof(struct can_frame));
}

int wiringPiCANRead(int s, unsigned int *id, unsigned char *data, int *length)
{
	struct can_frame frame;
	int ret;

	ret = read(s, &frame, sizeof(struct can_frame));
	if (ret <= 0)
	{
		goto exit;
	}

	*id = frame.can_id;
	*length = frame.len;
	memcpy(data, frame.data, frame.len);

exit:
	return ret;
}

int wiringPiCANSetFilter(int s, unsigned int id, unsigned int mask)
{
	struct can_filter filter[1];

	filter[0].can_id = id;
	filter[0].can_mask = mask;

	return setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &filter, sizeof(filter));
}

static int set_bitrate(const char *name, unsigned int bitrate)
{
	int ret;
	struct can_bittiming bt;

	ret = can_stop(name);
	if (ret != 0)
	{
		goto err_ret;
	}

	memset(&bt, 0, sizeof(bt));
	bt.bitrate = bitrate;

	struct req_info req_info = {
		.bittiming = &bt,
	};

	ret = set_link(name, 0, &req_info);
	if (ret != 0)
	{
		goto err_ret;
	}

	ret = can_start(name);
	if (ret != 0)
	{
		goto err_ret;
	}

	return 0;

err_ret:
	return ret;

}

int wiringPiCANSetupInterface(const char *name, unsigned int bitrate, unsigned int loopback)
{
	int ret;
	int s;
	struct sockaddr_can addr;

	if (loopback > 1)
	{
		return -1;
	}

	s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (s < 0)
	{
		return s;
	}

	ret = set_bitrate(name, bitrate);
	if (ret != 0)
	{
		goto err_ret;
	}

	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = if_nametoindex(name);

	ret = bind(s, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0)
	{
		goto err_ret;
	}

	ret = setsockopt(s, SOL_CAN_RAW, CAN_RAW_LOOPBACK, &loopback, sizeof(loopback));
    if (ret != 0)
	{
		goto err_ret;
	}

	return s;

err_ret:
	close(s);
	return ret;
}

int wiringPiCANSetup(unsigned int bitrate, unsigned int loopback)
{
	const char *name = "can0";

	return wiringPiCANSetupInterface(name, bitrate, loopback);
}
