/**
 * @file util.c  PCP Client
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */
#include <re.h>
#include <rew.h>
#include "util.h"


int get_default_pcpserver(int af, struct sa *srv)
{
	int err;

	err = net_default_gateway_get(af, srv);
	if (err)
		return err;

	sa_set_port(srv, PCP_PORT_SRV);

	return 0;
}


int resolve_protocol(const char *name)
{
	if (0 == str_casecmp(name, "udp")) return IPPROTO_UDP;
	if (0 == str_casecmp(name, "tcp")) return IPPROTO_TCP;
	return 0;
}


enum pcp_opcode resolve_opcode(const char *name)
{
	if (0 == str_casecmp(name, "announce")) return PCP_ANNOUNCE;
	if (0 == str_casecmp(name, "map"))      return PCP_MAP;
	if (0 == str_casecmp(name, "peer"))     return PCP_PEER;
	return -1;
}
