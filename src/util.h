/**
 * @file util.h  PCP Client
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */


int get_default_pcpserver(int af, struct sa *srv);
int resolve_protocol(const char *name);
enum pcp_opcode resolve_opcode(const char *name);
