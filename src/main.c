/**
 * @file main.c  PCP Client
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <re.h>
#include <rew.h>
#include "util.h"


static struct {
	struct sa pcp_server;
	struct pcp_peer peer;
	enum pcp_opcode opcode;
	uint32_t lifetime;

	/* options */
	struct sa third_party;
	bool prefer_fail;
	struct pcp_option_filter filter;
	const char *descr;

	bool verbose;
	bool wait;
} cli;


static struct pcp_conf conf = {
	3,     /* IRT */
	0,     /* MRC */
	1024,  /* MRT */
	0      /* MRD */
};


static void signal_handler(int signum)
{
	(void)signum;

	re_cancel();
}


static void usage(void)
{
	struct sa srv_addr;

	sa_init(&srv_addr, AF_INET);

	get_default_pcpserver(AF_INET, &srv_addr);

	(void)re_fprintf(stderr,
			 "Usage: repcpc [options] <PCP opcode>\n"
			 "Options:\n"
			 "\t-h\n"
			 "\t-l lifetime (default is %u seconds)\n"
			 "\t-p protocol (default is %s)\n"
			 "\t-i internal port\n"
			 "\t-e external address\n"
			 "\t-r remote peer address\n"
			 "\t-s PCP server address (default is %J)\n"
			 "\t-n Nonce string (hex 12 bytes)\n"
			 "\t-v Verbose output\n"
			 "\t-w Wait for user to stop program\n"
			 "\n"
			 "PCP options:\n"
			 "\t-T THIRD_PARTY address (e.g. 1.2.3.4)\n"
			 "\t-P PREFER_FAILURE (boolean)\n"
			 "\t-F FILTER option (e.g. 10.0.0.0:4000/24)\n"
			 "\t-D DESCRIPTION text\n"
			 "\n"
			 ,
			 cli.lifetime,
			 pcp_proto_name(cli.peer.map.proto),
			 &srv_addr);
}


static void pcp_resp_handler(int err, struct pcp_msg *msg, void *arg)
{
	const struct pcp_peer *peer = pcp_msg_payload(msg);
	(void)arg;

	if (err) {
		re_fprintf(stderr, "PCP error response: %m\n", err);
		goto out;
	}

	if (cli.verbose)
		re_printf("PCP Response: %H\n", pcp_msg_print, msg);
	else {
		re_printf("recv %s %3usec [%s, %u, %J]\n",
			  pcp_opcode_name(msg->hdr.opcode),
			  msg->hdr.lifetime,
			  pcp_proto_name(peer->map.proto),
			  peer->map.int_port, &peer->map.ext_addr);
	}

	if (msg->hdr.result != PCP_SUCCESS) {
		re_fprintf(stderr, "PCP error response: %s\n",
			   pcp_result_name(msg->hdr.result));
		goto out;
	}

	if (cli.verbose)
		re_printf("PCP Server uptime: %H\n",
			  fmt_human_time, &msg->hdr.epoch);

 out:
	if (!cli.wait)
		re_cancel();
}


int main(int argc, char *argv[])
{
	struct pcp_request *req = NULL;
	struct sa *third_party = NULL;
	struct pcp_option_filter *filter = NULL;
	struct pl addrport, prefix;
	bool *prefer_fail = NULL;
	int err = 0;

	sa_init(&cli.peer.map.ext_addr, AF_UNSPEC);
	sa_init(&cli.peer.remote_addr, AF_UNSPEC);
	sa_init(&cli.pcp_server, AF_UNSPEC);

	/* default values */
	cli.peer.map.proto = IPPROTO_UDP;
	cli.lifetime = 600;
	rand_bytes(cli.peer.map.nonce, sizeof cli.peer.map.nonce);

	err = libre_init();
	if (err)
		goto out;

	for (;;) {

		const int c = getopt(argc, argv,
				     "hl:p:i:e:r:s:n:vwT:PF:D:");
		if (0 > c)
			break;

		switch (c) {

		case '?':
		case 'h':
			usage();
			return -2;

		case 'l':
			cli.lifetime = atoi(optarg);
			break;

		case 'p':
			cli.peer.map.proto = resolve_protocol(optarg);
			if (cli.peer.map.proto == 0) {
				re_fprintf(stderr,
					   "unsupported protocol `%s'\n",
					   optarg);
				return 2;
			}
			break;

		case 'i':
			cli.peer.map.int_port = atoi(optarg);
			break;

		case 'e':
			err = sa_decode(&cli.peer.map.ext_addr,
					optarg, strlen(optarg));
			if (err) {
				re_fprintf(stderr,
					   "invalid external address: '%s'\n",
					   optarg);
				return 2;
			}
			break;

		case 'r':
			err = sa_decode(&cli.peer.remote_addr, optarg,
					strlen(optarg));
			if (err) {
				re_fprintf(stderr,
					   "invalid peer address: '%s'\n",
					   optarg);
				return 2;
			}
			break;

		case 's':
			err = sa_decode(&cli.pcp_server,
					optarg, strlen(optarg));
			if (err) {
				re_fprintf(stderr, "invalid server address:"
					   " '%s' (%m)\n", optarg, err);
				goto out;
			}
			break;

		case 'n':
			err = str_hex(cli.peer.map.nonce, sizeof cli.peer.map.nonce,
				      optarg);
			if (err) {
				re_fprintf(stderr,
					   "nonce must be 12 bytes (%s)\n",
					   optarg);
				goto out;
			}
			break;

		case 'v':
			cli.verbose = true;
			break;

		case 'w':
			cli.wait = true;
			break;

		case 'T':
			err = sa_set_str(&cli.third_party, optarg, 0);
			if (err) {
				re_fprintf(stderr,
					   "invalid thirdparty address:"
					   " '%s'\n",
					   optarg);
				goto out;
			}
			third_party = &cli.third_party;
			re_printf("option: THIRD_PARTY = %j\n", third_party);
			break;

		case 'P':
			cli.prefer_fail = true;
			prefer_fail = &cli.prefer_fail;
			re_printf("option: PREFER_FAILURE = true\n");
			break;

		case 'F':
			err = re_regex(optarg, strlen(optarg),
				       "[^/]+/[^]+", &addrport, &prefix);
			if (err) {
				re_fprintf(stderr,
					   "invalid filter option: %s\n",
					   optarg);
				goto out;
			}
			err = sa_decode(&cli.filter.remote_peer,
					addrport.p, addrport.l);
			if (err) {
				re_fprintf(stderr,
					   "invalid filter option: %r\n",
					   &addrport);
				goto out;
			}
			cli.filter.prefix_length = pl_u32(&prefix);

			filter = &cli.filter;
			re_printf("option: FILTER = %J/%u\n",
				  &filter->remote_peer, filter->prefix_length);
			break;

		case 'D':
			cli.descr = optarg;
			re_printf("option: DESCRIPTION = '%s'\n", optarg);
			break;
		}

		if (err)
			return -2;
	}

	argc -= optind;

	if (argc < 1 || argc > 2) {
		usage();
		return -2;
	}

	if (AF_UNSPEC == sa_af(&cli.pcp_server))
		get_default_pcpserver(AF_INET, &cli.pcp_server);

	if (AF_UNSPEC == sa_af(&cli.peer.map.ext_addr)) {
		sa_init(&cli.peer.map.ext_addr, sa_af(&cli.pcp_server));
	}

	cli.opcode = resolve_opcode(argv[optind]);
	if (cli.opcode == (enum pcp_opcode)-1) {
		re_fprintf(stderr, "unsupported PCP opcode `%s'\n",
			   argv[optind]);
		return 2;
	}

	if (!sa_isset(&cli.pcp_server, SA_ALL)) {
		re_fprintf(stderr, "missing PCP server address\n");
		return -2;
	}

	if (cli.verbose) {
		re_printf("PCP request `%s' to PCP-Server at %J\n",
			  pcp_opcode_name(cli.opcode), &cli.pcp_server);
		re_printf("lifetime = %u sec, protocol = %s, "
			  "internal_port = %u, external = %J\n",
			  cli.lifetime, pcp_proto_name(cli.peer.map.proto),
			  cli.peer.map.int_port, &cli.peer.map.ext_addr);
		re_printf("\n");
	}
	else {
		re_printf("send %s %3usec [%s, %u, %J]\n",
			  pcp_opcode_name(cli.opcode),
			  cli.lifetime, pcp_proto_name(cli.peer.map.proto),
			  cli.peer.map.int_port, &cli.peer.map.ext_addr);
	}

	if (cli.opcode == PCP_ANNOUNCE)
		cli.lifetime = 0;

	conf.mrd = 5;  /* todo: add argv option */

	/* send the PCP request */
	err = pcp_request(&req, &conf, &cli.pcp_server, cli.opcode,
			  cli.lifetime, &cli.peer,
			  pcp_resp_handler, NULL,
			  4,
			  PCP_OPTION_THIRD_PARTY,    third_party,
			  PCP_OPTION_PREFER_FAILURE, prefer_fail,
			  PCP_OPTION_FILTER,         filter,
			  PCP_OPTION_DESCRIPTION,    cli.descr);
	if (err) {
		re_fprintf(stderr,
			   "failed to send PCP request: %m\n", err);
		goto out;
	}

	err = re_main(signal_handler);

 out:
	mem_deref(req);

	libre_close();

	/* check for memory leaks */
	mem_debug();
	tmr_debug();

	return err;
}
