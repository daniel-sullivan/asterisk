/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Digium, Inc.
 *
 * Mark Michelson <mmichelson@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*** MODULEINFO
	<depend>pjproject</depend>
	<depend>res_pjsip</depend>
	<defaultenabled>yes</defaultenabled>
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

#include <netinet/in.h>	/* For IPPROTO_UDP and in6_addr */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <time.h>

#include <pjsip.h>

#include "asterisk/res_pjsip.h"
#include "asterisk/vector.h"
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/cli.h"
#include "asterisk/netsock2.h"
#include "asterisk/acl.h"
#include "asterisk/uuid.h"

/* Only guards int64 overflow of the monotonic deadline; the operator's deadline bounds the lease. */
#define CAPTURE_MAX_MS (INT64_MAX / 1000000LL / 2)
#define NSEC_PER_MS 1000000LL

/* Separate from the normal logger. All fields are under its session lock. */
struct pjsip_capture_lease {
	char nonce[AST_UUID_STR_LEN];
	int64_t expires_ns;
	struct ast_ha *peers;
	int fd;
};

static struct pjsip_capture_lease capture_lease = { .fd = -1 };

static void capture_close(struct pjsip_capture_lease *lease)
{
	if (lease->fd >= 0) {
		close(lease->fd);
	}
	ast_free_ha(lease->peers);
	*lease = (struct pjsip_capture_lease) { .fd = -1 };
}

static int64_t capture_time_ns(clockid_t clock)
{
	struct timespec now;

	if (clock_gettime(clock, &now)) {
		return -1;
	}
	return now.tv_sec * 1000000000LL + now.tv_nsec;
}

static int64_t capture_deadline(int64_t requested_ms, int64_t earliest_mono_ns, int64_t wall_ns)
{
	int64_t remaining_ms;
	if (earliest_mono_ns < 0 || wall_ns < 0) {
		return 0;
	}
	/* Round wall time up; time between the samples can only shorten the lease. */
	remaining_ms = requested_ms - (wall_ns + NSEC_PER_MS - 1) / NSEC_PER_MS;
	if (remaining_ms <= 0 || remaining_ms > CAPTURE_MAX_MS) {
		return 0;
	}
	return earliest_mono_ns + remaining_ms * NSEC_PER_MS;
}

static int capture_is_live(struct pjsip_capture_lease *lease, int64_t now_ns)
{
	if (!lease->nonce[0]) {
		return 0;
	}
	if (now_ns < 0 || now_ns >= lease->expires_ns) {
		capture_close(lease);
		return 0;
	}
	return 1;
}

static int capture_can_start(struct pjsip_capture_lease *lease, const char *nonce, int64_t now_ns)
{
	return capture_is_live(lease, now_ns) && lease->fd < 0 && !strcmp(lease->nonce, nonce);
}

static int capture_cancel(struct pjsip_capture_lease *lease, const char *nonce)
{
	if (!lease->nonce[0] || strcmp(lease->nonce, nonce)) {
		return 0;
	}
	capture_close(lease);
	return 1;
}

static void capture_write_record(struct pjsip_capture_lease *lease, const struct iovec *record,
	int count, size_t len)
{
	/* The cutoff is checked at admission to the unbuffered write, not by a timer. */
	if (lease->fd >= 0 && capture_is_live(lease, capture_time_ns(CLOCK_MONOTONIC))
		&& writev(lease->fd, record, count) != (ssize_t) len) {
		ast_log(LOG_WARNING, "Writing SIP capture record failed; capture closed\n");
		capture_close(lease);
	}
}

/*! \brief PCAP Header */
struct pcap_header {
	uint32_t magic_number; 	/*! \brief PCAP file format magic number */
	uint16_t version_major;	/*! \brief Major version number of the file format */
	uint16_t version_minor;	/*! \brief Minor version number of the file format */
	int32_t thiszone;	/*! \brief GMT to local correction */
	uint32_t sigfigs;	/*! \brief Accuracy of timestamps */
	uint32_t snaplen;	/*! \brief The maximum size that can be recorded in the file */
	uint32_t network;	/*! \brief Type of packets held within the file */
};

/*! \brief PCAP Packet Record Header */
struct pcap_record_header {
	uint32_t ts_sec;	/*! \brief When the record was created */
	uint32_t ts_usec;	/*! \brief When the record was created */
	uint32_t incl_len;	/*! \brief Length of packet as saved in the file */
	uint32_t orig_len;	/*! \brief Length of packet as sent over network */
};

static const struct pcap_header pjsip_pcap_header = {
	.magic_number = 0xa1b2c3d4,
	.version_major = 2,
	.version_minor = 4,
	.snaplen = 65535,
	.network = 1, /* Ethernet can carry both IPv4 and IPv6 records. */
};

static int capture_open_pcap(const char *filename)
{
	int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		return -1;
	}
	if (fchmod(fd, S_IRUSR | S_IWUSR)
		|| write(fd, &pjsip_pcap_header, sizeof(pjsip_pcap_header)) != sizeof(pjsip_pcap_header)) {
		close(fd);
		return -1;
	}
	return fd;
}

/*! \brief PCAP Ethernet Header */
struct pcap_ethernet_header {
	uint8_t dst[6];	/*! \brief Destination MAC address */
	uint8_t src[6];	/*! \brief Source MAD address */
	uint16_t type;	/*! \brief The type of packet contained within */
} __attribute__((__packed__));

/*! \brief PCAP IPv4 Header */
struct pcap_ipv4_header {
	uint8_t ver_ihl;	/*! \brief IP header version and other bits */
	uint8_t ip_tos;		/*! \brief Type of service details */
	uint16_t ip_len;	/*! \brief Total length of the packet (including IPv4 header) */
	uint16_t ip_id;		/*! \brief Identification value */
	uint16_t ip_off;	/*! \brief Fragment offset */
	uint8_t ip_ttl;		/*! \brief Time to live for the packet */
	uint8_t ip_protocol;	/*! \brief Protocol of the data held within the packet (always UDP) */
	uint16_t ip_sum;	/*! \brief Checksum (not calculated for our purposes */
	uint32_t ip_src;	/*! \brief Source IP address */
	uint32_t ip_dst;	/*! \brief Destination IP address */
};

/*! \brief PCAP IPv6 Header */
struct pcap_ipv6_header {
   union {
      struct ip6_hdrctl {
         uint32_t ip6_un1_flow; /*! \brief Version, traffic class, flow label */
         uint16_t ip6_un1_plen; /*! \brief Length of the packet (not including IPv6 header) */
         uint8_t ip6_un1_nxt; 	/*! \brief Next header field */
         uint8_t ip6_un1_hlim;	/*! \brief Hop Limit */
      } ip6_un1;
      uint8_t ip6_un2_vfc;	/*! \brief Version, traffic class */
   } ip6_ctlun;
   struct in6_addr ip6_src; /*! \brief Source IP address */
   struct in6_addr ip6_dst; /*! \brief Destination IP address */
};

/*! \brief PCAP UDP Header */
struct pcap_udp_header {
	uint16_t src;		/*! \brief Source IP port */
	uint16_t dst;		/*! \brief Destination IP port */
	uint16_t length;	/*! \brief Length of the UDP header plus UDP packet */
	uint16_t checksum;	/*! \brief Packet checksum, left uncalculated for our purposes */
};

struct method_logging_info {
	pj_str_t pj_name;    /*! \brief A PJSIP string for the method */
	pjsip_method method; /*! \brief The PJSIP method structure used for comparisons */
	char name[];         /*! \brief The method name */
};

/*! \brief PJSIP Logging Session */
struct pjsip_logger_session {
	/*! \brief Explicit addresses or ranges being logged */
	struct ast_ha *matches;
	/*! \brief Filename used for the pcap file */
	char pcap_filename[PATH_MAX];
	/*! \brief The pcap file itself */
	FILE *pcap_file;
	/*! \brief Whether the session is enabled or not */
	unsigned int enabled:1;
	/*! \brief Whether the session is logging all traffic or not */
	unsigned int log_all_traffic:1;
	/*! \brief Whether to log to verbose or not */
	unsigned int log_to_verbose:1;
	/*! \brief Whether to log to pcap or not */
	unsigned int log_to_pcap:1;
	/*! \brief Vector of SIP methods to log */
	AST_VECTOR(, struct method_logging_info *) log_methods;
};

/*! \brief The default logger session */
static struct pjsip_logger_session *default_logger;

/*! \brief Destructor for logger session */
static void pjsip_logger_session_destroy(void *obj)
{
	struct pjsip_logger_session *session = obj;

	if (session->pcap_file) {
		fclose(session->pcap_file);
	}

	ast_free_ha(session->matches);

	AST_VECTOR_RESET(&session->log_methods, ast_free);
	AST_VECTOR_FREE(&session->log_methods);
}

/*! \brief Allocator for logger session */
static struct pjsip_logger_session *pjsip_logger_session_alloc(void)
{
	struct pjsip_logger_session *session;

	session = ao2_alloc_options(sizeof(struct pjsip_logger_session), pjsip_logger_session_destroy,
		AO2_ALLOC_OPT_LOCK_RWLOCK);
	if (!session) {
		return NULL;
	}

	session->log_to_verbose = 1;

	AST_VECTOR_INIT(&session->log_methods, 0);

	return session;
}

/*! \note Must be called with the pjsip_logger_session lock held */
static int apply_method_filter(const struct pjsip_logger_session *session, const pjsip_method *method)
{
	size_t size = AST_VECTOR_SIZE(&session->log_methods);
	size_t i;

	if (size == 0) {
		/* Nothing in the vector means everything matches */
		return 0;
	}

	for (i = 0; i < size; ++i) {
		struct method_logging_info *candidate = AST_VECTOR_GET(&session->log_methods, i);
		if (pjsip_method_cmp(&candidate->method, method) == 0) {
			return 0;
		}
	}

	/* Nothing matched */
	return 1;
}

/*! \brief See if we pass debug filter */
static inline int pjsip_log_test_filter(const struct pjsip_logger_session *session, const char *address, int port, const pjsip_method *method)
{
	struct ast_sockaddr test_addr;

	if (!session->enabled) {
		return 0;
	}

	if (session->log_all_traffic) {
		return 1;
	}

	if (apply_method_filter(session, method)) {
		/* The method filter didn't match anything, so reject. */
		return 0;
	}

	/* A null address was passed in or no explicit matches. Just reject it. */
	if (ast_strlen_zero(address) || !session->matches) {
		/* If we matched on method and host is empty, accept, otherwise reject. */
		return AST_VECTOR_SIZE(&session->log_methods) > 0;
	}

	ast_sockaddr_parse(&test_addr, address, PARSE_PORT_IGNORE);
	ast_sockaddr_set_port(&test_addr, port);

	/* Compare the address against the matches */
	if (ast_apply_ha(session->matches, &test_addr) != AST_SENSE_ALLOW) {
		return 1;
	} else {
		return 0;
	}
}

/* Lease callers hold the session write lock. */
static void pjsip_logger_write_to_pcap(struct pjsip_logger_session *session, struct pjsip_capture_lease *lease,
	const char *msg, size_t msg_len, pj_sockaddr *source, pj_sockaddr *destination)
{
	struct timeval now = ast_tvnow();
	struct pcap_record_header pcap_record_header = {
		.ts_sec = now.tv_sec,
		.ts_usec = now.tv_usec,
	};
	struct pcap_ethernet_header pcap_ethernet_header = {
		.type = 0,
	};
	struct pcap_ipv4_header pcap_ipv4_header = {
		.ver_ihl = 0x45, /* IPv4 + 20 bytes of header */
		.ip_ttl = 128, /* We always put a TTL of 128 to keep Wireshark less blue */
	};
	struct pcap_ipv6_header pcap_ipv6_header = {
		.ip6_ctlun.ip6_un2_vfc = 0x60,
	};
	void *pcap_ip_header;
	size_t pcap_ip_header_len;
	struct pcap_udp_header pcap_udp_header = { 0 };

	/* Packets are always stored as UDP to simplify this logic */
	if (source) {
		pcap_udp_header.src = ntohs(pj_sockaddr_get_port(source));
	} else {
		pcap_udp_header.src = ntohs(0);
	}
	if (destination) {
		pcap_udp_header.dst = ntohs(pj_sockaddr_get_port(destination));
	} else {
		pcap_udp_header.dst = ntohs(0);
	}
	pcap_udp_header.length = ntohs(sizeof(struct pcap_udp_header) + msg_len);

	/* Construct the appropriate IP header */
	if ((source && source->addr.sa_family == pj_AF_INET()) ||
		(destination && destination->addr.sa_family == pj_AF_INET())) {
		pcap_ethernet_header.type = htons(0x0800); /* We are providing an IPv4 packet */
		pcap_ip_header = &pcap_ipv4_header;
		pcap_ip_header_len = sizeof(struct pcap_ipv4_header);
		if (source) {
			memcpy(&pcap_ipv4_header.ip_src, pj_sockaddr_get_addr(source), pj_sockaddr_get_addr_len(source));
		}
		if (destination) {
			memcpy(&pcap_ipv4_header.ip_dst, pj_sockaddr_get_addr(destination), pj_sockaddr_get_addr_len(destination));
		}
		pcap_ipv4_header.ip_len = htons(sizeof(struct pcap_udp_header) + sizeof(struct pcap_ipv4_header) + msg_len);
		pcap_ipv4_header.ip_protocol = IPPROTO_UDP; /* We always provide UDP */
	} else {
		pcap_ethernet_header.type = htons(0x86DD); /* We are providing an IPv6 packet */
		pcap_ip_header = &pcap_ipv6_header;
		pcap_ip_header_len = sizeof(struct pcap_ipv6_header);
		if (source) {
			memcpy(&pcap_ipv6_header.ip6_src, pj_sockaddr_get_addr(source), pj_sockaddr_get_addr_len(source));
		}
		if (destination) {
			memcpy(&pcap_ipv6_header.ip6_dst, pj_sockaddr_get_addr(destination), pj_sockaddr_get_addr_len(destination));
		}
		pcap_ipv6_header.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(struct pcap_udp_header) + msg_len);
		pcap_ipv6_header.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;
	}

	/* Add up all the sizes for this record */
	pcap_record_header.incl_len = pcap_record_header.orig_len = sizeof(pcap_ethernet_header) + pcap_ip_header_len + sizeof(pcap_udp_header) + msg_len;

	if (lease) {
		struct iovec record[] = {
			{ &pcap_record_header, sizeof(pcap_record_header) },
			{ &pcap_ethernet_header, sizeof(pcap_ethernet_header) },
			{ pcap_ip_header, pcap_ip_header_len },
			{ &pcap_udp_header, sizeof(pcap_udp_header) },
			{ (void *) msg, msg_len },
		};

		capture_write_record(lease, record, ARRAY_LEN(record),
			sizeof(pcap_record_header) + pcap_record_header.incl_len);
		return;
	}

	/* We lock the logger session since we're writing these out in parts */
	ao2_wrlock(session);
	if (session->pcap_file) {
		if (fwrite(&pcap_record_header, sizeof(struct pcap_record_header), 1, session->pcap_file) != 1) {
			ast_log(LOG_WARNING, "Writing PCAP header failed: %s\n", strerror(errno));
		}
		if (fwrite(&pcap_ethernet_header, sizeof(struct pcap_ethernet_header), 1, session->pcap_file) != 1) {
			ast_log(LOG_WARNING, "Writing ethernet header to pcap failed: %s\n", strerror(errno));
		}
		if (fwrite(pcap_ip_header, pcap_ip_header_len, 1, session->pcap_file) != 1) {
			ast_log(LOG_WARNING, "Writing IP header to pcap failed: %s\n", strerror(errno));
		}
		if (fwrite(&pcap_udp_header, sizeof(struct pcap_udp_header), 1, session->pcap_file) != 1) {
			ast_log(LOG_WARNING, "Writing UDP header to pcap failed: %s\n", strerror(errno));
		}
		if (fwrite(msg, msg_len, 1, session->pcap_file) != 1) {
			ast_log(LOG_WARNING, "Writing UDP payload to pcap failed: %s\n", strerror(errno));
		}
	}
	ao2_unlock(session);
}

static void capture_packet(pjsip_msg *sip, pjsip_transport *transport, const char *address,
	const char *msg, size_t len, pj_sockaddr *source, pj_sockaddr *destination)
{
	struct ast_sockaddr peer;
	const pjsip_method *method;

	/* TLS only, and only the INVITE transactions needed for failover. */
	if (!sip || !transport || !(transport->flag & PJSIP_TRANSPORT_SECURE) || !len) {
		return;
	}
	if (sip->type == PJSIP_REQUEST_MSG) {
		method = &sip->line.req.method;
	} else {
		pjsip_cseq_hdr *cseq = pjsip_msg_find_hdr(sip, PJSIP_H_CSEQ, NULL);
		if (!cseq) {
			return;
		}
		method = &cseq->method;
	}
	if (method->id != PJSIP_INVITE_METHOD) {
		return;
	}
	ao2_rdlock(default_logger);
	if (capture_lease.fd < 0) {
		ao2_unlock(default_logger);
		return;
	}
	ao2_unlock(default_logger);
	ao2_wrlock(default_logger);
	if (capture_lease.fd >= 0 && capture_is_live(&capture_lease, capture_time_ns(CLOCK_MONOTONIC))
		&& !default_logger->enabled
		&& ast_sockaddr_parse(&peer, address, PARSE_PORT_IGNORE)
		&& ast_apply_ha(capture_lease.peers, &peer) == AST_SENSE_DENY) {
		pjsip_logger_write_to_pcap(default_logger, &capture_lease, msg, len, source, destination);
	}
	ao2_unlock(default_logger);
}

static pj_status_t logging_on_tx_msg(pjsip_tx_data *tdata)
{
	char buffer[AST_SOCKADDR_BUFLEN];

	capture_packet(tdata->msg, tdata->tp_info.transport, tdata->tp_info.dst_name,
		tdata->buf.start, tdata->buf.cur - tdata->buf.start, NULL, &tdata->tp_info.dst_addr);
	ao2_rdlock(default_logger);
	if (!pjsip_log_test_filter(default_logger, tdata->tp_info.dst_name, tdata->tp_info.dst_port, &tdata->msg->line.req.method)) {
		ao2_unlock(default_logger);
		return PJ_SUCCESS;
	}
	ao2_unlock(default_logger);

	if (default_logger->log_to_verbose) {
		ast_verbose("<--- Transmitting SIP %s (%d bytes) to %s:%s --->\n%.*s\n",
			tdata->msg->type == PJSIP_REQUEST_MSG ? "request" : "response",
			(int) (tdata->buf.cur - tdata->buf.start),
			tdata->tp_info.transport->type_name,
			pj_sockaddr_print(&tdata->tp_info.dst_addr, buffer, sizeof(buffer), 3),
			(int) (tdata->buf.end - tdata->buf.start), tdata->buf.start);
	}

	if (default_logger->log_to_pcap) {
		pjsip_logger_write_to_pcap(default_logger, NULL, tdata->buf.start, (int) (tdata->buf.cur - tdata->buf.start),
			NULL, &tdata->tp_info.dst_addr);
	}

	return PJ_SUCCESS;
}

static pj_bool_t logging_on_rx_msg(pjsip_rx_data *rdata)
{
	char buffer[AST_SOCKADDR_BUFLEN];

	if (!rdata->msg_info.msg) {
		return PJ_FALSE;
	}
	/* A TLS read can contain several SIP messages; capture the parsed slice. */
	capture_packet(rdata->msg_info.msg, rdata->tp_info.transport, rdata->pkt_info.src_name,
		rdata->msg_info.msg_buf, rdata->msg_info.len, &rdata->pkt_info.src_addr, NULL);

	ao2_rdlock(default_logger);
	if (!pjsip_log_test_filter(default_logger, rdata->pkt_info.src_name, rdata->pkt_info.src_port, &rdata->msg_info.msg->line.req.method)) {
		ao2_unlock(default_logger);
		return PJ_FALSE;
	}
	ao2_unlock(default_logger);

	if (default_logger->log_to_verbose) {
		ast_verbose("<--- Received SIP %s (%d bytes) from %s:%s --->\n%s\n",
			rdata->msg_info.msg->type == PJSIP_REQUEST_MSG ? "request" : "response",
			rdata->msg_info.len,
			rdata->tp_info.transport->type_name,
			pj_sockaddr_print(&rdata->pkt_info.src_addr, buffer, sizeof(buffer), 3),
			rdata->pkt_info.packet);
	}

	if (default_logger->log_to_pcap) {
		pjsip_logger_write_to_pcap(default_logger, NULL, rdata->pkt_info.packet, rdata->msg_info.len,
			&rdata->pkt_info.src_addr, NULL);
	}

	return PJ_FALSE;
}

static pjsip_module logging_module = {
	.name = { "Logging Module", 14 },
	.priority = 0,
	.on_rx_request = logging_on_rx_msg,
	.on_rx_response = logging_on_rx_msg,
	.on_tx_request = logging_on_tx_msg,
	.on_tx_response = logging_on_tx_msg,
};

static char *pjsip_enable_logger_all(int fd)
{
	ao2_wrlock(default_logger);
	default_logger->enabled = 1;
	default_logger->log_all_traffic = 1;
	ao2_unlock(default_logger);

	if (fd >= 0) {
		ast_cli(fd, "PJSIP Logging enabled\n");
	}

	return CLI_SUCCESS;
}

static char *pjsip_enable_logger_host(int fd, const char *arg, unsigned int add_host)
{
	const char *host = arg;
	const char *mask;
	struct ast_sockaddr address;
	int error = 0;

	ao2_wrlock(default_logger);
	default_logger->enabled = 1;

	if (!add_host) {
		/* If this is not adding an additional host or subnet then we have to
		 * remove what already exists.
		 */
		ast_free_ha(default_logger->matches);
		default_logger->matches = NULL;
	}

	mask = strrchr(host, '/');
	if (!mask && !ast_sockaddr_parse(&address, arg, 0)) {
		if (ast_sockaddr_resolve_first_af(&address, arg, 0, AST_AF_UNSPEC)) {
			ao2_unlock(default_logger);
			return CLI_SHOWUSAGE;
		}
		host = ast_sockaddr_stringify(&address);
	}

	default_logger->matches = ast_append_ha_with_port("d", host, default_logger->matches, &error);
	if (!default_logger->matches || error) {
		if (fd >= 0) {
			ast_cli(fd, "Failed to add address '%s' for logging\n", host);
		}
		ao2_unlock(default_logger);
		return CLI_SUCCESS;
	}

	ao2_unlock(default_logger);

	if (fd >= 0) {
		ast_cli(fd, "PJSIP Logging Enabled for host: %s\n", ast_sockaddr_stringify_addr(&address));
	}

	return CLI_SUCCESS;
}

static struct method_logging_info *method_logging_info_alloc(const char *method)
{
	size_t method_bytes = strlen(method);
	struct method_logging_info *info;

	info = ast_calloc(1, sizeof(struct method_logging_info) + method_bytes + 1);
	if (!info) {
		return NULL;
	}

	memcpy(info->name, method, method_bytes + 1);
	pj_strset(&info->pj_name, info->name, method_bytes);
	pjsip_method_init_np(&info->method, &info->pj_name);

	return info;
}

static int method_logging_info_cmp(const struct method_logging_info *element,
	const struct method_logging_info *candidate)
{
	return pjsip_method_cmp(&element->method, &candidate->method) == 0
		? CMP_MATCH | CMP_STOP
		: 0;
}

static int method_logging_info_sort_cmp(const void *a, const void *b)
{
	const struct method_logging_info *const *m_a = a;
	const struct method_logging_info *const *m_b = b;
	return strcasecmp((*m_a)->name, (*m_b)->name);
}

/*! \brief Add the current or an additional method to match for filtering */
static char *pjsip_enable_logger_method(int fd, const char *arg, int add_method)
{
	struct ast_str *str;
	struct method_logging_info *method;

	method = method_logging_info_alloc(arg);
	if (!method) {
		return CLI_FAILURE;
	}

	ao2_wrlock(default_logger);
	default_logger->enabled = 1;

	if (!add_method) {
		/* Remove what already exists */
		AST_VECTOR_RESET(&default_logger->log_methods, ast_free);
	}

	/* Already in the list? */
	if (AST_VECTOR_CALLBACK(&default_logger->log_methods, method_logging_info_cmp, NULL, method) != NULL) {
		ast_cli(fd, "Method '%s' is already enabled\n", method->name);
		ao2_unlock(default_logger);
		ast_free(method);
		return CLI_SUCCESS;
	}

	if (AST_VECTOR_APPEND(&default_logger->log_methods, method)) {
		ast_log(LOG_ERROR, "Cannot register logger method '%s'. Unable to append.\n", method->name);
		ao2_unlock(default_logger);
		ast_free(method);
		return CLI_SUCCESS;
	}

	AST_VECTOR_SORT(&default_logger->log_methods, method_logging_info_sort_cmp);

	str = ast_str_create(256);
	if (str) {
		size_t i;
		for (i = 0; i < AST_VECTOR_SIZE(&default_logger->log_methods); i++) {
			method = AST_VECTOR_GET(&default_logger->log_methods, i);
			ast_str_append(&str, 0, "%s%.*s",
				ast_str_strlen(str) ? ", " : "",
				(int) method->pj_name.slen, method->pj_name.ptr);
		}

		ast_cli(fd, "PJSIP Logging Enabled for SIP Methods: %s\n", ast_str_buffer(str));
		ast_free(str);
	}

	ao2_unlock(default_logger);

	return CLI_SUCCESS;
}

static char *pjsip_disable_logger(int fd)
{
	ao2_wrlock(default_logger);
	if (fd >= 0) {
		capture_close(&capture_lease);
	}

	/* Default the settings back to the way they were */
	default_logger->enabled = 0;
	default_logger->log_all_traffic = 0;
	default_logger->pcap_filename[0] = '\0';
	default_logger->log_to_verbose = 1;
	default_logger->log_to_pcap = 0;

	AST_VECTOR_RESET(&default_logger->log_methods, ast_free);

	/* Stop logging to the PCAP file if active */
	if (default_logger->pcap_file) {
		fclose(default_logger->pcap_file);
		default_logger->pcap_file = NULL;
	}

	ast_free_ha(default_logger->matches);
	default_logger->matches = NULL;

	ao2_unlock(default_logger);

	if (fd >= 0) {
		ast_cli(fd, "PJSIP Logging disabled\n");
	}

	return CLI_SUCCESS;
}

static char *pjsip_set_logger_verbose(int fd, const char *arg)
{
	ao2_wrlock(default_logger);
	default_logger->log_to_verbose = ast_true(arg);
	ao2_unlock(default_logger);

	ast_cli(fd, "PJSIP Logging to verbose has been %s\n", ast_true(arg) ? "enabled" : "disabled");

	return CLI_SUCCESS;
}

static char *pjsip_set_logger_pcap(int fd, const char *arg)
{
	ao2_wrlock(default_logger);
	ast_copy_string(default_logger->pcap_filename, arg, sizeof(default_logger->pcap_filename));

	if (default_logger->pcap_file) {
		fclose(default_logger->pcap_file);
		default_logger->pcap_file = NULL;
	}

	default_logger->pcap_file = fopen(arg, "wb");
	if (!default_logger->pcap_file) {
		ao2_unlock(default_logger);
		ast_cli(fd, "Failed to open file '%s' for pcap writing\n", arg);
		return CLI_SUCCESS;
	}
	fwrite(&pjsip_pcap_header, 1, sizeof(pjsip_pcap_header), default_logger->pcap_file);

	default_logger->log_to_pcap = 1;
	ao2_unlock(default_logger);

	ast_cli(fd, "PJSIP logging to pcap file '%s'\n", arg);

	return CLI_SUCCESS;
}

enum pjsip_logger_mask {
	AST_PJSIP_LOGGER_UNSET = 0,
	AST_PJSIP_LOGGER_NONE = (1 << 0),
	AST_PJSIP_LOGGER_HOST = (1 << 1),
	AST_PJSIP_LOGGER_METHOD = (1 << 2),
	AST_PJSIP_LOGGER_VERBOSE = (1 << 3),
	AST_PJSIP_LOGGER_PCAP = (1 << 4),
	AST_PJSIP_LOGGER_ALL = (1 << 5),
};

static enum pjsip_logger_mask logger_cli_settings = AST_PJSIP_LOGGER_UNSET;
static enum pjsip_logger_mask logger_config_settings = AST_PJSIP_LOGGER_UNSET;

static char *pjsip_set_logger(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	static const char * const method_choices[] = {
		"INVITE", "CANCEL", "ACK",
		"BYE", "REGISTER", "OPTIONS",
		"SUBSCRIBE", "NOTIFY", "PUBLISH",
		"INFO", "MESSAGE",
		NULL
	};

	const char *what;

	if (cmd == CLI_INIT) {
		e->command = "pjsip set logger {on|off|host|add|method|methodadd|verbose|pcap}";
		e->usage =
			"Usage: pjsip set logger {on|off|host <name/subnet>|add <name/subnet>|method <method>|methodadd <method>|verbose <on/off>|pcap <filename>}\n"
			"       Enables or disabling logging of SIP packets\n"
			"       read on ports bound to PJSIP transports either\n"
			"       globally or enables logging for an individual\n"
			"       host or particular SIP method(s).\n"
			"       Messages can be filtered by SIP request methods\n"
			"       INVITE, CANCEL, ACK, BYE, REGISTER, OPTIONS,\n"
			"       SUBSCRIBE, NOTIFY, PUBLISH, INFO, and MESSAGE\n";
		return NULL;
	} else if (cmd == CLI_GENERATE) {
		if (a->argc && !strncasecmp(a->argv[e->args - 1], "method", 6)) {
			return ast_cli_complete(a->word, method_choices, a->n);
		}
		return NULL;
	}

	what = a->argv[e->args - 1];     /* Guaranteed to exist */

	if (a->argc == e->args) {        /* on/off */
		if (!strcasecmp(what, "on")) {
			logger_cli_settings |= AST_PJSIP_LOGGER_ALL;
			return pjsip_enable_logger_all(a->fd);
		} else if (!strcasecmp(what, "off")) {
			logger_cli_settings = AST_PJSIP_LOGGER_NONE;
			return pjsip_disable_logger(a->fd);
		}
	} else if (a->argc == e->args + 1) {
		if (!strcasecmp(what, "host")) {
			logger_cli_settings |= AST_PJSIP_LOGGER_HOST;
			return pjsip_enable_logger_host(a->fd, a->argv[e->args], 0);
		} else if (!strcasecmp(what, "add")) {
			logger_cli_settings |= AST_PJSIP_LOGGER_HOST;
			return pjsip_enable_logger_host(a->fd, a->argv[e->args], 1);
		} else if (!strcasecmp(what, "method")) {
			logger_cli_settings |= AST_PJSIP_LOGGER_METHOD;
			return pjsip_enable_logger_method(a->fd, a->argv[e->args], 0);
		} else if (!strcasecmp(what, "methodadd")) {
			logger_cli_settings |= AST_PJSIP_LOGGER_METHOD;
			return pjsip_enable_logger_method(a->fd, a->argv[e->args], 1);
		} else if (!strcasecmp(what, "verbose")) {
			logger_cli_settings |= AST_PJSIP_LOGGER_VERBOSE;
			return pjsip_set_logger_verbose(a->fd, a->argv[e->args]);
		} else if (!strcasecmp(what, "pcap")) {
			logger_cli_settings |= AST_PJSIP_LOGGER_PCAP;
			return pjsip_set_logger_pcap(a->fd, a->argv[e->args]);
		}
	}

	return CLI_SHOWUSAGE;
}

static char *capture_prepare(int fd, const char *deadline)
{
	char *end;
	int64_t requested_ms, before_ns, now_ns, expires_ns;
	char nonce[AST_UUID_STR_LEN];

	errno = 0;
	requested_ms = strtoll(deadline, &end, 10);
	if (errno || !isdigit((unsigned char) deadline[0]) || *end || requested_ms <= 0) {
		return CLI_SHOWUSAGE;
	}
	ao2_wrlock(default_logger);
	before_ns = capture_time_ns(CLOCK_MONOTONIC);
	if (capture_is_live(&capture_lease, before_ns) || default_logger->enabled) {
		ao2_unlock(default_logger);
		ast_cli(fd, "PJSIP capture refused: logger or lease already active\n");
		return CLI_FAILURE;
	}
	expires_ns = capture_deadline(requested_ms, before_ns, capture_time_ns(CLOCK_REALTIME));
	if (!expires_ns || !ast_uuid_generate_str(nonce, sizeof(nonce))
		|| (now_ns = capture_time_ns(CLOCK_MONOTONIC)) < 0 || now_ns >= expires_ns) {
		ao2_unlock(default_logger);
		ast_cli(fd, "PJSIP capture refused: deadline or nonce unavailable\n");
		return CLI_FAILURE;
	}
	ast_copy_string(capture_lease.nonce, nonce, sizeof(capture_lease.nonce));
	capture_lease.expires_ns = expires_ns;
	ao2_unlock(default_logger);
	ast_cli(fd, "PJSIP capture prepared %s\n", nonce);
	return CLI_SUCCESS;
}

static struct ast_ha *capture_parse_peers(const char *list)
{
	char *rest = ast_strdupa(list);
	char *cidr;
	struct ast_ha *peers = NULL;
	while ((cidr = strsep(&rest, ","))) {
		char *mask = strchr(cidr, '/');
		char *end;
		long bits;
		int error = 0;

		/* Numeric CIDRs only; never allow an empty list or a catch-all. */
		if (!mask || mask[1] < '1' || mask[1] > '9') {
			break;
		}
		bits = strtol(mask + 1, &end, 10);
		if (*end || bits < 1 || bits > 128) {
			break;
		}
		/* ast_apply_ha defaults to ALLOW; DENY marks the listed peers. */
		peers = ast_append_ha("deny", cidr, peers, &error);
		if (error || !peers) {
			break;
		}
	}
	if (cidr) {
		ast_free_ha(peers);
		return NULL;
	}
	return peers;
}

static char *capture_start(int fd, const char *nonce, const char *filename, const char *peer_list)
{
	struct ast_ha *peers;
	int file = -1;
	int started = 0;

	if (filename[0] != '/' || !(peers = capture_parse_peers(peer_list))) {
		return CLI_SHOWUSAGE;
	}
	ao2_wrlock(default_logger);
	if (capture_can_start(&capture_lease, nonce, capture_time_ns(CLOCK_MONOTONIC))
		&& !default_logger->enabled) {
		file = capture_open_pcap(filename);
		if (file >= 0) {
			if (capture_is_live(&capture_lease, capture_time_ns(CLOCK_MONOTONIC))) {
				capture_lease.fd = file;
				capture_lease.peers = peers;
				started = 1;
			} else {
				close(file);
			}
		}
		if (!started) {
			capture_close(&capture_lease);
		}
	}
	ao2_unlock(default_logger);
	if (!started) {
		ast_free_ha(peers);
		ast_cli(fd, "PJSIP capture refused: inactive nonce, logger enabled or file unavailable\n");
		return CLI_FAILURE;
	}
	ast_cli(fd, "PJSIP capture started %s\n", nonce);
	return CLI_SUCCESS;
}

static char *pjsip_capture_command(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int live, active, normal;
	char nonce[AST_UUID_STR_LEN];

	switch (cmd) {
	case CLI_INIT:
		e->command = "pjsip capture lease {prepare|start|cancel|status}";
		e->usage =
			"Usage: pjsip capture lease prepare <absolute-unix-ms>\n"
			"       pjsip capture lease start <nonce> <new-absolute-pcap-path> <cidr[,cidr...]>\n"
			"       pjsip capture lease cancel <nonce>\n"
			"       pjsip capture lease status\n"
			"       Capture decrypted TLS INVITE transactions from listed peers to a private pcap.\n"
			"       The normal logger must be off. Prepare fixes a deadline no further than the maximum lease.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}
	if (a->argc == 5 && !strcasecmp(a->argv[3], "prepare")) {
		return capture_prepare(a->fd, a->argv[4]);
	}
	if (a->argc == 7 && !strcasecmp(a->argv[3], "start")) {
		return capture_start(a->fd, a->argv[4], a->argv[5], a->argv[6]);
	}
	if (a->argc == 5 && !strcasecmp(a->argv[3], "cancel")) {
		ao2_wrlock(default_logger);
		active = capture_cancel(&capture_lease, a->argv[4]);
		ao2_unlock(default_logger);
		ast_cli(a->fd, active ? "PJSIP capture cancelled\n" : "PJSIP capture nonce inactive\n");
		return CLI_SUCCESS;
	}
	if (a->argc == 4 && !strcasecmp(a->argv[3], "status")) {
		ao2_wrlock(default_logger);
		live = capture_is_live(&capture_lease, capture_time_ns(CLOCK_MONOTONIC));
		active = capture_lease.fd >= 0;
		normal = default_logger->enabled;
		ast_copy_string(nonce, capture_lease.nonce, sizeof(nonce));
		ao2_unlock(default_logger);
		ast_cli(a->fd, "PJSIP capture %s%s%s; normal logger %s\n",
			active ? "active" : live ? "prepared" : "off", live ? " " : "", nonce, normal ? "on" : "off");
		return CLI_SUCCESS;
	}
	return CLI_SHOWUSAGE;
}

static struct ast_cli_entry cli_pjsip[] = {
	AST_CLI_DEFINE(pjsip_set_logger, "Enable/Disable PJSIP Logger Output"),
	AST_CLI_DEFINE(pjsip_capture_command, "Manage a time-limited PJSIP evidence capture"),
};

static void check_debug(void)
{
	RAII_VAR(char *, debug, ast_sip_get_debug(), ast_free);

	/* Got directive to disable debug */
	if (ast_false(debug)) {
		/* If the logger was enabled via the CLI instead of through the config file,
		 * then we shouldn't disable it on a reload.
		 * Only disable logging if logging isn't enabled via the CLI. */
		if (logger_cli_settings == AST_PJSIP_LOGGER_NONE || logger_cli_settings == AST_PJSIP_LOGGER_UNSET) {
			/* Logger not enabled via CLI currently so good to go ahead and disable. */
			pjsip_disable_logger(-1);
		} else {
			ast_debug(3, "Leaving logger enabled since logging settings overridden using CLI\n");
		}
		logger_config_settings = AST_PJSIP_LOGGER_NONE;
		return;
	}

	/* Got directive to enable debug */
	if (ast_true(debug)) {
		if (logger_cli_settings != AST_PJSIP_LOGGER_UNSET) {
			/* Logging was modified using the CLI command,
			 * and this overrides the default from the config. */
			ast_debug(3, "Leaving logger alone since logging has been overridden using CLI\n");
			return;
		}
		/* If logger already enabled via config, then nothing has changed. */
		if (!(logger_config_settings & AST_PJSIP_LOGGER_ALL)) {
			/* Logging was not previously enabled via config,
			 * but has been enabled via CLI. */
			logger_config_settings |= AST_PJSIP_LOGGER_ALL;
			pjsip_enable_logger_all(-1);
		}
		return;
	}

	/* Enabling debug, only for specific host */
	logger_config_settings = AST_PJSIP_LOGGER_HOST;
	if (pjsip_enable_logger_host(-1, debug, 0) != CLI_SUCCESS) {
		ast_log(LOG_WARNING, "Could not resolve host %s for debug "
			"logging\n", debug);
	}
}

static void global_reloaded(const char *object_type)
{
	check_debug();
}

static const struct ast_sorcery_observer global_observer = {
	.loaded = global_reloaded
};

static int load_module(void)
{
	if (ast_sorcery_observer_add(ast_sip_get_sorcery(), "global", &global_observer)) {
		ast_log(LOG_WARNING, "Unable to add global observer\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	default_logger = pjsip_logger_session_alloc();
	if (!default_logger) {
		ast_sorcery_observer_remove(
			ast_sip_get_sorcery(), "global", &global_observer);
		ast_log(LOG_WARNING, "Unable to create default logger\n");
		return AST_MODULE_LOAD_DECLINE;
	}

	check_debug();

	ast_sip_register_service(&logging_module);
	ast_cli_register_multiple(cli_pjsip, ARRAY_LEN(cli_pjsip));

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_cli_unregister_multiple(cli_pjsip, ARRAY_LEN(cli_pjsip));
	ast_sip_unregister_service(&logging_module);

	ast_sorcery_observer_remove(
		ast_sip_get_sorcery(), "global", &global_observer);
	ao2_wrlock(default_logger);
	capture_close(&capture_lease);
	ao2_unlock(default_logger);

	ao2_cleanup(default_logger);
	default_logger = NULL;

	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "PJSIP Packet Logger",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_APP_DEPEND,
	.requires = "res_pjsip",
);
