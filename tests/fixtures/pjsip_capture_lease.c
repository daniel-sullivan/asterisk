/* Focused fixture for the production lease code. No SIP network or Asterisk daemon. */
#include "asterisk.h"
#include "asterisk/module.h"

/* Section GC drops CLI and packet dispatch, but not constructor roots. */
#undef AST_MODULE_INFO
#define AST_MODULE_INFO(...)
#include "../../res/res_pjsip_logger.c"
#undef NDEBUG
#include <assert.h>

static int64_t mono_ns;

int __wrap_clock_gettime(clockid_t clock, struct timespec *now)
{
	assert(clock == CLOCK_MONOTONIC);
	now->tv_sec = mono_ns / 1000000000LL;
	now->tv_nsec = mono_ns % 1000000000LL;
	return 0;
}

void ast_free_ha(struct ast_ha *ha)
{
	assert(ha == NULL);
}

void ast_log(int level, const char *file, int line, const char *function, const char *fmt, ...)
{
	assert(!"unexpected Asterisk logger error");
}

int main(int argc, char **argv)
{
	struct pjsip_capture_lease lease = { .nonce = "first", .expires_ns = 100, .fd = -1 };
	char payload[] = "synthetic SIP packet";
	struct iovec record = { payload, sizeof(payload) };
	struct stat st;

	assert(argc == 2);
	assert(capture_deadline(60001, 1000, 1) == 60000001000LL);
	/* The boundary is CAPTURE_MAX_MS: accepted at it, refused above it, never wrapped. */
	assert(capture_deadline(CAPTURE_MAX_MS + 1, 1000, 1) == 1000 + CAPTURE_MAX_MS * NSEC_PER_MS);
	assert(capture_deadline(CAPTURE_MAX_MS + 1, 1000, 1) > 1000);
	assert(!capture_deadline(CAPTURE_MAX_MS + 2, 1000, 1));
	assert(!capture_deadline(INT64_MAX, 1000, 1));
	assert(!capture_deadline(1, 1000, 1));
	assert(!capture_deadline(60001, -1, 1));

	/* Both commands arrive while eligible, then wait for the server lock. */
	assert(capture_can_start(&lease, "first", 99));
	assert(!capture_can_start(&lease, "first", 100));
	assert(!capture_can_start(&lease, "first", 101));
	lease = (struct pjsip_capture_lease) { .nonce = "second", .expires_ns = 200, .fd = -1 };
	assert(capture_can_start(&lease, "second", 199));
	assert(!capture_cancel(&lease, "first"));
	assert(capture_cancel(&lease, "second"));
	assert(!capture_can_start(&lease, "second", 199));

	lease = (struct pjsip_capture_lease) { .nonce = "third", .expires_ns = 300, .fd = -1 };
	umask(0777);
	lease.fd = capture_open_pcap(argv[1]);
	assert(lease.fd >= 0);
	assert(capture_open_pcap(argv[1]) < 0);
	assert(!capture_can_start(&lease, "third", 299));
	mono_ns = 299;
	capture_write_record(&lease, &record, 1, sizeof(payload));
	assert(!fstat(lease.fd, &st));
	assert((st.st_mode & 0777) == 0600);
	assert(st.st_size == sizeof(pjsip_pcap_header) + sizeof(payload));

	/* Do not run cancel, status, or a timer. The record writer itself must stop. */
	mono_ns = 300;
	capture_write_record(&lease, &record, 1, sizeof(payload));
	assert(lease.fd < 0 && !lease.nonce[0]);
	assert(!stat(argv[1], &st));
	assert(st.st_size == sizeof(pjsip_pcap_header) + sizeof(payload));
	assert(!capture_can_start(&lease, "third", 299));
	return 0;
}
