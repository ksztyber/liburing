#include <assert.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define error(msg, ...) fprintf(stderr, msg, ## __VA_ARGS__)

sig_atomic_t g_stop;

void
sighandler(int signum)
{
	switch (signum) {
	case SIGTERM:
	case SIGINT:
		g_stop = 1;
		break;
	}
}

int
main(int argc, const char **argv)
{
	struct sockaddr_in sa = {};
	int i, fd, rc, block_size, offset;
	char *sndbuf, *rcvbuf;
	uint64_t bytes_transferred = 0;

	if (argc != 4) {
		error("usage: %s ADDR PORT BLOCK_SIZE\n", argv[0]);
		return 1;
	}

	if (signal(SIGINT, sighandler) == SIG_ERR) {
		error("signal() failed\n");
		return 1;
	}

	if (signal(SIGTERM, sighandler) == SIG_ERR) {
		error("signal() failed\n");
		return 1;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		error("socket() failed\n");
		return 1;
	}

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(argv[1]);
	sa.sin_port = htons(atoi(argv[2]));

	rc = connect(fd, &sa, sizeof(sa));
	if (rc != 0) {
		error("connect() failed\n");
		return 1;
	}

	block_size = atoi(argv[3]);

	sndbuf = calloc(1, block_size);
	if (sndbuf == NULL) {
		error("calloc() failed\n");
		return 1;
	}

	rcvbuf = calloc(1, block_size);
	if (rcvbuf == NULL) {
		error("calloc() failed\n");
		return 1;
	}

	for (i = 0; i < block_size; ++i) {
		sndbuf[i] = (char)(i & 0xff);
	}

	while (!g_stop) {
		memset(rcvbuf, 0, block_size);

		offset = 0;
		while (offset < block_size) {
			rc = send(fd, &sndbuf[offset], block_size - offset, 0);
			if (rc < 0) {
				error("send() failed: %d\n", rc);
				return 1;
			}

			offset += rc;
		}

		offset = 0;
		while (offset < block_size) {
			rc = recv(fd, &rcvbuf[offset], block_size - offset, 0);
			if (rc < 0) {
				error("recv() failed: %d\n", rc);
				return 1;
			}

			offset += rc;
		}

		rc = memcmp(rcvbuf, sndbuf, block_size);
		if (rc != 0) {
			error("memcmp() failed: %d\n", rc);
			return 1;
		}

		bytes_transferred += block_size;
	}

	printf("bytes transferred: %"PRIu64"\n", bytes_transferred);

	return 0;
}
