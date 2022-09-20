#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include "liburing.h"

/* one read/write + cancel */
#define QUEUE_DEPTH	2
#define MAX_IOV		64

#define error(msg, ...) fprintf(stderr, msg, ## __VA_ARGS__)

enum state {
	STATE_READ,
	STATE_WRITE
};

struct task {
	struct msghdr	msg;
	int		offset;
	bool		busy;
	struct iovec	iov[MAX_IOV];
	char		buf[0];
};

struct context {
	enum state	state;
	struct io_uring	ring;
	struct task	*task;
	int		block_size;
	bool		msg_waitall;
	bool		need_submit;
};

static void
prep_read_task(struct context *context, int fd)
{
	struct task *task = context->task;
	struct io_uring_sqe *sqe;
	int flags;

	task->iov[0].iov_base = &task->buf[task->offset];
	task->iov[0].iov_len = context->block_size - task->offset;

	task->msg.msg_iov = task->iov;
	task->msg.msg_iovlen = 1;

	flags = context->msg_waitall ? MSG_WAITALL : 0;

	sqe = io_uring_get_sqe(&context->ring);
	io_uring_prep_recvmsg(sqe, fd, &task->msg, flags);
	io_uring_sqe_set_data(sqe, task);

	context->need_submit = true;
	task->busy = true;
}

static void
prep_write_task(struct context *context, int fd)
{
	struct task *task = context->task;
	struct io_uring_sqe *sqe;

	task->iov[0].iov_base = &task->buf[task->offset];
	task->iov[0].iov_len = context->block_size - task->offset;

	task->msg.msg_iov = task->iov;
	task->msg.msg_iovlen = 1;

	sqe = io_uring_get_sqe(&context->ring);
	io_uring_prep_sendmsg(sqe, fd, &task->msg, 0);
	io_uring_sqe_set_data(sqe, task);

	context->need_submit = true;
	task->busy = true;
}

static int
cancel_task(struct context *context)
{
	struct io_uring_sqe *sqe;
	int rc;

	sqe = io_uring_get_sqe(&context->ring);
	io_uring_prep_cancel(sqe, context->task, 0);

	rc = io_uring_submit(&context->ring);

	return rc < 0 ? -1 : 0;
}

static int
process_completions(struct context *context)
{
	struct task *task = context->task;
	struct io_uring_cqe *cqe;
	int rc, status;

	rc = io_uring_peek_cqe(&context->ring, &cqe);
	if (rc != 0 || cqe == NULL) {
		return 0;
	}

	status = cqe->res;
	io_uring_cqe_seen(&context->ring, cqe);
	task->busy = false;

	if (status <= 0) {
		return -1;
	}

	assert(task->offset + status <= context->block_size);
	task->offset += status;

	switch (context->state) {
		case STATE_READ:
			if (task->offset == context->block_size) {
				context->state = STATE_WRITE;
				task->offset = 0;
			}
			break;
		case STATE_WRITE:
			if (task->offset == context->block_size) {
				context->state = STATE_READ;
				task->offset = 0;
			}
			break;
	}

	return 1;
}

static int
handle_client(struct context *context, int fd)
{
	struct task *task = context->task;
	int rc;

	context->state = STATE_READ;
	context->need_submit = false;

	assert(!task->busy);
	task->offset = 0;

	while (1) {
		switch (context->state) {
		case STATE_READ:
			if (!task->busy) {
				prep_read_task(context, fd);
			}
			break;
		case STATE_WRITE:
			if (!task->busy) {
				prep_write_task(context, fd);
			}
			break;
		}

		if (context->need_submit) {
			rc = io_uring_submit(&context->ring);
			if (rc < 0) {
				error("io_uring_submit() failed\n");
				break;
			}

			context->need_submit = false;
		}

		rc = process_completions(context);
		if (rc < 0) {
			break;
		}
	}

	if (task->busy) {
		rc = cancel_task(context);
		if (rc != 0) {
			error("failed to cancel task\n");
			return -1;
		} else {
			while (task->busy) {
				rc = process_completions(context);
				if (rc < 0) {
					break;
				}
			}
		}
	}

	close(fd);

	return 0;
}

static struct task *
alloc_task(int block_size)
{
	struct task *task;

	task = calloc(1, sizeof(*task) + block_size);
	if (!task) {
		return NULL;
	}

	return task;
}

int
main(int argc, const char **argv)
{
	struct sockaddr_in sa = {};
	struct context context = {};
	int rc, fd, client, tmp;

	if (argc != 4) {
		error("usage: %s PORT BLOCK_SIZE MSG_WAITALL\n", argv[0]);
		return 1;
	}

	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(atoi(argv[1]));

	context.block_size = atoi(argv[2]);
	if (context.block_size <= 0) {
		error("wrong block size: %d\n", context.block_size);
		return 1;
	}

	context.msg_waitall = atoi(argv[3]) == 1;
	printf("MSG_WAITALL=%s\n", context.msg_waitall ? "1" : "0");

	context.task = alloc_task(context.block_size);
	if (!context.task) {
		error("alloc_task() failed\n");
		return 1;
	}

	rc = io_uring_queue_init(QUEUE_DEPTH, &context.ring, 0);
	if (rc != 0) {
		error("io_uring_queue_init() failed\n");
		return 1;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		error("socket() failed\n");
		return 1;
	}

	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof tmp);
	if (rc != 0) {
		error("setsockopt() failed\n");
		return 1;
	}

	rc = bind(fd, &sa, sizeof(sa));
	if (rc != 0) {
		error("bind() failed\n");
		return 1;
	}

	rc = listen(fd, 1);
	if (rc != 0) {
		error("listen() failed\n");
		return 1;
	}

	while (1) {
		client = accept(fd, NULL, NULL);
		if (client < 0) {
			continue;
		}

		rc = handle_client(&context, client);
		if (rc != 0) {
			break;
		}
	}

	return 0;
}
