#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>

int epoch;
int done;

void
sig_handler(int n)
{
	done = 1;
}

int
fn(void *x)
{
	while (1) {
		printf("works! %d\n", epoch);
		usleep(500 * 1000);
	}
}

int
main(int argc, char **argv)
{
	int rc, flags, stack_size;
	uint8_t *stack;

	signal(SIGUSR1, sig_handler);
	stack_size = 1024 * 1024;
	stack = malloc(stack_size);
	stack += stack_size;
	flags = 0;
	flags |= CLONE_VM;
//	flags |= CLONE_THREAD;
	flags |= CLONE_SIGHAND;
	flags |= CLONE_FILES;
	rc = clone(fn, stack, flags, NULL);
	assert(rc != -1);
	epoch = 100;
	while (!done) {
		usleep(1000*1000);
		printf("master\n");
	}
	printf("done\n");
	return 0;
}
