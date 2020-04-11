#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <termios.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static const struct option options[] = {
	{"method", required_argument, NULL, 'm'},
	{"rounds", required_argument, NULL, 'r'},
	{0, 0, 0, 0}
};
static const char *optstring = "m:r:";

static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

static char *name;

char *randstring(int len)
{
        char *salt = calloc(len + 1, sizeof(char));
	int urandom = open("/dev/urandom", O_RDONLY);
	if (urandom == -1) {
		fprintf(stderr, "Couldn't open /dev/urandom!\n");
		exit(1);
	}
	unsigned char buf;
	char *p = salt;
	for (int i = 0; i < 16; i++) {
		if (read(urandom, &buf, 1) != 1) {
			fprintf(stderr, "Couldn't read from /dev/urandom!\n");
			exit(1);
		}
		*p = charset[buf % (sizeof(charset) - 1)];
		p++;
	}
	close(urandom);
	return salt;
}

void usage(void)
{
	fprintf(stderr, "Usage: %s [(-m|--method) METHOD] [(-r|--rounds) ROUNDS]\n", name);
	fprintf(stderr, "See crypt(3) for possible values of METHOD and ROUNDS.\n");
	exit(1);
}

int main(int argc, char *argv[]) {
	name = argv[0];
	char *method = NULL;
	char *rounds = NULL;
	int ch;
	while ((ch = getopt_long(argc, argv, optstring, options, NULL)) != -1) {
		switch (ch) {
		case 'm':
			method = optarg;
			break;
		case 'r':
			rounds = optarg;
			break;
		default:
			usage();
		}
	}

	char *salt = randstring(16);
	char *crypt_salt = NULL;
        if (!method || !strcmp(method, "crypt")) {
		crypt_salt = salt;
	} else {
		int ret = 0;
		if (rounds) {
			ret = asprintf(&crypt_salt, "$%s$rounds=%s$%s$", method, rounds, salt);
		} else {
			ret = asprintf(&crypt_salt, "$%s$%s$", method, salt);
		}
		if (!crypt_salt || ret < 0) {
			exit(1);
		}
	}

	printf("Password: ");
	fflush(stdout);
	struct termios t;
	tcgetattr(0, &t);
	t.c_lflag &= ~ECHO;
	tcsetattr(0, TCSADRAIN, &t);
	char *key = NULL;
	size_t key_len = 0;
	ssize_t len = getline(&key, &key_len, stdin);
	t.c_lflag |= ECHO;
	tcsetattr(0, TCSANOW, &t);

	printf("\n");
	if (len <= 1) {
		fprintf(stderr, "Password is empty!\n");
		exit(1);
	}
	if (key[len - 1] == '\n') {
		key[len - 1] = '\0';
	}

	char *hash = crypt(key, crypt_salt);
	if (hash) {
		printf("%s\n", hash);
		exit(0);
	}
	return 1;
}
