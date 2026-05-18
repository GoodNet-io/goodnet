/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * raw_client.c — plain POSIX demo for the goodnet raw_inject plugin.
 *
 * No SDK headers. No GoodNet glue. The whole point is to prove that
 * a client compiled against nothing but libc can speak to a goodnetd
 * that loads `goodnet_link_raw_inject.so`. The plugin reads our
 * inbound bytes and pipes them through `host_api->inject(MESSAGE)`;
 * whatever handler the operator wired for the configured msg_id
 * answers, and the bytes come back out our `read` call as if we
 * were talking to a regular echo service.
 *
 * Usage:
 *   ./raw_client                       # localhost:9999, "hello"
 *   ./raw_client <host> <port>         # connect, send "hello"
 *   ./raw_client <host> <port> <msg>   # connect, send <msg>
 *   ./raw_client --help                # show usage
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

static const char* kDefaultHost = "127.0.0.1";
static const int   kDefaultPort = 9999;
static const char* kDefaultMsg  = "hello";

static int usage(int rc) {
    fputs(
"usage: raw_client [host port [msg]]\n"
"\n"
"  Connects to a goodnetd process running the raw_inject link plugin,\n"
"  writes the message, and prints the bytes the kernel echoes back.\n"
"\n"
"  defaults: host=127.0.0.1 port=9999 msg=\"hello\"\n",
        rc == 0 ? stdout : stderr);
    return rc;
}

int main(int argc, char** argv) {
    if (argc >= 2 && (strcmp(argv[1], "--help") == 0 ||
                       strcmp(argv[1], "-h") == 0)) {
        return usage(0);
    }

    const char* host = (argc >= 2) ? argv[1] : kDefaultHost;
    const int   port = (argc >= 3) ? atoi(argv[2]) : kDefaultPort;
    const char* msg  = (argc >= 4) ? argv[3] : kDefaultMsg;

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "raw_client: invalid port %s\n", argv[2]);
        return 2;
    }
    const size_t msg_len = strlen(msg);
    if (msg_len == 0) {
        fprintf(stderr, "raw_client: empty message\n");
        return 2;
    }

    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct timeval tv;
    tv.tv_sec  = 5;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "raw_client: bad host %s\n", host);
        close(fd);
        return 2;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    if (write(fd, msg, msg_len) != (ssize_t)msg_len) {
        perror("write");
        close(fd);
        return 1;
    }

    unsigned char buf[4096];
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(buf)) {
        const ssize_t n = read(fd, buf + total, sizeof(buf) - (size_t)total);
        if (n > 0) {
            total += n;
            if ((size_t)total >= msg_len) break;
        } else if (n == 0) {
            break;
        } else {
            perror("read");
            close(fd);
            return 1;
        }
    }
    close(fd);

    if (total <= 0) {
        fprintf(stderr, "raw_client: no reply\n");
        return 1;
    }
    fwrite(buf, 1, (size_t)total, stdout);
    fputc('\n', stdout);
    return 0;
}
