#include "httpd.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#define MAX_CONNECTIONS 1000
#define BUF_SIZE 65535
#define QUEUE_SIZE 1000000

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static int listenfd;
int *clients;
static void start_server(const char *);
static void respond(int);

static char *buf;

// Client request
char *method, // "GET" or "POST"
    *uri,     // "/index.html" things before '?'
    *qs,      // "a=1&b=2" things after  '?'
    *prot,    // "HTTP/1.1"
    *payload; // for POST

int payload_size;

char client_ip[INET_ADDRSTRLEN];
char request_time[64];
int response_status = 0;
size_t response_bytes = 0;

header_t reqhdr[17] = {{"\0", "\0"}};

void write_log() {
    FILE *log = fopen("/var/log/foxweb.log", "a");
    if (!log){
        perror("fopen log");
        return;
    }

    fprintf(log, "%s - - [%s] \"%s %s %s\" %d %zu\n",
        client_ip,
        request_time,
        method ? method : "-",
        uri ? uri : "-",
        prot ? prot : "-",
        response_status,
        response_bytes);

    fclose(log);
}

void *respond_thread(void *arg) {
    int clientfd = *(int *)arg;
    free(arg); // Мы выделим под него память

    respond(clientfd);

    close(clientfd);
    pthread_exit(NULL);
}

void serve_forever(const char *PORT) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;

    printf("Server started %shttp://127.0.0.1:%s%s\n", "\033[92m", PORT, "\033[0m");

    start_server(PORT);

    while (1) {
        addrlen = sizeof(clientaddr);
        int *clientfd = malloc(sizeof(int));
        *clientfd = accept(listenfd, (struct sockaddr *)&clientaddr, &addrlen);

        if (*clientfd < 0) {
            perror("accept() error");
            free(clientfd);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, respond_thread, clientfd) != 0) {
            perror("pthread_create error");
            close(*clientfd);
            free(clientfd);
        }

        pthread_detach(tid); // не нужно ждать join
    }
}

// start server
void start_server(const char *port) {
  struct addrinfo hints, *res, *p;

  // getaddrinfo for host
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(NULL, port, &hints, &res) != 0) {
    perror("getaddrinfo() error");
    exit(1);
  }
  // socket and bind
  for (p = res; p != NULL; p = p->ai_next) {
    int option = 1;
    listenfd = socket(p->ai_family, p->ai_socktype, 0);
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    if (listenfd == -1)
      continue;
    if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
      break;
  }
  if (p == NULL) {
    perror("socket() or bind()");
    exit(1);
  }

  freeaddrinfo(res);

  // listen for incoming connections
  if (listen(listenfd, QUEUE_SIZE) != 0) {
    perror("listen() error");
    exit(1);
  }
}

// get request header by name
char *request_header(const char *name) {
  header_t *h = reqhdr;
  while (h->name) {
    if (strcmp(h->name, name) == 0)
      return h->value;
    h++;
  }
  return NULL;
}

// get all request headers
header_t *request_headers(void) { return reqhdr; }

// Handle escape characters (%xx)
static void uri_unescape(char *uri) {
  char chr = 0;
  char *src = uri;
  char *dst = uri;

  // Skip inital non encoded character
  while (*src && !isspace((int)(*src)) && (*src != '%'))
    src++;

  // Replace encoded characters with corresponding code.
  dst = src;
  while (*src && !isspace((int)(*src))) {
    if (*src == '+')
      chr = ' ';
    else if ((*src == '%') && src[1] && src[2]) {
      src++;
      chr = ((*src & 0x0F) + 9 * (*src > '9')) * 16;
      src++;
      chr += ((*src & 0x0F) + 9 * (*src > '9'));
    } else
      chr = *src;
    *dst++ = chr;
    src++;
  }
  *dst = '\0';
}

// client connection
void respond(int clientfd) {
    response_status = 0;
    response_bytes = 0;

    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getpeername(clientfd, (struct sockaddr*)&addr, &len);
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

    time_t now = time(NULL);
    struct tm *ptm = localtime(&now);
    strftime(request_time, sizeof(request_time), "%d/%b/%Y:%H:%M:%S %z", ptm);

    buf = malloc(BUF_SIZE);
    int rcvd = recv(clientfd, buf, BUF_SIZE, 0);

    if (rcvd <= 0) {
        free(buf);
        return;
    }

    buf[rcvd] = '\0';

    method = strtok(buf, " \t\r\n");
    uri = strtok(NULL, " \t");
    prot = strtok(NULL, " \t\r\n");

    uri_unescape(uri);

    qs = strchr(uri, '?');
    if (qs)
        *qs++ = '\0';
    else
        qs = uri - 1;

    header_t *h = reqhdr;
    char *t, *t2;
    while (h < reqhdr + 16) {
        char *key = strtok(NULL, "\r\n: \t");
        if (!key) break;

        char *val = strtok(NULL, "\r\n");
        while (*val == ' ') val++;

        h->name = key;
        h->value = val;
        h++;
        t = val + 1 + strlen(val);
        if (t[1] == '\r' && t[2] == '\n') break;
    }

    t = strtok(NULL, "\r\n");
    t2 = request_header("Content-Length");
    payload = t;
    payload_size = t2 ? atol(t2) : (rcvd - (t - buf));

    // временно перенаправим stdout
    FILE *client_fp = fdopen(dup(clientfd), "w");
    if (!client_fp) {
        perror("fdopen");
        free(buf);
        return;
    }

    // временно подменим stdout (только для локального потока)
    FILE *old_stdout = stdout;
    stdout = client_fp;

    route();

    fflush(stdout);
    fclose(client_fp);

    stdout = old_stdout;

    pthread_mutex_lock(&log_mutex);
    write_log();
    pthread_mutex_unlock(&log_mutex);

    free(buf);
}
