#ifndef _HTTPD_H___
#define _HTTPD_H___

#include <stdio.h>
#include <string.h>

// Client request
extern char *method, // "GET" or "POST"
    *uri,            // "/index.html" things before '?'
    *qs,             // "a=1&b=2" things after  '?'
    *prot,           // "HTTP/1.1"
    *payload;        // for POST

extern int payload_size;

extern int response_status;
extern size_t response_bytes;

// Server control functions
void serve_forever(const char *PORT);

char *request_header(const char *name);

typedef struct {
  char *name, *value;
} header_t;
extern header_t reqhdr[17];
header_t *request_headers(void);

// user shall implement this function

void route();

// Response
#define RESPONSE_PROTOCOL "HTTP/1.1"

#define HTTP_200 \
  response_status = 200; \
  response_bytes += printf("%s 200 OK\r\n" \
         "Content-Type: text/html\r\n" \
         "Connection: close\r\n\r\n", RESPONSE_PROTOCOL)

#define HTTP_201 \
  response_status = 201; \
  response_bytes += printf("%s 201 Created\r\n" \
         "Content-Type: text/html\r\n" \
         "Connection: close\r\n\r\n", RESPONSE_PROTOCOL)

#define HTTP_404 \
  response_status = 404; \
  response_bytes += printf("%s 404 Not Found\r\n" \
         "Content-Type: text/html\r\n" \
         "Connection: close\r\n\r\n", RESPONSE_PROTOCOL)

#define HTTP_500 \
  response_status = 500; \
  response_bytes += printf("%s 500 Internal Server Error\r\n" \
         "Content-Type: text/html\r\n" \
         "Connection: close\r\n\r\n", RESPONSE_PROTOCOL)

// some interesting macro for `route()`
#define ROUTE_START() if (0) {
#define ROUTE(METHOD, URI)                                                     \
  }                                                                            \
  else if (strcmp(URI, uri) == 0 && strcmp(METHOD, method) == 0) {
#define GET(URI) ROUTE("GET", URI)
#define POST(URI) ROUTE("POST", URI)
#define ROUTE_END()                                                            \
  }                                                                            \
  else HTTP_500;

#endif
