#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// Minimal stubs for testing
typedef struct event_base event_base;
typedef struct evdns_base evdns_base;
typedef struct evconnlistener evconnlistener;
typedef struct bufferevent bufferevent;

// Include the debug header to test the _basename fix (undefine NDEBUG to enable debug mode)
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "debug.h"

// Simple test of the fixed _basename function
int main() {
    const char *test1 = "/path/to/file.c";
    const char *test2 = "\\windows\\path\\file.c";
    const char *test3 = "justfilename.c";
    const char *test4 = "";
    
    printf("Test 1: %s -> %s\n", test1, _basename(test1));
    printf("Test 2: %s -> %s\n", test2, _basename(test2));  
    printf("Test 3: %s -> %s\n", test3, _basename(test3));
    printf("Test 4: %s -> %s\n", test4, _basename(test4));
    
    return 0;
}
