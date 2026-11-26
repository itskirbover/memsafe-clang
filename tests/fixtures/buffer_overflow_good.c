#include <stdio.h>
#include <string.h>

void good_buffers(const char *src) {
  char buf[16];
  buf[0] = 'a';
  buf[15] = '\0';
  memcpy(buf, src, 16);
  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf), "%s", src);
}
