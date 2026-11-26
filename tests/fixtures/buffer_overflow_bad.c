#include <stdio.h>
#include <string.h>

void bad_buffers(const char *src) {
  char buf[8];
  buf[8] = 'x';
  buf[-1] = 'y';
  memcpy(buf, src, 16);
  memset(buf, 0, 12);
  strcpy(buf, "this string overflows buf");
  sprintf(buf, "%s", src);
}
