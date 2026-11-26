#include <stdlib.h>

struct Item {
  int x;
};

void bad_uninit(int cond, int *src) {
  int *p;
  *p = 10;

  int *q;
  if (cond) {
    q = src;
  }
  int v = q[0];
  (void)v;

  Item *it;
  int m = it->x;
  (void)m;

  int *raw;
  free(raw);
}
