#include <stdlib.h>

void good_uaf() {
  int *p = (int *)malloc(sizeof(int));
  *p = 1;
  free(p);
  p = nullptr;
  free(p);

  int *q = (int *)malloc(sizeof(int));
  free(q);
  q = (int *)malloc(sizeof(int));
  *q = 2;
  free(q);
}
