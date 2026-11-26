#include <stdlib.h>

void allocate_out(int **out);
void init_ref(int *&out);

void good_uninit(int *src) {
  int *p = src;
  *p = 1;

  int *q;
  q = src;
  *q = 2;

  int *out_c;
  allocate_out(&out_c);
  *out_c = 3;

  int *out_cpp;
  init_ref(out_cpp);
  *out_cpp = 4;
}
