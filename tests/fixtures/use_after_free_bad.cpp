#include <stdlib.h>

struct Node {
  int value;
};

void bad_uaf(int cond) {
  int *p = (int *)malloc(sizeof(int));
  if (cond) {
    free(p);
  }
  *p = 42;
  free(p);

  Node *n = new Node{1};
  delete n;
  int v = n->value;
  (void)v;

  int *a = (int *)malloc(sizeof(int));
  int *b = a;
  free(a);
  *b = 7;
}
