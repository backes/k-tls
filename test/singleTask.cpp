#include <cstdlib>
#include <cstdio>
#include <cstdint>

#include "TLS/ktls.h"
#include "TLS/utls.h"
#include "TLS/tls.h"

using namespace TLS;

uint32_t globalVar;

void updateVars(void *in, void * /*out*/) {
  uint32_t *stackVar = ((uint32_t **)in)[0];
  uint32_t *heapVar = ((uint32_t **)in)[1];

  // one in the global data area, one on the stack, one on the heap:
  globalVar = 42;
  *stackVar = 47;
  *heapVar = 1113;
}

int main() {
  uint32_t *heapVar = reinterpret_cast<uint32_t *>(malloc(sizeof(*heapVar)));
  uint32_t stackVar;
  printf("Address of globalVar: %p\n", (void*)&globalVar);
  printf("Address of stackVar: %p\n", (void*)&stackVar);
  printf("Address of heapVar: %p\n", (void*)heapVar);

  // i == 0 : execute in U-TLS
  // i == 1 : execute in K-TLS
  for (int i = 0; i < 2; ++i) {
    printf("Executing in %s-TLS...\n", i == 0 ? "U" : "K");
    globalVar = 0;
    *heapVar = 0;
    stackVar = 0;
    TaskList t;
    uint32_t **in = reinterpret_cast<uint32_t **>(
        t.addTask(2 * sizeof(uint32_t *), 0, updateVars)->getInputData());
    in[0] = &stackVar;
    in[1] = heapVar;
    if (i == 0)
      utls_run(&t);
    else
      ktls_run(&t);
    if (globalVar != 42 || stackVar != 47 || *heapVar != 1113) {
      printf("Expecting variable values to be 42 / 47 / 1113. "
             "Found %d / %d / %d.\n",
             globalVar, stackVar, *heapVar);
      abort();
    }
  }

  printf("Test run completed.\n");
  return 0;
}
