#include <cstdlib>
#include <cstdio>
#include <cstdint>

#include <vector>

#include "TLS/ktls.h"
#include "TLS/tls.h"

using namespace TLS;

#define numParallelTasks 8
#define numUpdatesPerTask 4

// each element is 256 bytes large, in order to have less rollbacks
struct Elem {
  int i;
  char fill[256 - sizeof(i)];
  Elem(): i(-1) { }
};

struct UpdateInfo {
  std::vector<Elem> *vec;
  std::vector<int> *idxs;
};
void update(void *in, void * /*out*/) {
  UpdateInfo *info = (UpdateInfo*)in;
  for (int idx : *info->idxs)
    info->vec->at(idx).i = idx;
}

bool idxSetCorrectly(std::vector<Elem> &vec) {
  for (int idx = 0, e = vec.size(); idx != e; ++idx)
    if (vec[idx].i != idx)
      return false;
  return true;
}

int main() {
  printf("Executing loop for sizes 1 .. 65536, printing size, number of ktls "
         "tasks and number of ktls rollbacks\n");
  UpdateInfo infos[numParallelTasks];
  std::vector<int> idxss[numParallelTasks];
  for (auto &vec : idxss)
    vec.resize(numUpdatesPerTask);
  for (int i = 0; i < numParallelTasks; ++i)
    infos[i].idxs = &idxss[i];
  for (int size = 1; size <= 1 << 16; size <<= 1) {
    std::vector<Elem> vec(size);
    for (int i = 0; i < numParallelTasks; ++i)
      infos[i].vec = &vec;
    while (!idxSetCorrectly(vec)) {
      for (auto &info : infos)
        for (auto &idx : *info.idxs)
          idx = rand() % size;

      void *p = ktls_start_loop();
      if (!p) {
        perror("error starting loop");
        abort();
      }
      for (auto &info : infos)
        ktls_spawn_next(p, update, &info, sizeof(info));
      ktls_finish_loop(p);
    }
    struct ktls_stats stats;
    if (ktls_get_global_stats(&stats) != 0) {
      fprintf(stderr, "Error getting K-TLS stats\n");
      abort();
    }
    if (ktls_reset_global_stats() != 0) {
      fprintf(stderr, "Error resetting K-TLS stats\n");
      abort();
    }
    printf("  - %5d / %5d / %5d\n", size, stats.num_tasks, stats.num_rollbacks);
  }
  return 0;
}
