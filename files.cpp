/*
 * files.cpp
 *
 *  Created on: Jun 18, 2014
 *      Author: Clemens Hammacher <hammacher@cs.uni-saarland.de>
 */

#include "files.h"

#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

#include <sys/mman.h>
#include <sys/stat.h>

Mapping mapFile(const std::string &filename, bool useMmap) {
    struct stat st;

    if (stat(filename.c_str(), &st)) {
        perror("stat error");
        return Mapping();
    }
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("open error");
        return Mapping();
    }
    char *buf;
    if (useMmap) {
        buf = (char*)mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (buf == MAP_FAILED) {
            perror("mmap error");
            return Mapping();
        }
    } else {
        buf = (char*)malloc(st.st_size);
        if (buf == nullptr) {
            perror("malloc file buffer");
            return Mapping();
        }
        char *pos = buf, *end = pos + st.st_size;
        while (pos < end) {
            ssize_t n = read(fd, pos, end - pos);
            if (n < 1) {
                perror("error reading from file");
                return Mapping();
            }
            pos += n;
        }
    }
    if (close(fd)) {
        perror("close error");
        return Mapping();
    }

    return Mapping(filename, buf, st.st_size);
}

void closeMapping(const Mapping &map, bool useMmap) {
    if (useMmap) {
        if (munmap(map.start, map.len)) {
            perror("unmap error");
        }
    } else {
        free(map.start);
    }
}

void searchFiles(const std::string &directory, std::vector<std::string> &files) {
  struct dirent *entry;
  DIR *dp;

  dp = opendir(directory.c_str());
  if (dp == NULL) {
    std::cerr << "Cannot open directory '" << directory << "'" << std::endl;
    abort();
  }

  while ((entry = readdir(dp))) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    if (entry->d_type == DT_DIR) {
      searchFiles(directory + "/" + entry->d_name, files);
      continue;
    }
    int len = strlen(entry->d_name);
    if (len < 2 || memcmp(entry->d_name + len - 2, ".c", 2) != 0)
      continue;
    files.push_back(directory + "/" + entry->d_name);
  }

  closedir(dp);
}
