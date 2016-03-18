Thread-Level Speculation with Kernel Support
============================================

This repository contains the source code of the K-TLS and U-TLS systems as
described in [this paper][paper-st] (also available on [ACM][paper-acm]; download [paper as PDF][paper-github] or [slides][slides-github]):
> C. Hammacher, K. Streit, A. Zeller and S. Hack. Thread-Level Speculation with
> Kernel Support. In *Proceedings of the 25th International Conference on
> Compiler Construction (CC '16)*, pages 1-11, March 2016.

Additionally, the sources of the improved [tinySTM] implementation (with
improved data structures for better scalability) is included.

Building
========

The software (TinySTM, U-TLS and K-TLS) is split into different directories in
the `lib` folder.
All this software can be built by running the `make` command. If you need to
pass additional compiler or preprocessor flags, you place them in the
corresponding environment variables, for example like this:
```
  CPPFLAGS=-I/usr/local/include make
```

The kernel module is compiled for the currently running kernel.
If the directory `/lib/modules/$(uname -r)/build` does not exist, the Makefile
will output a warning and skip compilation of the kernel module.

Usage
=====

Before running experiments using K-TLS, make sure to load the kernel module:
```
  sudo insmod lib/KTLS/kmod/KTLS.ko
```

For debugging, load the module with the debug level set to `3` or `4`, and
observe the kernel messages printed:
```
  sudo insmod lib/KTLS/kmod/KTLS.ko debug=3
  dmesg -wT
```

Authors
=======

This software was written by Clemens Hammacher, with contributions by Daniel
Birtel and Janosch Gräf.

License
=======

Both U-TLS and K-TLS are available under the [GNU General Public License v3][GPL].

[tinySTM]: http://tmware.org/tinystm
[GPL]: https://gnu.org/licenses/gpl.html
[paper-st]: https://www.st.cs.uni-saarland.de/publications/details/hammacher-cc16/
[paper-acm]: http://dl.acm.org/citation.cfm?id=2892221
[paper-github]: https://github.com/hammacher/k-tls/blob/publications/cc16-hammacher-paper.pdf
[slides-github]: https://github.com/hammacher/k-tls/blob/publications/cc16-hammacher-slides.pdf
