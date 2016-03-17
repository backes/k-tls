Thread-Level Speculation with Kernel Support
============================================

This repository contains the source code of the K-TLS and U-TLS systems as
described in [this paper][paper-st] (also available on [ACM][paper-acm]; download [paper as PDF][paper-github] or [slides][slides-github]):
> C. Hammacher, K. Streit, A. Zeller and S. Hack. Thread-Level Speculation with
> Kernel Support. In *Proceedings of the 25th International Conference on
> Compiler Construction (CC '16)*, pages 1-11, March 2016.

Additionally, the sources of the improved [tinySTM] implementation (with
improved data structures for better scalability) is included.

All this software can be built by running the `make` command. If you need to
pass additional compiler or preprocessor flags, you can pass them on the
command line as follows:
```
  CPPFLAGS=-I/usr/local/include make
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
