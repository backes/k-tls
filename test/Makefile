Q ?= @
ObjDir ?= bin
ifeq ($(VERBOSE),1)
  Q=
endif

LIBRARY = $(OBJDIR)/libTLS.so

C_SOURCES   = $(wildcard *.c)
CXX_SOURCES = $(wildcard *.cpp)

C_TARGETS   = $(addprefix $(ObjDir)/,$(basename $(C_SOURCES)))
CXX_TARGETS = $(addprefix $(ObjDir)/,$(basename $(CXX_SOURCES)))
TARGETS     = $(C_TARGETS) $(CXX_TARGETS)

all : $(TARGETS)

# rebuild everything if the Makefile changes, and build obj dirs first:
DEPS = Makefile ../lib/TLS/obj/libTLS.so | $(ObjDir)/.dir

.PHONY: all clean

CXX      ?= g++
CC       ?= gcc
CPPFLAGS += -I../include
CXXFLAGS += -Wall -pedantic -std=c++11
CFLAGS   += -Wall -pedantic
LDFLAGS   = -lm -lpthread -ldl -L../lib/TLS/obj -lTLS
MKDIR    ?= mkdir -p

ifeq ($(VERBOSE),1)
  CPPFLAGS += -DVERBOSE
endif
ifeq ($(DEBUG),1)
  CPPFLAGS += -O0 -ggdb
else
  CPPFLAGS += -O2 -DNDEBUG
endif

clean :
	$(Q)rm -f $(TARGETS)

test : $(TARGETS)
	$(Q)echo "--- Running tests..."
	$(Q)for file in $(TARGETS); do echo "-- Running test $$file"; ./$$file || exit 1; done

%/.dir :
	$(Q)$(MKDIR) $(@D)
	$(Q)echo >$@

$(CXX_TARGETS) : $(ObjDir)/% : %.cpp $(DEPS)
	$(Q)echo Compiling $@
	$(Q)$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

$(C_TARGETS) : $(ObjDir)/% : %.c $(DEPS)
	$(Q)echo Compiling $@
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)
