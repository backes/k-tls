LEVEL = ..

# define TOOLNAME for building executable in ToolDir
#TOOLNAME = cindex

# define MODULE_NAME for building linked bitcode file in LibDir
MODULE_NAME = cindex

SOURCES = main.cpp files.cpp indexer.cpp

include $(LEVEL)/Makefile.common

# find a g++-4.9 if possible
CXX=$(shell for version in git 4.9 4.9.2 4.9.1 4.9.0; do which g++-$$version &>/dev/null && echo g++-$$version && exit; done)
ifeq ($(CXX),)
ifneq ($(TOOLNAME),)
$(warning did not find a g++-4.9*, falling back to default g++, hoping it will not fail...)
endif
CXX=g++
endif

# and filter out some unsupported flags for g++
UNSUPPORTED_FLAGS := -Wcovered-switch-default -stdlib=libc++ -rdynamic
CompileCommonOpts := $(filter-out $(UNSUPPORTED_FLAGS), $(CompileCommonOpts))
CXX.Flags := $(filter-out $(UNSUPPORTED_FLAGS), $(CXX.Flags))
LD.Flags := $(filter-out $(UNSUPPORTED_FLAGS), $(LD.Flags))

CXXFLAGS += -fgnu-tm

# don't use the -fgnu-tm when compiling to bytecode
LLVM_UNSUPPORTED_FLAGS += -fgnu-tm
# our llvm version is broken: it creates not-16-byte-aligned stack frames, but
# movaps instructions...
LLVM_FLAGS += -fno-vectorize

LDFLAGS += -L$(SambambaLibDir)

LIBS += -l$(TBB_LIB) -L$(TBB_LIB_DIR)

#LIBS += -l$(SAMBAMBA_SHLIB_NAME)

