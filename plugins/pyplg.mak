
# definitions for idapython (& other plugins dynamically linked to Python)
ifdef __NT__
  PYTHON_CFLAGS  := -I"$(PYTHON_ROOT)/include"
  ifeq ($(PYTHON_VERSION_MAJOR),3)
    PYTHON_LDFLAGS := "$(PYTHON_ROOT)/libs/python$(PYTHON_VERSION_MAJOR).lib"
  else
    PYTHON_LDFLAGS := "$(PYTHON_ROOT)/libs/python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR).lib"
  endif
else
  PYTHON_CFLAGS := $(shell $(PYTHON)-config --includes)
  ifdef __APPLE_SILICON__
    # to avoid codesigning complications on arm64 macs, we link against a stub tbd file. see plugins/idapython/tbd.readme
    PYTHON_LDFLAGS := -L$(R) -lpython$(PYTHON_VERSION_MAJOR) -ldl -framework CoreFoundation
  else
    # Yay! https://bugs.python.org/issue36721
    ifeq ($(PYTHON_VERSION_MAJOR),3)
      USE_EMBED := $(shell [ $(PYTHON_VERSION_MINOR) -ge 8 ] && echo true)
    endif
    ifeq ($(USE_EMBED),true)
      PYTHON_LDFLAGS := $(shell $(PYTHON)-config --ldflags --embed)
    else
      PYTHON_LDFLAGS := $(shell $(PYTHON)-config --ldflags)
    endif
  endif
endif
