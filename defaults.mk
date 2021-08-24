#############################################################################
# versions and paths for various external libraries and utils

ifdef __NT__
  # The following variables may have been set by vcvars.bat. You may
  # also set them manually. The default installation directories are
  # defined below in case these variables are not set.
  # Note: the following paths use backslashes (and may also contain a
  #       trailing backslash) in order to conform to the variables
  #       exported by vcvars.bat.

  # Visual C++ 2017 Install Directory
  VCINSTALLDIR ?= '$(PROGRAMFILES)\Microsoft Visual Studio\2017\Professional\VC\'

  # Visual C++ 2017 Tools Version
  # Note: if this variable is not set, the default version is obtained
  #       in allmake.mak under "Visual C++ 2017 Tools Version".
  # VCToolsVersion ?= '14.11.25503'

  # Windows SDK Install Directory
  WindowsSdkDir ?= '$(PROGRAMFILES)\Windows Kits\10\'

  # Windows SDK version
  # Note: if this variable is not set, the latest version is detected
  #       in allmake.mak under "Windows SDK Version".
  # WindowsSDKVersion ?= '10.0.17134.0\'

  # Microsoft SDK v7.1A is only used for the win32 debugger server for
  # Windows XP compatibility.
  MSSDK71_PATH = '$(PROGRAMFILES)/Microsoft SDKs/Windows/v7.1A'
else ifdef __MAC__
  # oldest supported version of MacOSX
  ifdef __ARM__
    MACOSX_DEPLOYMENT_TARGET = 11.0
  else
    MACOSX_DEPLOYMENT_TARGET = 10.9
  endif
endif

# Python
PYTHON_VERSION_MAJOR?=3
PYTHON_VERSION_MINOR?=4
PYTHON_VERNAME=python$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR)

# TODO clean this up
ifdef __NT__
  ifneq (,$(wildcard /cygdrive/c/Program\ Files/Python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)/python.exe))
    PYTHON_ROOT ?= C:/Program Files/Python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)
  else
    ifeq ($(PYTHON_VERSION_MAJOR),2)
      PYTHON_VERSUF=-x64
    endif
    PYTHON_ROOT ?= $(SYSTEMDRIVE)/Python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)$(PYTHON_VERSUF)
  endif
  PYTHON ?= "$(PYTHON_ROOT)/python.exe"
else
  PYTHON ?= $(PYTHON_VERNAME)
endif

# Qt
QTPROC-1=x64
QTPROC-$(__ARM__)=arm64
QTVER?=5.6.3-$(QTPROC-1)

QTDIR-$(__LINUX__) = /usr/local/Qt/$(QTVER)/
QTDIR-$(__MAC__)   = /Users/Shared/Qt/$(QTVER)/
QTDIR-$(__NT__)    = $(SYSTEMDRIVE)/Qt/$(QTVER)/
QTDIR ?= $(QTDIR-1)

ifdef __NT__
  ifdef NDEBUG
    QTSUFF=.dll
  else
    QTSUFF=d.dll
  endif
  QTLIBDIR=bin
else ifdef __LINUX__
  QTPREF=lib
  QTSUFF=.so.5
  QTLIBDIR=lib
endif

# SWiG
ifeq ($(PYTHON_VERSION_MAJOR),3)
  SWIG_VERSION?=4.0.1
  ifdef __NT__
    SWIG_DIR_SUFFIX?=-py3-stable-abi-cygwin
  else
    SWIG_DIR_SUFFIX?=-py3-stable-abi
  endif
else
  SWIG_VERSION?=4.0.0
endif
ifdef __NT__
  ifeq ($(PYTHON_VERSION_MAJOR),3)
    SWIG_DISTRIBUTION_HAS_UNIX_LAYOUT:=1
  endif
else
  SWIG_DISTRIBUTION_HAS_UNIX_LAYOUT:=1
endif

ifeq ($(SWIG_DISTRIBUTION_HAS_UNIX_LAYOUT),1)
  ifdef USE_CCACHE
    # we set CCACHE_DIR so as to not interfere with the system's ccache
    # and we set CCACHE_CPP2 to prevent SWiG from printing a bunch of
    # warnings due to re-using of the preprocessed source.
    SWIG?=CCACHE_DIR='$${HOME}/.ccache-swig' CCACHE_CPP2=1 $(SWIG_HOME)/bin/ccache-swig $(SWIG_HOME)/bin/swig
  else
    SWIG?=$(SWIG_HOME)/bin/swig
  endif
  SWIG_INCLUDES?=-I$(SWIG_HOME)/share/swig/$(SWIG_VERSION)/python -I$(SWIG_HOME)/share/swig/$(SWIG_VERSION)
else
  SWIG?=$(SWIG_HOME)/swig.exe
  SWIG_INCLUDES?=-I$(SWIG_HOME)/Lib/python -I$(SWIG_HOME)/Lib
endif

#############################################################################
# keep all paths in unix format, with forward slashes
ifeq ($(OS),Windows_NT)
  # define: convert dos path to unix path by replacing backslashes by slashes
  unixpath=$(subst \,/,$(1))

  PYTHON_ROOT  :=$(call unixpath,$(PYTHON_ROOT))
  PYTHON       :=$(call unixpath,$(PYTHON))
  SWIG         :=$(call unixpath,$(SWIG))
  QTDIR        :=$(call unixpath,$(QTDIR))
endif

#############################################################################
# http://stackoverflow.com/questions/16467718/how-to-print-out-a-variable-in-makefile
.print-%  : ; @echo $($*)
