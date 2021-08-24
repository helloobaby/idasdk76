__FUZZ_PLUGINS__=1

SRC_PATH = $(IDA)plugins/
BIN_PATH = $(R)plugins/


ifndef NO_DEFAULT_TARGETS
	BASE_OBJS += $(F)$(PROC)$(O)
endif

include $(RD)../../module.mak

ifdef __NT__
  ifndef NDEBUG
    $(MODULES): PDBFLAGS = /PDB:$(@:$(DLLEXT)=.pdb)
  endif
endif
