include ../../allmake.mak

GOALS-$(BUILD_IDA) += modules # target in $(IDA)module.mak
GOALS-$(BUILD_DBGSRV) += server # target in $(IDA)dbg/server.mak
.PHONY: $(GOALS-1)
all: $(GOALS-1)

#----------------------------------------------------------------------
ifdef __NT__
  ifndef __X86__
    SERVER = win64_remote$(B)
  else
    SERVER = win32_remote$(B)
  endif
endif
ifdef SERVER
  SERVERS += $(call server_exe,$(SERVER))
endif

#----------------------------------------------------------------------
STUB = $(call module_dll,win32_stub)
ifdef BUILD_IDA
  ifeq ($(or $(IDAHOME),$(DEMO_OR_FREE)),)
    MODULES += $(STUB)
  endif
endif

#----------------------------------------------------------------------
USER = $(call module_dll,win32_user)
ifeq ($(and $(BUILD_IDA),$(__NT__)),1)
  MODULES += $(USER)
endif

#----------------------------------------------------------------------
# we explicitly added our module targets
NO_DEFAULT_TARGETS = 1

# NOTE: all MODULES must be defined before including plugin.mak.
include ../plugin.mak
# NOTE: target-specific rules and dependencies that use variable
#       expansion to name the target (such as "$(MODULE): [...]") must
#       come after including plugin.mak

#----------------------------------------------------------------------
# select OBJS common to user plugin and debugger server
BASE_OBJS-$(__NT__) += $(F)win32_debmod$(O)
BASE_OBJS-$(__NT__) += $(F)win32_util$(O)
BASE_OBJS-$(__NT__) += $(F)winbase_debmod$(O)
BASE_OBJS += $(BASE_OBJS-1)

#----------------------------------------------------------------------
SERVER_OBJS += $(F)win32_server$(O)
SERVER_OBJS += $(F)tilfuncs$(O)
SERVER_OBJS += $(BASE_OBJS)

SERVER_STDLIBS += ole32.lib
SERVER_STDLIBS += oleaut32.lib

include ../server.mak

#----------------------------------------------------------------------
STUB_OBJS += $(F)win32_stub$(O)
STUB_OBJS += $(F)w32sehch$(O)
$(STUB): MODULE_OBJS += $(STUB_OBJS)
$(STUB): $(STUB_OBJS)

#----------------------------------------------------------------------
USER_OBJS += $(F)win32_user$(O)
USER_OBJS += $(F)w32sehch$(O)
USER_OBJS += $(BASE_OBJS)
$(USER): MODULE_OBJS += $(USER_OBJS)
$(USER): $(USER_OBJS)
$(USER): STDLIBS += user32.lib

#----------------------------------------------------------------------
include $(IDA)objdir.mak

# MAKEDEP dependency list ------------------
$(F)tilfuncs$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)diskio.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h          \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)ins/pc.hpp $(I)intel.hpp $(I)kernwin.hpp              \
                  $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp $(I)name.hpp     \
                  $(I)netnode.hpp $(I)network.hpp $(I)pro.h $(I)range.hpp   \
                  $(I)segment.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  ../../ldr/pe/cor.h ../../ldr/pe/corerror.h                \
                  ../../ldr/pe/corhdr.h ../../ldr/pe/mycor.h                \
                  ../../ldr/pe/pe.h ../../plugins/pdb/common.cpp            \
                  ../../plugins/pdb/cvconst.h ../../plugins/pdb/dbghelp.h   \
                  ../../plugins/pdb/dia2.h ../../plugins/pdb/idaaccess.hpp  \
                  ../../plugins/pdb/msdia.cpp ../../plugins/pdb/msdia.hpp   \
                  ../../plugins/pdb/pdb.hpp                                 \
                  ../../plugins/pdb/pdbaccess.hpp                           \
                  ../../plugins/pdb/pdbida.hpp                              \
                  ../../plugins/pdb/pdblocal.cpp                            \
                  ../../plugins/pdb/pdblocal.hpp                            \
                  ../../plugins/pdb/varser.hpp ../debmod.h tilfuncs.cpp     \
                  tilfuncs.hpp
$(F)w32sehch$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)dbg.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp          \
                  $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
                  $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
                  $(I)netnode.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)ua.hpp $(I)xref.hpp w32sehch.cpp w32sehch.h
$(F)win32_debmod$(O): $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp           \
                  $(I)config.hpp $(I)dbg.hpp $(I)diskio.hpp $(I)entry.hpp   \
                  $(I)err.h $(I)exehdr.h $(I)fixup.hpp $(I)fpro.h           \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp                     \
                  $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
                  $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
                  $(I)network.hpp $(I)offset.hpp $(I)pro.h $(I)prodir.h     \
                  $(I)range.hpp $(I)segment.hpp $(I)segregs.hpp $(I)ua.hpp  \
                  $(I)xref.hpp ../../ldr/pe/../idaldr.h                     \
                  ../../ldr/pe/common.cpp ../../ldr/pe/common.h             \
                  ../../ldr/pe/pe.h ../dbg_pe_hlp.cpp ../deb_pc.hpp         \
                  ../debmod.h ../pc_debmod.h ../pc_regs.hpp                 \
                  win32_debmod.cpp win32_debmod.h win32_debmod_impl.cpp     \
                  win32_rpc.h win32_undoc.h win32_util.hpp                  \
                  winbase_debmod.h
$(F)win32_server$(O): $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp         \
                  $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp          \
                  $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
                  $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp                 \
                  $(I)network.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp                   \
                  ../../ldr/pe/cor.h ../../ldr/pe/corerror.h                \
                  ../../ldr/pe/corhdr.h ../../ldr/pe/mycor.h                \
                  ../../ldr/pe/pe.h ../../plugins/pdb/cvconst.h             \
                  ../../plugins/pdb/dia2.h ../../plugins/pdb/idaaccess.hpp  \
                  ../../plugins/pdb/msdia.hpp ../../plugins/pdb/pdb.hpp     \
                  ../../plugins/pdb/pdbaccess.hpp                           \
                  ../../plugins/pdb/pdbida.hpp                              \
                  ../../plugins/pdb/pdblocal.hpp ../dbg_rpc_hlp.h           \
                  ../deb_pc.hpp ../debmod.h ../pc_debmod.h ../pc_regs.hpp   \
                  tilfuncs.hpp win32_debmod.h win32_rpc.h win32_server.cpp  \
                  win32_util.hpp winbase_debmod.h
$(F)win32_stub$(O): $(I)../ldr/pe/pe.h $(I)../plugins/pdb/pdb.hpp           \
                  $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)dbg.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h             \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
                  $(I)network.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)segregs.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  ../../ldr/pe/pe.h ../common_local_impl.cpp                \
                  ../common_stub_impl.cpp ../dbg_rpc_client.h               \
                  ../dbg_rpc_engine.h ../dbg_rpc_hlp.h ../deb_pc.hpp        \
                  ../debmod.h ../pc_local_impl.cpp ../pc_regs.hpp           \
                  ../rpc_debmod.h w32sehch.h win32_local_impl.cpp           \
                  win32_rpc.h win32_stub.cpp
$(F)win32_user$(O): $(I)../ldr/pe/pe.h $(I)../plugins/pdb/pdb.hpp           \
                  $(I)bitrange.hpp $(I)bytes.hpp $(I)config.hpp             \
                  $(I)dbg.hpp $(I)err.h $(I)expr.hpp $(I)fpro.h             \
                  $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
                  $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
                  $(I)network.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)segregs.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  ../../ldr/pe/pe.h ../common_local_impl.cpp                \
                  ../common_stub_impl.cpp ../dbg_rpc_hlp.h ../deb_pc.hpp    \
                  ../debmod.h ../pc_debmod.h ../pc_local_impl.cpp           \
                  ../pc_regs.hpp w32sehch.h win32_debmod.h                  \
                  win32_local_impl.cpp win32_rpc.h win32_server_stub.cpp    \
                  win32_user.cpp win32_util.hpp winbase_debmod.h
$(F)win32_util$(O): $(I)bytes.hpp $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp   \
                  $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp $(I)netnode.hpp  \
                  $(I)network.hpp $(I)pro.h $(I)range.hpp $(I)segment.hpp   \
                  $(I)ua.hpp $(I)xref.hpp ../deb_pc.hpp ../debmod.h         \
                  ../pc_debmod.h ../pc_regs.hpp win32_util.cpp              \
                  win32_util.hpp winbase_debmod.h
$(F)winbase_debmod$(O): $(I)bytes.hpp $(I)ida.hpp $(I)idd.hpp               \
                  $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp  \
                  $(I)netnode.hpp $(I)network.hpp $(I)pro.h $(I)range.hpp   \
                  $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp ../deb_pc.hpp     \
                  ../debmod.h ../pc_debmod.h ../pc_regs.hpp win32_util.hpp  \
                  winbase_debmod.cpp winbase_debmod.h
