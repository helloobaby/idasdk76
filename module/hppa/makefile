PROC=hppa
CONFIGS=hpux.cfg


include ../module.mak

# MAKEDEP dependency list ------------------
$(F)ana$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp  $(I)diskio.hpp               \
                  $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp                 \
                   $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)segregs.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  ../idaidp.hpp ana.cpp hppa.hpp ins.hpp
$(F)emu$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp  $(I)diskio.hpp               \
                  $(I)fixup.hpp $(I)fpro.h $(I)frame.hpp $(I)funcs.hpp      \
                  $(I)ida.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
                  $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp   \
                   $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)segregs.hpp $(I)struct.hpp $(I)typeinf.hpp            \
                  $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp emu.cpp hppa.hpp    \
                  ins.hpp
$(F)ins$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp  $(I)diskio.hpp               \
                  $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp                 \
                   $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)segregs.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  ../idaidp.hpp hppa.hpp ins.cpp ins.hpp
$(F)out$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp  $(I)diskio.hpp               \
                  $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp                 \
                   $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)segregs.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  ../idaidp.hpp hppa.hpp ins.hpp out.cpp
$(F)reg$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
                  $(I)config.hpp  $(I)diskio.hpp               \
                  $(I)fixup.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp        \
                  $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp $(I)lines.hpp      \
                  $(I)llong.hpp $(I)loader.hpp                 \
                   $(I)nalt.hpp $(I)name.hpp                \
                  $(I)netnode.hpp $(I)offset.hpp $(I)pro.h                  \
                  $(I)problems.hpp $(I)range.hpp $(I)segment.hpp            \
                  $(I)segregs.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp   \
                  ../idaidp.hpp hppa.hpp hppa_cfh.cpp ins.hpp               \
                  notify_codes.hpp reg.cpp
