include ../plugin.mak

CC_DEFS += QT_CORE_LIB
CC_DEFS += QT_DLL
CC_DEFS += QT_GUI_LIB
CC_DEFS += QT_NAMESPACE=QT
CC_DEFS += QT_THREAD_SUPPORT
CC_DEFS += QT_WIDGETS_LIB
CC_INCP += .
ifdef __LINUX__
  CC_F += -fPIC
else ifdef __NT__
  CFLAGS += /GS
  CFLAGS += /wd4946 # reinterpret_cast used between related classes
  CFLAGS += /wd4826 # Conversion from 'ptr32' to 'int64' is sign-extended. This may cause unexpected runtime behavior.
  CFLAGS += /wd4628 # Digraphs not supported. Avoids errors on things such as: "template<> inline void swap<::QT::QByteArray>"
  CFLAGS += /wd4718 # 'QT::QMapNode<int,int>::destroySubTree' : recursive call has no side effects, deleting
  CFLAGS += /wd4481 # warning C4481: nonstandard extension used: override specifier 'override'
endif

ifdef __MAC__
  PREF=$(QTDIR)lib/
  CC_INCP += $(PREF)QtCore.framework/Headers
  CC_INCP += $(PREF)QtGui.framework/Headers
  CC_INCP += $(PREF)QtWidgets.framework/Headers
  CFLAGS += -F$(PREF)
  LIBS += $(PREF)QtCore.framework/QtCore
  LIBS += $(PREF)QtGui.framework/QtGui
  LIBS += $(PREF)QtWidgets.framework/QtWidgets
  # We must change the library path in the plugin so they become relative
  # to the ida executable. Otherwise the plugin loads the second copy of
  # these libraries and crashes IDA
  CHANGE_LIBPATH=install_name_tool -change \
                 $(QTDIR)lib/$1.framework/Versions/4/$1 \
                 @executable_path/../Frameworks/$1.framework/Versions/4/$1 $@
  POSTACTION=@$(call CHANGE_LIBPATH,QtGui); \
              $(call CHANGE_LIBPATH,QtWidgets); \
              $(call CHANGE_LIBPATH,QtCore)
else
  CC_INCP += $(QTDIR)include
  CC_INCP += $(QTDIR)include/QtCore
  CC_INCP += $(QTDIR)include/QtGui
  CC_INCP += $(QTDIR)include/QtWidgets
  ifdef __LINUX__
    PREF=$(QTDIR)lib/lib
    POST=.so
  endif # __LINUX__
  ifdef __NT__
    PREF=$(QTDIR)lib/
    ifdef NDEBUG
      POST=$(A)
    else
      POST=d$(A)
    endif
  endif
  LIBS += $(PREF)Qt5Core$(POST)
  LIBS += $(PREF)Qt5Gui$(POST)
  LIBS += $(PREF)Qt5Widgets$(POST)
endif

$(F)moc_%.cpp: %.h
	$(QTDIR)bin/moc -I. $< > $@

# Add $(F) to vpath for $(F)moc_*$(O).
vpath %.cpp $(F)
