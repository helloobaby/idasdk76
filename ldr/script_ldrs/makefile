
include ../../allmake.mak

LDRDIR = $(R)loaders

LOADERS += archldr_tar.py
LOADERS += bios_image.py
LOADERS += pdfldr.py
LOADERS += uimage.py
LOADERS += wince.py
LOADERS-$(IDAADV) += hppacore.idc

LOADERS += $(LOADERS-1)

all: $(addprefix $(LDRDIR)/, $(LOADERS))

$(LDRDIR)/%.idc: %.idc
	$(CP) $? $@

$(LDRDIR)/%.py: %.py
	$(CP) $? $@

clean::
	rm -f $(addprefix $(LDRDIR)/, $(LOADERS))
