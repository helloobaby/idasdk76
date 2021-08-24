import idaapi

mymnem = "linux_kernel_call"

"""
    This is a sample plugin for extending processor modules

    It extends the IBM PC processor module to disassemble
        "int 80h"
    as
        "%s"

    for ELF files

(c) Hex-Rays
""" % mymnem

NN_kernel_call = idaapi.CUSTOM_INSN_ITYPE

#--------------------------------------------------------------------------
class linux_idp_hook_t(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def ev_ana_insn(self, insn):
        if idaapi.get_bytes(insn.ea, 2) != b"\xCD\x80":
            return False
        insn.itype = NN_kernel_call
        insn.size = 2
        return True

    def ev_out_mnem(self, outctx):
        if outctx.insn.itype != NN_kernel_call:
            return 0
        outctx.out_custom_mnem(mymnem)
        return 1

#--------------------------------------------------------------------------
class linuxprocext_t(idaapi.plugin_t):
    # Processor fix plugin module
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = ""
    wanted_hotkey = ""
    help = "Replaces int 0x80 with %s" % mymnem
    wanted_name = mymnem

    def init(self):
        self.prochook = None
        if idaapi.ph_get_id() != idaapi.PLFM_386 or idaapi.cvar.inf.filetype != idaapi.f_ELF:
            print("linuxprocext_t.init() skipped!")
            return idaapi.PLUGIN_SKIP

        self.prochook = linux_idp_hook_t()
        self.prochook.hook()

        print("linuxprocext_t.init() called!")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        print("linuxprocext_t.term() called!")
        if self.prochook:
            self.prochook.unhook()

#--------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return linuxprocext_t()
