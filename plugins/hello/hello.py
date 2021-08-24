import idaapi

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print "Hello world!"

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()

