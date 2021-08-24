#include <idc.idc>

class myplugin_t
{
  myplugin_t()
  {
    this.flags = 0;
    this.comment = "This is a comment";
    this.help = "This is help";
    this.wanted_name = "Sample IDC plugin";
    this.wanted_hotkey = "Alt-F6";
  }
  init()
  {
    return PLUGIN_OK;
  }
  run(arg)
  {
    msg("Hello world\n");
    return 0;
  }
  term()
  {
  }
}

static PLUGIN_ENTRY()
{
  return myplugin_t();
}
