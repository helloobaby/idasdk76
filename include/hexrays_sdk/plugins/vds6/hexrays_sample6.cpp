/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2021 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for the Hex-Rays Decompiler.
 *      It modifies the decompilation output: removes some space characters.
 *
 */

#include <hexrays.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
  bool inited = true;

  plugin_ctx_t()
  {
    install_hexrays_callback(hr_callback, nullptr);
  }
  ~plugin_ctx_t()
  {
    if ( inited )
    {
      remove_hexrays_callback(hr_callback, nullptr);
      term_hexrays_plugin();
    }
  }
  virtual bool idaapi run(size_t) override { return false; }
  static ssize_t idaapi hr_callback(
        void *ud,
        hexrays_event_t event,
        va_list va);
};

//--------------------------------------------------------------------------
inline bool is_cident_char(char c)
{
  return qisalnum(c) || c == '_';
}

//--------------------------------------------------------------------------
static void remove_spaces(simpleline_t &sl)
{
  char *ptr = &sl.line[0];
  // skip initial spaces, do not compress them
  while ( true )
  {
    ptr = (char*)tag_skipcodes(ptr);
    if ( !qisspace(*ptr) )
      break;
    if ( *ptr == '\0' )
      return;
    ptr++;
  }

  // remove all spaces except in string and char constants
  char delim = 0; // if not zero, then we are skipping until 'delim'
  char last = 0;  // last seen character
  while ( *ptr != '/' || ptr[1] != '/' ) // until comments
  {
    ptr = (char*)tag_skipcodes(tag_advance(ptr, 1));
    if ( *ptr == '\0' )
      break;
    if ( delim != 0 )
    {
      if ( *ptr == '\\' ) // escape character, skip it and the next as well
      {
        ptr++;
      }
      else
      {
        if ( *ptr == delim )
          delim = 0; // found it
      }
    }
    else if ( *ptr == '"' || *ptr == '\'' )
    {
      delim = *ptr;
    }
    else if ( qisspace(*ptr) )
    {
      char *end = ptr + 1;
      while ( qisspace(*end) )
        end++;
      // do not concatenate idents
      const char *nptr = tag_skipcodes(end);
      if ( !is_cident_char(last) || !is_cident_char(*nptr) )
        memmove(ptr, end, strlen(end)+1);
    }
    last = *ptr;
  }

}

//--------------------------------------------------------------------------
// This callback handles various hexrays events.
ssize_t idaapi plugin_ctx_t::hr_callback(
        void *,
        hexrays_event_t event,
        va_list va)
{
  switch ( event )
  {
    case hxe_func_printed:
      {
        cfunc_t *cfunc = va_arg(va, cfunc_t *);
        strvec_t &sv = cfunc->sv;
        for ( int i=0; i < sv.size(); i++ )
          remove_spaces(sv[i]);
      }
      break;
    default:
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
// Initialize the plugin.
static plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr; // no decompiler
  const char *hxver = get_hexrays_version();
  msg("Hex-rays version %s has been detected, %s ready to use\n",
      hxver, PLUGIN.wanted_name);
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
static char comment[] = "Sample plugin6 for Hex-Rays decompiler";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE           // Plugin should not appear in the Edit, Plugins menu
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "Hex-Rays space remover", // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
