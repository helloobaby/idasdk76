#include <loader.hpp>

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
inline bool register_idc_funcs(bool)
{
  return true;
}

//--------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
  ea_t base = get_imagebase();
  if ( base != BADADDR && new_base != BADADDR && base != new_base )
    rebase_or_warn(base, new_base);
}

//--------------------------------------------------------------------------
static bool init_plugin(void)
{
#ifndef RPC_CLIENT
  if ( !init_subsystem() )
    return false;
#endif

  bool ok = false;
  do
  {
    if ( !netnode::inited() || is_miniidb() || inf_is_snapshot() )
    {
#ifdef __LINUX__
      // local debugger is available if we are running under Linux
      return true;
#else
      // for other systems only the remote debugger is available
      if ( debugger.is_remote() )
        return true;
      break; // failed
#endif
    }

    if ( inf_get_filetype() != f_ELF )
      break;
    processor_t &ph = PH;
    if ( ph.id != TARGET_PROCESSOR && ph.id != -1 )
      break;

    ok = true;
  } while ( false );
#ifndef RPC_CLIENT
  if ( !ok )
    term_subsystem();
#endif
  return ok;
}

//--------------------------------------------------------------------------
inline void term_plugin(void)
{
#ifndef RPC_CLIENT
  term_subsystem();
#endif
}

//--------------------------------------------------------------------------
static const char comment[] = "Userland linux debugger plugin.";
