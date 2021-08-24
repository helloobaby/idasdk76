#include <fpro.h>
#include <prodir.h>
#include <diskio.hpp>
#include "linuxbase_debmod.h"

//--------------------------------------------------------------------------
static inline const char *str_bitness(int bitness)
{
  switch ( bitness )
  {
    case 8:
      return "[64]";
    case 4:
      return "[32]";
    default:
      return "[x]";
  }
}

//--------------------------------------------------------------------------
static void build_process_ext_name(ext_process_info_t *pinfo)
{
  pinfo->ext_name = str_bitness(pinfo->addrsize);

  char buf[QMAXPATH];
  qsnprintf(buf, sizeof(buf), "/proc/%u/cmdline", pinfo->pid);

  FILE *cmdfp = qfopen(buf, "r");
  if ( cmdfp == nullptr )
    return;

  int size = qfread(cmdfp, buf, sizeof(buf));
  buf[size] = '\0';
  qfclose(cmdfp);

#ifdef __ANDROID__
  while ( size >= 0 && buf[size] == '\0' )
    size--;
  size++;
#endif

  // arguments are separated by '\0'
  for ( int i=0; i < size; )
  {
    const char *in = &buf[i];
    qstring arg = in;
    quote_cmdline_arg(&arg);
    pinfo->ext_name.append(" ");
    pinfo->ext_name.append(arg);

    i += strlen(in) + 1;
  }
}

//--------------------------------------------------------------------------
// Returns the file name assciated with pid
bool idaapi linuxbase_debmod_t::get_exec_fname(
        int _pid,
        char *buf,
        size_t bufsize)
{
  char path[QMAXPATH];
  qsnprintf(path, sizeof(path), "/proc/%u/exe", _pid);
  int len = readlink(path, buf, bufsize-1);
  if ( len > 0 )
  {
    buf[len] = '\0';
    return true;
  }
  else
  {
    // ESXi keeps the real file name inside /proc/PID/exe (which is not a link)
    FILE *fp = qfopen(path, "r");
    if ( fp != NULL )
    {
      len = qfread(fp, buf, bufsize);
      qfclose(fp);
      if ( len > 1 && len < bufsize && buf[0] == '/' ) // sanity check
      {
        buf[len] = '\0';
        return true;
      }
    }
    buf[0] = '\0';
    return false;
  }
}

//--------------------------------------------------------------------------
// Get process bitness: 32bit - 4, 64bit - 8, 0 - unknown
int idaapi linuxbase_debmod_t::get_process_bitness(int _pid)
{
  char fname[QMAXPATH];
  qsnprintf(fname, sizeof(fname), "/proc/%u/maps", _pid);
  FILE *mapfp = fopenRT(fname);
  if ( mapfp == NULL )
    return 0;

  int bitness = 4;
  qstring line;
  while ( qgetline(&line, mapfp) >= 0 )
  {
    if ( line.empty() )
      continue;
    ea_t ea1;
    ea_t ea2;
    if ( qsscanf(line.begin(), "%a-%a ", &ea1, &ea2) == 2 )
    {
      size_t pos = line.find('-');
      if ( pos != qstring::npos && pos > 8 )
      {
        bitness = 8;
        break;
      }
    }
  }
  qfclose(mapfp);
  return bitness;
}

//--------------------------------------------------------------------------
int idaapi linuxbase_debmod_t::get_process_list(procvec_t *list, qstring *)
{
  int mypid = getpid();
  list->clear();
  qffblk64_t fb;
  for ( int code = qfindfirst("/proc/*", &fb, FA_DIREC);
        code == 0;
        code = qfindnext(&fb) )
  {
    if ( !qisdigit(fb.ff_name[0]) )
      continue;
    ext_process_info_t pinfo;
    pinfo.pid = atoi(fb.ff_name);
    if ( pinfo.pid == mypid )
      continue;
    char buf[MAXSTR];
    if ( !get_exec_fname(pinfo.pid, buf, sizeof(buf)) )
      continue; // we skip the process because we cannot debug it anyway
    pinfo.name = buf;
    pinfo.addrsize = get_process_bitness(pinfo.pid);
    build_process_ext_name(&pinfo);
    list->push_back(pinfo);
  }
  return list->size();
}
