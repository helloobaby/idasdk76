#ifndef __WINDMP_COMMON__
#define __WINDMP_COMMON__

#include <pro.h>
#include <diskio.hpp>
#include <range.hpp>

#include "dbgeng.h"

//--------------------------------------------------------------------------
struct dbgeng_dll_t
{
  dbgeng_dll_t()
    : pDebugCreate(NULL),
      pDebugConnect(NULL),
      dbgeng_hmod(NULL),
      dbghlp_hmod(NULL)
  {
  }

  // Debug Engine dll
  typedef HRESULT (STDAPICALLTYPE *pDebugCreate_t)(REFIID InterfaceId, PVOID *Interface);
  typedef HRESULT (STDAPICALLTYPE *pDebugConnect_t)(PCSTR RemoteOptions, REFIID InterfaceId, PVOID *Interface);

  // Debug engine session creation functions
  // (They are dynamically resolved)
  pDebugCreate_t pDebugCreate;
  pDebugConnect_t pDebugConnect;

  HMODULE dbgeng_hmod;
  HMODULE dbghlp_hmod;

  bool load(HRESULT *last_hr, const char *dbgtools_path);
  void unload();
};

//--------------------------------------------------------------------------
// The following flags are set by the loader and are used to notify
// the debugger module about the following:

// This file has been created by the loader and thus debug names
// are not present and should always be computed. If not set, then
// this means the database was created from the DMP file and have all the
// names prepopulated.
#define WDOPT_DBGMODE  0x1

// Do one time only post-loader initialziation
#define WDOPT_POSTLDR  0x2

//--------------------------------------------------------------------------
int get_windmp_ldr_options();
void set_windmp_ldr_options(int opt);
void prepare_symbol_name(qstring &name, size_t *mod_sep_pos);
bool was_input_crash_dump(qstring *fn = NULL);
void get_filename_no_ext(const char *path, qstring *name);
bool detect_dbgtools_path(char *path, size_t path_size);
bool pc_get_dbgtools_path(char *path, size_t path_size);
bool is_crash_dump_file(linput_t *li);
bool is_crash_dump_file(const char *filename);
void get_def_sympath(char *path, size_t sz);
bool is_sympath_set();
bool is_crash_dump_loader();

struct IDebugDataSpaces4;
struct IDebugControl4;
void ldr_init_crashdump(IDebugControl4 *dbg_control);
HRESULT read_process_memory(
        IDebugDataSpaces4 *space,
        const rangevec_t *inited_ranges,
        IN ULONG64 Offset,
        OUT PVOID Buffer,
        IN ULONG BufferSize,
        OUT OPTIONAL PULONG BytesRead);

bool get_minidump_mslist(
        HMODULE dbghlp_hmod,
        const char *dmpfile,
        rangevec_t *mslist);

#endif
