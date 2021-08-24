#ifdef __NT__
#include <windows.h>
#endif
#include <pro.h>
#include <ua.hpp>
#include "pc_debmod.h"

//--------------------------------------------------------------------------
//lint -esym(1566,pc_debmod_t::hwbpt_ea,pc_debmod_t::hwbpt_type)
//lint -esym(1566,pc_debmod_t::dr6,pc_debmod_t::dr7)
pc_debmod_t::pc_debmod_t()
{
  static const uchar bpt[] = X86_BPT_CODE;
  bpt_code.append(bpt, sizeof(bpt));
  sp_idx = R_ESP;
  pc_idx = R_EIP;
  sr_idx = R_EFLAGS;
  fs_idx = R_FS;
  gs_idx = R_GS;
  cs_idx = R_CS;
  ds_idx = R_DS;
  es_idx = R_ES;
  ss_idx = R_SS;
  nregs = X86_NREGS;

  cleanup_hwbpts();
  set_platform(get_local_platform());
}

//--------------------------------------------------------------------------
int pc_debmod_t::get_regidx(const char *regname, int *clsmask)
{
  return x86_get_regidx(clsmask, regname);
}

//--------------------------------------------------------------------------
int idaapi pc_debmod_t::dbg_is_ok_bpt(bpttype_t type, ea_t ea, int /* len */)
{
  if ( type == BPT_SOFT )
    return BPT_OK;

  return find_hwbpt_slot(ea, type) == -1 ? BPT_TOO_MANY : BPT_OK;
}

//--------------------------------------------------------------------------
// returns -1 if something is wrong
int pc_debmod_t::find_hwbpt_slot(ea_t ea, bpttype_t type) const
{
  for ( int i=0; i < MAX_BPT; i++ )
  {
    if ( hwbpt_ea[i] == ea && hwbpt_type[i] == type ) // another breakpoint is here
      return -1;
    if ( hwbpt_ea[i] == BADADDR ) // empty slot found
      return i;
  }
  return -1;
}

//--------------------------------------------------------------------------
bool pc_debmod_t::add_hwbpt(bpttype_t type, ea_t ea, int len)
{
  int i = find_hwbpt_slot(ea, type);      // get slot number
  if ( i != -1 )
  {
    hwbpt_ea[i] = ea;
    hwbpt_type[i] = type;
    if ( type == BPT_EXEC )
      type = 0; // exec bpts are encoded with 0 on x86

    // length code used by the processor
    int lenc = (len == 2) ? 1
             : (len == 4) ? 3
             : (len == 8) ? 2
             :              0;

    dr7 |= (1 << (i*2));            // enable local breakpoint
    dr7 |= (type << (16+(i*4)));    // set breakpoint type
    dr7 |= (lenc << (18+(i*4)));    // set breakpoint length

    return refresh_hwbpts();
  }
  return false;
}

//--------------------------------------------------------------------------
bool pc_debmod_t::del_hwbpt(ea_t ea, bpttype_t type)
{
  for ( int i=0; i < MAX_BPT; i++ )
  {
    if ( hwbpt_ea[i] == ea && hwbpt_type[i] == type )
    {
      hwbpt_ea[i] = BADADDR;            // clean the address
      dr7 &= ~(3 << (i*2));             // clean the enable bits
      dr7 &= ~(0xF << (i*4+16));        // clean the length and type
      return refresh_hwbpts();
    }
  }
  return false;
}


#ifdef __NT__
//--------------------------------------------------------------------------
// Set hardware breakpoint for one thread
bool pc_debmod_t::set_hwbpts(HANDLE hThread)
{
  //  sure_suspend_thread(ti);
  CONTEXT Context;
  Context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;

  BOOL ok = GetThreadContext(hThread, &Context);
  if ( !ok )
  {
    deberr("GetThreadContext");
    return false;
  }
  Context.Dr0 = hwbpt_ea[0];
  Context.Dr1 = hwbpt_ea[1];
  Context.Dr2 = hwbpt_ea[2];
  Context.Dr3 = hwbpt_ea[3];
  Context.Dr6 = 0;
  Context.Dr7 = dr7;

  ok = SetThreadContext(hThread, &Context);
  if ( !ok )
  {
    deberr("SetThreadContext");
  }
  //  sure_resume_thread(ti);
  return ok != FALSE;
}

//--------------------------------------------------------------------------
ea_t pc_debmod_t::is_hwbpt_triggered(thid_t id, bool is_stepping)
{
  CONTEXT Context;
  Context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
  HANDLE h = get_thread_handle(id);
  if ( GetThreadContext(h, &Context) )
  {
    for ( int i=0; i < MAX_BPT; i++ )
    {
      if ( (Context.Dr7 & uint32(1 << (i*2)))
        && (Context.Dr6 & uint32(1 << i)) )  // Local hardware breakpoint 'i'
      {
        ULONG_PTR *dr = NULL;
        switch ( i )
        {
          case 0: dr = &Context.Dr0; break;
          case 1: dr = &Context.Dr1; break;
          case 2: dr = &Context.Dr2; break;
          case 3: dr = &Context.Dr3; break;
        }
        if ( dr == NULL )
          break;
        if ( hwbpt_ea[i] == *dr )
        {
          set_hwbpts(h);             // Clear the status bits
          // do not report exec breakpoint if it occurs while we are stepping
          if ( is_stepping && hwbpt_type[i] == BPT_EXEC )
            break;
          return hwbpt_ea[i];
        }
        //? TRACING                else
        //                  debdeb("System hardware breakpoint at %08X ???\n", *dr); //?
        // what to do ?:
        // reset it, and continue as if no event were received ?
        // send it to IDA, and let the user setup a "stop on non-debugger hardware breakpoint" option ?
      }
    }
  }
  return BADADDR;
}
#endif // ifdef __NT__

//--------------------------------------------------------------------------
void pc_debmod_t::cleanup_hwbpts()
{
  for ( int i=0; i < MAX_BPT; i++ )
  {
    hwbpt_ea[i] = BADADDR;
    hwbpt_type[i] = bpttype_t(0);
  }
  dr6 = 0;
  dr7 = 0x100; // exact local breakpoints
}

//--------------------------------------------------------------------------
ea_t pc_debmod_t::calc_appcall_stack(const regvals_t &regvals)
{
  ea_t ea = inherited::calc_appcall_stack(regvals);
#ifndef __X86__
  // do not touch the red zone (used by gcc)
  ea = ea > 128 ? ea - 128 : BADADDR;
#endif
  return ea;
}

//--------------------------------------------------------------------------
int pc_debmod_t::finalize_appcall_stack(
        call_context_t &,
        regval_map_t &,
        bytevec_t &stk)
{
  // pc-specific: add endless loop, so user does not execute unwanted code
  // after manual appcall. we do not really need to write bpt,
  // but it is easy to include it here than skip it.
  // previously we reserved 'addrsize' bytes on the stack for this purpose,
  // and we use 3 of them.
  static const uchar bpt_and_loop[] = { 0xCC, 0xEB, 0xFE };
  stk.append(bpt_and_loop, sizeof(bpt_and_loop));
  return 0;
}

//--------------------------------------------------------------------------
bool pc_debmod_t::should_stop_appcall(
        thid_t tid,
        const debug_event_t *event,
        ea_t ea)
{
  if ( inherited::should_stop_appcall(tid, event, ea) )
    return true;

  // Check if the current instruction is a "RET" and then dereferences
  // the contents of SP to find the return address. IF it matches, it is
  // time to stop
  regvals_t regs;
  regs.resize(X86_NREGS);
  do
  {
    // Start by reading registers
    if ( dbg_read_registers(tid, X86_RC_GENERAL, regs.begin(), NULL) != DRC_OK )
      break;

    // Get the opcodes
    uchar opcode;
    if ( dbg_read_memory((ea_t)regs[pc_idx].ival, &opcode, 1, NULL) != 1 )
      break;
    // Check for "RET" and "RET n"
    if ( opcode != 0xC3 && opcode != 0xC2 )
      break;

    // Dereference value at ESP
    ea_t at_sp = BADADDR;
    if ( dbg_read_memory((ea_t)regs[sp_idx].ival, &at_sp, sizeof(at_sp), NULL) != sizeof(at_sp) )
      break;
    return ea == at_sp; // time to stop!
  } while ( false );
  return false;
}

//--------------------------------------------------------------------------
bool pc_debmod_t::preprocess_appcall_cleanup(thid_t, call_context_t &ctx)
{
  // Linux 2.6.24-19 has a bug(?):
  // it doesn't clear trace flag after single-stepping
  // so if we single-step and then make an appcall, we would restore eflags with TF set
  // but next time we resume the program, kernel thinks that TF was set by the user
  // and doesn't clear it, and so our appcall stops immediately
  // to prevent that, we'll always clear trace flag before restoring eflags
  if ( ctx.saved_regs.size() > sr_idx )
    ctx.saved_regs[sr_idx].ival &= ~0x100;
  return true; // success
}

//--------------------------------------------------------------------------
void pc_debmod_t::read_fpu_registers(
        regval_t *values,
        int clsmask,
        const void *fptr,
        size_t step)
{
  const uchar *vptr = (const uchar *)fptr;
  for ( int i=0; i < 8; i++,vptr+=step )
  {
    if ( (clsmask & X86_RC_FPU) != 0 )
    {
      regval_t *v = &values[R_ST0+i];
      memcpy(&v->fval, vptr, 10);    //-V512 v->fval underflow
      v->rvtype = RVT_FLOAT;
    }
    if ( (clsmask & X86_RC_MMX) != 0 )
      values[R_MMX0+i].set_bytes(vptr, 8);
  }
}

//--------------------------------------------------------------------------
const char *pc_debmod_t::get_local_platform()
{
#ifdef __NT__
#  define LOCAL_PLATFORM  "win32"
#else
#  ifdef __MAC__
#    define LOCAL_PLATFORM  "macosx"
#  else
#    ifdef __LINUX__
#      define LOCAL_PLATFORM  "linux"
#    else
#      define LOCAL_PLATFORM  "PC_UNDEFINED"
#    endif
#  endif
#endif
  return LOCAL_PLATFORM;
}
