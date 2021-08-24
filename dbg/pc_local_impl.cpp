// x86-specific code (compiled only on IDA side, never on the server side)

#include <dbg.hpp>
#include "pc_regs.hpp"
#include "deb_pc.hpp"

//--------------------------------------------------------------------------
//
//      DEBUGGER REGISTER AND INSTRUCTION INFORMATIONS
//
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
#if 0
static void DEBUG_REGVALS(regval_t *values)
{
  for ( int i = 0; i < qnumber(registers); i++ )
  {
    msg("%s = ", registers[i].name);
    switch ( registers[i].dtyp )
    {
      case dt_qword: msg("%016LX\n", values[i].ival); break;
      case dt_dword: msg("%08X\n", values[i].ival); break;
      case dt_word:  msg("%04X\n", values[i].ival); break;
      case dt_tbyte:
        for ( int j = 0; j < sizeof(regval_t); j++ )
        {
          if ( j == 10 )
            msg(" - "); // higher bytes are not used by x86 floats
          msg("%02X ", ((unsigned char*)&values[i])[j]);
        }
          // msg("%02X ", (unsigned short)values[i].fval[j]);
        msg("\n");
        break;
    }
  }
  msg("\n");
}
#endif

//--------------------------------------------------------------------------
drc_t idaapi x86_read_registers(
        thid_t thread_id,
        int clsmask,
        regval_t *values,
        qstring *errbuf)
{
  drc_t drc = s_read_registers(thread_id, clsmask, values, errbuf);
  if ( drc == DRC_OK )
  {
    // FPU related registers
    if ( (clsmask & X86_RC_FPU) != 0 )
    {
      for ( size_t i = 0; i < debugger.nregs; i++ )
      {
        const register_info_t &ri = debugger.regs(i);
        if ( ri.register_class == X86_RC_FPU && ri.dtype == dt_tbyte )
        {
          int rc = processor_t::realcvt(&values[i].fval, &values[i].fval, 004); // load long double
          if ( rc == 0 )
            break;                 // realcvt not implemented
          else if ( rc < 0 )       // error
            values[i].fval.clear();
        }
      }
    }
  }
  return drc;
}

//--------------------------------------------------------------------------
drc_t idaapi x86_write_register(
        thid_t thread_id,
        int reg_idx,
        const regval_t *value,
        qstring *errbuf)
{
  regval_t rv = *value;
  // FPU related registers
  const register_info_t &ri = debugger.regs(reg_idx);
  if ( ri.register_class == X86_RC_FPU && ri.dtype == dt_tbyte )
  {
    uchar fn[10];
    int code = processor_t::realcvt(fn, &rv.fval, 014); // store long double    //-V536 octal
    if ( code == REAL_ERROR_FPOVER )
      memcpy(&rv.fval, fn, 10);    //-V512 rv.fval underflow
  }
  return s_write_register(thread_id, reg_idx, &rv, errbuf);
}

//--------------------------------------------------------------------------
int is_x86_valid_bpt(bpttype_t type, ea_t ea, int len)
{
  if ( type != BPT_SOFT )
  {
    if ( (debugger.flags & DBG_FLAG_ANYSIZE_HWBPT) == 0 )
      return check_x86_hwbpt(type, ea, len);

    if ( type == 0 )
      return BPT_BAD_TYPE;
  }
  return BPT_OK;
}

//--------------------------------------------------------------------------
void processor_specific_init(void)
{
}

//--------------------------------------------------------------------------
void processor_specific_term(void)
{
}
