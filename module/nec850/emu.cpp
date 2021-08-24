/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Processor emulator
 *
 */
#include <ida.hpp>
#include <auto.hpp>
#include <frame.hpp>
#include <jumptable.hpp>
#include "ins.hpp"
#include "necv850.hpp"

//----------------------------------------------------------------------
//#notify.is_sane_insn
// is the instruction sane for the current file type?
// arg:  int no_crefs
// 1: the instruction has no code refs to it.
//    ida just tries to convert unexplored bytes
//    to an instruction (but there is no other
//    reason to convert them into an instruction)
// 0: the instruction is created because
//    of some coderef, user request or another
//    weighty reason.
// The instruction is in 'cmd'
// returns: 1-ok, <=0-no, the instruction isn't likely to appear in the program
int nec850_t::nec850_is_sane_insn(const insn_t &insn, int /*no_crefs*/) const
{
#define CHECK_R0_WRITE(n)             \
  if ( ((Feature & CF_CHG ## n) != 0) \
    && insn.Op ## n.is_reg(rZERO) )   \
  {                                   \
    return 0;                         \
  }
  int Feature = insn.get_canon_feature(ph);

  CHECK_R0_WRITE(1);
  CHECK_R0_WRITE(2);
  return 1;
}

//----------------------------------------------------------------------
int idaapi nec850_is_sp_based(const insn_t &insn, const op_t &x)
{
  int res = OP_SP_ADD;
  if ( x.type == o_displ && x.reg == rSP )
    return res | OP_SP_BASED;

  // check for movea   8, sp, r28
  if ( insn.itype == NEC850_MOVEA && insn.Op2.is_reg(rSP) && x.type == o_imm )
    return res | OP_SP_BASED;

  return res | OP_FP_BASED;
}

//----------------------------------------------------------------------
bool idaapi nec850_create_func_frame(func_t *pfn)
{
  asize_t frsize;

  insn_t insn;
  if ( decode_insn(&insn, pfn->start_ea) != 0
    && (insn.itype == NEC850_PREPARE_i || insn.itype == NEC850_PREPARE_sp) )
  {
    frsize = insn.Op2.value * 4;
  }
  else
  {
    frsize = 0;
  }
  return add_frame(pfn, frsize, 0, 0);
}

//----------------------------------------------------------------------
int idaapi nec850_get_frame_retsize(const func_t * /*pfn*/)
{
  return 0;
}

//----------------------------------------------------------------------
static bool spoils(const insn_t &insn, uint16 reg)
{
  int n;
  switch ( insn.itype )
  {
    case NEC850_ZXB:
    case NEC850_SXB:
    case NEC850_ZXH:
    case NEC850_SXH:
      n = 0;
      break;

    case NEC850_XOR:
    case NEC850_SUBR:
    case NEC850_SUB:
    case NEC850_STSR:
    case NEC850_SLD_B:
    case NEC850_SLD_H:
    case NEC850_SLD_W:
    case NEC850_SHR:
    case NEC850_SHL:
    case NEC850_SATSUBR:
    case NEC850_SATSUB:
    case NEC850_SATADD:
    case NEC850_SAR:
    case NEC850_OR:
    case NEC850_NOT:
    case NEC850_MULH:
    case NEC850_MOV:
    case NEC850_LD_B:
    case NEC850_LD_H:
    case NEC850_LD_W:
    case NEC850_JARL:
    case NEC850_AND:
    case NEC850_ADD:
    case NEC850_DIVH:
    case NEC850_BSW:
    case NEC850_BSH:
    case NEC850_HSW:
    case NEC850_SLD_BU:
    case NEC850_SLD_HU:
    case NEC850_LD_BU:
    case NEC850_LD_HU:
      n = 1;
      break;

    case NEC850_XORI:
    case NEC850_SATSUBI:
    case NEC850_ORI:
    case NEC850_MULHI:
    case NEC850_MOVHI:
    case NEC850_MOVEA:
    case NEC850_ANDI:
    case NEC850_ADDI:
    case NEC850_SETF:
    case NEC850_SASF:
      n = 2;
      break;

    case NEC850_CMOV:
      n = 4;
      break;

    case NEC850_MUL:
    case NEC850_MULU:
    case NEC850_DIVH_r3:
    case NEC850_DIVHU:
    case NEC850_DIV:
    case NEC850_DIVU:
      return insn.ops[1].is_reg(reg) || insn.ops[2].is_reg(reg);

    case NEC850_DISPOSE_r0:
    case NEC850_DISPOSE_r:
      return reg == rSP || reg_in_list12(reg, insn.Op2.value);

    case NEC850_PREPARE_sp:
      return reg == rSP;

    case NEC850_PREPARE_i:
      return reg == rSP || reg == rEP;

    default:
      return false;
  }
  return insn.ops[n].is_reg(reg);
}

//----------------------------------------------------------------------
// does the instruction spoil the flags?
static bool spoils_flags(const insn_t &insn)
{
  switch ( insn.itype )
  {
    case NEC850_ADD:
    case NEC850_ADDI:
    case NEC850_ADF:
    case NEC850_AND:
    case NEC850_ANDI:
    case NEC850_BSH:
    case NEC850_BSW:
    case NEC850_CAXI:
    case NEC850_CLR1:
    case NEC850_CMP:
    case NEC850_CTRET:
    case NEC850_DIV:
    case NEC850_DIVH:
    case NEC850_DIVHU:
    case NEC850_DIVH_r3:
    case NEC850_DIVQ:
    case NEC850_DIVQU:
    case NEC850_DIVU:
    case NEC850_EIRET:
    case NEC850_FERET:
    case NEC850_HSH:
    case NEC850_HSW:
    case NEC850_NOT:
    case NEC850_NOT1:
    case NEC850_OR:
    case NEC850_ORI:
    case NEC850_RETI:
    case NEC850_SAR:
    case NEC850_SATADD:
    case NEC850_SATSUB:
    case NEC850_SATSUBI:
    case NEC850_SATSUBR:
    case NEC850_SBF:
    case NEC850_SCH0L:
    case NEC850_SCH0R:
    case NEC850_SCH1L:
    case NEC850_SCH1R:
    case NEC850_SET1:
    case NEC850_SHL:
    case NEC850_SHR:
    case NEC850_SUB:
    case NEC850_SUBR:
    case NEC850_TST:
    case NEC850_TST1:
    case NEC850_XOR:
    case NEC850_XORI:

    case NEC850_BINS:
    case NEC850_ROTL:
      return true;

    default:
      // other insns don't spoil fixed point flags
      return false;
  }
}

//----------------------------------------------------------------------
bool nec850_t::get_gp_based_addr(ea_t *target, const insn_t &_insn, const op_t &op) const
{
  if ( g_gp_ea == BADADDR )
    return false;
  if ( op.phrase == rGP )
  {
    *target = g_gp_ea;
    return true;
  }
  uint16 op_phrase = op.phrase;
  *target = BADADDR;
  insn_t tmp = _insn;
  while ( true )
  {
    flags_t F = get_flags(tmp.ea);
    if ( !is_flow(F) || has_xref(F) )
      break;
    if ( decode_prev_insn(&tmp, tmp.ea) == BADADDR )
      break;

    if ( tmp.itype == NEC850_MOVEA
      && tmp.Op2.reg == rGP
      && tmp.Op3.reg == op_phrase )
    {
      *target = g_gp_ea + tmp.Op1.value;
      break;
    }

    if ( spoils(tmp, op_phrase) )
      break;
  }
  return *target != BADADDR;
}

//----------------------------------------------------------------------
void nec850_t::handle_operand(const insn_t &insn, const op_t &op, bool isRead)
{
  ea_t ea;
  flags_t F = get_flags(insn.ea);
  switch ( op.type )
  {
    case o_imm:
      if ( op_adds_xrefs(F, op.n) )
        insn.add_off_drefs(op, dr_O, 0);
      break;

    case o_displ:
      set_immd(insn.ea);
      if ( !is_defarg(F, op.n) )
      {
        if ( may_create_stkvars() && op.reg == rSP )
        {
          func_t *pfn = get_func(insn.ea);
          if ( pfn != NULL && insn.create_stkvar(op, op.addr, STKVAR_VALID_SIZE) )
            op_stkvar(insn.ea, op.n);
        }
        else if ( get_gp_based_addr(&ea, insn, op) )
        {
          refinfo_t ri;
          ri.flags = REF_OFF32|REFINFO_PASTEND|REFINFO_NOBASE|REFINFO_SIGNEDOP;
          ri.target = BADADDR;
          ri.base = ea;
          ri.tdelta = 0;
          op_offset_ex(insn.ea, op.n, &ri);
          F = get_flags(insn.ea);
        }
      }

      if ( op_adds_xrefs(F, op.n) )
      { // create data xrefs
        ea_t base_ea;
        if ( get_gp_based_addr(&base_ea, insn, op) )
        {
          ea = base_ea + op.addr;
          insn.add_dref(ea, op.offb, isRead ? dr_R : dr_W);
        }
        else
        {
          int outf = get_displ_outf(insn, op, F);
          ea = insn.add_off_drefs(op, isRead ? dr_R : dr_W, outf);
        }
        if ( ea != BADADDR )
          insn.create_op_data(ea, op);
      }
      break;

    case o_near:
      {
        bool iscall = has_insn_feature(insn.itype, CF_CALL);

        ea_t dest = to_ea(insn.cs, op.addr);
        if ( dest == insn.ea + insn.size )
        {
          // PIC pattern:
          //    jarl nextaddr, r29
          // nextaddr:
          iscall = false;
        }
        insn.add_cref(dest, op.offb, iscall ? fl_CN : fl_JN);
        if ( flow && iscall )
        {
          if ( !func_does_return(dest) )
            flow = false;
        }
      }
      break;

    case o_mem:
      {
        ea = to_ea(insn.cs, op.addr);
        insn.create_op_data(ea, op);
        insn.add_dref(op.addr, op.offb, isRead ? dr_R : dr_W);
      }
      break;
  }
}

//----------------------------------------------------------------------
static void idaapi trace_stack(func_t *pfn, const insn_t &insn)
{
  sval_t delta;
  switch ( insn.itype )
  {
    case NEC850_PREPARE_i:
    case NEC850_PREPARE_sp:
      {
        delta = -((bitcount(insn.Op1.value) * 4) + (insn.Op2.value << 2));

        // PATTERN #1
        /*
        00000030     _func3:
        00000030 000                 br      loc_5E
        00000032
        00000032     loc_32:                                 -- CODE XREF: _func3+32j
        00000032 000                 st.w    r6, 4[sp]
        0000005A
        0000005A     loc_5A:                                 -- CODE XREF: _func3+10j
        0000005A                                             -- _func3+14j ...
        0000005A 000                 dispose 2, {lp}, [lp]
        0000005E     -- ---------------------------------------------------------------------------
        0000005E
        0000005E     loc_5E:                                 -- CODE XREF: _func3
        0000005E -0C                 prepare {lp}, 2
        00000062 000                 br      loc_32
        00000062     -- End of function _func3
        */
        bool farref;
        insn_t tmp;
        if ( decode_preceding_insn(&tmp, insn.ea, &farref) != BADADDR
          && (tmp.itype == NEC850_BR || tmp.itype == NEC850_JR)
          && tmp.Op1.addr == insn.ea
          && func_contains(pfn, tmp.ea) )
        {
          add_auto_stkpnt(pfn, tmp.ea + tmp.size, delta);
        }
      }
      break;
    case NEC850_DISPOSE_r:
    case NEC850_DISPOSE_r0:
      // count registers in LIST12 and use the imm5 for local vars
      delta = (bitcount(insn.Op2.value) * 4) + (insn.Op1.value << 2);
      break;
    case NEC850_ADD:
    case NEC850_ADDI:
    case NEC850_MOVEA:
      delta = insn.Op1.value;
      break;
    default:
      return;
  }
  add_auto_stkpnt(pfn, insn.ea + insn.size, delta);
}

//----------------------------------------------------------------------
// pattern:
//   mov #address, lp
//   jmp [reg1]
// address:
//   flow to the next instruction
static bool indirect_function_call(const insn_t &_insn)
{
  if ( _insn.itype != NEC850_JMP || _insn.Op1.is_reg(rLP) )
    return false;

  insn_t insn = _insn;
  ea_t ret_addr = insn.ea + insn.size;   // after the jmp

  bool flows = false;
  while ( decode_prev_insn(&insn, insn.ea) != BADADDR )
  {
    if ( insn.itype == NEC850_MOV
      && insn.Op1.type == o_imm
      && insn.Op1.dtype == dt_dword
      && insn.Op2.is_reg(rLP) )
    { // MOV #address, lp
      op_offset(insn.ea, 0, REF_OFF32);
      if ( insn.Op1.value == ret_addr )
      { // normal return, after the jmp instruction
        flows = true;
      }
      else
      { // add xref to return address
        add_cref(_insn.ea, insn.Op1.value, fl_JN);
      }
      break;
    }

    if ( spoils(insn, rLP) )
      break;

    flags_t F = get_flags(insn.ea);
    if ( !is_flow(F) || has_xref(F) )
      break;
  }
  return flows;
}

//----------------------------------------------------------------------
int nec850_t::nec850_emu(const insn_t &insn)
{
  int aux = insn.auxpref;

  int Feature = insn.get_canon_feature(ph);
  flow = (Feature & CF_STOP) == 0;

  if ( Feature & CF_USE1 )
    handle_operand(insn, insn.Op1, true);
  if ( Feature & CF_CHG1 )
    handle_operand(insn, insn.Op1, false);
  if ( Feature & CF_USE2 )
    handle_operand(insn, insn.Op2, true);
  if ( Feature & CF_CHG2 )
    handle_operand(insn, insn.Op2, false);
  if ( Feature & CF_USE3 )
    handle_operand(insn, insn.Op3, true);
  if ( Feature & CF_CHG3 )
    handle_operand(insn, insn.Op3, false);

  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  flags_t F = get_flags(insn.ea);
  if ( insn.itype == NEC850_MOVEA
    && insn.Op1.type == o_imm
    && !is_defarg(F, insn.Op1.n) )
  {
    // movea imm16, sp, reg (reg != sp)
    if ( insn.Op2.is_reg(rSP)
      && !insn.Op3.is_reg(rSP)
      && may_create_stkvars()
      && insn.create_stkvar(insn.Op1, insn.Op1.value, 0) )
    {
      op_stkvar(insn.ea, insn.Op1.n);
    }
    else if ( insn.Op2.is_reg(rGP)
           && g_gp_ea != BADADDR )
    {
      ea_t ea = g_gp_ea + insn.Op1.value;

      refinfo_t ri;
      ri.flags = REF_OFF32|REFINFO_PASTEND|REFINFO_SIGNEDOP|REFINFO_NOBASE;
      ri.target = BADADDR;
      ri.base = g_gp_ea;
      ri.tdelta = 0;
      op_offset_ex(insn.ea, insn.Op1.n, &ri);
      F = get_flags(insn.ea);
      if ( op_adds_xrefs(F, insn.Op1.n) )
        insn.add_dref(ea, insn.Op1.offb, dr_O);
    }
  }

  // add dref to callt table entry address
  if ( insn.itype == NEC850_CALLT
    && g_ctbp_ea != BADADDR )
  {
    ea_t ea = g_ctbp_ea + (insn.Op1.value << 1);
    insn.create_op_data(ea, insn.Op1.offb, dt_word);
    insn.add_dref(ea, insn.Op1.offb, dr_R);
  }

  if ( indirect_function_call(insn) )
    flow = true;

  if ( (aux & N850F_SP) && may_trace_sp() )
  {
    func_t *pfn = get_func(insn.ea);
    if ( pfn != NULL )
      trace_stack(pfn, insn);
  }

  // add flow
  if ( flow )
    add_cref(insn.ea, insn.ea + insn.size, fl_F);

  return 1;
}

//----------------------------------------------------------------------
int nec850_may_be_func(const insn_t &insn)
{
  int prop = 0;
  if ( insn.itype == NEC850_PREPARE_i || insn.itype == NEC850_PREPARE_sp )
    prop = 100;
  return prop;
}

//----------------------------------------------------------------------
inline bool is_ret_itype(const insn_t &insn)
{
  return insn.itype == NEC850_RETI
      || insn.itype == NEC850_DBRET
      || insn.itype == NEC850_CTRET
      || insn.itype == NEC850_DISPOSE_r
      || insn.itype == NEC850_JMP && insn.Op1.is_reg(rLP);
}

//----------------------------------------------------------------------
bool nec850_is_return(const insn_t &insn, bool strict)
{
  if ( is_ret_itype(insn) )
    return true;
  if ( insn.itype == NEC850_DISPOSE_r0 )
    return !strict;
  return false;
}

//-------------------------------------------------------------------------
static bool find_set(
        ea_t *value,
        ea_t *valea,
        insn_t insn,  // make a copy
        int reg)
{
  simple_bfi_t bfi(insn.ea);
  while ( true )
  {
    cref_t prev_insn_ref = bfi.prev_insn();
    if ( prev_insn_ref == fl_U || decode_insn(&insn, bfi.cur_ea) <= 0 )
      break;
    switch ( insn.itype )
    {
      case NEC850_MOV:
        if ( insn.Op2.is_reg(reg) && insn.Op1.type == o_reg )
        {
          reg = insn.Op1.reg;
          continue;
        }
        if ( insn.Op2.is_reg(reg) && insn.Op1.type == o_imm )
        {
          *value = insn.Op1.value;
          *valea = insn.ea;
          return true;
        }
        break;
      case NEC850_ADDI:
      case NEC850_MOVEA:
        if ( insn.Op3.is_reg(reg)
          && insn.Op1.type == o_imm
          && insn.Op2.is_reg(rZERO) )
        {
          *value = insn.Op1.value;
          *valea = insn.ea;
          return true;
        }
        break;
    }
    if ( spoils(insn, reg) )
      break;
  }
  return false;
}

//-------------------------------------------------------------------------
struct nec850_jump_pattern_t : public jump_pattern_t
{
protected:
  enum { rA, rC };

  nec850_jump_pattern_t(switch_info_t *_si, const char (*_depends)[4])
    : jump_pattern_t(_si, _depends, rC)
  {
    modifying_r32_spoils_r64 = false;
    non_spoiled_reg = rA;
  }

public:
  virtual bool handle_mov(tracked_regs_t &_regs) override;
  virtual void check_spoiled(tracked_regs_t *_regs) const override;

protected:
  // movea  -minv, rA', rA  | add -minv, rA
  bool jpi_sub_lowcase();
  // cmp followed by the conditional jump
  // it calls jpi_condjump() and jpi_cmp_ncases() that can be redefined in
  // the derived class.
  bool jpi_cmp_ncases_condjump();
  // switch rA
  bool jpi_jump();

  // bh default
  virtual bool jpi_condjump() newapi;
  // cmp ncases, rA
  virtual bool jpi_cmp_ncases() newapi;
};

//-------------------------------------------------------------------------
bool nec850_jump_pattern_t::handle_mov(tracked_regs_t &_regs)
{
  if ( insn.itype != NEC850_MOV
    && insn.Op1.type != o_reg
    && insn.Op2.type != o_reg )
  {
    return false;
  }
  return set_moved(insn.Op2, insn.Op1, _regs);
}

//-------------------------------------------------------------------------
#define PROC_MAXCHGOP 3
void nec850_jump_pattern_t::check_spoiled(tracked_regs_t *__regs) const
{
  tracked_regs_t &_regs = *__regs;
  for ( uint i = 0; i < _regs.size(); ++i )
  {
    const op_t &x = _regs[i];
    if ( x.type == o_reg && spoils(insn, x.reg)
      || x.type == o_condjump && spoils_flags(insn) )
    {
      set_spoiled(&_regs, x);
    }
  }
  check_spoiled_not_reg(&_regs, PROC_MAXCHGOP);
}

//----------------------------------------------------------------------
// movea  -minv, rA', rA  | add -minv, rA
bool nec850_jump_pattern_t::jpi_sub_lowcase()
{
  if ( insn.itype == NEC850_MOVEA )
  {
    if ( insn.Op1.type != o_imm
      || insn.Op2.type != o_reg
      || !is_equal(insn.Op3, rA) )
    {
      return false;
    }
    trackop(insn.Op2, rA);
  }
  else if ( insn.itype == NEC850_ADD )
  {
    if ( insn.Op1.type != o_imm || !is_equal(insn.Op2, rA) )
      return false;
  }
  else
  {
    return false;
  }
  si->lowcase = uval_t(-uint32(insn.Op1.value));
  return true;
}

//-------------------------------------------------------------------------
// cmp followed by the conditional jump
bool nec850_jump_pattern_t::jpi_cmp_ncases_condjump(void)
{
  // var should not be spoiled
  QASSERT(10317, !is_spoiled(rA));

  if ( jpi_condjump() // continue matching if found
    || is_spoiled(rC)
    || !jpi_cmp_ncases() )
  {
    return false;
  }

  op_t &op = regs[rC];
  // assert: op.type == o_condjump
  if ( (op.value & cc_inc_ncases) != 0 )
    ++si->ncases;
  si->defjump = op.specval;
  si->set_expr(insn.Op1.reg, insn.Op1.dtype);
  return true;
}

//----------------------------------------------------------------------
// switch rA
bool nec850_jump_pattern_t::jpi_jump()
{
  if ( insn.itype != NEC850_SWITCH
    || insn.Op1.type != o_reg
    || insn.Op1.reg == rZERO )
  {
    return false;
  }

  si->jumps = insn.ea + insn.size;
  si->set_elbase(si->jumps);
  si->flags |= SWI_SIGNED;
  si->set_jtable_element_size(2);
  si->set_shift(1);
  si->set_expr(insn.Op1.reg, dt_dword);
  trackop(insn.Op1, rA);
  return true;
}

//----------------------------------------------------------------------
// bh default
bool nec850_jump_pattern_t::jpi_condjump()
{
  op_t op;
  op.type = o_condjump;
  op.value = 0;
  switch ( insn.itype )
  {
    case NEC850_BH:   // higher
    case NEC850_BNH:  // not higher
      op.value |= cc_inc_ncases;
      break;
    case NEC850_BL:   // lower
    case NEC850_BNC:  // no carry (not lower)
      break;
    default:
      return false;
  }
  ea_t jump = to_ea(insn.cs, insn.Op1.addr);
  switch ( insn.itype )
  {
    case NEC850_BH:
    case NEC850_BNC:
      op.specval = jump;
      break;
    case NEC850_BL:
    case NEC850_BNH:
      // we have conditional jump to the switch body
      // assert: eas[0] != BADADDR
      if ( jump > eas[0] )
        return false;
      op.specval = insn.ea + insn.size;

      // possibly followed by 'jr default'
      {
        insn_t deflt;
        if ( decode_insn(&deflt, op.specval) > 0
          && deflt.itype == NEC850_JR
          && deflt.Op1.type == o_near )
        {
          op.specval = deflt.Op1.addr;
        }
      }
      break;
    default:
      return false;
  }
  op.addr = insn.ea;
  trackop(op, rC);
  return true;
}

//----------------------------------------------------------------------
// cmp ncases, rA
bool nec850_jump_pattern_t::jpi_cmp_ncases()
{
  if ( insn.itype != NEC850_CMP
    || insn.Op1.type != o_imm && insn.Op1.type != o_reg
    || !same_value(insn.Op2, rA) )
  {
    return false;
  }

  const op_t &x = insn.Op1;
  uval_t val;
  ea_t dummy;
  if ( x.type == o_imm )
    val = x.value;
  // assert: x.type == o_reg
  else if ( !find_set(&val, &dummy, insn, x.reg) )
    return false;
  si->ncases = ushort(val);
  return true;
}

//----------------------------------------------------------------------
// jump pattern #1
// 2 movea  -minv, rA', rA  | add -minv, rA (optional)
// 1 cmp    ncases, rA      | cmp rNcases, rA
//   bh     default           (nearest to "cmp")
// 0 switch  rA
// 0 -> 1 -> 2

static const char nec850_depends1[][4] =
{
  { 1 },                      // 0
  { 2 | JPT_OPT | JPT_NEAR }, // 1
  { 0 },                      // 2 optional, near
};

//-------------------------------------------------------------------------
class nec850_jump_pattern1_t : public nec850_jump_pattern_t
{
public:
  nec850_jump_pattern1_t(switch_info_t *_si)
    : nec850_jump_pattern_t(_si, nec850_depends1) {}

  virtual bool jpi2(void) override { return jpi_sub_lowcase(); }
  virtual bool jpi1(void) override { return jpi_cmp_ncases_condjump(); }
  virtual bool jpi0(void) override { return jpi_jump(); }
};

//----------------------------------------------------------------------
static int is_jump_pattern1(switch_info_t *si, const insn_t &insn, procmod_t *)
{
  nec850_jump_pattern1_t jp(si);
  if ( !jp.match(insn) )
    return JT_NONE;
  return JT_SWITCH;
}

//----------------------------------------------------------------------
// jump pattern #2 (addi instead of cmp)
// 2 movea  -minv, rA', rA  | add -minv, rA (optional)
// 1 addi   -ncases, rA, r0
//   bl     default           (nearest to "cmp")
// 0 switch  rA
// 0 -> 1 -> 2

static const char nec850_depends2[][4] =
{
  { 1 },                      // 0
  { 2 | JPT_OPT | JPT_NEAR }, // 1
  { 0 },                      // 2 optional, near
};

//-------------------------------------------------------------------------
class nec850_jump_pattern2_t : public nec850_jump_pattern_t
{
public:
  nec850_jump_pattern2_t(switch_info_t *_si)
    : nec850_jump_pattern_t(_si, nec850_depends2) {}

  bool jpi2(void) override { return jpi_sub_lowcase(); }
  bool jpi1(void) override { return jpi_cmp_ncases_condjump(); }
  bool jpi0(void) override { return jpi_jump(); }

protected:
  // bl default
  bool jpi_condjump() override;
  // addi -ncases, rA, r0
  bool jpi_cmp_ncases() override;
};

//----------------------------------------------------------------------
// bl default
bool nec850_jump_pattern2_t::jpi_condjump()
{
  op_t op;
  op.type = o_condjump;
  op.value = 0;
  switch ( insn.itype )
  {
    case NEC850_BH:   // higher
      op.value |= cc_inc_ncases;
      break;
    case NEC850_BL:   // lower
      break;
    default:
      return false;
  }
  ea_t jump = to_ea(insn.cs, insn.Op1.addr);
  switch ( insn.itype )
  {
    case NEC850_BL:
      op.specval = jump;
      break;
    case NEC850_BH:
      // we have conditional jump to the switch body
      // assert: eas[0] != BADADDR
      if ( jump > eas[0] )
        return false;
      op.specval = insn.ea + insn.size;
      break;
    default:
      return false;
  }
  op.addr = insn.ea;
  trackop(op, rC);
  return true;
}

//----------------------------------------------------------------------
// addi -ncases, rA, r0
bool nec850_jump_pattern2_t::jpi_cmp_ncases()
{
  if ( insn.itype != NEC850_ADDI
    || insn.Op1.type != o_imm
    || !insn.Op3.is_reg(rZERO)
    || !same_value(insn.Op2, rA) )
  {
    return false;
  }

  si->ncases = ushort(-uint32(insn.Op1.value));
  return true;
}

//----------------------------------------------------------------------
static int is_jump_pattern2(switch_info_t *si, const insn_t &insn, procmod_t *)
{
  nec850_jump_pattern2_t jp(si);
  if ( !jp.match(insn) )
    return JT_NONE;
  return JT_SWITCH;
}

//----------------------------------------------------------------------
// jump pattern #3 (without 'switch' insn)
// 3 movea -minv, rA', rA     | add -minv, rA (optional)
// 2 cmp   ncases, rA         | cmp rNcases, rA
//   bh    default              (nearest to "cmp")
// 1 shl   2, rA              | shl 1, rA
// 0 jmp   jumps[rA]
//
// jumps:  jr case0 (4 bytes) | (2 bytes)
//         jr case1
//         ...
//
// 0 -> 1 -> 2 -> 3

static const char nec850_depends3[][4] =
{
  { 1 },                      // 0
  { 2 },                      // 1
  { 3 | JPT_OPT | JPT_NEAR }, // 2
  { 0 },                      // 3 optional, near
};

//-------------------------------------------------------------------------
class nec850_jump_pattern3_t : public nec850_jump_pattern_t
{
public:
  nec850_jump_pattern3_t(switch_info_t *_si)
    : nec850_jump_pattern_t(_si, nec850_depends3)
  {
    si->flags |= SWI_JMPINSN;
  }

  virtual bool jpi3(void) override { return jpi_sub_lowcase(); }
  virtual bool jpi2(void) override { return jpi_cmp_ncases_condjump(); }
  virtual bool jpi1(void) override; // shl shift, rA
  virtual bool jpi0(void) override; // jmp jumps[rA]
};

//----------------------------------------------------------------------
// shl shift, rA
bool nec850_jump_pattern3_t::jpi1()
{
  if ( insn.itype != NEC850_SHL
    || insn.Op1.type != o_imm
    || !same_value(insn.Op2, rA) )
  {
    return false;
  }
  int elsize;
  if ( insn.Op1.value == 1 )
    elsize = 2;
  else if ( insn.Op1.value == 2 )
    elsize = 4;
  else
    return false;
  si->set_jtable_element_size(elsize);
  return true;
}

//----------------------------------------------------------------------
// jmp jumps[rA]
bool nec850_jump_pattern3_t::jpi0()
{
  if ( insn.itype != NEC850_JMP || insn.Op1.type != o_displ )
    return false;
  si->jumps = insn.Op1.addr;
  track(insn.Op1.phrase, rA, dt_dword);
  return true;
}

//----------------------------------------------------------------------
static int is_jump_pattern3(switch_info_t *si, const insn_t &insn, procmod_t *)
{
  nec850_jump_pattern3_t jp(si);
  if ( !jp.match(insn) )
    return JT_NONE;
  op_offset(jp.eas[0], 0, REFINFO_NOBASE | REF_OFF32);
  // rollback data created in handle_operand()
  del_items(si->jumps, DELIT_SIMPLE);
  return JT_SWITCH;
}

//----------------------------------------------------------------------
bool idaapi nec850_is_switch(switch_info_t *si, const insn_t &insn)
{
  if ( insn.itype != NEC850_SWITCH && insn.itype != NEC850_JMP )
    return false;

  static is_pattern_t *const patterns[] =
  {
    is_jump_pattern1,
    is_jump_pattern2,
    is_jump_pattern3,
  };
  return check_for_table_jump(si, insn, patterns, qnumber(patterns));
}

//-------------------------------------------------------------------------
sval_t nec850_t::regval(
        const op_t &op,
        getreg_t *getreg,
        const regval_t *rv) const
{
  if ( op.reg > rSR31 )
  {
    warning("Bad register number passed to nec850.get_register_value: %d", op.reg);
    return 0;
  }
  return sval_t(getreg(ph.reg_names[op.reg], rv).ival);
}

//-------------------------------------------------------------------------
static bool is_bcond(int itype)
{
  return itype == NEC850_BV
      || itype == NEC850_BL
      || itype == NEC850_BZ
      || itype == NEC850_BNH
      || itype == NEC850_BN
      || itype == NEC850_BR
      || itype == NEC850_BLT
      || itype == NEC850_BLE
      || itype == NEC850_BNV
      || itype == NEC850_BNC
      || itype == NEC850_BNZ
      || itype == NEC850_BH
      || itype == NEC850_BP
      || itype == NEC850_BSA
      || itype == NEC850_BGE
      || itype == NEC850_BGT;
}

//-------------------------------------------------------------------------
ea_t nec850_t::nec850_next_exec_insn(
        ea_t ea,
        getreg_t *getreg,
        const regval_t *regvalues) const
{
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return BADADDR;

  // First check for Bcond.
  if ( is_bcond(insn.itype) )
  {
    uint32_t PSW = getreg("PSW", regvalues).ival;
    bool Z   = (PSW & (1 << 0)) != 0;
    bool S   = (PSW & (1 << 1)) != 0;
    bool OV  = (PSW & (1 << 2)) != 0;
    bool CY  = (PSW & (1 << 3)) != 0;
    bool SAT = (PSW & (1 << 4)) != 0;
    bool condition = false;
    switch ( insn.itype )
    {
      case NEC850_BV:  condition = OV;                break;
      case NEC850_BL:  condition = CY;                break;
      case NEC850_BZ:  condition = Z;                 break;
      case NEC850_BNH: condition = (CY || Z);         break;
      case NEC850_BN:  condition = S;                 break;
      case NEC850_BR:  condition = true;              break;
      case NEC850_BLT: condition = (S != OV);         break;
      case NEC850_BLE: condition = ((S != OV) || Z);  break;
      case NEC850_BNV: condition = !OV;               break;
      case NEC850_BNC: condition = !CY;               break;
      case NEC850_BNZ: condition = !Z;                break;
      case NEC850_BH:  condition = !(CY || Z);        break;
      case NEC850_BP:  condition = !S;                break;
      case NEC850_BSA: condition = SAT;               break;
      case NEC850_BGE: condition = !(S != OV);        break;
      case NEC850_BGT: condition = !((S != OV) || Z); break;
    }
    ea_t target = condition ? insn.Op1.addr : BADADDR;
    return target;
  }

  // Then check for other instructions.
  ea_t target = BADADDR;
  switch ( insn.itype )
  {
    case NEC850_RETI:
      {
        uint32_t PSW = getreg("PSW", regvalues).ival;
        if ( (PSW & (1 << 6)) != 0 ) // PSW.EP
        {
          target = getreg("EIPC", regvalues).ival;
        }
        else
        {
          if ( (PSW & (1 << 7)) != 0 ) // PSW.NP
            target = getreg("FEPC", regvalues).ival;
          else
            target = getreg("EIPC", regvalues).ival;
        }
      }
      break;

    case NEC850_JR:
      target = insn.Op1.addr;
      break;

    case NEC850_JMP:
      target = regval(insn.Op1, getreg, regvalues) + insn.Op1.addr;
      break;

    case NEC850_JARL:
      if ( insn.Op1.type == o_reg )
        target = regval(insn.Op1, getreg, regvalues);
      else
        target = insn.Op1.addr;
      break;

    case NEC850_SWITCH:
      // TODO
      break;

    case NEC850_DISPOSE_r:
      target = regval(insn.Op3, getreg, regvalues);
      break;

    case NEC850_CALLT:
      target = insn.Op1.addr;
      break;

    case NEC850_CTRET:
      target = getreg("CTPC", regvalues).ival;
      break;

    case NEC850_EIRET:
      target = getreg("EIPC", regvalues).ival;
      break;

    case NEC850_FERET:
      target = getreg("FEPC", regvalues).ival;
      break;

    case NEC850_LOOP:
      if ( regval(insn.Op1, getreg, regvalues) - 1 != 0 )
        target = insn.Op2.addr;
      break;

    case NEC850_DBHVTRAP:
    case NEC850_DBRET:
    case NEC850_DBTRAP:
    case NEC850_FETRAP:
    case NEC850_HALT:
    case NEC850_HVCALL:
    case NEC850_HVTRAP:
    case NEC850_RIE:
    case NEC850_RMTRAP:
    case NEC850_SYSCALL:
    case NEC850_TRAP:
      // TODO
      break;
  }

  return target;
}

//-------------------------------------------------------------------------
ea_t nec850_t::nec850_calc_step_over(ea_t ip) const
{
  insn_t insn;
  if ( ip == BADADDR || decode_insn(&insn, ip) < 1 )
    return BADADDR;

  bool step_over = is_call_insn(insn)
                || insn.itype == NEC850_LOOP;
  if ( step_over )
    return insn.ea + insn.size;

  return BADADDR;
}

//-------------------------------------------------------------------------
bool nec850_t::nec850_get_operand_info(
        idd_opinfo_t *opinf,
        ea_t ea,
        int n,
        getreg_t *getreg,
        const regval_t *regvalues)
{
  if ( n < 0 || n > 4 ) // check the operand number
    return false;
  insn_t insn;
  if ( decode_insn(&insn, ea) < 1 )
    return false;

  // TODO check for op.type == o_cond?
  opinf->modified = has_cf_chg(insn.get_canon_feature(ph), n);

  uint64 v = 0;
  const op_t &op = insn.ops[n];
  switch ( op.type )
  {
    case o_imm:
      v = op.value;
      break;

    case o_mem:
    case o_near:
      opinf->ea = op.addr;
      break;

    case o_reg:
      v = regval(op, getreg, regvalues);
      break;

    case o_displ:
      // TODO
      break;

    case o_reglist:
    case o_regrange:
      // TODO how to represent multiple registers?
      break;

    default:
      return false;
  }
  opinf->value._set_int(v);
  opinf->value_size = get_dtype_size(op.dtype);
  return true;
}

//--------------------------------------------------------------------------
int nec850_t::nec850_get_reg_index(const char *name) const
{
  if ( name == NULL || name[0] == '\0' )
    return -1;
  for ( size_t i = 0; i < ph.regs_num; i++ )
    if ( stricmp(ph.reg_names[i], name) == 0 )
      return i;
  return -1;
}

//--------------------------------------------------------------------------
bool nec850_t::nec850_get_reg_info(
        const char **main_regname,
        bitrange_t *bitrange,
        const char *regname)
{
  int regnum = nec850_get_reg_index(regname);
  if ( regnum == -1 )
    return false;

  if ( bitrange != NULL )
    *bitrange = bitrange_t(0, 32);

  if ( main_regname != NULL )
    *main_regname = ph.reg_names[regnum];

  return true;
}
