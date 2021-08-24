#ifndef __NECV850_INC__
#define __NECV850_INC__

#include "../idaidp.hpp"
#include <list>
#include <pro.h>
#include <fpro.h>
#include <idd.hpp>
#include <ida.hpp>
#include <name.hpp>
#include <idp.hpp>
#include <ieee.h>

#define PROCMOD_NAME            nec850
#define PROCMOD_NODE_NAME       "$ prog pointers"


 #ifndef SIGN_EXTEND
   #define SIGN_EXTEND(type, var, nbits) \
     if ( var & (1 << (nbits-1)) ) \
       var |= ~type((1 << nbits)-1)
 #endif


//----------------------------------------------------------------------
// Specific flags

//
// Used in op_t.specflag1
#define N850F_USEBRACKETS     0x01  // some instructions use [reg] syntax even when there is no actual memory dereference
#define N850F_OUTSIGNED       0x02  // output as signed value
#define N850F_VAL32           0x04  // value/addr is wider than 16-bit

#define o_reglist               o_idpspec1      // Register list (for DISPOSE)
                                                // bitmask of registers is in 'value' field
//
// Used in insn.auxpref
#define N850F_SP                 0x00000001 // instruction modifies the stack pointer
#define N850F_FP                 0x00000010 // instruction works with floating-point data

#define o_cond                 o_idpspec2      // Condition code as operand (for CMOV/CMPF)
                                               // condition stored in 'value' field

#define o_regrange             o_idpspec3      // Register range (rh-rl, for PUSHSP/POPSP)
#define regrange_high          specval_shorts.high  // high  register (rh)
#define regrange_low           specval_shorts.low   // low register (rl)

//----------------------------------------------------------------------
// Registers def
enum NEC850_Registers
{
  rZERO,
  rR1,   rR2,   rSP /* r3 */, rGP /* r4 */,
  rR5,   rR6,   rR7,   rR8,
  rR9,   rR10,  rR11,  rR12,
  rR13,  rR14,  rR15,  rR16,
  rR17,  rR18,  rR19,  rR20,
  rR21,  rR22,  rR23,  rR24,
  rR25,  rR26,  rR27,  rR28,
  rR29,  rEP,   rR31,
  rLP = rR31,

  // system registers start here
  rSR0,
  rEIP=rSR0, rEIPSW, rFEPC, rFEPSW,
  rECR,   rPSW,    rSR6,   rSR7,
  rSR8,   rSR9,    rSR10,  rSR11,
  rSR12,  rSR13,   rSR14,  rSR15,
  rSR16,  rSR17,   rSR18,  rSR19,
  rSR20,  rSR21,   rSR22,  rSR23,
  rSR24,  rSR25,   rSR26,  rSR27,
  rSR28,  rSR29,   rSR30,  rSR31,

  // E1F FPU registers
  EFG, ECT,

  // segment registers
  rVep, // virtual element pointer segment register
  rVcs, rVds,

  rLastRegister
};

enum NEC850_CCode // for CMOV
{
  CC_V,   // 0000: Overflow (OV=1)
  CC_CL,  // 0001: Carry (CY=1)
  CC_Z,   // 0010: Zero (Z=1)
  CC_NH,  // 0011: Not higher (Less than or equal) ((CY or Z) = 1)
  CC_SN,  // 0100: Negative) S=1
  CC_T,   // 0101: Always (true)
  CC_LT,  // 0110: Less than signed (S xor OV) = 1
  CC_LE,  // 0111: Less than or equal signed (((S xor OV) or Z) = 1)
  CC_NV,  // 1000: no overflow (OV=0)
  CC_NCNL,// 1001: no carry (CY=0)
  CC_NZ,  // 1010: not zero (Z=0)
  CC_H,   // 0011: Higher (Greater than) ((CY or Z) = 0)
  CC_NSP, // 0100: Positive (S=0)
  CC_SAT, // 1101: Saturated (SAT=1)
  CC_GE,  // 1110: Greater than or equal signed (S xor OV) = 0
  CC_GT,  // 1111: Greater than signed (((S xor OV) or Z) = 0)
};

enum proctype_t
{
  V850,   // including V850
  V850E,  //
  V850ES, // including V850E1
  V850E2M,// including V850E2
  RH850,  //
};
//----------------------------------------------------------------------
// Prototypes

// prototypes -- out.cpp
void idaapi nec850_header(outctx_t &ctx);
void idaapi nec850_segstart(outctx_t &ctx, segment_t *seg);
void idaapi nec850_segend(outctx_t &ctx, segment_t *seg);

bool reg_in_list12(uint16 reg, uint32 L);

// prototypes -- ana.cpp
int  detect_inst_len(uint16 w);
int  fetch_instruction(uint32 *w);

// prototypes -- emu.cpp
bool idaapi nec850_is_switch(switch_info_t *si, const insn_t &insn);
bool idaapi nec850_create_func_frame(func_t *pfn);
int  idaapi nec850_get_frame_retsize(const func_t *pfn);
int  idaapi nec850_is_sp_based(const insn_t &insn, const op_t &x);
int  nec850_may_be_func(const insn_t &insn);
bool nec850_is_return(const insn_t &insn, bool strict);
int get_imm_outf(const insn_t &insn, const op_t &x);
int get_displ_outf(const insn_t &insn, const op_t &x, flags_t F);

extern const char *const RegNames[];

typedef const regval_t &idaapi getreg_t(const char *name, const regval_t *regvalues);

//------------------------------------------------------------------
DECLARE_PROC_LISTENER(idb_listener_t, struct nec850_t);

struct nec850_t : public procmod_t
{
  // altval(1) -> global pointer
  // altval(2) -> CALLT base pointer
#define GP_EA_IDX 1
#define CTBP_EA_IDX 2
  netnode helper;

  idb_listener_t idb_listener = idb_listener_t(*this);
  ea_t g_gp_ea = BADADDR;   // global pointer
  ea_t g_ctbp_ea = BADADDR; // CALLT base pointer
  int ptype = 0;
  bool flow = false;

  bool inline idaapi is_v850e() const   { return ptype >= (int)V850E; }
  bool inline idaapi is_v850es() const  { return ptype >= (int)V850ES; }
  bool inline idaapi is_v850e1() const  { return is_v850es(); }
  bool inline idaapi is_v850e1f() const { return is_v850e1(); }
  bool inline idaapi is_v850e2m() const { return ptype >= (int)V850E2M; }
  bool inline idaapi is_v850e2() const  { return is_v850e2m(); }
  bool inline idaapi is_rh850() const   { return ptype >= (int)RH850; }

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

  const char *idaapi set_idp_options(
        const char *keyword,
        int value_type,
        const void * value,
        bool idb_loaded);

  bool decode_instruction(const uint32 w, insn_t &ins);
  bool decode_coprocessor(const uint32 w, insn_t &ins) const;
  int nec850_ana(insn_t *pinsn);

  bool get_gp_based_addr(ea_t *target, const insn_t &_insn, const op_t &op) const;
  void handle_operand(const insn_t &insn, const op_t &op, bool isRead);
  int nec850_emu(const insn_t &insn);
  int nec850_is_sane_insn(const insn_t &insn, int no_crefs) const;
  sval_t regval(
        const op_t &op,
        getreg_t *getreg,
        const regval_t *rv) const;

  // debugger functions
  ea_t nec850_next_exec_insn(
        ea_t ea,
        getreg_t *getreg,
        const regval_t *regvalues) const;
  ea_t nec850_calc_step_over(ea_t ip) const;
  bool nec850_get_operand_info(
        idd_opinfo_t *opinf,
        ea_t ea,
        int n,
        getreg_t *getreg,
        const regval_t *regvalues);
  bool nec850_get_reg_info(
        const char **main_regname,
        bitrange_t *bitrange,
        const char *regname);
  int nec850_get_reg_index(const char *name) const; // static

  void nec850_footer(outctx_t &ctx) const;

  void save_all_options();
  void load_from_idb();
};
extern int data_id;

#endif
