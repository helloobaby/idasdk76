/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "78k_0s.hpp"
#include <segregs.hpp>
#include <diskio.hpp>
int data_id;

//----------------------------------------------------------------------
static const char *const RegNames[] =
{
  "X", "A", "C", "B", "E", "D", "L", "H", "AX", "BC", "DE","HL",
  "PSW", "SP", "s", "cc", "dpr",
  "CY",
  "cs", "ds"
};
//----------------------------------------------------------------------
static const asm_t nec78k0s =
{
  AS_COLON | ASH_HEXF0 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF4 | AS_N2CHR | AS_ONEDUP | AS_NOXRF,
  UAS_NOSPA,
  "NEC _78K_0S Assembler",
  0,
  NULL,     // header
  ".org",
  ".end",

  ";",      // comment string
  '"',      // string delimiter
  '\'',     // char delimiter
  "'\"",    // special symbols in char and string constants

  ".db",    // ascii string directive
  ".db",    // byte directive
  ".dw",    // word directive
  NULL,     // no double words
  NULL,     // no qwords
  NULL,     // oword  (16 bytes)
  NULL,     // no float
  NULL,     // no double
  NULL,     // no tbytes
  NULL,     // no packreal
  NULL,     //".db.#s(b,w) #d,#v",   // #h - header(.byte,.word)
                    // #d - size of array
                    // #v - value of array elements
                    // #s - size specifier
  ".rs %s", // uninited data (reserve space)
  ".equ",
  NULL,     // seg prefix
  "*",      // a_curip
  NULL,     // returns function header line
  NULL,     // returns function footer line
  NULL,     // public
  NULL,     // weak
  NULL,     // extrn
  NULL,     // comm
  NULL,     // get_type_name
  NULL,     // align
  '(', ')', // lbrace, rbrace
  NULL,     // mod
  NULL,     // and
  NULL,     // or
  NULL,     // xor
  NULL,     // not
  NULL,     // shl
  NULL,     // shr
  NULL,     // sizeof
};
//----------------------------------------------------------------------
#define FAMILY "NEC series:"
static const char *const shnames[] =
{
  "78k0s",
  NULL
};
static const char *const lnames[] =
{
  FAMILY"NEC 78K/0S",
  NULL
};
static const asm_t *const asms[] =
{
  &nec78k0s,
  NULL
};
//--------------------------------------------------------------------------
// return opcodes
static const uchar retcNEC78K0S_0[] = { 0x24 };    // reti
static const uchar retcNEC78K0S_1[] = { 0x20 };    // ret

static const bytes_t retcodes[] =
{
  { sizeof(retcNEC78K0S_0), retcNEC78K0S_0 },
  { sizeof(retcNEC78K0S_1), retcNEC78K0S_1 },
  { 0, NULL }
};

//------------------------------------------------------------------
bool nec78k0s_t::nec_find_ioport_bit(outctx_t &ctx, int port, int bit)
{
  // find bit register in the ports list
  const ioport_bit_t *b = find_ioport_bit(ioh.ports, port, bit);
  if ( b != NULL && !b->name.empty() )
  {
    // output bit register name
    ctx.out_line(b->name.c_str(), COLOR_IMPNAME);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
void nec78k0s_t::load_from_idb()
{
  ioh.restore_device();
}

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(SET_MODULE_DATA(nec78k0s_t));
  return 0;
}

//----------------------------------------------------------------------
ssize_t idaapi nec78k0s_t::on_event(ssize_t msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_init:
      inf_set_be(false);
      helper.create(PROCMOD_NODE_NAME);
      break;

    case processor_t::ev_term:
      ioh.ports.clear();
      clr_module_data(data_id);
      break;

    case processor_t::ev_newfile:
      {
        inf_set_gen_lzero(true);
        char cfgfile[QMAXFILE];
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        iohandler_t::parse_area_line0_t cb(ioh);
        if ( choose_ioport_device2(&ioh.device, cfgfile, &cb) )
          ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
      }
      break;

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
      load_from_idb();
      break;

    case processor_t::ev_creating_segm:    // new segment
      {
        segment_t *s = va_arg(va, segment_t *);
        // Set default value of DS register for all segments
        set_default_dataseg(s->sel);
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        nec78k0s_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        nec78k0s_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        nec78k0s_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return emu(*insn) ? 1 : -1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
      }


    default:
      break;
  }
  return 0;
}

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_NEC_78K0S,         // id
                          // flag
    PRN_HEX
  | PR_SEGTRANS,
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  RegNames,                     // Regsiter names
  qnumber(RegNames),            // Number of registers

  Rcs,Rds,
  0,                            // size of a segment register
  Rcs,Rds,

  NULL,                         // No known code start sequences
  retcodes,

  0,
  NEC_78K_0S_last,
  Instructions,                 // instruc
};
