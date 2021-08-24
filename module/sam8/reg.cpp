#include "sam8.hpp"
#include <segregs.hpp>

//----------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void *, int msgid, va_list)
{
  if ( msgid == processor_t::ev_get_procmod )
    return size_t(new sam8_t);
  return 0;
}

ssize_t idaapi sam8_t::on_event(ssize_t msgid, va_list va)
{
  // deal with notification codes
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
      inf_set_be(true);       // Set big endian mode in the IDA kernel
      break;

    case processor_t::ev_newfile:
      {
        // create a new segment for code data
        segment_t seg;
        seg.start_ea = SAM8_CODESEG_START;
        seg.end_ea   = SAM8_CODESEG_START + SAM8_CODESEG_SIZE;
        seg.sel     = allocate_selector(seg.start_ea >> 4);
        seg.type    = SEG_NORM;
        add_segm_ex(&seg, "code", NULL, ADDSEG_NOSREG|ADDSEG_OR_DIE);
      }
      {
        // create a new segment for the external data
        segment_t seg;
        seg.start_ea = SAM8_EDATASEG_START;
        seg.end_ea   = SAM8_EDATASEG_START + SAM8_EDATASEG_SIZE;
        seg.sel     = allocate_selector(seg.start_ea >> 4);
        seg.flags   = SFL_HIDDEN;
        seg.type    = SEG_BSS;
        add_segm_ex(&seg, "emem", NULL, ADDSEG_NOSREG|ADDSEG_OR_DIE);
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        sam8_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        sam8_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        sam8_segstart(*ctx, seg);
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

    case processor_t::ev_out_data:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        bool analyze_only = va_argi(va, bool);
        sam8_out_data(*ctx, analyze_only);
        return 1;
      }

    default:
      break;
  }
  return code;
}


//-----------------------------------------------------------------------
// Condition codes
const char *const ccNames[] =
{
  "F",
  "LT",
  "LE",
  "ULE",
  "OV",
  "MI",
  "EQ",
  "C",
  "T",
  "GE",
  "GT",
  "UGT",
  "NOV",
  "PL",
  "NE",
  "NC",
};


/************************************************************************/
/* Register names                                                       */
/************************************************************************/
static const char *const RegNames[] =
{
  "cs","ds"
};


/************************************************************************/
/*                      Samsung Assembler   -   Version 1.42            */
/*              Copyright   1995,96 M.Y.Chong SAMSUNG ASIA PTE LTD      */
/*                             Semiconductor Division                   */
/************************************************************************/

/************************************************************************/
/* File headers for SAMA assembler                                      */
/************************************************************************/
static const char *const sama_headers[] =
{
  "",
  "; Filename of DEF file describing the chip in use",
  "CHIP <DEF Filename>",
  "",
  "; External memory EQU definitions",
  "; These will appear here when output using the samaout plugin",
  NULL
};


/************************************************************************/
/* Definition of SAMA assembler                                         */
/************************************************************************/
static const asm_t sama =
{
  AS_COLON,
  0,
  "Samsung Assembler (SAMA) by Samsung Semiconductor Division",
  0,
  (const char**) sama_headers,         // no headers
  "org",
  "end",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "+_*/%&|^()<>!+$@#.,\'\"?",    // special symbols in char+string constants

  "db",         // ascii string directive
  "db",         // byte directive
  "dw",         // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  NULL,         // uninited arrays
  "equ",        // equ
  NULL,         // seg prefix
  "$",
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  "~",     // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
  0,
};

/************************************************************************/
/* Assemblers supported by this module                                  */
/************************************************************************/
static const asm_t *const asms[] = { &sama, NULL };


/************************************************************************/
/* Short names of processor                                             */
/************************************************************************/
static const char *const shnames[] =
{
  "SAM8",
  NULL
};

/************************************************************************/
/* Long names of processor                                              */
/************************************************************************/
#define FAMILY "Samsung microcontrollers:"
static const char *const lnames[] =
{
  FAMILY"Samsung SAM8-based processors",
  NULL
};



//--------------------------------------------------------------------------
// Opcodes of "return" instructions. This information will be used in 2 ways:
//      - if an instruction has the "return" opcode, its autogenerated label
//        will be "locret" rather than "loc".
//      - IDA will use the first "return" opcode to create empty subroutines.

static const uchar retcode_1[] = { 0xAF };
static const uchar retcode_2[] = { 0xBF };

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { 0, NULL }                            // NULL terminated array
};


// processor code for SAM8
#define PLFM_SAM8 0x8020

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_SAM8,              // id
                          // flag
    PR_RNAMESOK           // can use register names for byte names
  | PR_BINMEM,
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,              // array of short processor names
                        // the short names are used to specify the processor
                        // with the -p command line switch)
  lnames,               // array of long processor names
                        // the long names are used to build the processor type
                        // selection menu

  asms,                 // array of target assemblers

  notify,               // the kernel event notification callback

  RegNames,             // Register names
  qnumber(RegNames),    // Number of registers

  rVcs,rVds,
  0,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0,SAM8_last,
  Instructions,                 // instruc
};
