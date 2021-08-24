
#include "pc_regs.hpp"

//-------------------------------------------------------------------------
// NOTE: keep in sync with register_class_x86_t
const char *x86_register_classes[] =
{
  "General registers",
  "Segment registers",
  "FPU registers",
  "MMX registers",
  "XMM registers",
  "YMM registers",
  NULL
};

//-------------------------------------------------------------------------
static const char *const eflags[] =
{
  "CF",         //  0
  NULL,         //  1
  "PF",         //  2
  NULL,         //  3
  "AF",         //  4
  NULL,         //  5
  "ZF",         //  6
  "SF",         //  7
  "TF",         //  8
  "IF",         //  9
  "DF",         // 10
  "OF",         // 11
  "IOPL",       // 12
  "IOPL",       // 13
  "NT",         // 14
  NULL,         // 15
  "RF",         // 16
  "VM",         // 17
  "AC",         // 18
  "VIF",        // 19
  "VIP",        // 20
  "ID",         // 21
  NULL,         // 22
  NULL,         // 23
  NULL,         // 24
  NULL,         // 25
  NULL,         // 26
  NULL,         // 27
  NULL,         // 28
  NULL,         // 29
  NULL,         // 30
  NULL          // 31
};

//-------------------------------------------------------------------------
static const char *const ctrlflags[] =
{
  "CTRL.IM",
  "CTRL.DM",
  "CTRL.ZM",
  "CTRL.OM",
  "CTRL.UM",
  "CTRL.PM",
  NULL,
  NULL,
  "CTRL.PC",
  "CTRL.PC",
  "CTRL.RC",
  "CTRL.RC",
  "CTRL.X",
  NULL,
  NULL,
  NULL
};

//-------------------------------------------------------------------------
static const char *const statflags[] =
{
  "STAT.IE",
  "STAT.DE",
  "STAT.ZE",
  "STAT.OE",
  "STAT.UE",
  "STAT.PE",
  "STAT.SF",
  "STAT.ES",
  "STAT.C0",
  "STAT.C1",
  "STAT.C2",
  "STAT.TOP",
  "STAT.TOP",
  "STAT.TOP",
  "STAT.C3",
  "STAT.B"
};

//-------------------------------------------------------------------------
static const char *const tagsflags[] =
{
  "TAG0",
  "TAG0",
  "TAG1",
  "TAG1",
  "TAG2",
  "TAG2",
  "TAG3",
  "TAG3",
  "TAG4",
  "TAG4",
  "TAG5",
  "TAG5",
  "TAG6",
  "TAG6",
  "TAG7",
  "TAG7"
};

//-------------------------------------------------------------------------
static const char *const xmm_format[] =
{
  "XMM_4_floats",
};

//-------------------------------------------------------------------------
static const char *const ymm_format[] =
{
  "YMM_8_floats",
};

//-------------------------------------------------------------------------
static const char *const mmx_format[] =
{
  "MMX_8_bytes",
};

//-------------------------------------------------------------------------
static const char *const mxcsr_bits[] =
{
  "IE",         //  0 Invalid Operation Flag
  "DE",         //  1 Denormal Flag
  "ZE",         //  2 Divide-by-Zero Flag
  "OE",         //  3 Overflow Flag
  "UE",         //  4 Underflow Flag
  "PE",         //  5 Precision Flag
  "DAZ",        //  6 Denormals Are Zeros*
  "IM",         //  7 Invalid Operation Mask
  "DM",         //  8 Denormal Operation Mask
  "ZM",         //  9 Divide-by-Zero Mask
  "OM",         // 10 Overflow Mask
  "UM",         // 11 Underflow Mask
  "PM",         // 12 Precision Mask
  "RC",         // 13 Rounding Control
  "RC",         // 14 Rounding Control
  "FZ",         // 15 Flush to Zero
  NULL,         // 16
  NULL,         // 17
  NULL,         // 18
  NULL,         // 19
  NULL,         // 20
  NULL,         // 21
  NULL,         // 22
  NULL,         // 23
  NULL,         // 24
  NULL,         // 25
  NULL,         // 26
  NULL,         // 27
  NULL,         // 28
  NULL,         // 29
  NULL,         // 30
  NULL          // 31
};

//-------------------------------------------------------------------------
// General registers
#ifdef __EA64__
register_info_t r_rax   = { "RAX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_rbx   = { "RBX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_rcx   = { "RCX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_rdx   = { "RDX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_rsi   = { "RSI",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_rdi   = { "RDI",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_rbp   = { "RBP",    REGISTER_ADDRESS|REGISTER_FP, X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_rsp   = { "RSP",    REGISTER_ADDRESS|REGISTER_SP, X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_rip   = { "RIP",    REGISTER_ADDRESS|REGISTER_IP, X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_r8    = { "R8",     REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_r9    = { "R9",     REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_r10   = { "R10",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_r11   = { "R11",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_r12   = { "R12",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_r13   = { "R13",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_r14   = { "R14",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
register_info_t r_r15   = { "R15",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_qword,  NULL,       0 };
#endif
register_info_t r_eax   = { "EAX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword,  NULL,       0 };
register_info_t r_ebx   = { "EBX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword,  NULL,       0 };
register_info_t r_ecx   = { "ECX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword,  NULL,       0 };
register_info_t r_edx   = { "EDX",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword,  NULL,       0 };
register_info_t r_esi   = { "ESI",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword,  NULL,       0 };
register_info_t r_edi   = { "EDI",    REGISTER_ADDRESS,             X86_RC_GENERAL,  dt_dword,  NULL,       0 };
register_info_t r_ebp   = { "EBP",    REGISTER_ADDRESS|REGISTER_FP, X86_RC_GENERAL,  dt_dword,  NULL,       0 };
register_info_t r_esp   = { "ESP",    REGISTER_ADDRESS|REGISTER_SP, X86_RC_GENERAL,  dt_dword,  NULL,       0 };
register_info_t r_eip   = { "EIP",    REGISTER_ADDRESS|REGISTER_IP, X86_RC_GENERAL,  dt_dword,  NULL,       0 };

//-------------------------------------------------------------------------
// NOTE: keep in sync with register_x86_t
register_info_t x86_registers[] =
{
  // FPU registers
  { "ST0",    0,                            X86_RC_FPU,      dt_tbyte,  NULL,       0 },
  { "ST1",    0,                            X86_RC_FPU,      dt_tbyte,  NULL,       0 },
  { "ST2",    0,                            X86_RC_FPU,      dt_tbyte,  NULL,       0 },
  { "ST3",    0,                            X86_RC_FPU,      dt_tbyte,  NULL,       0 },
  { "ST4",    0,                            X86_RC_FPU,      dt_tbyte,  NULL,       0 },
  { "ST5",    0,                            X86_RC_FPU,      dt_tbyte,  NULL,       0 },
  { "ST6",    0,                            X86_RC_FPU,      dt_tbyte,  NULL,       0 },
  { "ST7",    0,                            X86_RC_FPU,      dt_tbyte,  NULL,       0 },
  { "CTRL",   0,                            X86_RC_FPU,      dt_word,   ctrlflags,  0x1F3F },
  { "STAT",   0,                            X86_RC_FPU,      dt_word,   statflags,  0xFFFF },
  { "TAGS",   0,                            X86_RC_FPU,      dt_word,   tagsflags,  0xFFFF },
  // Segment registers
  { "CS",     REGISTER_CS|REGISTER_NOLF,    X86_RC_SEGMENTS, dt_word,   NULL,       0 },
  { "DS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,   NULL,       0 },
  { "ES",     0,                            X86_RC_SEGMENTS, dt_word,   NULL,       0 },
  { "FS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,   NULL,       0 },
  { "GS",     REGISTER_NOLF,                X86_RC_SEGMENTS, dt_word,   NULL,       0 },
  { "SS",     REGISTER_SS,                  X86_RC_SEGMENTS, dt_word,   NULL,       0 },
  // General registers
#ifdef __EA64__
  r_rax,
  r_rbx,
  r_rcx,
  r_rdx,
  r_rsi,
  r_rdi,
  r_rbp,
  r_rsp,
  r_rip,
  r_r8,
  r_r9,
  r_r10,
  r_r11,
  r_r12,
  r_r13,
  r_r14,
  r_r15,
#else
  r_eax,
  r_ebx,
  r_ecx,
  r_edx,
  r_esi,
  r_edi,
  r_ebp,
  r_esp,
  r_eip,
#endif
  { "EFL",    0,                            X86_RC_GENERAL,  dt_dword,  eflags,     0x00000FD5 }, // OF|DF|IF|TF|SF|ZF|AF|PF|CF
  // XMM registers
  { "XMM0",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM1",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM2",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM3",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM4",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM5",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM6",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM7",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
#ifdef __EA64__
  { "XMM8",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM9",   REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM10",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM11",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM12",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM13",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM14",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
  { "XMM15",  REGISTER_CUSTFMT,             X86_RC_XMM,      dt_byte16, xmm_format, 0 },
#endif
  { "MXCSR",  0,                            X86_RC_XMM,      dt_dword,  mxcsr_bits, 0xFFFF },
  // MMX registers
  { "MM0",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM1",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM2",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM3",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM4",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM5",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM6",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  { "MM7",    REGISTER_CUSTFMT,             X86_RC_MMX,      dt_qword,  mmx_format, 0 },
  // YMM registers
  { "YMM0",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM1",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM2",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM3",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM4",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM5",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM6",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM7",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
#ifdef __EA64__
  { "YMM8",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM9",   REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM10",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM11",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM12",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM13",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM14",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
  { "YMM15",  REGISTER_CUSTFMT,             X86_RC_YMM,      dt_byte32, ymm_format, 0 },
#endif
};
CASSERT(qnumber(x86_registers) == X86_NREGS);

//-------------------------------------------------------------------------
int x86_get_regidx(int *clsmask, const char *regname)
{
  for ( size_t i = 0; i < qnumber(x86_registers); i++ )
  {
    if ( strieq(regname, x86_registers[i].name) )
    {
      if ( clsmask != NULL )
        *clsmask = x86_registers[i].register_class;
      return i;
    }
  }
  return -1;
}

//-------------------------------------------------------------------------
int x86_get_regclass(int idx)
{
  if ( idx >= 0 && idx < qnumber(x86_registers) )
    return x86_registers[idx].register_class;
  return 0;
}
