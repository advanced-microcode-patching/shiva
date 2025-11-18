
static void shiva_aarch64_emit_insn(uint8_t *buf, uint32_t insn)
{
	*(uint32_t *)buf = insn;
	return;
}

enum shiva_aarch64_br_opcodes
{
  B2		  = 0xbc000000, /* Not in the specs, but an imm branch */
  B               = 0x14000000,
  BL              = 0x80000000 | B,
  BCOND           = 0x40000000 | B,
  CBZ             = 0x20000000 | B,
  CBNZ            = 0x21000000 | B,
  TBZ             = 0x36000000 | B,
  TBNZ            = 0x37000000 | B
};

/* Condition code values.  */
#define EQ 0
#define NE 1
#define CS 2
#define CC 3
#define MI 4
#define PL 5
#define VS 6
#define VC 7
#define HI 8
#define LS 9
#define GE 10
#define LT 11
#define GT 12
#define LE 13
#define AL 14
#define NV 15


#define shiva_aarch64_encode(val, size, offset) \
    ((uint32_t) ((val & ((1ULL << size) - 1)) << offset))

#define shiva_aarch64_emit_bcond(mem, cond, off) \
    shiva_aarch64_emit_insn(mem,	\
	BCOND |				\
	shiva_aarch64_encode((off) >> 2, 19, 5) | \
	shiva_aarch64_encode((cond), 4, 0))

#define shiva_aarch64_emit_b(mem, is_bl, offset) \
    shiva_aarch64_emit_insn (mem, ((is_bl) ? BL : B) | \
    (shiva_aarch64_encode ((offset) >> 2, 26, 0)))

#define shiva_aarch64_emit_b2(mem, offset) \
    shiva_aarch64_emit_insn (mem, B2 | \
    shiva_aarch64_encode ((offset) >> 2, 26, 0))

#define shiva_aarch64_emit_cb(mem, is_cbnz, rn, is64, offset)                       \
  shiva_aarch64_emit_insn (mem,                                       \
                     ((is_cbnz) ? CBNZ : CBZ)                   \
                     | shiva_aarch64_encode (rn, 1, 31)  /* sf */        \
                     | shiva_aarch64_encode (offset >> 2, 19, 5) /* imm19 */  \
                     | shiva_aarch64_encode (is64, 5, 0))

#define shiva_aarch64_emit_tb(mem, is_tbnz, bit, rt, offset)                 \
  shiva_aarch64_emit_insn (mem,                                      \
                     ((is_tbnz) ? TBNZ: TBZ)                   \
                     | shiva_aarch64_encode (bit >> 5, 1, 31)       \
                     | shiva_aarch64_encode (bit, 5, 19)           \
                     | shiva_aarch64_encode (offset >> 2, 14, 5)  \
                     | shiva_aarch64_encode (rt, 5, 0))

