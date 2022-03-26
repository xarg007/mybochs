#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cassert>
#include <cstring>
#include <cstdarg>

// C++11(ISO/IEC-14882:2011)@gcc9+@debian11
extern "C"
{
#include <sys/stat.h>
#include <sys/types.h>
};

typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long int uint64_t;

extern void xlog_init();
extern void xlog_uninit();
extern void xlog_mutex_lock();
extern void xlog_mutex_lock();
int xlog_info(const char *fmt, ...);
int xlog_hexdump(const uint8_t *const p_data, uint32_t i_len);

#ifdef XLOG_PTHREAD_T
#include <pthread.h>
pthread_mutex_t xlog_mutex_v = {0};
pthread_mutexattr_t xlog_attr_v = {0};
#endif

void xlog_init()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_init(&xlog_mutex_v, NULL);
#endif
    return;
}

void xlog_uninit()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_destroy(&xlog_mutex_v);
#endif
    return;
}

void xlog_mutex_lock()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_lock(&xlog_mutex_v);
#endif
    return;
}

void xlog_mutex_unlock()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_unlock(&xlog_mutex_v);
#endif
    return;
}

int xlog_core(unsigned int ui_level, const char *fmt, va_list args)
{
    int iret = vprintf(fmt, args);
    // fflush(stdout);
    return iret;
}

int xlog_info_x(const char *fmt, ...)
{
    int iret = 0;

    int log_switch = 1;

    if (log_switch)
    {
        va_list args;
        va_start(args, fmt);
        iret = xlog_core(1, fmt, args);
        va_end(args);
    }

    return iret;
}

int xlog_hexdump(const uint8_t *const p_data, uint32_t i_len)
{
    int iret = 0;
    xlog_mutex_lock();
    if (p_data == NULL || i_len == 0)
    {
        xlog_mutex_unlock();
        return 0;
    }

    xlog_info_x("\n");
    xlog_info_x("%016p", p_data);
    xlog_info_x("|00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F|0123456789ABCDEF|\n");
    xlog_info_x("      =============================================================================\n");

    unsigned int i_row = (i_len % 16 != 0 ? i_len / 16 + 1 : i_len / 16);
    for (unsigned int i = 0; i < i_row; i++) //逐行处理
    {
        //数据相对地址
        xlog_info_x("      0x%08x|", i * 16);

        //十六进制数据
        xlog_info_x("\e[32m");
        //当前行1~8列数据
        for (unsigned int j = 0; j < 8; j++)
        {
            if ((i * 16 + j) < i_len)
            {
                xlog_info_x("%02x ", *(p_data + i * 16 + j));
            }
            else
            {
                xlog_info_x("** ");
            }
        }

        //在第8列与第9列中加空格列
        xlog_info_x(" ");

        //当前行前9~16列数据
        for (unsigned int j = 8; j < 16; j++)
        {
            if ((i * 16 + j) < i_len)
            {
                if (j < 15)
                    xlog_info_x("%02x ", *(p_data + i * 16 + j));
                else
                    xlog_info_x("%02x", *(p_data + i * 16 + j));
            }
            else
            {
                if (j < 15)
                    xlog_info_x("** ");
                else
                    xlog_info_x("**");
            }
        }

        xlog_info_x("\e[0m");

        //数据与字符边界
        xlog_info_x("|");

        //显示字符
        for (unsigned int j = 0; j < 16; j++)
        {
            if ((i * 16 + j) < i_len)
            {
                unsigned char test_char = *(p_data + i * 16 + j);
                do
                {
                    if (isalpha(test_char))
                        break;
                    if (isdigit(test_char))
                        break;
                    if (ispunct(test_char))
                        break;
                    if (test_char == 0x20)
                        break;
                    if (test_char == 0x0)
                        break;
                    test_char = '.';
                } while (0);

                if (test_char == 0x0)
                {
                    xlog_info_x("\e[37m.\e[0m");
                }
                else
                {
                    xlog_info_x("%c", test_char);
                }
            }
            else
            {
                xlog_info_x("*");
            }
        }

        //行尾边界处理
        xlog_info_x("|");
        //换下一行
        xlog_info_x("\n");
    }
    xlog_info_x("      =============================================================================\n");
    xlog_info_x("\n");

    xlog_mutex_unlock();
    return iret;
}

int xlog_info(const char *fmt, ...)
{
    int iret = 0;
    xlog_mutex_lock();

    int log_switch = 1;

    if (log_switch)
    {
        va_list args;
        va_start(args, fmt);
        iret = xlog_core(1, fmt, args);
        va_end(args);
    }

    xlog_mutex_unlock();
    return iret;
}

uint8_t *get_elf64_data(const char *filename, uint32_t *len)
{
    xlog_info("  >> get_elf64_data(\"%s\", len) entry;\n", filename);
    *len = 0x12;

    uint8_t *p_data = NULL;
    struct stat statbuf = {0};
    stat(filename, &statbuf);

    unsigned int iLen = statbuf.st_size;
    if (iLen > 0 && iLen < 10 * 1024 * 1024) //文件目前最大设为10M
    {
        FILE *hFile = fopen(filename, "rb");
        if (hFile == NULL)
            return NULL;

        *len = iLen;
        p_data = (unsigned char *)calloc(iLen / 4 + 2, sizeof(uint8_t) * 4);

        size_t size_readok = fread(p_data, 1, iLen, hFile);
        fclose(hFile);

        if (size_readok != iLen)
        {
            free(p_data);
            return NULL;
        }

        return p_data;
    }

    xlog_info("  >> get_elf64_data() exit;\n");
    return NULL;
}
//==========================================

//==========================================
/* 64-bit ELF base types. */
typedef unsigned long long int Elf64_Addr;
typedef unsigned short int Elf64_Half;
typedef signed short int Elf64_SHalf;
typedef unsigned long long int Elf64_Off;
typedef signed int Elf64_Sword;
typedef unsigned int Elf64_Word;
typedef unsigned long long int Elf64_Xword;
typedef signed long long int Elf64_Sxword;

struct S_ELF64_ELFHeader_t
{
    unsigned char e_ident[16]; /* ELF "magic number" */
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry; /* Entry point virtual address */
    Elf64_Off e_phoff;  /* Program header table file offset */
    Elf64_Off e_shoff;  /* Section header table file offset */
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
};
//==========================================

//==========================================
struct S_ELF64_ELFHeader_t *parse_elf64_elf_header(uint8_t *pElfData)
{
    xlog_info("  >> func{%s:(%05d)} is call.{pElfData=%p}.\n", __func__, __LINE__, pElfData);

    if (pElfData != NULL)
    {
        struct S_ELF64_ELFHeader_t *pElfHeader = (struct S_ELF64_ELFHeader_t *)pElfData;

        xlog_info("        struct S_ELF64_ELFHeader_t pElfHeader = {%p} \n", pElfHeader);
        xlog_info("        {\n");
        xlog_info("                 unsigned char e_ident[16] = {");
        for (int i = 0; i < 16; i++)
        {
            if (i < 15)
            {
                xlog_info("%02x ", pElfHeader->e_ident[i]);
            }
            else
            {
                xlog_info("%02x", pElfHeader->e_ident[i]);
            }
        }
        xlog_info("};\n");
        xlog_info("                 Elf64_Half    e_type      = 0x%04x;\n", pElfHeader->e_type);
        xlog_info("                 Elf64_Half    e_machine   = 0x%04x;\n", pElfHeader->e_machine);
        xlog_info("                 Elf64_Word    e_version   = 0x%x  ;\n", pElfHeader->e_version);
        xlog_info("                 Elf64_Addr    e_entry     = 0x%llx;\n", pElfHeader->e_entry);
        xlog_info("                 Elf64_Off     e_phoff     = 0x%llx;\n", pElfHeader->e_phoff);
        xlog_info("                 Elf64_Off     e_shoff     = 0x%llx;\n", pElfHeader->e_shoff);
        xlog_info("                 Elf64_Word    e_flags     = 0x%x  ;\n", pElfHeader->e_flags);
        xlog_info("                 Elf64_Half    e_ehsize    = 0x%04x;\n", pElfHeader->e_ehsize);
        xlog_info("                 Elf64_Half    e_phentsize = 0x%04x;\n", pElfHeader->e_phentsize);
        xlog_info("                 Elf64_Half    e_phnum     = 0x%04x;\n", pElfHeader->e_phnum);
        xlog_info("                 Elf64_Half    e_shentsize = 0x%04x;\n", pElfHeader->e_shentsize);
        xlog_info("                 Elf64_Half    e_shnum     = 0x%04x;\n", pElfHeader->e_shnum);
        xlog_info("                 Elf64_Half    e_shstrndx  = 0x%04x;\n", pElfHeader->e_shstrndx);
        xlog_info("        };\n");

        return pElfHeader;
    }

    return NULL;
}

uint8_t *getInstrData(const char *pFileName)
{
    unsigned char *pHexData = NULL;
    unsigned int iLen = 0;
    pHexData = get_elf64_data(pFileName, &iLen);
    if (pHexData == NULL && iLen <= 0)
    {
        return NULL;
    }

    xlog_info("  >> func{%s:(%05d)} is call, pHexData=\"%p\" .\n", __func__, __LINE__, pHexData);
    xlog_hexdump(pHexData, 16 * 10 + 9);

    struct S_ELF64_ELFHeader_t *pElfHeader = parse_elf64_elf_header(pHexData);

    uint8_t *pInstr = pHexData + pElfHeader->e_entry;

    return pInstr;
}

//========================================================================

class CMyBochsApp_t
{
public:
    CMyBochsApp_t();
    virtual ~CMyBochsApp_t();

public:
    virtual int MainProc(int argc, char *argv[]);
};

class bxInstruction_c
{
public:
    bxInstruction_c();
    virtual ~bxInstruction_c();
};

class CMyBochsCpu_t
{
public:
    CMyBochsCpu_t();
    virtual ~CMyBochsCpu_t();

public:
    virtual void cpu_loop(void);
    
    static void BxError(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu);
    static void exe1(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu);
    static void exe2(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu);
    static void exe3(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu);
    static void exe4(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu);
};

class CSimulator_t
{
public:
    class CMyBochsCpu_t *mp_cpu;

public:
    CSimulator_t();
    CSimulator_t(CMyBochsCpu_t *cpu);
    virtual ~CSimulator_t();

public:
    virtual int begin_simulator(int argc, char *argv[]);
};

//========================================================================
class CSimulator_t;
extern int bx_begin_simulator(CSimulator_t *pSim, int argc, char *argv[]);
extern int bx_main_proc(int argc, char *argv[]);

CMyBochsApp_t::CMyBochsApp_t()
{
    xlog_info("  >> CMyBochsApp_t::CMyBochsApp_t() called.\n");
}

CMyBochsApp_t::~CMyBochsApp_t()
{
    xlog_info("  >> CMyBochsApp_t::~CMyBochsApp_t() called.\n");
}

int CMyBochsApp_t::MainProc(int argc, char *argv[])
{
    xlog_info("  >> CMyBochsApp_t::MainProc(argc=%d, argv=%p) called.\n", argc, argv);
    return bx_main_proc(argc, argv);
}

bxInstruction_c::bxInstruction_c()
{
}

bxInstruction_c::~bxInstruction_c()
{
}

CMyBochsCpu_t::CMyBochsCpu_t()
{
    xlog_info("  >> CMyBochsCpu_t::CMyBochsCpu_t() called.\n");
}

CMyBochsCpu_t::~CMyBochsCpu_t()
{
    xlog_info("  >> CMyBochsCpu_t::~CMyBochsCpu_t() called.\n");
}

CSimulator_t::CSimulator_t()
    : mp_cpu(NULL)
{
    xlog_info("  >> CSimulator_t::CSimulator_t() called.\n");
}

CSimulator_t::CSimulator_t(CMyBochsCpu_t *cpu)
    : mp_cpu(cpu)
{
    xlog_info("  >> CSimulator_t::CSimulator_t() called.\n");
}

CSimulator_t::~CSimulator_t()
{
    xlog_info("  >> CSimulator_t::~CSimulator_t() called.\n");
    delete mp_cpu;
}

int CSimulator_t::begin_simulator(int argc, char *argv[])
{
    xlog_info("  >> CSimulator_t::begin_simulator(argc=%d, argv=%p) called.\n", argc, argv);
    int iret = 0;
    try
    {
        iret = bx_begin_simulator(this, argc, argv);
    }
    catch (...)
    {
        //
    }

    return iret;
}

//制用解码用表
////////////////////////////////////////////////////////////////////////////
typedef unsigned char Bit8u;
typedef signed char Bit8s;
typedef unsigned short Bit16u;
typedef signed short Bit16s;
typedef unsigned int Bit32u;
typedef signed int Bit32s;
typedef unsigned long long Bit64u;
typedef signed long long Bit64s;

typedef void (*BxExecutePtr_tR)(bxInstruction_c *, CMyBochsCpu_t *);

void CMyBochsCpu_t::BxError(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu)
{
    xlog_info("  >> func:CMyBochsCpu_t::%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
}

void CMyBochsCpu_t::exe1(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu)
{
    xlog_info("  >> func:CMyBochsCpu_t::%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
}

void CMyBochsCpu_t::exe2(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu)
{
    xlog_info("  >> func:CMyBochsCpu_t::%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
}
void CMyBochsCpu_t::exe3(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu)
{
    xlog_info("  >> func:CMyBochsCpu_t::%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
}
void CMyBochsCpu_t::exe4(bxInstruction_c *i, CMyBochsCpu_t *pThisCpu)
{
    xlog_info("  >> func:CMyBochsCpu_t::%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
}

struct bxIAOpcodeTable
{
    BxExecutePtr_tR execute1;
    BxExecutePtr_tR execute2;
    Bit8u src[4];
    Bit8u opflags;
};
//======================================================================
#define OP_NONE 0
#define BX_TRACE_END 0
#define OP_Ib 0
//======================================================================
enum OpCodeIdx_t
{
#define bx_define_opcode(a, b, c, d, e, f, s1, s2, s3, s4, g) a,
#include "mybochs-la-0.1.05.x86_64_decode.def"
//bx_define_opcode(BX_IA_ERROR, "error", "error", &CMyBochsCpu_t::BxError, &CMyBochsCpu_t::exe1, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, BX_TRACE_END)
//bx_define_opcode(BX_IA_AAA,   "aaa",   "aaa",   NULL,                    &CMyBochsCpu_t::exe1, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_AAD,   "aad",   "aad",   NULL,                    &CMyBochsCpu_t::exe1, 0, OP_Ib,   OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_AAM,   "aam",   "aam",   NULL,                    &CMyBochsCpu_t::exe1, 0, OP_Ib,   OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_AAS,   "aas",   "aas",   NULL,                    &CMyBochsCpu_t::exe1, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_DAA,   "daa",   "daa",   NULL,                    &CMyBochsCpu_t::exe1, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_DAS,   "das",   "das",   NULL,                    &CMyBochsCpu_t::exe1, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, 0)
   BX_IA_LAST
};
#undef  bx_define_opcode

// table of all Bochs opcodes
//bxIAOpcodeTable BxOpcodesTable[] = {
//    /*BX_IA_ADC_EwGw,*/ {&CMyBochsCpu_t::exe1, &CMyBochsCpu_t::exe1, {0, 0, 0, 0}, 0},
//    /*BX_IA_ADD_EwGw,*/ {&CMyBochsCpu_t::exe1, &CMyBochsCpu_t::exe1, {0, 0, 0, 0}, 0},
//    /*BX_IA_AND_EwGw,*/ {&CMyBochsCpu_t::exe1, &CMyBochsCpu_t::exe1, {0, 0, 0, 0}, 0},
//    /*BX_IA_CMP_EwGw,*/ {&CMyBochsCpu_t::exe1, &CMyBochsCpu_t::exe1, {0, 0, 0, 0}, 0},
//    /*BX_IA_OR_EwGw, */ {&CMyBochsCpu_t::exe1, &CMyBochsCpu_t::exe1, {0, 0, 0, 0}, 0},
//    /*BX_IA_SBB_EwGw,*/ {&CMyBochsCpu_t::exe1, &CMyBochsCpu_t::exe1, {0, 0, 0, 0}, 0},
//    /*BX_IA_SUB_EwGw,*/ {NULL, NULL, {0, 0, 0, 0}, 0},
//};

bxIAOpcodeTable BxOpcodesTable[] =
{
#define bx_define_opcode(a, b, c, d, e, f, s1, s2, s3, s4, g) { d, e, { s1, s2, s3, s4 }, g },
#include "mybochs-la-0.1.05.x86_64_decode.def"
};
#undef  bx_define_opcode

extern int decoder_ud64(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table);
extern int decoder64(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table);
extern int decoder64_modrm(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table);

// opcode 00
static const Bit64u BxOpcodeTable00[] = {
    // last_opcode_lockable(0, BX_IA_ADD_EbGb)
    0xFFFFEEEEAAAABBBB,
};

// opcode 01
static const Bit64u BxOpcodeTable01[] = {
    0xFFFFEEEEAAAABaBB,
    0xFFFFEEEEAAAABeBB,
};

// opcode 02
static const Bit64u BxOpcodeTable02[] = {
    0xFFFFEEEEAAAABaBB,
    0xFFFFEEEEAAAABeBB,
};

// opcode 03
static const Bit64u BxOpcodeTable03[] = {
    0xFFFFEEEEAAAABaBB,
    0xFFFFEEEEAAAABeBB,
};

typedef int (*BxFetchDecode64Ptr)(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table);

struct BxOpcodeDecodeDescriptor64
{
    BxFetchDecode64Ptr decode_method;
    const void *opcode_table;
};

static BxOpcodeDecodeDescriptor64 decode64_descriptor[] = {
    /*       00 => 0x0000*/ {&decoder64, BxOpcodeTable00},
    /*       01 => 0x0001*/ {&decoder64, BxOpcodeTable01},
    /*       02 => 0x0002*/ {&decoder64, BxOpcodeTable02},
    /*       03 => 0x0003*/ {&decoder64, BxOpcodeTable03},
#if 1       
    /*       04 => 0x0004*/ {&decoder64, NULL},  //BxOpcodeTable04},
    /*       05 => 0x0005*/ {&decoder64, NULL},  //BxOpcodeTable05},
    /*       06 => 0x0006*/ {&decoder64, NULL},  //BxOpcodeTable06},
    /*       07 => 0x0007*/ {&decoder64, NULL},  //BxOpcodeTable07},
    /*       08 => 0x0008*/ {&decoder64, NULL},  //BxOpcodeTable08},
    /*       09 => 0x0009*/ {&decoder64, NULL},  //BxOpcodeTable09},
    /*       0A => 0x000A*/ {&decoder64, NULL},  //BxOpcodeTable0A},
    /*       0B => 0x000B*/ {&decoder64, NULL},  //BxOpcodeTable0B},
    /*       0C => 0x000C*/ {&decoder64, NULL},  //BxOpcodeTable0C},
    /*       0D => 0x000D*/ {&decoder64, NULL},  //BxOpcodeTable0D},
    /*       0E => 0x000E*/ {&decoder64, NULL},  //BxOpcodeTable0E},
    /*       0F => 0x000F*/ {&decoder64, NULL},  //BxOpcodeTable0F},
    /*       10 => 0x0010*/ {&decoder64, NULL},  //BxOpcodeTable10},
    /*       11 => 0x0011*/ {&decoder64, NULL},  //BxOpcodeTable11},
    /*       12 => 0x0012*/ {&decoder64, NULL},  //BxOpcodeTable12},
    /*       13 => 0x0013*/ {&decoder64, NULL},  //BxOpcodeTable13},
    /*       14 => 0x0014*/ {&decoder64, NULL},  //BxOpcodeTable14},
    /*       15 => 0x0015*/ {&decoder64, NULL},  //BxOpcodeTable15},
    /*       16 => 0x0016*/ {&decoder64, NULL},  //BxOpcodeTable16},
    /*       17 => 0x0017*/ {&decoder64, NULL},  //BxOpcodeTable17},
    /*       18 => 0x0018*/ {&decoder64, NULL},  //BxOpcodeTable18},
    /*       19 => 0x0019*/ {&decoder64, NULL},  //BxOpcodeTable19},
    /*       1A => 0x001A*/ {&decoder64, NULL},  //BxOpcodeTable1A},
    /*       1B => 0x001B*/ {&decoder64, NULL},  //BxOpcodeTable1B},
    /*       1C => 0x001C*/ {&decoder64, NULL},  //BxOpcodeTable1C},
    /*       1D => 0x001D*/ {&decoder64, NULL},  //BxOpcodeTable1D},
    /*       1E => 0x001E*/ {&decoder64, NULL},  //BxOpcodeTable1E},
    /*       1F => 0x001F*/ {&decoder64, NULL},  //BxOpcodeTable1F},
    /*       20 => 0x0020*/ {&decoder64, NULL},  //BxOpcodeTable20},
    /*       21 => 0x0021*/ {&decoder64, NULL},  //BxOpcodeTable21},
    /*       22 => 0x0022*/ {&decoder64, NULL},  //BxOpcodeTable22},
    /*       23 => 0x0023*/ {&decoder64, NULL},  //BxOpcodeTable23},
    /*       24 => 0x0024*/ {&decoder64, NULL},  //BxOpcodeTable24},
    /*       25 => 0x0025*/ {&decoder64, NULL},  //BxOpcodeTable25},
    /*       26 => 0x0026*/ {&decoder64, NULL},  //BxOpcodeTable26},
    /*       27 => 0x0027*/ {&decoder64, NULL},  //BxOpcodeTable27},
    /*       28 => 0x0028*/ {&decoder64, NULL},  //BxOpcodeTable28},
    /*       29 => 0x0029*/ {&decoder64, NULL},  //BxOpcodeTable29},
    /*       2A => 0x002A*/ {&decoder64, NULL},  //BxOpcodeTable2A},
    /*       2B => 0x002B*/ {&decoder64, NULL},  //BxOpcodeTable2B},
    /*       2C => 0x002C*/ {&decoder64, NULL},  //BxOpcodeTable2C},
    /*       2D => 0x002D*/ {&decoder64, NULL},  //BxOpcodeTable2D},
    /*       2E => 0x002E*/ {&decoder64, NULL},  //BxOpcodeTable2E},
    /*       2F => 0x002F*/ {&decoder64, NULL},  //BxOpcodeTable2F},
    /*       30 => 0x0030*/ {&decoder64, NULL},  //BxOpcodeTable30},
    /*       31 => 0x0031*/ {&decoder64, NULL},  //BxOpcodeTable31},
    /*       32 => 0x0032*/ {&decoder64, NULL},  //BxOpcodeTable32},
    /*       33 => 0x0033*/ {&decoder64, NULL},  //BxOpcodeTable33},
    /*       34 => 0x0034*/ {&decoder64, NULL},  //BxOpcodeTable34},
    /*       35 => 0x0035*/ {&decoder64, NULL},  //BxOpcodeTable35},
    /*       36 => 0x0036*/ {&decoder64, NULL},  //BxOpcodeTable36},
    /*       37 => 0x0037*/ {&decoder64, NULL},  //BxOpcodeTable37},
    /*       38 => 0x0038*/ {&decoder64, NULL},  //BxOpcodeTable38},
    /*       39 => 0x0039*/ {&decoder64, NULL},  //BxOpcodeTable39},
    /*       3A => 0x003A*/ {&decoder64, NULL},  //BxOpcodeTable3A},
    /*       3B => 0x003B*/ {&decoder64, NULL},  //BxOpcodeTable3B},
    /*       3C => 0x003C*/ {&decoder64, NULL},  //BxOpcodeTable3C},
    /*       3D => 0x003D*/ {&decoder64, NULL},  //BxOpcodeTable3D},
    /*       3E => 0x003E*/ {&decoder64, NULL},  //BxOpcodeTable3E},
    /*       3F => 0x003F*/ {&decoder64, NULL},  //BxOpcodeTable3F},
    /*       40 => 0x0040*/ {&decoder64, NULL},  //BxOpcodeTable40},
    /*       41 => 0x0041*/ {&decoder64, NULL},  //BxOpcodeTable41},
    /*       42 => 0x0042*/ {&decoder64, NULL},  //BxOpcodeTable42},
    /*       43 => 0x0043*/ {&decoder64, NULL},  //BxOpcodeTable43},
    /*       44 => 0x0044*/ {&decoder64, NULL},  //BxOpcodeTable44},
    /*       45 => 0x0045*/ {&decoder64, NULL},  //BxOpcodeTable45},
    /*       46 => 0x0046*/ {&decoder64, NULL},  //BxOpcodeTable46},
    /*       47 => 0x0047*/ {&decoder64, NULL},  //BxOpcodeTable47},
    /*       48 => 0x0048*/ {&decoder64, NULL},  //BxOpcodeTable48},
    /*       49 => 0x0049*/ {&decoder64, NULL},  //BxOpcodeTable49},
    /*       4A => 0x004A*/ {&decoder64, NULL},  //BxOpcodeTable4A},
    /*       4B => 0x004B*/ {&decoder64, NULL},  //BxOpcodeTable4B},
    /*       4C => 0x004C*/ {&decoder64, NULL},  //BxOpcodeTable4C},
    /*       4D => 0x004D*/ {&decoder64, NULL},  //BxOpcodeTable4D},
    /*       4E => 0x004E*/ {&decoder64, NULL},  //BxOpcodeTable4E},
    /*       4F => 0x004F*/ {&decoder64, NULL},  //BxOpcodeTable4F},
    /*       50 => 0x0050*/ {&decoder64, NULL},  //BxOpcodeTable50},
    /*       51 => 0x0051*/ {&decoder64, NULL},  //BxOpcodeTable51},
    /*       52 => 0x0052*/ {&decoder64, NULL},  //BxOpcodeTable52},
    /*       53 => 0x0053*/ {&decoder64, NULL},  //BxOpcodeTable53},
    /*       54 => 0x0054*/ {&decoder64, NULL},  //BxOpcodeTable54},
    /*       55 => 0x0055*/ {&decoder64, NULL},  //BxOpcodeTable55},
    /*       56 => 0x0056*/ {&decoder64, NULL},  //BxOpcodeTable56},
    /*       57 => 0x0057*/ {&decoder64, NULL},  //BxOpcodeTable57},
    /*       58 => 0x0058*/ {&decoder64, NULL},  //BxOpcodeTable58},
    /*       59 => 0x0059*/ {&decoder64, NULL},  //BxOpcodeTable59},
    /*       5A => 0x005A*/ {&decoder64, NULL},  //BxOpcodeTable5A},
    /*       5B => 0x005B*/ {&decoder64, NULL},  //BxOpcodeTable5B},
    /*       5C => 0x005C*/ {&decoder64, NULL},  //BxOpcodeTable5C},
    /*       5D => 0x005D*/ {&decoder64, NULL},  //BxOpcodeTable5D},
    /*       5E => 0x005E*/ {&decoder64, NULL},  //BxOpcodeTable5E},
    /*       5F => 0x005F*/ {&decoder64, NULL},  //BxOpcodeTable5F},
    /*       60 => 0x0060*/ {&decoder64, NULL},  //BxOpcodeTable60},
    /*       61 => 0x0061*/ {&decoder64, NULL},  //BxOpcodeTable61},
    /*       62 => 0x0062*/ {&decoder64, NULL},  //BxOpcodeTable62},
    /*       63 => 0x0063*/ {&decoder64, NULL},  //BxOpcodeTable63},
    /*       64 => 0x0064*/ {&decoder64, NULL},  //BxOpcodeTable64},
    /*       65 => 0x0065*/ {&decoder64, NULL},  //BxOpcodeTable65},
    /*       66 => 0x0066*/ {&decoder64, NULL},  //BxOpcodeTable66},
    /*       67 => 0x0067*/ {&decoder64, NULL},  //BxOpcodeTable67},
    /*       68 => 0x0068*/ {&decoder64, NULL},  //BxOpcodeTable68},
    /*       69 => 0x0069*/ {&decoder64, NULL},  //BxOpcodeTable69},
    /*       6A => 0x006A*/ {&decoder64, NULL},  //BxOpcodeTable6A},
    /*       6B => 0x006B*/ {&decoder64, NULL},  //BxOpcodeTable6B},
    /*       6C => 0x006C*/ {&decoder64, NULL},  //BxOpcodeTable6C},
    /*       6D => 0x006D*/ {&decoder64, NULL},  //BxOpcodeTable6D},
    /*       6E => 0x006E*/ {&decoder64, NULL},  //BxOpcodeTable6E},
    /*       6F => 0x006F*/ {&decoder64, NULL},  //BxOpcodeTable6F},
    /*       70 => 0x0070*/ {&decoder64, NULL},  //BxOpcodeTable70},
    /*       71 => 0x0071*/ {&decoder64, NULL},  //BxOpcodeTable71},
    /*       72 => 0x0072*/ {&decoder64, NULL},  //BxOpcodeTable72},
    /*       73 => 0x0073*/ {&decoder64, NULL},  //BxOpcodeTable73},
    /*       74 => 0x0074*/ {&decoder64, NULL},  //BxOpcodeTable74},
    /*       75 => 0x0075*/ {&decoder64, NULL},  //BxOpcodeTable75},
    /*       76 => 0x0076*/ {&decoder64, NULL},  //BxOpcodeTable76},
    /*       77 => 0x0077*/ {&decoder64, NULL},  //BxOpcodeTable77},
    /*       78 => 0x0078*/ {&decoder64, NULL},  //BxOpcodeTable78},
    /*       79 => 0x0079*/ {&decoder64, NULL},  //BxOpcodeTable79},
    /*       7A => 0x007A*/ {&decoder64, NULL},  //BxOpcodeTable7A},
    /*       7B => 0x007B*/ {&decoder64, NULL},  //BxOpcodeTable7B},
    /*       7C => 0x007C*/ {&decoder64, NULL},  //BxOpcodeTable7C},
    /*       7D => 0x007D*/ {&decoder64, NULL},  //BxOpcodeTable7D},
    /*       7E => 0x007E*/ {&decoder64, NULL},  //BxOpcodeTable7E},
    /*       7F => 0x007F*/ {&decoder64, NULL},  //BxOpcodeTable7F},
    /*       80 => 0x0080*/ {&decoder64, NULL},  //BxOpcodeTable80},
    /*       81 => 0x0081*/ {&decoder64, NULL},  //BxOpcodeTable81},
    /*       82 => 0x0082*/ {&decoder64, NULL},  //BxOpcodeTable82},
    /*       83 => 0x0083*/ {&decoder64, NULL},  //BxOpcodeTable83},
    /*       84 => 0x0084*/ {&decoder64, NULL},  //BxOpcodeTable84},
    /*       85 => 0x0085*/ {&decoder64, NULL},  //BxOpcodeTable85},
    /*       86 => 0x0086*/ {&decoder64, NULL},  //BxOpcodeTable86},
    /*       87 => 0x0087*/ {&decoder64, NULL},  //BxOpcodeTable87},
    /*       88 => 0x0088*/ {&decoder64, NULL},  //BxOpcodeTable88},
    /*       89 => 0x0089*/ {&decoder64, NULL},  //BxOpcodeTable89},
    /*       8A => 0x008A*/ {&decoder64, NULL},  //BxOpcodeTable8A},
    /*       8B => 0x008B*/ {&decoder64, NULL},  //BxOpcodeTable8B},
    /*       8C => 0x008C*/ {&decoder64, NULL},  //BxOpcodeTable8C},
    /*       8D => 0x008D*/ {&decoder64, NULL},  //BxOpcodeTable8D},
    /*       8E => 0x008E*/ {&decoder64, NULL},  //BxOpcodeTable8E},
    /*       8F => 0x008F*/ {&decoder64, NULL},  //BxOpcodeTable8F},
    /*       90 => 0x0090*/ {&decoder64, NULL},  //BxOpcodeTable90},
    /*       91 => 0x0091*/ {&decoder64, NULL},  //BxOpcodeTable91},
    /*       92 => 0x0092*/ {&decoder64, NULL},  //BxOpcodeTable92},
    /*       93 => 0x0093*/ {&decoder64, NULL},  //BxOpcodeTable93},
    /*       94 => 0x0094*/ {&decoder64, NULL},  //BxOpcodeTable94},
    /*       95 => 0x0095*/ {&decoder64, NULL},  //BxOpcodeTable95},
    /*       96 => 0x0096*/ {&decoder64, NULL},  //BxOpcodeTable96},
    /*       97 => 0x0097*/ {&decoder64, NULL},  //},BxOpcodeTable97
    /*       98 => 0x0098*/ {&decoder64, NULL},  //BxOpcodeTable98},
    /*       99 => 0x0099*/ {&decoder64, NULL},  //BxOpcodeTable99},
    /*       9A => 0x009A*/ {&decoder64, NULL},  //BxOpcodeTable9A},
    /*       9B => 0x009B*/ {&decoder64, NULL},  //BxOpcodeTable9B},
    /*       9C => 0x009C*/ {&decoder64, NULL},  //BxOpcodeTable9C},
    /*       9D => 0x009D*/ {&decoder64, NULL},  //BxOpcodeTable9D},
    /*       9E => 0x009E*/ {&decoder64, NULL},  //BxOpcodeTable9E},
    /*       9F => 0x009F*/ {&decoder64, NULL},  //BxOpcodeTable9F},
    /*       A0 => 0x00A0*/ {&decoder64, NULL},  //BxOpcodeTableA0},
    /*       A1 => 0x00A1*/ {&decoder64, NULL},  //BxOpcodeTableA1},
    /*       A2 => 0x00A2*/ {&decoder64, NULL},  //BxOpcodeTableA2},
    /*       A3 => 0x00A3*/ {&decoder64, NULL},  //BxOpcodeTableA3},
    /*       A4 => 0x00A4*/ {&decoder64, NULL},  //BxOpcodeTableA4},
    /*       A5 => 0x00A5*/ {&decoder64, NULL},  //BxOpcodeTableA5},
    /*       A6 => 0x00A6*/ {&decoder64, NULL},  //BxOpcodeTableA6},
    /*       A7 => 0x00A7*/ {&decoder64, NULL},  //BxOpcodeTableA7},
    /*       A8 => 0x00A8*/ {&decoder64, NULL},  //BxOpcodeTableA8},
    /*       A9 => 0x00A9*/ {&decoder64, NULL},  //BxOpcodeTableA9},
    /*       AA => 0x00AA*/ {&decoder64, NULL},  //BxOpcodeTableAA},
    /*       AB => 0x00AB*/ {&decoder64, NULL},  //BxOpcodeTableAB},
    /*       AC => 0x00AC*/ {&decoder64, NULL},  //BxOpcodeTableAC},
    /*       AD => 0x00AD*/ {&decoder64, NULL},  //BxOpcodeTableAD},
    /*       AE => 0x00AE*/ {&decoder64, NULL},  //BxOpcodeTableAE},
    /*       AF => 0x00AF*/ {&decoder64, NULL},  //BxOpcodeTableAF},
    /*       B0 => 0x00B0*/ {&decoder64, NULL},  //BxOpcodeTableB0},
    /*       B1 => 0x00B1*/ {&decoder64, NULL},  //BxOpcodeTableB1},
    /*       B2 => 0x00B2*/ {&decoder64, NULL},  //BxOpcodeTableB2},
    /*       B3 => 0x00B3*/ {&decoder64, NULL},  //BxOpcodeTableB3},
    /*       B4 => 0x00B4*/ {&decoder64, NULL},  //BxOpcodeTableB4},
    /*       B5 => 0x00B5*/ {&decoder64, NULL},  //BxOpcodeTableB5},
    /*       B6 => 0x00B6*/ {&decoder64, NULL},  //BxOpcodeTableB6},
    /*       B7 => 0x00B7*/ {&decoder64, NULL},  //BxOpcodeTableB7},
    /*       B8 => 0x00B8*/ {&decoder64, NULL},  //BxOpcodeTableB8},
    /*       B9 => 0x00B9*/ {&decoder64, NULL},  //BxOpcodeTableB9},
    /*       BA => 0x00BA*/ {&decoder64, NULL},  //BxOpcodeTableBA},
    /*       BB => 0x00BB*/ {&decoder64, NULL},  //BxOpcodeTableBB},
    /*       BC => 0x00BC*/ {&decoder64, NULL},  //BxOpcodeTableBC},
    /*       BD => 0x00BD*/ {&decoder64, NULL},  //BxOpcodeTableBD},
    /*       BE => 0x00BE*/ {&decoder64, NULL},  //BxOpcodeTableBE},
    /*       BF => 0x00BF*/ {&decoder64, NULL},  //BxOpcodeTableBF},
    /*       C0 => 0x00C0*/ {&decoder64, NULL},  //BxOpcodeTableC0},
    /*       C1 => 0x00C1*/ {&decoder64, NULL},  //BxOpcodeTableC1},
    /*       C2 => 0x00C2*/ {&decoder64, NULL},  //BxOpcodeTableC2},
    /*       C3 => 0x00C3*/ {&decoder64, NULL},  //BxOpcodeTableC3},
    /*       C4 => 0x00C4*/ {&decoder64, NULL},  //BxOpcodeTableC4},
    /*       C5 => 0x00C5*/ {&decoder64, NULL},  //BxOpcodeTableC5},
    /*       C6 => 0x00C6*/ {&decoder64, NULL},  //BxOpcodeTableC6},
    /*       C7 => 0x00C7*/ {&decoder64, NULL},  //BxOpcodeTableC7},
    /*       C8 => 0x00C8*/ {&decoder64, NULL},  //BxOpcodeTableC8},
    /*       C9 => 0x00C9*/ {&decoder64, NULL},  //BxOpcodeTableC9},
    /*       CA => 0x00CA*/ {&decoder64, NULL},  //BxOpcodeTableCA},
    /*       CB => 0x00CB*/ {&decoder64, NULL},  //BxOpcodeTableCB},
    /*       CC => 0x00CC*/ {&decoder64, NULL},  //BxOpcodeTableCC},
    /*       CD => 0x00CD*/ {&decoder64, NULL},  //BxOpcodeTableCD},
    /*       CE => 0x00CE*/ {&decoder64, NULL},  //BxOpcodeTableCE},
    /*       CF => 0x00CF*/ {&decoder64, NULL},  //BxOpcodeTableCF},
    /*       D0 => 0x00D0*/ {&decoder64, NULL},  //BxOpcodeTableD0},
    /*       D1 => 0x00D1*/ {&decoder64, NULL},  //BxOpcodeTableD1},
    /*       D2 => 0x00D2*/ {&decoder64, NULL},  //BxOpcodeTableD2},
    /*       D3 => 0x00D3*/ {&decoder64, NULL},  //BxOpcodeTableD3},
    /*       D4 => 0x00D4*/ {&decoder64, NULL},  //BxOpcodeTableD4},
    /*       D5 => 0x00D5*/ {&decoder64, NULL},  //BxOpcodeTableD5},
    /*       D6 => 0x00D6*/ {&decoder64, NULL},  //BxOpcodeTableD6},
    /*       D7 => 0x00D7*/ {&decoder64, NULL},  //BxOpcodeTableD7},
    /*       D8 => 0x00D8*/ {&decoder64, NULL},  //BxOpcodeTableD8},
    /*       D9 => 0x00D9*/ {&decoder64, NULL},  //BxOpcodeTableD9},
    /*       DA => 0x00DA*/ {&decoder64, NULL},  //BxOpcodeTableDA},
    /*       DB => 0x00DB*/ {&decoder64, NULL},  //BxOpcodeTableDB},
    /*       DC => 0x00DC*/ {&decoder64, NULL},  //BxOpcodeTableDC},
    /*       DD => 0x00DD*/ {&decoder64, NULL},  //BxOpcodeTableDD},
    /*       DE => 0x00DE*/ {&decoder64, NULL},  //BxOpcodeTableDE},
    /*       DF => 0x00DF*/ {&decoder64, NULL},  //BxOpcodeTableDF},
    /*       E0 => 0x00E0*/ {&decoder64, NULL},  //BxOpcodeTableE0},
    /*       E1 => 0x00E1*/ {&decoder64, NULL},  //BxOpcodeTableE1},
    /*       E2 => 0x00E2*/ {&decoder64, NULL},  //BxOpcodeTableE2},
    /*       E3 => 0x00E3*/ {&decoder64, NULL},  //BxOpcodeTableE3},
    /*       E4 => 0x00E4*/ {&decoder64, NULL},  //BxOpcodeTableE4},
    /*       E5 => 0x00E5*/ {&decoder64, NULL},  //BxOpcodeTableE5},
    /*       E6 => 0x00E6*/ {&decoder64, NULL},  //BxOpcodeTableE6},
    /*       E7 => 0x00E7*/ {&decoder64, NULL},  //BxOpcodeTableE7},
    /*       E8 => 0x00E8*/ {&decoder64, NULL},  //BxOpcodeTableE8},
    /*       E9 => 0x00E9*/ {&decoder64, NULL},  //BxOpcodeTableE9},
    /*       EA => 0x00EA*/ {&decoder64, NULL},  //BxOpcodeTableEA},
    /*       EB => 0x00EB*/ {&decoder64, NULL},  //BxOpcodeTableEB},
    /*       EC => 0x00EC*/ {&decoder64, NULL},  //BxOpcodeTableEC},
    /*       ED => 0x00ED*/ {&decoder64, NULL},  //BxOpcodeTableED},
    /*       EE => 0x00EE*/ {&decoder64, NULL},  //BxOpcodeTableEE},
    /*       EF => 0x00EF*/ {&decoder64, NULL},  //BxOpcodeTableEF},
    /*       F0 => 0x00F0*/ {&decoder64, NULL},  //BxOpcodeTableF0},
    /*       F1 => 0x00F1*/ {&decoder64, NULL},  //BxOpcodeTableF1},
    /*       F2 => 0x00F2*/ {&decoder64, NULL},  //BxOpcodeTableF2},
    /*       F3 => 0x00F3*/ {&decoder64, NULL},  //BxOpcodeTableF3},
    /*       F4 => 0x00F4*/ {&decoder64, NULL},  //BxOpcodeTableF4},
    /*       F5 => 0x00F5*/ {&decoder64, NULL},  //BxOpcodeTableF5},
    /*       F6 => 0x00F6*/ {&decoder64, NULL},  //BxOpcodeTableF6},
    /*       F7 => 0x00F7*/ {&decoder64, NULL},  //BxOpcodeTableF7},
    /*       F8 => 0x00F8*/ {&decoder64, NULL},  //BxOpcodeTableF8},
    /*       F9 => 0x00F9*/ {&decoder64, NULL},  //BxOpcodeTableF9},
    /*       FA => 0x00FA*/ {&decoder64, NULL},  //BxOpcodeTableFA},
    /*       FB => 0x00FB*/ {&decoder64, NULL},  //BxOpcodeTableFB},
    /*       FC => 0x00FC*/ {&decoder64, NULL},  //BxOpcodeTableFC},
    /*       FD => 0x00FD*/ {&decoder64, NULL},  //BxOpcodeTableFD},
    /*       FE => 0x00FE*/ {&decoder64, NULL},  //BxOpcodeTableFE},
    /*       FF => 0x00FF*/ {&decoder64, NULL},  //BxOpcodeTableFF},
    /*    0F 00 => 0x0100*/ {&decoder64, NULL},  //BxOpcodeTable0F00},
    /*    0F 01 => 0x0101*/ {&decoder64, NULL},  //BxOpcodeTable0F01},
    /*    0F 02 => 0x0102*/ {&decoder64, NULL},  //BxOpcodeTable0F02},
    /*    0F 03 => 0x0103*/ {&decoder64, NULL},  //BxOpcodeTable0F03},
    /*    0F 04 => 0x0104*/ {&decoder64, NULL},  //BxOpcodeTable0F04},
    /*    0F 05 => 0x0105*/ {&decoder64, NULL},  //BxOpcodeTable0F05},
    /*    0F 06 => 0x0106*/ {&decoder64, NULL},  //BxOpcodeTable0F06},
    /*    0F 07 => 0x0107*/ {&decoder64, NULL},  //BxOpcodeTable0F07},
    /*    0F 08 => 0x0108*/ {&decoder64, NULL},  //BxOpcodeTable0F08},
    /*    0F 09 => 0x0109*/ {&decoder64, NULL},  //BxOpcodeTable0F09},
    /*    0F 0A => 0x010A*/ {&decoder64, NULL},  //BxOpcodeTable0F0A},
    /*    0F 0B => 0x010B*/ {&decoder64, NULL},  //BxOpcodeTable0F0B},
    /*    0F 0C => 0x010C*/ {&decoder64, NULL},  //BxOpcodeTable0F0C},
    /*    0F 0D => 0x010D*/ {&decoder64, NULL},  //BxOpcodeTable0F0D},
    /*    0F 0E => 0x010E*/ {&decoder64, NULL},  //BxOpcodeTable0F0E},
    /*    0F 0F => 0x010F*/ {&decoder64, NULL},  //BxOpcodeTable0F0F},
    /*    0F 10 => 0x0110*/ {&decoder64, NULL},  //BxOpcodeTable0F10},
    /*    0F 11 => 0x0111*/ {&decoder64, NULL},  //BxOpcodeTable0F11},
    /*    0F 12 => 0x0112*/ {&decoder64, NULL},  //BxOpcodeTable0F12},
    /*    0F 13 => 0x0113*/ {&decoder64, NULL},  //BxOpcodeTable0F13},
    /*    0F 14 => 0x0114*/ {&decoder64, NULL},  //BxOpcodeTable0F14},
    /*    0F 15 => 0x0115*/ {&decoder64, NULL},  //BxOpcodeTable0F15},
    /*    0F 16 => 0x0116*/ {&decoder64, NULL},  //BxOpcodeTable0F16},
    /*    0F 17 => 0x0117*/ {&decoder64, NULL},  //BxOpcodeTable0F17},
    /*    0F 18 => 0x0118*/ {&decoder64, NULL},  //BxOpcodeTable0F18},
    /*    0F 19 => 0x0119*/ {&decoder64, NULL},  //BxOpcodeTable0F19},
    /*    0F 1A => 0x011A*/ {&decoder64, NULL},  //BxOpcodeTable0F1A},
    /*    0F 1B => 0x011B*/ {&decoder64, NULL},  //BxOpcodeTable0F1B},
    /*    0F 1C => 0x011C*/ {&decoder64, NULL},  //BxOpcodeTable0F1C},
    /*    0F 1D => 0x011D*/ {&decoder64, NULL},  //BxOpcodeTable0F1D},
    /*    0F 1E => 0x011E*/ {&decoder64, NULL},  //BxOpcodeTable0F1E},
    /*    0F 1F => 0x011F*/ {&decoder64, NULL},  //BxOpcodeTable0F1F},
    /*    0F 20 => 0x0120*/ {&decoder64, NULL},  //BxOpcodeTable0F20},
    /*    0F 21 => 0x0121*/ {&decoder64, NULL},  //BxOpcodeTable0F21},
    /*    0F 22 => 0x0122*/ {&decoder64, NULL},  //BxOpcodeTable0F22},
    /*    0F 23 => 0x0123*/ {&decoder64, NULL},  //BxOpcodeTable0F23},
    /*    0F 24 => 0x0124*/ {&decoder64, NULL},  //BxOpcodeTable0F24},
    /*    0F 25 => 0x0125*/ {&decoder64, NULL},  //BxOpcodeTable0F25},
    /*    0F 26 => 0x0126*/ {&decoder64, NULL},  //BxOpcodeTable0F26},
    /*    0F 27 => 0x0127*/ {&decoder64, NULL},  //BxOpcodeTable0F27},
    /*    0F 28 => 0x0128*/ {&decoder64, NULL},  //BxOpcodeTable0F28},
    /*    0F 29 => 0x0129*/ {&decoder64, NULL},  //BxOpcodeTable0F29},
    /*    0F 2A => 0x012A*/ {&decoder64, NULL},  //BxOpcodeTable0F2A},
    /*    0F 2B => 0x012B*/ {&decoder64, NULL},  //BxOpcodeTable0F2B},
    /*    0F 2C => 0x012C*/ {&decoder64, NULL},  //BxOpcodeTable0F2C},
    /*    0F 2D => 0x012D*/ {&decoder64, NULL},  //BxOpcodeTable0F2D},
    /*    0F 2E => 0x012E*/ {&decoder64, NULL},  //BxOpcodeTable0F2E},
    /*    0F 2F => 0x012F*/ {&decoder64, NULL},  //BxOpcodeTable0F2F},
    /*    0F 30 => 0x0130*/ {&decoder64, NULL},  //BxOpcodeTable0F30},
    /*    0F 31 => 0x0131*/ {&decoder64, NULL},  //BxOpcodeTable0F31},
    /*    0F 32 => 0x0132*/ {&decoder64, NULL},  //BxOpcodeTable0F32},
    /*    0F 33 => 0x0133*/ {&decoder64, NULL},  //BxOpcodeTable0F33},
    /*    0F 34 => 0x0134*/ {&decoder64, NULL},  //BxOpcodeTable0F34},
    /*    0F 35 => 0x0135*/ {&decoder64, NULL},  //BxOpcodeTable0F35},
    /*    0F 36 => 0x0136*/ {&decoder64, NULL},  //BxOpcodeTable0F36},
    /*    0F 37 => 0x0137*/ {&decoder64, NULL},  //BxOpcodeTable0F37},
    /*    0F 38 => 0x0138*/ {&decoder64, NULL},  //BxOpcodeTable0F38},
    /*    0F 39 => 0x0139*/ {&decoder64, NULL},  //BxOpcodeTable0F39},
    /*    0F 3A => 0x013A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A},
    /*    0F 3B => 0x013B*/ {&decoder64, NULL},  //BxOpcodeTable0F3B},
    /*    0F 3C => 0x013C*/ {&decoder64, NULL},  //BxOpcodeTable0F3C},
    /*    0F 3D => 0x013D*/ {&decoder64, NULL},  //BxOpcodeTable0F3D},
    /*    0F 3E => 0x013E*/ {&decoder64, NULL},  //BxOpcodeTable0F3E},
    /*    0F 3F => 0x013F*/ {&decoder64, NULL},  //BxOpcodeTable0F3F},
    /*    0F 40 => 0x0140*/ {&decoder64, NULL},  //BxOpcodeTable0F40},
    /*    0F 41 => 0x0141*/ {&decoder64, NULL},  //BxOpcodeTable0F41},
    /*    0F 42 => 0x0142*/ {&decoder64, NULL},  //BxOpcodeTable0F42},
    /*    0F 43 => 0x0143*/ {&decoder64, NULL},  //BxOpcodeTable0F43},
    /*    0F 44 => 0x0144*/ {&decoder64, NULL},  //BxOpcodeTable0F44},
    /*    0F 45 => 0x0145*/ {&decoder64, NULL},  //BxOpcodeTable0F45},
    /*    0F 46 => 0x0146*/ {&decoder64, NULL},  //BxOpcodeTable0F46},
    /*    0F 47 => 0x0147*/ {&decoder64, NULL},  //BxOpcodeTable0F47},
    /*    0F 48 => 0x0148*/ {&decoder64, NULL},  //BxOpcodeTable0F48},
    /*    0F 49 => 0x0149*/ {&decoder64, NULL},  //BxOpcodeTable0F49},
    /*    0F 4A => 0x014A*/ {&decoder64, NULL},  //BxOpcodeTable0F4A},
    /*    0F 4B => 0x014B*/ {&decoder64, NULL},  //BxOpcodeTable0F4B},
    /*    0F 4C => 0x014C*/ {&decoder64, NULL},  //BxOpcodeTable0F4C},
    /*    0F 4D => 0x014D*/ {&decoder64, NULL},  //BxOpcodeTable0F4D},
    /*    0F 4E => 0x014E*/ {&decoder64, NULL},  //BxOpcodeTable0F4E},
    /*    0F 4F => 0x014F*/ {&decoder64, NULL},  //BxOpcodeTable0F4F},
    /*    0F 50 => 0x0150*/ {&decoder64, NULL},  //BxOpcodeTable0F50},
    /*    0F 51 => 0x0151*/ {&decoder64, NULL},  //BxOpcodeTable0F51},
    /*    0F 52 => 0x0152*/ {&decoder64, NULL},  //BxOpcodeTable0F52},
    /*    0F 53 => 0x0153*/ {&decoder64, NULL},  //BxOpcodeTable0F53},
    /*    0F 54 => 0x0154*/ {&decoder64, NULL},  //BxOpcodeTable0F54},
    /*    0F 55 => 0x0155*/ {&decoder64, NULL},  //BxOpcodeTable0F55},
    /*    0F 56 => 0x0156*/ {&decoder64, NULL},  //BxOpcodeTable0F56},
    /*    0F 57 => 0x0157*/ {&decoder64, NULL},  //BxOpcodeTable0F57},
    /*    0F 58 => 0x0158*/ {&decoder64, NULL},  //BxOpcodeTable0F58},
    /*    0F 59 => 0x0159*/ {&decoder64, NULL},  //BxOpcodeTable0F59},
    /*    0F 5A => 0x015A*/ {&decoder64, NULL},  //BxOpcodeTable0F5A},
    /*    0F 5B => 0x015B*/ {&decoder64, NULL},  //BxOpcodeTable0F5B},
    /*    0F 5C => 0x015C*/ {&decoder64, NULL},  //BxOpcodeTable0F5C},
    /*    0F 5D => 0x015D*/ {&decoder64, NULL},  //BxOpcodeTable0F5D},
    /*    0F 5E => 0x015E*/ {&decoder64, NULL},  //BxOpcodeTable0F5E},
    /*    0F 5F => 0x015F*/ {&decoder64, NULL},  //BxOpcodeTable0F5F},
    /*    0F 60 => 0x0160*/ {&decoder64, NULL},  //BxOpcodeTable0F60},
    /*    0F 61 => 0x0161*/ {&decoder64, NULL},  //BxOpcodeTable0F61},
    /*    0F 62 => 0x0162*/ {&decoder64, NULL},  //BxOpcodeTable0F62},
    /*    0F 63 => 0x0163*/ {&decoder64, NULL},  //BxOpcodeTable0F63},
    /*    0F 64 => 0x0164*/ {&decoder64, NULL},  //BxOpcodeTable0F64},
    /*    0F 65 => 0x0165*/ {&decoder64, NULL},  //BxOpcodeTable0F65},
    /*    0F 66 => 0x0166*/ {&decoder64, NULL},  //BxOpcodeTable0F66},
    /*    0F 67 => 0x0167*/ {&decoder64, NULL},  //BxOpcodeTable0F67},
    /*    0F 68 => 0x0168*/ {&decoder64, NULL},  //BxOpcodeTable0F68},
    /*    0F 69 => 0x0169*/ {&decoder64, NULL},  //BxOpcodeTable0F69},
    /*    0F 6A => 0x016A*/ {&decoder64, NULL},  //BxOpcodeTable0F6A},
    /*    0F 6B => 0x016B*/ {&decoder64, NULL},  //BxOpcodeTable0F6B},
    /*    0F 6C => 0x016C*/ {&decoder64, NULL},  //BxOpcodeTable0F6C},
    /*    0F 6D => 0x016D*/ {&decoder64, NULL},  //BxOpcodeTable0F6D},
    /*    0F 6E => 0x016E*/ {&decoder64, NULL},  //BxOpcodeTable0F6E},
    /*    0F 6F => 0x016F*/ {&decoder64, NULL},  //BxOpcodeTable0F6F},
    /*    0F 70 => 0x0170*/ {&decoder64, NULL},  //BxOpcodeTable0F70},
    /*    0F 71 => 0x0171*/ {&decoder64, NULL},  //BxOpcodeTable0F71},
    /*    0F 72 => 0x0172*/ {&decoder64, NULL},  //BxOpcodeTable0F72},
    /*    0F 73 => 0x0173*/ {&decoder64, NULL},  //BxOpcodeTable0F73},
    /*    0F 74 => 0x0174*/ {&decoder64, NULL},  //BxOpcodeTable0F74},
    /*    0F 75 => 0x0175*/ {&decoder64, NULL},  //BxOpcodeTable0F75},
    /*    0F 76 => 0x0176*/ {&decoder64, NULL},  //BxOpcodeTable0F76},
    /*    0F 77 => 0x0177*/ {&decoder64, NULL},  //BxOpcodeTable0F77},
    /*    0F 78 => 0x0178*/ {&decoder64, NULL},  //BxOpcodeTable0F78},
    /*    0F 79 => 0x0179*/ {&decoder64, NULL},  //BxOpcodeTable0F79},
    /*    0F 7A => 0x017A*/ {&decoder64, NULL},  //BxOpcodeTable0F7A},
    /*    0F 7B => 0x017B*/ {&decoder64, NULL},  //BxOpcodeTable0F7B},
    /*    0F 7C => 0x017C*/ {&decoder64, NULL},  //BxOpcodeTable0F7C},
    /*    0F 7D => 0x017D*/ {&decoder64, NULL},  //BxOpcodeTable0F7D},
    /*    0F 7E => 0x017E*/ {&decoder64, NULL},  //BxOpcodeTable0F7E},
    /*    0F 7F => 0x017F*/ {&decoder64, NULL},  //BxOpcodeTable0F7F},
    /*    0F 80 => 0x0180*/ {&decoder64, NULL},  //BxOpcodeTable0F80},
    /*    0F 81 => 0x0181*/ {&decoder64, NULL},  //BxOpcodeTable0F81},
    /*    0F 82 => 0x0182*/ {&decoder64, NULL},  //BxOpcodeTable0F82},
    /*    0F 83 => 0x0183*/ {&decoder64, NULL},  //BxOpcodeTable0F83},
    /*    0F 84 => 0x0184*/ {&decoder64, NULL},  //BxOpcodeTable0F84},
    /*    0F 85 => 0x0185*/ {&decoder64, NULL},  //BxOpcodeTable0F85},
    /*    0F 86 => 0x0186*/ {&decoder64, NULL},  //BxOpcodeTable0F86},
    /*    0F 87 => 0x0187*/ {&decoder64, NULL},  //BxOpcodeTable0F87},
    /*    0F 88 => 0x0188*/ {&decoder64, NULL},  //BxOpcodeTable0F88},
    /*    0F 89 => 0x0189*/ {&decoder64, NULL},  //BxOpcodeTable0F89},
    /*    0F 8A => 0x018A*/ {&decoder64, NULL},  //BxOpcodeTable0F8A},
    /*    0F 8B => 0x018B*/ {&decoder64, NULL},  //BxOpcodeTable0F8B},
    /*    0F 8C => 0x018C*/ {&decoder64, NULL},  //BxOpcodeTable0F8C},
    /*    0F 8D => 0x018D*/ {&decoder64, NULL},  //BxOpcodeTable0F8D},
    /*    0F 8E => 0x018E*/ {&decoder64, NULL},  //BxOpcodeTable0F8E},
    /*    0F 8F => 0x018F*/ {&decoder64, NULL},  //BxOpcodeTable0F8F},
    /*    0F 90 => 0x0190*/ {&decoder64, NULL},  //BxOpcodeTable0F90},
    /*    0F 91 => 0x0191*/ {&decoder64, NULL},  //BxOpcodeTable0F91},
    /*    0F 92 => 0x0192*/ {&decoder64, NULL},  //BxOpcodeTable0F92},
    /*    0F 93 => 0x0193*/ {&decoder64, NULL},  //BxOpcodeTable0F93},
    /*    0F 94 => 0x0194*/ {&decoder64, NULL},  //BxOpcodeTable0F94},
    /*    0F 95 => 0x0195*/ {&decoder64, NULL},  //BxOpcodeTable0F95},
    /*    0F 96 => 0x0196*/ {&decoder64, NULL},  //BxOpcodeTable0F96},
    /*    0F 97 => 0x0197*/ {&decoder64, NULL},  //BxOpcodeTable0F97},
    /*    0F 98 => 0x0198*/ {&decoder64, NULL},  //BxOpcodeTable0F98},
    /*    0F 99 => 0x0199*/ {&decoder64, NULL},  //BxOpcodeTable0F99},
    /*    0F 9A => 0x019A*/ {&decoder64, NULL},  //BxOpcodeTable0F9A},
    /*    0F 9B => 0x019B*/ {&decoder64, NULL},  //BxOpcodeTable0F9B},
    /*    0F 9C => 0x019C*/ {&decoder64, NULL},  //BxOpcodeTable0F9C},
    /*    0F 9D => 0x019D*/ {&decoder64, NULL},  //BxOpcodeTable0F9D},
    /*    0F 9E => 0x019E*/ {&decoder64, NULL},  //BxOpcodeTable0F9E},
    /*    0F 9F => 0x019F*/ {&decoder64, NULL},  //BxOpcodeTable0F9F},
    /*    0F A0 => 0x01A0*/ {&decoder64, NULL},  //BxOpcodeTable0FA0},
    /*    0F A1 => 0x01A1*/ {&decoder64, NULL},  //BxOpcodeTable0FA1},
    /*    0F A2 => 0x01A2*/ {&decoder64, NULL},  //BxOpcodeTable0FA2},
    /*    0F A3 => 0x01A3*/ {&decoder64, NULL},  //BxOpcodeTable0FA3},
    /*    0F A4 => 0x01A4*/ {&decoder64, NULL},  //BxOpcodeTable0FA4},
    /*    0F A5 => 0x01A5*/ {&decoder64, NULL},  //BxOpcodeTable0FA5},
    /*    0F A6 => 0x01A6*/ {&decoder64, NULL},  //BxOpcodeTable0FA6},
    /*    0F A7 => 0x01A7*/ {&decoder64, NULL},  //BxOpcodeTable0FA7},
    /*    0F A8 => 0x01A8*/ {&decoder64, NULL},  //BxOpcodeTable0FA8},
    /*    0F A9 => 0x01A9*/ {&decoder64, NULL},  //BxOpcodeTable0FA9},
    /*    0F AA => 0x01AA*/ {&decoder64, NULL},  //BxOpcodeTable0FAA},
    /*    0F AB => 0x01AB*/ {&decoder64, NULL},  //BxOpcodeTable0FAB},
    /*    0F AC => 0x01AC*/ {&decoder64, NULL},  //BxOpcodeTable0FAC},
    /*    0F AD => 0x01AD*/ {&decoder64, NULL},  //BxOpcodeTable0FAD},
    /*    0F AE => 0x01AE*/ {&decoder64, NULL},  //BxOpcodeTable0FAE},
    /*    0F AF => 0x01AF*/ {&decoder64, NULL},  //BxOpcodeTable0FAF},
    /*    0F B0 => 0x01B0*/ {&decoder64, NULL},  //BxOpcodeTable0FB0},
    /*    0F B1 => 0x01B1*/ {&decoder64, NULL},  //BxOpcodeTable0FB1},
    /*    0F B2 => 0x01B2*/ {&decoder64, NULL},  //BxOpcodeTable0FB2},
    /*    0F B3 => 0x01B3*/ {&decoder64, NULL},  //BxOpcodeTable0FB3},
    /*    0F B4 => 0x01B4*/ {&decoder64, NULL},  //BxOpcodeTable0FB4},
    /*    0F B5 => 0x01B5*/ {&decoder64, NULL},  //BxOpcodeTable0FB5},
    /*    0F B6 => 0x01B6*/ {&decoder64, NULL},  //BxOpcodeTable0FB6},
    /*    0F B7 => 0x01B7*/ {&decoder64, NULL},  //BxOpcodeTable0FB7},
    /*    0F B8 => 0x01B8*/ {&decoder64, NULL},  //BxOpcodeTable0FB8},
    /*    0F B9 => 0x01B9*/ {&decoder64, NULL},  //BxOpcodeTable0FB9},
    /*    0F BA => 0x01BA*/ {&decoder64, NULL},  //BxOpcodeTable0FBA},
    /*    0F BB => 0x01BB*/ {&decoder64, NULL},  //BxOpcodeTable0FBB},
    /*    0F BC => 0x01BC*/ {&decoder64, NULL},  //BxOpcodeTable0FBC},
    /*    0F BD => 0x01BD*/ {&decoder64, NULL},  //BxOpcodeTable0FBD},
    /*    0F BE => 0x01BE*/ {&decoder64, NULL},  //BxOpcodeTable0FBE},
    /*    0F BF => 0x01BF*/ {&decoder64, NULL},  //BxOpcodeTable0FBF},
    /*    0F C0 => 0x01C0*/ {&decoder64, NULL},  //BxOpcodeTable0FC0},
    /*    0F C1 => 0x01C1*/ {&decoder64, NULL},  //BxOpcodeTable0FC1},
    /*    0F C2 => 0x01C2*/ {&decoder64, NULL},  //BxOpcodeTable0FC2},
    /*    0F C3 => 0x01C3*/ {&decoder64, NULL},  //BxOpcodeTable0FC3},
    /*    0F C4 => 0x01C4*/ {&decoder64, NULL},  //BxOpcodeTable0FC4},
    /*    0F C5 => 0x01C5*/ {&decoder64, NULL},  //BxOpcodeTable0FC5},
    /*    0F C6 => 0x01C6*/ {&decoder64, NULL},  //BxOpcodeTable0FC6},
    /*    0F C7 => 0x01C7*/ {&decoder64, NULL},  //BxOpcodeTable0FC7},
    /*    0F C8 => 0x01C8*/ {&decoder64, NULL},  //BxOpcodeTable0FC8},
    /*    0F C9 => 0x01C9*/ {&decoder64, NULL},  //BxOpcodeTable0FC9},
    /*    0F CA => 0x01CA*/ {&decoder64, NULL},  //BxOpcodeTable0FCA},
    /*    0F CB => 0x01CB*/ {&decoder64, NULL},  //BxOpcodeTable0FCB},
    /*    0F CC => 0x01CC*/ {&decoder64, NULL},  //BxOpcodeTable0FCC},
    /*    0F CD => 0x01CD*/ {&decoder64, NULL},  //BxOpcodeTable0FCD},
    /*    0F CE => 0x01CE*/ {&decoder64, NULL},  //BxOpcodeTable0FCE},
    /*    0F CF => 0x01CF*/ {&decoder64, NULL},  //BxOpcodeTable0FCF},
    /*    0F D0 => 0x01D0*/ {&decoder64, NULL},  //BxOpcodeTable0FD0},
    /*    0F D1 => 0x01D1*/ {&decoder64, NULL},  //BxOpcodeTable0FD1},
    /*    0F D2 => 0x01D2*/ {&decoder64, NULL},  //BxOpcodeTable0FD2},
    /*    0F D3 => 0x01D3*/ {&decoder64, NULL},  //BxOpcodeTable0FD3},
    /*    0F D4 => 0x01D4*/ {&decoder64, NULL},  //BxOpcodeTable0FD4},
    /*    0F D5 => 0x01D5*/ {&decoder64, NULL},  //BxOpcodeTable0FD5},
    /*    0F D6 => 0x01D6*/ {&decoder64, NULL},  //BxOpcodeTable0FD6},
    /*    0F D7 => 0x01D7*/ {&decoder64, NULL},  //BxOpcodeTable0FD7},
    /*    0F D8 => 0x01D8*/ {&decoder64, NULL},  //BxOpcodeTable0FD8},
    /*    0F D9 => 0x01D9*/ {&decoder64, NULL},  //BxOpcodeTable0FD9},
    /*    0F DA => 0x01DA*/ {&decoder64, NULL},  //BxOpcodeTable0FDA},
    /*    0F DB => 0x01DB*/ {&decoder64, NULL},  //BxOpcodeTable0FDB},
    /*    0F DC => 0x01DC*/ {&decoder64, NULL},  //BxOpcodeTable0FDC},
    /*    0F DD => 0x01DD*/ {&decoder64, NULL},  //BxOpcodeTable0FDD},
    /*    0F DE => 0x01DE*/ {&decoder64, NULL},  //BxOpcodeTable0FDE},
    /*    0F DF => 0x01DF*/ {&decoder64, NULL},  //BxOpcodeTable0FDF},
    /*    0F E0 => 0x01E0*/ {&decoder64, NULL},  //BxOpcodeTable0FE0},
    /*    0F E1 => 0x01E1*/ {&decoder64, NULL},  //BxOpcodeTable0FE1},
    /*    0F E2 => 0x01E2*/ {&decoder64, NULL},  //BxOpcodeTable0FE2},
    /*    0F E3 => 0x01E3*/ {&decoder64, NULL},  //BxOpcodeTable0FE3},
    /*    0F E4 => 0x01E4*/ {&decoder64, NULL},  //BxOpcodeTable0FE4},
    /*    0F E5 => 0x01E5*/ {&decoder64, NULL},  //BxOpcodeTable0FE5},
    /*    0F E6 => 0x01E6*/ {&decoder64, NULL},  //BxOpcodeTable0FE6},
    /*    0F E7 => 0x01E7*/ {&decoder64, NULL},  //BxOpcodeTable0FE7},
    /*    0F E8 => 0x01E8*/ {&decoder64, NULL},  //BxOpcodeTable0FE8},
    /*    0F E9 => 0x01E9*/ {&decoder64, NULL},  //BxOpcodeTable0FE9},
    /*    0F EA => 0x01EA*/ {&decoder64, NULL},  //BxOpcodeTable0FEA},
    /*    0F EB => 0x01EB*/ {&decoder64, NULL},  //BxOpcodeTable0FEB},
    /*    0F EC => 0x01EC*/ {&decoder64, NULL},  //BxOpcodeTable0FEC},
    /*    0F ED => 0x01ED*/ {&decoder64, NULL},  //BxOpcodeTable0FED},
    /*    0F EE => 0x01EE*/ {&decoder64, NULL},  //BxOpcodeTable0FEE},
    /*    0F EF => 0x01EF*/ {&decoder64, NULL},  //BxOpcodeTable0FEF},
    /*    0F F0 => 0x01F0*/ {&decoder64, NULL},  //BxOpcodeTable0FF0},
    /*    0F F1 => 0x01F1*/ {&decoder64, NULL},  //BxOpcodeTable0FF1},
    /*    0F F2 => 0x01F2*/ {&decoder64, NULL},  //BxOpcodeTable0FF2},
    /*    0F F3 => 0x01F3*/ {&decoder64, NULL},  //BxOpcodeTable0FF3},
    /*    0F F4 => 0x01F4*/ {&decoder64, NULL},  //BxOpcodeTable0FF4},
    /*    0F F5 => 0x01F5*/ {&decoder64, NULL},  //BxOpcodeTable0FF5},
    /*    0F F6 => 0x01F6*/ {&decoder64, NULL},  //BxOpcodeTable0FF6},
    /*    0F F7 => 0x01F7*/ {&decoder64, NULL},  //BxOpcodeTable0FF7},
    /*    0F F8 => 0x01F8*/ {&decoder64, NULL},  //BxOpcodeTable0FF8},
    /*    0F F9 => 0x01F9*/ {&decoder64, NULL},  //BxOpcodeTable0FF9},
    /*    0F FA => 0x01FA*/ {&decoder64, NULL},  //BxOpcodeTable0FFA},
    /*    0F FB => 0x01FB*/ {&decoder64, NULL},  //BxOpcodeTable0FFB},
    /*    0F FC => 0x01FC*/ {&decoder64, NULL},  //BxOpcodeTable0FFC},
    /*    0F FD => 0x01FD*/ {&decoder64, NULL},  //BxOpcodeTable0FFD},
    /*    0F FE => 0x01FE*/ {&decoder64, NULL},  //BxOpcodeTable0FFE},
    /*    0F FF => 0x01FF*/ {&decoder64, NULL},  //BxOpcodeTable0FFF},
    /* 0F 38 00 => 0x0200*/ {&decoder64, NULL},  //BxOpcodeTable0F3800},
    /* 0F 38 01 => 0x0201*/ {&decoder64, NULL},  //BxOpcodeTable0F3801},
    /* 0F 38 02 => 0x0202*/ {&decoder64, NULL},  //BxOpcodeTable0F3802},
    /* 0F 38 03 => 0x0203*/ {&decoder64, NULL},  //BxOpcodeTable0F3803},
    /* 0F 38 04 => 0x0204*/ {&decoder64, NULL},  //BxOpcodeTable0F3804},
    /* 0F 38 05 => 0x0205*/ {&decoder64, NULL},  //BxOpcodeTable0F3805},
    /* 0F 38 06 => 0x0206*/ {&decoder64, NULL},  //BxOpcodeTable0F3806},
    /* 0F 38 07 => 0x0207*/ {&decoder64, NULL},  //BxOpcodeTable0F3807},
    /* 0F 38 08 => 0x0208*/ {&decoder64, NULL},  //BxOpcodeTable0F3808},
    /* 0F 38 09 => 0x0209*/ {&decoder64, NULL},  //BxOpcodeTable0F3809},
    /* 0F 38 0A => 0x020A*/ {&decoder64, NULL},  //BxOpcodeTable0F380A},
    /* 0F 38 0B => 0x020B*/ {&decoder64, NULL},  //BxOpcodeTable0F380B},
    /* 0F 38 0C => 0x020C*/ {&decoder64, NULL},  //BxOpcodeTable0F380C},
    /* 0F 38 0D => 0x020D*/ {&decoder64, NULL},  //BxOpcodeTable0F380D},
    /* 0F 38 0E => 0x020E*/ {&decoder64, NULL},  //BxOpcodeTable0F380E},
    /* 0F 38 0F => 0x020F*/ {&decoder64, NULL},  //BxOpcodeTable0F380F},
    /* 0F 38 10 => 0x0210*/ {&decoder64, NULL},  //BxOpcodeTable0F3810},
    /* 0F 38 11 => 0x0211*/ {&decoder64, NULL},  //BxOpcodeTable0F3811},
    /* 0F 38 12 => 0x0212*/ {&decoder64, NULL},  //BxOpcodeTable0F3812},
    /* 0F 38 13 => 0x0213*/ {&decoder64, NULL},  //BxOpcodeTable0F3813},
    /* 0F 38 14 => 0x0214*/ {&decoder64, NULL},  //BxOpcodeTable0F3814},
    /* 0F 38 15 => 0x0215*/ {&decoder64, NULL},  //BxOpcodeTable0F3815},
    /* 0F 38 16 => 0x0216*/ {&decoder64, NULL},  //BxOpcodeTable0F3816},
    /* 0F 38 17 => 0x0217*/ {&decoder64, NULL},  //BxOpcodeTable0F3817},
    /* 0F 38 18 => 0x0218*/ {&decoder64, NULL},  //BxOpcodeTable0F3818},
    /* 0F 38 19 => 0x0219*/ {&decoder64, NULL},  //BxOpcodeTable0F3819},
    /* 0F 38 1A => 0x021A*/ {&decoder64, NULL},  //BxOpcodeTable0F381A},
    /* 0F 38 1B => 0x021B*/ {&decoder64, NULL},  //BxOpcodeTable0F381B},
    /* 0F 38 1C => 0x021C*/ {&decoder64, NULL},  //BxOpcodeTable0F381C},
    /* 0F 38 1D => 0x021D*/ {&decoder64, NULL},  //BxOpcodeTable0F381D},
    /* 0F 38 1E => 0x021E*/ {&decoder64, NULL},  //BxOpcodeTable0F381E},
    /* 0F 38 1F => 0x021F*/ {&decoder64, NULL},  //BxOpcodeTable0F381F},
    /* 0F 38 20 => 0x0220*/ {&decoder64, NULL},  //BxOpcodeTable0F3820},
    /* 0F 38 21 => 0x0221*/ {&decoder64, NULL},  //BxOpcodeTable0F3821},
    /* 0F 38 22 => 0x0222*/ {&decoder64, NULL},  //BxOpcodeTable0F3822},
    /* 0F 38 23 => 0x0223*/ {&decoder64, NULL},  //BxOpcodeTable0F3823},
    /* 0F 38 24 => 0x0224*/ {&decoder64, NULL},  //BxOpcodeTable0F3824},
    /* 0F 38 25 => 0x0225*/ {&decoder64, NULL},  //BxOpcodeTable0F3825},
    /* 0F 38 26 => 0x0226*/ {&decoder64, NULL},  //BxOpcodeTable0F3826},
    /* 0F 38 27 => 0x0227*/ {&decoder64, NULL},  //BxOpcodeTable0F3827},
    /* 0F 38 28 => 0x0228*/ {&decoder64, NULL},  //BxOpcodeTable0F3828},
    /* 0F 38 29 => 0x0229*/ {&decoder64, NULL},  //BxOpcodeTable0F3829},
    /* 0F 38 2A => 0x022A*/ {&decoder64, NULL},  //BxOpcodeTable0F382A},
    /* 0F 38 2B => 0x022B*/ {&decoder64, NULL},  //BxOpcodeTable0F382B},
    /* 0F 38 2C => 0x022C*/ {&decoder64, NULL},  //BxOpcodeTable0F382C},
    /* 0F 38 2D => 0x022D*/ {&decoder64, NULL},  //BxOpcodeTable0F382D},
    /* 0F 38 2E => 0x022E*/ {&decoder64, NULL},  //BxOpcodeTable0F382E},
    /* 0F 38 2F => 0x022F*/ {&decoder64, NULL},  //BxOpcodeTable0F382F},
    /* 0F 38 30 => 0x0230*/ {&decoder64, NULL},  //BxOpcodeTable0F3830},
    /* 0F 38 31 => 0x0231*/ {&decoder64, NULL},  //BxOpcodeTable0F3831},
    /* 0F 38 32 => 0x0232*/ {&decoder64, NULL},  //BxOpcodeTable0F3832},
    /* 0F 38 33 => 0x0233*/ {&decoder64, NULL},  //BxOpcodeTable0F3833},
    /* 0F 38 34 => 0x0234*/ {&decoder64, NULL},  //BxOpcodeTable0F3834},
    /* 0F 38 35 => 0x0235*/ {&decoder64, NULL},  //BxOpcodeTable0F3835},
    /* 0F 38 36 => 0x0236*/ {&decoder64, NULL},  //BxOpcodeTable0F3836},
    /* 0F 38 37 => 0x0237*/ {&decoder64, NULL},  //BxOpcodeTable0F3837},
    /* 0F 38 38 => 0x0238*/ {&decoder64, NULL},  //BxOpcodeTable0F3838},
    /* 0F 38 39 => 0x0239*/ {&decoder64, NULL},  //BxOpcodeTable0F3839},
    /* 0F 38 3A => 0x023A*/ {&decoder64, NULL},  //BxOpcodeTable0F383A},
    /* 0F 38 3B => 0x023B*/ {&decoder64, NULL},  //BxOpcodeTable0F383B},
    /* 0F 38 3C => 0x023C*/ {&decoder64, NULL},  //BxOpcodeTable0F383C},
    /* 0F 38 3D => 0x023D*/ {&decoder64, NULL},  //BxOpcodeTable0F383D},
    /* 0F 38 3E => 0x023E*/ {&decoder64, NULL},  //BxOpcodeTable0F383E},
    /* 0F 38 3F => 0x023F*/ {&decoder64, NULL},  //BxOpcodeTable0F383F},
    /* 0F 38 40 => 0x0240*/ {&decoder64, NULL},  //BxOpcodeTable0F3840},
    /* 0F 38 41 => 0x0241*/ {&decoder64, NULL},  //BxOpcodeTable0F3841},
    /* 0F 38 42 => 0x0242*/ {&decoder64, NULL},  //BxOpcodeTable0F3842},
    /* 0F 38 43 => 0x0243*/ {&decoder64, NULL},  //BxOpcodeTable0F3843},
    /* 0F 38 44 => 0x0244*/ {&decoder64, NULL},  //BxOpcodeTable0F3844},
    /* 0F 38 45 => 0x0245*/ {&decoder64, NULL},  //BxOpcodeTable0F3845},
    /* 0F 38 46 => 0x0246*/ {&decoder64, NULL},  //BxOpcodeTable0F3846},
    /* 0F 38 47 => 0x0247*/ {&decoder64, NULL},  //BxOpcodeTable0F3847},
    /* 0F 38 48 => 0x0248*/ {&decoder64, NULL},  //BxOpcodeTable0F3848},
    /* 0F 38 49 => 0x0249*/ {&decoder64, NULL},  //BxOpcodeTable0F3849},
    /* 0F 38 4A => 0x024A*/ {&decoder64, NULL},  //BxOpcodeTable0F384A},
    /* 0F 38 4B => 0x024B*/ {&decoder64, NULL},  //BxOpcodeTable0F384B},
    /* 0F 38 4C => 0x024C*/ {&decoder64, NULL},  //BxOpcodeTable0F384C},
    /* 0F 38 4D => 0x024D*/ {&decoder64, NULL},  //BxOpcodeTable0F384D},
    /* 0F 38 4E => 0x024E*/ {&decoder64, NULL},  //BxOpcodeTable0F384E},
    /* 0F 38 4F => 0x024F*/ {&decoder64, NULL},  //BxOpcodeTable0F384F},
    /* 0F 38 50 => 0x0250*/ {&decoder64, NULL},  //BxOpcodeTable0F3850},
    /* 0F 38 51 => 0x0251*/ {&decoder64, NULL},  //BxOpcodeTable0F3851},
    /* 0F 38 52 => 0x0252*/ {&decoder64, NULL},  //BxOpcodeTable0F3852},
    /* 0F 38 53 => 0x0253*/ {&decoder64, NULL},  //BxOpcodeTable0F3853},
    /* 0F 38 54 => 0x0254*/ {&decoder64, NULL},  //BxOpcodeTable0F3854},
    /* 0F 38 55 => 0x0255*/ {&decoder64, NULL},  //BxOpcodeTable0F3855},
    /* 0F 38 56 => 0x0256*/ {&decoder64, NULL},  //BxOpcodeTable0F3856},
    /* 0F 38 57 => 0x0257*/ {&decoder64, NULL},  //BxOpcodeTable0F3857},
    /* 0F 38 58 => 0x0258*/ {&decoder64, NULL},  //BxOpcodeTable0F3858},
    /* 0F 38 59 => 0x0259*/ {&decoder64, NULL},  //BxOpcodeTable0F3859},
    /* 0F 38 5A => 0x025A*/ {&decoder64, NULL},  //BxOpcodeTable0F385A},
    /* 0F 38 5B => 0x025B*/ {&decoder64, NULL},  //BxOpcodeTable0F385B},
    /* 0F 38 5C => 0x025C*/ {&decoder64, NULL},  //BxOpcodeTable0F385C},
    /* 0F 38 5D => 0x025D*/ {&decoder64, NULL},  //BxOpcodeTable0F385D},
    /* 0F 38 5E => 0x025E*/ {&decoder64, NULL},  //BxOpcodeTable0F385E},
    /* 0F 38 5F => 0x025F*/ {&decoder64, NULL},  //BxOpcodeTable0F385F},
    /* 0F 38 60 => 0x0260*/ {&decoder64, NULL},  //BxOpcodeTable0F3860},
    /* 0F 38 61 => 0x0261*/ {&decoder64, NULL},  //BxOpcodeTable0F3861},
    /* 0F 38 62 => 0x0262*/ {&decoder64, NULL},  //BxOpcodeTable0F3862},
    /* 0F 38 63 => 0x0263*/ {&decoder64, NULL},  //BxOpcodeTable0F3863},
    /* 0F 38 64 => 0x0264*/ {&decoder64, NULL},  //BxOpcodeTable0F3864},
    /* 0F 38 65 => 0x0265*/ {&decoder64, NULL},  //BxOpcodeTable0F3865},
    /* 0F 38 66 => 0x0266*/ {&decoder64, NULL},  //BxOpcodeTable0F3866},
    /* 0F 38 67 => 0x0267*/ {&decoder64, NULL},  //BxOpcodeTable0F3867},
    /* 0F 38 68 => 0x0268*/ {&decoder64, NULL},  //BxOpcodeTable0F3868},
    /* 0F 38 69 => 0x0269*/ {&decoder64, NULL},  //BxOpcodeTable0F3869},
    /* 0F 38 6A => 0x026A*/ {&decoder64, NULL},  //BxOpcodeTable0F386A},
    /* 0F 38 6B => 0x026B*/ {&decoder64, NULL},  //BxOpcodeTable0F386B},
    /* 0F 38 6C => 0x026C*/ {&decoder64, NULL},  //BxOpcodeTable0F386C},
    /* 0F 38 6D => 0x026D*/ {&decoder64, NULL},  //BxOpcodeTable0F386D},
    /* 0F 38 6E => 0x026E*/ {&decoder64, NULL},  //BxOpcodeTable0F386E},
    /* 0F 38 6F => 0x026F*/ {&decoder64, NULL},  //BxOpcodeTable0F386F},
    /* 0F 38 70 => 0x0270*/ {&decoder64, NULL},  //BxOpcodeTable0F3870},
    /* 0F 38 71 => 0x0271*/ {&decoder64, NULL},  //BxOpcodeTable0F3871},
    /* 0F 38 72 => 0x0272*/ {&decoder64, NULL},  //BxOpcodeTable0F3872},
    /* 0F 38 73 => 0x0273*/ {&decoder64, NULL},  //BxOpcodeTable0F3873},
    /* 0F 38 74 => 0x0274*/ {&decoder64, NULL},  //BxOpcodeTable0F3874},
    /* 0F 38 75 => 0x0275*/ {&decoder64, NULL},  //BxOpcodeTable0F3875},
    /* 0F 38 76 => 0x0276*/ {&decoder64, NULL},  //BxOpcodeTable0F3876},
    /* 0F 38 77 => 0x0277*/ {&decoder64, NULL},  //BxOpcodeTable0F3877},
    /* 0F 38 78 => 0x0278*/ {&decoder64, NULL},  //BxOpcodeTable0F3878},
    /* 0F 38 79 => 0x0279*/ {&decoder64, NULL},  //BxOpcodeTable0F3879},
    /* 0F 38 7A => 0x027A*/ {&decoder64, NULL},  //BxOpcodeTable0F387A},
    /* 0F 38 7B => 0x027B*/ {&decoder64, NULL},  //BxOpcodeTable0F387B},
    /* 0F 38 7C => 0x027C*/ {&decoder64, NULL},  //BxOpcodeTable0F387C},
    /* 0F 38 7D => 0x027D*/ {&decoder64, NULL},  //BxOpcodeTable0F387D},
    /* 0F 38 7E => 0x027E*/ {&decoder64, NULL},  //BxOpcodeTable0F387E},
    /* 0F 38 7F => 0x027F*/ {&decoder64, NULL},  //BxOpcodeTable0F387F},
    /* 0F 38 80 => 0x0280*/ {&decoder64, NULL},  //BxOpcodeTable0F3880},
    /* 0F 38 81 => 0x0281*/ {&decoder64, NULL},  //BxOpcodeTable0F3881},
    /* 0F 38 82 => 0x0282*/ {&decoder64, NULL},  //BxOpcodeTable0F3882},
    /* 0F 38 83 => 0x0283*/ {&decoder64, NULL},  //BxOpcodeTable0F3883},
    /* 0F 38 84 => 0x0284*/ {&decoder64, NULL},  //BxOpcodeTable0F3884},
    /* 0F 38 85 => 0x0285*/ {&decoder64, NULL},  //BxOpcodeTable0F3885},
    /* 0F 38 86 => 0x0286*/ {&decoder64, NULL},  //BxOpcodeTable0F3886},
    /* 0F 38 87 => 0x0287*/ {&decoder64, NULL},  //BxOpcodeTable0F3887},
    /* 0F 38 88 => 0x0288*/ {&decoder64, NULL},  //BxOpcodeTable0F3888},
    /* 0F 38 89 => 0x0289*/ {&decoder64, NULL},  //BxOpcodeTable0F3889},
    /* 0F 38 8A => 0x028A*/ {&decoder64, NULL},  //BxOpcodeTable0F388A},
    /* 0F 38 8B => 0x028B*/ {&decoder64, NULL},  //BxOpcodeTable0F388B},
    /* 0F 38 8C => 0x028C*/ {&decoder64, NULL},  //BxOpcodeTable0F388C},
    /* 0F 38 8D => 0x028D*/ {&decoder64, NULL},  //BxOpcodeTable0F388D},
    /* 0F 38 8E => 0x028E*/ {&decoder64, NULL},  //BxOpcodeTable0F388E},
    /* 0F 38 8F => 0x028F*/ {&decoder64, NULL},  //BxOpcodeTable0F388F},
    /* 0F 38 90 => 0x0290*/ {&decoder64, NULL},  //BxOpcodeTable0F3890},
    /* 0F 38 91 => 0x0291*/ {&decoder64, NULL},  //BxOpcodeTable0F3891},
    /* 0F 38 92 => 0x0292*/ {&decoder64, NULL},  //BxOpcodeTable0F3892},
    /* 0F 38 93 => 0x0293*/ {&decoder64, NULL},  //BxOpcodeTable0F3893},
    /* 0F 38 94 => 0x0294*/ {&decoder64, NULL},  //BxOpcodeTable0F3894},
    /* 0F 38 95 => 0x0295*/ {&decoder64, NULL},  //BxOpcodeTable0F3895},
    /* 0F 38 96 => 0x0296*/ {&decoder64, NULL},  //BxOpcodeTable0F3896},
    /* 0F 38 97 => 0x0297*/ {&decoder64, NULL},  //BxOpcodeTable0F3897},
    /* 0F 38 98 => 0x0298*/ {&decoder64, NULL},  //BxOpcodeTable0F3898},
    /* 0F 38 99 => 0x0299*/ {&decoder64, NULL},  //BxOpcodeTable0F3899},
    /* 0F 38 9A => 0x029A*/ {&decoder64, NULL},  //BxOpcodeTable0F389A},
    /* 0F 38 9B => 0x029B*/ {&decoder64, NULL},  //BxOpcodeTable0F389B},
    /* 0F 38 9C => 0x029C*/ {&decoder64, NULL},  //BxOpcodeTable0F389C},
    /* 0F 38 9D => 0x029D*/ {&decoder64, NULL},  //BxOpcodeTable0F389D},
    /* 0F 38 9E => 0x029E*/ {&decoder64, NULL},  //BxOpcodeTable0F389E},
    /* 0F 38 9F => 0x029F*/ {&decoder64, NULL},  //BxOpcodeTable0F389F},
    /* 0F 38 A0 => 0x02A0*/ {&decoder64, NULL},  //BxOpcodeTable0F38A0},
    /* 0F 38 A1 => 0x02A1*/ {&decoder64, NULL},  //BxOpcodeTable0F38A1},
    /* 0F 38 A2 => 0x02A2*/ {&decoder64, NULL},  //BxOpcodeTable0F38A2},
    /* 0F 38 A3 => 0x02A3*/ {&decoder64, NULL},  //BxOpcodeTable0F38A3},
    /* 0F 38 A4 => 0x02A4*/ {&decoder64, NULL},  //BxOpcodeTable0F38A4},
    /* 0F 38 A5 => 0x02A5*/ {&decoder64, NULL},  //BxOpcodeTable0F38A5},
    /* 0F 38 A6 => 0x02A6*/ {&decoder64, NULL},  //BxOpcodeTable0F38A6},
    /* 0F 38 A7 => 0x02A7*/ {&decoder64, NULL},  //BxOpcodeTable0F38A7},
    /* 0F 38 A8 => 0x02A8*/ {&decoder64, NULL},  //BxOpcodeTable0F38A8},
    /* 0F 38 A9 => 0x02A9*/ {&decoder64, NULL},  //BxOpcodeTable0F38A9},
    /* 0F 38 AA => 0x02AA*/ {&decoder64, NULL},  //BxOpcodeTable0F38AA},
    /* 0F 38 AB => 0x02AB*/ {&decoder64, NULL},  //BxOpcodeTable0F38AB},
    /* 0F 38 AC => 0x02AC*/ {&decoder64, NULL},  //BxOpcodeTable0F38AC},
    /* 0F 38 AD => 0x02AD*/ {&decoder64, NULL},  //BxOpcodeTable0F38AD},
    /* 0F 38 AE => 0x02AE*/ {&decoder64, NULL},  //BxOpcodeTable0F38AE},
    /* 0F 38 AF => 0x02AF*/ {&decoder64, NULL},  //BxOpcodeTable0F38AF},
    /* 0F 38 B0 => 0x02B0*/ {&decoder64, NULL},  //BxOpcodeTable0F38B0},
    /* 0F 38 B1 => 0x02B1*/ {&decoder64, NULL},  //BxOpcodeTable0F38B1},
    /* 0F 38 B2 => 0x02B2*/ {&decoder64, NULL},  //BxOpcodeTable0F38B2},
    /* 0F 38 B3 => 0x02B3*/ {&decoder64, NULL},  //BxOpcodeTable0F38B3},
    /* 0F 38 B4 => 0x02B4*/ {&decoder64, NULL},  //BxOpcodeTable0F38B4},
    /* 0F 38 B5 => 0x02B5*/ {&decoder64, NULL},  //BxOpcodeTable0F38B5},
    /* 0F 38 B6 => 0x02B6*/ {&decoder64, NULL},  //BxOpcodeTable0F38B6},
    /* 0F 38 B7 => 0x02B7*/ {&decoder64, NULL},  //BxOpcodeTable0F38B7},
    /* 0F 38 B8 => 0x02B8*/ {&decoder64, NULL},  //BxOpcodeTable0F38B8},
    /* 0F 38 B9 => 0x02B9*/ {&decoder64, NULL},  //BxOpcodeTable0F38B9},
    /* 0F 38 BA => 0x02BA*/ {&decoder64, NULL},  //BxOpcodeTable0F38BA},
    /* 0F 38 BB => 0x02BB*/ {&decoder64, NULL},  //BxOpcodeTable0F38BB},
    /* 0F 38 BC => 0x02BC*/ {&decoder64, NULL},  //BxOpcodeTable0F38BC},
    /* 0F 38 BD => 0x02BD*/ {&decoder64, NULL},  //BxOpcodeTable0F38BD},
    /* 0F 38 BE => 0x02BE*/ {&decoder64, NULL},  //BxOpcodeTable0F38BE},
    /* 0F 38 BF => 0x02BF*/ {&decoder64, NULL},  //BxOpcodeTable0F38BF},
    /* 0F 38 C0 => 0x02C0*/ {&decoder64, NULL},  //BxOpcodeTable0F38C0},
    /* 0F 38 C1 => 0x02C1*/ {&decoder64, NULL},  //BxOpcodeTable0F38C1},
    /* 0F 38 C2 => 0x02C2*/ {&decoder64, NULL},  //BxOpcodeTable0F38C2},
    /* 0F 38 C3 => 0x02C3*/ {&decoder64, NULL},  //BxOpcodeTable0F38C3},
    /* 0F 38 C4 => 0x02C4*/ {&decoder64, NULL},  //BxOpcodeTable0F38C4},
    /* 0F 38 C5 => 0x02C5*/ {&decoder64, NULL},  //BxOpcodeTable0F38C5},
    /* 0F 38 C6 => 0x02C6*/ {&decoder64, NULL},  //BxOpcodeTable0F38C6},
    /* 0F 38 C7 => 0x02C7*/ {&decoder64, NULL},  //BxOpcodeTable0F38C7},
    /* 0F 38 C8 => 0x02C8*/ {&decoder64, NULL},  //BxOpcodeTable0F38C8},
    /* 0F 38 C9 => 0x02C9*/ {&decoder64, NULL},  //BxOpcodeTable0F38C9},
    /* 0F 38 CA => 0x02CA*/ {&decoder64, NULL},  //BxOpcodeTable0F38CA},
    /* 0F 38 CB => 0x02CB*/ {&decoder64, NULL},  //BxOpcodeTable0F38CB},
    /* 0F 38 CC => 0x02CC*/ {&decoder64, NULL},  //BxOpcodeTable0F38CC},
    /* 0F 38 CD => 0x02CD*/ {&decoder64, NULL},  //BxOpcodeTable0F38CD},
    /* 0F 38 CE => 0x02CE*/ {&decoder64, NULL},  //BxOpcodeTable0F38CE},
    /* 0F 38 CF => 0x02CF*/ {&decoder64, NULL},  //BxOpcodeTable0F38CF},
    /* 0F 38 D0 => 0x02D0*/ {&decoder64, NULL},  //BxOpcodeTable0F38D0},
    /* 0F 38 D1 => 0x02D1*/ {&decoder64, NULL},  //BxOpcodeTable0F38D1},
    /* 0F 38 D2 => 0x02D2*/ {&decoder64, NULL},  //BxOpcodeTable0F38D2},
    /* 0F 38 D3 => 0x02D3*/ {&decoder64, NULL},  //BxOpcodeTable0F38D3},
    /* 0F 38 D4 => 0x02D4*/ {&decoder64, NULL},  //BxOpcodeTable0F38D4},
    /* 0F 38 D5 => 0x02D5*/ {&decoder64, NULL},  //BxOpcodeTable0F38D5},
    /* 0F 38 D6 => 0x02D6*/ {&decoder64, NULL},  //BxOpcodeTable0F38D6},
    /* 0F 38 D7 => 0x02D7*/ {&decoder64, NULL},  //BxOpcodeTable0F38D7},
    /* 0F 38 D8 => 0x02D8*/ {&decoder64, NULL},  //BxOpcodeTable0F38D8},
    /* 0F 38 D9 => 0x02D9*/ {&decoder64, NULL},  //BxOpcodeTable0F38D9},
    /* 0F 38 DA => 0x02DA*/ {&decoder64, NULL},  //BxOpcodeTable0F38DA},
    /* 0F 38 DB => 0x02DB*/ {&decoder64, NULL},  //BxOpcodeTable0F38DB},
    /* 0F 38 DC => 0x02DC*/ {&decoder64, NULL},  //BxOpcodeTable0F38DC},
    /* 0F 38 DD => 0x02DD*/ {&decoder64, NULL},  //BxOpcodeTable0F38DD},
    /* 0F 38 DE => 0x02DE*/ {&decoder64, NULL},  //BxOpcodeTable0F38DE},
    /* 0F 38 DF => 0x02DF*/ {&decoder64, NULL},  //BxOpcodeTable0F38DF},
    /* 0F 38 E0 => 0x02E0*/ {&decoder64, NULL},  //BxOpcodeTable0F38E0},
    /* 0F 38 E1 => 0x02E1*/ {&decoder64, NULL},  //BxOpcodeTable0F38E1},
    /* 0F 38 E2 => 0x02E2*/ {&decoder64, NULL},  //BxOpcodeTable0F38E2},
    /* 0F 38 E3 => 0x02E3*/ {&decoder64, NULL},  //BxOpcodeTable0F38E3},
    /* 0F 38 E4 => 0x02E4*/ {&decoder64, NULL},  //BxOpcodeTable0F38E4},
    /* 0F 38 E5 => 0x02E5*/ {&decoder64, NULL},  //BxOpcodeTable0F38E5},
    /* 0F 38 E6 => 0x02E6*/ {&decoder64, NULL},  //BxOpcodeTable0F38E6},
    /* 0F 38 E7 => 0x02E7*/ {&decoder64, NULL},  //BxOpcodeTable0F38E7},
    /* 0F 38 E8 => 0x02E8*/ {&decoder64, NULL},  //BxOpcodeTable0F38E8},
    /* 0F 38 E9 => 0x02E9*/ {&decoder64, NULL},  //BxOpcodeTable0F38E9},
    /* 0F 38 EA => 0x02EA*/ {&decoder64, NULL},  //BxOpcodeTable0F38EA},
    /* 0F 38 EB => 0x02EB*/ {&decoder64, NULL},  //BxOpcodeTable0F38EB},
    /* 0F 38 EC => 0x02EC*/ {&decoder64, NULL},  //BxOpcodeTable0F38EC},
    /* 0F 38 ED => 0x02ED*/ {&decoder64, NULL},  //BxOpcodeTable0F38ED},
    /* 0F 38 EE => 0x02EE*/ {&decoder64, NULL},  //BxOpcodeTable0F38EE},
    /* 0F 38 EF => 0x02EF*/ {&decoder64, NULL},  //BxOpcodeTable0F38EF},
    /* 0F 38 F0 => 0x02F0*/ {&decoder64, NULL},  //BxOpcodeTable0F38F0},
    /* 0F 38 F1 => 0x02F1*/ {&decoder64, NULL},  //BxOpcodeTable0F38F1},
    /* 0F 38 F2 => 0x02F2*/ {&decoder64, NULL},  //BxOpcodeTable0F38F2},
    /* 0F 38 F3 => 0x02F3*/ {&decoder64, NULL},  //BxOpcodeTable0F38F3},
    /* 0F 38 F4 => 0x02F4*/ {&decoder64, NULL},  //BxOpcodeTable0F38F4},
    /* 0F 38 F5 => 0x02F5*/ {&decoder64, NULL},  //BxOpcodeTable0F38F5},
    /* 0F 38 F6 => 0x02F6*/ {&decoder64, NULL},  //BxOpcodeTable0F38F6},
    /* 0F 38 F7 => 0x02F7*/ {&decoder64, NULL},  //BxOpcodeTable0F38F7},
    /* 0F 38 F8 => 0x02F8*/ {&decoder64, NULL},  //BxOpcodeTable0F38F8},
    /* 0F 38 F9 => 0x02F9*/ {&decoder64, NULL},  //BxOpcodeTable0F38F9},
    /* 0F 38 FA => 0x02FA*/ {&decoder64, NULL},  //BxOpcodeTable0F38FA},
    /* 0F 38 FB => 0x02FB*/ {&decoder64, NULL},  //BxOpcodeTable0F38FB},
    /* 0F 38 FC => 0x02FC*/ {&decoder64, NULL},  //BxOpcodeTable0F38FC},
    /* 0F 38 FD => 0x02FD*/ {&decoder64, NULL},  //BxOpcodeTable0F38FD},
    /* 0F 38 FE => 0x02FE*/ {&decoder64, NULL},  //BxOpcodeTable0F38FE},
    /* 0F 38 FF => 0x02FF*/ {&decoder64, NULL},  //BxOpcodeTable0F38FF},
    /* 0F 3A 00 => 0x0200*/ {&decoder64, NULL},  //BxOpcodeTable0F3A00},
    /* 0F 3A 01 => 0x0301*/ {&decoder64, NULL},  //BxOpcodeTable0F3A01},
    /* 0F 3A 02 => 0x0302*/ {&decoder64, NULL},  //BxOpcodeTable0F3A02},
    /* 0F 3A 03 => 0x0303*/ {&decoder64, NULL},  //BxOpcodeTable0F3A03},
    /* 0F 3A 04 => 0x0304*/ {&decoder64, NULL},  //BxOpcodeTable0F3A04},
    /* 0F 3A 05 => 0x0305*/ {&decoder64, NULL},  //BxOpcodeTable0F3A05},
    /* 0F 3A 06 => 0x0306*/ {&decoder64, NULL},  //BxOpcodeTable0F3A06},
    /* 0F 3A 07 => 0x0307*/ {&decoder64, NULL},  //BxOpcodeTable0F3A07},
    /* 0F 3A 08 => 0x0308*/ {&decoder64, NULL},  //BxOpcodeTable0F3A08},
    /* 0F 3A 09 => 0x0309*/ {&decoder64, NULL},  //BxOpcodeTable0F3A09},
    /* 0F 3A 0A => 0x030A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A0A},
    /* 0F 3A 0B => 0x030B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A0B},
    /* 0F 3A 0C => 0x030C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A0C},
    /* 0F 3A 0D => 0x030D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A0D},
    /* 0F 3A 0E => 0x030E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A0E},
    /* 0F 3A 0F => 0x030F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A0F},
    /* 0F 3A 10 => 0x0310*/ {&decoder64, NULL},  //BxOpcodeTable0F3A10},
    /* 0F 3A 11 => 0x0311*/ {&decoder64, NULL},  //BxOpcodeTable0F3A11},
    /* 0F 3A 12 => 0x0312*/ {&decoder64, NULL},  //BxOpcodeTable0F3A12},
    /* 0F 3A 13 => 0x0313*/ {&decoder64, NULL},  //BxOpcodeTable0F3A13},
    /* 0F 3A 14 => 0x0314*/ {&decoder64, NULL},  //BxOpcodeTable0F3A14},
    /* 0F 3A 15 => 0x0315*/ {&decoder64, NULL},  //BxOpcodeTable0F3A15},
    /* 0F 3A 16 => 0x0316*/ {&decoder64, NULL},  //BxOpcodeTable0F3A16},
    /* 0F 3A 17 => 0x0317*/ {&decoder64, NULL},  //BxOpcodeTable0F3A17},
    /* 0F 3A 18 => 0x0318*/ {&decoder64, NULL},  //BxOpcodeTable0F3A18},
    /* 0F 3A 19 => 0x0319*/ {&decoder64, NULL},  //BxOpcodeTable0F3A19},
    /* 0F 3A 1A => 0x031A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A1A},
    /* 0F 3A 1B => 0x031B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A1B},
    /* 0F 3A 1C => 0x031C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A1C},
    /* 0F 3A 1D => 0x031D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A1D},
    /* 0F 3A 1E => 0x031E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A1E},
    /* 0F 3A 1F => 0x031F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A1F},
    /* 0F 3A 20 => 0x0320*/ {&decoder64, NULL},  //BxOpcodeTable0F3A20},
    /* 0F 3A 21 => 0x0321*/ {&decoder64, NULL},  //BxOpcodeTable0F3A21},
    /* 0F 3A 22 => 0x0322*/ {&decoder64, NULL},  //BxOpcodeTable0F3A22},
    /* 0F 3A 23 => 0x0323*/ {&decoder64, NULL},  //BxOpcodeTable0F3A23},
    /* 0F 3A 24 => 0x0324*/ {&decoder64, NULL},  //BxOpcodeTable0F3A24},
    /* 0F 3A 25 => 0x0325*/ {&decoder64, NULL},  //BxOpcodeTable0F3A25},
    /* 0F 3A 26 => 0x0326*/ {&decoder64, NULL},  //BxOpcodeTable0F3A26},
    /* 0F 3A 27 => 0x0327*/ {&decoder64, NULL},  //BxOpcodeTable0F3A27},
    /* 0F 3A 28 => 0x0328*/ {&decoder64, NULL},  //BxOpcodeTable0F3A28},
    /* 0F 3A 29 => 0x0329*/ {&decoder64, NULL},  //BxOpcodeTable0F3A29},
    /* 0F 3A 2A => 0x032A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A2A},
    /* 0F 3A 2B => 0x032B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A2B},
    /* 0F 3A 2C => 0x032C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A2C},
    /* 0F 3A 2D => 0x032D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A2D},
    /* 0F 3A 2E => 0x032E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A2E},
    /* 0F 3A 2F => 0x032F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A2F},
    /* 0F 3A 30 => 0x0330*/ {&decoder64, NULL},  //BxOpcodeTable0F3A30},
    /* 0F 3A 31 => 0x0331*/ {&decoder64, NULL},  //BxOpcodeTable0F3A31},
    /* 0F 3A 32 => 0x0332*/ {&decoder64, NULL},  //BxOpcodeTable0F3A32},
    /* 0F 3A 33 => 0x0333*/ {&decoder64, NULL},  //BxOpcodeTable0F3A33},
    /* 0F 3A 34 => 0x0334*/ {&decoder64, NULL},  //BxOpcodeTable0F3A34},
    /* 0F 3A 35 => 0x0335*/ {&decoder64, NULL},  //BxOpcodeTable0F3A35},
    /* 0F 3A 36 => 0x0336*/ {&decoder64, NULL},  //BxOpcodeTable0F3A36},
    /* 0F 3A 37 => 0x0337*/ {&decoder64, NULL},  //BxOpcodeTable0F3A37},
    /* 0F 3A 38 => 0x0338*/ {&decoder64, NULL},  //BxOpcodeTable0F3A38},
    /* 0F 3A 39 => 0x0339*/ {&decoder64, NULL},  //BxOpcodeTable0F3A39},
    /* 0F 3A 3A => 0x033A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A3A},
    /* 0F 3A 3B => 0x033B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A3B},
    /* 0F 3A 3C => 0x033C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A3C},
    /* 0F 3A 3D => 0x033D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A3D},
    /* 0F 3A 3E => 0x033E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A3E},
    /* 0F 3A 3F => 0x033F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A3F},
    /* 0F 3A 40 => 0x0340*/ {&decoder64, NULL},  //BxOpcodeTable0F3A40},
    /* 0F 3A 41 => 0x0341*/ {&decoder64, NULL},  //BxOpcodeTable0F3A41},
    /* 0F 3A 42 => 0x0342*/ {&decoder64, NULL},  //BxOpcodeTable0F3A42},
    /* 0F 3A 43 => 0x0343*/ {&decoder64, NULL},  //BxOpcodeTable0F3A43},
    /* 0F 3A 44 => 0x0344*/ {&decoder64, NULL},  //BxOpcodeTable0F3A44},
    /* 0F 3A 45 => 0x0345*/ {&decoder64, NULL},  //BxOpcodeTable0F3A45},
    /* 0F 3A 46 => 0x0346*/ {&decoder64, NULL},  //BxOpcodeTable0F3A46},
    /* 0F 3A 47 => 0x0347*/ {&decoder64, NULL},  //BxOpcodeTable0F3A47},
    /* 0F 3A 48 => 0x0348*/ {&decoder64, NULL},  //BxOpcodeTable0F3A48},
    /* 0F 3A 49 => 0x0349*/ {&decoder64, NULL},  //BxOpcodeTable0F3A49},
    /* 0F 3A 4A => 0x034A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A4A},
    /* 0F 3A 4B => 0x034B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A4B},
    /* 0F 3A 4C => 0x034C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A4C},
    /* 0F 3A 4D => 0x034D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A4D},
    /* 0F 3A 4E => 0x034E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A4E},
    /* 0F 3A 4F => 0x034F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A4F},
    /* 0F 3A 50 => 0x0350*/ {&decoder64, NULL},  //BxOpcodeTable0F3A50},
    /* 0F 3A 51 => 0x0351*/ {&decoder64, NULL},  //BxOpcodeTable0F3A51},
    /* 0F 3A 52 => 0x0352*/ {&decoder64, NULL},  //BxOpcodeTable0F3A52},
    /* 0F 3A 53 => 0x0353*/ {&decoder64, NULL},  //BxOpcodeTable0F3A53},
    /* 0F 3A 54 => 0x0354*/ {&decoder64, NULL},  //BxOpcodeTable0F3A54},
    /* 0F 3A 55 => 0x0355*/ {&decoder64, NULL},  //BxOpcodeTable0F3A55},
    /* 0F 3A 56 => 0x0356*/ {&decoder64, NULL},  //BxOpcodeTable0F3A56},
    /* 0F 3A 57 => 0x0357*/ {&decoder64, NULL},  //BxOpcodeTable0F3A57},
    /* 0F 3A 58 => 0x0358*/ {&decoder64, NULL},  //BxOpcodeTable0F3A58},
    /* 0F 3A 59 => 0x0359*/ {&decoder64, NULL},  //BxOpcodeTable0F3A59},
    /* 0F 3A 5A => 0x035A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A5A},
    /* 0F 3A 5B => 0x035B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A5B},
    /* 0F 3A 5C => 0x035C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A5C},
    /* 0F 3A 5D => 0x035D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A5D},
    /* 0F 3A 5E => 0x035E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A5E},
    /* 0F 3A 5F => 0x035F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A5F},
    /* 0F 3A 60 => 0x0360*/ {&decoder64, NULL},  //BxOpcodeTable0F3A60},
    /* 0F 3A 61 => 0x0361*/ {&decoder64, NULL},  //BxOpcodeTable0F3A61},
    /* 0F 3A 62 => 0x0362*/ {&decoder64, NULL},  //BxOpcodeTable0F3A62},
    /* 0F 3A 64 => 0x0364*/ {&decoder64, NULL},  //BxOpcodeTable0F3A64},
    /* 0F 3A 64 => 0x0364*/ {&decoder64, NULL},  //BxOpcodeTable0F3A64},
    /* 0F 3A 65 => 0x0365*/ {&decoder64, NULL},  //BxOpcodeTable0F3A65},
    /* 0F 3A 66 => 0x0366*/ {&decoder64, NULL},  //BxOpcodeTable0F3A66},
    /* 0F 3A 67 => 0x0367*/ {&decoder64, NULL},  //BxOpcodeTable0F3A67},
    /* 0F 3A 68 => 0x0368*/ {&decoder64, NULL},  //BxOpcodeTable0F3A68},
    /* 0F 3A 69 => 0x0369*/ {&decoder64, NULL},  //BxOpcodeTable0F3A69},
    /* 0F 3A 6A => 0x036A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A6A},
    /* 0F 3A 6B => 0x036B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A6B},
    /* 0F 3A 6C => 0x036C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A6C},
    /* 0F 3A 6D => 0x036D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A6D},
    /* 0F 3A 6E => 0x036E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A6E},
    /* 0F 3A 6F => 0x036F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A6F},
    /* 0F 3A 70 => 0x0370*/ {&decoder64, NULL},  //BxOpcodeTable0F3A70},
    /* 0F 3A 71 => 0x0371*/ {&decoder64, NULL},  //BxOpcodeTable0F3A71},
    /* 0F 3A 72 => 0x0372*/ {&decoder64, NULL},  //BxOpcodeTable0F3A72},
    /* 0F 3A 73 => 0x0373*/ {&decoder64, NULL},  //BxOpcodeTable0F3A73},
    /* 0F 3A 74 => 0x0374*/ {&decoder64, NULL},  //BxOpcodeTable0F3A74},
    /* 0F 3A 75 => 0x0375*/ {&decoder64, NULL},  //BxOpcodeTable0F3A75},
    /* 0F 3A 76 => 0x0376*/ {&decoder64, NULL},  //BxOpcodeTable0F3A76},
    /* 0F 3A 77 => 0x0377*/ {&decoder64, NULL},  //BxOpcodeTable0F3A77},
    /* 0F 3A 78 => 0x0378*/ {&decoder64, NULL},  //BxOpcodeTable0F3A78},
    /* 0F 3A 79 => 0x0379*/ {&decoder64, NULL},  //BxOpcodeTable0F3A79},
    /* 0F 3A 7A => 0x037A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A7A},
    /* 0F 3A 7B => 0x037B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A7B},
    /* 0F 3A 7C => 0x037C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A7C},
    /* 0F 3A 7D => 0x037D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A7D},
    /* 0F 3A 7E => 0x037E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A7E},
    /* 0F 3A 7F => 0x037F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A7F},
    /* 0F 3A 80 => 0x0380*/ {&decoder64, NULL},  //BxOpcodeTable0F3A80},
    /* 0F 3A 81 => 0x0381*/ {&decoder64, NULL},  //BxOpcodeTable0F3A81},
    /* 0F 3A 82 => 0x0382*/ {&decoder64, NULL},  //BxOpcodeTable0F3A82},
    /* 0F 3A 83 => 0x0383*/ {&decoder64, NULL},  //BxOpcodeTable0F3A83},
    /* 0F 3A 84 => 0x0384*/ {&decoder64, NULL},  //BxOpcodeTable0F3A84},
    /* 0F 3A 85 => 0x0385*/ {&decoder64, NULL},  //BxOpcodeTable0F3A85},
    /* 0F 3A 86 => 0x0386*/ {&decoder64, NULL},  //BxOpcodeTable0F3A86},
    /* 0F 3A 87 => 0x0387*/ {&decoder64, NULL},  //BxOpcodeTable0F3A87},
    /* 0F 3A 88 => 0x0388*/ {&decoder64, NULL},  //BxOpcodeTable0F3A88},
    /* 0F 3A 89 => 0x0389*/ {&decoder64, NULL},  //BxOpcodeTable0F3A89},
    /* 0F 3A 8A => 0x038A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A8A},
    /* 0F 3A 8B => 0x038B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A8B},
    /* 0F 3A 8C => 0x038C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A8C},
    /* 0F 3A 8D => 0x038D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A8D},
    /* 0F 3A 8E => 0x038E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A8E},
    /* 0F 3A 8F => 0x038F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A8F},
    /* 0F 3A 90 => 0x0390*/ {&decoder64, NULL},  //BxOpcodeTable0F3A90},
    /* 0F 3A 91 => 0x0391*/ {&decoder64, NULL},  //BxOpcodeTable0F3A91},
    /* 0F 3A 92 => 0x0392*/ {&decoder64, NULL},  //BxOpcodeTable0F3A92},
    /* 0F 3A 93 => 0x0393*/ {&decoder64, NULL},  //BxOpcodeTable0F3A93},
    /* 0F 3A 94 => 0x0394*/ {&decoder64, NULL},  //BxOpcodeTable0F3A94},
    /* 0F 3A 95 => 0x0395*/ {&decoder64, NULL},  //BxOpcodeTable0F3A95},
    /* 0F 3A 96 => 0x0396*/ {&decoder64, NULL},  //BxOpcodeTable0F3A96},
    /* 0F 3A 97 => 0x0397*/ {&decoder64, NULL},  //BxOpcodeTable0F3A97},
    /* 0F 3A 98 => 0x0398*/ {&decoder64, NULL},  //BxOpcodeTable0F3A98},
    /* 0F 3A 99 => 0x0399*/ {&decoder64, NULL},  //BxOpcodeTable0F3A99},
    /* 0F 3A 9A => 0x039A*/ {&decoder64, NULL},  //BxOpcodeTable0F3A9A},
    /* 0F 3A 9B => 0x039B*/ {&decoder64, NULL},  //BxOpcodeTable0F3A9B},
    /* 0F 3A 9C => 0x039C*/ {&decoder64, NULL},  //BxOpcodeTable0F3A9C},
    /* 0F 3A 9D => 0x039D*/ {&decoder64, NULL},  //BxOpcodeTable0F3A9D},
    /* 0F 3A 9E => 0x039E*/ {&decoder64, NULL},  //BxOpcodeTable0F3A9E},
    /* 0F 3A 9F => 0x039F*/ {&decoder64, NULL},  //BxOpcodeTable0F3A9F},
    /* 0F 3A A0 => 0x03A0*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA0},
    /* 0F 3A A1 => 0x03A1*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA1},
    /* 0F 3A A2 => 0x03A2*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA2},
    /* 0F 3A A3 => 0x03A3*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA3},
    /* 0F 3A A4 => 0x03A4*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA4},
    /* 0F 3A A5 => 0x03A5*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA5},
    /* 0F 3A A6 => 0x03A6*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA6},
    /* 0F 3A A7 => 0x03A7*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA7},
    /* 0F 3A A8 => 0x03A8*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA8},
    /* 0F 3A A9 => 0x03A9*/ {&decoder64, NULL},  //BxOpcodeTable0F3AA9},
    /* 0F 3A AA => 0x03AA*/ {&decoder64, NULL},  //BxOpcodeTable0F3AAA},
    /* 0F 3A AB => 0x03AB*/ {&decoder64, NULL},  //BxOpcodeTable0F3AAB},
    /* 0F 3A AC => 0x03AC*/ {&decoder64, NULL},  //BxOpcodeTable0F3AAC},
    /* 0F 3A AD => 0x03AD*/ {&decoder64, NULL},  //BxOpcodeTable0F3AAD},
    /* 0F 3A AE => 0x03AE*/ {&decoder64, NULL},  //BxOpcodeTable0F3AAE},
    /* 0F 3A AF => 0x03AF*/ {&decoder64, NULL},  //BxOpcodeTable0F3AAF},
    /* 0F 3A B0 => 0x03B0*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB0},
    /* 0F 3A B1 => 0x03B1*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB1},
    /* 0F 3A B2 => 0x03B2*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB2},
    /* 0F 3A B3 => 0x03B3*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB3},
    /* 0F 3A B4 => 0x03B4*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB4},
    /* 0F 3A B5 => 0x03B5*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB5},
    /* 0F 3A B6 => 0x03B6*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB6},
    /* 0F 3A B7 => 0x03B7*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB7},
    /* 0F 3A B8 => 0x03B8*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB8},
    /* 0F 3A B9 => 0x03B9*/ {&decoder64, NULL},  //BxOpcodeTable0F3AB9},
    /* 0F 3A BA => 0x03BA*/ {&decoder64, NULL},  //BxOpcodeTable0F3ABA},
    /* 0F 3A BB => 0x03BB*/ {&decoder64, NULL},  //BxOpcodeTable0F3ABB},
    /* 0F 3A BC => 0x03BC*/ {&decoder64, NULL},  //BxOpcodeTable0F3ABC},
    /* 0F 3A BD => 0x03BD*/ {&decoder64, NULL},  //BxOpcodeTable0F3ABD},
    /* 0F 3A BE => 0x03BE*/ {&decoder64, NULL},  //BxOpcodeTable0F3ABE},
    /* 0F 3A BF => 0x03BF*/ {&decoder64, NULL},  //BxOpcodeTable0F3ABF},
    /* 0F 3A C0 => 0x03C0*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC0},
    /* 0F 3A C1 => 0x03C1*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC1},
    /* 0F 3A C2 => 0x03C2*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC2},
    /* 0F 3A C3 => 0x03C3*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC3},
    /* 0F 3A C4 => 0x03C4*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC4},
    /* 0F 3A C5 => 0x03C5*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC5},
    /* 0F 3A C6 => 0x03C6*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC6},
    /* 0F 3A C7 => 0x03C7*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC7},
    /* 0F 3A C8 => 0x03C8*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC8},
    /* 0F 3A C9 => 0x03C9*/ {&decoder64, NULL},  //BxOpcodeTable0F3AC9},
    /* 0F 3A CA => 0x03CA*/ {&decoder64, NULL},  //BxOpcodeTable0F3ACA},
    /* 0F 3A CB => 0x03CB*/ {&decoder64, NULL},  //BxOpcodeTable0F3ACB},
    /* 0F 3A CC => 0x03CC*/ {&decoder64, NULL},  //BxOpcodeTable0F3ACC},
    /* 0F 3A CD => 0x03CD*/ {&decoder64, NULL},  //BxOpcodeTable0F3ACD},
    /* 0F 3A CE => 0x03CE*/ {&decoder64, NULL},  //BxOpcodeTable0F3ACE},
    /* 0F 3A CF => 0x03CF*/ {&decoder64, NULL},  //BxOpcodeTable0F3ACF},
    /* 0F 3A D0 => 0x03D0*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD0},
    /* 0F 3A D1 => 0x03D1*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD1},
    /* 0F 3A D2 => 0x03D2*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD2},
    /* 0F 3A D3 => 0x03D3*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD3},
    /* 0F 3A D4 => 0x03D4*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD4},
    /* 0F 3A D5 => 0x03D5*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD5},
    /* 0F 3A D6 => 0x03D6*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD6},
    /* 0F 3A D7 => 0x03D7*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD7},
    /* 0F 3A D8 => 0x03D8*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD8},
    /* 0F 3A D9 => 0x03D9*/ {&decoder64, NULL},  //BxOpcodeTable0F3AD9},
    /* 0F 3A DA => 0x03DA*/ {&decoder64, NULL},  //BxOpcodeTable0F3ADA},
    /* 0F 3A DB => 0x03DB*/ {&decoder64, NULL},  //BxOpcodeTable0F3ADB},
    /* 0F 3A DC => 0x03DC*/ {&decoder64, NULL},  //BxOpcodeTable0F3ADC},
    /* 0F 3A DD => 0x03DD*/ {&decoder64, NULL},  //BxOpcodeTable0F3ADD},
    /* 0F 3A DE => 0x03DE*/ {&decoder64, NULL},  //BxOpcodeTable0F3ADE},
    /* 0F 3A DF => 0x03DF*/ {&decoder64, NULL},  //BxOpcodeTable0F3ADF},
    /* 0F 3A E0 => 0x03E0*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE0},
    /* 0F 3A E1 => 0x03E1*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE1},
    /* 0F 3A E2 => 0x03E2*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE2},
    /* 0F 3A E3 => 0x03E3*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE3},
    /* 0F 3A E4 => 0x03E4*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE4},
    /* 0F 3A E5 => 0x03E5*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE5},
    /* 0F 3A E6 => 0x03E6*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE6},
    /* 0F 3A E7 => 0x03E7*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE7},
    /* 0F 3A E8 => 0x03E8*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE8},
    /* 0F 3A E9 => 0x03E9*/ {&decoder64, NULL},  //BxOpcodeTable0F3AE9},
    /* 0F 3A EA => 0x03EA*/ {&decoder64, NULL},  //BxOpcodeTable0F3AEA},
    /* 0F 3A EB => 0x03EB*/ {&decoder64, NULL},  //BxOpcodeTable0F3AEB},
    /* 0F 3A EC => 0x03EC*/ {&decoder64, NULL},  //BxOpcodeTable0F3AEC},
    /* 0F 3A ED => 0x03ED*/ {&decoder64, NULL},  //BxOpcodeTable0F3AED},
    /* 0F 3A EE => 0x03EE*/ {&decoder64, NULL},  //BxOpcodeTable0F3AEE},
    /* 0F 3A EF => 0x03EF*/ {&decoder64, NULL},  //BxOpcodeTable0F3AEF},
    /* 0F 3A F0 => 0x03F0*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF0},
    /* 0F 3A F1 => 0x03F1*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF1},
    /* 0F 3A F2 => 0x03F2*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF2},
    /* 0F 3A F3 => 0x03F3*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF3},
    /* 0F 3A F4 => 0x03F4*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF4},
    /* 0F 3A F5 => 0x03F5*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF5},
    /* 0F 3A F6 => 0x03F6*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF6},
    /* 0F 3A F7 => 0x03F7*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF7},
    /* 0F 3A F8 => 0x03F8*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF8},
    /* 0F 3A F9 => 0x03F9*/ {&decoder64, NULL},  //BxOpcodeTable0F3AF9},
    /* 0F 3A FA => 0x03FA*/ {&decoder64, NULL},  //BxOpcodeTable0F3AFA},
    /* 0F 3A FB => 0x03FB*/ {&decoder64, NULL},  //BxOpcodeTable0F3AFB},
    /* 0F 3A FC => 0x03FC*/ {&decoder64, NULL},  //BxOpcodeTable0F3AFC},
    /* 0F 3A FD => 0x03FD*/ {&decoder64, NULL},  //BxOpcodeTable0F3AFD},
    /* 0F 3A FE => 0x03FE*/ {&decoder64, NULL},  //BxOpcodeTable0F3AFE},
    /* 0F 3A FF => 0x03FF*/ {&decoder64, NULL},  //BxOpcodeTable0F3AFF},
#endif
    /*                   */ {NULL, NULL}};

////////////////////////////////////////////////////////////////////////////
//#define BX_CONST64(x)  (x)
// const Bit64u ATTR_LAST_OPCODE = BX_CONST64(0x8000000000000000);
//#define last_opcode_lockable(attr, ia_opcode)       ((attr) | (Bit64u(ia_opcode) << 48) | ATTR_LAST_OPCODE)
//==========================================================================

int decoder64_modrm(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    return 0;
}

int decoder64(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);

    //得到真正的处理逻辑；
    // Bit16u ia_opcode = findOpcode((const Bit64u*) opcode_table, decmask);
    // if (fetchImmediate(iptr, remain, i, ia_opcode, true) < 0)
    // assign_srcs(i, ia_opcode, nnn, rm);

    return 0;
}

int decoder_ud64(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    return 0;
}

int fetchDecode64(const Bit8u *iptr, bxInstruction_c *i, unsigned remainingInPage)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    xlog_hexdump(const_cast<const uint8_t *>(iptr), 16 * 5 + 11);
    if (remainingInPage > 15)
        remainingInPage = 15;
    // i->setILen(remainingInPage);

    unsigned remain = remainingInPage;
    unsigned b1 = *iptr;

    b1 = 0;
    int ia_opcode = 0;
    // unsigned seg_override = 0;

    // bool lock = 0;
    unsigned sse_prefix = 0;
    unsigned rex_prefix = 0;

fetch_b1:
    b1 = *iptr++;
    remain--;
    //先处理前缀字节码
    switch (b1)
    {
    case 0x40 ... 0x4F:
    {
        goto fetch_b1;
        // break;
    }
    case 0xF2: // REPNE/REPNZ
    case 0xF3: // REP/REPE/REPZ
    {
        // TBC
    }
    case 0x2e: // CS:
    case 0x26: // ES:
    case 0x36: // SS:
    case 0x3e: // DS:
    {
        // TBC
    }
    case 0x64: // FS:
    case 0x65: // GS:
    {
    }
    case 0x66: // OpSize
    {
    }
    case 0x67: // AddrSize
    {
    }
    case 0xf0: // LOCK:
    {
    }
    case 0x0f: // 2 byte escape
    {
        if (remain != 0)
        {
            remain--;
            b1 = 0x100 | *iptr++; // 0x0F?? -> 01??
            break;
        }
    }
    default:
    {
        break;
    }
    }

    // handle 3-byte opcode
    if (b1 == 0x138 || b1 == 0x13a)
    {
        if (remain == 0)
            return (-1);
        if (b1 == 0x138)
            b1 = 0x200 | *iptr++; // 0f38->0138->02??
        else
            b1 = 0x300 | *iptr++; // 0f3a->013a->03??
        remain--;
    }

    //找到真正的指令码
    b1 = 0;
    //查表
    BxOpcodeDecodeDescriptor64 *decode_descriptor = &decode64_descriptor[b1];
    ia_opcode = decode_descriptor->decode_method(iptr, remain, i, b1, sse_prefix, rex_prefix, decode_descriptor->opcode_table);

    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);

    return ia_opcode;
}

//==========================================================================

uint8_t *pInsData = NULL;
uint32_t insCnt = 0;

void CMyBochsCpu_t::cpu_loop(void)
{
    printf("  >> CMyBochsCpu_t::cpu_loop(tbc) called.\n");

    unsigned int iCnt = 0;

    while (1)
    {
        //检查事件
        xlog_info("    >>> func:CMyBochsCpu_t::%s() called; check Event;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
#if 0
        if (0) //(BX_CPU_THIS_PTR async_event) 
        {
            if (handleAsyncEvent())
            {
                // If request to return to caller ASAP.
                return;
            }
        }
#endif
        xlog_info("    >>> func:CMyBochsCpu_t::%s() called; build instruction from hexbyte code;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
        //取址、取指、译码、构建指令对象；
        // bxICacheEntry_c *entry = getICacheEntry();
        // bxInstruction_c *i = entry->i;
        uint8_t *pThisIns = pInsData + insCnt;

        xlog_hexdump(pThisIns, 16 * 5 + 9);

        // entry = serveICacheMiss((Bit32u) eipBiased, pAddr);

        int i_opcode = fetchDecode64(pThisIns, NULL, 15);
        xlog_info("    >>> func:CMyBochsCpu_t::%s() called; opcode=%x;(line:%d@%s)\n", __func__, i_opcode, __LINE__, __FILE__);

        insCnt = insCnt + 4;

        // boundaryFetch(fetchPtr, remainingInPage, i);

        //构建指令OBJ
        // instructionobj.constructor()
        // ret = assignHandler(i, BX_CPU_THIS_PTR fetchModeMask);

        //执行指令
        xlog_info("    >>> func:CMyBochsCpu_t::%s() called; inst->exec();(line:%d@%s)\n", __func__, __LINE__, __FILE__);
        for (;;)
        {
            // instructionobj.exec();
            break;
        }

        if (iCnt++ >= 3)
            break;
    }

    return;
}

int bx_begin_simulator(CSimulator_t *pSim, int argc, char *argv[])
{
    xlog_info("  >> func:%s(argc=%d, argv=%p) entry;(line:%d@%s)\n", __func__, argc, argv, __LINE__, __FILE__);
    int iret = 0;

    // temp tbc
    pInsData = getInstrData(argv[0]);
    try
    {
        CMyBochsCpu_t *ptrCpu = pSim->mp_cpu;

        ptrCpu->cpu_loop();
    }
    catch (...)
    {
        xlog_info("  >> func:%s() exceptions;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    }
    xlog_info("  >> func:%s() exit(%d);(line:%d@%s)\n", __func__, iret, __LINE__, __FILE__);

    return iret;
}

int bx_main_proc(int argc, char *argv[])
{
    xlog_info("  >> func:%s(argc=%d, argv=%p) entry;(line:%d@%s)\n", __func__, argc, argv, __LINE__, __FILE__);
    int iret = 0;
    try
    {
        CSimulator_t *ptrSim = new CSimulator_t(new CMyBochsCpu_t);
        iret = ptrSim->begin_simulator(argc, argv);

        delete ptrSim;
        // throw 0; // test throw;
    }
    catch (...)
    {
        xlog_info("  >> func:%s() exceptions;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    }

    xlog_info("  >> func:%s() exit(%d);(line:%d@%s)\n", __func__, iret, __LINE__, __FILE__);

    return 0;
}

CMyBochsApp_t theApp;

// g++ -std=c++11 -g -Wall -O0 mybochs-la-0.1.0?.cpp -o myapp_exe_?

int main(int argc, char *argv[])
{
    xlog_info("  >> func:%s(argc=%d, argv=%p) entry;(line:%d@%s)\n", __func__, argc, argv, __LINE__, __FILE__);
    xlog_info("  >> the mybochs app starting ... ...\n");
    xlog_init();
    int iret = 0;
    do
    {
        xlog_info("   >> the mybochs app do_work().\n");

        CMyBochsApp_t *ptrApp = &theApp;
        // xlog_info("\e[1m");
        iret = ptrApp->MainProc(argc, argv);
        // xlog_info("\e[0m");
        xlog_info("  >> func:%s() do_work() end;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    } while (0);

    xlog_uninit();
    xlog_info("  >> the mybochs app exit(%d).\n", iret);
    xlog_info("  >> func:%s() exit(%d);(line:%d@%s)\n", __func__, iret, __LINE__, __FILE__);
    return 0;
}

#if 0
g++ -std=c++11 -g -Wall -O0 mybochs-la-0.1.00.cpp -o myapp_exe_0
g++ -std=c++11 -g -Wall -O0 mybochs-la-0.1.01.cpp -o myapp_exe_1
g++ -std=c++11 -g -Wall -O0 mybochs-la-0.1.02.cpp -o myapp_exe_2
#endif
