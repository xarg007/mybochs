#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <cctype>
#include <cassert>

extern "C"
{
#include <sys/stat.h>
#include <sys/types.h>
};

//==========================================
//typedef                   char    int8_t;
//typedef             short int     int16_t;
//typedef                   int     int32_t;
//typedef        long long  int     int64_t;
typedef unsigned            char    uint8_t;
typedef unsigned      short int     uint16_t;
typedef unsigned            int     uint32_t;
typedef unsigned long long  int     uint64_t;

extern void xlog_init();
extern void xlog_uninit();
extern void xlog_mutex_lock();
extern void xlog_mutex_lock();
int xlog_info(const char* fmt, ...);
int xlog_hexdump(const uint8_t* const p_data, uint32_t i_len);

//==========================================

#ifdef XLOG_PTHREAD_T
#include <pthread.h>
pthread_mutex_t     xlog_mutex_v = {0};
pthread_mutexattr_t xlog_attr_v  = {0};
#endif

void xlog_init()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_init(&xlog_mutex_v, NULL);
#endif
    return ;
}

void xlog_uninit()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_destroy(&xlog_mutex_v);
#endif
    return ;
}

void xlog_mutex_lock()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_lock(&xlog_mutex_v);
#endif
    return ;
}

void xlog_mutex_unlock()
{
#ifdef XLOG_PTHREAD_T
    pthread_mutex_unlock(&xlog_mutex_v);
#endif
    return ;
}

int xlog_core(unsigned int ui_level, const char* fmt, va_list args)
{
    int iret = vprintf(fmt, args);
    fflush(stdout);
    return iret;
}

int xlog_info_x(const char* fmt, ...)
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

int xlog_hexdump(const uint8_t* const p_data, uint32_t i_len)
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
    for (unsigned int i = 0; i < i_row; i++)//逐行处理
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
                xlog_info_x("%02x ", *(p_data + i*16 + j));
            }
            else
            {
                xlog_info_x("** " );
            }
        }
        
        //在第8列与第9列中加空格列
        xlog_info_x(" ");
        
        //当前行前9~16列数据
        for (unsigned int j = 8; j < 16; j++)
        {
            if ((i * 16 + j) < i_len)
            {
                if (j < 15) xlog_info_x("%02x ", *(p_data + i*16 + j));
                else        xlog_info_x("%02x" , *(p_data + i*16 + j));
            }
            else
            {
                if (j < 15) xlog_info_x("** ");
                else        xlog_info_x("**" );
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
                unsigned char test_char = *(p_data + i*16 + j);
                do
                {
                    if(isalpha(test_char)) break;
                    if(isdigit(test_char)) break;
                    if(ispunct(test_char)) break;
                    if(test_char == 0x20 ) break;
                    if(test_char == 0x0  ) break;
                    test_char = '.';
                }while(0);
                
                if(test_char == 0x0)
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

int xlog_info(const char* fmt, ...)
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

uint8_t* get_elf64_data(const char* filename, uint32_t* len)
{
    xlog_info("  >> get_elf64_data(\"%s\", len) entry;\n", filename);
    *len = 0x12;
    
    uint8_t* p_data         = NULL;
    struct stat statbuf     = {0};
    stat(filename, &statbuf);
    
    unsigned int iLen = statbuf.st_size;
    if(iLen > 0 && iLen < 10*1024*1024) //文件目前最大设为10M
    {
        FILE* hFile = fopen(filename, "rb");
        if(hFile == NULL) 
            return NULL;
        
        *len = iLen;
        p_data = (unsigned char*)calloc(iLen/4+2, sizeof(uint8_t)*4);
        
        size_t size_readok = fread(p_data, 1, iLen, hFile);
        fclose(hFile);
        
        if(size_readok != iLen)
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
typedef unsigned long long  int Elf64_Addr  ;
typedef unsigned      short int Elf64_Half  ;
typedef   signed      short int Elf64_SHalf ;
typedef unsigned long long  int Elf64_Off   ;
typedef   signed            int Elf64_Sword ;
typedef unsigned            int Elf64_Word  ;
typedef unsigned long long  int Elf64_Xword ;
typedef   signed long long  int Elf64_Sxword;

struct S_ELF64_ELFHeader_t
{
	unsigned char e_ident[16]; /* ELF "magic number" */
	Elf64_Half    e_type     ;
	Elf64_Half    e_machine  ;
	Elf64_Word    e_version  ;
	Elf64_Addr    e_entry    ; /* Entry point virtual address */
	Elf64_Off     e_phoff    ; /* Program header table file offset */
	Elf64_Off     e_shoff    ; /* Section header table file offset */
	Elf64_Word    e_flags    ;
	Elf64_Half    e_ehsize   ;
	Elf64_Half    e_phentsize;
	Elf64_Half    e_phnum    ;
	Elf64_Half    e_shentsize;
	Elf64_Half    e_shnum    ;
	Elf64_Half    e_shstrndx ;
};
//==========================================

//==========================================
struct S_ELF64_ELFHeader_t* parse_elf64_elf_header(uint8_t* pElfData)
{
    xlog_info("  >> func{%s:(%05d)} is call.{pElfData=%p}.\n", __func__, __LINE__, pElfData);

    if(pElfData != NULL)
    {
        struct S_ELF64_ELFHeader_t* pElfHeader = (struct S_ELF64_ELFHeader_t*)pElfData;

        xlog_info("        struct S_ELF64_ELFHeader_t pElfHeader = {%p} \n", pElfHeader);
        xlog_info("        {\n");
        xlog_info("                 unsigned char e_ident[16] = {");
        for(int i=0; i<16; i++)
        {
            if(i<15)
            {
                xlog_info("%02x ", pElfHeader->e_ident[i]);
            }
            else
            {
                xlog_info("%02x", pElfHeader->e_ident[i]);
            }
        }
        xlog_info("};\n");
        xlog_info("                 Elf64_Half    e_type      = 0x%04x;\n", pElfHeader->e_type     );
        xlog_info("                 Elf64_Half    e_machine   = 0x%04x;\n", pElfHeader->e_machine  );
        xlog_info("                 Elf64_Word    e_version   = 0x%x  ;\n", pElfHeader->e_version  );
        xlog_info("                 Elf64_Addr    e_entry     = 0x%llx;\n", pElfHeader->e_entry    );
        xlog_info("                 Elf64_Off     e_phoff     = 0x%llx;\n", pElfHeader->e_phoff    );
        xlog_info("                 Elf64_Off     e_shoff     = 0x%llx;\n", pElfHeader->e_shoff    );
        xlog_info("                 Elf64_Word    e_flags     = 0x%x  ;\n", pElfHeader->e_flags    );
        xlog_info("                 Elf64_Half    e_ehsize    = 0x%04x;\n", pElfHeader->e_ehsize   );
        xlog_info("                 Elf64_Half    e_phentsize = 0x%04x;\n", pElfHeader->e_phentsize);
        xlog_info("                 Elf64_Half    e_phnum     = 0x%04x;\n", pElfHeader->e_phnum    );
        xlog_info("                 Elf64_Half    e_shentsize = 0x%04x;\n", pElfHeader->e_shentsize);
        xlog_info("                 Elf64_Half    e_shnum     = 0x%04x;\n", pElfHeader->e_shnum    );
        xlog_info("                 Elf64_Half    e_shstrndx  = 0x%04x;\n", pElfHeader->e_shstrndx );
        xlog_info("        };\n");

        return pElfHeader;
    }

    return NULL;
}

uint8_t * getInstrData(const char* pFileName)
{
    unsigned char*  pHexData  = NULL;
    unsigned int    iLen      = 0;
    pHexData = get_elf64_data(pFileName, &iLen);
    if(pHexData == NULL && iLen <= 0)
    {
        return NULL;
    }
    
    xlog_info("  >> func{%s:(%05d)} is call, pHexData=\"%p\" .\n", __func__, __LINE__, pHexData);
    xlog_hexdump(pHexData, 16*10+9);
    
    struct S_ELF64_ELFHeader_t* pElfHeader = parse_elf64_elf_header(pHexData);
    
    uint8_t * pInstr = pHexData + pElfHeader->e_entry;
    
    return pInstr;
}

//========================================================================

class CMyBochsApp_t
{
public:
    CMyBochsApp_t();
    virtual ~CMyBochsApp_t();
public:
    virtual int MainProc(int argc, char* argv[]);
};

class CMyBochsCpu_t
{
public:
    CMyBochsCpu_t();
    virtual ~CMyBochsCpu_t();
public:
    virtual void cpu_loop(void);
};

class CSimulator_t
{
public:
    class CMyBochsCpu_t* mp_cpu;
public:
    CSimulator_t();
    CSimulator_t(CMyBochsCpu_t* cpu);
    virtual ~CSimulator_t();
    
public:
    virtual int begin_simulator(int argc, char* argv[]);
};

//========================================================================
class CSimulator_t;
extern int bx_begin_simulator(CSimulator_t* pSim, int argc, char* argv[]);
extern int bx_main_proc(int argc, char* argv[]);

CMyBochsApp_t::CMyBochsApp_t()
{
    printf("  >> CMyBochsApp_t::CMyBochsApp_t() called.\n");
}

CMyBochsApp_t::~CMyBochsApp_t()
{
    printf("  >> CMyBochsApp_t::~CMyBochsApp_t() called.\n");
}

int CMyBochsApp_t::MainProc(int argc, char* argv[])
{
    printf("  >> CMyBochsApp_t::MainProc(argc=%d, argv=%p) called.\n", argc, argv);
    return bx_main_proc(argc, argv);
}

CMyBochsCpu_t::CMyBochsCpu_t()
{
    printf("  >> CMyBochsCpu_t::CMyBochsCpu_t() called.\n");
}

CMyBochsCpu_t::~CMyBochsCpu_t()
{
    printf("  >> CMyBochsCpu_t::~CMyBochsCpu_t() called.\n");
}

CSimulator_t::CSimulator_t()
    :mp_cpu(NULL)
{
    printf("  >> CSimulator_t::CSimulator_t() called.\n");
}

CSimulator_t::CSimulator_t(CMyBochsCpu_t* cpu)
    :mp_cpu(cpu)
{
    printf("  >> CSimulator_t::CSimulator_t() called.\n");
}

CSimulator_t::~CSimulator_t()
{
    printf("  >> CSimulator_t::~CSimulator_t() called.\n");
    delete mp_cpu;
}

int CSimulator_t::begin_simulator(int argc, char* argv[])
{
    printf("  >> CSimulator_t::begin_simulator(argc=%d, argv=%p) called.\n", argc, argv);
    int iret = 0;
    try
    {
        iret = bx_begin_simulator(this, argc, argv);
    }
    catch(...)
    {
        //
    }

    return iret;
}

//制用解码用表
////////////////////////////////////////////////////////////////////////////
typedef unsigned char      Bit8u;
typedef   signed char      Bit8s;
typedef unsigned short     Bit16u;
typedef   signed short     Bit16s;
typedef unsigned int       Bit32u;
typedef   signed int       Bit32s;
typedef unsigned long long Bit64u;
typedef   signed long long Bit64s;

typedef struct s_bxInstruction_c
{
    int itemp;
}bxInstruction_c;

typedef void (*BxExecutePtr_tR)(bxInstruction_c *);

void exe1(bxInstruction_c *)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
}

void exe2(bxInstruction_c *)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
}
void exe3(bxInstruction_c *)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
}
void exe4(bxInstruction_c *)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
}

//bx_define_opcode(BX_IA_AAA, "aaa", "aaa", NULL, &BX_CPU_C::AAA, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_AAD, "aad", "aad", NULL, &BX_CPU_C::AAD, 0, OP_Ib, OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_AAM, "aam", "aam", NULL, &BX_CPU_C::AAM, 0, OP_Ib, OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_AAS, "aas", "aas", NULL, &BX_CPU_C::AAS, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_DAA, "daa", "daa", NULL, &BX_CPU_C::DAA, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, 0)
//bx_define_opcode(BX_IA_DAS, "das", "das", NULL, &BX_CPU_C::DAS, 0, OP_NONE, OP_NONE, OP_NONE, OP_NONE, 0)

struct bxIAOpcodeTable
{
    BxExecutePtr_tR execute1;
    BxExecutePtr_tR execute2;
    Bit8u src[4];
    Bit8u opflags;
};

enum OpCodeIdx
{
    BX_IA_ADC_EwGw,
    BX_IA_ADD_EwGw,
    BX_IA_AND_EwGw,
    BX_IA_CMP_EwGw,
    BX_IA_OR_EwGw, 
    BX_IA_SBB_EwGw,
    BX_IA_SUB_EwGw,
    BX_IA_LAST
};

// table of all Bochs opcodes
bxIAOpcodeTable BxOpcodesTable[] = 
{
/*BX_IA_ADC_EwGw,*/ {exe1, exe2, {0,0,0,0}, 0},
/*BX_IA_ADD_EwGw,*/ {exe1, exe2, {0,0,0,0}, 0},
/*BX_IA_AND_EwGw,*/ {exe1, exe2, {0,0,0,0}, 0},
/*BX_IA_CMP_EwGw,*/ {exe1, exe2, {0,0,0,0}, 0},
/*BX_IA_OR_EwGw, */ {exe1, exe2, {0,0,0,0}, 0},
/*BX_IA_SBB_EwGw,*/ {exe1, exe2, {0,0,0,0}, 0},
/*BX_IA_SUB_EwGw,*/ {NULL, NULL, {0,0,0,0}, 0},
};

//bxIAOpcodeTable BxOpcodesTable[] = 
//{
//#define bx_define_opcode(a, b, c, d, e, f, s1, s2, s3, s4, g) { d, e, { s1, s2, s3, s4 }, g },
////提供了一个可扩展的配置表
////#include "??"
//#undef  bx_define_opcode
//};

int decoder64_modrm(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    return 0;
}

int decoder64(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    return 0;
}

int decoder_ud64(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    return 0;
}

// opcode 00
static const Bit64u BxOpcodeTable00[] = 
{ 
    //last_opcode_lockable(0, BX_IA_ADD_EbGb)
    0xFFFFEEEEAAAABBBB,
};

// opcode 01
static const Bit64u BxOpcodeTable01[] = 
{ 
    0xFFFFEEEEAAAABaBB,
    0xFFFFEEEEAAAABeBB,
};


// opcode 02
static const Bit64u BxOpcodeTable02[] = 
{ 
    0xFFFFEEEEAAAABaBB,
    0xFFFFEEEEAAAABeBB,
};

// opcode 03
static const Bit64u BxOpcodeTable03[] = 
{
    0xFFFFEEEEAAAABaBB,
    0xFFFFEEEEAAAABeBB,
};

typedef int (*BxFetchDecode64Ptr)(const Bit8u *iptr, unsigned &remain, bxInstruction_c *i, unsigned b1, unsigned sse_prefix, unsigned rex_prefix, const void *opcode_table);
//typedef int (*BxFetchDecode64Ptr)(
//        const Bit8u *iptr,
//        unsigned &remain,
//        bxInstruction_c *i,
//        unsigned b1,
//        unsigned sse_prefix,
//        unsigned rex_prefix,
//        const void *opcode_table
//        );

struct BxOpcodeDecodeDescriptor64
{
    BxFetchDecode64Ptr decode_method;
    const void *       opcode_table;
};

static BxOpcodeDecodeDescriptor64 decode64_descriptor[] =
{
   /*       00 */ { &decoder64_modrm, BxOpcodeTable00 },
   /*       01 */ { &decoder64_modrm, BxOpcodeTable01 },
   /*       02 */ { &decoder64_modrm, BxOpcodeTable02 },
   /*       03 */ { &decoder64_modrm, BxOpcodeTable03 },
   /*       04 */ { &decoder64,       NULL            },
   /*       05 */ { &decoder64,       NULL            },
   /*       06 */ { &decoder_ud64,    NULL            },
   /*       07 */ { &decoder_ud64,    NULL            },
};

////////////////////////////////////////////////////////////////////////////
//#define BX_CONST64(x)  (x)
//const Bit64u ATTR_LAST_OPCODE = BX_CONST64(0x8000000000000000);
//#define last_opcode_lockable(attr, ia_opcode)       ((attr) | (Bit64u(ia_opcode) << 48) | ATTR_LAST_OPCODE)
//==========================================================================

int fetchDecode64(const Bit8u *iptr, bxInstruction_c *i, unsigned remainingInPage)
{
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    
    xlog_hexdump(const_cast<const uint8_t*>(iptr), 16*5+11);
    
    unsigned remain = remainingInPage;
    unsigned b1 = *iptr;
    b1 = 0;
    int ia_opcode = 0;
    //unsigned seg_override = 0;
    
    //bool lock = 0;
    unsigned sse_prefix = 0;
    unsigned rex_prefix = 0;
  
    //先处理前缀字节码
    
    //找到真正的指令码
    
    //查表
    BxOpcodeDecodeDescriptor64 *decode_descriptor = &decode64_descriptor[b1];
    ia_opcode = decode_descriptor->decode_method(iptr, remain, i, b1, sse_prefix, rex_prefix, decode_descriptor->opcode_table);
    
    //得到真正的处理逻辑；
    xlog_info("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    
    return ia_opcode;
}

//==========================================================================

uint8_t * pInsData = NULL;
uint32_t  insCnt   = 0;

void CMyBochsCpu_t::cpu_loop(void)
{
    printf("  >> CMyBochsCpu_t::cpu_loop(tbc) called.\n");
    
    unsigned int iCnt = 0;
    
    while(1)
    {
        //???
        printf("  >> CMyBochsCpu_t::cpu_loop(tbc) step 1 get addr.\n");
        uint8_t * pThisIns = pInsData + insCnt;
        
        xlog_hexdump(pThisIns, 16*5+9);
        
        int i_opcode = fetchDecode64(pThisIns, NULL, 15);
        
        insCnt = insCnt + 4;
        //译码 [] //查表
        // e9 70 ef ff ff =>  jmpq   10b0 <__xstat@plt>
        
        //构建指令OBJ
        #if 0
        //instructionobj.constructor()
        #endif
        //执行指令
        #if 0
        //instructionobj.exec();
        #endif 
        //linux
        //sleep(1);
        //???
        printf("  >> CMyBochsCpu_t::cpu_loop(tbc) step 2.(%d)\n", i_opcode);
        //???
        printf("  >> CMyBochsCpu_t::cpu_loop(tbc) step 3.\n");
        iCnt++;
        if(iCnt>=3)
            break;
    }
    
    return;
}

int bx_begin_simulator(CSimulator_t* pSim, int argc, char* argv[])
{
    xlog_info("  >> func:%s(argc=%d, argv=%p) entry;(line:%d@%s)\n", __func__, argc, argv, __LINE__, __FILE__);
    int iret = 0;
    
    //temp tbc
    pInsData = getInstrData(argv[0]);
    try
    {
        CMyBochsCpu_t* ptrCpu = pSim->mp_cpu;
        
        ptrCpu->cpu_loop();
    }
    catch(...)
    {
        xlog_info("  >> func:%s() exceptions;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    }
    xlog_info("  >> func:%s() exit(%d);(line:%d@%s)\n", __func__, iret, __LINE__, __FILE__);
    
    return iret;
}

int bx_main_proc(int argc, char* argv[])
{
    xlog_info("  >> func:%s(argc=%d, argv=%p) entry;(line:%d@%s)\n", __func__, argc, argv, __LINE__, __FILE__);
    int iret = 0;
    try
    {
        CSimulator_t* ptrSim = new CSimulator_t(new CMyBochsCpu_t);
        iret = ptrSim->begin_simulator(argc, argv);
        
        delete ptrSim;
        throw 0; //test throw;
    }
    catch(...)
    {
        xlog_info("  >> func:%s() exceptions;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    }
    
    xlog_info("  >> func:%s() exit(%d);(line:%d@%s)\n", __func__, iret, __LINE__, __FILE__);
    
    return 0;
}

CMyBochsApp_t theApp;

//g++ -std=c++11 -g -Wall -O0 mybochs-la-0.1.0?.cpp -o myapp_exe_?

int main(int argc, char* argv[])
{
    xlog_info("  >> func:%s(argc=%d, argv=%p) entry;(line:%d@%s)\n", __func__, argc, argv, __LINE__, __FILE__);
    xlog_info("  >> the mybochs app starting ... ...\n");
    xlog_init();
    int iret = 0;
    do
    {
        xlog_info("   >> the mybochs app do_work().\n");
        
        CMyBochsApp_t* ptrApp = &theApp;
        //xlog_info("\e[1m");
        iret = ptrApp->MainProc(argc, argv);
        //xlog_info("\e[0m");
        xlog_info("  >> func:%s() do_work() end;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    }while(0);
    
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
