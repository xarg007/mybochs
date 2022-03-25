#include <cstdio>

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

class CMyBochsApp_t
{
public:
    CMyBochsApp_t();
    virtual ~CMyBochsApp_t();
public:
    virtual int MainProc(int argc, char* argv[]);
};

extern int bx_begin_simulator(CSimulator_t* pSim, int argc, char* argv[]);
extern int bx_main_proc(int argc, char* argv[]);

//==========================================================

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
        printf("  >> CSimulator_t::begin_simulator() exceptions.\n");
    }

    return iret;
}

CMyBochsCpu_t::CMyBochsCpu_t()
{
    printf("  >> CMyBochsCpu_t::CMyBochsCpu_t() called.\n");
}

CMyBochsCpu_t::~CMyBochsCpu_t()
{
    printf("  >> CMyBochsCpu_t::~CMyBochsCpu_t() called.\n");
}

void CMyBochsCpu_t::cpu_loop(void)
{
    printf("  >> CMyBochsCpu_t::cpu_loop(tbc) called.\n");
    unsigned int iCnt = 0;
    while(1)
    {
        //???
        printf("  >> CMyBochsCpu_t::cpu_loop(tbc) step 1.\n");
        //???
        printf("  >> CMyBochsCpu_t::cpu_loop(tbc) step 2.\n");
        //???
        printf("  >> CMyBochsCpu_t::cpu_loop(tbc) step 3.\n");
        
        iCnt++;
        if(iCnt>=3)
        {
            break;
        }
    }
    
    return;
}

int bx_begin_simulator(CSimulator_t* pSim, int argc, char* argv[])
{
    printf("  >> func:%s(pSim=%p, argc=%d, argv=%p) entry;(line:%d@%s)\n", 
                                    __func__, pSim, argc, argv, __LINE__, __FILE__);
    
    CMyBochsCpu_t* ptrCpu = pSim->mp_cpu;
    
    ptrCpu->cpu_loop();
    
    printf("  >> func:%s() exit;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    
    return 0;
}

int bx_main_proc(int argc, char* argv[])
{
    printf("  >> func:%s(argc=%d, argv=%p) entry;(line:%d@%s)\n", __func__, argc, argv, __LINE__, __FILE__);
    int iret = 0;
    try
    {
        //parse args
        //get config
        CSimulator_t* ptrSim = new CSimulator_t(new CMyBochsCpu_t);
        
        iret = ptrSim->begin_simulator(argc, argv);
        
        delete ptrSim;
    }
    catch(...)
    {
        printf("  >> func:%s() exceptions;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    }
    
    printf("  >> func:%s() exit;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    
    return iret;
}

CMyBochsApp_t theApp;

//g++ -std=c++11 -g -Wall -O0 mybochs-la-0.1.0?.cpp -o myapp_exe_?
int main(int argc, char* argv[])
{
    printf("  >> func:%s(argc=%d, argv=%p) entry;(line:%d@%s)\n", __func__, argc, argv, __LINE__, __FILE__);
    
    int iret = 0;
    
    do
    {
        printf("  >> func:%s() do_working;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    
        CMyBochsApp_t* ptrApp = &theApp;
        
        iret = ptrApp->MainProc(argc, argv);
        
    }while(0);
    
    printf("  >> func:%s() exit(%d);(line:%d@%s)\n", __func__, iret, __LINE__, __FILE__);
    
    return 0;
}

#if 0
g++ -std=c++11 -g -Wall -O0 mybochs-la-0.1.00.cpp -o myapp_exe_0
g++ -std=c++11 -g -Wall -O0 mybochs-la-0.1.01.cpp -o myapp_exe_1
g++ -std=c++11 -g -Wall -O0 mybochs-la-0.1.02.cpp -o myapp_exe_2
#endif
