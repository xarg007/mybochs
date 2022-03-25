#include <cstdio>

extern int bx_main_proc(int argc, char* argv[]);

class CMyBochsApp_t
{
public:
    CMyBochsApp_t()
    {
        printf("  >> CMyBochsApp_t::CMyBochsApp_t() called.\n");
    }
    virtual ~CMyBochsApp_t()
    {
        printf("  >> CMyBochsApp_t::~CMyBochsApp_t() called.\n");
    }
public:
    virtual int MainProc(int argc, char* argv[])
    {
        printf("  >> CMyBochsApp_t::MainProc(argc=%d, argv=%p) called.\n", argc, argv);
        return bx_main_proc(argc, argv);
    }
public:
    static int TestFuncStatic(int iTest)
    {
        printf("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
        return 0;
    }
    int TestFunc(int iTest)
    {
        printf("  >> func:%s() called;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
        return 0;
    }
};

CMyBochsApp_t theApp;

int bx_main_proc(int argc, char* argv[])
{
    printf("  >> func:%s(argc=%d, argv=%p) entry;(line:%d@%s)\n", __func__, argc, argv, __LINE__, __FILE__);
    int iret = 0;
    try
    {
        int (*pFunc)(int) = &CMyBochsApp_t::TestFuncStatic;
        //pFunc = &CMyBochsApp_t::TestFuncStatic;
        iret = pFunc(0xfa);
        
        typedef int (CMyBochsApp_t::*pFuncPtr)(int);
        pFuncPtr pf = &CMyBochsApp_t::TestFunc;
        CMyBochsApp_t* ptrThis = &theApp;
        iret = (ptrThis->*(pFuncPtr)(pf))(0xbb);
        iret = (ptrThis->*(pf))(0xbc);
        throw 0;
    }
    catch(...)
    {
        printf("  >> func:%s() exceptions;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    }
    
    printf("  >> func:%s() exit;(line:%d@%s)\n", __func__, __LINE__, __FILE__);
    
    return iret;
}

int main(int argc, char* argv[])
{
    printf("  >> the mybochs app starting ... ...\n");
    int iret = 0;
    do
    {
        printf("   >> the mybochs app do_work().\n");
        CMyBochsApp_t* ptrApp = &theApp;
        iret = ptrApp->MainProc(argc, argv);
        
    }while(0);
    
    printf("  >> the mybochs app exit(%d).\n", iret);
    
    return 0;
}

