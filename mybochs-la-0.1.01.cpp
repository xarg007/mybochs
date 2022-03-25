#include <cstdio>

class CMyBochsApp
{
public:
    CMyBochsApp()
    {
        printf("  >> CMyBochsApp::CMyBochsApp() called.\n");
    }
    virtual ~CMyBochsApp()
    {
        printf("  >> CMyBochsApp::~CMyBochsApp() called.\n");
    }
public:
    virtual int MainProc(int argc, char* argv[])
    {
        printf("  >> CMyBochsApp::~MainProc(argc=%d, argv=%p) called.\n", argc, argv);
        return 0;
    }
};

CMyBochsApp theApp;

int main(int argc, char* argv[])
{
    printf("  >> the mybochs app starting ... ...\n");
    int iret = 0;
    do
    {
        printf("   >> the mybochs app do_work().\n");
        CMyBochsApp* ptrApp = &theApp;
        iret = ptrApp->MainProc(argc, argv);
        
    }while(0);
    
    printf("  >> the mybochs app exit(%d).\n", iret);
    
    return 0;
}

