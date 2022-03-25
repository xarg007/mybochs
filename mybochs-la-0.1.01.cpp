#include <cstdio>

class CMyBochsApp
{
public:
    CMyBochsApp()
    {
        printf("  >> CMyBochsApp::CMyBochsApp() called.\n");
    }
    ~CMyBochsApp()
    {
        printf("  >> CMyBochsApp::~CMyBochsApp() called.\n");
    }
    public:
    int MainProc(int argc, char* argv[])
    {
        printf("  >> CMyBochsApp::~MainProc(argc=%d, argv=%p) called.\n", argc, argv);
        return 0;
    }
};

CMyBochsApp theApp;

int main(int argc, char* argv[])
{
    printf("  >> the mybochs app starting ... ...\n");
    
    do
    {
        printf("   >> the mybochs app do_work().\n");
        CMyBochsApp* ptrApp = &theApp;
        ptrApp->MainProc(argc, argv);
        
    }while(0);
    
    printf("  >> the mybochs app starting ... ...\n");
    
    return 0;
}

