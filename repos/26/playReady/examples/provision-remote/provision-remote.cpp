#include <windows.h>
#include <mfmediaengine.h>
#include <mfcontentdecryptionmodule.h>
#include <propvarutil.h>
#include <wrl/client.h>
#include <cstdio>

using namespace Microsoft::WRL;

#define CK(e) do { HRESULT _h = (e); if (FAILED(_h)) { \
    std::printf("[x] %s -> 0x%08X\n", #e, (unsigned)_h); return 1; } } while (0)

int main()
{
    CreateDirectoryW(L"testdata", nullptr);

    CK(CoInitializeEx(nullptr, COINIT_MULTITHREADED));

    ComPtr<IMFMediaEngineClassFactory4> cf;
    CK(CoCreateInstance(CLSID_MFMediaEngineClassFactory, nullptr,
                        CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&cf)));

    ComPtr<IMFContentDecryptionModuleFactory> fac;
    CK(cf->CreateContentDecryptionModuleFactory(L"com.microsoft.playready",
                                                IID_PPV_ARGS(&fac)));

    ComPtr<IPropertyStore> st;
    CK(PSCreateMemoryPropertyStore(IID_PPV_ARGS(&st)));
    PROPVARIANT sp;
    CK(InitPropVariantFromString(L"testdata", &sp));
    st->SetValue(MF_CONTENTDECRYPTIONMODULE_STOREPATH, sp);
    IPropertyStore* cfgs[1] = { st.Get() };

    ComPtr<IMFContentDecryptionModuleAccess> access;
    CK(fac->CreateContentDecryptionModuleAccess(L"com.microsoft.playready",
                                                cfgs, 1, &access));

    ComPtr<IMFContentDecryptionModule> cdm;
    CK(access->CreateContentDecryptionModule(st.Get(), &cdm));

    ComPtr<IMFContentDecryptionModuleSession> sess;
    CK(cdm->CreateSession(MF_MEDIAKEYSESSION_TYPE_TEMPORARY, nullptr, &sess));

    static const BYTE one[1] = { 0 };
    HRESULT gr = sess->GenerateRequest(L"cenc", one, 1);
    std::printf("[i] GenerateRequest -> 0x%08X\n", (unsigned)gr);

    Sleep(2000);

    if (GetFileAttributesW(L"testdata/Cache/msprcore.bla") != INVALID_FILE_ATTRIBUTES)
        return 0;
    std::printf("[!] no msprcore.bla after 2s\n");
    return 1;
}
