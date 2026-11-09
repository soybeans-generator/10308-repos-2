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
    wchar_t root[MAX_PATH], bla[MAX_PATH];
    GetTempPathW(MAX_PATH, root);
    lstrcatW(root, L"playReady");
    swprintf_s(bla, L"%s\\Cache\\msprcore.bla", root);
    CreateDirectoryW(root, nullptr);

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
    CK(InitPropVariantFromString(root, &sp));
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
    sess->GenerateRequest(L"cenc", one, 1);

    for (int i = 0; i < 480; i++) {
        if (GetFileAttributesW(bla) != INVALID_FILE_ATTRIBUTES) {
            std::printf("%ls\n", bla);
            return 0;
        }
        Sleep(250);
    }
    std::printf("[!] no msprcore.bla in 120s\n");
    return 1;
}
