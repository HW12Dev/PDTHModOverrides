#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>
#include <unknwn.h>

static HMODULE pdthmodoverrides_dll = NULL;

HMODULE dinput8_dll;

#pragma comment(lib, "user32.lib")

// same as __declspec(dllexport), but with the raw unmangled name
#pragma comment(linker, "/EXPORT:DirectInput8Create=_DirectInput8Create@20")

extern "C" {
  HRESULT(WINAPI* DirectInput8Create_o)(HINSTANCE hInst, DWORD dwVersion, REFIID riidltf, LPVOID* ppvOut, LPUNKNOWN punkOuter);
  HRESULT WINAPI DirectInput8Create(HINSTANCE hInst, DWORD dwVersion, REFIID riidltf, LPVOID* ppvOut, LPUNKNOWN punkOuter)
  {
    return DirectInput8Create_o(hInst, dwVersion, riidltf, ppvOut, punkOuter);
  }
}


BOOL APIENTRY DllMain(HMODULE hmodule, DWORD reason, LPVOID reserved)
{
  if (reason == DLL_PROCESS_ATTACH)
  {
    DisableThreadLibraryCalls(hmodule);

    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat_s(systemPath, "\\dinput8.dll");
    dinput8_dll = LoadLibraryA(systemPath);

    DirectInput8Create_o = (decltype(DirectInput8Create_o))GetProcAddress(dinput8_dll, "DirectInput8Create");

    if (!dinput8_dll)
      return 0;
    pdthmodoverrides_dll = LoadLibrary("PDTHModOverrides.dll");
  }
  if (reason == DLL_PROCESS_DETACH)
  {
    FreeLibrary(dinput8_dll);
    FreeLibrary(pdthmodoverrides_dll);
  }
  return TRUE;
}