#include <cstdio>
#include <wchar.h>

extern "C"
{
	// Opravdu velmi jednoduch� p��klad �kodliv�ho DLL
	// https://docs.microsoft.com/en-us/cpp/cpp/dllexport-dllimport
	__declspec(dllexport) void __cdecl Attack(void)
	{
		wprintf(L"Jednoduch� demo - DLL");
	}
}