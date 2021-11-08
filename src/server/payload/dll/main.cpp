#include <cstdio>
#include <wchar.h>

extern "C"
{
	// Opravdu velmi jednoduchý příklad škodlivého DLL
	// https://docs.microsoft.com/en-us/cpp/cpp/dllexport-dllimport
	__declspec(dllexport) void __cdecl Attack(void)
	{
		wprintf(L"Jednoduche demo - DLL");
	}
}