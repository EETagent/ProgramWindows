#include <cstdio>
#include <wchar.h>

extern "C"
{
	// Opravdu velmi jednoduchý pøíklad škodlivého DLL
	// https://docs.microsoft.com/en-us/cpp/cpp/dllexport-dllimport
	__declspec(dllexport) void __cdecl Attack(void)
	{
		wprintf(L"Jednoduché demo - DLL");
	}
}