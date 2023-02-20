// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <Windows.h>
#define DllExport   __declspec( dllexport )
using namespace std;
DllExport void Hello() {
    try {
        cout << "hello from cpp dll!\n";
    }
    catch(exception ex){
        cout << "stuff\n";
    }
}
DWORD Init(LPVOID lparam) {
    while (true) {
        Sleep(2000);
        cout << "running" << endl;
    }
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

