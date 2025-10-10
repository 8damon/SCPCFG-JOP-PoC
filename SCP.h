#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>

#ifndef SCP_ENABLE_LOGS
#define SCP_ENABLE_LOGS 1
#endif

BYTE* ScpcfgFindDispatchNoES(HMODULE hNtdll);

void* ScpcfgBuildThunkStrict(HMODULE hNtdll, void* target);
void ScpcfgFreeThunk(void* thunk);