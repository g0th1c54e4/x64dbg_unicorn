#pragma once

#include <triton/context.hpp>
#include <triton/x86Specifications.hpp>
#include "pluginmain.h"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
//#include <Windows.h>
//#include <tlhelp32.h>


//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();
