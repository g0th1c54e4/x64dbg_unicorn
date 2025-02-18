#pragma once

#include "pluginmain.h"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <triton/context.hpp>
#include <triton/x86Specifications.hpp>

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();
