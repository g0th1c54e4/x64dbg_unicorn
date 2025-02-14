#pragma once

#include "pluginmain.h"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <Windows.h>

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();
