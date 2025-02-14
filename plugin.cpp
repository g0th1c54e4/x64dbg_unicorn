#include "plugin.h"

uint64_t get_stack_begin();
uint64_t get_stack_end();

uc_hook hookcode;
uc_hook hookMemInvalid;
uc_hook hookMem;
csh hCs = 0;

void Unicorn_error_print_infomation(uc_engine* uc) {
    dprintf("-------------------------------------------\n");
    dprintf("Registers:\n");
    auto get_reg = [&](uc_x86_reg ucreg) -> uint64_t {
        uint64_t val = 0;
        if (uc_reg_read(uc, ucreg, &val) != CS_ERR_OK) {
            dprintf("get_reg() failed.\n");
        }
        return val;
    };

    dprintf("RAX: %llX\n", get_reg(UC_X86_REG_RAX));
    dprintf("RBX: %llX\n", get_reg(UC_X86_REG_RBX));
    dprintf("RCX: %llX\n", get_reg(UC_X86_REG_RCX));
    dprintf("RDX: %llX\n", get_reg(UC_X86_REG_RDX));
    dprintf("RBP: %llX\n", get_reg(UC_X86_REG_RBP));
    dprintf("RSP: %llX\n", get_reg(UC_X86_REG_RSP));
    dprintf("RSI: %llX\n", get_reg(UC_X86_REG_RSI));
    dprintf("RDI: %llX\n", get_reg(UC_X86_REG_RDI));
    dprintf("\n");
    dprintf("R8: %llX\n", get_reg(UC_X86_REG_R8));
    dprintf("R9: %llX\n", get_reg(UC_X86_REG_R9));
    dprintf("R10: %llX\n", get_reg(UC_X86_REG_R10));
    dprintf("R11: %llX\n", get_reg(UC_X86_REG_R11));
    dprintf("R12: %llX\n", get_reg(UC_X86_REG_R12));
    dprintf("R13: %llX\n", get_reg(UC_X86_REG_R13));
    dprintf("R14: %llX\n", get_reg(UC_X86_REG_R14));
    dprintf("R15: %llX\n", get_reg(UC_X86_REG_R15));
    dprintf("\n");
    dprintf("RIP: %llX\n", get_reg(UC_X86_REG_RIP));
    dprintf("\n");
    dprintf("RFLAGS: %llX\n", get_reg(UC_X86_REG_RFLAGS));
    dprintf("\n");
    dprintf("Stack:  ('--->' is RSP)\n"); // 18个条目
    uint64_t rsp = get_reg(UC_X86_REG_RSP);
    for (uint64_t i = 0; i < 22; i++){ // 4个上部 18个下部
        uint64_t curRsp = (rsp - (4 * 8)) + (i * 8);
        uint64_t curRsp_data = 0;
        if (uc_mem_read(uc, curRsp, &curRsp_data, sizeof(uint64_t)) != CS_ERR_OK) {
            dprintf("uc_mem_read() failed.\n");
        }
        if (curRsp == rsp) {
            dprintf(" --->| %llX: \t%llX\n", curRsp, curRsp_data);
        }
        else {
            dprintf("     | %llX: \t%llX\n", curRsp, curRsp_data);
        }
        
    }

    dprintf("-------------------------------------------\n");
}

uint64_t Align(uint64_t value, uint64_t align_value) {
    if (value / align_value * align_value == value) {
        return value;
    }
    return ((value / align_value) + 1) * align_value;
}

typedef struct _MAPPER{
    duint addr;
    size_t len;
    bool mapped;
}MAPPER, * PMAPPER;
std::vector<MAPPER> gMappedMemoryInfo;

void EmuHookCode(uc_engine* uc, duint addr, size_t size, void* userdata){
    duint curRip;
    uc_reg_read(uc, UC_X86_REG_RIP, &curRip);

    uint8_t* codebuf = new uint8_t[size]();
    uc_mem_read(uc, addr, codebuf, size);
    cs_insn* ins = nullptr;
    cs_disasm(hCs, codebuf, size, addr, 0, &ins);
    dprintf("executing instruction at 0x%llX, size: %llu   comd: %s\t%s\n", addr, size, ins->mnemonic, ins->op_str);
    delete[] codebuf;
    
    //Script::Debug::SetBreakpoint(addr);
    //Script::Debug::Run();
    //Script::Debug::Wait();
    //Script::Debug::DeleteBreakpoint(addr);

    //auto get_reg = [&](uc_x86_reg ucreg) -> uint64_t {
    //    uint64_t val = 0;
    //    if (uc_reg_read(uc, ucreg, &val) != CS_ERR_OK) {
    //        dprintf("get_reg() failed.\n");
    //    }
    //    return val;
    //};

    //if (get_reg(UC_X86_REG_RSP) != Script::Register::GetRSP()) {
    //    Unicorn_error_print_infomation(uc);
    //    int a = 5;
    //}

    return;
}

// return false to stop emulation
bool EmuHookMemInvalid(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata){
    MAPPER lMemMap;
    unsigned char mem[PAGE_SIZE];
    uc_err err;

    duint modbase = Script::Module::GetMainModuleBase();
    duint modsize = Script::Module::GetMainModuleSize();
    if (!(address > modbase && address < (modbase + modsize))) {
        dprintf("Outer memory access: %llu\n", address);
    }

    duint curRip;
    uc_reg_read(uc, UC_X86_REG_RIP, &curRip);

    switch (type){
    default:
        return false;
    case UC_MEM_WRITE_UNMAPPED:
        dprintf("Unmapped Memory write reached | address: %llX   rip: %llX\n", address, curRip);
        return false;
    case UC_MEM_READ_UNMAPPED:
        dprintf("Unmapped memory read reached | address: %llX   rip: %llX\n", address, curRip);
        // Lets map the memory
        //TODO: Goes in a callback that ensures we're not mapping overlapped memory
        if (DbgMemIsValidReadPtr(address)){
            //Address is accessible. Map one page size at a time and save it
            if (DbgMemRead(address, mem, PAGE_SIZE)){
                // map the memory
                err = uc_mem_map(uc, address, PAGE_SIZE, UC_PROT_ALL);
                if (err != UC_ERR_OK){
                    dprintf("Something went wrong mapping the memory\n");
                    return false;
                }
                err = uc_mem_write(uc, address, mem, PAGE_SIZE);
                if (err != UC_ERR_OK){
                    dprintf("Error writing to the mapped memory\n");
                    return false;
                }
                //store info
                lMemMap.addr = address;
                lMemMap.len = PAGE_SIZE;
                lMemMap.mapped = true;
                gMappedMemoryInfo.push_back(lMemMap);
            }
            return true;
        }
        dprintf("Invalid Memory read\n");
        return false;
    case UC_MEM_FETCH_UNMAPPED:
        dprintf("Unmapped fetched memory reached\n");
        return false;
    }
    return true;
}

void EmuHookMem(uc_engine* uc, uc_mem_type type, duint address, int size, int64_t value, void* userdata){
    switch (type){
    default:
        break;
    case UC_MEM_READ:
        dprintf("Reading Memory at: %llX size: %u\n", address, size);
        break;
    case UC_MEM_WRITE:
        dprintf("Writing to Memory at: %llX, value: %llX, size: %u\n", address, value, size);
        break;
    }
    return;
}

// Command use the same signature as main in C
// argv[0] contains the full command, after that are the arguments
// NOTE: arguments are separated by a COMMA (not space like WinDbg)
static bool cbExampleCommand(int argc, char** argv) {

    auto parseExpr = [](const char* expression, duint& value){
        bool success = false;
        value = DbgEval(expression, &success);
        if (!success) {
            dprintf("Invalid expression '%s'\n", expression);
        }
        return success;
    };
    if (strcmp(argv[1], "print") == 0) {
        dprintf("ProcessID: 0x%x\n", DbgValFromString("$pid")); // 被调试的可执行文件的进程ID
        dprintf("hProcess: 0x%x\n", DbgValFromString("$hp")); // 调试的可执行文件句柄
        dprintf("\n");

        char modname[MAX_PATH] = { 0 };
        char path[MAX_PATH] = { 0 };
        Script::Module::GetMainModuleName(modname);
        Script::Module::GetMainModulePath(path);
        
        dprintf("name: %s\n", modname);
        dprintf("base: %llx\n", Script::Module::GetMainModuleBase());
        dprintf("entry: %llx\n", Script::Module::GetMainModuleEntry());
        dprintf("path: %s\n", path);
        dprintf("size: %llx\n", Script::Module::GetMainModuleSize());

        ListInfo modSecs;
        Script::Module::GetMainModuleSectionList(&modSecs);
        Script::Module::ModuleSectionInfo* sectionInfo(static_cast<Script::Module::ModuleSectionInfo*>(modSecs.data));
        for (int i = 0; i < modSecs.count; i++){
            dprintf("section name [%d]: %s\n", i, sectionInfo[i].name);
            dprintf("section addr [%d]: %llx\n", i, sectionInfo[i].addr);
            dprintf("section size [%d]: %llx\n", i, sectionInfo[i].size);
            dprintf("\n");
        }
        BridgeFree(sectionInfo);

        Script::Module::ModuleInfo mainMod;
        Script::Module::GetMainModuleInfo(&mainMod);

        ListInfo modExports;
        ListInfo modImports;
        Script::Module::GetExports(&mainMod, &modExports);
        Script::Module::GetImports(&mainMod, &modImports);
        Script::Module::ModuleExport* ExportInfo(static_cast<Script::Module::ModuleExport*>(modExports.data));
        Script::Module::ModuleImport* ImportInfo(static_cast<Script::Module::ModuleImport*>(modImports.data));
        for (int i = 0; i < modExports.count; i++) {
            dprintf("export name [%d]: %s\n", i, ExportInfo[i].name);
            dprintf("export rva [%d]: %llx\n", i, ExportInfo[i].rva);
            dprintf("export va [%d]: %llx\n", i, ExportInfo[i].va);
            dprintf("export forwarded [%d]: %d\n", i, ExportInfo[i].forwarded);
            dprintf("export forwardName [%d]: %s\n", i, ExportInfo[i].forwardName);
            dprintf("export ordinal [%d]: %llx\n", i, ExportInfo[i].ordinal);
            dprintf("\n");
        }
        for (int i = 0; i < modImports.count; i++) {
            dprintf("import name [%d]: %s\n", i, ImportInfo[i].name);
            dprintf("import ordinal [%d]: %llx\n", i, ImportInfo[i].ordinal);
            dprintf("import rva [%d]: %llx\n", i, ImportInfo[i].iatRva);
            dprintf("import va [%d]: %llx\n", i, ImportInfo[i].iatVa);
            dprintf("\n");
        }
        BridgeFree(ExportInfo);
        BridgeFree(ImportInfo);

        ListInfo mods;
        Script::Module::GetList(&mods);
        Script::Module::ModuleInfo* modInfo(static_cast<Script::Module::ModuleInfo*>(mods.data));
        for (int i = 0; i < mods.count; i++) {
            dprintf("module name [%d]: %s\n", i, modInfo[i].name);
            dprintf("module base [%d]: %llx\n", i, modInfo[i].base);
            dprintf("module entry [%d]: %llx\n", i, modInfo[i].entry);
            dprintf("module path [%d]: %s\n", i, modInfo[i].path);
            dprintf("module sectionCount [%d]: %d\n", i, modInfo[i].sectionCount);
            dprintf("module size [%d]: %llx\n", i, modInfo[i].size);
            dprintf("\n");
        }
        BridgeFree(modInfo);
    }
    if (strcmp(argv[1], "print2") == 0) {
        REGDUMP regs;
        if (!DbgGetRegDumpEx(&regs, sizeof(REGDUMP))) {
            return false;
        }

        dprintf("rax: %llx\n", Script::Register::Get(Script::Register::RAX));
        dprintf("rbx: %llx\n", Script::Register::Get(Script::Register::RBX));
        dprintf("rcx: %llx\n", Script::Register::Get(Script::Register::RCX));
        dprintf("rdx: %llx\n", Script::Register::Get(Script::Register::RDX));
        dprintf("rsi: %llx\n", Script::Register::Get(Script::Register::RSI));
        dprintf("rdi: %llx\n", Script::Register::Get(Script::Register::RDI));
        dprintf("rsp: %llx\n", Script::Register::Get(Script::Register::RSP));
        dprintf("rbp: %llx\n", Script::Register::Get(Script::Register::RBP));
        dprintf("rip: %llx\n", Script::Register::Get(Script::Register::RIP));
        dprintf("r8: %llx\n", Script::Register::Get(Script::Register::R8));
        dprintf("r9: %llx\n", Script::Register::Get(Script::Register::R9));
        dprintf("r10: %llx\n", Script::Register::Get(Script::Register::R10));
        dprintf("r11: %llx\n", Script::Register::Get(Script::Register::R11));
        dprintf("r12: %llx\n", Script::Register::Get(Script::Register::R12));
        dprintf("r13: %llx\n", Script::Register::Get(Script::Register::R13));
        dprintf("r14: %llx\n", Script::Register::Get(Script::Register::R14));
        dprintf("r15: %llx\n", Script::Register::Get(Script::Register::R15));

        dprintf("dr0: %llx\n", Script::Register::Get(Script::Register::DR0));
        dprintf("dr1: %llx\n", Script::Register::Get(Script::Register::DR1));
        dprintf("dr2: %llx\n", Script::Register::Get(Script::Register::DR2));
        dprintf("dr3: %llx\n", Script::Register::Get(Script::Register::DR3));
        dprintf("dr6: %llx\n", Script::Register::Get(Script::Register::DR6));
        dprintf("dr7: %llx\n", Script::Register::Get(Script::Register::DR7));

        dprintf("eflags: %llx\n", regs.regcontext.eflags);
        dprintf("zf: %d\n", Script::Flag::Get(Script::Flag::ZF));
        dprintf("of: %d\n", Script::Flag::Get(Script::Flag::OF));
        dprintf("cf: %d\n", Script::Flag::Get(Script::Flag::CF));
        dprintf("pf: %d\n", Script::Flag::Get(Script::Flag::PF));
        dprintf("sf: %d\n", Script::Flag::Get(Script::Flag::SF));
        dprintf("tf: %d\n", Script::Flag::Get(Script::Flag::TF));
        dprintf("af: %d\n", Script::Flag::Get(Script::Flag::AF));
        dprintf("df: %d\n", Script::Flag::Get(Script::Flag::DF));
        dprintf("if: %d\n", Script::Flag::Get(Script::Flag::IF));
        
        dprintf("cs: %x\n", regs.regcontext.cs);
        dprintf("ds: %x\n", regs.regcontext.ds);
        dprintf("fs: %x\n", regs.regcontext.fs);
        dprintf("ss: %x\n", regs.regcontext.ss);
        dprintf("gs: %x\n", regs.regcontext.gs);
        dprintf("es: %x\n", regs.regcontext.es);
    }

    return true;
}
static bool cbExampleCommand_unicorn(int argc, char** argv) {

    if (argc < 2) {
        dprintf("Usage: unicorn [final_addr]\n");
        return false;
    }

    auto parseExpr = [](const char* expression, duint& value) {
        bool success = false;
        value = DbgEval(expression, &success);
        if (!success) {
            dprintf("Invalid expression '%s'\n", expression);
        }
        return success;
    };

    uc_engine* uc;
    uc_err err;
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

    if (err != UC_ERR_OK) {
        dprintf("uc_open() failed!!!\n");
        return false;
    }
    duint modBase = Script::Module::GetMainModuleBase();
    duint modSize = Script::Module::GetMainModuleSize();
    if (uc_mem_map(uc, modBase, modSize, UC_PROT_ALL) != UC_ERR_OK) {
        dprintf("uc_mem_map() failed!!!\n");
        return false;
    }

    {
        uint8_t* buf = new uint8_t[modSize]();
        duint readsize = 0;
        if ((!Script::Memory::Read(modBase, buf, modSize, &readsize)) || (readsize != modSize)) {
            dprintf("Script::Memory::Read() failed!!!\n");
            return false;
        }

        if (uc_mem_write(uc, modBase, buf, modSize) != UC_ERR_OK) {
            dprintf("uc_mem_write() failed!!!\n");
            return false;
        }
        delete[] buf;
    }


    ListInfo modSecs;
    Script::Module::GetMainModuleSectionList(&modSecs);
    Script::Module::ModuleSectionInfo* sectionInfo(static_cast<Script::Module::ModuleSectionInfo*>(modSecs.data));
    for (int i = 0; i < modSecs.count; i++) {

        uint8_t* buf = new uint8_t[sectionInfo[i].size]();
        duint readsize = 0;
        if ((!Script::Memory::Read(sectionInfo[i].addr, buf, sectionInfo[i].size, &readsize)) || (readsize != sectionInfo[i].size)) {
            dprintf("Script::Memory::Read() failed!!!\n");
            return false;
        }

        if (uc_mem_write(uc, sectionInfo[i].addr, buf, sectionInfo[i].size) != UC_ERR_OK) {
            dprintf("uc_mem_write() failed!!!\n");
            return false;
        }
        delete[] buf;
    }
    BridgeFree(sectionInfo);

    auto write_uc_reg = [&](uc_x86_reg ucreg, Script::Register::RegisterEnum dbgreg) {
        duint reg_value = Script::Register::Get(dbgreg);
        if ((err = uc_reg_write(uc, ucreg, &reg_value)) != UC_ERR_OK) {
            dprintf("uc_reg_write() failed!!! ucreg:%d | err:%d\n", ucreg, err);
        }
        };

    REGDUMP regs;
    if (!DbgGetRegDumpEx(&regs, sizeof(REGDUMP))) {
        dprintf("DbgGetRegDumpEx() failed!!!\n");
        return false;
    }

    write_uc_reg(UC_X86_REG_RAX, Script::Register::RAX);
    write_uc_reg(UC_X86_REG_RBX, Script::Register::RBX);
    write_uc_reg(UC_X86_REG_RCX, Script::Register::RCX);
    write_uc_reg(UC_X86_REG_RDX, Script::Register::RDX);
    write_uc_reg(UC_X86_REG_RSP, Script::Register::RSP);
    write_uc_reg(UC_X86_REG_RBP, Script::Register::RBP);
    write_uc_reg(UC_X86_REG_RSI, Script::Register::RSI);
    write_uc_reg(UC_X86_REG_RDI, Script::Register::RDI);
    write_uc_reg(UC_X86_REG_RIP, Script::Register::RIP);
    write_uc_reg(UC_X86_REG_R8, Script::Register::R8);
    write_uc_reg(UC_X86_REG_R9, Script::Register::R9);
    write_uc_reg(UC_X86_REG_R10, Script::Register::R10);
    write_uc_reg(UC_X86_REG_R11, Script::Register::R11);
    write_uc_reg(UC_X86_REG_R12, Script::Register::R12);
    write_uc_reg(UC_X86_REG_R13, Script::Register::R13);
    write_uc_reg(UC_X86_REG_R14, Script::Register::R14);
    write_uc_reg(UC_X86_REG_R15, Script::Register::R15);

    auto write_uc_segreg = [&](uc_x86_reg ucreg, unsigned short seg) {
        if ((err = uc_reg_write(uc, ucreg, &seg)) != UC_ERR_OK) {
            dprintf("uc_reg_write() failed!!! ucreg:%d err:%d| \n", ucreg, err);
        }
        };
    write_uc_segreg(UC_X86_REG_CS, regs.regcontext.cs);
    write_uc_segreg(UC_X86_REG_DS, regs.regcontext.ds);
    write_uc_segreg(UC_X86_REG_FS_BASE, regs.regcontext.fs);
    write_uc_segreg(UC_X86_REG_GS_BASE, regs.regcontext.gs);
    write_uc_segreg(UC_X86_REG_SS, regs.regcontext.ss);
    write_uc_segreg(UC_X86_REG_ES, regs.regcontext.es);

    regs.regcontext.eflags &= (~0x100); // 清除TF位（因为x64dbg可能会设置此位，导致unicorn无法顺利执行）
    if ((err = uc_reg_write(uc, UC_X86_REG_RFLAGS, &(regs.regcontext.eflags))) != UC_ERR_OK) {
        dprintf("EFLAGS uc_reg_write() failed!!! err:%d\n", err);
        return false;
    }

    uint64_t rsp = Script::Register::GetRSP();
    uint64_t stack_begin = get_stack_begin();
    uint64_t stack_end = get_stack_end();
    uint64_t rip = Script::Register::GetRIP();
    uint64_t stack_size = stack_end - stack_begin;
    uint64_t stack_size_align = Align(stack_size, 0x1000);

    if ((err = uc_mem_map(uc, stack_begin, stack_size_align, UC_PROT_READ | UC_PROT_WRITE)) != UC_ERR_OK) {
        dprintf("uc_mem_map() failed!!! err:%d\n", err);
        return false;
    }

    uint8_t* buf = new uint8_t[stack_size_align]();
    duint readsize = 0;

    if ((!Script::Memory::Read(stack_begin, buf, stack_size, &readsize)) || (readsize != stack_size)) {
        dprintf("Script::Memory::Read() failed!!!\n");
        return false;
    }
    if (uc_mem_write(uc, stack_begin, buf, stack_size_align) != UC_ERR_OK) {
        dprintf("uc_mem_write() failed!!!\n");
        return false;
    }
    delete[] buf;

    //set hooks
    err = uc_hook_add(uc, &hookcode, UC_HOOK_CODE, EmuHookCode, nullptr, rip, rip + 0x100);
    if (err != UC_ERR_OK) {
        dprintf("Failed to register code hook\n");
        return false;
    }
    err = uc_hook_add(uc, &hookMemInvalid, UC_HOOK_MEM_INVALID, EmuHookMemInvalid, nullptr, 1, 0);
    if (err != UC_ERR_OK) {
        dprintf("Failed to register mem invalid hook\n");
        return false;
    }
    //err = uc_hook_add(uc, &hookMem, UC_HOOK_MEM_WRITE, EmuHookMem, nullptr, 1, 0);
    //if (err != UC_ERR_OK) {
    //    dprintf("Failed to register mem write\n");
    //    return false;
    //}

    duint final_addr = 0;
    parseExpr(argv[1], final_addr);

    if ((err = uc_emu_start(uc, rip, final_addr, 0, 0)) != UC_ERR_OK) {
        dprintf("uc_emu_start() failed!!! err:%d\n", err);
        Unicorn_error_print_infomation(uc);
        return false;
    }
    else {
        dprintf("uc_emu_start() success!!!\n");
        Unicorn_error_print_infomation(uc);
    }

    if (uc_close(uc) != UC_ERR_OK) {
        dprintf("uc_close() failed!!!\n");
        return false;
    }

    return true;
}

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct){
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);

    // Prefix of the functions to call here: _plugin_register
    _plugin_registercommand(pluginHandle, "xzc", cbExampleCommand, true);
    _plugin_registercommand(pluginHandle, "unicorn", cbExampleCommand_unicorn, true);

    // Return false to cancel loading the plugin.
    return true;
}

// Deinitialize your plugin data here.
// NOTE: you are responsible for gracefully closing your GUI
// This function is not executed on the GUI thread, so you might need
// to use WaitForSingleObject or similar to wait for everything to close.
void pluginStop(){
    // Prefix of the functions to call here: _plugin_unregister
    cs_close(&hCs);
}

// Do GUI/Menu related things here.
// This code runs on the GUI thread: GetCurrentThreadId() == GuiGetMainThreadId()
// You can get the HWND using GuiGetWindowHandle()
void pluginSetup(){
    // Prefix of the functions to call here: _plugin_menu
    cs_open(CS_ARCH_X86, CS_MODE_64, &hCs);
}

uint64_t get_stack_begin() {    // 不断减减减
    uint64_t rsp = Script::Register::GetRSP();
    while (Script::Memory::IsValidPtr(rsp)) {
        rsp -= 8;
    }
    return rsp + 8;
}

uint64_t get_stack_end() {     // 不断加加加
    uint64_t rsp = Script::Register::GetRSP();
    while (Script::Memory::IsValidPtr(rsp)) {
        rsp += 8;
    }
    return rsp - 8;
}