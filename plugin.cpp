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

static bool EnumAllMemoryBlocks(HANDLE hProcess, std::vector<MEMORY_BASIC_INFORMATION>& memories) {

    memories.clear();
    memories.reserve(200);

    SYSTEM_INFO sysInfo = { 0 };
    GetSystemInfo(&sysInfo);

    const char* p = (const char*)sysInfo.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION  memInfo = { 0 };
    while (p < sysInfo.lpMaximumApplicationAddress) {
        size_t size = VirtualQueryEx(
            hProcess,								// 进程句柄
            p,										// 要查询内存块的基地址指针
            &memInfo,								// 接收内存块信息的 MEMORY_BASIC_INFORMATION 对象
            sizeof(MEMORY_BASIC_INFORMATION32)		// 缓冲区大小
        );
        if (size == 0) {
            dprintf("VirtualQueryEx() failed. err: %d\n", GetLastError());
        }
        if (size != sizeof(MEMORY_BASIC_INFORMATION32)) { 
            break;
        }
        memories.push_back(memInfo);
        p += memInfo.RegionSize;
    }

    return memories.size() > 0;
}

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

        dprintf("ProcessID: 0x%X\n", DbgGetProcessId()); // 被调试的可执行文件的进程ID
        dprintf("hProcess: 0x%X\n", (duint)DbgGetProcessHandle()); // 调试的可执行文件句柄

        dprintf("Stack Begin: %llX\n", get_stack_begin());
        dprintf("Stack End: %llX\n", get_stack_end());

        MEMMAP map{};
        DbgMemMap(&map);
        for (int i = 0; i < map.count; i++){
            map.page[i];
            dprintf("AllocationBase: %p\n", map.page[i].mbi.AllocationBase);
            dprintf("AllocationProtect: %lu\n", map.page[i].mbi.AllocationProtect);
            dprintf("BaseAddress: %p\n", map.page[i].mbi.BaseAddress); //
            dprintf("RegionSize: %llX\n", map.page[i].mbi.RegionSize); //
            //dprintf("State: %lX\n", map.page[i].mbi.State);

            switch (map.page[i].mbi.Type){
            default: break;
            case MEM_IMAGE:
                dprintf("Type: IMG\n"); break;
            case MEM_MAPPED:
                dprintf("Type: MAP\n"); break;
            case MEM_PRIVATE:
                dprintf("Type: PRV\n"); break;
            }

            
            dprintf("Protect: %lX\n", map.page[i].mbi.Protect); //
            
            dprintf("--------------------------\n");
        }

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

    { // 对诸如"堆"的内存区域进行初始化
        MEMMAP map{};
        DbgMemMap(&map);
        for (int i = 0; i < map.count; i++) {
            if (map.page[i].mbi.Type == MEM_IMAGE) { // 是exe或dll
                continue;
            }
            if (map.page[i].mbi.Protect == 0 || map.page[i].mbi.Protect == PAGE_NOACCESS) { // 没权限
                continue;
            }
            if (map.page[i].mbi.RegionSize > 0x000000007FFFFFFF) { // 太大了
                continue;
            }
            uint64_t mem_addr = (uint64_t)map.page[i].mbi.BaseAddress;
            uint64_t mem_size = (uint64_t)map.page[i].mbi.RegionSize;
            if ((err = uc_mem_map(uc, mem_addr, mem_size, UC_PROT_ALL)) != UC_ERR_OK) {
                dprintf("uc_mem_map() failed!!! err:%d\n", err);
                return false;
            }
            uint8_t* buf = new uint8_t[mem_size]();
            duint readsize = 0;
            if ((!Script::Memory::Read(mem_addr, buf, mem_size, &readsize)) || (readsize != mem_size)) {
                dprintf("Script::Memory::Read() failed!!!\n");
                delete[] buf;
                return false;
            }
            if (uc_mem_write(uc, mem_addr, buf, mem_size) != UC_ERR_OK) {
                dprintf("uc_mem_write() failed!!!\n");
                delete[] buf;
                return false;
            }
            delete[] buf;
        }
    }

    {
        uint8_t* buf = new uint8_t[modSize]();
        duint readsize = 0;
        if ((!Script::Memory::Read(modBase, buf, modSize, &readsize)) || (readsize != modSize)) {
            dprintf("Script::Memory::Read() failed!!!\n");
            delete[] buf;
            return false;
        }

        if (uc_mem_write(uc, modBase, buf, modSize) != UC_ERR_OK) {
            dprintf("uc_mem_write() failed!!!\n");
            delete[] buf;
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

bool pluginInit(PLUG_INITSTRUCT* initStruct){
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);

    cs_open(CS_ARCH_X86, CS_MODE_64, &hCs);
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
    cs_close(&hCs);
}

// Do GUI/Menu related things here.
// This code runs on the GUI thread: GetCurrentThreadId() == GuiGetMainThreadId()
// You can get the HWND using GuiGetWindowHandle()
void pluginSetup(){
    
}

uint64_t get_stack_begin() {
    uint64_t rsp = Script::Register::GetRSP();
    MEMMAP map{};
    DbgMemMap(&map);
    for (int i = 0; i < map.count; i++) {
        if ((uint64_t)map.page[i].mbi.BaseAddress <= rsp &&
            ((uint64_t)map.page[i].mbi.BaseAddress + map.page[i].mbi.RegionSize) >= rsp) {
            return (uint64_t)map.page[i].mbi.BaseAddress;
        }
    }
    dprintf("get_stack_begin() returnd 0, failed!");
    return 0;
}
uint64_t get_stack_end() {
    uint64_t rsp = Script::Register::GetRSP();
    MEMMAP map{};
    DbgMemMap(&map);
    for (int i = 0; i < map.count; i++) {
        if ((uint64_t)map.page[i].mbi.BaseAddress <= rsp &&
            ((uint64_t)map.page[i].mbi.BaseAddress + map.page[i].mbi.RegionSize) >= rsp) {
            return (uint64_t)map.page[i].mbi.BaseAddress + map.page[i].mbi.RegionSize - 8;
        }
    }
    dprintf("get_stack_end() returnd 0, failed!");
    return 0;
}