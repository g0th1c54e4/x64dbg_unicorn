#include "plugin.h"

uint64_t get_module_export_function(std::string dll_name, std::string func_name);

uint64_t get_stack_begin();
uint64_t get_stack_end();

uc_hook hookcode;
uc_hook hookMemInvalid;
uc_hook hookMem;
uc_hook hookIntr;

csh hCs = 0;

enum {
    MENU_QUICK_EMU,
};

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

void EmuHookSyscall(uc_engine* uc, uint32_t intno, void* user_data) {
    duint curRip;
    uc_reg_read(uc, UC_X86_REG_RIP, &curRip);

    dprintf("Found SYSCALL Instruction!  location: %llX\n", curRip);

    //curRip = 0x55555555;
    //uc_reg_write(uc, UC_X86_REG_RIP, &curRip); // 可以修改RIP!!!
}

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
    duint curRip;
    uc_reg_read(uc, UC_X86_REG_RIP, &curRip);
    switch (type) {
    default:
        return false;
    case UC_MEM_WRITE_UNMAPPED:
        dprintf("Unmapped Memory WRITE reached | address: %llX   rip: %llX\n", address, curRip);
        return false;
    case UC_MEM_READ_UNMAPPED:
        dprintf("Unmapped memory READ reached | address: %llX   rip: %llX\n", address, curRip);
        return false;
    case UC_MEM_FETCH_UNMAPPED:
        dprintf("Unmapped memory FETCH reached | address: %llX   rip: %llX\n", address, curRip);
        return false;
    case UC_MEM_FETCH_PROT:
        //dprintf("Exec to Memory at: %llX, value: %llX, size: %u\n", address, value, size);
        break;
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

        dprintf("Peb: %llX\n", DbgGetPebAddress(DbgGetProcessId()));
        dprintf("Teb: %llX\n", DbgGetTebAddress(DbgGetThreadId()));
        dprintf("GS Base: %llX\n", DbgGetTebAddress(DbgGetThreadId())); // gs_base

        //MEMMAP map{};
        //DbgMemMap(&map);
        //uint64_t totalSize = 0;
        //for (int i = 0; i < map.count; i++){
        //    map.page[i];
        //    dprintf("AllocationBase: %p\n", map.page[i].mbi.AllocationBase);
        //    dprintf("AllocationProtect: %lu\n", map.page[i].mbi.AllocationProtect);
        //    dprintf("BaseAddress: %p\n", map.page[i].mbi.BaseAddress); //
        //    dprintf("RegionSize: %llX\n", map.page[i].mbi.RegionSize); //
        //    //dprintf("State: %lX\n", map.page[i].mbi.State);

        //    switch (map.page[i].mbi.Type){
        //    default: break;
        //    case MEM_IMAGE:
        //        dprintf("Type: IMG\n"); break;
        //    case MEM_MAPPED:
        //        dprintf("Type: MAP\n"); break;
        //    case MEM_PRIVATE:
        //        dprintf("Type: PRV\n"); break;
        //    }
        //    
        //    dprintf("Protect: %lX\n", map.page[i].mbi.Protect); //
        //    
        //    dprintf("--------------------------\n");
        //    totalSize += map.page[i].mbi.RegionSize;
        //}
        //dprintf("Memory Map Total Size: 0x%llX\n", totalSize);
    }
    if (strcmp(argv[1], "print2") == 0) {
        uint64_t addr = get_module_export_function(argv[2], argv[3]);
        dprintf("export function address: %llX\n", addr);
    }

    return true;
}
bool unicorn_main_emu(uint64_t final_addr) {

    auto free_uc = [](uc_engine* uc) -> bool {
        uc_err err;
        uc_mem_region* region;
        uint32_t count;
        if ((err = uc_mem_regions(uc, &region, &count)) != UC_ERR_OK) {
            dprintf("uc_mem_regions() failed!!! err:%d\n", err);
            return false;
        }
        for (int i = 0; i < count; i++) {
            size_t mapsize = (region[i].end - region[i].begin) + 1;
            if ((err = uc_mem_unmap(uc, region[i].begin, mapsize)) != UC_ERR_OK) {
                dprintf("uc_mem_unmap() failed!!! err:%d\n", err);
                return false;
            }
        }
        if ((err = uc_free(region))) {
            dprintf("uc_free() failed!!! err:%d\n", err);
            return false;
        }
        if ((err = uc_close(uc)) != UC_ERR_OK) {
            dprintf("uc_close() failed!!! err:%d\n", err);
            return false;
        }
        return true;
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
    { // 对诸如"堆"的内存区域进行初始化
        MEMMAP map{};
        DbgMemMap(&map);
        for (int i = 0; i < map.count; i++) {
            //if (map.page[i].mbi.Type == MEM_IMAGE) { // 是exe或dll
            //    continue;
            //}
            if (map.page[i].mbi.Protect == 0 || map.page[i].mbi.Protect == PAGE_NOACCESS || !DbgMemIsValidReadPtr((duint)map.page[i].mbi.BaseAddress)) { // 没权限
                continue;
            }
            uint64_t mem_addr = (uint64_t)map.page[i].mbi.BaseAddress;
            uint64_t mem_size = (uint64_t)map.page[i].mbi.RegionSize;
            uint32_t prot = UC_PROT_ALL;
            if (map.page[i].mbi.Type == MEM_IMAGE && !(mem_addr >= modBase && (mem_addr + mem_size) <= (modBase + modSize))) {
                prot = UC_PROT_READ | UC_PROT_WRITE;
            }
            if ((err = uc_mem_map(uc, mem_addr, mem_size, prot)) != UC_ERR_OK) {
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
            if ((err = uc_mem_write(uc, mem_addr, buf, mem_size)) != UC_ERR_OK) {
                dprintf("uc_mem_write() failed!!! err:%d\n", err);
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
            free_uc(uc);
            delete[] buf;
            return false;
        }

        if ((err = uc_mem_write(uc, modBase, buf, modSize)) != UC_ERR_OK) {
            dprintf("uc_mem_write() failed!!! err:%d\n", err);
            free_uc(uc);
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
            free_uc(uc);
            delete[] buf;
            return false;
        }

        if ((err = uc_mem_write(uc, sectionInfo[i].addr, buf, sectionInfo[i].size)) != UC_ERR_OK) {
            dprintf("uc_mem_write() failed!!! err:%d\n", err);
            free_uc(uc);
            delete[] buf;
            return false;
        }
        delete[] buf;
    }
    BridgeFree(sectionInfo);

    auto write_uc_reg_withdbg = [&](uc_x86_reg ucreg, Script::Register::RegisterEnum dbgreg) {
        duint reg_value = Script::Register::Get(dbgreg);
        if ((err = uc_reg_write(uc, ucreg, &reg_value)) != UC_ERR_OK) {
            dprintf("uc_reg_write() failed!!! ucreg:%d | err:%d\n", ucreg, err);
        }
        };

    REGDUMP regs;
    if (!DbgGetRegDumpEx(&regs, sizeof(REGDUMP))) {
        dprintf("DbgGetRegDumpEx() failed!!!\n");
        free_uc(uc);
        return false;
    }

    write_uc_reg_withdbg(UC_X86_REG_RAX, Script::Register::RAX);
    write_uc_reg_withdbg(UC_X86_REG_RBX, Script::Register::RBX);
    write_uc_reg_withdbg(UC_X86_REG_RCX, Script::Register::RCX);
    write_uc_reg_withdbg(UC_X86_REG_RDX, Script::Register::RDX);
    write_uc_reg_withdbg(UC_X86_REG_RSP, Script::Register::RSP);
    write_uc_reg_withdbg(UC_X86_REG_RBP, Script::Register::RBP);
    write_uc_reg_withdbg(UC_X86_REG_RSI, Script::Register::RSI);
    write_uc_reg_withdbg(UC_X86_REG_RDI, Script::Register::RDI);
    write_uc_reg_withdbg(UC_X86_REG_RIP, Script::Register::RIP);
    write_uc_reg_withdbg(UC_X86_REG_R8, Script::Register::R8);
    write_uc_reg_withdbg(UC_X86_REG_R9, Script::Register::R9);
    write_uc_reg_withdbg(UC_X86_REG_R10, Script::Register::R10);
    write_uc_reg_withdbg(UC_X86_REG_R11, Script::Register::R11);
    write_uc_reg_withdbg(UC_X86_REG_R12, Script::Register::R12);
    write_uc_reg_withdbg(UC_X86_REG_R13, Script::Register::R13);
    write_uc_reg_withdbg(UC_X86_REG_R14, Script::Register::R14);
    write_uc_reg_withdbg(UC_X86_REG_R15, Script::Register::R15);

    auto write_uc_reg = [&](uc_x86_reg ucreg, uint64_t val) {
        if ((err = uc_reg_write(uc, ucreg, &val)) != UC_ERR_OK) {
            dprintf("uc_reg_write() failed!!! ucreg:%d err:%d| \n", ucreg, err);
        }
    };

    write_uc_reg(UC_X86_REG_CS, regs.regcontext.cs);
    write_uc_reg(UC_X86_REG_DS, regs.regcontext.ds);
    //write_uc_reg(UC_X86_REG_FS_BASE, regs.regcontext.fs);
    uint64_t gs_base = DbgGetTebAddress(DbgGetThreadId()); // TEB address
    write_uc_reg(UC_X86_REG_GS_BASE, gs_base);
    write_uc_reg(UC_X86_REG_SS, regs.regcontext.ss);
    write_uc_reg(UC_X86_REG_ES, regs.regcontext.es);

    regs.regcontext.eflags &= (~0x100); // 清除TF位（因为x64dbg可能会设置此位，导致unicorn无法顺利地模拟执行）
    if ((err = uc_reg_write(uc, UC_X86_REG_RFLAGS, &(regs.regcontext.eflags))) != UC_ERR_OK) {
        dprintf("EFLAGS uc_reg_write() failed!!! err:%d\n", err);
        free_uc(uc);
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
        free_uc(uc);
        delete[] buf;
        return false;
    }
    if ((err = uc_mem_write(uc, stack_begin, buf, stack_size_align)) != UC_ERR_OK) {
        dprintf("uc_mem_write() failed!!! err:%d\n", err);
        free_uc(uc);
        delete[] buf;
        return false;
    }
    delete[] buf;

    //set hooks
    err = uc_hook_add(uc, &hookcode, UC_HOOK_CODE, EmuHookCode, nullptr, 1, 0);
    if (err != UC_ERR_OK) {
        dprintf("Failed to register code hook\n");
        free_uc(uc);
        return false;
    }
    err = uc_hook_add(uc, &hookMemInvalid, UC_HOOK_MEM_INVALID, EmuHookMemInvalid, nullptr, 1, 0);
    if (err != UC_ERR_OK) {
        dprintf("Failed to register mem invalid hook\n");
        free_uc(uc);
        return false;
    }

    err = uc_hook_add(uc, &hookIntr, UC_HOOK_INSN, EmuHookSyscall, nullptr, 1, 0, UC_X86_INS_SYSCALL);
    if (err != UC_ERR_OK) {
        dprintf("Failed to register syscall hook\n");
        free_uc(uc);
        return false;
    }

    //err = uc_hook_add(uc, &hookMem, UC_HOOK_MEM_WRITE, EmuHookMem, nullptr, 1, 0);
    //if (err != UC_ERR_OK) {
    //    dprintf("Failed to register mem write\n");
    //    return false;
    //}

    if ((err = uc_emu_start(uc, rip, final_addr, 0, 0)) != UC_ERR_OK) {
        dprintf("uc_emu_start() failed!!! err:%d\n", err);
        Unicorn_error_print_infomation(uc);
        free_uc(uc);
        return false;
    }
    else {
        dprintf("uc_emu_start() success!!!\n");
        Unicorn_error_print_infomation(uc);
    }
    free_uc(uc);

    return true;
}
static bool cbExampleCommand_unicorn(int argc, char** argv) {

    if (argc < 2) {
        dprintf("Usage: unicorn [final_addr]\n");
        return false;
    }
    DbgScriptCmdExec("ClearLog"); // 清屏
    
    auto parseExpr = [](const char* expression, duint& value) {
        bool success = false;
        value = DbgEval(expression, &success);
        if (!success) {
            dprintf("Invalid expression '%s'\n", expression);
        }
        return success;
    };

    duint final_addr = 0;
    parseExpr(argv[1], final_addr);

    return unicorn_main_emu(final_addr);
}

using namespace triton;
using namespace triton::arch;
using namespace triton::arch::x86;



bool cbExampleCommand_triton(int argc, char** argv) { // 千万不要在Debug配置下运行，不然triton会出现莫名其妙的BUG

    DbgScriptCmdExec("ClearLog"); // 清屏

    triton::Context* ctx = new triton::Context(ARCH_X86_64);
    ctx->setMode(triton::modes::mode_e::ALIGNED_MEMORY, true);
    ctx->setAstRepresentationMode(triton::ast::representations::mode_e::PYTHON_REPRESENTATION);
    
    { // 对诸如"堆"的内存区域进行初始化
        MEMMAP map{};
        DbgMemMap(&map);
        for (int i = 0; i < map.count; i++) {
            if (map.page[i].mbi.Protect == 0 || map.page[i].mbi.Protect == PAGE_NOACCESS || !DbgMemIsValidReadPtr((duint)map.page[i].mbi.BaseAddress)) { // 没权限
                continue;
            }

            uint64_t mem_addr = (uint64_t)map.page[i].mbi.BaseAddress;
            uint64_t mem_size = (uint64_t)map.page[i].mbi.RegionSize;
            uint8_t* buf = new uint8_t[mem_size]();
            duint readsize = 0;
            if ((!Script::Memory::Read(mem_addr, buf, mem_size, &readsize)) || (readsize != mem_size)) {
                dprintf("Script::Memory::Read() failed!!!\n");
                delete[] buf;
                return false;
            }
            ctx->setConcreteMemoryAreaValue(mem_addr, buf, mem_size);
            delete[] buf;
        }
    }

    //{
    //    duint modBase = Script::Module::GetMainModuleBase();
    //    duint modSize = Script::Module::GetMainModuleSize();
    //    uint8_t* buf = new uint8_t[modSize]();
    //    duint readsize = 0;
    //    if ((!Script::Memory::Read(modBase, buf, modSize, &readsize)) || (readsize != modSize)) {
    //        dprintf("Script::Memory::Read() failed!!!\n");
    //        delete[] buf;
    //        return false;
    //    }
    //    ctx->setConcreteMemoryAreaValue(modBase, buf, modSize);
    //    delete[] buf;
    //}
    //ListInfo modSecs;
    //Script::Module::GetMainModuleSectionList(&modSecs);
    //Script::Module::ModuleSectionInfo* sectionInfo(static_cast<Script::Module::ModuleSectionInfo*>(modSecs.data));
    //for (int i = 0; i < modSecs.count; i++) {
    //    uint8_t* buf = new uint8_t[sectionInfo[i].size]();
    //    duint readsize = 0;
    //    if ((!Script::Memory::Read(sectionInfo[i].addr, buf, sectionInfo[i].size, &readsize)) || (readsize != sectionInfo[i].size)) {
    //        dprintf("Script::Memory::Read() failed!!!\n");
    //        delete[] buf;
    //        return false;
    //    }
    //    ctx->setConcreteMemoryAreaValue(sectionInfo[i].addr, buf, sectionInfo[i].size);
    //    delete[] buf;
    //}
    //BridgeFree(sectionInfo);

    REGDUMP regs;
    if (!DbgGetRegDumpEx(&regs, sizeof(REGDUMP))) {
        dprintf("DbgGetRegDumpEx() failed!!!\n");
        return false;
    }
    
    auto write_triton_reg_withdbg = [&](const triton::arch::Register& reg, Script::Register::RegisterEnum dbgreg) {
        duint reg_value = Script::Register::Get(dbgreg);
        ctx->setConcreteRegisterValue(reg, (uint64_t)reg_value);
    };

    write_triton_reg_withdbg(ctx->registers.x86_rax, Script::Register::RAX);
    write_triton_reg_withdbg(ctx->registers.x86_rbx, Script::Register::RBX);
    write_triton_reg_withdbg(ctx->registers.x86_rcx, Script::Register::RCX);
    write_triton_reg_withdbg(ctx->registers.x86_rdx, Script::Register::RDX);
    write_triton_reg_withdbg(ctx->registers.x86_rsp, Script::Register::RSP);
    write_triton_reg_withdbg(ctx->registers.x86_rbp, Script::Register::RBP);
    write_triton_reg_withdbg(ctx->registers.x86_rsi, Script::Register::RSI);
    write_triton_reg_withdbg(ctx->registers.x86_rdi, Script::Register::RDI);
    write_triton_reg_withdbg(ctx->registers.x86_rip, Script::Register::RIP);
    write_triton_reg_withdbg(ctx->registers.x86_r8 , Script::Register::R8);
    write_triton_reg_withdbg(ctx->registers.x86_r9 , Script::Register::R9);
    write_triton_reg_withdbg(ctx->registers.x86_r10, Script::Register::R10);
    write_triton_reg_withdbg(ctx->registers.x86_r11, Script::Register::R11);
    write_triton_reg_withdbg(ctx->registers.x86_r12, Script::Register::R12);
    write_triton_reg_withdbg(ctx->registers.x86_r13, Script::Register::R13);
    write_triton_reg_withdbg(ctx->registers.x86_r14, Script::Register::R14);
    write_triton_reg_withdbg(ctx->registers.x86_r15, Script::Register::R15);

    ctx->setConcreteRegisterValue(ctx->registers.x86_cs, regs.regcontext.cs);
    ctx->setConcreteRegisterValue(ctx->registers.x86_ds, regs.regcontext.ds);
    ctx->setConcreteRegisterValue(ctx->registers.x86_fs, regs.regcontext.fs);
    ctx->setConcreteRegisterValue(ctx->registers.x86_gs, regs.regcontext.gs);
    ctx->setConcreteRegisterValue(ctx->registers.x86_ss, regs.regcontext.ss);
    ctx->setConcreteRegisterValue(ctx->registers.x86_es, regs.regcontext.es);

    regs.regcontext.eflags &= (~0x100); // 清除TF位（因为x64dbg可能会设置此位，导致triton无法顺利地模拟执行）
    ctx->setConcreteRegisterValue(ctx->registers.x86_eflags, regs.regcontext.eflags);

    uint64_t stack_begin = get_stack_begin();
    uint64_t stack_end = get_stack_end();
    uint64_t stack_size = stack_end - stack_begin;
    uint64_t stack_size_align = Align(stack_size, 0x1000);

    uint8_t* buf = new uint8_t[stack_size_align]();
    duint readsize = 0;

    if ((!Script::Memory::Read(stack_begin, buf, stack_size, &readsize)) || (readsize != stack_size)) {
        dprintf("Script::Memory::Read() failed!!!\n");
        delete[] buf;
        return false;
    }
    ctx->setConcreteMemoryAreaValue(stack_begin, buf, stack_size_align);
    delete[] buf;

    SELECTIONDATA sel;
    GuiSelectionGet(GUI_DISASSEMBLY, &sel);
    dprintf("Seting Until Address: %llX\n", sel.start);
    
    ctx->taintRegister(ctx->registers.x86_rsi);
    while (true) {
        Instruction inst;
        uint64_t rip = (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rip);
        if (rip == sel.start) {
            break;
        }

        uint8_t codebuf[16]{};
        duint readsize = 0;
        Script::Memory::Read(rip, codebuf, 16, &readsize);
        inst.setAddress(rip);
        inst.setOpcode(codebuf, readsize);
        ctx->processing(inst);
        if (inst.isTainted()) {
            dprintf("Tainted: %llx\n", inst.getAddress());
        }
    }
    dprintf("\n");
    {
        dprintf("-------------------------------------------\n");
        dprintf("Registers:\n");

        dprintf("rax: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rax));
        dprintf("rbx: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rbx));
        dprintf("rcx: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rcx));
        dprintf("rdx: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rdx));
        dprintf("rsp: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rsp));
        dprintf("rbp: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rbp));
        dprintf("rsi: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rsi));
        dprintf("rdi: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rdi));
        dprintf("\n");
        dprintf("r8: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_r8));
        dprintf("r9: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_r9));
        dprintf("r10: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_r10));
        dprintf("r11: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_r11));
        dprintf("r12: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_r12));
        dprintf("r13: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_r13));
        dprintf("r14: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_r14));
        dprintf("r15: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_r15));
        dprintf("\n");
        dprintf("rip: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rip));
        dprintf("\n");
        dprintf("rflags: %llX\n", (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_eflags));
        dprintf("\n");
        dprintf("Stack:  ('--->' is RSP)\n"); // 18个条目
        uint64_t rsp = (uint64_t)ctx->getConcreteRegisterValue(ctx->registers.x86_rsp);
        for (uint64_t i = 0; i < 22; i++) { // 4个上部 18个下部
            uint64_t curRsp = (rsp - (4 * 8)) + (i * 8);
            uint64_t curRsp_data = 0;
            auto vec = ctx->getConcreteMemoryAreaValue(curRsp, sizeof(uint64_t));
            std::memcpy(&curRsp_data, vec.data(), vec.size());
            if (curRsp == rsp) {
                dprintf(" --->| %llX: \t%llX\n", curRsp, curRsp_data);
            }
            else {
                dprintf("     | %llX: \t%llX\n", curRsp, curRsp_data);
            }

        }

        dprintf("-------------------------------------------\n");
    }
    ctx->clearArchitecture(); // 释放内存
    delete ctx;
    return true;
}

void quick_emu() { // 针对菜单
    if (!DbgIsDebugging()) {
        MessageBoxW(NULL, L"请先进入调试状态", L"unicorn", MB_OK);
        return;
    }
    SELECTIONDATA sel;
    GuiSelectionGet(GUI_DISASSEMBLY, &sel);
    dprintf("Seting Until Address: %llX\n", sel.start);
    DbgScriptCmdExec("ClearLog"); // 清屏
    unicorn_main_emu(sel.start);
}

bool pluginInit(PLUG_INITSTRUCT* initStruct){
    
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);

    cs_open(CS_ARCH_X86, CS_MODE_64, &hCs);
    _plugin_registercommand(pluginHandle, "xzc", cbExampleCommand, true);
    _plugin_registercommand(pluginHandle, "uc", cbExampleCommand_unicorn, true);
    _plugin_registercommand(pluginHandle, "triton", cbExampleCommand_triton, true);

    // Return false to cancel loading the plugin.
    return true;
}

void pluginStop(){
    cs_close(&hCs);
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info) {
    switch (info->hEntry) {
    case MENU_QUICK_EMU:
        quick_emu();
        break;

    default:
        break;
    }
}

void pluginSetup(){
    _plugin_menuaddentry(hMenuDisasm, MENU_QUICK_EMU, "start");
}

uint64_t get_module_export_function(std::string dll_name, std::string func_name){
    uint64_t result = 0;

    ListInfo mods;
    Script::Module::GetList(&mods);
    Script::Module::ModuleInfo* modInfo(static_cast<Script::Module::ModuleInfo*>(mods.data));
    for (int i = 0; i < mods.count; i++) {
        if (strcmp(modInfo[i].name, dll_name.c_str()) == 0) {
            ListInfo modExports;
            Script::Module::GetExports(&modInfo[i], &modExports);
            Script::Module::ModuleExport* ExportInfo(static_cast<Script::Module::ModuleExport*>(modExports.data));
            for (int i = 0; i < modExports.count; i++) {
                if (strcmp(ExportInfo[i].name, func_name.c_str()) == 0) {
                    result = ExportInfo[i].va;
                    break;
                }
            }
            BridgeFree(ExportInfo);
            if (result != 0) {
                break;
            }
        }
    }
    BridgeFree(modInfo);
    return result;
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