///
/// Copyright (C) 2026, Andrea Mambretti
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>

#include <s2e/S2EExecutor.h>

#include <klee/util/ExprTemplates.h>

#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <bits/stdc++.h>

#include "cco.h"

#define MASK2 256
#define MASK 65536
#define PAGE_SIZE 4096ULL
#define PAGES 2

namespace s2e {
namespace plugins {

namespace {

//
// This class can optionally be used to store per-state plugin data.
//
// Use it as follows:
// void kdo::onEvent(S2EExecutionState *state, ...) {
//     DECLARE_PLUGINSTATE(kdoState, state);
//     plgState->...
// }
//
class kdoState: public PluginState {
    // Declare any methods and fields you need here
public:
    bool enable_print = false;
    bool disable_copyfromuser = false;
    bool track_sysret = false;
    bool store_hook_triggered = false;
    bool store_hook_patched = false;

    /* switch to enable post_store_hook handler */
    bool enable_post_store_hook = false;

    int offset = 0;
    int memop_counter = 0;
    std::map<uint64_t,uint64_t> store_counter;
    std::map<uint64_t, uint64_t> cfu_counters;

    uint64_t kdo_original_data_addr = 0;
    uint64_t kdo_original_ptr_addr = 0;

    uint64_t counter_counterfeit = 0;
    uint64_t counter_attacker_buf = 0;
    uint64_t counter_object_entry = 0;

    std::set<uint64_t> list_pc_generating_constraints;

    kdoState() {}

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new kdoState();
    }

    virtual ~kdoState() {
        // Destroy any object if needed
    }

    virtual kdoState *clone() const {
        return new kdoState(*this);
    }
};


}

S2E_DEFINE_PLUGIN(kdo, "Describe what the plugin does here", "", );

void kdo::initialize() {
    syscall_counter = 0;

    ConfigFile *cfg = s2e()->getConfig();

    report.state_0_panic = false;
    report.state_1_panic = false;

    report.state_0_memop = false;
    report.state_1_memop = false;

    report.state_0_return = false;
    report.state_1_return = false;

    report.state_0_n_constraints_memop = 0;
    report.state_1_n_constraints_memop = 0;

    report.state_0_n_constraints_return = 0;
    report.state_1_n_constraints_return = 0;

    report.state_0_counterfeit_counter_memop = 0;
    report.state_0_attacker_counter_memop = 0;
    report.state_0_kdo_object_entry_counter_memop = 0;

    report.state_1_counterfeit_counter_memop = 0;
    report.state_1_attacker_counter_memop = 0;
    report.state_1_kdo_object_entry_counter_memop = 0;

    report.state_0_counterfeit_counter_return = 0;
    report.state_0_attacker_counter_return = 0;
    report.state_0_kdo_object_entry_counter_return = 0;

    report.state_1_counterfeit_counter_return = 0;
    report.state_1_attacker_counter_return = 0;
    report.state_1_kdo_object_entry_counter_return = 0;

    report.id = cfg->getString(getConfigKey() + ".kdo_id");
    getDebugStream() << "report id =" << report.id << "\n";

    std::string memop_type = cfg->getString(getConfigKey() + ".kdo_memop_type");

    std::string syscall_type = cfg->getString(getConfigKey() + ".kdo_syscall_type");

    if (syscall_type.compare("different") == 0) {
        report.different_syscall = true;
    }
    else {
        report.different_syscall = false;
    }

    report.signal = false;
    report.real_store_id = -1;

    if (memop_type.compare("memmov") == 0)
        report.operand = Report::MEMMOV;
    else if (memop_type.compare("memcpy") == 0)
        report.operand = Report::MEMCPY;
    else
        report.operand = Report::UNKNOWN;

    original_data_state_id = -1;
    counterfeit_data_state_id = -1;

    parse_filter_list(cfg, getConfigKey() + ".filter_addr_start", getConfigKey() + ".filter_addr_end");
    parse_cfuid_list(cfg, getConfigKey() + ".kdo_cfu_id_list");

    parse_nop_calls(cfg, getConfigKey()+ ".nop");

    kdo_multilable = (bool) cfg->getBool(getConfigKey() + ".kdo_is_multilable");

    kdo_asan_memop_ctr     = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_asan_memop_ctr");
    kdo_asan_memop_callid  = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_asan_memop_callid");

    kdo_asan_memcpy_addr    = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_asan_memcpy_addr");
    kdo_asan_memmov_addr    = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_asan_memmov_addr");

    if (kdo_multilable) {
        getDebugStream() << "MULTILABLE RUN\n";
        parse_storeid_list(cfg, getConfigKey() + ".kdo_store_hook_callid");
    } else {
        getDebugStream() << "REGULAR RUN\n";
        kdo_store_hook_callid   = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_store_hook_callid");
        getDebugStream() << "store_hook_callid" << kdo_store_hook_callid << "\n";
        kdo_store_hook_ctr      = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_store_ctr");
        getDebugStream() << "store_hook_ctr" << kdo_store_hook_ctr << "\n";
    }
    kdo_store_hook_addr     = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_store_hook_addr");
    kdo_post_store_hook_addr = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_post_store_hook_addr");

    kdo_copy_from_user_callid   = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_copy_from_user_callid");
    kdo_copy_from_user_addr     = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_copy_from_user_addr");

    kdo_attacker_data_size = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_attacker_data_size");

    kdo_corruption_location = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_corruption_location");

    kdo_counterfeit_data_size   = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_counterfeit_data_size");

    kdo_target_object_offset = (uint64_t) cfg->getInt(getConfigKey() + ".kdo_target_object_offset");

    kdo_fork_state = (bool) cfg->getBool(getConfigKey() + ".kdo_fork_state");

    if (kdo_counterfeit_data_size <= 0) {
        getDebugStream() << "Missing counterfeit data size\n";
        missing_data_size = true;
    }
    else {
        missing_data_size = false;
    }

    symbolic = (bool) cfg->getBool(getConfigKey() + ".symbolic");




    m_linmon = dynamic_cast<LinuxMonitor *>(static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor")));
    if (!m_linmon)
        getDebugStream() << "Linux Monitor not available\n";

    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    if (!m_monitor)
        getDebugStream() << "m_monitor not available\n";

    m_process = s2e()->getPlugin<ProcessExecutionDetector>();
    if (!m_process)
        getDebugStream() << "m_process not available\n";

    m_base = s2e()->getPlugin<BaseInstructions>();
    if (!m_base)
        getDebugStream() << "m_base not available\n";

    m_executor = s2e()->getExecutor();

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &kdo::onTranslateBlockStart));

    s2e()->getCorePlugin()->onEngineShutdown.connect(
            sigc::mem_fun(*this, &kdo::onEngineShutdown));

    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
            sigc::mem_fun(*this, &kdo::onTranslateInstruction));

    s2e()->getCorePlugin()->onConstraint.connect(
            sigc::mem_fun(*this, &kdo::onConstraint));

    s2e()->getCorePlugin()->onSymbolicAddress.connect(
            sigc::mem_fun(*this, &kdo::onSymbolicAddress));

    s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
            sigc::mem_fun(*this, &kdo::onTranslateSyscallInstruction));

    s2e()->getCorePlugin()->onConcretization.connect(
            sigc::mem_fun(*this, &kdo::onConcretization));

    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &kdo::onProcessUnload));

}

std::string kdo::print_mem_op_type(int p) {
    switch (p) {
        case Report::MEMMOV:
            return "memmov";
            break;

        case Report::MEMCPY:
            return "memcpy";
            break;

        case Report::UNKNOWN:
            return "unknown";
            break;

        default:
            return "unknown";
            break;
    };
}

void kdo::onEngineShutdown() {
    getDebugStream() << "Outputting report\n";
    std::error_code EC;
    llvm::raw_ostream *cout = new llvm::raw_fd_ostream(REPORT, EC);
    *cout << "#### " << report.id << " ####\n";
    *cout << "Type syscall: " << (report.different_syscall ? std::string("different") : std::string("same")) << "\n";
    *cout << "Memory operation: " << print_mem_op_type(report.operand) << "\n";
    *cout << "Memop signal: " << (report.signal ? "true": "false") << "\n";

    if (report.real_store_id != -1) {
        if (report.real_store_id != kdo_store_hook_ctr) {
            *cout << "Corrected store counter: " << report.real_store_id << "\n";
        }
        else {
            *cout << "Original store counter is correct\n";
        }
    }

    *cout << "----\n";
    *cout << "STATE 0\n";
    *cout << "Panic: "  << (report.state_0_panic ? std::string("yes") : std::string("no")) << "\n";
    *cout << "Reached memop: " << (report.state_0_memop ? std::string("yes") : std::string("no")) << "\n";
    *cout << "Constraints@memop #: " << report.state_0_n_constraints_memop << "\n";
    *cout << "Counterfeit@memop #: " << report.state_0_counterfeit_counter_memop << "\n";
    *cout << "Attacker_buf@memop #: " << report.state_0_attacker_counter_memop << "\n";
    *cout << "Kdo_object_entry@memop #: " << report.state_0_kdo_object_entry_counter_memop << "\n";
    *cout << "Reached return: " << (report.state_0_return ? std::string("yes") : std::string("no")) << "\n";
    *cout << "Constraints@return #: " << report.state_0_n_constraints_return << "\n";
    *cout << "Counterfeit@return #: " << report.state_0_counterfeit_counter_return << "\n";
    *cout << "Attacker_buf@return #: " << report.state_0_attacker_counter_return << "\n";
    *cout << "Kdo_object_entry@return #: " << report.state_0_kdo_object_entry_counter_return << "\n";
    *cout << "----\n";

    if (kdo_fork_state) {
        *cout << "STATE 1\n";
        *cout << "Panic: "  << (report.state_1_panic ? std::string("yes") : std::string("no")) << "\n";
        *cout << "Reached memop: " << (report.state_1_memop ? std::string("yes") : std::string("no")) << "\n";
        *cout << "Constraints@memop #: " << report.state_1_n_constraints_memop << "\n";
        *cout << "Counterfeit@memop #: " << report.state_1_counterfeit_counter_memop << "\n";
        *cout << "Attacker_buf@memop #: " << report.state_1_attacker_counter_memop << "\n";
        *cout << "Kdo_object_entry@memop #: " << report.state_1_kdo_object_entry_counter_memop << "\n";
        *cout << "Reached return: " << (report.state_1_return ? std::string("yes") : std::string("no")) << "\n";
        *cout << "Constraints@return #: " << report.state_1_n_constraints_return << "\n";
        *cout << "Counterfeit@return #: " << report.state_1_counterfeit_counter_return << "\n";
        *cout << "Attacker_buf@return #: " << report.state_1_attacker_counter_return << "\n";
        *cout << "Kdo_object_entry@return #: " << report.state_1_kdo_object_entry_counter_return << "\n";
        *cout << "\n";
    }

    delete cout;
}

void kdo::get_page_boundaries(uint64_t addr, uint64_t *page_start, uint64_t *page_end, uint64_t *offset) {
    *page_start = addr & ~(PAGE_SIZE - 1);
    *page_end = *page_start + (PAGE_SIZE * PAGES) - 1;
    *offset = addr & (PAGE_SIZE - 1);
    getDebugStream() << "addr " << hexval(addr) << "\n";
    getDebugStream() << "page_start " << hexval(*page_start) << "\n";
    getDebugStream() << "page_end " << hexval(*page_end) << "\n";
    getDebugStream() << "offset " << hexval(*offset) << "\n";

}

void kdo::onInitialState(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(kdoState, state);
    getDebugStream(state) << "initial state created\n";
    if (!plgState->store_hook_patched) {
        getDebugStream(state) << "Patching memory from 87bb02d0 to 87bb0470\n";

        //bool done = patchMemory(state, 0xffffffff87bb02d0, 0xffffffff87bb0470, 0x90, true);
        patchMemory(state, 0xffffffff87bb02d0, 0xffffffff87bb0470, 0x90, true);

        //m_executor->flushTb();

        //if (done)
            //plgState->store_hook_patched = true;

        state->regs()->setPc(state->regs()->getPc() + 10);

        //throw CpuExitException();
    }
}

void kdo::onConcretization(S2EExecutionState *state, klee::ref<klee::Expr> condition, const std::string &info) {
    auto current_pc = state->regs()->getPc();
    getDebugStream(state) << "Concretization detected " << info << " PC= " << hexval(current_pc) << "\n";
}

void kdo::parse_nop_calls(ConfigFile *cfg, const std::string &list) {
    ConfigFile::integer_list l = cfg->getIntegerList(list);

    for (auto it : l) {
        getDebugStream() << "Loading " << hexval(it) <<"\n";
        nop_calls.push_back(it);
    }
}

void kdo::parse_filter_list(ConfigFile *cfg, const std::string &start_s, const std::string &end_s)  {
    ConfigFile::integer_list start = cfg->getIntegerList(start_s);
    ConfigFile::integer_list end = cfg->getIntegerList(end_s);

    s2e_assert(nullptr, start.size() == end.size(), "Error in config file, start and end address lists should be of the same size");

    auto it_start = start.begin();
    auto it_end = end.begin();
    for (; it_start != start.end(); it_start++, it_end++) {
        getDebugStream() << "Adding filter for constraints " << hexval(*it_start) << " - " << hexval(*it_end) << "\n";
        constraint_filter.push_back(std::make_pair(*it_start, *it_end));
    }
}


void kdo::parse_ctr_for_id(ConfigFile *cfg, uint64_t id,  const std::string &list_ctr, int type) {
    ConfigFile::integer_list list = cfg->getIntegerList(list_ctr);
    auto  it = list.begin();
    //std::map<int, std::vector<int> > mymap;
    std::string nametype;
    if (type == CFU)
        nametype = std::string("CFU");
    else if (type == STORE)
        nametype = std::string("STORE");

    getDebugStream() << nametype << ") add int id=" << id << " counter ";

    for (; it != list.end(); it++) {
        getDebugStream() << *it << " ";
        if (type == CFU)
            copy_from_user_ids[id].push_back(*it);
        else if (type == STORE)
            store_ids[id].push_back(*it);
    }
    getDebugStream() << "\n";
}


void kdo::parse_storeid_list(ConfigFile *cfg, const std::string &list_s) {
    ConfigFile::integer_list list = cfg->getIntegerList(list_s);

    auto it = list.begin();

    for (; it != list.end(); it++) {
        getDebugStream() << getConfigKey() + "["+ std::to_string(*it)+"]\n";
        parse_ctr_for_id(cfg, *it, getConfigKey()+"["+std::to_string(*it)+"]", STORE);
    }
}

void kdo::parse_cfuid_list(ConfigFile *cfg, const std::string &list_s) {
    ConfigFile::integer_list list = cfg->getIntegerList(list_s);

    auto it = list.begin();

    for (; it != list.end(); it++) {
        getDebugStream() << getConfigKey() + "["+ std::to_string(*it) + "]\n";
        parse_ctr_for_id(cfg, *it, getConfigKey()+"["+std::to_string(*it)+"]", CFU);
    }
}


void kdo::onTranslateSyscallInstruction(ExecutionSignal *signal, S2EExecutionState *state,
        TranslationBlock *tb, uint64_t pc, enum special_instruction_t type,
        const special_instruction_data_t *data) {
    if (type == SYSCALL) {
        //signal->connect(sigc::mem_fun(*this, &kdo::onSyscall));
        return;
    }
    else if (type == SYSRET) {
        signal->connect(sigc::mem_fun(*this, &kdo::onSysret));
    }
    else {
        return;
    }

}

void kdo::onSysret(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(kdoState, state);
    if (!plgState->track_sysret)
        return;

    if (!m_process->isTrackedPid(state, m_linmon->getPid(state)))
        return;

    getDebugStream(state) << "Sysret @" << hexval(pc) << "\n";

    if (state->getID() == original_data_state_id) {
        report.state_1_n_constraints_return = state->constraints().size();
        report.state_1_counterfeit_counter_return = plgState->counter_counterfeit;
        report.state_1_attacker_counter_return = plgState->counter_attacker_buf;
        report.state_1_kdo_object_entry_counter_return = plgState->counter_object_entry;
        report.state_1_return = true;
    }
    if (state->getID() == counterfeit_data_state_id) {
        report.state_0_n_constraints_return = state->constraints().size();
        report.state_0_counterfeit_counter_return = plgState->counter_counterfeit;
        report.state_0_attacker_counter_return = plgState->counter_attacker_buf;
        report.state_0_kdo_object_entry_counter_return = plgState->counter_object_entry;
        report.state_0_return = true;
    }

    plgState->track_sysret = false;
    dump(state, true);
    m_executor->terminateState(*state, "killing state at sysret");
}

void kdo::onSyscall(S2EExecutionState *state, uint64_t pc) {
    if (!m_process->isTrackedPid(state, m_linmon->getPid(state))) {
        return;
    }

    syscall_counter++;

    getDebugStream(state) << "Syscall - #" << syscall_counter << "\n";

}


void kdo::dumpArray(S2EExecutionState *state, const char *name, uint64_t len, uint64_t ptr) {
    std::stringstream ss;
    for (int i = 0; i < len; ++i) {
        klee::ref<Expr> res = state->mem()->read(ptr+i, klee::Expr::Int8);

        getDebugStream(state) << name << "[" << i << "] = " << res << "\n";

        //if (!isa<ConstantExpr>(res)) {
            //ss << ". ";
        //}
        //else {
            //ConstantExpr *ce = dyn_cast<ConstantExpr>(res);
            //ss << hexval(ce->getZExtValue()) << " ";
        //}
    }
    getDebugStream(state) << name <<  "\n" << ss.str() << "\n";

}

void kdo::dump(S2EExecutionState *state, bool is_end) {
    auto plgState = state->getPluginState<kdoState>(this);

    getDebugStream(state) << "Dumping state " << state->getID() << "\n";

    if (state->getID() == original_data_state_id) {
        dumpArray(state, "kdo_original_data", kdo_counterfeit_data_size+plgState->offset, plgState->kdo_original_data_addr);
        if (is_end)
            dumpState(state, ONLYSYMB_RES_FILE_END);
        else
            dumpState(state, ONLYSYMB_RES_FILE_MEMCPY);
    }

    if (state->getID() == counterfeit_data_state_id) {
        dumpArray(state, "kdo_counterfeit_data", kdo_counterfeit_data_size, kdo_counterfeit_data_addr);
        if (is_end)
            dumpState(state, COUNTERFEIT_RES_FILE_END);
        else
            dumpState(state, COUNTERFEIT_RES_FILE_MEMCPY);
    }
}

void kdo::onProcessUnload(S2EExecutionState *state, uint64_t addressSpece, uint64_t pid, uint64_t returnCode) {
    auto plgState = state->getPluginState<kdoState>(this);
    if  (!m_process->isTrackedPid(state, m_linmon->getPid(state))) {
        return;
    }

    getDebugStream(state) << "Exiting main detected\n";
    getDebugStream(state) << "Collected " << state->constraints().size() << " constraints\n";

    if (state->getID() == original_data_state_id) {
        report.state_1_n_constraints_return = state->constraints().size();
        report.state_1_counterfeit_counter_return = plgState->counter_counterfeit;
        report.state_1_attacker_counter_return = plgState->counter_attacker_buf;
        report.state_1_kdo_object_entry_counter_return = plgState->counter_object_entry;
        report.state_1_return = true;
    }

    if (state->getID() == counterfeit_data_state_id) {
        report.state_0_n_constraints_return = state->constraints().size();
        report.state_0_counterfeit_counter_return = plgState->counter_counterfeit;
        report.state_0_attacker_counter_return = plgState->counter_attacker_buf;
        report.state_0_kdo_object_entry_counter_return = plgState->counter_object_entry;
        report.state_0_return = true;
    }

    m_executor->terminateState(*state, "killing state");
}

void kdo::onConstraint(S2EExecutionState *state,
        klee::ref<klee::Expr> condition, bool *skip) {
    std::size_t found;
    auto current_pc = state->regs()->getPc();

    DECLARE_PLUGINSTATE(kdoState, state);
    //getDebugStream(state) << "Generated constraint at " << hexval(current_pc) << "\n";
    //if (panic_triggered) {
    //getDebugStream(state) << "skipping because panic_triggered\n";
    //*skip = true;
    //return;
    //}

    for (auto el : constraint_filter) {
        auto start = el.first;
        auto end = el.second;

        if ((current_pc >= start) &&
                (current_pc <= end)) {
            *skip = true;
            return;
        }
    }
    *skip = false;
    plgState->list_pc_generating_constraints.insert(current_pc);

    std::string ss;
    llvm::raw_string_ostream ros(ss);
    ros << condition;

    found = ros.str().find(std::string("kdo_attacker"));
    if (found != std::string::npos) {
        plgState->counter_attacker_buf++;
    }

    found = ros.str().find(std::string("kdo_vuln"));
    if (found != std::string::npos) {
        plgState->counter_attacker_buf++;
    }

    found = ros.str().find(std::string("kdo_counterfeit"));
    if (found != std::string::npos) {
        plgState->counter_counterfeit++;
    }

    found = ros.str().find(std::string("kdo_target"));
    if (found != std::string::npos) {
        plgState->counter_object_entry++;
    }

    //getDebugStream(state) << "PC: " <<  hexval(current_pc) <<  "      " << condition << "\n";
    //getDebugStream(state) << "Accepted:\n" << condition <<"\n";
}


void kdo::dumpState(S2EExecutionState *state, const char *filename) {
    std::error_code EC;
    llvm::raw_ostream *cout = new llvm::raw_fd_ostream(filename, EC);
    state->dumpQuery(*cout);
    delete cout;
}

void kdo::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize)
{
    S2E_KDO_PLUGIN_COMMAND command ;

    //DECLARE_PLUGINSTATE(kdoState, state);

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_KDO_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        // TODO: add custom commands here
        case KDO_COUNTERFEIT_AREA:
            kdo_counterfeit_data_addr = (uint64_t) command.counterfeit_area_ptr;
            getDebugStream(state) << "Received command from s2e kernel module with ptr "
                << hexval(kdo_counterfeit_data_addr) << "\n";
            break;
        case KDO_PANIC:
            dump(state, true);

            if (state->getID() == original_data_state_id)
                report.state_1_panic = true;

            if (state->getID() == counterfeit_data_state_id)
                report.state_0_panic = true;

            m_executor->terminateState(*state, "killing state at panic");
            break;
        default:
            getWarningsStream(state) << "Unknown command " << command.Command << "\n";
            break;
    }
}

void kdo::onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc) {
    //DECLARE_PLUGINSTATE(kdoState, state);
    if (pc == kdo_corruption_location) {
        if (report.different_syscall) {
            getDebugStream(state) << "Translating corruption location\n";
            signal->connect(sigc::mem_fun(*this, &kdo::onCorruptPtr));
        }
    }
}

bool kdo::patchMemory(S2EExecutionState *state, uint64_t start, uint64_t end, uint8_t byte, bool flush=false) {
    for (unsigned int i = 0; start + i <= end; ++i) {
        if(!state->mem()->write(start+i, &byte, sizeof(byte))) {
            getDebugStream(state) << "Error while writing at " << hexval(start+i) << "\n";
            return false;
        }
    }
    return true;
}

void kdo::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc) {
    if (pc == kdo_post_store_hook_addr) {
        signal->connect(sigc::mem_fun(*this, &kdo::onPostStoreHook));
    }
    if (pc == kdo_asan_memcpy_addr || pc == kdo_asan_memmov_addr) {
        signal->connect(sigc::mem_fun(*this, &kdo::onAsanMemOp));
    }
    if (pc == kdo_store_hook_addr) {
        signal->connect(sigc::mem_fun(*this, &kdo::onStoreHook));
    }
    if (pc == kdo_copy_from_user_addr) {
        signal->connect(sigc::mem_fun(*this, &kdo::onCopyFromUser));
    }
}

void kdo::onCopyFromUser(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(kdoState, state);
    uint64_t len;
    uint64_t callid;

    callid = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDI]));

    if (!m_process->isTrackedPid(state, m_linmon->getPid(state)))
        return;

    if (plgState->disable_copyfromuser)
        return;

    if (copy_from_user_ids.find(callid) == copy_from_user_ids.end()) {
        return;
    }

    if (plgState->cfu_counters.find(callid) == plgState->cfu_counters.end()) {
        getDebugStream(state) << "Initializing counter for " << callid << "\n";
        plgState->cfu_counters[callid] = 0;
    }

    getInfoStream(state) << m_linmon->getPid(state) << ") Trapped pc @ kdo_copy_from_user "
        << hexval(pc) << "  callid="
        << callid << "  counter="
        << plgState->cfu_counters[callid] << "\n";

    if (symbolic &&
        std::find(copy_from_user_ids[callid].begin(), copy_from_user_ids[callid].end(), plgState->cfu_counters[callid]++) != copy_from_user_ids[callid].end()) {
        kdo_attacker_data_addr = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_ESI]));
        len = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDX]));
        m_base->makeSymbolic(state, kdo_attacker_data_addr, len, "kdo_attacker_buf_"+std::to_string(callid));
    }
}

void kdo::onCorruptPtr(S2EExecutionState *state, uint64_t pc) {
    getDebugStream(state) << "Trapped pc @ corrupt_ptr " << hexval(pc) << "\n";
    auto plgState = state->getPluginState<kdoState>(this);
    uint64_t ptr_to_be_written;

    uint64_t page_start = 0x0;
    uint64_t page_end = 0x0;
    uint64_t offset = 0x0;

    if (!m_process->isTrackedPid(state, m_linmon->getPid(state)))
        return;

    if (report.different_syscall)
        state->jumpToSymbolicCpp();

    plgState->enable_print = true;
    plgState->track_sysret = true;

  //////////////////////////////////////

    // This check enables forking only when necessary
    if (kdo_fork_state)
        state->enableForking();

    S2EExecutor::StatePair sp = s2e()->getExecutor()->fork(*state);

    if (kdo_fork_state) {
        assert(sp.first == state);
        assert(sp.second && sp.second != sp.first);
        if (sp.second) {
            S2EExecutionState *secondState = static_cast<S2EExecutionState *>(sp.second);
            secondState->disableForking();
            original_data_state_id = secondState->getID();
            getDebugStream(secondState) << "STATE " << original_data_state_id << " here\n";
            auto plgsecondstate = secondState->getPluginState<kdoState>(this);
            plgsecondstate->enable_post_store_hook = false;

            if (symbolic && !missing_data_size) {
                m_base->makeSymbolic(secondState, plgState->kdo_original_data_addr, kdo_counterfeit_data_size, "kdo_vuln_buf");
            }
        }
    }

    if (sp.first) {
        S2EExecutionState *firstState = static_cast<S2EExecutionState *>(sp.first);
        firstState->disableForking();
        counterfeit_data_state_id = firstState->getID();
        getDebugStream(firstState) << "STATE " << counterfeit_data_state_id << " here\n";

        //copy data from one object to counterfeit object
        if (!missing_data_size) {
            for (int i = 0; i < kdo_counterfeit_data_size; ++i) {
                uint8_t byte;
                firstState->mem()->read(plgState->kdo_original_data_addr+i, &byte, sizeof(byte));
                firstState->mem()->write(kdo_counterfeit_data_addr+i, &byte, sizeof(byte));
            }
            ptr_to_be_written = kdo_counterfeit_data_addr;
        }
        else {
            get_page_boundaries(plgState->kdo_original_data_addr, &page_start, &page_end, &offset);
            // Set new counterfeit_data_size based on the offset within the
            // page and the end of the page not ideal but the best we can do so far
            kdo_counterfeit_data_size = (((PAGE_SIZE * PAGES) -1) - offset);
            getDebugStream(firstState) << "kdo_counterfeit_data_size compute size " << hexval(kdo_counterfeit_data_size) << "\n";

            for (int64_t i = page_start; i < page_end; ++i) {
                uint8_t byte;
                firstState->mem()->read(i, &byte, sizeof(byte));
                firstState->mem()->write(kdo_counterfeit_data_addr+i, &byte, sizeof(byte));
            }
            ptr_to_be_written = kdo_counterfeit_data_addr+offset;
            plgState->offset = offset;
        }
        // corrupt the pointer and point to counterfeit area
        getDebugStream(firstState) << "Ptr to be written " << hexval(ptr_to_be_written) << " at location " <<
        hexval(plgState->kdo_original_ptr_addr) << "\n";
        firstState->switchToConcrete();
#if 1
        if (!firstState->mem()->write(plgState->kdo_original_ptr_addr, &ptr_to_be_written, sizeof(uint64_t))) {
            getDebugStream(firstState) << "Error while corrupting pointer in first state.\n";
        }
#endif
        firstState->switchToSymbolic();

        if (symbolic) {
            // make the new area symbolic
            if (!missing_data_size)
                m_base->makeSymbolic(firstState, ptr_to_be_written, kdo_counterfeit_data_size, "kdo_counterfeit_buf");
            else
                m_base->makeSymbolic(firstState, ptr_to_be_written, kdo_counterfeit_data_size, "kdo_counterfeit_no_size_buf");
#if 1
            if (kdo_target_object_offset != -1) {
                getDebugStream(firstState) << "kdo_target_object_entry address= " << hexval(plgState->kdo_original_ptr_addr-kdo_target_object_offset)
                << "\n Offset = " << hexval(kdo_target_object_offset) << "\n";

                m_base->makeSymbolic(firstState, plgState->kdo_original_ptr_addr-kdo_target_object_offset, kdo_target_object_offset, "kdo_target_object_entry");
            }
#endif
        }
    }

    getDebugStream(state) << "Returning from onCorruptPtr\n";
}


void kdo::onSymbolicAddress(S2EExecutionState *state, klee::ref<klee::Expr> virt_addr,
    uint64_t conc_addr, bool &concretize, CorePlugin::symbolicAddressReason reason) {
    //auto current_pc = state->regs()->getPc();
    //getDebugStream(state) << "Hit on symbolic address " << virt_addr << " concrete val " << hexval( conc_addr ) << " PC " << current_pc << "\n";
    //concretize = false;

}

void kdo::onAsanMemOp(S2EExecutionState *state, uint64_t pc) {
    uint64_t len;
    uint64_t callid;
    uint64_t ptr_src;
    uint64_t ptr_dst;
    uint64_t page_ptr_dst;
    uint64_t page_counterfeit_obj;

    std::string operation;
    if (pc == kdo_asan_memcpy_addr)
        operation = "memcpy";
    else if (pc == kdo_asan_memmov_addr)
        operation = "memmov";
    else
        operation = "unknown";

    auto plgState = state->getPluginState<kdoState>(this);

    callid = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_ECX]));

    if (!m_process->isTrackedPid(state, m_linmon->getPid(state)))
        return;

    if (callid != kdo_asan_memop_callid)
        return;

    klee::ref<klee::Expr> len2 = state->regs()->read(CPU_OFFSET(regs[R_EDX]), klee::Expr::Int64);

    len = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDX]));

    getInfoStream(state) << "PID= " << m_linmon->getPid(state) << "-" << operation << ") Id= "<< callid << " Counter= "
        << plgState->memop_counter << " kdo_asan_memop_ctr= " << kdo_asan_memop_ctr<<" len= "<< len2 << "\n";
    ptr_src = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_ESI]));
    ptr_dst = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDI]));
    len =  state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDX]));
    getDebugStream(state) << "Dst ptr " << hexval(ptr_dst) << "\n";


    getDebugStream(state) << "Trapped asan_memcpy@" << hexval(pc)
        << " with callid=" << callid << " len=" << len <<  "\n";

    if (plgState->memop_counter++ == kdo_asan_memop_ctr) {
        ptr_src = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_ESI]));
        ptr_dst = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDI]));

        if (state->getID() == counterfeit_data_state_id) {
            page_ptr_dst = ptr_dst & ~(MASK-1); // get page address from dst memcpy
            page_counterfeit_obj = kdo_counterfeit_data_addr & ~(MASK-1); // get page address of counterfeit from kernel

            getDebugStream(state) << "page_ptr_dst " << hexval(page_ptr_dst) << "\n";
            getDebugStream(state) << "page_counterfeit_obj " << hexval(page_counterfeit_obj) << "\n";
            getDebugStream(state) << ((page_ptr_dst == page_counterfeit_obj) ? "true\n" : "false\n"); // if this is false, we did successfully corrupt the right store

            report.signal = ((page_ptr_dst == page_counterfeit_obj) ? true : false);

            if (!report.signal) {
                if (!kdo_multilable) {
                    for (unsigned int i = 0; i < stores.size(); ++i) {
                        uint64_t element = stores[i];
                        uint64_t tmp = element & ~(MASK2 - 1);
                        getDebugStream(state) << i <<  ") store =" << hexval(element) << "- tmp = " << hexval(tmp) << "\n";
                        if (tmp == (ptr_dst & ~(MASK2 - 1))) {
                            getDebugStream(state) << "Checked index= " << i << "\n";
                            report.real_store_id = i;
                        }
                    }
                }
                else {
                    for (auto el : store_ids) {
                        getDebugStream(state) << "Multilable: " << el.first << "\n";
                        for (unsigned int i = 0; i < el.second.size(); ++i) {
                            uint64_t element = el.second[i];
                            uint64_t tmp = element & ~(MASK2 - 1);
                            getDebugStream(state) << i << ") store =" << hexval(element) << "- tmp = " << hexval(tmp) << "\n";
                            if (tmp == (ptr_dst & ~(MASK2 - 1))) {
                                getDebugStream(state) << "Checked index = " << i << "\n";
                                report.real_store_id = i;
                            }
                        }
                    }
                }
            }
        }

        //getDebugStream(state) << "TeST pre casting\n";
        //auto ce = llvm::dyn_cast<ConstantExpr>(len2);
        //len = ce->getZExtValue();
        //getDebugStream(state) << "TeST post casting\n";

        plgState->disable_copyfromuser = true;

        if (symbolic) {
            // Inspecting source buffer
            dumpArray(state, "memcpy_src", len, ptr_src);

            dump(state, false);
            getDebugStream(state) << "Collected " << state->constraints().size() << " constraints\n";
            if (state->getID() == original_data_state_id) {
                getDebugStream(state) << "Setting report @ memop for onlysymb state\n";
                report.state_1_n_constraints_memop = state->constraints().size();
                report.state_1_counterfeit_counter_memop = plgState->counter_counterfeit;
                report.state_1_attacker_counter_memop = plgState->counter_attacker_buf;
                report.state_1_kdo_object_entry_counter_memop = plgState->counter_object_entry;
                report.state_1_memop = true;
            }
            if (state->getID() == counterfeit_data_state_id) {
                getDebugStream(state) << "Setting report @ memop for counterfeit state\n";
                report.state_0_n_constraints_memop = state->constraints().size();
                report.state_0_counterfeit_counter_memop = plgState->counter_counterfeit;
                report.state_0_attacker_counter_memop = plgState->counter_attacker_buf;
                report.state_0_kdo_object_entry_counter_memop = plgState->counter_object_entry;
                report.state_0_memop = true;
            }
        }
        else {
            std::stringstream ss;
            for (int i = 0; i < kdo_attacker_data_size; ++i) {
                uint8_t byte;
                state->mem()->read(kdo_attacker_data_addr+i, &byte, sizeof(byte));
                ss << hexval(byte) << ",";
            }
            getDebugStream(state) << "output" << "\n";
            getDebugStream(state) << ss.str() << "\n";
        }
    }
}

void kdo::onStoreHook(S2EExecutionState *state, uint64_t pc) {
    uint64_t callid;
    uint64_t ptr_addr;
    uint64_t data_addr;

    auto plgState = state->getPluginState<kdoState>(this);

    if (!m_process->isTrackedPid(state, m_linmon->getPid(state)))
        return;

    callid = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_ECX]));

    klee::ref<Expr> ptr_addr_expr = state->regs()->read(offsetof(CPUX86State, regs[R_EDI]), klee::Expr::Int64);
    klee::ref<Expr> data_addr_expr = state->regs()->read(offsetof(CPUX86State, regs[R_ESI]), klee::Expr::Int64);

    if (kdo_multilable && plgState->store_counter.find(callid) == plgState->store_counter.end()) {
        getDebugStream(state) << "Initializing store counter for " << callid << "\n";
        plgState->store_counter[callid] = 0;
    }

    // If it is not multilable run:
    // - save all store with the right callid under stores to be inspected
    // - if same syscall case, then enable and use post_store_hook
    if (!kdo_multilable) {
        if (callid == kdo_store_hook_callid) {
            getDebugStream(state) << "-----------\n";
            getInfoStream(state) << "("<< m_linmon->getPid(state) <<") (NO MULTILABLE) StoreHook id = " << callid << " store_counter = "
                << plgState->store_counter[callid] << " kdo_store_hook_ctr = " << kdo_store_hook_ctr << "\n";
            getDebugStream(state) << "ptr_addr " << ptr_addr_expr << "\n";
            getDebugStream(state) << "data_addr " << data_addr_expr << "\n";
            getDebugStream(state) << "-----------\n";

            //auto ce = dyn_cast<ConstantExpr>(data_addr_expr);
            if (auto ce = dyn_cast<ConstantExpr>(data_addr_expr)) {
                // Save all stores values with ID = store_hook_callid for evaluation later
                stores.push_back(ce->getZExtValue());
            } else {
                data_addr = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_ESI]));
                stores.push_back(data_addr);
            }


        }

        if (callid == kdo_store_hook_callid &&
                plgState->store_counter[callid]++ == kdo_store_hook_ctr) {

            ptr_addr = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_EDI]));
            data_addr = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_ESI]));
            getDebugStream(state) << "store_hook_triggered assigning pointers\n";

            plgState->kdo_original_ptr_addr = ptr_addr;
            plgState->kdo_original_data_addr = data_addr;

            plgState->store_hook_triggered = true;

            if (!report.different_syscall) {
                getDebugStream(state) << "Enabling post store hook handler\n";
                plgState->enable_post_store_hook = true;
            }
        }
    }
    else {
        //if (store_ids.find(callid) != store_ids.end() &&
                //std::find(store_ids[callid].begin(), store_ids[callid].end(), plgState->store_counter[callid]++ ) != store_ids[callid].end()) {
            if (store_ids.find(callid) != store_ids.end() && plgState->store_counter[callid]++) {
            getDebugStream(state) << "-------------\n";
            getInfoStream(state) << "("<< m_linmon->getPid(state) << ") (MULTILABLE) StoreHook id = " << callid << " store_counter = "
                << plgState->store_counter[callid]-1 << "\n";
            getDebugStream(state) << "ptr_addr " << ptr_addr_expr << "\n";
            getDebugStream(state) << "data_addr " << data_addr_expr << "\n";
            getDebugStream(state) << "-----------\n";

            if (auto ce = dyn_cast<ConstantExpr>(data_addr_expr)) {
                store_ids[callid].push_back(ce->getZExtValue());
            } else {
                data_addr = state->regs()->read<uint64_t>(CPU_OFFSET(regs[R_ESI]));
                store_ids[callid].push_back(data_addr);
                getDebugStream(state) << "Failed to retrieve value\n";
            }


        }
    }
}

void kdo::onPostStoreHook(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(kdoState, state);
    if (!plgState->enable_post_store_hook)
        return;

    state->jumpToSymbolicCpp();
    getDebugStream(state) << "OnPostStoreHook\n";

    if (!m_process->isTrackedPid(state,m_linmon->getPid(state)))
        return;

    if (report.different_syscall) // we should not be here if that's the case
        return;


    getDebugStream(state) << "same syscall case detected - proceed with corruption\n";
    onCorruptPtr(state, pc);
    plgState->enable_post_store_hook = false;
    getDebugStream(state) << "End PostStoreHook\n";
}

} // namespace plugins
} // namespace s2e
