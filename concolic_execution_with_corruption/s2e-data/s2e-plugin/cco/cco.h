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

#ifndef S2E_PLUGINS_KDO_H
#define S2E_PLUGINS_KDO_H

#include <s2e/Plugin.h>
#include <s2e/ConfigFile.h>

#include <sstream>
#include <iostream>

#include <s2e/Plugins/Core/BaseInstructions.h>

#define COUNTERFEIT_RES_FILE_END "s2e-last/counterfeit.txt"
#define COUNTERFEIT_RES_FILE_MEMCPY "s2e-last/counterfeit-memcpy.txt"
#define ONLYSYMB_RES_FILE_END "s2e-last/onlysymb.txt"
#define ONLYSYMB_RES_FILE_MEMCPY "s2e-last/onlysymb-memcpy.txt"
#define REPORT "s2e-last/report.txt"

namespace s2e {
namespace plugins {

class Report {
public:
    std::string id;

    bool state_0_panic;
    bool state_1_panic;

    bool state_0_memop;
    bool state_1_memop;

    bool state_0_return;
    bool state_1_return;

    uint64_t state_0_n_constraints_memop;
    uint64_t state_1_n_constraints_memop;

    uint64_t state_0_n_constraints_return;
    uint64_t state_1_n_constraints_return;

    uint64_t state_0_counterfeit_counter_memop;
    uint64_t state_0_attacker_counter_memop;
    uint64_t state_0_kdo_object_entry_counter_memop;

    uint64_t state_1_counterfeit_counter_memop;
    uint64_t state_1_attacker_counter_memop;
    uint64_t state_1_kdo_object_entry_counter_memop;

    uint64_t state_0_counterfeit_counter_return;
    uint64_t state_0_attacker_counter_return;
    uint64_t state_0_kdo_object_entry_counter_return;

    uint64_t state_1_counterfeit_counter_return;
    uint64_t state_1_attacker_counter_return;
    uint64_t state_1_kdo_object_entry_counter_return;

    enum mem_op{
        MEMCPY = 0,
        MEMMOV = 1,
        UNKNOWN = 2,
    } operand;

    bool signal;
    int real_store_id;

    bool different_syscall;
};

enum id_store{
    STORE = 1,
    CFU = 2,
};


enum S2E_KDO_COMMANDS {
    // TODO: customize list of commands here
    KDO_COUNTERFEIT_AREA,
    KDO_PANIC,
};

struct S2E_KDO_PLUGIN_COMMAND{
    S2E_KDO_COMMANDS Command;
    union {
        // Command parameters go here
        void *counterfeit_area_ptr;
    };
};



class kdo : public Plugin, public IPluginInvoker {

    S2E_PLUGIN
public:
    kdo(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    OSMonitor *m_monitor;
    LinuxMonitor *m_linmon;
    ProcessExecutionDetector *m_process;
    BaseInstructions *m_base;
    S2EExecutor *m_executor;

    Report report;

    int original_data_state_id;
    int counterfeit_data_state_id;

    uint64_t syscall_counter;

    std::vector<std::pair<uint64_t,uint64_t>> constraint_filter;
    std::vector<uint64_t> nop_calls;

    std::map<uint64_t, std::vector<uint64_t>> copy_from_user_ids;

    std::vector<uint64_t> stores;
    std::map<uint64_t, std::vector<uint64_t>> store_ids;

    /* memcpy info */
    uint64_t kdo_asan_memop_callid;
    uint64_t kdo_asan_memcpy_addr;
    uint64_t kdo_asan_memmov_addr;
    uint64_t kdo_asan_memop_ctr;

    /* store hook info */
    uint64_t kdo_store_hook_callid;
    uint64_t kdo_store_hook_addr;
    uint64_t kdo_store_hook_ctr;

    /* post store hook info */
    uint64_t kdo_post_store_hook_addr;

    /* copy from user info */
    uint64_t kdo_copy_from_user_callid;
    uint64_t kdo_copy_from_user_addr;

    /* attacker data info */
    uint64_t kdo_attacker_data_addr;
    uint64_t kdo_attacker_data_size;

    /* counterfeat data info */
    uint64_t kdo_counterfeit_data_addr;
    uint64_t kdo_counterfeit_data_size;

    bool missing_data_size;
    bool kdo_fork_state;
    bool kdo_multilable;

    uint64_t kdo_target_object_offset;
    /* pointer to original object data */
    //uint64_t kdo_original_data_addr;

    /* address to ptr to be corrupted */
    //uint64_t kdo_original_ptr_addr;

    /* address to corruption location */
    uint64_t kdo_corruption_location;

    /* switch to activate symbolic execution */
    bool symbolic;


    // Allow the guest to communicate with this plugin using s2e_invoke_plugin
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

    /* S2E Handlers to install the right hooks at translation time */
    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onTranslateSyscallInstruction(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
    enum special_instruction_t type, const special_instruction_data_t *data);

    /* KDO handlers */
    void onAsanMemOp(S2EExecutionState *state, uint64_t pc);
    void onStoreHook(S2EExecutionState *state, uint64_t pc);
    void onPostStoreHook(S2EExecutionState *state, uint64_t pc);
    void onCopyFromUser(S2EExecutionState *state, uint64_t pc);
    void onCorruptPtr(S2EExecutionState *state, uint64_t pc);
    void onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid, uint64_t returnCode);
    void onTargetLoad(S2EExecutionState *state);
    void onSyscall(S2EExecutionState *state, uint64_t pc);
    void onSysret(S2EExecutionState *state, uint64_t pc);
    void onSymbolicAddress(S2EExecutionState *state, klee::ref<klee::Expr> virt_addr, uint64_t conc_addr, bool &concretize, CorePlugin::symbolicAddressReason reason);
    void onInitialState(S2EExecutionState *state);
    void onEngineShutdown();

    /* Utility to perform big memory manipulation (e.g., overwrite our own handlers if they generate useless constraints) */
    bool patchMemory(S2EExecutionState *state, uint64_t start, uint64_t end, uint8_t byte, bool flush);

    void dump(S2EExecutionState *state, bool is_end);
    void dumpArray(S2EExecutionState *state, const char *name, uint64_t len, uint64_t ptr);

    /* Handler to accept and reject constraints based on program counters */
    void onConstraint(S2EExecutionState *state, klee::ref<klee::Expr> condition, bool *skip);

    /* Handler to observe concretization */
    void onConcretization(S2EExecutionState *state, klee::ref<klee::Expr> condition, const std::string&);

    /* Handler to parse list of (start,end) addresses to filter constraints */
    void parse_filter_list(ConfigFile *cfg, const std::string &start_s, const std::string &end_s);
    void parse_cfuid_list(ConfigFile *cfg, const std::string &list);
    void parse_storeid_list(ConfigFile *cfg, const std::string &list);
    void parse_nop_calls(ConfigFile *cfg, const std::string &list);
    void parse_ctr_for_id(ConfigFile *cfg, uint64_t id, const std::string &list, int type);

    /* Utility to print all the info related to the state */
    void dumpState(S2EExecutionState *state, const char *);

    void get_page_boundaries(uint64_t addr, uint64_t *page_start, uint64_t *page_end, uint64_t *offset);
    std::string print_mem_op_type(int p);


};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_KDO_H
