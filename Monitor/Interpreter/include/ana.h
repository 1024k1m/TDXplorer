#ifndef _ANALYZE_H__
#define _ANALYZE_H__

#include <linux/types.h>
#include <iostream>
#include <map>
#include "hub.h"
#include "defines.h"
#include "AnaCtrl.h"
#include "singlestep.h"
#include "flags.h"

class VMState;
class CThinCtrl;
class SymExecutor;
class ConExecutor;
class EFlagsManager;

/*to share data between Interpreter and user analyzer*/
struct ExecProfile {
    /*Execution modes
    0 : DEFAULT MODE, Single pat hseeded mode, EXEC_MD_SINGLE_PATH_SEDED                  
    1 : Path search start at a given ins count, EXEC_MD_START_PATH_SEARCH_AT_INS_COUNT
    2 :  Path search start at a given rip, EXEC_MD_START_PATH_SEARCH_AT_RIP        
    */
    int executionMode;
    unsigned long startIncCount;
    unsigned long startRip;

    /*Termination modes
    0 : DEFAULT MODE, terminate at stack balance, function return
    1 : terminate at specific RIP
    2 : terminate at specific ins count
    3 : terminate at ana request
    */
    int terminationMode;
    /*for termination mode 1*/
    unsigned long terminate_rip;
    /*for termination mode 2*/
    unsigned long terminate_ins_count;
};

struct ExecData {
    wrapInstruction *win;
    struct OpDetails opDetails[2];
    unsigned long buf[512];
    unsigned long insn_count;
    unsigned long start_rsp;
    CUR_INS_STATE cur_ins_state;
    uint8_t priv_flag_chg_ins;
    bool is_next_ins_seamret;
    ulong current_path;
};

class CAnalyze {
    
    VMState *m_VM;
    POOL* m_page_pool;

    bool defineSymbolsForScalls(unsigned long scall_idx, unsigned long tmp/*pt_regs_base_adr*/);

   public:
    EveMeta* m_emeta;
    CThinCtrl *m_Thin;
    std::shared_ptr<CAnaCtrl> m_AnaCtrl;
    std::shared_ptr<SymExecutor> a_SymExecutor;
    std::shared_ptr<ConExecutor> a_ConExecutor;
    std::shared_ptr<EFlagsManager> a_EFlagsMgr;
    std::shared_ptr<CFuzzCtrl> a_FuzzCtrl;
    std::shared_ptr<CDtFlwTrc> a_DtFlwTrc;

    struct ExecData *execData;
    struct ExecProfile *execProfile;

    // CFattCtrl(ExecCtrl *EC, VMState *VM);
    CAnalyze(VMState *VM, EveMeta* meta);
    ~CAnalyze();

    bool beginAnalysis(ulong addr);
    int analyztsHub(int anaPoint);
    int onEndOfInsExec();
    int onEndOfBbExec();
    int onBeforeCIESIE();
    int onEndOfInsDecode();
    void track_khole_mappings();
    void doEndOfPathChecks(int scall_status);
    void endOfPathJobs(int scall_status);
    ulong getKholePte(ulong rip);
    ulong findKeyHoleVa(ulong pa);
    ulong keyholeIdxToVa(int khole_idx, ulong pa);
    bool findMapedKholes();
    bool validateKholeEditRange(ulong adr);
    bool validateKholeRange(ulong adr);
    bool isKholeEditAddress(ulong adr);
    bool isKholeAddress(ulong adr);
    bool isModuleLibSymAccess(ulong adr);
    ulong getSeedFromMemory(ulong adr);
    void pageMapSanitizer(ulong pte);
    void pageAccessSanitizer(ulong seam_va);

    void setExecProfileSinglePath();
    void setExecProfileMultiPath();

    void setAnaCtrl(std::shared_ptr<CAnaCtrl> anactrl) {m_AnaCtrl = anactrl;};
    void setSymExecutor(std::shared_ptr<SymExecutor> symexecutor) {a_SymExecutor = symexecutor;}
    void setConExecutor(std::shared_ptr<ConExecutor> conexecutor) {a_ConExecutor = conexecutor;}
    void setEflagsMgr(std::shared_ptr<EFlagsManager> eflagsmgr) {a_EFlagsMgr = eflagsmgr;}
    void setFuzzCtrl(std::shared_ptr<CFuzzCtrl> fuzzctrl) {a_FuzzCtrl = fuzzctrl;}
    void setDtFlwTrc(std::shared_ptr<CDtFlwTrc> dtflwtrc) {a_DtFlwTrc = dtflwtrc;}

   private:

};


using namespace std;
struct ana_mem_block{
    bool    is_read;
    bool    is_write;
    uint    sym_size;
    bool    is_dyn_sym;
    string  sym_name;
    bool    symbol_for_path_exp;
};
typedef struct ana_mem_block anaMemBlk;

#define DSIZE 0x180
struct module_layout {  //size 0x50
	/* The actual code + data. */
	void *base;
	/* Total size. */
	unsigned int size;
	/* The size of the executable code.  */
	unsigned int text_size;
	/* Size of RO section of the module (text+rodata) */
	unsigned int ro_size;
	/* Size of RO after init section */
	unsigned int ro_after_init_size;
    char misc[0x38];
};

struct module {

    char data[DSIZE];

	struct module_layout core_layout; 
	struct module_layout init_layout;

};

#endif  // _ANALYZE_H__
