#include <string>
#include "ana.h"
#include <asm/ptrace.h>
#include "state.h"
#include "historytree.h"
#include "singlestep.h"
#include "common_idata.h"
#include "seam.h"
#include "pagemanager.h"

struct iData *tdx_sp_ins;

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

extern bool endCurrentPath;
extern PATH_END_RSN endCurrentPathReason;
extern struct servReq *sreq;

struct MacReg*  m_regs;
std::map<ulong, ulong> seam_va_pa_map;
std::map<ulong, ulong> seam_pa_va_map;
std::map<ulong /*buf base*/, ulong /*conc adr from seeded*/> sym_buf_bases;

#define PTE_TO_PA_MASK		0xfffffff000UL
#define PG_SZ_4K            0x1000UL
#define PTE_PRESENT_MASK    0x1

int dispatch_count = 0;
int is_se = 0;
int scall_failed_count = 0;
int sym_buf_count = 1;

ulong last_path = 0;
ulong lp_keyhole_va_base;
ulong lp_khole_edit_base_va;

CAnalyze::CAnalyze(VMState *VM, EveMeta* meta) {
    m_VM = VM;
    execData = new ExecData;
    execData->insn_count = 0; 
    execData->is_next_ins_seamret = false;
    execData->current_path = 0;
    execProfile = new ExecProfile;
    execProfile->executionMode = 0; /*DEFAULT, single pat hseeded*/
    execProfile->terminationMode = 0; /*DEFAULT, terminate at stack balance, function return*/
    execProfile->terminate_ins_count = 0;

}

CAnalyze::~CAnalyze() {
}

void CAnalyze::setExecProfileSinglePath(){
        execProfile->executionMode = EXEC_MD_SINGLE_PATH_SEDED;
        execProfile->terminationMode = END_AT_ANA_REQUEST;
        execProfile->startIncCount = 0;
}

void CAnalyze::setExecProfileMultiPath(){
    std::cout << "setExecProfileMultiPath" << std::endl;
    execProfile->executionMode = EXEC_MD_START_PATH_SEARCH_AT_INS_COUNT;
    execProfile->startIncCount = 0;
}   

ulong CAnalyze::getSeedFromMemory(ulong adr){

    bool res;
    MemValue mv;

    mv.size = 8;
    mv.addr = adr;
    mv.bsym = false;
    mv.isSymList = false;

    res = m_VM->readMemory (mv);
    assert(res);
    assert(!mv.bsym);

    return mv.i64;
}

ulong CAnalyze::findKeyHoleVa(ulong pa){

    int lp_keyhole_idx = 0;
    bool res;
    MemValue mv;
    ulong seam_va = 0;
    ulong khole_pte;

    if(pa == 0x0){
        return 0;
    }

    while(lp_keyhole_idx < 128){

        khole_pte = *(ulong *)(lp_khole_edit_base_va + lp_keyhole_idx*8);

        if((khole_pte & PTE_PRESENT_MASK) && ((khole_pte & PTE_TO_PA_MASK) == pa)){
                seam_va = keyholeIdxToVa(lp_keyhole_idx, pa);
                return seam_va;
        }

        lp_keyhole_idx++;
    }

    std::cout << "end\n";
    return seam_va;
}

ulong CAnalyze::keyholeIdxToVa(int khole_idx, ulong pa){

    ulong seam_va = lp_keyhole_va_base + khole_idx*(PG_SZ_4K);
    seam_pa_va_map.insert({pa, seam_va});
    seam_va_pa_map.insert({seam_va, pa});
    std::cout << "pa: 0x" << std::hex << pa << "\t seam va: 0x" << seam_va << std::endl;

    return seam_va;
}

bool CAnalyze::validateKholeEditRange(ulong adr){
    if((adr < lp_khole_edit_base_va) || (adr) >= (lp_khole_edit_base_va + 128*8)){
        std::cout << "key hole edit access out off range for current LP !" << std::endl;
        assert(0);
    }
    return false;
}

bool CAnalyze::isKholeEditAddress(ulong adr){
    std::cout << "1adr: 0x" << std::hex << adr << std::endl;
    if((adr >> 63) != 1){ /*khole edit mapping in the lower half of 48bit adr space*/
        std::cout << "2khole-edit adr: 0x" << std::hex << adr << std::endl;
        return true;
    }
    return false;
}

bool CAnalyze::validateKholeRange(ulong adr){

    if((adr < lp_keyhole_va_base) || (adr >= (lp_keyhole_va_base + PG_SZ_4K*128))){
        std::cout << "khole access, out of LP khole renge" << std::endl;
        assert(0);
    }
    return false;
}

bool CAnalyze::isKholeAddress(ulong adr){

    if((adr >= sreq->khole_start) && (adr < sreq->mod_data_rgn_start)){
        std::cout << "khole access: 0x" << std::hex << adr << std::endl;
        return true;
    }
    return false;
}

bool CAnalyze::isModuleLibSymAccess(ulong adr){
    
    if((adr >= sreq->mod_code_rgn_start) && (adr < sreq->mod_stack_rgn_start)){
        std::cout << "Module lib symbol access: 0x" << std::hex << adr << std::endl;
        return true;
    }
    return false;
}

bool CAnalyze::findMapedKholes(){

    return true;
}

/*---sanitiy checks and post processing --------------------------------------------------------------------------------START*/
void CAnalyze::doEndOfPathChecks(int scall_status){

    std::cout << "doEndOfPAthChecks ....................." << std::endl;
    std::set<unsigned long> sym_range;
    std::string s_name = "gpa_B4_7";
    
    switch (scall_status)
    {
        case PATH_SEAMRET_FAIL: /*scall fail*/
        {
                
        }break;
        case PATH_SEAMRET_PASS: /*scall success*/
        {
            
        } break;
        default:
            break;
    }
    
    /*Checking for all modified data can tell us which regions have been changed. But since we do not 
    know what those memory objects are, given a modified address we can not reason
    m_Thin->m_PM->checkModifiedData();*/

    /*check sEPT data, symbolic buffer----------*/
    if(updated_sept_page_seam_va != 0){
        std::cout << "checking sEPT page symbolic buffer contents ..." << std::endl;
        int sept_idx = 0;
        bool res;

        MemValue mv2 ;
        mv2.size = 8 ;

        /*read the exact 8 byte block that is expected to be modified*/
        mv2.addr = updated_sept_page_seam_va;
        mv2.bsym = false;
        mv2.isSymList = false;

        res = m_VM->readMemory (mv2);
        assert(res);
        if(mv2.bsym){
            assert(mv2.expr);
            std::cout << "Update expected sEPTE: ";
            mv2.expr->print();
            std::cout << std::endl;
        }
        else{
            std::cout << "Update expected sEPTE: 0x" << std::hex << mv2.i64 << std::endl;
        }

        /*check sEPT data, symbolic buffer*/
        while(sept_idx < 512){
            mv2.bsym = false;
            mv2.addr = updated_sept_page_seam_va + 8*sept_idx;
            // mv2.isSymList = false ;  ???
            res = m_VM->readMemory (mv2);
            assert(res);
            if(mv2.bsym){
                assert(mv2.expr);
                std::cout << "buffer offset: 0x" << std::hex << sept_idx*8; 
                std::cout << " 8 byte block: ";
                mv2.expr->print();
                std::cout << std::endl;
            }
            
            sept_idx +=1;
        }
    }
}
/*---sanitiy checks and post processing ----------------------------------------------------------------------------------END*/

void CAnalyze::endOfPathJobs(int scall_status){ //analysis at the end of each path

}

ulong CAnalyze::getKholePte(ulong rip){

    ulong pte;

    std::cout << "khe-ins: 0x" << sreq->keyhole_edit_ins_adr[0] << " 0x" << sreq->keyhole_edit_ins_adr[1] << std::endl;

    if(rip == sreq->keyhole_edit_ins_adr[0]){
        pte = m_regs->regs.rdx;
        std::cout << "pte-x: 0x" << std::hex << pte << std::endl;
    }
    else if(rip == sreq->keyhole_edit_ins_adr[1]){
        pte = m_regs->regs.rsi;
        std::cout << "pte-y: 0x" << std::hex << pte << std::endl;
    }
    else{
        assert(0);
    }
    return pte;
}

bool beginAnalysis(ulong addr){

    return m_Thin->processFunction(addr);
}
