#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "defs.h"
#include "seam.h"
#include "common.h"

extern int switch_to_tdx_module_context(TDXCALL_TYPE call_type);
extern void block_persistant_khole_mappings(ulong current_lp);

void setup_tdxmodule_tdcall_state(ulong tdcall);
void setup_and_do_tdcal(ulong tdcall_number, ulong lp);

extern void do_tdxcall(ulong seamcall);

#define TDCALL(...) do_tdxcall(__VA_ARGS__)
#define TDEXIT(...) do_tdxcall(__VA_ARGS__)

extern struct comArea *com;

void td_agent();

void setup_and_do_tdcal(ulong tdcall_number, ulong lp){
	
    com->current_lp = lp;
    com->tdcall_vmcs[lp].vm_exit_reason = VMEXIT_REASON_TDCALL;
    com->current_tdx_vmcs_pa = com->tdcall_vmcs[lp].vmcs_pa;
    switch_to_tdx_module_context(TDXCALL_TYPE_TDCALL);
    setup_tdxmodule_tdcall_state(tdcall_number);
    block_persistant_khole_mappings(lp);
    TDCALL(tdcall_number);
}

void td_agent(){


}
