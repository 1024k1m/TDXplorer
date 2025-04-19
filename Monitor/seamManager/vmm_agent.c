#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "defs.h"
#include "seam.h"
#include "common.h"
#include "td_control_structures.h"
#include "tdx_local_data.h"

void remove_debug_bp(ulong dr_num);
void set_debug_bp(ulong address, ulong dr_num, ulong trigger_condition, ulong bp_size);
extern int switch_to_tdx_module_context(TDXCALL_TYPE call_type);
extern void setup_tdxmodule_seamcall_state(ulong seamcall);
extern void do_tdxcall(ulong seamcall);
extern uint64_t get_saved_register_value(REGS_64 reg);
extern void log_active_keyhole_mappings();
extern void block_persistant_khole_mappings(ulong current_lp);
extern ulong get_tdmr_next_avl_pa(ulong td, ulong hkid, ulong hkid_owner);
extern ulong get_tdr_va_of_running_td(ulong pa, ulong lp);
extern ulong va_to_pa(ulong cr3, ulong va);
extern ulong get_region_base_pa(REGION region);
extern void fill_khole_refs(ulong lp);

ulong get_offset(OFFSET_TYPE type);

extern struct vm *vm;

void start_se();
extern void setup_and_do_tdcal(ulong tdcall_number, ulong lp);
void run_servtd_bind();

#define SEAMCALL(...) do_tdxcall(__VA_ARGS__)

extern struct comArea *com;

#ifdef TEST_TDH_SERVTD_BIND
ulong td_0_created = 0;
#endif

void start_se(){
	
	com->seam_state = SEAM_STATE_TEMP;
	com->single_step_on = true;
}

void setup_and_do_seamcall(ulong seamcall_number, ulong lp){
	
	com->current_lp = lp;
	com->seamcall_vmcs[lp].vm_exit_reason = VMEXIT_REASON_SEAMCALL;
	com->current_tdx_vmcs_pa = com->seamcall_vmcs[lp].vmcs_pa;
	switch_to_tdx_module_context(TDXCALL_TYPE_SEAMCALL);
	setup_tdxmodule_seamcall_state(seamcall_number);
	SEAMCALL(seamcall_number);
}

void add_a_new_page_custom(ulong td_id, ulong lp_id){

	com->td_mem.next_td_page_gpa = com->td[td_id].next_4k_pg_gpa_to_add;
	com->td[td_id].next_4k_pg_gpa_to_add += _4K;

	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_PAGE_ADD ,lp_id);
}

void add_a_new_sept_custom(ulong td_id, ulong lp_id, int level, ulong gpa){

	com->current_td_being_setup = td_id;
	com->sept.septe_level = level;
	com->sept.start_gpa = gpa;
	
	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_SEPT_ADD, lp_id);
}

/*TD Creation and Key Resource Assignment-----------
	TDH_MNG_CREATE,
	TDH_MNG_KEY_CONFIG,
TDCS Memory Allocation and TD Initialization--------
	TDH_MNG_ADDCX,
	TDH_SYS_INFO,
	TDH_MNG_INIT,
Virtual Processor Creation and Configuration--------
	TDH_VP_CREATE,
	TDH_VP_ADDCX,
	TDH_VP_INIT,
	TDH_VP_WR -The host VMM may modify a few TD VMCS execution control fields using this SEAMCALL
TD Boot Memory Setup, measurement & finalize--------
	TDH_MEM_SEPT_ADD,
	TDH_MEM_PAGE_ADD,
	TDH_MR_EXTEND
	TDH_MR_FINALIZE*/
void create_td(ulong td_id, ulong lp_id, ulong initial_gpa_max, ulong initial_pages_to_add){

	// ulong lp_id = 0;
	ulong tdcs_add_count, tdvps_add_count, sept_parent_level, gpa_start, pg_count, pg_start;
	ulong chunk_gpa;

	if((td_id >= MAX_TDS) || (td_id < 0)){
		LOG("invalid TD id: %lu\n", td_id);
		exit(0);
	}
	if((initial_gpa_max <= 0) || (initial_gpa_max > TD_GPA_RANGE_MAX) || (initial_gpa_max & PAGE_OFST != 0)){
		LOG("invalid initial_gpa_max: 0x%lx\n", initial_gpa_max);
		exit(0);
	}
	com->current_td_being_setup = td_id;
	com->td[td_id].initial_gpa_max = initial_gpa_max;
	com->td[td_id].next_gpa_to_allocate_in_sept = initial_gpa_max;

	/*TD Creation and Key Resource Assignment------------*/
	setup_and_do_seamcall(TDH_MNG_CREATE, lp_id);
	setup_and_do_seamcall(TDH_MNG_KEY_CONFIG, lp_id);

	/*TDCS Memory Allocation and TD Initialization-------*/
	tdcs_add_count = 0;
	do{
		if (tdcs_add_count == 0){
			com->td[td_id].tdcs_base = get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		}
		else if(tdcs_add_count == 3){
			com->td[td_id].tdcs_eptp_root = get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);
		}
		setup_and_do_seamcall(TDH_MNG_ADDCX, lp_id);
		tdcs_add_count++;
	}while(tdcs_add_count < MIN_NUM_TDCS_PAGES);
	setup_and_do_seamcall(TDH_SYS_INFO, lp_id); /*to get sys_info*/
	setup_and_do_seamcall(TDH_MNG_INIT, lp_id);

	/*testing TDH_SERVTD_BIND*/
#ifdef TEST_TDH_SERVTD_BIND
	run_servtd_bind();
#endif

	/*Virtual Processor Creation and Configuration-------*/
	/*In the current design, we provide only 1 vCPU for a TD (i.e. only 1 VP CREATE). If this is 
	changed in future, we also need to update all places where we consider a TD to only have 1 vCPU.*/
	LOG("com->tdmr_next_avl_pa tdvps:%lx\n", com->tdmr_next_avl_pa);
	setup_and_do_seamcall(TDH_VP_CREATE, lp_id);
	LOG("tdvps pa: %lx\n", com->td[td_id].tdvpr);
	tdvps_add_count = 0;
	do{
		LOG("com->tdmr_next_avl_pa:%lx\n", com->tdmr_next_avl_pa);
		if(tdvps_add_count == 0)
			com->tdcall_vmcs[td_id].vmcs_pa = get_tdmr_next_avl_pa(td_id, com->td[td_id].hkid, td_id);;
		setup_and_do_seamcall(TDH_VP_ADDCX, lp_id);
		tdvps_add_count++;
	}while(tdvps_add_count < (MAX_TDVPS_PAGES - 1));
	setup_and_do_seamcall(TDH_VP_INIT, lp_id);

	/*As noticed, during VP Init the corresponding tdvps is associated with the current LP id.
	This is the LP on which the VMLAUNCH must take place. So we save the value for future use.*/
	com->td[td_id].vcpu_associated_lp = lp_id;

	/*TD Boot Memory Setup : sept-------------------------------*/
	/*here we create the initial sept tree. the root sept page, sPML4 (for 4 level ept) OR sPML5
	(for 5 level ept) has already been created.
	under TDH_MNG_ADDCX. Now, we add the remaining lower level sEPT pages accordingly.
	For 4 level EPT : one sPDPT (parent sept level 3), one sPD (parent sept level 2), and one or 
	few sPT (parent sept level 1) pages.	
	For 5 level EPT : one sPML4 (parent sept level 4), one sPDPT (parent sept level 3), one sPD 
	(parent sept level 2), and one or few sPT (parent sept level 1) pages.	
	The number of sPT pages added depends on the initial_gpa_max. Eg: if initial_gpa_max = 4M, we 
	add a sPT page for each 2M block. i.e. 1 for GPA range starting at 0, another for GPA range 
	starting at 2M*/
	gpa_start = 0;
	sept_parent_level = TDX_SEPT_LEVELS;
	while(sept_parent_level > 0){

		com->sept.septe_level = sept_parent_level;
		com->sept.start_gpa = 0;

		if(sept_parent_level == 1){
			if(gpa_start < initial_gpa_max){
				LOG("gpa start:0x%lx\n", gpa_start);
				com->sept.start_gpa = gpa_start;
				gpa_start += _2M;
			}
			else{
				break;
			}
		}
		else{
			com->sept.start_gpa = 0;
			sept_parent_level--;
		}
		setup_and_do_seamcall(TDH_MEM_SEPT_ADD, lp_id);

		LOG("R8: %lx\n", get_saved_register_value(R8));
		if(get_saved_register_value(R8) != NULL_PA){
			LOG("SEPT add issue\n");
			exit(0);
		}
	}

	/*TD Boot Memory Setup : initial pages---------------------------*/
	pg_count = 0;
	pg_start = 0;
	while (pg_count < initial_pages_to_add){
		
		com->td_mem.next_td_page_gpa = pg_start;
		com->td[td_id].next_4k_pg_gpa_to_add = pg_start + _4K;
		/*We do not actually run  the TD. Therefore, for the moment we do not need to pass actuall data 
		in to td pages being added. So, we use some page in the host as the source page. 
		we have used the first 2 pages of SEAM_AGENT_SEAMCALL_DATA_PA, so use the 3rd page here.*/
		com->td_mem.next_source_page_hpa = SEAM_AGENT_SEAMCALL_DATA_PA + 2*_4K;
		setup_and_do_seamcall(TDH_MEM_PAGE_ADD, lp_id);

		pg_start += _4K;
		pg_count++;
	}

	/*TD Boot Memory Setup : measurement-----------------------------*/
	chunk_gpa = 0;
	while (chunk_gpa < initial_pages_to_add*_4K){
		
		com->td_mem.next_chunk_to_measure_gpa = chunk_gpa;
		setup_and_do_seamcall(TDH_MR_EXTEND, lp_id);

		chunk_gpa += 256; /*each chunk is 256B*/
	}

	/*TD Boot Memory Setup : finalize--------------------------------*/
	setup_and_do_seamcall(TDH_MR_FINALIZE, lp_id);
	com->td[td_id].is_created = true;
}

/*TDX Module init
	TDH_SYS_INIT,
	TDH_SYS_LP_INIT,
	TDH_SYS_CONFIG,
	TDH_SYS_KEY_CONFIG,
	TDH_SYS_TDMR_INIT */
void init_tdx_module(){

	ulong lp;
	LOG("init_tdx_module\n");
	com->seamvmcs.vm_exit_reason = VMEXIT_REASON_SEAMCALL;

	/*TDH_SYS_INIT-----------------------------------*/
	setup_and_do_seamcall(TDH_SYS_INIT, LP_0);

	/*TDH_SYS_LP_INIT--------------------------------*/
	lp = 0;
	while(lp < NUM_ADDRESSIBLE_LPS){
		com->current_lp = lp;
		setup_and_do_seamcall(TDH_SYS_LP_INIT, lp);
		lp++;
	}

	lp = 0;
	com->current_lp = lp;
	/*TDH_SYS_CONFIG-----------------------------------*/
	setup_and_do_seamcall(TDH_SYS_CONFIG, lp);

	/*TDH_SYS_KEY_CONFIG-------------------------------*/
	setup_and_do_seamcall(TDH_SYS_KEY_CONFIG, lp);

	/*TDH_SYS_TDMR_INIT--------------------------------*/
	do{
		setup_and_do_seamcall(TDH_SYS_TDMR_INIT, lp);
	}while(get_saved_register_value(RDX) < (TDX_TDMR0_START_PA + TDX_TDMR0_FULL_SIZE));
	/*The above terminating condition is consistant with the specs and kvm.
	The returned rdx is the block in the tdmr to be initialized next.*/
}

void run_td(ulong td_id, ulong lp){

	LOG("\nRun td: %lu\n", td_id);
    block_persistant_khole_mappings(lp);
	
	com->td_owner_for_next_tdxcall = td_id;
	com->tdcall_vmcs[td_id].vm_exit_qualification = 0;
	com->tdcall_vmcs[td_id].rip = TD_START_RIP;
    setup_and_do_seamcall(TDH_VP_ENTER, lp);
	com->td[td_id].is_running = true;

	log_active_keyhole_mappings();

}

void bind_serv_td(ulong td_id, ulong serv_td_id, ulong lp_id){

	com->current_td_being_setup = td_id;
	com->serv_td_owenr_being_setup = serv_td_id;

	setup_and_do_seamcall(TDH_SERVTD_BIND, lp_id);
}

void prebind_serv_td(ulong td_id, ulong lp_id){

	com->current_td_being_setup = td_id;

	setup_and_do_seamcall(TDH_SERVTD_PREBIND, lp_id);
}

void add_a_new_sept(ulong td_id, ulong lp_id, int level){

	com->current_td_being_setup = td_id;
	com->sept.septe_level = level;
	com->sept.start_gpa = com->td[td_id].next_gpa_to_allocate_in_sept;
	
	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_SEPT_ADD, lp_id);
}

void tdh_sept_rd(ulong td_id, ulong lp_id, int level, ulong gpa){

	com->current_td_being_setup = td_id;
	com->sept.septe_level = level;
	com->sept.start_gpa = gpa;
	
	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_SEPT_RD, lp_id);
}

void add_a_new_page(ulong td_id, ulong lp_id){

	com->td_mem.next_td_page_gpa = com->td[td_id].next_4k_pg_gpa_to_add;
	com->td[td_id].next_4k_pg_gpa_to_add += _4K;

	block_persistant_khole_mappings(lp_id);
	setup_and_do_seamcall(TDH_MEM_PAGE_AUG ,lp_id);
}

#ifdef TEST_TDH_SERVTD_BIND
void run_servtd_bind(){
	
	if(td_0_created == 1){

		ulong target_td = TD_1;
		ulong service_td = TD_0;

		//set object offsets for symbolization
		tdcs_t tdcs_base;
		//offset for  tdcs_p->service_td_fields.servtd_bindings_table[servtd_slot].state  1 byte
		ulong binding_state_ofst = (ulong)&tdcs_base.service_td_fields.servtd_bindings_table[0].state - (ulong)&tdcs_base;
		//offset for  attributes  8 bytes , can also consider the first 4 bytes to capture migratable flag
		ulong attributes_offset = (ulong)&tdcs_base.executions_ctl_fields.attributes - (ulong)&tdcs_base;
		//offset for  tdcs_p->management_fields.op_state   4 bytes
		ulong op_state_ofst = (ulong)&tdcs_base.management_fields.op_state - (ulong)&tdcs_base;

		LOG("binding_state_ofst: 0x%lx\n", binding_state_ofst);
		LOG("attributes_ofst: 0x%lx\n", attributes_offset);
		LOG("op_state ofst: 0x%lx\n", op_state_ofst);
		com->sreq.tdcs_binding_state_ofst = binding_state_ofst;
		com->sreq.tdcs_attributes_offset = attributes_offset;
		com->sreq.tdcs_op_state_ofst = op_state_ofst;

		com->sreq.tdcs_start_pa = com->td[target_td].tdcs_base;
		LOG("tdcs_start_pa: 0x%lx\n", com->sreq.tdcs_start_pa);
		// exit(0);

		ulong dr_adr = (LINEAR_BASE_CODE_REGION | TDX_MODULE_ADR_MASK) + get_offset(OFFSET_TYPE_TDH_SERVTD_BIND_LEAF);
		set_debug_bp(dr_adr, DEBUG_DR0, DB_CONDITION_INS_EXEC, DB_LENGTH_1_BYTE);
		// start_se();
		/*service td binding*/
		bind_serv_td(target_td, service_td, LP_0);
		/*service td prebinding*/
		// prebind_serv_td(TD_0, LP_1);
		LOG("Ending current test case.\n");
		exit(0);
	}

}
#endif

void vmm_agent(){
	
    LOG("VMM agent\n");

	init_tdx_module();
	exit(0);
	/*The same LP# on which a given TD vcpu was initialized must be used for VP_ENTER. At VP_INIT, 
	associate_vcpu_initial() binds the tdvpr to the LP on which the init is done, Later at VP_ENTER, 
	check_and_associate_vcpu() --> associate_vcpu() checks the folowing :
	"Check if VCPU is not associated with any LP, and associate it with the current LP.  The VCPU may 
	already be associated with the current LP, but if it's associated with another LP this is an error."
	Thus, make sure to create the two TDs on different LPs for them to be run on two lps later*/
	create_td(TD_0, LP_0, TD_GPA_RANGE, TD_INITIAL_PAGE_COUNT);
#ifdef TEST_TDH_SERVTD_BIND
	td_0_created = 1;
#endif
	create_td(TD_1, LP_1, TD_GPA_RANGE, TD_INITIAL_PAGE_COUNT);
	LOG("\nTwo TDs created.\n");


	ulong cur_td = TD_0;
	ulong gpa = 0;
	gpa = (1UL << 48);

	ulong lp_1 = LP_2;
	add_a_new_sept_custom(cur_td, lp_1, SEPT_LVL_4, gpa);
	add_a_new_sept_custom(cur_td, lp_1, SEPT_LVL_3, gpa);
	add_a_new_sept_custom(cur_td, lp_1, SEPT_LVL_2, gpa);

	add_a_new_sept_custom(cur_td, lp_1, SEPT_LVL_1, gpa);


    run_td(TD_0, com->td[TD_0].vcpu_associated_lp);
	com->sreq.td_num_on_lp[com->td[TD_0].vcpu_associated_lp] = TD_0;

	com->sreq.td_running = 1;
	run_td(TD_1, com->td[TD_1].vcpu_associated_lp);
	com->sreq.td_num_on_lp[com->td[TD_1].vcpu_associated_lp] = TD_1;

}