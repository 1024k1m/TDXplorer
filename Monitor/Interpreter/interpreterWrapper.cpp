#include "hub.h"
#include "interpreterWrapper.h"
#include "cpuregs.h"

extern "C" {
        ExecState* newExecState() {
            unsigned long adds, adde;
            adds = 0x0;
            adde = 0xfffffffffffff000;
            return new ExecState(adds, adde);
        }

        void do_SynRegsFromNative(ExecState *e, struct MacReg *mreg){
            e->SynRegsFromNative(mreg);
        }

        void do_SynRegsToNative(ExecState *e, struct MacReg *mreg){
            e->SynRegsToNative(mreg);
        }

        void do_dispatch(ExecState *e, unsigned long adr) {
            e->processAt(adr); 
        }


}