
/********************************************************************************************************************************
                              ~initial.c~
              Written By Solomon G and Edwin Cervantes
initial.c is our nucleus initialization or entry point for the OS Kaya. Our checklist is as follows
    -Set the PC to the address of our nucleus function that is to handle exceptions of that type
    -Set the $SP to the RAMTOP
    -Set the Status register to mask all interrupts, turn VM off, enable processor Local Timer, and be in Kernel Mode
    -Initialize initPCB() and initSemd()
    -Initialize Process Count, Soft-block Count, Ready Queue, and Current Process
    -Initialize all nucleus maintained semaphores
    -Instantiate a single process and place its ProcBlk in the Ready Queue
    -Call the scheduler
Phase 2 Global Vars
    -processCount(int)
    -softBlockCount(int)
    -currentProcess(pcb_PTR)
    -readyQueue(pcb_PTR)
*********************************************************************************************************************************/

/*Boot code for Operating System
    -Populate the four new areas in low memory to facilitate correct operation of a context switch
        -Set the $SP to the last page of physical memory
        -Set PC to the appropriate function
        -Set the status: VM-off, Interrupts-masked, Supervisor mode-on
    -initPCB()
    -initASL()
    -initialize Phase 2 global Vars
    -p = allocatePCB()
        -initialize p_state
            -Set stack pointer to the penultimate page of physical memory
            -Set PC to (p2test)
            -Set status from above
        -processCount++
        -insertProcQ(&readyQueue, p)
        -scheduler()
*/
/* h files to include */
#include "../h/const.h"
#include "../h/types.h"
/* e files to include */
#include "../e/pcb.e"
#include "../e/asl.e"
#include "../e/initial.e"
#include "../e/interrupts.e"
#include "../e/exceptions.e"
#include "../e/scheduler.e"
/* include the µmps2 library */
#include "/usr/local/include/umps2/umps/libumps.e"

/* Global variables as follows */

/* current process count */
int processCount;

/* soft blocked count */
int softBlockCount;

/* current process */
pcb_PTR currentProcess;

/* ready queue processes */
pcb_PTR readyQueue;

int semdTable[SEMALLOC];

extern void test();



int main() {
    int i;
    unsigned int RAMTOP;
        
    /* defining the rdev egister area*/
    devregarea_PTR registerBus;

    state_PTR newState;



    /* initialize global variables defined above */
    readyQueue = mkEmptyProcQ();
    currentProcess = NULL;
    processCount = 0;
    softBlockCount = 0;

    registerBus = (devregarea_PTR) RAMBASEADDR;

    RAMTOP = (registerBus->rambase) + (registerBus->ramsize);

    for( i = 0; i < SEMALLOC; i++){
        /* initialize every semaphore with a starting address of 0 */
        semdTable[i] = 0;
    }
    /* a pointer to locate areas of the memory */
    /*newState = (state_PTR) MEMAREA;*/

    /* This is the syscall area */
    newState = (state_PTR) SYSCALLNEWAREA;
    newState->s_status = ALLOFF;
    newState->s_sp = RAMTOP;
    newState->s_pc = (memaddr) syscallHandler; /* syscallHandler */
    newState->s_t9 = (memaddr) syscallHandler; /* syscallHandler */

    /* This is the Prog trap area */
    newState = (state_PTR) PRGMTRAPNEWAREA;
    newState->s_status = ALLOFF;
    newState->s_sp = RAMTOP;
    newState->s_pc = (memaddr) progTrapHandler; /* progTrapHandler */
    newState->s_t9 = (memaddr) progTrapHandler;/* progTrapHandler */

    /* This is the tblmgmt area */
    newState = (state_PTR) TBLMGMTNEWAREA;
    newState->s_status = ALLOFF;
    newState->s_sp = RAMTOP;
    newState->s_pc = (memaddr) tlbHandler;
    newState->s_t9 = (memaddr) tlbHandler;

    /* This is the interrupt area */
    newState = (state_PTR) INTERRUPTNEWAREA;
    newState->s_status = ALLOFF;
    newState->s_sp = RAMTOP;
    newState->s_pc = (memaddr) interruptHandler;
    newState->s_t9 = (memaddr) interruptHandler; 

      /* initialize ASL and PCB */
    initPcbs();
    initASL();
   
  


    currentProcess = allocPcb();
    processCount++;

    /*If currproc =! NULL*/
    currentProcess->p_state.s_sp = (RAMTOP - FRAMESIZE);
    currentProcess->p_state.s_pc = (memaddr) test; 
    currentProcess->p_state.s_t9 = (memaddr) test;
    currentProcess->p_state.s_status = (ALLOFF | INTERRUPTSON | IM | TE);


    /* insert the newly process into ready queue */
    insertProcQ(&(readyQueue), currentProcess);

    /* the new process is in the queue */
    currentProcess = NULL;


    /* load an interval time*/
    LDIT(INTERVALTMR);

    /* Call the scheduler */
    scheduler();

    return -1; /*We get a warning if we don't return a value*/
}
