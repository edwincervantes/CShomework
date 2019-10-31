/********************************************************************************************************************************

                              ~exceptions.c~
              Written By Solomon G and Edwin Cervantes
Exceptions are synchronous events generated when processor detects any predefined condition while executing instructions.
This is where exceptions will be handled for the most part through
-sysCallHandler()
-prgTrapHandler()
-tlbTrapHandler()

*********************************************************************************************************************************/
#include "../h/const.h"
#include "../h/types.h"
#include "../e/initial.e"
#include "../e/scheduler.e"
#include "../e/pcb.e"
#include "../e/asl.e"
#include "/usr/local/include/umps2/umps/libumps.e"

cpu_t TODStart;
cpu_t currentTOD;


/*Local Functions*/
HIDDEN void createNewProcess(state_PTR state);
HIDDEN void terminateProcess();
HIDDEN void verhogen(state_PTR state);
HIDDEN void passeren(state_PTR state);
HIDDEN void syscall5(state_PTR state);
HIDDEN void calculateCpuTime(state_PTR state);
HIDDEN void waitForClock(state_PTR state);
HIDDEN void waitForIODevice(state_PTR state);
HIDDEN void passUpOrDie(state_PTR state, int trap);
HIDDEN void copyState(state_PTR src, state_PTR dest);
HIDDEN void helperTerminateProgeny(pcb_PTR p);


/*PROGTRAP defined as 1*/
void progTrapHandler(){
    /* find the area in mem */
    state_PTR oldS = (state_PTR) PRGMTRAPOLDAREA;
    passUpOrDie(oldS, PROGTRAP);
    /* Pass up the process to its appropriate
    handler or terminate it */
}


void contextSwitch(state_PTR state){
    /* load the new processor state */
    LDST(state);
}

/*TLBTRAP defined as 0*/
void tlbHandler(){
    /* find the area in mem */
    state_PTR oldS = (state_PTR) TBLMGMTOLDAREA;
    passUpOrDie(oldS, TLBTRAP);
    /* Pass up the process to its appropriate
    handler or terminate it */;
}

void syscallHandler(){
    unsigned int tempCause, calledStatus;
    int sysReq;
    state_PTR called, prog;
    called = (state_PTR) SYSCALLOLDAREA; /*Getting from memory, look at const.h*/
    sysReq = called -> s_a0; /*Pulling what syscall number was called, stored in a0 of old. Made it unsigned because our numbers can't be negative*/
    calledStatus = called -> s_status; /*Just storing our status*/
  
    /*Program Trap check
    Steps: - Copy the state from oldSys over to oldProg
            - Set the cause register in oldProg to reflect a Privileged Instruction exception
            -ProgTrap()*/
  
    if( (sysReq>0) && (sysReq<9) && ((calledStatus & USERMODEON) != ALLOFF)){ /*Need to check usermode is okay to be on here*/
        prog = (state_PTR) PRGMTRAPOLDAREA;
        copyState(called, prog);
        tempCause = (prog -> s_cause) & ~(PRIVATEINSTUC);
        (prog -> s_cause) = (tempCause | (10 << 2)); /*Between 10 and 2*/
        progTrapHandler();
    }
  
    called -> s_pc = called -> s_pc + 4; /*We must increment to the next instruction. We know to add 4 from Machine Org*/
  
    /*Here we are passing down our syscall # and performing the exception needed*/
    /**/
  
    switch(sysReq){
			case CREATEPROCESS:
				createNewProcess(called);
			break;
			case TERMINATEPROCESS:
				terminateProcess();
			break;
			case VERHOGEN:
				verhogen(called);
			break;
			case PASSEREN:
				passeren(called);
			break;
			case SPECTRAPVEC:
				syscall5(called);
			break;
			case GETCPUTIME:
				calculateCpuTime(called);
			break;
			case WAITCLOCK:
				waitForClock(called);
			break;
			case WAITIO:
				waitForIODevice(called);
			break;
			default: 
				passUpOrDie(called, SYSTRAP); /*SYSTRAP defined as 2*/
			break;
	}
}




/* Syscall 1 */
HIDDEN void createNewProcess (state_PTR state){
    state_PTR temp;
    pcb_PTR p;
    /* get a new process */
    p = allocPcb();

    if (p != NULL){
        /* there is now n+1 running processes */
        processCount++;
        /* since there is a free process, and if the process 
        has a parent, it is inserted into the parent, and then
        placed in the ready queue */
        insertChild(currentProcess, p);
        insertProcQ(&(readyQueue), p);
        /* copy the content from the state's 
        $a1 register to the new pcb_t's state */
        temp = (state_PTR) state->s_a1;
        copyState(temp, &(p->p_state));
        /* acknowledge the success of the new process
        by placing 0 in the state's $v0 register */ 
        state->s_v0 = SUCCEEDED;
    } else {
        /* if there are no free processes, acknowledge 
        the failure of a new allocated pcb_t by placing 
        -1 in the state's $v0 register */
        state->s_v0 = FAILED;
    }
    /* context switch */
    contextSwitch(state);
    }

/* Syscall 2 will go here */
HIDDEN void terminateProcess() {
    /* check if there are no children. If so, process is decremented.
    we remove current process, and free up a pcb_t */
    if(emptyChild(currentProcess)){
        processCount--;
        outChild(currentProcess);
        freePcb(currentProcess);
    } else {
        helperTerminateProgeny(currentProcess);
    }
}

/* Syscall 3 */
HIDDEN void verhogen(state_PTR state) {
    /* the semaphore is placed in the a1 register of the 
    passed in state_t */
    pcb_PTR p =NULL;
    int* semaphore = (int*) state->s_a1;
    /* increment the semaphore - the V operation on 
    the semaphore */
    ((*semaphore))++;
    /* if the synchronization semaphore is less than or equal to 0, 
    then it will remove the process from the blocked processes 
    and place it in the ready queue - which synchronizes the processes */
    if((*semaphore) <= 0) {
        /* unblock the next process */
        p = removeBlocked(semaphore);
        /* current process is then placed in the ready 
        queue */
        if(p != NULL) {
            /* place it in the ready queue */
            insertProcQ(&readyQueue, p);
            softBlockCount--;
        }else
        {
            /* idk */
        }
        
    }
    /* perform a context switch on the requested process */
    contextSwitch(state);
}

/* Syscall 4 */
HIDDEN void passeren(state_PTR state) {
    /* get the semaphore in the s_a1 */
    int* semaphore = (int*) state->s_a1;
    /* decrement the semaphore */
    (*semaphore)--;
    if ((*semaphore) < 0) {
        /* copy from the old syscall area to the new process's state */
        copyState(state, &(currentProcess->p_state));
        /* the process now must wait */
        insertBlocked(semaphore, currentProcess);
        softBlockCount++;
        /* get a new job */
        scheduler();
    }
    /* if the semaphore is greater than or equal to zero, do not 
    block the process, just load the new state by context switching*/
    contextSwitch(state);
}

/* Syscall 5*/

HIDDEN void syscall5(state_PTR state) {
    /* get the exception from the a1 register */
    switch(state->s_a1) {

        case TLBTRAP:
        
            if(currentProcess->newTLB != NULL) {
                terminateProcess();
            }

            /* store the syscall area state in the new tlb */
            currentProcess->newTLB = (state_PTR) state->s_a3;
            /* store the syscall area state in the old tlb*/
            currentProcess->oldTLB = (state_PTR) state->s_a2;
            break;
        case PROGTRAP:

            if(currentProcess->newPgm != NULL) {
                terminateProcess();
            }
            /* store the syscall area state in the new pgm */
            currentProcess->newPgm = (state_PTR) state->s_a3;
            currentProcess->oldPgm = (state_PTR) state->s_a2;
            break;

        case SYSTRAP:

            if(currentProcess->newSys != NULL) {
                terminateProcess();
            }

            /* store the syscall area state in the new pgm */
            currentProcess->newSys = (state_PTR) state->s_a3;
            /* store the syscall area state in the old pgm*/
            currentProcess->oldSys = (state_PTR) state->s_a2;
            break;
    }
    contextSwitch(state);
}

/* Syscall 6 */
HIDDEN void calculateCpuTime(state_PTR state) {
        /* the clock can be started by placing a new value in the 
        STCK ROM function */
        cpu_t TODEnd, eTime;
        /* copy the state from the old syscall into the pcb_t's state */
        copyState(state, &(currentProcess->p_state)); 
        /* start the clock  for the stop */ 
        STCK(TODEnd);
        /* calculate the elapsed time */
        eTime = TODEnd - TODStart;
        currentProcess->p_time = (currentProcess->p_time) + eTime;
        /* store the state in the pcb_t's v0 register */
        currentProcess->p_state.s_v0 = currentProcess->p_time;
        /* start the clock */
        STCK(TODStart);
        contextSwitch(&(currentProcess->p_state));
}

/* Syscall 7 */
HIDDEN void waitForClock(state_PTR state) {
     int *semaphore;
     /* get the semaphore index of the clock timer */
     semaphore = (int*) &(semdTable[PSEUDOCLOCK]);
     /* perform a p operation */
     (*semaphore)--;
     if ((*semaphore) < 0)
     {
         /* block the process */
         insertBlocked(semaphore, currentProcess);
         /* copy from the old syscall area into the new pcb_state */
         copyState(state, &(currentProcess->p_state));
         /* increment the number of waiting processes */
         softBlockCount++;
     }
     /* else invoke scheduler() */
     scheduler();
}

/* Syscall 8 */
HIDDEN void waitForIODevice(state_PTR state){
    int lineNum, deviceNum, terminal, index;
    int *semaphore;
    /* line number in the a1 register */
    lineNum = state->s_a1;
     /* device number in the a2 register */
    deviceNum = state->s_a2;
     /* terminal read/write in the a1 register */
    terminal = state->s_a3;

    /* these devices can't do IO request */
    if (lineNum < DISKNUM || lineNum > TERMINT){

        /* terminate */
        terminateProcess();
    }

    /* calculate the index of the device sema4 that did IO request and if it's a terminal read */
    if (lineNum == TERMINT && terminal == TRUE){

        index = PERDEV * (lineNum - DEVNOSEM + terminal) + deviceNum;
    
    /* calculate index without the terminal read */
    } else {
        index = PERDEV * (lineNum - DEVNOSEM) + deviceNum;
    }
    semaphore = &(semdTable[index]);
    /* p operation */
    (*semaphore)--;
    if ((*semaphore) < 0){
        /* block the current process */
        insertBlocked(semaphore, currentProcess);
        copyState(state, &(currentProcess->p_state));
        softBlockCount++;

        /* call scheduler to get a new processor */
        scheduler();
    }
    contextSwitch(state);
}

/*Allows caller to store the address of 2 processor states
Only occurs for TLBtrap, or ProgTrap or SYScall >= 9 occurs
-Has a sys5 for that trap been called? - Check if sys/tlb/progNEW != NULL in the current process meaning sys5 was executed
    No: Terminate process and all its offspring(sys2)
    Yes: Copy the state that caused the exception from oldXXX -> location specified in their PCB
-LDST(current->newSys)*/

HIDDEN void passUpOrDie(state_PTR oldS, int trap){
    switch(trap){
        case TLBTRAP: /*0*/
            if(currentProcess -> newTLB != NULL){
                copyState(oldS, currentProcess -> oldTLB);
                contextSwitch(currentProcess -> newTLB);
            }
        break;

        case PROGTRAP: /*1*/
            if(currentProcess -> newPgm != NULL){
                copyState(oldS, currentProcess -> oldPgm);
                contextSwitch(currentProcess ->newPgm);
            }
        break;

        case SYSTRAP:  /*2*/
            if(currentProcess -> newSys != NULL){
                copyState(oldS, currentProcess -> oldSys);
                contextSwitch(currentProcess -> newSys);
            }
        break;

    }
    /*No cases match. KILL EVERYONE*/
    terminateProcess();
}
HIDDEN void helperTerminateProgeny(pcb_PTR p){
    /* terminate each progeny */
    while(!emptyChild(p)){
        helperTerminateProgeny(removeChild(p));
    }

    /* check the pcb_b has a semaphore address */
    if (p->p_semAdd != NULL){

        /* get the sempahore */
        /*int* sema4 = p->p_semAdd;*/

        /* when sempahore address is found, call outBlocked */
        outBlocked(p);

        /* Handle semaphore count when unblocking 
        i.e. softBlockCount and/or (*sem)--
        */
    }
    /* n-1 processes left */
    processCount--;
    freePcb(p);
}

HIDDEN void copyState(state_PTR src, state_PTR dest) {
    int i;

    /* id */
    dest->s_asid = src->s_asid;

    /* register cause */
    dest->s_cause = src->s_cause;

    /* pc */
    dest->s_pc = src->s_pc;

    /* status register */
    dest->s_status = src->s_status;

    /* each register */
    
    for (i=0; i < STATEREGNUM; i++){
        dest->s_reg[i] = src->s_reg[i];
    }
}
