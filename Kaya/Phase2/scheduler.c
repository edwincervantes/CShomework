/********************************************************************************************************************************

                              ~initial.c~
              Written By Solomon G and Edwin Cervantes

scheduler.c is implemented of a "round-robin" style scheduler with a time slice of 5 milliseconds.

This scheduler will also perform simple deadlock detection and if deadlock == true we will perform some appropriate action.

    ReadyQueue - A tail pointer to a queue of ProcBlk's representing processes that are ready and waiting for a turn at execution
    CurrentProcess - A pointer to a ProcBlk that represents the current executing process
    ProcessCount - The count of the number of processes in the system
    Soft-blockCount - The number of processes in the system currently blocked and waiting for an interrypt; I/O complete/Time expired

ReadyQueue == NULL (empty)
    -If ProcessCount == 0, invoke Halt Rom service/instruction
    -If ProcessCount > 0 && Soft-blockCount == 0 then DeadLock; Invoke Panic ROM service/instruction
    If ProcessCount > 0 && Soft-blockCount > 0 enter a "Wait State"


*********************************************************************************************************************************/
#include "../h/const.h"
#include "../h/types.h"
#include "../e/initial.e"
#include "../e/pcb.e"
#include "../e/asl.e"
#include "/usr/local/include/umps2/umps/libumps.e"

/*scheduler() uses a Round-Robin scheduling algo

Once there are no more processes, we will HALT
When there is DeadLock we will invoke Panic()
When we enter a WaitState we will Wait

GLOBAL VARIABLES */
cpu_t TODStart;
cpu_t currentTOD;

void scheduler(){

    /* Check to see if there are any ready jobs */
    if (emptyProcQ(readyQueue) == NULL){

        currentProcess = NULL;
        if (processCount == 0){

        /* This is to check if there are no jobs left, then halt */
            HALT();
        }

        /* If there are one or more jobs, i.e. is there an IO? */
        if (processCount > 0){
            if (softBlockCount == 0){

                /* kernel panic */
                PANIC();
            } else if (softBlockCount > 0){
                    /* enable interrupts for the next job */
                    setSTATUS(getSTATUS() | ALLOFF | INTERRUPTSON | IC | IM);
                    WAIT(); /* wait */
                }
        }
    } else {

        /* Lets see if there is a current processes. If so store off time
        We will save the amt of time currentProcess had on the CPU and commit to cpuTime*/
        if (currentProcess != NULL)
        {
            STCK(currentTOD);
            currentProcess->p_time = (currentProcess->p_time) + (currentTOD - TODStart);
        }

        /* generate an interrupt when timer is up */
        if(currentTOD < QUANTUM) {
            /* our current job will be less than 
            our quantum, take the shorter */
            setTIMER(currentTOD);
        } else {
            /* set the quantum */
            setTIMER(QUANTUM);
        }

        /* If it's not null, remove the ready of readyQ */
        currentProcess = removeProcQ(&readyQueue);

        /* start the time */
        STCK(TODStart);
        contextSwitch(&(currentProcess -> p_state));
    }
}
