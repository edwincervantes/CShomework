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
#include "../e/exceptions.e"
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
   /* Lets see if there is a current processes. If so store off time
    We will save the amt of time currentProcess had on the CPU and commit to cpuTime*/
    if (currentProcess != NULL)
        {
            STCK(currentTOD);
            currentProcess->p_time = (currentProcess->p_time) + (currentTOD - TODStart);
        }
    /* Check to see if there are any ready jobs */
    if (!emptyProcQ(readyQueue)){
        currentProcess = removeProcQ(&readyQueue);/*Who is the next process in our q*/

        STCK(TODStart); /*start ckick*/

        setTIMER(QUANTUM); /*Start our quantum of 5000 ms*/
        contextSwitch(&(currentProcess -> p_state)); /*BAM context switch*/
    
    } else { /*No jobs in readyq. Enter either halt, panic or wait*/
        currentProcess = NULL;
        if(processCount == 0){ /*This is what we want*/
            HALT();
        }
        if(processCount > 0 && softBlockCount == 0) { /*We enter deadlock, screwed*/
            PANIC();
		}
        if(processCount > 0 && softBlockCount > 0) {
			setSTATUS((getSTATUS() | ALLOFF | INTERRUPTSON | INTERRUPTSCON | IM));
			WAIT(); /* chill out and wait state */
		}

    }
}
