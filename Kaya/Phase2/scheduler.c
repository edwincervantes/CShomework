/*********************************************** SCHEDULER.C ******************************************************/
/******************************************************************************************************************/

/*  Scheduler.c is implemented using a "round-robin" scheduling algorithm with a time slice as defined by QUANTUM,
    which is 5ms. This .c file handles the scheduling of a new process following the completion of the previous process
    with a single CPU. These processes/jobs are scheduled from our readyQueue list. In addition, our scheduler deals
    with deadlock and checks for other scheduling situations to take some appropriate action. 
    
    ==== Written By Solomon G and Edwin Cervantes ==== */
/******************************************************************************************************************/

/*********************************************** #INCLUDE MODULES *************************************************/
/* .h files to include */
#include "../h/const.h"
#include "../h/types.h"

/* .e files to include */
#include "../e/initial.e"
#include "../e/exceptions.e"
#include "../e/pcb.e"
#include "../e/asl.e"

/* include the µmps2 library */
#include "/usr/local/include/umps2/umps/libumps.e"
/****************************************************************************************************************/


/*********************************************** GLOBAL VARIABLES ***********************************************/
cpu_t TODStart; /* time when process started */
cpu_t currentTOD; /* time when process finished */
/****************************************************************************************************************/


/*  Function: schedules all processes/jobs and keep track of the usage of cpu time */
/*  Parameters: N/A */
/*  Returns: N/A */
void scheduler(){

    /*  See if there is a current processes. If so store off time
        We will save the amt of time currentProcess had on the CPU and commit to cpuTime */
    if (currentProcess != NULL) {
        int eTime;
        STCK(currentTOD); /* load the current time */
        eTime = currentTOD - TODStart; /* calculate the Elapsed time */
        currentProcess->p_time = (currentProcess->p_time) + (eTime);
    }

    /*  Check to see if there are any ready jobs */
    currentProcess = removeProcQ(&readyQueue);/*Who is the next process in our q*/
    if (currentProcess != NULL){
        STCK(TODStart); /* load start clock */
        setTIMER(QUANTUM); /* Start our timer */
        contextSwitch(&(currentProcess -> p_state)); /* BAM context switch happens - change the state of currentProcess */
    }

/********* No jobs in readyQueue. Enter either halt, panic or wait *********/ 
    if(processCount == 0){ 
        HALT();
    }

    if(processCount > 0 && softBlockCount == 0){
    /*  We enter deadlock, screwed, we DO NOT want to end up here (also SHOULDN"T HAPPEN) because processCount shouldn't 
        be less than 0 */
        PANIC(); 
	}

    if(processCount > 0 && softBlockCount > 0) {

		setSTATUS((getSTATUS() | ALLOFF | INTERRUPTSON | INTERRUPTSCON | IM)); /* Set status */
		WAIT(); /* chill out and wait state */ 
	}
}
/******************************************* END OF INITIAL.C **************************************************/
/***************************************************************************************************************/
