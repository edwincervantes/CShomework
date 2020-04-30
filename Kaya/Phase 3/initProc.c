/*********************************************** initProc.c *******************************************************/
/********************************************************************************************************************/

/*  
    test(){
    -Initialize all of our global variables
    -KSeg0S
        -64 entries
            -HI - 0x20000+i and bit shift
            -LO - 0x20000+i DIRTYON GLOBALON
    -Swap Pool
        Set each entry to unoccupied
            -ASID = -1
            -SegNO = 0
            -PageNO = 0
            -pte_PTR = NULL
    -SwapPoolSema4 = 1
    -An Array of Semaphores: one for each interrupting device = 1
    -MasterSema4 = 0 .........Test() knows when to sys2 itself
    -Process initialization loop
        -Set up KUseg2 pgtab
            -32 entries
                -HI = 0x80000+1 w/ ASID
                -LO = ALLOFF and DIRTY
            -Fix last entry 
                HI = 0xBFFFF w ASID
        -Set 3 appropriate three entries in the global seg table
        -call sys1
    -Sys2 our array
    -Sys2 test()

    }
    
    uProcInit(){
    -We must figure out who we are? Getting out ASID
    -Set up the three new areas for Passup or Die
        -Stack page
        -PC = addr of Phase3 handler
        -ASID = Your ASID value
        -Status: Interrupt EN, Local Timer EN, VMON, KUON
    -Call sys 5 three times
    -Put the contents of the tape dev (asid-1) onto the backing store dev(disk0)
        -Keep reading until tape block marker in no longer ENDOFBLOCK
    -Write out to appropriate location on backing store
    -Set up a new state for the user proc
        -ASID - Youre ASID
        -Stack page - last page of KUseg2
        -Status: Interrupt EN, Local Timer EN, VMON, UsermodeON
        -PC - Well known address from the start of KUseg2
    -LDST to this new sate
    }
    ==== Written By Solomon G and Edwin Cervantes ==== */
/********************************************************************************************************************/




/***************Files to include****************/
#include "../h/const.h"
#include "../h/types.h"
#include "../e/page.e"
#include "../e/sys.e"
#include "../e/exceptions.e"

#include "/usr/local/include/umps2/umps/libumps.e"

/***************Files to include****************/



/***************Global Variables****************/
pteOS_t ksegOS;     /*OS page tab*/
pte_t kUseg3;       /*Segment 3, designated by SEGNO=11*/
pool_t pool[POOLSIZE];     
int next;           /*What page will we take next from the pool*/ 
trapProc_t userProcesses[MAXUSERPROC];  
int mutexSem[SEMALLOC];
int diskSem0, diskSem1, poolSem, masterSem;     /*Global semaphores*/
int getASID();
/***************Global Variables****************/


/***************Hidden Functions****************/
HIDDEN void setProc();
/***************Hidden Functions****************/

/*
Parameters: N/A
Returns: N/A
Purpose: Test for the Kaya OS
*/
void test(){
    /*Local vars*/
    int status; 
    state_t processState;
    segTabPTR segTable;

    next = 0;
        /*Used for MUTEX*/
    diskSem0 = 1;
    diskSem1 = 1;
    poolSem = 1;

        /*Used to sync*/
    masterSem = 0;

    /*Set semaphores to 1*/
    for(int i=0; i<SEMALLOC; i++){
        mutexSem[i] = 1;
    }

    /*Page table*/
    ksegOS.header = (PAGETABNUM << 24) | KSEGOSPTESIZE;
    /*Set OS pages*/
    for(int i=0; i<KSEGOSPTESIZE; i++){
        ksegOS.pteTable[i].entryHI = ((0x20000 + i) << SHIFTTWELVE);
        ksegOS.pteTable[i].entryLO = ((0x20000 + i) << SHIFTTWELVE) |DIRTYON|VALIDON|GLOBALON; 
    }

    /*Initialize the swap pool. Setting all entries to unoccupied*/
    for(int i=0; i<POOLSIZE; i++){
        clearPool(i);
    }

    /*Initialize all our processes numbered in MAXUSERPROC*/
    for (int i = 1; i < MAXUSERPROC + 1; ++i){
        userProcesses[i-1].Tp_pte.header = (PAGETABNUM << 24) | KUSEGPTESIZE;

        for(int j=0; j < KUSEGPTESIZE; j++){
            userProcesses[i-1].Tp_pte.pteTable[j].entryHI = ((0x80000 + j) << SHIFTTWELVE) | (i << SHIFTSIX);
            userProcesses[i-1].Tp_pte.pteTable[j].entryLO = ALLOFF | DIRTYON;
        }
        		/* Init last entry in the table */
		userProcesses[i-1].Tp_pte.pteTable[KUSEGPTESIZE-1].entryHI = (0xBFFFF  << SHIFTTWELVE) | (i << SHIFTSIX);
		
		/* Getting location of seg table */
		segTable = (segTabPTR ) (SEGSTART + (i * SEGWIDTH));

		/*Point to  page tab*/
		segTable->ksegOS = &ksegOS;
		segTable->kUseg2 = &(userProcesses[i-1].Tp_pte);


		/* initialization "handler" */
		processState.s_t9 = processState.s_pc = (memaddr)setProc;
		processState.s_status = ALLOFF | INTERRUPTSON | IM | TE;
        processState.s_asid = (i << SHIFTSIX);
		processState.s_sp = (TAPEBUFFSTART - (((TRAPTYPES-1) * PAGESIZE * (i-1)) + (PAGESIZE * TLBTRAP)));
		userProcesses[i-1].Tp_sem = 0;

		/*Create the process and set status. Make sure status is valid*/
		status = SYSCALL(CREATEPROCESS, (int)&processState, 0, 0);
		if(status != RECVSTATUS){
			/* process creation failed for unknown reason */
			SYSCALL(TERMINATEPROCESS,0,0,0);
		}
    }
	/* Perform sys4 on the masterSem for each process created */
	for (int i = 0; i < MAXUSERPROC; i++){
		SYSCALL(PASSEREN, (int)&masterSem, 0, 0);
	}
	
	/* Kill our test process */
	SYSCALL(TERMINATEPROCESS, 0, 0, 0);
}


 /*
Parameters: N/A
Returns: N/A
Purpose: This will initialize u-proc by calling 3 Sys 5's (as mentioned in the video), which is 
    reading in the u-proc's .text & .data from the tape.
    aka, FIGURING OUT WHO YOU ARE!
*/   
void uProcInit(){
    /* some local variables */
    int asid;
    int currentStatus;
    int pageNumeric;
    int prevStatus;
    int instruction;
    int buf;

    state_PTR *latestArea;
    state_t stateForProcess;
    device_PTR tape;
    device_PTR disk;


  
    /* find who you are */
    asid = getASID();

    /* set up a state for process */
    latestArea = setStateArea();

    /* carry on the three Sys 5 */
    for (int i = 0; i < 3; i++){
        SYSCALL(SPECTRAPVEC, i, (int)&(userProcesses[asid-1].Told_trap[i]), (int)latestArea);
    }

    /* Read contents of tape device, which is asid - 1 onto the backing store, which is disk 0 */
    tape = (device_PTR) TAPEDEV + ((asid-1) * DEVREGSIZE);
    disk = (device_PTR) DISKDEV;
    buf = BUFFER + ((asid-1) * FRAMESIZE);

    pageNumeric = 0; /* initialize page number */

    while((tape->d_data1 != 0) && (tape-> d_data1 !=1)){
        /* specify the starting physical address for read operation */
		tape->d_data0 = buf;
		
		/*  read the current block up to the next EOB/EOT marker.
            then copy it to RAM starting at data 0 addr (buffer) */
		tape->d_command = 3;
		
		/* waitingggg */
		currentStatus = SYSCALL(WAITIO, TAPENUM, asid-1, 0);
		
		/* this is to block for disk 0 */
		SYSCALL(PASSEREN, (int)&poolSem,0,0);
		
		/* now turn off interrupts */
		prevStatus = getSTATUS();
		setSTATUS(ALLOFF);
		
		/* okay, find cylinder/track */
		instruction = pageNumeric << 8 | 2;
		disk->d_command = instruction;
		
		/* waitingggg */
		currentStatus = SYSCALL(WAITIO, DISKNUM, 0, 0);
		
		/* now turn interrupts back on */
		setSTATUS(prevStatus);
		
		/* let's check status. if it isn't ready, sys2 it */
		if(currentStatus != READY)
		{
			SYSCALL(TERMINATE,0,0,0);
		}
		
		/* writing to disk */
		disk->d_data0 = buf;
		instruction = (((0 << 8) | pageNumeric) << 8) | 4;
		
		/* let's turn off interrupts */
		prevStatus = getSTATUS();
		setSTATUS(ALLOFF);
		
		disk->d_command = instruction;
		
		/* waitingggg */
		currentStatus = SYSCALL(WAITIO, DISKNUM, 0, 0);
		
		/* turn interrupts back on */
		setSTATUS(prevStatus);
		
		/* let's check status. if it isn't ready, sys2 it */
		if(currentStatus != READY)
		{
			SYSCALL(TERMINATE,0,0,0);
		}
		
		/* unblock the pool semaphore */
		SYSCALL(VERHOGEN, (int)&poolSem,0,0);
		
        /* increment pagenumber */
		pageNumeric = pageNumeric  + 1;
	}
	
	/* this is us setting up the state for the process*/
	stateForProcess.s_pc = (memaddr) PAGE52ADDRESS;
	stateForProcess.s_t9 = (memaddr) PAGE52ADDRESS;
	stateForProcess.s_sp = LASTSEG2PG;
	stateForProcess.s_asid = getENTRYHI();	
	stateForProcess.s_status = ALLOFF | TE | CURRENTVM | IM;
	
    /* load state */
	contextSwitch(&stateForProcess);

}

/*I have no clue how we begin writing this*/
 /*
Parameters: page location, page index, ASID
Returns: N/A
Purpose: Perform disk operation to write to backing store
*/   
void diskIO(){


}

 /*
Parameters: N/A
Returns: N/A
Purpose: Rturns the current ASID
*/   
int getASID(){
    int asid = getENTRYHI();
    asid = asid & BITNOTNEEDEDMASKED >> 6;
    return asid;
}

 /*
Parameters: frame number(int)
Returns: N/A
Purpose: Clean up pool frame by setting asid to -1, 0, 0 , and NULL
*/   
void clearPool(int i){
        pool[i].asid = -1;
        pool[i].segNo = 0;
        pool[i].pageNo = 0;
        pool[i].pte = NULL;
}

