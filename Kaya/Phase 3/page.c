
/*********************************************** page.c *******************************************************/
/********************************************************************************************************************/
/*  

TLB Handler
-Who am I?
    -The current processID is in the ASID registed
    -This is needed as the index into phase 2 global struct
-Why are we here?
    -Examine to oldMem cause Reg. What TLB trap happened?
-If TLB invalid (missing page on load or store) continue, otherwise nuke it
-Which page is missing?
    -oldmem ASID register had segment # and page #
-Acquire MUTEX on swappool data struct(sys4)
    -If missing page from KUSEG3, check if the page is still missing
        -Check the KUseg3 page table entries valid bit
            -If on, it is no longer missing:
                release MUTEX and return control to process (LDST oldMem)
    Pick a frame to use
    If frame is currently occupied:
        -Turn the valid bit off in the page table of current frame's occupant
        -Deal with TLB cache consistency
        -Write current frames contents to disk on backing store
    Read missing page into selected frame
    Update swapPool data structure
    Update missing page's page table entry:frame number and valid bit
    Deal with TLB cache consistency

Release MUTEX and return control to process(LDST)

    ==== Written By Solomon G and Edwin Cervantes ==== */
/********************************************************************************************************************/


/***************Files to include****************/
#include "../h/const.h"
#include "../h/types.h"
#include "../e/initProc.e"
#include "../e/sys.e"
#include "../e/exceptions.e"

#include "/usr/local/include/umps2/umps/libumps.e"
/***************Files to include****************/

/***************Hidden Functions****************/

HIDDEN unsigned int getFrame();

/***************Hidden Functions****************/

/*
Parameters: N/A
Returns: N/A
Purpose: Handle faults
*/   
void TLBhandler(){
    state_PTR procInQuestion;
    int asid, procID, pageNum, frameNum, status, causeNum, segmentNum, pageIndex, pageMiss, pageLoc;
    devregarea_PTR device = (devregarea_PTR) RAMBASEADDR;

    asid = getASID();

    procInQuestion = getCaller(asid, TLBTRAP);      /*Finding out who we are*/

    SYSCALL(PASSEREN, (int) &poolSem, 0, 0);    /*Gain MUTEX over pool semaphore*/

    causeNum =(procInQuestion -> s_cause & 0xFC) >> 2;      /*Why are we here?*/

    pageLoc = (device -> rambase) + (device -> ramsize);    /*Calculate our RAMTOP*/
	pageLoc = pageLoc - (PAGESIZE * 3);/* start of user frame*/

    segmentNum = procInQuestion -> s_asid >> 30;    /*What is the segment number*/

    pageMiss = (procInQuestion -> s_asid & 0x3FFFF000) >> 12;       /*What page are we missing*/

    pageIndex = pageMiss;

    /*Check TLB valid bit, Kill it if so*/
    if(causeNum != TLBTWO && causeNum != TLBTHREE){
        SYSCALL(TERMINATEPROCESS, 0, 0, 0);
    }

    frameNum = getFrame();      /*Get the frame number*/
    pageLoc = pageLoc - (frameNum * PAGESIZE);      /*Witchcraft*/

    if(pageMiss >= KUSEGPTESIZE){       /*Check if missing*/
        pageIndex = KUSEGPTESIZE - 1;   
    }

    if(pool[frameNum].asid != -1){      /*Check if occupied*/
        status = getSTATUS();
        setSTATUS(ALLOFF);      /*Turning off interrupts*/

        procID = pool[frameNum].asid;       /*Get ID of proc*/
        pageNum = pool[frameNum].pageNo;     /*Get page #*/

        pool[frameNum].pte -> entryLO = DIRTYON | ALLOFF;   /*Change proc*/
        
        /*Clean up time*/
        clearPool(frameNum);

        TLBCLR();       

        setSTATUS(status);      /*Turn on interrupts*/

        diskIO();        /*Write to backing store. Not sure how but we need to pass on page location, index and ASID obviously*/

    }
    /*Update process page table*/
    pool[frameNum].asid = asid;
    pool[frameNum].pageNo = pageMiss;
    pool[frameNum].segNo = segmentNum;
    pool[frameNum].pte = NULL;      /*This is not supposed to be NULL just not sure what to update to*/
    pool[frameNum].pte -> entryLO = VALIDON | DIRTYON;

    TLBCLR();

    SYSCALL(VERHOGEN, (int) &poolSem, 0, 0);    /*Release MUTEX*/

    contextSwitch(procInQuestion);      /*Return control*/


}

/*
Parameters: N/A
Returns: N/A
Purpose: Goes through frames one by one. Once get to the last frame, reset
*/   
HIDDEN int getFrame(){
    int frame;
    frame = 0;
    frame = frame++;
    if(frame >= POOLSIZE){
        frame = 0;
    }
    return(frame);
}











