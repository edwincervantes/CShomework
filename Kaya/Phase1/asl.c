/******************************************************************************************************************************

                              ~ASL.c~
              Written By Solomon G and Edwin Cervantes

ASL.c implements a semaphore list, which will be seen as an integer value and will keep addresses
of Semaphore descriptors, semd_t. Like pcb.c, asl will have an asl free list with MAXPROC free semd_t.
The active list is implemneted and stored as a singly linked list (stack) that has two dummy nodes (min addr of 0)
and max (addr the maximum largest unsigned integer value).

*******************************************************************************************************************************/

/* h files to include */
#include "../h/types.h"
#include "../h/const.h"
#include "../e/initial.e"
/* e files to include */
#include "../e/pcb.e"

/* ---------------------------------------------------------------- */ 
/*------------------- Some Global Definitions ---------------------*/

/* Pointer to the head free list of semd_t */
HIDDEN semd_PTR semdFree_h;

/* Pointer to the head of the active list, semd_t. */
HIDDEN semd_PTR semdASL_h;


HIDDEN void freeSemd(semd_PTR s);
HIDDEN semd_PTR allocSemd();
HIDDEN semd_PTR searchSemAdd(int *semAdd);
/* -------------------------------------------------------- */ 
/*------------------- Helper function ---------------------*/
semd_PTR washDishesAsl(semd_PTR s){

    /* if null, return null */
    if (s == NULL){
        return NULL;
    } else {
        /* clean all the values of semd_t to be used again */
        s->s_next = NULL;
        s->s_procQ = mkEmptyProcQ();
        s->s_semAdd = NULL;
        return s;
    }
} /* End of washDishesAsl */


/* This function takes a semd_t and points it into the semd_t free list.
if there is nothing on the list, a newly free list is created. */
HIDDEN void freeSemd(semd_PTR s){
    /* Check to see if the free list is empty. But first, clean
    the node */
    /* washDishesAsl(s); */
    if (semdFree_h == NULL){
        /* a free list is created */
        semdFree_h = s;
        /* Once the newly element is added, it has no next semd_t */
        semdFree_h->s_next = NULL;
    } else{
        /* If the semd_t free list is not empty, s's
        next field equal to the head of the semd_t free list */
        s->s_next = semdFree_h;
        /* Assign the next semd_t to be the head */
        semdFree_h = s;
    }
} /* End of freeSemd */

/* This function allocates a semd_t from the semd_t free list
and returns a pointer to it. */
HIDDEN semd_PTR allocSemd(){
    semd_PTR free = semdFree_h;
    /* If the free list head is null, return null */
    if (semdFree_h == NULL){
        return NULL;
    }
    /* adjust the pointer */
    semdFree_h = semdFree_h->s_next;
    free = washDishesAsl(free);
    return free;
}

/* Initialize the semdFree list to contain all the elements of the arraystaticsemdt
semdTable[MAXPROC]This method will be only called once during data structure
initializa-tion. */
void initASL(){
    semd_PTR lastDummyNode;
    HIDDEN semd_t semdTable[MAXPROC + 2];
    int i;
    semdFree_h = NULL;
    semdASL_h = NULL;

    /* Inserting MAXPROC nodes into the free list */
    for (i=0; i < MAXPROC; i++){
        freeSemd(&(semdTable[i]));
    }

    /* intialize the active list with two dummy nodes */
    lastDummyNode = &(semdTable[MAXPROC + 1]);

    /* clean the node */
    lastDummyNode->s_next = NULL;
    lastDummyNode->s_procQ = mkEmptyProcQ();
    
    /* last dummy node, its addr set to 0xFFFFFFFF */
    lastDummyNode -> s_semAdd = (int*) MAXINT;

    /* maxproc's next is the last dummy node in active
    semd_t list */
    (semdTable[MAXPROC]).s_next = lastDummyNode;


    /*assign the other node to be the first dummy node */
    semdASL_h = &(semdTable[MAXPROC]);  
    semdASL_h -> s_procQ = mkEmptyProcQ();
    
    /* first dummy node, its addr set to 0 */
    semdASL_h-> s_semAdd = 0;

} /* End of initASL */


/* This function go through the semiphore active list for a specified
semd_t addressed which is passed in as an argument to the fucntion below. */
HIDDEN semd_PTR searchSemAdd(int *semAdd){
    /* Get the head of the list */
    semd_PTR temp = semdASL_h;

    /* If the semaphore address is null, set the
	address to be the MAXINT so the loop may iterate
	correctly and does not return null */
    if (semAdd == NULL){
        semAdd = (int*) MAXINT;
    }

    /* while the semdAsl_h address is less than the
	specified integer address - the first node will be skipped since
    it's dummy */
    while (semAdd > (temp->s_next->s_semAdd)){
            /* assign to the next value
		    in the linked list - as done above */
            temp=temp->s_next;
    }

    /* return the found semd_t */
    return temp;
} /* End of searchSemAdd */

/* Insert the ProcBlk pointed to by p at the tail of the process queue
associated with the semaphore whose physical address is semAdd
and set the semaphore address of p to semAdd. If the semaphore is
currently not active (i.e. there is no descriptor for it in the ASL), allo-
cate a new descriptor from the semdFree list, insert it in the ASL (at
the appropriate position), initialize all of the fields (i.e. set s semAdd
to semAdd, and s procq to mkEmptyProcQ()), and proceed as
above. If a new semaphore descriptor needs to be allocated and the
semdFree list is empty, return TRUE. In all other cases return FALSE.
*/
int insertBlocked (int *semAdd, pcb_PTR p){
    semd_PTR temp, allSemd;
    /* Let's find the closest semd_t using its location */
    temp = searchSemAdd(semAdd);
    /* Case one: Semaphore is currently active and we insert the ProcBlk*/
    /* Once we have received the location, we check to see if 
    it matches the description */
    if ((temp->s_next->s_semAdd) == semAdd){
        /* If the located semd_t matches the semaphore addr */
        p -> p_semAdd = semAdd;
        /* Once found, insert the pcb_t into the process queue */
        insertProcQ(&(temp -> s_next -> s_procQ), p);
        /* return false to indicate the semd_t matched the semaphore
        addr and it is not blocked */
        return FALSE;
    }
        /* if the semd_t address doesn match the address, semAdd,
        one - it's possible that the semd_t free list is empty
        two - there's a free semd_t in the free list */
        allSemd = allocSemd();

        /* If there no more free semd_t on the free list, that's bad */
        if (allSemd == NULL){
            return TRUE;
        }

        /* insert ned node into the ASL_h list */
        allSemd->s_next = temp->s_next;
        temp->s_next = allSemd;
        allSemd->s_semAdd = semAdd;
        allSemd->s_procQ = mkEmptyProcQ();

        /* insert newly added pcb_t process queue
        into the process queue */
        p->p_semAdd = semAdd;
        insertProcQ(&(allSemd->s_procQ), p);
       
        /* new semd_t is allocated at this point */
        return FALSE;
} /* End of insertBlocked */

/* Search the ASL for a descriptor of this semaphore.
If none is found, return NULL; otherwise, remove thefirst (i.e. head)
ProcBlkfrom the process queue of the found semaphore descriptor and re-turn a pointer to it.
If the process queue for this semaphore becomesempty (emptyProcQ(sprocq)is TRUE),
remove the semaphoredescriptor from the ASL and return it to the semdFree list. */
pcb_PTR removeBlocked (int *semAdd){
    /* Intializing pointers */
    pcb_PTR getHeadPcb;
    semd_PTR temp, getHeadSemd;
    /* find semd_t */
    temp = searchSemAdd(semAdd);



    /* if address has been found */
    if(temp->s_next->s_semAdd == semAdd){
        getHeadPcb = removeProcQ(&(temp->s_next->s_procQ));

        /* Check if the pcb_t process queue is empty.
        If it is, free it */
        if (emptyProcQ(temp->s_next->s_procQ)){
            getHeadSemd = temp->s_next;
            temp->s_next = getHeadSemd->s_next;
            freeSemd(getHeadSemd);
        }
        /* return head */
        return getHeadPcb;
    }
    /* else return null */
    return NULL;
} /* End of removeBlocked */

/* Remove the ProcBlk pointed to by p from the process queue associated with
p’s semaphore (p→psemAdd) on the ASL. If ProcBlkpointed to by p does not appear
in the process queue associated withp’s semaphore, which is an error condition,
return NULL; otherwise,return p. */
pcb_PTR outBlocked (pcb_PTR p){
    semd_PTR temp, outSemd;
    pcb_PTR outPcb;
    /* Get the location of the semaphore */
    temp = searchSemAdd(p->p_semAdd);
    if((temp != NULL) && ((temp->s_next->s_semAdd) == (p->p_semAdd))){

        outPcb = outProcQ(&(temp->s_next->s_procQ), p);
        /* Condition to check if the newly removed pcb_t is allowing the
		semd_t to be free - if so, re allocate to the
		free list of semd_t */
        if (emptyProcQ(temp->s_next->s_procQ)){
            /* Since it's free now, allocate. */
            outSemd = temp->s_next;
            temp->s_next = temp->s_next->s_next;
            /* free the unused semd_t */
            freeSemd(outSemd);
        }
        /* return outPcb */
        return outPcb;
    }
    return NULL;
} /* End of outBlocked */




/*  a pointer to the ProcBlk that is at the head of the pro-
cess queue associated with the semaphore semAdd. Return NULL
if semAdd is not found on the ASL or if the process queue associ-
ated with semAdd is empty. */
pcb_PTR headBlocked (int *semAdd){
    semd_PTR temp;
    /* search for the semaphore by using the semaphore address*/
    temp = searchSemAdd(semAdd);

    /* if there's a match */
    if(temp ->s_next->s_semAdd == semAdd){
        return headProcQ(temp->s_next->s_procQ);
    }
    /* return null otherwise */
    return NULL;
} /* End of headBlocked */

/* ------------------------------------------------- END OF ASLs.c ------------------------------------------------- */
/* --------------------------------------------------------------------------------------------------------------- */ 





