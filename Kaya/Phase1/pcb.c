/* h files to include */
#include "../h/const.h"
#include "../h/types.h"
/* e files to include */
#include "../e/pcb.e"
#include "../e/asl.e"



/*
---------------Allocation and Deallocation of pcb_t-------------------
*/

void freePcb (pcb_PTR p)
{

}

pcb_PTR allocPcb()
{

}

void initPcbs()
{
  static pcb_t procTable[MAXPROC];

  pcbList_h = mkEmptyProcQ;

  for(int  i = 0; i < MAXPROC; i++){
    freePcb (&(procTable[i]));
  }
}


/*
---------------Process Queue Maintenance of pcb_t-------------------
*/

/* Initialize the tp of an empty process queue, which would return null. */
pcb_PTR mkEmptyProcQ()
{
    return NULL;
}
/* This is a boolean expression in which if tp points to an empty queue process, return null */
int emptyProcQ(pcb_PTR tp)
{
    return (tp == NULL);
}

/* Insert the pcb_t pointed to by p into the process queue tp */
insertProcQ(pcb_PTR *tp, pcb_PTR p)
{
    /* Base case - if the queue is empty, then assign pbc_t's next and previous element to be itself. */
    if emptyProcQ(*tp)
    {
        p->p_next = p;
        p->p_prev = p;
    } else
    {
        /* If the queue has more than 1 or more elements, re-assign the new element to point to the next one.
        Re-arrange the pointers to the point to the new added element. */
        p->p_next = (*tp)->p_next;
        (*tp)->p_next = p;

    }
}
/* Removes the first element from the process queue in which tp is passed in. */
pcb_PTR removeProcQ(pcb_PTR *tp)
{
    pcb_PTR temp = NULL; /*Intialize temp to be NULL */

    /* Returns null if the list is empty */
    if(emptyProcQ(*tp))
    {
        return NULL;
    /* If the process queue has one element, then pointers are re-assigned.
    The value pointing to the next pcb_t will be itself*/
    } else if ((*tp)->p_next == (*tp))
    {
        /* Since tp is the only element, we can get the value and return it.
        Now since it's removed, we have to do a function call to the mkEmptyProcQ()
        to assign the next pointer to be NULL. */
        temp = (*tp);
        (*tp) = mkEmptyProcQ();
        return temp;
    }

        /* If the process queue has more than one element, first get the head of the list. */
        temp = (*tp)->p_next;
        /* Re-assign tp pointing to the next's next element */
        (*tp)->p_next->p_next->p_prev = (*tp);
        /* Re-assign tp be the the next element */
        (*tp)->p_next = ((*tp)->p_next->p_next);
        /* Return the head */
        return temp;
}

pcb_PTR outProcQ(pcb_PTR *tp, pcb_PTR p)
{
    pcb_PTR temp = NULL;
    if(emptyProcQ(*tp))
    {
        return NULL;
    } else if ((*tp)->p_next == (*tp))
    {
        temp = (*tp);
        (*tp) - mkEmptyProcQ();
        return temp;
    } /* More cases on this one */


}

/*Returns a pointer to the head from the process queue
whose tail is pointed to by tp. This head should not be removed.
If there is no process queue, return NULL. */
pcb_PTR headProcQ(pcb_PTR tp)
{
    return (tp->p_next);
}
