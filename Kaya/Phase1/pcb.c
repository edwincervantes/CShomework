/********************************************************************************************************************************

                              ~PCB.c~
              Written By Solomon G and Edwin Cervantes

PCB.c is a system of controlling process control blocks in a queue manager.
There are four basic ProcBlk related functions.
-The Allocation and Deallocation of ProcBlk
-The Maintenance of queues of ProcBlks
-The Maintenance of a single stored list of active demaphore descriptors
each of which supports a queue of ProcBlks



*********************************************************************************************************************************/

/* h files to include */
#include "../h/const.h"
#include "../h/types.h"
/* e files to include */
#include "../e/pcb.e"
#include "../e/asl.e"

/* ---------------------------------------------------------------- */
/*------------------- Some Global Definitions ---------------------*/
HIDDEN pcb_PTR pcbList_h; /* the pcb_t free list of size 20 */

/* -------------------------------------------------------- */
/*------------------- Helper function ---------------------*/
pcb_PTR washPcbDishes(pcb_PTR p)
{

  /* clean previous and next fields */
  p->p_next = NULL;
  p->p_prev = NULL;

  /* clean tree relationships */
  p->p_prnt = NULL;
  p->p_child = NULL;
  p->p_next_sib = NULL;
  p->p_prev_sib = NULL;

  /* clean semaphore */
  p->p_semAdd = NULL;
  /*Time is 0 to start*/
  p->p_time = 0;

  /*Clean states*/
  p->oldPgm = NULL;
  p->oldSys = NULL;
  p->oldTLB = NULL;
  p->newPgm = NULL;
  p->newSys = NULL;
  p->newTLB = NULL;

  return p;
}

pcb_PTR washChild(pcb_PTR p)
{
  /* clean all the childs */
  p->p_prev_sib = NULL;
  p->p_next_sib = NULL;
  p->p_prnt = NULL;
  return p;
}
/* ----------------------------------------------------------------------- */
/*--------------- Allocation and Deallocation of pcb_t ------------------- */

/* Insert the element pointed to by p onto
the pcbFree List which is pcbList_h */
void freePcb(pcb_PTR p)
{
  /* easily call insertProcQ */
  pcb_PTR temp = washPcbDishes(p);
  p = temp;
  insertProcQ(&(pcbList_h), p);
} /* End of freePcb */

/* Return NULL if the pcbFree list is empty.
Otherwise, removean element from the pcbFree list,
provide initial values for ALLof the ProcBlk’sfields
(i.e. NULL and/or 0) and then return apointer to the removed element.
ProcBlk’s get reused, so it isimportant that no previous value persist
in a ProcBlk when itgets reallocated. */
pcb_PTR allocPcb()
{
  pcb_PTR temp = removeProcQ(&(pcbList_h));
  if (temp != NULL)
  {
    temp = washPcbDishes(temp);
  }
  return temp;
} /* End of allocPcb */

/* Initialize the pcbFree list to contain all the elements of thestatic
array of MAXPROC ProcBlk’s. This method will be calledonly once during
data structure initialization. */
void initPcbs()
{
  HIDDEN pcb_t procTable[MAXPROC];
  int i;
  /* Intializing pcbList_h to be NULL */
  pcbList_h = mkEmptyProcQ();
  

  /* Insert  MAXPROC nodes onto pcbList_h */
  for (i = 0; i < MAXPROC; i++)
  {
    freePcb(&(procTable[i]));
  }
} /* End of initPcbs */

/* ---------------------------------------------------------------------- */
/* --------------- Process Queue Maintenance of pcb_t ------------------- */

/* Initialize the tp of an empty process queue,
which would return null. */
pcb_PTR mkEmptyProcQ()
{
  return NULL;
}

/* This is a boolean expression. If
tp points to an empty process queue, return null */
int emptyProcQ(pcb_PTR tp)
{

  return (tp == NULL);
} /* End of emptyProcQ */

/* Insert the pcb_t pointed to by p into the process queue tp */
void insertProcQ(pcb_PTR *tp, pcb_PTR p)
{
  /* Base case - if the queue is empty, then assign
    pbc_t's next and previous element to be itself. */
  if (emptyProcQ((*tp)))
  {
    (*tp) = p;
    p->p_next = p;
    p->p_prev = p;
    /* If the queue has 1 or more elements, re-assign the new element to point to the next one.
      Re-arrange the pointers to the point to the new added element. */
  }
  else
  {

    /* Assign the new node's next addr to be the tail pointer's next addr */
    p->p_next = (*tp)->p_next;
    (*tp)->p_next->p_prev = p;
    /* Now, the tail ptr's next addr will be the new node's addr */
    (*tp)->p_next = p;
    /* The new node previous addr should be the tail ptr's old addr */
    p->p_prev = (*tp);
  }
  /* Set the tail pointer to the new node */
  (*tp) = p;
} /* End of insertProcQ */

/* Removes the first element from the process queue in which tp is passed in. */
pcb_PTR removeProcQ(pcb_PTR *tp)
{

  pcb_PTR temp; /*Intiaylize variable temp */

  /* Case1: Returns null if the list is empty */
  if (emptyProcQ(*tp))
  {
    return NULL;
    /* Case2: If the process queue has one element, then pointers are re-assigned.
    The value pointing to the next pcb_t will be itself*/
  }
  else if ((*tp)->p_next == (*tp))
  {
    /* Since tp is the only element, we can get the value and return it.
        Now since it's removed, we have to do a function call to the mkEmptyProcQ()
        to assign the next pointer to be NULL. */
    temp = (*tp);
    (*tp) = mkEmptyProcQ();

    return temp;
  }
  /* Case3: If the process queue has more than one element, first get the head of the list. */
  temp = (*tp)->p_next;
  /* Re-assign tp pointing to the next's next element */
  (*tp)->p_next->p_next->p_prev = (*tp);
  (*tp)->p_next = ((*tp)->p_next->p_next);
  /* Return the head */

  return temp;
} /* End of removeProcQ */

/* Remove the ProcBlk pointed to by p from the process queue whose
tail-pointer is pointed to by tp. Update the process queue’s tail
pointer if necessary. If the desired entry is not in the indicated queue
(an error condition), return NULL; otherwise, return p. Note that p
can point to any element of the process queue. */
pcb_PTR outProcQ(pcb_PTR *tp, pcb_PTR p)
{
  pcb_PTR temp1, midVal;
  /* Case1 (Empty): there is no process queue, simply return null */
  if (emptyProcQ(*tp) || emptyProcQ(p)){
    return NULL;
  }
  if ((*tp) == p){
    if ((*tp)->p_next == (*tp)){
      /* We are seacrhing for the tp and it is
					      the last pcb_t on the list. */
      temp1 = (*tp);
      (*tp) = mkEmptyProcQ();
      /* tail pointer */
      return temp1;
      /* We are looking for the tp but there are pcb_t left in the list. */
    } else {
      /* allocate ptrs accordingly */
      (*tp)->p_next->p_prev = (*tp)->p_prev;
      (*tp)->p_prev->p_next = (*tp)->p_next;
      (*tp) = (*tp)->p_prev;
    }
    return p;
  } else {
    /* start at p_next */
    midVal = (*tp)->p_next;
    while (midVal != (*tp)){
      if (midVal == p) {
        /* Re-arrange the ptrs of the neighbors before
        and after the element we just found and removed.
        Thus, they can point to each other */
        temp1 = midVal;
        temp1->p_prev->p_next = midVal->p_next;
        temp1->p_next->p_prev = midVal->p_prev;
        temp1->p_next = NULL;
        temp1->p_prev = NULL;
        return temp1;
      }
      midVal = midVal->p_next;
    }
    return NULL;
  }
}

/*Returns a pointer to the head from the process queue
whose tail is pointed to by tp. This head should not be removed.
If there is no process queue, return NULL. */
pcb_PTR headProcQ(pcb_PTR tp)
{
  if (tp == NULL){
    return NULL;
  }
  if ((tp->p_next) == tp){
    return tp;
  }
  return (tp->p_next);
} /* End of headProcQ */

/*
---------------Process Tree Maintenance of pcb_t-------------------
*/

/* A boolean expression returning true if pcb_t has a child. Otherwise, return false. */
int emptyChild(pcb_PTR p)
{
  return (p->p_child == NULL);
} /* End of emptyChild */

/* If the inserted pcb_t is the one and only child, then we should set its sibilings to be NULL
Every child points to its parent so we don't get rid of prnt pointer */
void insertChild(pcb_PTR prnt, pcb_PTR p)
{
  if (emptyChild(prnt))
  {
    prnt->p_child = p;
    p->p_prnt = prnt;
    p->p_prev_sib = NULL;
    p->p_next_sib = NULL;
    /* If there's more than one chid, we have to re-arrange the ptrs accordingly */
  }
  else
  {
    prnt->p_child->p_prev_sib = p;
    p->p_prev_sib = NULL;
    p->p_next_sib = prnt->p_child;
    prnt->p_child = p;
    p->p_prnt = prnt;
  }
} /* End of insertChild */

/* Make the first child of the ProcBlk pointed to by p no longer a
child of p. Return NULL if initially there were no children of p.
Otherwise, return a pointer to this removed first child ProcBlk. */
pcb_PTR removeChild(pcb_PTR p)
{
  pcb_PTR temp;
  /* First case: P had no offspring so we return NULL */
  if (emptyChild(p))
  {
    return NULL;
  }
  /* Second case: P only has one child. Check p_child for p_next_sib */
  temp = (p->p_child);
  if ((p->p_child->p_next_sib) == NULL)
  {

    p->p_child = NULL;
    temp->p_prnt = NULL;
    temp->p_next_sib = NULL;
    temp->p_prev_sib = NULL;
    return temp;
  }
  /* Third case: P has more than 1 child.  Check p_child for p_next_sib */
  else
  {
    /* Now, make the p_child pointer to point to the next_sibling of the first child */
    p->p_child = p->p_child->p_next_sib;
    p->p_child->p_prev_sib = NULL;
    temp->p_prnt = NULL;
    temp->p_next_sib = NULL;
    temp->p_prev_sib = NULL;
    return temp;
  }
} /* End of removeChild */

/* Make the ProcBlk pointed to by p no longer the child of its parent.
If the ProcBlk pointed to by p has no parent, return NULL; otherwise,
return p. Note that the element pointed to by p need not be the first
child of its parent. */
pcb_PTR outChild(pcb_PTR p)
{
  /* First case: if p has not parent or is NULL return NULL */
  if ((p == NULL) || (p->p_prnt == NULL))
  {
    return NULL;
  }
  /* Second case: If removing first child */
  if ((p->p_prnt->p_child) == p)
  {
    return removeChild(p -> p_prnt); /*P_PRNT*/
  }
  /* Third case: P is at the end of the child List */
  if ((p->p_next_sib) == NULL)
  {
    p->p_prev_sib->p_next_sib = NULL; 
    return p;
  }
  /* Fourth case: P is a middle child */
  if (((p->p_prev_sib) != NULL) && ((p->p_next_sib != NULL)))
  {
    p->p_next_sib->p_prev_sib = p->p_prev_sib;
    p->p_prev_sib->p_next_sib = p->p_next_sib;

    return p;
  }

  return NULL;
} /* End of outChild */

/* ------------------------------------------------- END OF PCB.c ------------------------------------------------- */
/* --------------------------------------------------------------------------------------------------------------- */
