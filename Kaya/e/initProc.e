#ifndef INITPROC_E
#define INITPROC_E

#include "../h/types.h"
#include "../h/const.h"


extern int diskSem0, diskSem1, poolSem, masterSem;
extern trapProc_t userProcesses[MAXUSERPROC]; 
extern pool_t pool[POOLSIZE]; 

extern unsigned int getENTRYHI(void);
extern unsigned int getASID();
extern void diskIO();
extern void clearPool(int i);


#endif

