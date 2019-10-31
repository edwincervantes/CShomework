#ifndef EXCEPTIONS
#define EXCEPTIONS


#include "../h/types.h"


/***************************************************************/

extern void syscallHandler();
extern void tlbHandler();
extern void progTrapHandler();
extern void contextSwitch(state_PTR s);

/***************************************************************/
#endif
