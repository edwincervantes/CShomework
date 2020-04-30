/*********************************************** sys.c*******************************************************/
/********************************************************************************************************************/
/*  

This is how we will implement syscalls 9-18.
First enter our userSyscallHandler() to figure out what syscall was called.
Then we are directed to the syscall we must perform.


    ==== Written By Solomon G and Edwin Cervantes ==== */
/********************************************************************************************************************/

/***************Files to include****************/
#include "../h/const.h"
#include "../h/types.h"
#include "../e/initProc.e"
#include "../e/exceptions.e"

#include "/usr/local/include/umps2/umps/libumps.e"
/***************Files to include****************/


/***************Hidden Functions****************/
HIDDEN void sysCall9();
HIDDEN void sysCall10();
HIDDEN void sysCall11();
HIDDEN void sysCall12();
HIDDEN void sysCall13();
HIDDEN void sysCall14();
HIDDEN void sysCall15();
HIDDEN void sysCall16();
HIDDEN void sysCall17();
HIDDEN void sysCall18();
/***************Hidden Functions****************/

 /*
Parameters: N/A
Returns: N/A
Purpose: We need to try to figure out what the syscall is. This will then direct us to the corect syscall
*/   
void userSyscallHandler() {
	state_PTR caller;
	int sysReq;
	unsigned int asid = getASID();      /* get ASID */
	caller = getCaller(asid, SYSTRAP);      /*Caller*/
	

	sysReq = caller -> s_a0;    /*Sys number is stored in a0*/
	switch(sysReq) {
		
		case(READ_FROM_TERMINAL):
			syscall9();
		break;  

        case(WRITE_TO_TERMINAL):
            sysCall10();
        break;

        case(V_VIRTUAL_SEMAPHORE):
            sysCall11();
        break;

        case(P_VIRTUAL_SEMAPHORE):
            sysCall12();
        break;

        case(DELAY):
            sysCall13();
        break;

        case(DISK_PUT):
            sysCall14();
        break;

        case(DISK_GET):
            sysCall15();
        break;

        case(WRITE_TO_PRINTER):
            sysCall16();
        break;

        case(GET_TOD):
            sysCall17;
        break;

        case(TERMINATE):
            sysCall18;
        break;

        default:
            sysCall18();
        break;
    }
    return 0;
}

/*
READ FROM TERMINAL
When requested, this
service causes the requesting U-proc to be suspended until a line of input (string
of characters) has been transmitted from the terminal device associated with the
U-proc
*/
HIDDEN void sysCall9(){
	sysCall18();
}


/*
WRITE TO TERMINAL
When requested, this service causes the requesting U-proc to be suspended until
a line of output (string of characters) has been transmitted to the terminal device
associated with the U-proc.
*/
HIDDEN void sysCall10(){
    /*local vars*/
	int i;
	int command;
	int status;
	int oldStatus;
    state_PTR caller;
    int asid;
	
	device_t* terminal;
	
	int span = (int) caller->s_a2;
	char *getString = (char *) caller->s_a1;
	
	/* get the device register for the terminal we will write to */
	terminal = (device_t*) TERMINALDEV + ((asid-1) * DEVREGSIZE);
	
	/* it is an error to write to a terminal device from an address in ksegOS, request a SYS10 with a length
	   less than 0, or a length greater than 128. Any of these errors result in a terminate. */
	if(span < 0 || span > 128 || getString <= (char*) OSEND) {
		
		terminate();
		
	}

	/* for each character give the transmit command to the terminal */
	for (i = 0; i < span; i++){
		
		command = (getString[i] << 8) | 2; /* page 47 yellow */
		
		oldStatus = getSTATUS(); /*t urn off interrupts */
		setSTATUS(ALLOFF);
		
		terminal->t_transm_command = command;
		status = SYSCALL (WAITIO, TERMINT, asid-1, 0);
		
		setSTATUS(oldStatus);
		
		/* if terminal status is not 5 (character transmitted), negate for v0 */
		if((status &  0x0F) != 5)
		{
			i = i * -1; 
		}
	}
	
	caller->s_v0 = i;
	loadState(caller);
}


/*
V VIRTUAL SEMAPHORE
When this service is requested, it is interpreted by the nucleus as a request to
perform a V operation on a semaphore.
*/
HIDDEN void sysCall11(){
	sysCall18();
}


/*
P VIRTUAL SEMAPHORE
When this service is requested, it is interpreted by the nucleus as a request to
perform a P operation on a semaphore.
*/
HIDDEN void sysCall12(){
	sysCall18();
}


/*
DELAY
This service causes the executing U-proc to be delayed for n seconds. The re-
questing U-proc is to be delayed at least n seconds and not substantially longer.
*/
HIDDEN void sysCall13(){
	sysCall18();
}


/*
DISK PUT
provide synchronous I/O on the μMPS2 disk devices.
*/
HIDDEN void sysCall14(){
	sysCall18();
}


/*
DISK GET
provide synchronous I/O on the μMPS2 disk devices.
*/
HIDDEN void sysCall15(){
	sysCall18();
}


/*
WRITE TO PRINTER
When requested, this service causes the requesting U-proc to be suspended until
a line of output (string of characters) has been transmitted to the printer device
associated with the U-proc.
*/
HIDDEN void sysCall16(){
    int i;
    int devStatus;
    int asid;
    state_PTR caller;

    device_PTR devPrinter;

    int span = (int) caller->s_a2;
    char *getString = (char *) caller->s_a1;

    /*  grab the device register for the printer */
    devPrinter = (device_PTR) PRINTDEV + ((asid-1) * DEVREGSIZE);

    /*  if there is an error to write to a printer device from an address in ksegOS,
        request a SYS10 with a length less than 0, or a length greater than 128.
        Any of these errors result in a terminate.*/
	if(span < 0 || span > 128 || getString <= (char*) OSEND) {
		
		sysCall18();
		
	}

	/*  here, for each character, let's give the transmit command to the terminal */
	for (i = 0; i < span; i++){
		
		/* give command and load character into data0 */
		devPrinter->d_data0 = getString[i];
		devPrinter->d_command = 2;	
		
		devStatus = SYSCALL (WAITIO, 6, asid-1, 0); /*wait*/
		
		/* if device status is not 1 (ready) */
		if(devStatus != READY)
		{
			i = i * -1; 
		}
	}
	
	caller->s_v0 = i;
	loadState(caller);
	
}


/*
GET TOD
When this service is requested, it causes the number of microseconds since the
system was last booted/reset to be placed/returned in the U-proc’s v0.
*/
HIDDEN void sysCall17(){
	state_PTR caller;
	cpu_t time;
	
	int asid =  getASID();      /* determine which uProc is requestor. get ASID */	
	caller = getCaller(asid, SYSTRAP);      /*Let's find our caller*/
	STCK(time);     /*Store clock*/
	
	/*Store time in v0, and context switch */
	caller -> s_v0 = time;
	contextSwitch(caller);
}


/*
TERMINATE
This services causes the executing U-proc to cease to exist.
*/
HIDDEN void sysCall18(){
    state_PTR caller;
	
	int asid =  getASID();      /* determine which uProc is requestor. get ASID */	
	caller = getCaller(asid, SYSTRAP);      /*Let's find our caller*/
	SYSCALL(PASSEREN, (int)&poolSem, 0, 0);    	/*Take control of swap pool */


	/* check all pages and clear them out */
	for(int i=0;i<POOLSIZE;++i){
		if(pool[i].asid == asid){
			clearPool(i);
		}
	}

	SYSCALL(VERHOGEN, (int)&poolSem, 0, 0);        /*Release control of the pool */
	SYSCALL(VERHOGEN, (int)&masterSem, 0, 0);  	
	SYSCALL(TERMINATEPROCESS, 0, 0, 0);         /*Kill it*/
}

state_PTR getCaller(unsigned int ASID, int trapType) {
	state_PTR u = (&((userProcesses[ASID-1]).Told_trap[trapType]));
    return u;
}



