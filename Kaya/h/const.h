#ifndef CONSTS
#define CONSTS

/****************************************************************************
 *
 * This header file contains utility constants & macro definitions.
 *
 ****************************************************************************/

/* Hardware & software constants */
#define FRAMESIZE		4096	/* page size in bytes */
#define WORDLEN			4		/* word size in bytes */
#define PTEMAGICNO		0x2A

#define STATEREGNUM	31
#define ROMPAGESTART	0x20000000	 /* ROM Reserved Page */

#define MEMAREA 0x200003D4
/* Sets number of processes avaliable at start */
#define MAXPROC 20
#define MAXINT  0xFFFFFFFF
#define SEMALLOC 49     /* number of devices using sempahores and a pseudo-time clock (only 1) */
#define SEMTIMER 50
#define PSEUDOCLOCK SEMALLOC - 1

/* old and new processor state locations */
/* SYSYCALLS */
#define SYSCALLNEWAREA 0x200003D4
#define SYSCALLOLDAREA 0X20000348

/* Program trap */
#define PRGMTRAPNEWAREA 0x200002BC
#define PRGMTRAPOLDAREA 0x20000230

/*Trap numbers*/
#define TLBTRAP 0
#define PROGTRAP 1
#define SYSTRAP	2

/* Table management */
#define TBLMGMTNEWAREA 0x200001A4
#define TBLMGMTOLDAREA 0x20000118

/* Interrupt handling */
#define INTERRUPTNEWAREA 0x2000008C
#define INTERRUPTOLDAREA 0x20000000

#define INTBIT 0x1000003C
#define INTDEV 0x10000050

/*Length of a word*/
#define LENGTHWORD 4
#define INTNOTNEEDED -1
#define EIGHT 8
#define THREE 3

/* timer, timescale, TOD-LO and other bus regs */
#define RAMBASEADDR	0x10000000
#define TODLOADDR	0x1000001C
#define INTERVALTMR	0x10000020
#define TIMESCALEADDR	0x10000024

/* Interrupts */
/* to turn on interrupts */
#define INTERRUPTSON 0x00000004 
/* to turn on interrupts that current on */
#define INTERRUPTSCON 0x00000001
/* to turn off interrupts */
#define INTERUPTSOFF 0xFFFFFFFB
/* turn on interrupt mask */
#define IM  0x0000FF00 
/* to turn on private instruction */
#define PRIVATEINSTUC 0xFF 

/* Kernel/User */
/* turn on for kernel mode */
#define KERNELMODEON 0x00000004 
/* turn off for kernel mode */
#define KERNELMODEOFF 0xFFFFFFF7
/* turn on for usermode */
#define USERMODEON 0x00000008

/* all off */
#define ALLOFF 0x00000000
#define CURRENTVM   0x01000000

/* utility constants */
#define	TRUE		1
#define	FALSE		0
#define ON              1
#define OFF             0
#define HIDDEN		static
#define EOS		'\0'
#define SUCCEEDED 0
#define FAILED -1 


#define NULL ((void *)0xFFFFFFFF)

/*Page table stuff*/
#define KUSEGPTESIZE	32
#define KSEGOSPTESIZE	64
#define MAXUSERPROC     1       /*Let's start with one User Process like Mikey recommends*/
#define POOLSIZE        3 * MAXUSERPROC
#define PAGESIZE		4096	
#define SEGSTART		0x20000500
#define SEGWIDTH		12
#define OSPAGES		KSEGOSPTESIZE

#define OSSIZE		(OSPAGES * PAGESIZE)
#define KSEGOSLAST 	(ROMPAGESTART + OSSIZE)
#define PAGETABNUM      0x2A
#define DIRTYON		0x00000400
#define VALIDON		0x00000200
#define GLOBALON	0x00000100
#define TAPEBUFF 	8
#define DISKBUFF
#define TAPEBUFFSTART	(KSEGOSLAST - (((DISKBUFF + TAPEBUFF) * PAGESIZE)))

/* vectors number and type */
#define VECTSNUM	4
#define SHIFTTWELVE 12
#define SHIFTSIX    6
#define TLBTRAP		0
#define PROGTRAP	1
#define SYSTRAP		2

#define TRAPTYPES	3

#define INTERVALTIME 100000     /* interval timer period */
#define QUANTUM 5000    /* CPU burst time */


#define TLBTWO      2
#define TLBTHREE    3


#define DEVREGLEN	4	/* device register field length in bytes & regs per dev */
#define DEVREGSIZE	16 	/* device register size in bytes */

/* device register field number for non-terminal devices */
#define STATUS		0
#define COMMAND		1
#define DATA0		2
#define DATA1		3

/* device register field number for terminal devices */
#define RECVSTATUS      0
#define RECVCOMMAND     1
#define TRANSTATUS      2
#define TRANCOMMAND     3

/* Syscall Vals */

#define CREATEPROCESS 	 1
#define TERMINATEPROCESS 2
#define VERHOGEN 		 3
#define PASSEREN 		 4
#define SPECTRAPVEC 	 5
#define GETCPUTIME 		 6
#define WAITCLOCK 		 7
#define WAITIO 			 8
#define READ_FROM_TERMINAL 9
#define WRITE_TO_TERMINAL 10
#define V_VIRTUAL_SEMAPHORE 11
#define P_VIRTUAL_SEMAPHORE 12
#define DELAY           13
#define DISK_PUT        14
#define DISK_GET        15
#define WRITE_TO_PRINTER 16
#define GET_TOD         17
#define TERMINATE       18


 /* device & line number */
#define FIRST 0x1
#define SECOND 0x2
#define THIRD 0x4
#define FOURTH 0x8
#define FIFTH 0x10
#define SIXTH 0x20
#define SEVENTH	0x40
#define EIGHTH 0x80

#define DISKCOUNT        8
#define DISKNUM			3
#define TAPENUM 		4
#define NETWORKNUM		5
#define PRINTERNUM		6
#define TERMINT		7

#define SEEK        2

#define TE  0x08000000  /* local timer on */


/* Phase 3 addr */
#define PAGE52ADDRESS 	0x8000000B
#define LASTSEG2PG 	0xC0000000
#define DEVICEREG 	0x10000050

/* For Phase 3 purpose */
#define OSEND 			(FRAMESIZE * KSEGOSPTESIZE)
#define KSEGEND 		(ROMPAGESTART + OSEND)
#define BITNOTNEEDEDMASKED 	0x00000FC0
#define BUFFER 	(KSEGEND - (DISKCOUNT * PAGESIZE))
#define TAPEDEV (((TAPENUM-3) * DEVREGSIZE * DEVPERINT) + DEVICEREG)
#define DISKDEV (((DISKNUM-3) * DEVREGSIZE * DEVPERINT) + DEVICEREG)
#define PRINTDEV (((PRINTERNUM - 3) * DEVREGSIZE * DEVPERINT) + DEVICEREG)
#define TERMINALDEV (((TERMINT-3) * DEVREGSIZE * DEVPERINT) + DEVICEREG)
 





#define PERDEV      8       /* each device has 8 sempahores */
#define DEVNOSEM    3       /* the first three devices don't have 8 sempahores */
/* device common STATUS codes */
#define UNINSTALLED	0
#define READY		1
#define BUSY		3

/* device common COMMAND codes */
#define RESET		0
#define ACK		1

/* operations */
#define	MIN(A,B)	((A) < (B) ? A : B)
#define MAX(A,B)	((A) < (B) ? B : A)
#define	ALIGNED(A)	(((unsigned)A & 0x3) == 0)

/* Useful operations */
#define STCK(T) ((T) = ((* ((cpu_t *) TODLOADDR)) / (* ((cpu_t *) TIMESCALEADDR))))
#define LDIT(T)	((* ((cpu_t *) INTERVALTMR)) = (T) * (* ((cpu_t *) TIMESCALEADDR)))


#endif
