#ifndef TYPES
#define TYPES
#include "../h/const.h"

/****************************************************************************
 *
 * This header file contains utility types definitions.
 *
 ****************************************************************************/
typedef unsigned int memaddr;

typedef signed int cpu_t;


typedef struct state_t {
	unsigned int	s_asid;
	unsigned int	s_cause;
	unsigned int	s_status;
	unsigned int 	s_pc;
	int	 			s_reg[STATEREGNUM];

} state_t, *state_PTR;

typedef struct pcb_t {
/* Defines the structure of a Proccess Control Block,(pcb_t) */
 /* process queue fields */
 struct pcb_t *p_next,		/* ptr to old proc state */
				*p_prev,	/* ptr to new proc state */

 /* process tree fields */
				*p_prnt,/* ptr to parent */
				*p_child,	/* ptr to first child */
				*p_next_sib,		/* ptr to next sibling */
				*p_prev_sib; /* ptr to prev. sibling */

				/* process status information. We set these to NULL so we can check if an operation was performed in passUpOrDie()*/
			 state_t p_state; 			/* state of the processor */
			 int* p_semAdd; 		/* ptr to semaphore addr */
			 state_PTR oldSys;		/* old sys */
			 state_PTR newSys;		/* new sys */
			 state_PTR oldPgm;		/*Old program trap*/
			 state_PTR newPgm;		/*New program trap*/
			 state_PTR oldTLB;		/*Old tlb*/
			 state_PTR newTLB;		/*New tlb*/
			 cpu_t p_time;			/* start time of day */
} pcb_t, *pcb_PTR;


/* semaphore descriptor type */
typedef struct semd_t {
	struct semd_t	*s_next,	/* next semaphore addr */
					*s_prev;	/* prev. semaphore addr */
				
	int				*s_semAdd;	/* ptr to the semaphore addr */
	pcb_t			*s_procQ;	/* tail ptr to a process queue */
}semd_t, *semd_PTR;




typedef struct {
	unsigned int d_status;
	unsigned int d_command;
	unsigned int d_data0;
	unsigned int d_data1;
} device_t, *device_PTR;

typedef struct pteE_t {
	unsigned int	entryHI;
	unsigned int	entryLO;
} pteE_t;

typedef struct pteOS_t {
	int 		header;
	pteE_t	pteTable[KSEGOSPTESIZE];
} pteOS_t;

typedef struct pte_t {
	int				header;
	pteE_t		pteTable[KUSEGPTESIZE];
} pte_t;


typedef struct segTab_t {
	pteOS_t			*ksegOS;
	pte_t			*kUseg2;
	pte_t			*kUseg3;
} segTab_t, *segTabPTR;

typedef struct pool_t {
	int			asid;
	int			segNo;
	int			pageNo;
	pteE_t	    *pte;
} pool_t;

typedef struct trapProc_t {
	int			Tp_sem;
	pte_t		Tp_pte;
	int			Tp_backStoreAddr;
	state_t		Tnew_trap[TRAPTYPES];
	state_t		Told_trap[TRAPTYPES];
} trapProc_t, *trapProc_tPTR;

#define t_recv_status		d_status
#define t_recv_command		d_command
#define t_transm_status		d_data0
#define t_transm_command	d_data1

#define DEVINTNUM 5
#define DEVPERINT 8

/* device register area */
typedef struct {
	unsigned int rambase;
	unsigned int ramsize;
	unsigned int execbase;
	unsigned int execsize;
	unsigned int bootbase;
	unsigned int bootsize;
	unsigned int todhi;
	unsigned int todlo;
	unsigned int intervaltimer;
	unsigned int timescale;
	unsigned int inst_dev[DEVINTNUM];
	unsigned int interrupt_dev[DEVINTNUM];
	device_t   devreg[DEVINTNUM * DEVPERINT];
} devregarea_t, *devregarea_PTR;


#define	s_at	s_reg[0]
#define	s_v0	s_reg[1]
#define s_v1	s_reg[2]
#define s_a0	s_reg[3]
#define s_a1	s_reg[4]
#define s_a2	s_reg[5]
#define s_a3	s_reg[6]
#define s_t0	s_reg[7]
#define s_t1	s_reg[8]
#define s_t2	s_reg[9]
#define s_t3	s_reg[10]
#define s_t4	s_reg[11]
#define s_t5	s_reg[12]
#define s_t6	s_reg[13]
#define s_t7	s_reg[14]
#define s_s0	s_reg[15]
#define s_s1	s_reg[16]
#define s_s2	s_reg[17]
#define s_s3	s_reg[18]
#define s_s4	s_reg[19]
#define s_s5	s_reg[20]
#define s_s6	s_reg[21]
#define s_s7	s_reg[22]
#define s_t8	s_reg[23]
#define s_t9	s_reg[24]
#define s_gp	s_reg[25]
#define s_sp	s_reg[26]
#define s_fp	s_reg[27]
#define s_ra	s_reg[28]
#define s_HI	s_reg[29]
#define s_LO	s_reg[30]


#endif
