#A program used to compute Ackermann's function
#Written by EJ Cervantes

#A(m,n) = n+1 if m=0
#A(m,n) = A(m-1,1) if m>0 and n=0
#A(m.n) = A(m-1,A(m,n-1,1)) if m>0 and n>0

.data

intPromptM:
    .asciiz "\Enter the m value of Ackermann: "       #Asks for user input
     
intPromptN: 
    .asciiz "\Enter the n value of Ackermann: "     #Asks for user input
    
    
    
#______________________________________________________________________________________________#

.text
.globl main

main:
    li $v0, 51
    la $a0, intPromptM          #m is stored in a0  
    syscall
    
    move $s0, $a0               #store m in s0
    
    li $v0, 51
    la $a0, intPromptN          #n stored in 10 
    syscall
    
    move $a1, $a0               #Move n to a1
    move $a0, $s0               #Move m back to a0
    
    jal startAck
    
    move $a0, $v0               #Result stored in a0
    li $v0, 1           
    syscall
    
    li $v0, 10                  #Kill
    syscall
startAck:
    addi $sp, $sp, -12          #Create room in stack for 2 vars

    sw $ra, 0($sp)              #Add ra to stack
    sw $s6, 4($sp)              #Add s6 to stack
    sw $s7, 8($sp)              #add s7 to stack

    move $s6, $a0               #m in s6
    move $s7, $a1               #n in a7
    j startAck2

startAck2:
    beqz $s6, ack0              #Branch if m = 0
    bgtz $s6, ackG              #Branch if m > 0
    
ack0:
    addi $v0, $s7, 1            # n + 1
    j doneAck  
    
ackG:
    beqz $s7, ackG0            #Branch if m > 0 and n = 0
    bgtz $s7, ackGG            #Branch if m > 0 and n > 0
    
ackG0:
    addi $s6, $s6, -1          #m - 1 and store back
    li $s7, 1                  #n = 1
    j startAck2
    


ackGG:
    move $s3,$s6              #Make a copy of m in s3
    addi $s7, $s7, -1         #n - 1
    jal startAck2             
    move $s7,$v0              #A(m, n-1) m is in a0
    addi $s3,$s7,-1           # new m = m-1
    jal startAck2    
    
doneAck:
    lw $s6, 8($sp)       #Restore
    lw $s7, 4($sp)       #""
    lw $ra, 0($sp)       #""
    add $sp,$sp,12       #Refill stack
    jr $ra               #return ra  
                     
     
    
    
    
    
    
    
