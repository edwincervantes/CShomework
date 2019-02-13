#Program to perform selection sort on a given array
#Written by EJ Cervantes

.data
.align 2
valueCount:
    .word 5
values:
    .word 2,4,3,5,1
    
#________________________________________________________________________#

.text
.globl main

main:
    move $s0, $0                         #s0: index = 0
    move $s4, $0                         #s4: n = 0
    move $s3, $0                         #Address for min
    addi $s1, $s1, 999                   #Smallest int
    lw $s2, valueCount                   #Count of values
    la $s7, values                       #Array stored at s7
    j loop1
    move $s0, $0                        #Restore i to 0
    j printList
loop1:
    j findMin

loop2:
    j swap
    addi $s4, $s4, 1                   #n++
    j findMin

findMin:
    bge $s0, $s2, loop2                 #while(index<n)
    sll $t0, $s0, 2                     #Convert array index into memory offset
    lw $t1, values($t0)                 #values[i] in t1
    la $t2, values($t0)
    addi $s0, $s0, 1                    #index++
    blt $t1, $s1, change                #Change min

change:
    move $s1, $t1                       #s1 is new min
    move $s3, $t2                       #s3 has address of new min
    j findMin
    
swap:
    lw $s5, values($s4)                 #Load whatever is in values s4 into s5
    lw $s6, values($s3)                 #New min is in s6
    sw $s5, values($s3)                 #Swap
    sw $s6, values($s4)                 #""
    

printList:
    bge $s0, $s2, fin                #while(index<n)   
    lw $a0, values($s0)              #Move values[] to a0
    addi $s0, $s0, 1                 #i++
    li $v0, 1                        
    syscall
    
    j printList
    
fin:
    li $v0, 10
    syscall
    
    
    
    
    
    
    
    
    
    