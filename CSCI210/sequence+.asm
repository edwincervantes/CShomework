#Program to add up a sequence of values
#The first value is the mumber of values to sum
#EJ Cervantes
    .data
    .align 2
count: .word 10
values: .word 42, 666, 5, 12, 77, 234, -42, 43, 65, 111

    .text
    .globl main
main:
    move $s0, $0 # s0 index = 0
    move $s1, $0 # s1 runningSum = 0
    lw $s2, count # s2: n - number of values to solve
    la $s7, values #Get array address
    
loop:
    bge $s0, $s2, done #While index<n
    sll $t0, $s0, 2 #Convert index into array offset
    lw $t1, values($t0) #t1 <- array[index]
    add $s1, $s1, $t1 #running sum += array[index]
    addi $s0, $s0, 1 #index++
    j loop
    
done:
    move $a0, $s1
    li $v0, 1
    syscall #prrint running sum
    
    li $v0, 10
    syscall
    