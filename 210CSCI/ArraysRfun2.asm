        # Program to find and display the smallest value that appears in the array
        # Written by EJ Cervantes
            
        .data
        .align  2
arraySize:  .word   10
values: .word   10, 0, 42, 99, 88, 42, 54, 156, 42, -2

#---------------------------------------------------

        .text
        .globl  main
        
main:   
    move    $s0, $0 	# s0: index = 0
    addi    $s1, $s1, 1	#s1: smallestInt = 0
    lw    $s2, arraySize  #Number of values in our array
    la    $s7, values  #get array address and load in s7
    
loop:
    bge    $s0, $s2, done  #while (index < n)
    sll    $t0, $s0, 2    #convert array index into memory offset
    lw    $t1, values($t0)  #t0 = next value in array
    addi $s0, $s0, 1  #Index++
    blt    $t1, $s1, change  # if t1 < s1 then change
    j loop  #jump to loop
    
change:
    move    $s1, $t1   #s1 now = t1
    j loop  #jump to loop
    
done:    
    move $a0, $s1  #Display lowest
    li $v0, 1
    syscall
    
    li $v0, 10
    syscall