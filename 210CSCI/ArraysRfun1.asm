        # Program to count and display the number of times a certain target appears in the array
        # Written by EJ Cervantes
            
        .data
        .align  2
arraySize:  .word   10
values: .word   10, 42, 99, 88, 42, 54, 156, 42, 0, 666

#---------------------------------------------------

        .text
        .globl  main
        
main:   
    move    $s0, $0 	# s0: index = 0
    move    $s1, $0 	#s1: counter = 0
    
    li    $s7, 42         # li target value of 42 into s7
    lw    $s2, arraySize    #get size of array = s6
    la    $s6, values    #load array address
    
    loop:    bge $s0, $s2, done  #while (index < n)
    sll    $t0, $s0, 2  #offset array index
    lw    $t1, values($t0)  #t0 = next value in array
    addi $s0, $s0, 1  #Index++
    beq $t1, $s7, equal  #Checks if values[n] == s7
    j loop  #Repeat loop
    
    equal:    addi $s1, $s1, 1  #Counter++ iff equal
    j loop  #jump to loop
    
    done:    move $a0, $s1  #Display counter
    li $v0, 1
    syscall
    
    li $v0, 10
    syscall

    
    
        