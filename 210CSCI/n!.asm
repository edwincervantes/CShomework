#Program written to find the factorial of a given number by user input
#Written by EJ Cervantes

.data



intPrompt:
    .asciiz "\Please enter an integer to get the factorial\n"    #Ask user input
    
intResult:
    .ascii "\nThe factorial is: "
    
num: 
    .word 0
 
answer:
    .word 0

#--------------- Usual stuff at beginning of main -----------------
        .text
       .globl main
main: 
    li $v0, 4         #Make room for int in v0
    la $a0, intPrompt #Store variable in a0
    syscall

    li $v0, 5         #add int to v0
    syscall           

    sw $v0, num       #move value from v0 to int word
        
    
    lw $a0, num       #Calls and retrives num
    jal factorial     #Find factorial
    sw $v0, answer    #result of factorial is stored here
    
    
    li $v0, 4
    la $a0, intResult    #Displays result message
    syscall
    
    
    li $v0, 1        #actual integer value answer
    lw $a0, answer
    syscall
    
    li $v0, 10
    syscall
    #----------------------------------------------------------------#
    
factorial:
    subu $sp, $sp, 8     #Creats space in stack for two values
    sw $ra, ($sp)        #Store returning address to stack
    sw $s0, 4($sp)       #Store local var to stack
    
    li $v0, 1            #Return value of one
    beq $a0, 0, done     #If factorial is equal to 0 go to done to restore stack
    
    move $s0, $a0        #Copy contents a0 to s0
    addi $a0, $a0, -1    #Next number in factorial
    jal factorial        #Recursion call
    
    mul $v0, $s0, $v0    #Multiply each int that is then popped off the stack
  
done:
    lw $ra, ($sp)        #Return address from stack   
    lw $s0, 4($sp)       #Local variable moved to register from stack
    addu $sp, $sp, 8   #Add back to stack to restore
    
    jr $ra               #Return from function
    
     
    
    