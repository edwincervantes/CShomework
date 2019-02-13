#Program written to find the fibonacci sequence of the given user input
#F(n) = F(n-2) + F(n-1)
#Written by EJ Cervantes

.data

intPrompt:
    .asciiz "\Enter an integer n to find Fibonacci(n)\n"       #Asks for user input
     
intResult: 
    .ascii "\n The Fibonacci number is: "
    
num:
    .word 0
    
answer:
    .word 0
 #________________________________________________________________________________________________#
 
 .text
 .globl main
 
 main:
     li $v0, 4               #Make room for n in v0
     la $a0, intPrompt       #Store n in a0
     syscall
     
     li $v0, 5               #add n to v0
     syscall
     
     move $t1, $v0       # n-> t1
     move $a0, $t1       #n -> a0
     move $v0, $t1       #n -> v0
     jal fibSequence     
     move $s1, $v0       #Final answer in s1
     
     li $v0, 4
     la $a0, intResult       #Displays result message
     syscall
     
     li $v0, 1        #Actual integer value answer and print
     move $a0, $s1
     syscall
     
     li $v0, 10         #Call program to end
     syscall
#___________________________________________________________________________#


 fibSequence:
     beqz $a0,ifZero           #Base case if a0 = 0
     beq $a0,1,ifOne           #Base case if a0 = 1
     addi $sp, $sp, -4       #Creates space in stack for 1 value
     sw $ra, 0($sp)          #Store ra on stack
     addi $a0, $a0, -1       #n-1
     jal fibSequence
     
     add $a0, $a0, 1         #n+1
     lw $ra, 0($sp)          #filling in ra from the stack
     add $sp, $sp, 4         #Restore stack
     
     addi $sp,$sp,-4         #Push return value to stack
     sw $v0,0($sp)           #Calling fib(n-2)
     sub $sp,$sp,4           #storing return address on stack
     sw $ra,0($sp)           #Store ra on stack

     addi $a0,$a0,-2         #n-2
     jal fibSequence         #fib(n-2)
     add $a0,$a0,2           #n+2

     lw $ra,0($sp)           #restoring return address from stack
     add $sp,$sp,4           #Restore stack

     lw $s2,0($sp)           #Pop return value from stack
     add $sp,$sp,4           #Resotre stack

     add $v0,$v0,$s2         #f(n - 2)+fib(n-1)
     jr $ra                  #decrement/next in stack
        
     
 ifZero:
     li $v0, 0
     jr $ra                  #Returns 0
 
 ifOne:
     li $v0, 1
     jr $ra                  #Returns 1
     
     
 
