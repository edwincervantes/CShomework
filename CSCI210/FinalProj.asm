#Program to perform binary search on an array of initially unsorted list
#After list is sorted, user should be able to run repeated binary searches.
#A return of -1 means the value is not in the list
#A return of the index of the value if found.
#A 0(zero) means quit program

 #Written by EJ Cervantes
 #4DEC2018
 
.data
arr:.word 3,9,4,12,-6,11,27,314,0,550,41,-245,409,81,-2,-3,344,3455,656,437,42,9090,1224,23,34,45,56,67,78,89,21,32,43,54,65,76,87,98,90,31,121,234,231,-12,-1354,-13,-14,-15,-16,-17,-457
arrLen: .word 51
space:  .asciiz " "
newLine: .asciiz "\n"
out1: .asciiz "The sorted array is: "
out2: .asciiz "Search for an integer in this array by entering 1."
out3: .asciiz "Enter 0 to quit the program."
out4: .asciiz "Thank you for playing. Have a good day :)"
out5: .asciiz "Enter the integer you wish to search for"
out6: .asciiz "Your integer is in the array at position: "
out7: .asciiz "-1"
out8: .asciiz "Press 1 to try again or 0 to quit."

.text
.globl main

#Main prepares our registers that we will be using.
#After that then calls insertion sort to put our unordered list into ascending order
#We then print to screen the prompts to begin the game including the sorted array and instructions
main:
       la      $a0, arr                #$0 contains the arr address
       la      $t0, arrLen             #t0 contains arr len address
       lw      $t0, ($t0)	      #arrLen
       sll     $t0, $t0, 2	     
       addi    $t0, $t0, -4	
       add     $a1, $a0, $t0          # $a1 contains the last mem loc of arr
      
     
       la      $a0, arr 	     #arrrayin a0
       jal     insertionSort                    #insert
       
       la $a0,out1	     #print out1
       li $v0,4	     #print
       syscall                        # print 
        
       jal nextLine     
      
       la $a0, arr                   #$a0 contains the base address
       jal printArray
       
       jal nextLine
       
       la $a0, out2	    #a0 now has out2 and calls to print
       li $v0, 4
       syscall
       
       jal nextLine
       
       la $a0, out3	    #Print out 3
       li, $v0, 4
       syscall

#Beginning of our binary search. 
#Reads in integer 1 or 0 to determine if user would like to play again or quit
 start:      
       jal nextLine
       
       li $v0, 5                     #read integer
       syscall
       move $t1, $v0                 #Either 1 or 0 is in t1
       
       beqz $t1, equalZero           #If int == 0    
       li $t7, 1                     #Puts 1 in t7 to check if integer = 1
       beq $t1, $t7, equalOne        #If int == 1 
       
#####################
 #User wants to quit game if enters this function.
 #Outputs goodbye message and kills program
 equalZero:la $a0, out4         #Print out 4
       li $v0, 4
       syscall
       li $v0, 10                 # fin
       syscall

#If equal to one, arrLen/2
#Go to spot in arr
#Compare arr[arrLen/2]
#If less than check to left until done
#If more check to right
#If found, j equalZero
#If not found, do something so prog doesn't crash

 equalOne:la $t0, arr    #t0 now contains arr
       la $t7, arrLen             #arrLen in t7
       lw $t7, ($t7)	#lw
       mul $t6, $t6, 4	#t6 contains bit size of array
       sra $t5, $t7, 1	#t5 = arrlen/2 
       mul $t5, $t5, 4
       lw $s0, arr($t5)        #s0 = arr[arrLen/2]
          
       la $a0, out5	#out5 print
       li $v0, 4
       syscall 
    
       jal nextLine
       
       li $v0, 5           #read integer
       syscall
       move $t1, $v0          #Either 1 or 0 is in t1
       blt $t1, $s0, leftSide         # int < arr[arrLen/2
       bgt $t1, $s0, rightSide	     # int > arr[arrLen/2
       beq $t1, $s0, found
       
 leftSide:j checkL
 
 #decrement iterator	
 sub1:    addi $t5, $t5, -4	     #t5--
     bltz $t5, notFound	     #if t5 < 0 we know the element is not in the list
     j leftSide


  rightSide: j checkR
 
 #Increment iterator
  add1:    addi $t5, $t5, 4	     #t5++
      bgt $t5, $t6, notFound	     #if t5 is greater than the space allocated for the list of integers, it does not exist
      j rightSide     
  
 checkL:lw $s0, arr($t5)              #s0 = arr[arrLen/2]
     beq $t1, $s0, found	      #If int == arr[arrLen/2
j sub1

 checkR:lw $s0, arr($t5)        #s0 = arr[arrLen/2]
     beq $t1, $s0, found	#If int == arr[arrLen/2
j add1
 found:la $a0, out6         #Print out 6
     li $v0, 4
     syscall
     
     sra $t7, $t5, 2
     
     li $v0, 1
     move $a0, $t7
     syscall
       
     jal nextLine
     
     jal prompt
       
     j start
 notFound:la $a0, out7         #Print out 7
     li $v0, 4
     syscall
     
     jal nextLine
     
     jal prompt
 
     j start
 
#Creates next line to print things on   
 nextLine:la $a0, newLine                 # print new line under out1
       li $v0, 4	         #print	
       syscall	         #print
       j exit
 
 #Reminds users of the instructions after they've played the game once 
 prompt:la $a0, out8         #Print out 8
     li $v0, 4
     syscall
     
     j exit

 #Print array and loop are used to output the array after it is ordered     
 printArray:move $t0, $a0	    #prep to print

 loop: blt $a1,$t0,exit           # if t0 > a1 j exit
 
       lw $a0,($t0)	#t0 -> a0
       li $v0,1
       syscall

       la $a0, space             #print space between arr elems
       li $v0,4	#print
       syscall	#print

       addi $t0, $t0, 4          #move to next arr element
       j loop

exit:  jr $ra	#Return address
 
    
insert: lw $t1, ($a1)
        addi $t2, $a1, -4 	#Called to insert our a1 key into certain incrementing position of sorted list
        
  loop1: blt $t2, $a0, done	#Check to see if done arr[i] < arr[i+1]
        lw $t3, ($t2)	#Curr location of arr in t3
        blt $t3, $t1, done	# t3<t1
        sw $t3, 4 ($t2)	#Store value in arr[i+1] if greater than
        addi $t2, $t2, -4	#Next
        j loop1
  done: sw $t1, 4 ($t2) 	#Stores moved element into correct place in arr
        jr $ra
  
#Main algorithm of insertion sort
#Implemented by using recursion
insertionSort: beq $a0, $a1, done1                    #a0==a1
       addi $sp, $sp, -8	#Stack stuff, Prepares array for manipulation
       sw   $ra, 4 ($sp)	
       sw   $a1, ($sp)	
       addi $a1, $a1, -4	
       jal insertionSort
       lw  $a1, ($sp)	
       jal insert
       lw $ra, 4 ($sp)	#More stack stuff
       lw $a1, ($sp)
       addi $sp, $sp, 8
       
 done1:jr $ra 
 