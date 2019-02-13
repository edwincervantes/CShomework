	#Our first silly MIPS Program
	#Add up 3 values
	#Written by Edwin Cervantes
	
       .data
       .align 2
stuff: .word  42, 666, 777, 89, 14

#------------------------------------------------
       .text
       .globl main   
 main: la $s0, stuff     #add 5 words to address s0
       lw $s1, 0($s0)    #Put first value in s1
       lw $s2, 4($s0)    #Put second value in s2. Goes by 4's because it is at the word level
       lw $s3, 8($s0) #Put third value in s3
       lw $s4, 12($s0) #Put fourth value in s4
       lw $s5, 16($s0) #Put fifth value in s5
       
       sll $s1, $s1, 1 #Multiply the conents of s1 by 2 and store them back
       sll $s2, $s2, 1 #Multiply the conents of s2 by 2 and store them back
       sll $s3, $s3, 1 #Multiply the conents of s3 by 2 and store them back
       sll $s4, $s4, 1 #Multiply the conents of s4 by 2 and store them back
       sll $s5, $s5, 1 #Multiply the conents of s5 by 2 and store them back
       
       add $t0, $s1, $s2 #Add first two values together and store them in t0
       add $t1, $s3, $s4 #Add second two values together and store them in t1
       add $t0, $t0, $t1 #Add t1 to the running sum of t0
       add $t0, $t0, $s5 #Add last integer to running sum
       
       
       
       
       li $v0, 1 #Print out the program
       move $a0, $t0 #Move contents of t0 to a0 
       syscall  #Calls to system to do something
       
       li $v0, 10  #Ends progrm
       syscall     
	
