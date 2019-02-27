	lw $s0, n 
	addi $t0,$s0,-1 			#t0 = n-1
	li $t1, 0 				# i = 0
	li $s3, 0 				# j = 0
	la $s1, B 				#s1 = address a[0]	
	la $s2, B 				#s2 = address a[0]
	la $s3, B 				#s2 = address a[0]
LapSort:					# for ( int i=0;i<n-1;i++)
	beq $t0,$t1,PRINT 			# i > n-1 => goto KTLap1
	addi $t2,$t1,0				# t2 = min,
	la $s1, B 				# s1 = address array
	la $s2, B				# s2 = address array
	mul $t3,$t2,4				# t3 = min * 4
	add $s2,$s2,$t3				# get index address arr[min]
	mul $t3,$t1,4				# t3 = i * 4
	add $s1,$s1,$t3				# get index address arr[i]
	addi $t4,$t1,0				# t4 = j;j= i
	addi $t4,$t4,1				# j = j + 1
LapSort2:					# for ( int j=i+1;j<n;i++)		
	beq $s0,$t4,Swap			# j > n => Exit		
	la $s3, B 				# s3 = address array
	lw $s5,($s2)				# s5 = arr[min]
	mul $t5,$t4,4				# temp5 = j * 4
	add $s3,$s3,$t5				# get index address arr[j]
	lw $s6, ($s3)				# s6 = arr[j]
	ble $s5,$s6,Continue			# arr[min] <= arr[j] goto continue
	addi $t2,$t4,0				# min = j
	#la $s2, B				# s2 = address array	
	#add $s2,$s2,$t5			# get index address arr[j]
	add $s2,$s3,$0				# index min = index j
Continue:
	addi $t4,$t4,1				# j++
	j LapSort2
Swap:
	beq $t2,$t1,Continue2			# min != i goto Continue2
	lw $s5,($s2)				# s5 = arr[min]
	lw $t7,($s1)				# t7 = arr[i]		
	sw $t7,($s2)				# arr[min] = t7
	sw $s5, ($s1)				# arr[i] = s5
Continue2:
	addi $t1,$t1,1				# i++
	j LapSort