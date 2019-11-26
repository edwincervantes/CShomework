/*
Go program used to find largest number in an array iterrating through it.
Arrays must be predetermined (size, type)
Print largest at the end.
*/

package main

import "fmt"

func main(){

var number[10]int
number[0] = 1
number[1] = 5
number[2] = 3
number[3] = 486
number[4] = 234
number[5] = 356
number[6] = 45
number[7] = 8
number[8] = 42
number[9] = 65

var a int = number[0]

for i:=0; i <=9; i++{
	if (a < number[i]){
		a = number[i]
	}
}
fmt.Printf("%#v\n", a)
}

