/*Below is an example of selection sort taking a set of numbers ordered originally from largest to smallest, to smallest to largest*/
package main
 
import (
    "fmt"
)

func main(){
	var Arr = []int {9,9,8,7,6,5,4,3,2,1}		/*Arr is an array of integers of size 10*/
	fmt.Println("\n The list unsorted: \n\n", Arr )		/*Print statement*/
	selectionSort(Arr,10)		/*Do the thing*/
	fmt.Println("\n The list sorted: \n\n", Arr, "\n" )	/*Print statement*/
}

func selectionSort(arr []int, size int){		/*We must pass in the array and size*/
	for i := 0; i < size; i++{
		var min = i
		for j := i; j < size; j++{
			if arr[j] < arr[i]{
				min = j			/*Iterate through whole array and find the min*/
			}		
		}
		arr[i], arr[min] = arr[min], arr[i]	/*Min in arr takes place of [i]*/
	}
}


