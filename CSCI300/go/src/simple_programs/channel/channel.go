package main

import "fmt"

//Function: Used to print Happy Birthday messgae
//Parameters: channel(string)
//Returns: N/A
func happyBirdthday( name chan string) {

		fmt.Println("Happy Birthday " + <-name + "!!!!!!")

}

func main(){

	c := make(chan string) //Create Channel

	go happyBirdthday(c) //Start goroutine and pass channel c

	c <- "EJ"

	close(c)

	fmt.Println("TYFYS")

}
