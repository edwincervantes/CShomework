#Lets declare strings and assign them to global vars
global m: string;
global n: string;
global o: int;

event bro_init()
	{
	m = "We are leaving in less than:";
	n = "seconds.";
	o = 5;
	print "Hello, World!";
	}

event bro_done()
	{
	print m;
	print o;
	print n;
	}
