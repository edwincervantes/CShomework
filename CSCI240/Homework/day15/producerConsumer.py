import threading
import time
import random
counter = 0

def process():
    global counter
    counter+=1

class MyThread(threading.Thread):
    def run(self):
        print("{} started!\n".format(self.getName()))
        for i in range(5):
            process()
        print("{} finished! counter ={}\n".format(self.getName(),counter))

def main():
    for x in range(2):
        mythread = MyThread(name = "Thread-{}".format(x + 1))
        mythread.start()
if __name__ == '__main__':main()
