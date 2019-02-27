#trying threads and locks
# mostly from https://en.wikibooks.org/wiki/Python_Programming/Threading
# modifications inserted by Gary Lewandowski
# February 2019

import threading
import time
import random

counter = 0
lock = threading.Lock()
# note on locks


def process():
    global counter
    lock.acquire()
    try:
        counter+=1
    finally:
        lock.release()

class MyThread(threading.Thread):
    def run(self):
        print("{} started!\n".format(self.getName()))              # "Thread-x started!"
#        time.sleep(1)                                      # Pretend to work for a second
        for i in range(100):
            process()
        print("{} finished! counter = {}\n".format(self.getName(),counter))             # "Thread-x finished!"

def main():
    for x in range(4):                                     # Four times...
        mythread = MyThread(name = "Thread-{}".format(x + 1))  # ...Instantiate a thread and pass a unique ID to it
        mythread.start()                                   # ...Start the thread

if __name__ == '__main__':main()
