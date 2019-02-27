#python producer consumer example
import threading
import time
import random

buffer = [None] * 100
index = -1
lock = threading.Lock()

def producer(count):
  global buffer
  global index

  index += 1
  buffer[index] = count


def consumer():
  global buffer
  global index

  while index < 0:
      continue
  value = buffer[index]
  print value
  index -= 1

class MyThread(threading.Thread):
    def run(self):
        print("{} started!\n".format(self.getName()))
        if self.getName() == "Thread-1":
            for i in range(50):
                producer(2*i)
        elif self.getName() == "Thread-3":
            for i in range(50):
                producer(2*i+1)
        else:
            for i in range(100):
                consumer()
        print("{} finished!\n".format(self.getName()))

def main():
    for x in range(3):                                     # Four times...
        mythread = MyThread(name = "Thread-{}".format(x + 1))  # ...Instantiate a thread and pass a unique ID to it
        mythread.start()                                   # ...Start the thread

if __name__ == '__main__':main()
