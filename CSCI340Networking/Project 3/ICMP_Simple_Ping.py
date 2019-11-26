import subprocess
import shlex

cmd   = "ping -c 1 www.cs.xu.edu"

args = shlex.split(cmd)
try:
    subprocess.check_call(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    print ("Xavier CS web server is up!")
except subprocess.CalledProcessError:
    print ("Failed to get ping.")
