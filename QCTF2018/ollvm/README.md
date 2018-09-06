# QCTF2018 ollvm
## 转载

https://blog.csdn.net/qq_33438733/article/details/81137057


脚本
==========


```python

import subprocess
import os
import logging
import json
import string

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

pwd_pin='/home/fanda/Desktop/tools/pin-3.7-97619-g0d0c92f4f-gcc-linux/pin'
inscount0='/home/fanda/Desktop/tools/pin-3.7-97619-g0d0c92f4f-gcc-linux/source/tools/MyPinTool/obj-intel64/inscount0.so'
filename='./ollvm'

class shell(object):
    def runCmd(self, cmd):
        res = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sout, serr = res.communicate()
        return res.returncode, sout, serr, res.pid

    def initPin(self, cmd):
        res = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.res = res

    def pinWrite(self, input):
        self.res.stdin.write(input)

    def pinRun(self):
        sout, serr = self.res.communicate()
        return sout, serr
cmd = pwd_pin+ " -t " + inscount0+ " -- " + filename
subprocess.Popen(cmd,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
#### brup args ascii
dic = string.letters+'_{}'+string.digits
cur=''
shell = shell()
cout_old=0
start_time = time.time()
for i in range(38):
    for s in dic:
        pwd = cur+s+'?'*(37-len(cur))
        print len(pwd)
        rcmd = cmd+' '+pwd
        shell.initPin(rcmd)
        sout,serr = shell.pinRun()
        cout = sout.split("Count ")[1]
        cout_sub= int(cout) - cout_old
        cout_old = int(cout)
        if cout_sub > 1000000 and cout_sub < 1500000 :
            cur=cur+s
        print ("current flag ", pwd,"current count:",cout,"sub_count ",cout_sub)

#QCTF{5Ym4aOEww2NcZcvUPOWKYMnPaqPywR2m}



```
