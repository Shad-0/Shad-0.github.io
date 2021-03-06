---
title:  "Breaking the perimeter: LyncSmash & Linkedin2username"
date:   2018-07-10 15:04:23
categories: External
tags: OSINT, External, Lync, Foothold, Enumeration, Skype for business
---

In this blog I am going to cover some little known tools that have proven extremely valuable when breaching the perimeter during external engagements. I think most penetration testers will agree that in the 
majority of cases, the perimeter is rarely breached with CVE's (although one still finds the odd lone forgotten server at some obsuce subdomain). Instead of attacking the technologies at the different
endpoints, I prefer to attack the weakest link in the security chain: Humans. Wether it is through social engineering, phishing, or password attacks, humans tend to be the easiest to exploit. 

A few weeks ago I was on an external engagement against a fairly large company. Initial recogniance revealed many interesting subdomains, however most were placed behind an authenticated gateway, meaning I could
not reach them without valid domain credentials. This severely reduced my attack surface which was slightly annoying. Initially, the only two exposed servers I could access was a fairly new exchange server with no externally exploitable
vulnerabilities and a 2013 Microsoft Lync server. One possible attack here would be to come up with a list of probable usernames using the email convention from my point of contact and perform a password spray 
against the Lync server, however first i'd need a list of employees to try.

![Always a welcome sight on externals]({{ "/images/Lync/lync.png" | absolute_url }})

A few months ago, a colleague of mine released a tool called [Linkedin2username](https://gitlab.com/initstring/linkedin2username/). The tool is a scraper that will take in a company name, and login 
parameters. It will then log into LinkedIn and do a search for all employees of said company, which it then saves locally. Finally, it will grab the first and last name and compose a  list of probable usernames 
using common email conventions such as firstname.lastname, lastname.f, firstname.l and so on. This is incredibly useful when used in conjuction with username enumeration flaws, as it provides a very 
comprehensive list of posible usernames we can then attack.

I ran the tool against the company which identified roughly 700 users. Awesome! Although there were bound to be some invalid or old names in there, I figured most would be valid, and felt pretty good
about my chances of finding a user with Password1, Winter2018 or something of the sort. Rather than attempting all different conventions (over 2000 usernames), I decided to use the convention from emails found
during recon. 

The last piece needed for my attack was the name of the domain the users belonged to. By default, many directories in both Exchange and Lync are protected using NTLM over http. Due to the way NTLM authentication works,
Sending a  Type 1 message with null data results in a response which leaks internal server data, such as product numbers and domain information. I wrote a small script to extract this information which can be found [here](https://github.com/Shad-0/Tools) 

![NTLMSSP data extracted from /ews/ in my lab]({{ "/images/Lync/nmap2.png" | absolute_url }})

Great! now that we have a list of plausible usernames and the name of the domain they are likely to authenticate to. We now need a way to differentiate valid from invalid usernames which we can then attack.
This is where Lyncsmash comes in. [LyncSmash](https://github.com/nyxgeek/lyncsmash), developed by nyxgeek, is a tool for attacking self hosted Microsoft Lync installations. If you'd like to read the details 
behind how it works I strongly suggest you read [this](https://www.trustedsec.com/2017/08/attacking-self-hosted-skype-businessmicrosoft-lync-installations/) blog post.
Self hosted Lync installations suffer from multiple information disclosure flaws. First, many folders are protected with NTLM over http authentication, allowing us to obtain domain information. 
the second flaw is a username enumeration flaw. Like Exchange, attempting to login with a valid username will return a response much quicker than an invalid username. 
The second flaw was reported to Microsoft, who do not aknowledge it as a vulnerability, meaning it is likely never going to be patched.

I used the list produced by LinkedIn2username, and sprayed two passwords across all accounts. If the password lockout threshold of the target is not known, I strongly recommend keeping the spray at 1/2 passwords
per day. Otherwise you risk locking out valid accounts, which will not only be extremely, noisy but can also have a significant business impact for the target. You've been warned.

Invalid usernames with the incorrect credentials will produce the following output:

![No succesfull logins here!]({{ "/images/Lync/invalid.png" | absolute_url }})

Where as a correct login will produce the following result:

![And we score!!]({{ "/images/Lync/valid.png" | absolute_url }})

Booya! valid creds! I let the script continue and ended up with 4 valid accounts. Great, now to log in to the portal....

![So close but yet so far...]({{ "/images/Lync/modded.png" | absolute_url }})

After logging I was greeted with a lovely 2FA input field asking me for a Google authenticator token. hmmm. Game over? Not yet! Remember that exchange server that was exposed?
I took my credentials there and what do you know, no 2FA! All of the accounts enumerated were a goldmine. One belonged to someone in a manager type role, who appeared to get automated emails every time
a new employee was hired. In those emails were details about the employees start date, instructions to set up their Google 2FA aaand...

![Yep...temporary plaintext credentials]({{ "/images/Lync/email.png" | absolute_url }})

I picked a few accounts that had not started yet and therefore were not set up and proceeded to hijack their 2FA set up. I was succesfull in registering my device, and was able to use a few of the newly 
hijacked accounts to access the companies intranet and external resources. From here it was simply a matter of more enumeration until I was able to VPN into their internal network. Game over.

I hope the above post highlights the power of these two tools when used together, and how dangerous a simple information disclosure flaw can be to an organization under the right conditions.

Thanks for reading! 

   



