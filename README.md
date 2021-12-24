# pktIntel
## Tool used to perform threat intelligence against packet data

	- Author: Nik Alleyne
	- Author Blog: www.securitynik.com

Author Books: 

	- Hack and Detect - Leveraging the Cyber Kill Chain for Practical 
	- Mastering TShark Network Forensics - Moving From Zero to Hero



All configuration information found in the **pktIntel.conf** file

File: **checkTshark.py**

- This script is used to check if TShark is running. If TShark is not running, this script can be used to setup continuous monitoring for packets. 
- This script has been updated as of December 24, 2021 to now accommodate other capturing tools.
---------------------------------------------------
Found the following capturing tools
Please select a number for a capturing tool
--------------------------------------------------
1 : Found tshark -> True -> /usr/bin/tshark 
2 : Found tcpdump -> True -> /usr/bin/tcpdump 
3 : Found dumpcap -> True -> /usr/bin/dumpcap 

[*] Please select a number: 


File: **pktintel.py** 

- To work effectively, you must have PCAP files available. If you do not currently have any, execute **checkTshark.py** and it will take care of that for you.

Currently, the script is **not** configured to send the TShark process to the background, if you wish to send it to the background, make the following changes:

**FROM:**
	sp.call(['tshark', '--interface', 'any', '-w', pcap_dir + 'securitynik.pcap', '--ring-buffer', '--files:100', '--ring-buffer', 'filesize:100000', '--color', '--print'], stderr=sp.PIPE)


**TO:**
	sp.call(['tshark', '--interface', 'any', '-w', pcap_dir + 'securitynik.pcap', '--ring-buffer', '--files:100', '--ring-buffer', 'filesize:100000', '--color', '--print', **'&'**], stderr=sp.PIPE)

	- NOTE THE "&" AFTER THE "--print" argument sends the TShark process to the background.


# Commands
## --ip 
- Does IP threat Intelligence. 
- This is a very effective mechanism. Focuses solely on IP field. 
- More specifically, we look for traffic where the TCP Syn flag is set. the hope is we are looking for traffic in which the client is about to start communication.

## --domain
- Does domain name threat intelligence.
- Still very effective. However, with DNS over HTTPS and DNS over TLS, this may become less effective over time.
- Focuses on the DNS query name.
- Also focuses on TLS client Hello Handshake record, extracting the Server Name Indication value (SNI)


## --url
- Does URL threat intelligence against the packet data
- Most effective for HTTP traffic or decrypted HTTPS traffic.
- With the world moving to more and more encryption, this is the least effective of the 3. 
- There are ways to decrypt the traffic so all is not lost 


Here is the YouTube link to a video showing how the tool is used:


[![Video Showing How To Use The Tool](https://img.youtube.com/vi/ikhKUylOJCw/0.jpg)](https://www.youtube.com/watch?v=ikhKUylOJCw)

https://www.youtube.com/watch?v=ikhKUylOJCw

Have Fun
<br>Nik Alleyne</br>
www.securitynik.com
