# Vulnerability and Attack Description

We find a design flaw in the Ring Security System. It can be exploited by a local area network attacker to stealthily delay or intercept commands and events of Ring security system. Many other IoT devices share this design flaw. We have documented the discovered vulnerability and our exploitation method in a research paper, which has been submitted to  IEEE S&P symposium, so please keep it confidential until the paper is published. We write this report for an ethical and responsible disclosure.

**Vulnerability Description.** For network communication, message delays that are caused by packet transmission are inevitable. Normally, such delays are sub-seconds and would not cause issues. However, we observe that in the Ring Security System, attackers can maliciously extend this delay for up to 60 seconds without causing any alarm, and some delayed messages are discarded by the system. None of the malicious actions are reported in any form of alerts or notifications. Based on this delay attack, attackers can stealthily delay intrusion alerts and invalidate smart home routines on Alexa that are triggered by Ring events. Moreover, we find that the Ring security system does not check the order of actions and commands and allows a delayed command that is issued earlier to override a latter action, which results in an unexpected final state.

**How to** **launch such attacks.** To launch this attack, attackers need to hijack the TCP connection between the Ring hub and cloud server. This can be easily achieved via the mature arp spoofing attack (surprisingly, this old attack is still effective against the newest Ring hub), which only requires the attacker has access to the same LAN as the Ring hub. Scenarios for launching this attack is very common:

1. When a Ring hub is used in shared WiFi networks (e.g., customers in a hotel, students in an university, and employees in a company connect their Ring security system to the shared WiFi network for smart automation applications), there could be thousands of smart devices connected to the same LAN, which can be fooled by the reported attack.
2. For home deployments, the victim's home WiFi password could be leaked by malicious mobile apps (e.g., [some WiFi finder apps](https://securityboulevard.com/2019/04/popular-wifi-finder-app-leaks-2-million-passwords/)) or when the victim inadvertently shares the password with guests or neighbors. With the leaked password, attackers can join and access the victim's home LAN using their own devices.
3. For remote attackers, they can utilize compromised devices or malicious web scripts to access the victim's home LAN (e.g., *[Web-based Attacks to Discover and Control Local IoT Devices](https://www.esat.kuleuven.be/cosic/publications/article-3079.pdf)*).
4. Attackers that have access to the ISP facilities (e.g., the user's broadband cable and the ISP's router) can hijack Ring's connection more easily. Even Ring's session with the cloud is encrypted and is mixed with many other sessions in the same household, it is not difficult to recognize it by listening to the DNS lookup.

**Possible exploitations.**  Once the connection between the hub and the cloud is redirected to flow through the attacker-controlled device/process, the attackers can leverage the delay as an attack primitive to launch three types of attacks.

1. **Alert-Delay Attack.** A user of Ring security system wants to be notified of critical state updates as soon as possible. With the default setting of the Ring security system, users can receive immediate alerts of unexpected entry on their mobile phone or other smart home devices (e.g., Alexa Echo speakers) when the system is armed and then the contact sensors are opened . Users can also manually enable notifications for all contact sensor open events. We find these event messages can be delayed for up to 64 seconds before sending to the cloud server and this neither causes the hub and cloud server to drop the connection nor triggers a device offline alarm. As a result, critical events such as burglary and smoke could have tens of seconds delay to be noticed by users, which significantly undermines the effect of early warning.
2. **Routine-Invalidate Attack.** The Ring security system can be integrated into Amazon's Alexa platform to trigger the execution of Alexa routines. We observe that Ring events will no longer be able to trigger the execution of routines if they are delayed for longer than 30 seconds, which means that the routines are invalidated. Same as the Alert-Delay attack, this routine runtime anomaly is neither reported by Ring nor Alexa. As it is common for users to automate other appliances with Ring sensors, this vulnerability allows attackers to induce hazardous situations (e.g., prevent the heater from being turned off after users leaving) by invalidating certain routines with delays.
3. **Action-Reorder Attack.** The Ring security system can be switched between armed/disarmed modes via either commands from the cloud (i.e., using Ring mobile app or Alexa) or manual operations on the keypad. We find that a former mode switch command can override a latter manual operation if the command is delayed to be after the manual operation. E.g., when the Ring security system is first commanded to disarm and then manually set to armed, attackers can maliciously delay the arm command to cause the system's final state to be disarmed.

**Impact of exploitations**. Compared to conventional jamming and Denial of Service (DoS) attacks (e.g., discarding packets), this attack is much more severe for two reasons:

1. Attackers can keep stealthy during the attack by causing no hub offline alerts. During the delay, attackers can fool both the hub and the cloud to believe that the connection between them is still healthy by acknowledging TCP segments. This means that victims are not aware of the attack even after some hazards happen (e.g., door opens, intruders get in) .
2. Attackers have full control of whether a delayed message can be accepted by the Ring cloud or not. They can either delay them longer for the Routine-Invalidate attacks or use shorter delay for the action-reorder attack. While jamming and DoS attackers can only wait for the event to be retransmitted because the delayed event messages are discarded at the time of session breaking.

**In summary**, the lack of appropriate handling of delays of Ring security system messages brings attackers the convenience to craft inconsistencies between devices' states in the real world and on the cloud. This delay can be further exploited to invalidate Alexa routines. We follow this approach to build a prototype attacking tool, whose principle is illustrated in the graph below. 

![https://lucid.app/publicSegments/view/f15dea13-a5fe-4b5c-9e5c-3e283f46a3cc/image.png](https://lucid.app/publicSegments/view/f15dea13-a5fe-4b5c-9e5c-3e283f46a3cc/image.png)

**The procedure of event message delay attack could be described as the following 5 steps:**

1. We hijack the connection between the Ring hub's connection via arp spoofing. More specifically, we periodically send fake arp response messages from an attacking host to the hub and the home router claiming the other end's IP address is associated with the attacking host's MAC address. In this way, whatever the hub communicates with the cloud server will flow through the attacking host.
2. We add iptables rules on the attacking host, which redirect all packets between the hub and the cloud server to a local port to be accessed by a user-space program.
3. On the attacking computer, we run a program that listens to the redirection port for any TCP connecting request. When the hub launches a TCP connection to the cloud server  (the original connection should have already been interrupted at step 1, but the hub will try to reconnect), it will be accepted by our program. After accepting the connection, our program retrieves the request's original destination IP address (i.e., the Ring cloud server) and launches a new connection to the cloud. In this way, the original direction TCP connection between the hub and the cloud is broken into two independent connections. The TCP/IP stack on the attacking host can automatically maintain both connections. 
4. On the attacking computer, we establish two queues to accommodate TCP segments' payloads received from two TCP connections respectively. At the same time, there are another two threads that running continuously to fetch segment payloads from queues and send them to their original destination. Until this step, we build a transparent proxy on the attacking host that forwards messages between the hub and the cloud.
5. In our program, we start another thread that checks segments' lengths (since the content has been encrypted) before putting them into the queue.  Since certain types of events usually have a fixed length, the program can accurately localize the segment that contains the message that we are interested in. Whenever it sees the target segment, it suspends the sending threads for a configurable time, which intentionally extends delay. After the end of the delay period, the suspended sending thread resumes working to send out all segments that are cached in the queue. 

In the rest of this report, we will describe the detailed procedures to reproduce the message delay and attacks based on it. 

# Reproducing Steps

Here we describe the procedures to reproduce the **Alert-Delay Attack** in a real-world testbed.

[Devices used for reproducing the State-Update Delay Attack](https://www.notion.so/c92c597309c54774bb1281f2f4175b53)

We reproduce the vulnerability using a minimal Ring security system deployment that includes a Ring hub, a keypad, and a contact sensor. The sensor and the keypad are paired with the base station and the base station is connected to the WiFi router. We also link the Ring account to our Amazon account that the echo speaker is registered on. 

### Hub TCP Session Hijacking

After the hub establishing the connection with the Ring cloud server, we can launch arp spoofing by sending forged arp responses to them. More specifically, for the hub, we claim the home router's IP address is at our Laptop's MAC address. For the router, we claim the laptop's MAC address is associated with the hub's IP address. In this way, traffic between them will be redirected to our Laptop. Then, we follow the doc of [mitmproxy](https://docs.mitmproxy.org/stable/howto-transparent/)  to further forward the redirected packets to a local port using these steps.

Enable IP forwarding

```bash
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
```

Disable ICMP redirects

```bash
sysctl -w net.ipv4.conf.all.send_redirects=0
```

Insert iptables rules

```bash
iptables -t nat -A PREROUTING -p tcp --src <Ring hub IP> -m multiport --dports 1:65535  -j REDIRECT --to-port $listenPort
iptables -t nat -A PREROUTING -p tcp --dst <Ring hub IP> -m multiport --dports 1:65535  -j REDIRECT --to-port $listenPort 
```

We automate the arp spoofing and packet redirection with a python script in `<project_root>/spoof/spoof.py`.  To use it, you need first go to the folder and install the required python packages specified in the `requirement.txt`. After that, edit the file of `delay.conf` by replacing the interface name with yours (i.e., the interface name printed by the`ifconfig`command) and hub/device IP address in your testbed.

```scheme
[common]
interface = eth0   #attacking host network interface name
hub = 192.168.1.1 #home router IP address
device = 192.168.1.23 #Ring hub IP address
port = 10000    #proxy listening port
```

 Then, run the script with sudo privilege and leave it running.

```bash
$ sudo -E python3 spoof.py
```

The script will prompt the sending of each arp response like this

```jsx
[+] Sent to 192.168.1.23 : 192.168.1.1 is-at 00:1c:42:3a:65:dc
[+] Sent to 192.168.1.1 : 192.168.1.23 is-at 00:1c:42:3a:65:dc
[+] Sent to 192.168.1.23 : 192.168.1.1 is-at 00:1c:42:3a:65:dc
[+] Sent to 192.168.1.1 : 192.168.1.23 is-at 00:1c:42:3a:65:dc
[+] Sent to 192.168.1.23 : 192.168.1.1 is-at 00:1c:42:3a:65:dc
[+] Sent to 192.168.1.1 : 192.168.1.23 is-at 00:1c:42:3a:65:dc
[+] Sent to 192.168.1.23 : 192.168.1.1 is-at 00:1c:42:3a:65:dc
[+] Sent to 192.168.1.1 : 192.168.1.23 is-at 00:1c:42:3a:65:dc
[+] Sent to 192.168.1.23 : 192.168.1.1 is-at 00:1c:42:3a:65:dc
```

After the redirection of packets, we run our proxy program that listens to the redirection port. On receiving any TCP connection requests, it accepts them and retrieves the original destination IP address. Then, it launches a new connection to the original destination IP address (i.e., the Ring cloud). As a result, an original TCP session is broken into two independent ones. For any session between the hub and the cloud, we spawn 4 threads to handle the write and read of each TCP connection. Messages received from one side are put into a queue, which is popped and sent out by the writing thread of the other side. By checking the content in the queue, we can inspect every received message.

The proxy program is located in `<project_root>/proxy/passthrough.py`. You can run it by specifying the redirection port. By default, the port is 10000. Please make sure the port is not occupied by other programs and matches the configuration in `<project_root>/spoof/delay.conf`.

```scheme
.$ python3 proxy.py -p 10000 
# -p is used to specify the redirection port, 
# need to match the set value in 'delay.conf'
```

Then, the program will automatically prompt the length and time of received packets.

```jsx
attacker@demo:~/... .../proxy$ python3 passthrough.py 
07/08/2021 09:26:10 PM | TLS record of [28, 52] bytes to ('192.168.1.23', 46328)
07/08/2021 09:26:39 PM | TLS record of [28] bytes to ('3.238.77.118', 443)
07/08/2021 09:26:39 PM | TLS record of [48] bytes to ('3.238.77.118', 443)
07/08/2021 09:26:39 PM | TLS record of [28, 52] bytes to ('192.168.1.23', 46328)
07/08/2021 09:27:08 PM | TLS record of [28] bytes to ('3.238.77.118', 443)
07/08/2021 09:27:08 PM | TLS record of [48] bytes to ('3.238.77.118', 443)
07/08/2021 09:27:08 PM | TLS record of [28, 52] bytes to ('192.168.1.23', 46328)
```

### **Alert-Delay Attack**

Messages of the Ring security hub can be easily recognized by their lengths. The hub exchanges keep-alive messages with the cloud server in **30** seconds period. In each exchange, the hub sends two TLS records with the lengths of **28** and **48** bytes to the cloud, and the cloud reply with two records of **28** and **52** bytes. When sending events to the cloud, the hub always starts with two consecutive TLS records of 28 and 504 bytes. 

 We inspect every packet that is received from the hub. If it has the matching length, we let the thread that is writing to the cloud sleep for a period. In this way, the target event is only sent out after the sleeping, which means a delay of message arrival. Since we maintain separate TCP connections with the hub and the server, all received TCP segments will be acknowledged automatically to prevent the TCP timeout and none of the order of TCP segments order will be violated. As a result, the TCP connection is maintained and would not break during the delay of messages. 

According to our experiment, the Ring hub drops the connection at 5 seconds after two failed (i.e., delayed) keep-alive attempts. Depends on when the delay starts in a keep-alive period, the stealthy delay has an interval ranging from 35 seconds to 65 seconds. Before the end of the delay, users' smartphone will not receive any alerts for events like "entry delay stated" and "contact open"

To reproduce this, we need to add a line in the `<project_root>/proxy/flag.txt` while keeping the proxy running. The line of text controls the length of the event to be delayed and the period of delay. For example

```scheme
504,504 40 
# this configuration defines a 40 seconds delay for the next 
# event message towards the Ring cloud server. 
```

means starting delay period of 40 seconds when receiving an event with the length falling in the range of $[504,504]$ bytes. The from the prompt, you should be able to see the indication of delay start and end. 

```jsx
07/08/2021 09:49:30 PM | record of [28, 504] bytes to ('3.238.77.118', 443)
07/08/2021 09:49:53 PM | record of [28] bytes to ('3.238.77.118', 443)
07/08/2021 09:49:53 PM | record of [48] bytes to ('3.238.77.118', 443)
07/08/2021 09:49:53 PM | record of [28, 52] bytes to ('192.168.1.23', 48190)
07/08/2021 09:49:56 PM | record of [28, 504] bytes to ('3.238.77.118', 443)
07/08/2021 09:49:56 PM | ---------------delay starts for 40 seconds---------------
07/08/2021 09:49:56 PM | record of [28] bytes to ('3.238.77.118', 443)
07/08/2021 09:49:56 PM | record of [504] bytes to ('3.238.77.118', 443)
07/08/2021 09:50:22 PM | record of [28] bytes to ('3.238.77.118', 443)
07/08/2021 09:50:22 PM | record of [48] bytes to ('3.238.77.118', 443)
07/08/2021 09:50:36 PM | ---------------delay ends for 40 seconds---------------
07/08/2021 09:50:36 PM | record of [28, 52] bytes to ('192.168.1.23', 48190)
07/08/2021 09:50:51 PM | record of [28] bytes to ('3.238.77.118', 443)
07/08/2021 09:50:51 PM | record of [48] bytes to ('3.238.77.118', 443)
```

After the end of the delay, we can see the smart phone raises the corresponding notification.

### **Routine-Invalidate Attack**

For validating the Routine-Invalidate attack, we set two Alexa routines to toggle an Amazon smart plug with the Ring security system armed/disarmed events. We find that the routines will not be executed as long as the event is delayed for longer than 29 seconds. Even if the connection between the hub and the cloud is not dropped, the discarded event will never be retransmitted to trigger the routine. The same phenomenon also happens for command messages that disarm the Ring security system. As it is common for users to use Ring sensors events to automate their other smart devices that are linked to Alexa, this design flaw exposes the risk of leaving some devices in unsafe states for a long time. Also, for smart locks and plugs that are paired to the Ring hub, attackers can also invalidate commands towards them which results in a risky state.

### **Action-Reorder Attack**

The action reorder attack is conducted by using an echo speaker to issue a voice command that disarms the Ring security system. The resulted command message from the cloud to the Ring hub is immediately delayed for 29 seconds. Before the end of the delay, if we manually arm the security system with the keypad, the delayed command of disarm can override this manual operation which actually happens later and leaves the system's final state as "disarmed".