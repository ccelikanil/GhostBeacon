# GhostBeacon v1.0

<p align="center"> <img src="rsc/banner.png" /> </p>                                                                                                                

# CLI-based 802.11 Hidden Access Point (AP) & Rogue (Fake) Access Point (AP) Spotter

## Features:

1. 802.11 Rogue (Fake) Access Point Spotter
2. 802.11 Hidden Access Point Spotter

## Proof-of-Concepts (PoCs) & How it works

TL;DR - Basically, provided features are depending on how 802.11 protocol works. 

### Main Menu

<p align="center"> <img src="rsc/readme-screenshots/0_mainmenu.PNG" /> </p>
<p align="center"> Figure #1 - Main Menu </p>

- Program first checks if the dependencies are installed on target OS. If dependencies are not installed, program calls ``rsc/setup.sh`` setup file to install dependencies automatically:

<p align="center"> <img src="rsc/readme-screenshots/1_mainmenu_dependencyinstall.PNG" /> </p>
<p align="center"> Figure #2 - Dependency Installation</p>

- Then, program checks whether there's a wireless card plugged in and then it checks if corresponding wireless card is in **"Monitor Mode"**. Since we are going to sniff the air for capturing packets, the card needs to be in **"Monitor Mode"**. 
- After necessary checks completed, users can choose ``1`` for  **"Rogue (Fake) AP Spotter"** module or ``2`` for **Hidden AP Spotter"** module.

### Module #1: Rogue (Fake) Access Point Spotter

<p align="center"> <img src="rsc/readme-screenshots/2_fakeap_selectmodule.PNG" /> </p>
<p align="center"> Figure #3 - Rogue (Fake) AP Spotter Module </p>

- In this module, an ``airodump-ng`` window pops up to display available SSIDs in wireless card's scan range.

<p align="center"> <img src="rsc/readme-screenshots/3_fakeap_spawnairodump.PNG" /> </p>
<p align="center"> Figure #4 - airodump-ng </p>

- Then, users are asked to enter an SSID value to check if there's any rogue (fake) access point with same SSID is present.
- Also, users are asked to enter a value for packet sniffing duration.
- When these inputs are provided, the program starts to sniff **"Beacon Frames"** in the area and saves all access points with unique BSSID (MAC address) values into a list *- namely, the "Comparison List*".

<p align="center"> <img src="rsc/readme-screenshots/4_fakeap_spotopn_privacy.PNG" /> </p>
<p align="center"> Figure #5 - Sample Run: Spotting Rogue (Fake) Access Points </p>

**Explanation of **"Figure #5"** is as follows:**
- User first inputs an SSID value, **"RFC6797"**, followed by the duration value, **"30"**.
- Program finds **4** unique access points (in this particular example) with given SSID and saves them into the comparison list.
- After completing Beacon sniffing, program does it's calculation depending on following code:

  ```
  Pseudo-code of lines 271..294 in GhostBeacon.py
  
    iterate (for) through uniqueBSSID list:
        if bssid.encryption is None:
            if bssid.uptime is minUptime:
                if bssid.pwr is minPWR:
                    print("AP IS 99% A ROGUE (FAKE) AP!")
                else if bssid.pwr not minPWR:
                    print("AP is OPN and has MINIMUM UPTIME. High chances to be a ROGUE (FAKE) AP!")
            else if bssid.uptime not minUptime:
                if bssid.pwr is minPWR:
                    print("AP is OPN and has the CLOSEST SIGNAL. High chances to be a ROGUE (FAKE) AP!")
                else if bssid.pwr not minPWR:
                    print("AP is OPN. Might be a ROGUE (FAKE) AP. Consider checking your asset list.

      else if bssid.encryption not None:
          if bssid.uptime is minUptime:
                if bssid.pwr is minPWR:
                    print("AP has encryption (privacy bit set) but it has MINIMUM UPTIME and has the CLOSEST SIGNAL. High chances to be a ROGUE (FAKE) AP!")
                else if bssid.pwr not minPWR:
                    print("AP has encryption (privacy bit set) but it has MINIMUM UPTIME. Consider checking your asset list.")
          else if bssid.uptime not minUptime:
                if bssid.pwr is minPWR:
                    print("AP has encryption (privacy bit set) but it has the CLOSEST SIGNAL. Consider checking your asset list.")
                else if bssid.pwr not minPWR:
                    print("High chances to be a false-positive.")
  ```
<p align="center"> Code Snippet #1 - Pseudo-code of Rogue (Fake) AP Detection Mechanism </p>

**Brief explanation:**
- Rogue *(Fake)* Access Points generally have no encryption *(they are OPN)* to force victims for connecting them to their fake APs and ask the original AP's password by using a **Captive Portal**. That's why our first check is AP's encryption *(i.e. Privacy Bit)*.
- Since Fake APs are deployed later than the original AP, their uptime values are usually shorter than the original AP. Even though uptime value is easy to fake, it's still pretty easy to discriminate this value.
- Due to 802.11's protocol implementation, clients are tend to connect to the nearest AP among the ones having same SSID value. Which brings us to our next control: **PWR (TX)** check *(i.e. Signal Strength)*. If an attacker wants a victim to connect to their Rogue AP, they first need to disconnect the victim from original AP and force them to send a connection request *(i.e. Probe Request)* to their Rogue AP by setting up an AP with stronger signal.
- Fake APs may have encryption *(they may have their Privacy Bit set)*. If target BSSID has an encryption, same controls needs to be done as we did on OPN BSSIDs.     
<p align="center"> <img src="rsc/readme-screenshots/5_fakeap_spotopn_minuptime.PNG" /> </p>
<p align="center"> Figure #6 - Sample Run: Spotting Rogue (Fake) Access Points </p>

<p align="center"> <img src="rsc/readme-screenshots/6_fakeap_enc_minuptime_minpwr.png" /> </p>
<p align="center"> Figure #7 - Sample Run: Spotting Rogue (Fake) Access Points </p>

<p align="center"> <img src="rsc/readme-screenshots/7_fakeap_enc_minpwr_minuptime.png" /> </p>
<p align="center"> Figure #8 - Sample Run: Spotting Rogue (Fake) Access Points </p>

### Module #2: Hidden Access Point Spotter 

<p align="center"> <img src="rsc/readme-screenshots/8_hiddenap_selectmodule.PNG" /> </p>
<p align="center"> Figure #9 - Hidden AP Spotter Module </p>

<p align="center"> <img src="rsc/readme-screenshots/9_hiddenap_probehunt.png" /> </p>
<p align="center"> Figure #10 - Sample Run: Hunting Hidden AP's SSID Value </p>

**Explanation of "Figure #10" is as follows:**
- User inputs a timeout value for Beacon sniffing.
- See below:

```
Lines 388..391 in GhostBeacon.py
...

try:
		sniff(iface=wirelessInterfaces[0], prn=checkHiddenBeacon, store=0, timeout=timeout)
		print("[!] Hunting for probes...\n")
		sniff(iface=wirelessInterfaces[0], prn=checkProbeResponse, store=0, timeout=timeout)

...
```
<p align="center"> Code Snippet #2 - Function Calls for "checkHiddenBeacon" and "checkProbeResponse" </p>

- In above snippet, since **"Probe Response"** sniffing is done after Beacon sniffing, the same timeout value needs to be applied in here and that's why we have to wait for ``timeout*2`` seconds.
- Program first discovers **"Beacon Frames"** and checks whether the SSID value is hidden in that specific Beacon Frame packet.
- Determining whether the SSID is hidden or not is pretty simple and can be done in two ways: **First way is:** if **"Clear Beacons"** are being sent, that is, if the SSID length is zero, this means that the SSID is hidden. **Second way is:** If SSID has **"Null Bytes (``\000``)"** inside it's value, this means that that SSID is also hidden. Luckily, we can guess the SSID length by counting null bytes inside the SSID info.

How hidden SSID values being captured and what is the relationship with **"Probe Response"** packets? Well, there are couple of different ways for finding out the real values for hidden SSIDs. What we are currently doing in this program's first version is as follows:
- When you set an AP to hide it's SSID info, you are basically telling that AP to hide it's SSID information on the **"Beacon Frames"** that it broadcasts. **"Beacon Frames"** are the packets that APs broadcasts to let every STATION (STA) *- i.e. clients* nearby that they exist and available for connection requests. When this information *- namely, the SSID* is hidden, naturally, nobody would be able to send any connection request to this AP, except the ones having the correct information.
- However, it's not so hard to identify this *hidden* information.

Let's go deeper:

We will be focusing on **3 *(three)*** frames in below figure: **"Beacon Frames"**, **"Probe Requests"** & **"Probe Responses"**

<p align="center"> <img src="rsc/readme-screenshots/ap_sta_communication.png" /> </p>
<p align="center"> Figure #11 - Communication Between Access Point (AP) and Client (Station/STA) </p>

- Like previously said, AP's need to send **"Beacon Frames"** to tell nearby clients that they are ready for connection.

<p align="center"> <img src="rsc/readme-screenshots/beaconframe.png" /> </p>
<p align="center"> Figure #12 - 802.11 Beacon Frame </p>

- Note that, a **"Beacon Frame"**'s key elements are **"Source Address"** and **"Transmitter Address"** has AP's MAC address *- namely, AP's BSSID*
- **"Receiver Address"** and **"Transmitter Address"** values are ``FF:FF:FF:FF:FF:FF``, which means the packet is being sent as **Broadcast**.
- **"SSID"** and **"Channel Number"** sections are also set to tell clients that what this AP's name and which channel that it is currently present. **"Channel Number"** is also another important point because Access Point and the Client should be on the same channel number for a successful connection.
- Other information about this frame class is irrelevant for now.

- When a **"STATION/STA"** *- or Client* wants to connect to a specific Access Point, it simply needs to send a **"Probe Request"** containing corresponding AP's **"SSID"** information and it's **"Channel Number"**:

<p align="center"> <img src="rsc/readme-screenshots/proberequest.png" /> </p>
<p align="center"> Figure #13 - 802.11 Probe Request </p>


```
...
```

## What's next? & Current Roadmap for this project

...

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/anilcelik) 
