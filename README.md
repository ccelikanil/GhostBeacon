# GhostBeacon

<p align="center"> <img src="rsc/banner.png" /> </p>                                                                                                                

# CLI-based 802.11 Hidden Access Point (AP) & Rogue (Fake) Access Point (AP) Spotter

## Features:

1. 802.11 Rogue (Fake) Access Point Spotter
2. 802.11 Hidden Access Point Spotter

## How it works?

You can visit my **Medium post** for a long explanation.

TL;DR - Basically, provided features are depending on how 802.11 protocol works. 

## Some PoCs

### Main Menu

<p align="center"> <img src="rsc/readme-screenshots/0_mainmenu.PNG" /> </p>
<p align="center"> Figure #1 - Main Menu </p>

- Program first checks if the dependencies are installed on target OS. If dependencies are not installed, program calls ``rsc/setup.sh`` setup file to install dependencies automatically:

<p align="center"> <img src="rsc/readme-screenshots/1_mainmenu_dependencyinstall.PNG" /> </p>
<p align="center"> Figure #2 - Dependency Installation</p>

- Then, program checks whether there's a wireless card plugged in and then it checks if corresponding wireless card is in **"Monitor Mode"**. Since we are going to sniff the air for capturing packets, the card needs to be in **"Monitor Mode"**. 
- After necessary checks completed, users can choose ``1`` for  **"Rogue (Fake) AP Spotter"** module or ``2`` for **Hidden AP Spotter"** module.

### Rogue (Fake) AP Module

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
- Program finds **4** unique access points with given SSID and saves them into the comparison list.
- After completing Beacon listening, program does it's calculation depending on following code:

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










## What's next?

...
