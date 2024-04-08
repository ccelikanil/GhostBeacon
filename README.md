# GhostBeacon

<p align="center"> <img src="rsc/banner.png" /> </p>                                                                                                                

# CLI-based 802.11 Hidden AP & Rogue (Fake) AP Spotter

## Features:

1. 802.11 Rogue (Fake) Access Point Spotter
2. 802.11 Hidden Access Point Spotter

## How it works?

You can visit my **Medium post** for a long explanation.

TL;DR - Basically, provided features are depending on how 802.11 protocol works. 

## Some PoCs

### Main Menu:

<p align="center"> <img src="rsc/readme-screenshots/0_mainmenu.PNG" /> </p>

- Program first checks if the dependencies are installed on target OS. If dependencies are not installed, program calls ``rsc/setup.sh`` setup file to install dependencies automatically:

<p align="center"> <img src="rsc/readme-screenshots/1_mainmenu_dependencyinstall.PNG" /> </p>

- Then, program checks whether there's a wireless card plugged in and then it checks if corresponding wireless card is in **"Monitor Mode"**. Since we are going to sniff the air for capturing packets, the card needs to be in **"Monitor Mode"**. 
- After necessary checks completed, users can choose ``1`` for  **"Rogue (Fake) AP Spotter"** module or ``2`` for **Hidden AP Spotter"** module.


## What's next?

...
