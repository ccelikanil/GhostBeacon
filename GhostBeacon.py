#!/usr/bin/python3

import os
import pytz
import re
import signal
import sys
import subprocess
import time
from datetime import datetime, timedelta
from scapy.all import *

# Global Variables

changedCards = []
processes = []
wirelessInterfaces = []
operatingMode = ''
savedFile = ''
processID = ''
ssidFound = False
ssid = ''
bssid = ''
ssidCapabilities = {}
uniqueBSSID = []

def checkRequirements():
	try:
		subprocess.check_call(['which', 'aircrack-ng'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		print("\033[92m[+] aircrack-ng suite is already installed, script can continue.\033[0m")
		
		subprocess.check_call(['which', "mdk4"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		print("\033[92m[+] mdk4 is already installed, script can continue.\033[0m")
		
		subprocess.check_call(['which', "gnome-terminal"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		print("\033[92m[+] gnome-terminal is already installed, script can continue.\033[0m")
		
		print("\n######################################################\n")
	
	except (OSError, subprocess.CalledProcessError):
		print("\nSome of the requirements are not currently installed. You can try to install requirements manually by using \"requirements.txt\" file.\n")
		print("######################################################\n")
		print("!!! EXITING !!!")
		exit(0)

def listInterfaces():
	global wirelessInterfaces
	global operatingMode 
		
	getInterfaces = subprocess.check_output(['iwconfig'], universal_newlines=True)
	
	wirelessInterfaces = re.findall(r'^\w+\d*\s+', getInterfaces, re.MULTILINE)
	wirelessInterfaces = [iface.strip() for iface in wirelessInterfaces]
	numberofCards = len(wirelessInterfaces) 
	
	operatingMode = re.findall(r'Mode:\w+\s', getInterfaces)
	operatingMode = [mode.replace("Mode:", "").strip() for mode in operatingMode]
	
	print("######################################################\n")
	print("Wireless Interfaces List (Total : " + str(numberofCards) +")\n")

	if not wirelessInterfaces:
		print("\033[91mError: No wireless interfaces found.\033[0m")
	
	else:
		for i in range(len(wirelessInterfaces)):
			print("Wireless Interface Name " + str(i+1) + ": " + "\"" + wirelessInterfaces[i] + "\"" + ", Operating Mode: " + operatingMode[i])
	
	print("\n######################################################\n")

def changeOperatingMode():	
	global changedCards
	
	for i in range(len(wirelessInterfaces)):
		if (operatingMode[i] == "Managed"):
			print("\nLooks like Wireless Interface " + str(i+1) + " is in \"Managed Mode\". Would you like to put it into \"Monitor Mode\"? (Y/N)")
			changeOperation = input().lower()
			
			while changeOperation not in ['y', 'n']:
    				changeOperation = input("Invalid input. Please enter 'y' or 'n': ").lower()
    			
			if (changeOperation == 'y'):
				message = "Putting in monitor mode..."
				
				for char in message:
					print(char, end = "", flush = True)
					time.sleep(0.05)
				print()
				
				subprocess.call(['sudo', 'ifconfig', wirelessInterfaces[i], 'down'])
				subprocess.call(['sudo', 'iwconfig', wirelessInterfaces[i], 'mode', 'monitor'])
				subprocess.call(['sudo', 'ifconfig', wirelessInterfaces[i], 'up'])
				
				changedCards.append(wirelessInterfaces[i])
    				
				print("\n\033[92m[+] Wireless Interface " + str(i+1) + " now is in \"Monitor Mode\".\033[0m")
				
			elif (changeOperation == 'n'):
				print("\n\033[91m[!] Wireless Interface " + str(i+1) + " needs to be in \"Monitor Mode\" to continue!!\033[0m")
				changeOperatingMode()
				
		else:
			print("\033[92m[!] Interface " + str(i+1) + " is in \"Monitor Mode\".\033[0m")
	
		
	print("\n######################################################\n")
	
class BeaconSignalReceived(Exception):
    pass

def checkBeacon(packet):
    global ssidFound
    global uniqueBSSID
    global ssidCapabilities
    global ouiBytes
    global pwr
    global minPWR

    def signalHandler(sig, frame):
        i = 1

        for bssid, uptimeStr, enc, pwr in uniqueBSSID:
            print(
                f"{i} - BSSID: \"{bssid}\", Uptime: {uptimeStr}, Encryption: {enc}, PWR: {pwr}")
            i += 1

        raise BeaconSignalReceived("Beacon signal received!")

    signal.signal(signal.SIGINT, signalHandler)

    if packet.haslayer(Dot11Beacon):
        if packet.info.decode('utf-8') == ssid and not ssidFound:
            ssidFound = True
            ssidCapabilities[ssid] = packet[Dot11Beacon].cap  # store unique SSID's to ssidCapabilities list

            bssid = packet[Dot11].addr3.upper()

            # Calculate & Sort Uptime ---

            timestamp = packet[Dot11].timestamp
            epoch = datetime.utcfromtimestamp(0)
            beaconTime = epoch + timedelta(
                microseconds=timestamp)  # actual uptime + epoch
            uptime = beaconTime - epoch
            uptimeStr = str(uptime).split('.')[0]

            # Get encryption capabilities

            if "privacy" not in (ssidCapabilities[ssid].flagrepr()):  # check if beacon's privacy bit is 0
                enc = "OPN"
            else:
                enc = "WEP/WPA/2/3"

            # Check OUI

            ouiBytes = []
            extractedBSSID = packet[Dot11].addr3.upper()[:8]
            ouiBytes.append(extractedBSSID)

            # Get TX

            if packet.haslayer(RadioTap):
                pwr = packet[RadioTap].dBm_AntSignal
            else:
                print("\033[91m[!] Unable to obtain PWR value!\033[0m")

            # calculate min tx
            if not uniqueBSSID:  # Check if uniqueBSSID list is empty
                minPWR = pwr
            else:
                minPWR = min(uniqueBSSID, key=lambda x: abs(x[3]))[3]

            if abs(pwr) < abs(minPWR):
                minPWR = pwr

            ############################

            if bssid not in [x[0] for x in uniqueBSSID]:
                print(
                    f"\n\033[92m[+] Found SSID \"{ssid}\" w/BSSID value \"{bssid}\". AP's uptime: {uptimeStr}\033[0m")

                if bssid not in [x[0] for x in uniqueBSSID]:
                    print(
                        f"\n[!] {bssid} added to the comparison list. Searching for next beacon, please wait...")
                    uniqueBSSID.append((bssid, uptimeStr, enc, pwr))

                    ssidFound = False

                uptimeStr = ''  # reset uptime value for each bssid

            elif bssid in [x[0] for x in uniqueBSSID]:
                ssidFound = False


def spotFakeAP():
	global savedFile
	global processID
	global processes
	global ssidFound
	global ssid
	global bssid
	global ssidCapabilities
	global uniqueBSSID
    
	ssidCapabilities = {}
	uniqueBSSID = []

	print("Fake AP Spotter Module is selected. \"airodump-ng\" window is spawning...")

	# add card selection feature

	savedFile = os.popen("date +%Y-%m-%d_%H-%M-%S").read().strip() 

	spawnMonitor = f"airodump-ng {wirelessInterfaces[0]} --band abg --output-format csv --uptime --write beacons/{savedFile}"
	airodumpProcess = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', spawnMonitor])
	processID = airodumpProcess.pid
	processes.append(processID)
	#stdout, stderr = airodumpProcess.communicate()
	time.sleep(5)
    
	#os.kill(processID, signal.SIGTERM)    # now it's unnecessary but let it stay until first release

	print("\n[!] At this point, you have to provide an SSID (preferably, your own SSID) to check whether there is a suspicious (rogue) AP is present.")
	print("[!] Optionally, you may enter your BSSID value to separate your original AP from others (if there is any)") 
    
	ssid = input("\nEnter target SSID: ")
    
	# Check whether given input is a valid BSSID
	bssidPattern = re.compile("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    

	####### Will add this feature
	"""
	print("\n[!] Do you want to enter BSSID to exclude your own AP? (Format -> AA:BB:CC:DD:EE:FF) - y/n")
	answer = input().lower()
    
	while answer not in ['y', 'n']:
		answer = input("\nInvalid input. Please enter 'y' or 'n': ").lower()
    
	if answer == 'y':
		while True:
			bssid = input("\nEnter BSSID of original AP: ")
            
			if len(bssid) == 17 and bssidPattern.match(bssid):
				break

			else:
				print("\nInvalid BSSID format. Please enter in the format of AA:BB:CC:DD:EE:FF")
    """
	#######

	duration = int(input("\nEnter the duration to listen for beacons (in seconds): "))
	timeout = duration if duration > 0 else None
    
	print("\n[!] Listening for beacons, please wait...\n")
        
	try:
		sniff(iface=wirelessInterfaces[0], prn=checkBeacon, store=0, timeout=timeout)
        
		print("\n\033[92m[!] Beacon reading is DONE!\033[0m")
		print(f"\n\033[92m[!] SSID \"{ssid}\" with all unique BSSIDs:\n\033[0m")
		print("\033[90m[!] Check BSSIDs to see whether they are in your asset list!\033[0m\n") 
        
		if len(uniqueBSSID) > 1:									
			minUptimeBSSID, minUptime, enc, pwr = min(uniqueBSSID, key=lambda x: x[1])	# sort uptimes
                
			print("\n[!] Comparing BSSIDs:\n")
            
			for bssid, uptime, enc, pwr in uniqueBSSID:
				if enc == "OPN":
					if bssid == minUptimeBSSID:
						if minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' IS 99% A ROGUE (FAKE) AP!\033[0m\n")
						elif not minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP is OPN and has MINIMUM UPTIME. High chances to be a ROGUE (FAKE) AP!\033[0m\n")
					elif bssid != minUptimeBSSID:
						if minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP is OPN and has the CLOSEST SIGNAL. High chances to be a ROGUE (FAKE) AP!\033[0m\n")
						elif not minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP is OPN. Might be a ROGUE (FAKE) AP. Consider checking your asset it.\033[0m\n")
				elif enc != "OPN":
					if bssid == minUptimeBSSID:
						if minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP has encryption (privacy bit set) but it has MINIMUM UPTIME and has the CLOSEST SIGNAL. High chances to be a ROGUE (FAKE) AP!\033[0m\n")
						elif not minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP has encryption (privacy bit set) but it has MINIMUM UPTIME. Consider checking your asset list.\033[0m\n")
					elif bssid != minUptimeBSSID:
						if minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP has encryption (privacy bit set) but it has the CLOSEST SIGNAL. Consider checking your asset list.\033[0m\n")
						elif not minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' High chances to be a false-positive.\033[0m\n")
				"""
				if bssid == minUptimeBSSID:
					if enc == "OPN":
						if minPWR:
							p
						elif not minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' has no encryption (OPN) and has the least AP uptime. We are not sure about it's signal power but there are high chances to be a ROGUE (FAKE) AP.\033[0m\n")
					elif enc == "WEP/WPA/2/3":
						print(f"\033[91m[!] BSSID: '{bssid}' has encryption (privacy bit set) but it has the least AP uptime. Consider checking your asset list.\033[0m\n")
				"""
		elif len(uniqueBSSID) == 1:
			print("\n\033[92m[!] Only one BSSID found!\033[0m")
		else:
			print("\n\033[91m[!] No beacon!!\033[0m")

		for i, (bssid, uptimeStr, enc, pwr) in enumerate(uniqueBSSID, 1):
			print(f"{i} - BSSID: \"{bssid}\", Uptime: {uptimeStr}, Encryption: {enc}, PWR: {pwr}")
        
		#print(minPWR)
		# Find Rogue APs w/Uptime
		

	except BeaconSignalReceived:
		message = "\nFinding Rogue/Fake APs...\n"
        
		for char in message:
			print(char, end = "", flush = True)
			time.sleep(0.05)
        
		print()
	    	
def spotHiddenAP():
	print("""
	
	######################################################
		      
		     Hidden Access Point Spotter
		      
	######################################################
	
	""")	
	
	
def safeExit():
	# Kill spawned processes
	
	for i in range(len(processes)):
		message = "\nKilling processes...\n"
		
		for char in message:
			print(char, end = "", flush = True)
			time.sleep(0.05)
		
		print()
		
		subprocess.call(['pkill', 'gnome-terminal'])
		
		print("\033[92mDONE!\033[0m")

	# Restore card interfaces

	for i in range(len(changedCards)):
		message = "\n[!] Restoring Wireless Interface " + str(i+1) +  " to \"Managed Mode\""
		
		for char in message:
			print(char, end = "", flush = True)
			time.sleep(0.05)
		print()
		
		subprocess.call(['sudo', 'ifconfig', changedCards[i], 'down'])
		subprocess.call(['sudo', 'iwconfig', wirelessInterfaces[i], 'mode', 'managed'])	
		subprocess.call(['sudo', 'ifconfig', changedCards[i], 'up'])
		
		print("\n\033[92m[+] Wireless Interface " + str(i+1) + " restored to \"Managed Mode\"!\033[0m")

def main():
	
	print("""
	
	  /$$$$$$  /$$                             /$$     /$$$$$$$                                                   
	 /$$__  $$| $$                            | $$    | $$__  $$                                                  
	| $$  \__/| $$$$$$$   /$$$$$$   /$$$$$$$ /$$$$$$  | $$  \ $$  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$ 
	| $$ /$$$$| $$__  $$ /$$__  $$ /$$_____/|_  $$_/  | $$$$$$$  /$$__  $$ |____  $$ /$$_____/ /$$__  $$| $$__  $$
	| $$|_  $$| $$  \ $$| $$  \ $$|  $$$$$$   | $$    | $$__  $$| $$$$$$$$  /$$$$$$$| $$      | $$  \ $$| $$  \ $$
	| $$  \ $$| $$  | $$| $$  | $$ \____  $$  | $$ /$$| $$  \ $$| $$_____/ /$$__  $$| $$      | $$  | $$| $$  | $$
	|  $$$$$$/| $$  | $$|  $$$$$$/ /$$$$$$$/  |  $$$$/| $$$$$$$/|  $$$$$$$|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$
	\______/ |__/  |__/ \______/ |_______/    \___/  |_______/  \_______/ \_______/ \_______/ \______/ |__/  |__/
                                                                                                              

    	######################################################################################
                                       
        	  802.11 Hidden AP & Fake AP Spotter - Developed by Anıl Çelik (@ccelikanil)
        	      
	######################################################################################                                           
	""")

	checkRequirements()
	listInterfaces()
	changeOperatingMode()
	spotFakeAP()
	
	safeExit()
	
if __name__ == '__main__':
	main()
