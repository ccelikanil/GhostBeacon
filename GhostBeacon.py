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
		print("\nSome of the requirements are not currently installed. Installing dependencies...\n")
		subprocess.run(['sudo', 'chmod', '+x', 'rsc/setup.sh']) # give execution permisson to setup file
		subprocess.run(['sudo', 'bash', 'rsc/setup.sh'])	# install dependencies
		print("######################################################\n")

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
	global minpwrBSSID
	global adjustedUptime

	minpwrBSSID = ''

	def signalHandler(sig, frame):
		i = 1

		for bssid, uptimeStr, enc, pwr in uniqueBSSID:
			print(f"{i} - BSSID: \"{bssid}\", Uptime: {uptimeStr}, Encryption: {enc}, PWR: {pwr}")
			
			i += 1

		raise BeaconSignalReceived("Beacon signal received!")

	signal.signal(signal.SIGINT, signalHandler)

	if packet.haslayer(Dot11Beacon):
		if packet.info.decode('utf-8') == ssid and not ssidFound:
			ssidFound = True
			ssidCapabilities[ssid] = packet[Dot11Beacon].cap  # store unique SSID's to ssidCapabilities list

			bssid = packet[Dot11].addr3.upper()

			# Calculate & Sort Uptime

			timestamp = packet[Dot11].timestamp
			epoch = datetime.utcfromtimestamp(0)
			beaconTime = epoch + timedelta(microseconds=timestamp)  # actual uptime + epoch
			uptime = beaconTime - epoch
			uptimeStr = str(uptime).split('.')[0]

			# Adjust <DD, HH:MM:SS>

			def adjustUptime(uptimeStr): 
				parts = uptimeStr.split(', ')

				if len(parts) == 2:
					days = int(parts[0].split()[0])
					timePart = parts[-1]
				else:
					days = 0
					timePart = parts[0]

				timeParts = timePart.split(':')
				hours = int(timeParts[0]) + days * 24
				minutes = int(timeParts[1])
				seconds = int(timeParts[2])

				return f"{hours:02}:{minutes:02}:{seconds:02}"
				adjustedUptime = ''

			adjustedUptime = adjustUptime(uptimeStr)

            # Get encryption capabilities

			if "privacy" not in (ssidCapabilities[ssid].flagrepr()):  # check if beacon's privacy bit is 0
				enc = "OPN"
			else:
				enc = "Privacy bit is present (1)"

			# Check OUI - will add this feature
			"""
			ouiBytes = []
			extractedBSSID = packet[Dot11].addr3.upper()[:8]
			ouiBytes.append(extractedBSSID)
			"""
            # Get TX

			if packet.haslayer(RadioTap):
				pwr = packet[RadioTap].dBm_AntSignal
			else:
				print("\033[91m[!] Unable to obtain PWR value!\033[0m")

            # calculate min tx
			
			if not uniqueBSSID:  # Check if uniqueBSSID list is empty
				minPWR = pwr
				minpwrBSSID = bssid
			else:
				current_minPWR = min(uniqueBSSID, key=lambda x: abs(x[3]))[3]
				current_minpwrBSSID = min(uniqueBSSID, key=lambda x: abs(x[3]))[0]

				if abs(pwr) < abs(current_minPWR):
					minPWR = pwr
					minpwrBSSID = bssid
				else:
					minPWR = current_minPWR
					minpwrBSSID = current_minpwrBSSID

            ############################

			if bssid not in [x[0] for x in uniqueBSSID]:
				print(f"\n\033[92m[+] Found SSID \"{ssid}\" w/BSSID value \"{bssid}\". AP's uptime: {uptimeStr}\033[0m")

				if bssid not in [x[0] for x in uniqueBSSID]:
					print(f"\n[!] {bssid} added to the comparison list. Searching for next beacon, please wait...")
					uniqueBSSID.append((bssid, adjustedUptime, enc, pwr))

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
	global adjustedUptime
    
	ssidCapabilities = {}
	uniqueBSSID = []

	print("\n\033[92m[!] Fake AP Spotter Module is selected. \"airodump-ng\" window is spawning...\033[0m")

	# add card selection feature

	savedFile = os.popen("date +%Y-%m-%d_%H-%M-%S").read().strip() 

	spawnMonitor = f"airodump-ng {wirelessInterfaces[0]} --band abg --output-format csv --uptime --write beacons/{savedFile}"
	airodumpProcess = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', spawnMonitor])
	processID = airodumpProcess.pid
	processes.append(processID)
	time.sleep(5)
    
	print("\n[!] At this point, you have to provide an SSID (preferably, your own SSID) to check whether there is a suspicious (rogue) AP is present.")
	#print("[!] Optionally, you may enter your BSSID value to separate your original AP from others (if there is any)") 
    
	ssid = input("\nEnter target SSID: ")  
	duration = int(input("\nEnter the duration to listen for beacons (in seconds): "))
	timeout = duration if duration > 0 else None
    
	print("\n[!] Listening for beacons, please wait...\n")
        
	try:
		sniff(iface=wirelessInterfaces[0], prn=checkBeacon, store=0, timeout=timeout)

		print("\n\033[92m[!] Beacon reading is DONE!\033[0m")
		print(f"\n\033[92m[!] SSID \"{ssid}\" with all unique BSSIDs:\n\033[0m")
		print("\033[90m[!] Check BSSIDs to see whether they are in your asset list!\033[0m\n") 
        
		if len(uniqueBSSID) > 1:									
			minUptimeBSSID = min(uniqueBSSID, key=lambda x: x[1])	# sort uptimes
						                
			print("\n[!] Comparing BSSIDs:\n")

			for bssid, adjustedUptime, enc, pwr in uniqueBSSID:
				if enc == "OPN":
					if adjustedUptime == minUptimeBSSID[1]:
						if pwr == minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' IS 99% A ROGUE (FAKE) AP!\033[0m\n")
						elif pwr != minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP is OPN and has MINIMUM UPTIME. High chances to be a ROGUE (FAKE) AP!\033[0m\n")
					elif adjustedUptime != minUptimeBSSID[1]:
						if pwr == minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP is OPN and has the CLOSEST SIGNAL. High chances to be a ROGUE (FAKE) AP!\033[0m\n")
						elif pwr != minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP is OPN. Might be a ROGUE (FAKE) AP. Consider checking your asset list.\033[0m\n")
				
				elif enc != "OPN":
					if adjustedUptime == minUptimeBSSID[1]:
						if pwr == minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP has encryption (privacy bit set) but it has MINIMUM UPTIME and has the CLOSEST SIGNAL. High chances to be a ROGUE (FAKE) AP!\033[0m\n")
						elif pwr != minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP has encryption (privacy bit set) but it has MINIMUM UPTIME. Consider checking your asset list.\033[0m\n")
					elif adjustedUptime != minUptimeBSSID[1]:
						if pwr == minPWR:
							print(f"\033[91m[!] BSSID: '{bssid}' AP has encryption (privacy bit set) but it has the CLOSEST SIGNAL. Consider checking your asset list.\033[0m\n")
						elif pwr != minPWR:
							print(f"\033[90m[!] BSSID: '{bssid}' High chances to be a false-positive.\033[0m\n")

		elif len(uniqueBSSID) == 1:
			print("\n\033[92m[!] Only one BSSID found!\033[0m")
		else:
			print("\n\033[91m[!] No beacon!!\033[0m")

		print("[!] Whole BSSID list:\n")

		for i, (bssid, adjustedUptime, enc, pwr) in enumerate(uniqueBSSID, 1):
			print(f"{i} - BSSID: \"{bssid}\", Uptime: {adjustedUptime}, Encryption: {enc}, PWR: {pwr}")
        
	except BeaconSignalReceived:
		message = "\nFinding Rogue/Fake APs...\n"
        
		for char in message:
			print(char, end = "", flush = True)
			time.sleep(0.05)
        
		print()

def checkHiddenBeacon(packet):
	global hiddenSSIDFlag
	global hiddenBSSID
	global uniqueBSSID
	
	hiddenChannel = None

	if packet.haslayer(Dot11Beacon):
		ssid = packet.info.decode('utf-8')
		bssid = packet.addr3.upper()
		
		hiddenChannel = int.from_bytes(packet[Dot11Elt:3].info, byteorder='little')		# Calculate channel number

		nullChars = ssid.count("\000")	# Count null chars (\000)

		# If beacon is "clear" or beacon has "null chars (\000)" 
		
		if ssid == "" or "\000" in ssid:
			if (bssid, hiddenChannel, nullChars) not in uniqueBSSID:
				if "\000" in ssid:
					nullChars = ssid.count("\000")
					uniqueBSSID.append((bssid, hiddenChannel, nullChars))
				elif ssid == "":
					nullChars = 0
					uniqueBSSID.append((bssid, hiddenChannel, nullChars))
				
				hiddenSSIDFlag = True
				hiddenBSSID = bssid

				print(f"\n\033[92m[+] Hidden SSID detected! BSSID value: \"{bssid}\", Channel: {hiddenChannel}, SSID length: {nullChars}\033[0m\n")
				print("\033[90m[!] Trying to obtain AP's SSID value...\033[0m\n")

def checkProbeResponse(packet):
	global hiddenSSIDFlag
	global hiddenBSSID
	global uniqueBSSID

	if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 0x0005:
		bssid = packet.addr3.upper()
		channel = int.from_bytes(packet[Dot11Elt:3].info, byteorder='little')
		ssid = packet.info.decode('utf-8')

		print(f"\033[90m[!] Caught Probe Response for {bssid} but seems like it doesn't belong to an hidden AP. Possible SSID: {ssid}\033[0m")

		for hiddenBSSID, hiddenChannel, nullChars in uniqueBSSID:
			if bssid == hiddenBSSID and channel == hiddenChannel:
				ssid = packet.info.decode('utf-8')
				print(f"\033[92m[+] Caught Probe Response packet for hidden SSID! SSID: {ssid}, BSSID: {bssid}, Channel: {channel}\033[0m")
			#else:
				

def spotHiddenAP():
	global hiddenSSIDFlag
	global hiddenBSSID

	hiddenSSIDFlag = False
	hiddenBSSID = ""

	print("\n\033[92m[!] Hidden AP Spotter Module is selected. \"airodump-ng\" window is spawning...\033[0m\n")
	
	duration = int(input("\nEnter the duration to listen for beacons (in seconds): "))
	timeout = duration if duration > 0 else None
	
	print(f"\n\033[90m[!] Since Beacon reading and Probe Response reading done in separate functions, we have to wait for {timeout*2} seconds.\033[0m")
	print("\n[!] Listening for beacons, please wait...\n")
	

	spawnMonitor = f"airodump-ng {wirelessInterfaces[0]} --band abg --output-format csv --uptime --write beacons/{savedFile}"
	airodumpProcess = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', spawnMonitor])
	processID = airodumpProcess.pid
	processes.append(processID)
	time.sleep(5)

	try:
		sniff(iface=wirelessInterfaces[0], prn=checkHiddenBeacon, store=0, timeout=timeout)
		print("[!] Hunting for probes...\n")
		sniff(iface=wirelessInterfaces[0], prn=checkProbeResponse, store=0, timeout=timeout)

		print("\n[!] Whole BSSID list w/Hidden SSID value(s):\n")
		
		if len(uniqueBSSID) == 0:
			print("\n\033[91m[!] No hidden SSID is present!\033[0m") 
		else:
			i = 1
		
			for i, (bssid, hiddenChannel, nullChars) in enumerate(uniqueBSSID, 1):
				print(f"{i} - BSSID: {bssid}, Channel: {hiddenChannel}, SSID length: {nullChars}")
		
	except KeyboardInterrupt:
		print("Interrupted!")

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
                                       
          802.11 Rogue (Fake) AP & Hidden AP Spotter - Developed by Anıl Çelik (@ccelikanil)
        	      
	######################################################################################                                           
	""")

	print("\033[90m[!] This tool may generate false-positive info. Always consider checking your asset list.\033[0m\n")

	checkRequirements()
	listInterfaces()
	changeOperatingMode()
	
	while True:
		print("\n\033[92m[!] Select '1' for 'Rogue (Fake) AP Spotter' , Select '2' for 'Hidden AP Spotter' or Select '0' to exit.\033[0m")

		choice = input("\n[!] Select module: ")

		if choice == "1":
			spotFakeAP()
			safeExit()
			break
		elif choice == "2":
			spotHiddenAP()
			safeExit()
			break
		elif choice == "0":	
			print("\n\033[91m[!] Exiting...\033[0m")
			safeExit()
			break
		else:
			print("\n\033[91m[!] Invalid choice! Please select a valid option.\033[0m")
	
if __name__ == '__main__':
	main()
