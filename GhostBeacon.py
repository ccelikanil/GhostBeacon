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

			#print("BSSID with minimum power: ", minpwrBSSID)

            ############################

			if bssid not in [x[0] for x in uniqueBSSID]:
				print(f"\n\033[92m[+] Found SSID \"{ssid}\" w/BSSID value \"{bssid}\". AP's uptime: {uptimeStr}\033[0m")

				if bssid not in [x[0] for x in uniqueBSSID]:
					print(f"\n[!] {bssid} added to the comparison list. Searching for next beacon, please wait...")
					uniqueBSSID.append((bssid, adjustedUptime, enc, pwr))

					ssidFound = False

				uptimeStr = ''  # reset uptime value for each bssid
				#adjustedUptime = '' # reset adjustedUptime value for each bssid

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
	# bssidPattern = re.compile("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    

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
			minUptimeBSSID = min(uniqueBSSID, key=lambda x: x[1])	# sort uptimes
						                
			print("\n[!] Comparing BSSIDs:\n")
            
			#print(minUptimeBSSID[1])
			#print(minpwrBSSID)
			#print("minpwr:", minPWR)
			#print("minpwrbssid:", minpwrBSSID)


			for bssid, adjustedUptime, enc, pwr in uniqueBSSID:
				#print(pwr)
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
							print(f"\033[91m[!] BSSID: '{bssid}' AP is OPN. Might be a ROGUE (FAKE) AP. Consider checking your asset it.\033[0m\n")
				
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
        
		#print(min(uniqueBSSID, key=lambda x: x[1]))	# sort uptimes

		#print(minPWR)
		# Find Rogue APs w/Uptime
		

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
	
	if packet.haslayer(Dot11Beacon):
		ssid = packet.info.decode('utf-8')
		bssid = packet.addr3.upper()

		# Calculate Channel Number
		
		channelRAW = packet[Dot11Elt:3]
		channel = int.from_bytes(channelRAW.info, byteorder='little')

		# Count null chars (\000)

		nullChars = ssid.count("\000")

		# If beacon is "clear" or beacon has "null chars (\000)" 
		
		if ssid == "" or "\000" in ssid:
			if (bssid, channel, nullChars) not in uniqueBSSID:
				if "\000" in ssid:
					nullChars = ssid.count("\000")
					uniqueBSSID.append((bssid, channel, nullChars))
				elif ssid == "":
					nullChars = 0
					uniqueBSSID.append((bssid, channel, nullChars))
				
				hiddenSSIDFlag = True
				hiddenBSSID = bssid

				print(f"\n\033[92m[+] Hidden SSID detected! BSSID value: \"{bssid}\", Channel: {channel}, SSID length: {nullChars}\033[0m\n")
				print("\033[90m[!] Trying to obtain AP's SSID value...\033[0m\n") 
				#print("hidden ssid detected! bssid: ", bssid, "channel: ", channel, "SSID length: ", nullChars)

def spotHiddenAP():
	global hiddenSSIDFlag
	global hiddenBSSID

	hiddenSSIDFlag = False
	hiddenBSSID = ""

	print("Hidden AP Spotter Module is selected. \"airodump-ng\" window is spawning...\n")
	print("[!] Listening for beacons, please wait...\n")

	spawnMonitor = f"airodump-ng {wirelessInterfaces[0]} --band abg --output-format csv --uptime --write beacons/{savedFile}"
	airodumpProcess = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', spawnMonitor])
	processID = airodumpProcess.pid
	processes.append(processID)
	time.sleep(5)

	try:
		sniff(iface=wirelessInterfaces[0], prn=checkHiddenBeacon, store=0, timeout=30)

		print("[!] Whole BSSID list w/Hidden SSID value(s):\n")
		
		i = 1

		for i, (bssid, channel, nullChars) in enumerate(uniqueBSSID, 1):
			print(f"{i} - BSSID: {bssid}, Channel: {channel}, SSID length: {nullChars}")

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
                                       
        	  802.11 Hidden AP & Fake AP Spotter - Developed by Anıl Çelik (@ccelikanil)
        	      
	######################################################################################                                           
	""")

	print("[!] This tool may generate false-positive info. Always consider checking your asset list.\n")

	checkRequirements()
	listInterfaces()
	changeOperatingMode()
	spotHiddenAP()
	
	safeExit()
	
if __name__ == '__main__':
	main()
