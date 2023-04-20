#!/usr/bin/python3

import os
import pytz
import re
import signal
import subprocess
import time
from  datetime import datetime, timedelta
from scapy.all import *

# Global Variables

changedCards = []
processes = []
wirelessInterfaces = []
operatingMode = ''
savedFile = ''
processID = ''
ssidFound = False

def checkRequirements():
	try:
		subprocess.check_call(['which', 'aircrack-ng'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		print("[+] aircrack-ng suite is already installed, script can continue.")
		
		subprocess.check_call(['which', "mdk4"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		print("[+] mdk4 is already installed, script can continue.")
		
		subprocess.check_call(['which', "gnome-terminal"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		print("[+] gnome-terminal is already installed, script can continue.")
		
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
		print("Error: No wireless interfaces found.")
	
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
    				
				print("\n[+] Wireless Interface " + str(i+1) + " now is in \"Monitor Mode\".")
				
			elif (changeOperation == 'n'):
				print("\nWireless Interface " + str(i+1) + " needs to be in \"Monitor Mode\" to continue!!")
				changeOperatingMode()
				
		else:
			print("[!] Interface " + str(i+1) + " is in \"Monitor Mode\".")
	
		
	print("\n######################################################\n")
	
def spotFakeAP():
	global savedFile
	global processID
	global processes
	global ssidFound
	
	ssidCapabilities = {}

	print("Fake AP Spotter Module is selected.\"airodump-ng\" window is spawning...")

	# add card selection feature

	savedFile = os.popen("date +%Y-%m-%d_%H-%M-%S | base64").read().strip() 

	spawnMonitor = f"airodump-ng {wirelessInterfaces[0]} --band abg --output-format csv --uptime --write {savedFile}"
	airodumpProcess = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', spawnMonitor])
	processID = airodumpProcess.pid
	processes.append(processID)
	#stdout, stderr = airodumpProcess.communicate()
	time.sleep(5)
	
	#os.kill(processID, signal.SIGTERM)	# now it's unnecessary but let it stay until first release

	print("\n[!] At this point, you have to provide an SSID (preferably, your own SSID) to check whether there is a suspicious (fake) SSID is present.")
	print("[!] Optionally, you may enter your BSSID value to seperate your original AP from others (if there is any)") 
	
	ssid = input("\nEnter target SSID: ")
	
	# Check whether given input is a valid BSSID
	bssid_pattern = re.compile("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
	
	print("\n[!] Do you want to enter BSSID to exclude your own AP? (Format -> AA:BB:CC:DD:EE:FF) - y/n")
	answer = input().lower()
	
	while answer not in ['y', 'n']:
    		answer = input("\nInvalid input. Please enter 'y' or 'n': ").lower()
	
	if answer == 'y':
		while True:
			bssid = input("\nEnter BSSID of original AP: ")
			
			if len(bssid) == 17 and bssid_pattern.match(bssid):
				break

			else:
				print("\nInvalid BSSID format. Please enter in the format of AA:BB:CC:DD:EE:FF")
    	
	def checkBeacon(packet):
		global ssidFound
		
		if packet.haslayer(Dot11Beacon):
			if packet.info.decode('utf-8') == ssid and not ssidFound:
				ssidFound = True
				ssidCapabilities[ssid] = packet[Dot11Beacon].cap	# store unique SSID's to ssidCapabilities list	
				
				bssid = packet[Dot11].addr3.upper()
				
				# --- Calculate Uptime ---
				
				timestamp = packet[Dot11].timestamp

				epoch = datetime.utcfromtimestamp(0)
				beaconTime = epoch + timedelta(microseconds=timestamp)	# actual uptime + epoch | ALL THE FUCKING PROBLEM WAS microseconds=timestamp :))))))))
				uptime = beaconTime - epoch
				uptimeStr = str(uptime).split('.')[0]
				
				# --- Calculate Uptime ---	
				
				print(f"[+] Found SSID \"{ssid}\" w/BSSID value \"{bssid}\". AP's uptime: {uptimeStr}")
		
	sniff(iface=wirelessInterfaces[0], prn=checkBeacon, store=0)
    	
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
		
		print("DONE!")

	# Restore card interfaces

	for i in range(len(changedCards)):
		message = "\nRestoring Wireless Interface " + str(i+1) +  " to \"Managed Mode\""
		
		for char in message:
			print(char, end = "", flush = True)
			time.sleep(0.05)
		print()
		
		subprocess.call(['sudo', 'ifconfig', changedCards[i], 'down'])
		subprocess.call(['sudo', 'iwconfig', wirelessInterfaces[i], 'mode', 'managed'])	
		subprocess.call(['sudo', 'ifconfig', changedCards[i], 'up'])
		
		print("\n[+] Wireless Interface " + str(i+1) + " restored to \"Managed Mode\"!")

def main():
	
	print("""
	
	$$$$$$$\  $$\           $$\       $$\      $$\            $$\               $$\       
	$$  __$$\ \__|          $$ |      $$ | $\  $$ |           $$ |              $$ |      
	$$ |  $$ |$$\  $$$$$$\  $$$$$$$\  $$ |$$$\ $$ | $$$$$$\ $$$$$$\    $$$$$$$\ $$$$$$$\  
	$$$$$$$\ |$$ |$$  __$$\ $$  __$$\ $$ $$ $$\$$ | \____$$\\_$$  _|  $$  _____|$$  __$$\ 
	$$  __$$\ $$ |$$ |  \__|$$ |  $$ |$$$$  _$$$$ | $$$$$$$ | $$ |    $$ /      $$ |  $$ |
	$$ |  $$ |$$ |$$ |      $$ |  $$ |$$$  / \$$$ |$$  __$$ | $$ |$$\ $$ |      $$ |  $$ |
	$$$$$$$  |$$ |$$ |      $$$$$$$  |$$  /   \$$ |\$$$$$$$ | \$$$$  |\$$$$$$$\ $$ |  $$ |
	\_______/ \__|\__|      \_______/ \__/     \__| \_______|  \____/  \_______|\__|  \__|
        
        ######################################################################################
                                       
        	     802.11 Hidden AP & Fake AP Spotter - Developed by Anıl Çelik
        	      
	######################################################################################                                           
	""")

	checkRequirements()
	listInterfaces()
	changeOperatingMode()
	spotFakeAP()
	
	safeExit()
	
if __name__ == '__main__':
	main()
