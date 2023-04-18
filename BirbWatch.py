#!/usr/bin/python3

import subprocess
import re
import time

# Global Variables

changedCards = []
wirelessInterfaces = []
operatingMode = ''

def checkRequirements():
	try:
		subprocess.check_call(['which', 'aircrack-ng'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		print("[+] aircrack-ng suite is already installed, script can continue.")
		
		subprocess.check_call(['which', "mdk4"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		print("[+] mdk4 is already installed, script can continue.")
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
					print(char, end="", flush = True)
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
			print("[+] Interface " + str(i+1) + " is in \"Monitor Mode\".")
	
		
	print("\n######################################################\n")
	
def safeExit():
	for i in range(len(changedCards)):
		message = "Restoring Wireless Interface " + str(i+1) +  " to \"Managed Mode\""
		
		for char in message:
			print(char, end="", flush = True)
			time.sleep(0.05)
		print()
		
		subprocess.call(['sudo', 'ifconfig', changedCards[i], 'down'])
		subprocess.call(['sudo', 'iwconfig', wirelessInterfaces[i], 'mode', 'managed'])	
		subprocess.call(['sudo', 'ifconfig', changedCards[i], 'up'])
		
		print("\n[+] Wireless Interface " + str(i+1) + " restored to \"Managed Mode\"!")

def spotFakeAP():
	print("""
	
	######################################################
		      
		      Fake Access Point Spotter
		      
	######################################################
	
	""")
	
	
	
def spotHiddenAP():
	print("""
	
	######################################################
		      
		     Hidden Access Point Spotter
		      
	######################################################
	
	""")
		
	

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
	
	safeExit()
	
if __name__ == '__main__':
	main()
