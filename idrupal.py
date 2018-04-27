#!/usr/bin/python3
import requests
import argparse
import re

####################################################################################################################################
#					TODO
####################################################################################################################################
# Pull in file of paths
# Do args
# add cve code 7600
#	will need command, function | args
# add cve code 7602
#	will need user, password, command, function | args
# add cve code drupalgedon1 (eh maybe)
#
# Finish fingerpriting of server
#
#
#
####################################################################################################################################
verbose = False
###### FIX PROXY
#proxies = {'http': proxy, 'https': proxy}

def check_version(version):
	cve_2018_7600 = ['7.58', '8.4.6', '8.5.1', 'https://www.drupal.org/sa-core-2018-002']
	cve_2018_7602 = ['7.59', '8.4.8', '8.5.3', 'https://www.drupal.org/sa-core-2018-004']

	if version[0] == "7":
		if version < cve_2018_7600[0]:
			print("[+] Possibly vulnerable to CVE-2018-7600!")
			if verbose == True:
				print("[+] See " + cve_2018_7600[-1] + " for more information.")
		else:
			print("[-] Not vulnerable to CVE-2018-7600!")

		if version < cve_2018_7602[0]:
			print("[+] Possibly vulnerable to CVE-2018-7602!")
			if verbose == True:
				print("[+] See " + cve_2018_7602[-1] + " for more information.")
		else:
			print("[-] Not vulnerable to CVE-2018-7602!")
	elif version[0] == "8":
		if version[2] == "4":
			if version < cve_2018_7600[1]:
				print("[+] Possibly vulnerable to CVE-2018-7600!")
				if verbose == True:
					print("[+] See " + cve_2018_7600[-1] + " for more information.")
			else:
				print("[-] Not vulnerable to CVE-2018-7600!")
			if version < cve_2018_7602[1]:
				print("[+] Possibly vulnerable to CVE-2018-7602!")
				if verbose == True:
					print("[+] See " + cve_2018_7602[-1] + " for more information.")
			else:
				print("[-] Not vulnerable to CVE-2018-7602!")
		elif version[2] == "5":
			if version < cve_2018_7600[2]:
				print("[+] Possibly vulnerable to CVE-2018-7600!")
				if verbose == True:
					print("[+] See " + cve_2018_7600[-1] + " for more information.")
			else:
				print("[-] Not vulnerable to CVE-2018-7600!")
			if version < cve_2018_7602[2]:
				print("[+] Possibly vulnerable to CVE-2018-7602!")
				if verbose == True:
					print("[+] See " + cve_2018_7602[-1] + " for more information.")
			else:
				print("[-] Not vulnerable to CVE-2018-7602!")
	elif version[0] == "6":
		print("[+] Possibly vulnerable to CVE-2018-7600!")
		if verbose == True:
			print("[+] See " + cve_2018_7600[-1] + " for more information.")
		print("[+] Possibly vulnerable to CVE-2018-7602!")
		if verbose == True:
			print("[+] See " + cve_2018_7602[-1] + " for more information.")
	else:
		print("[!] CAN NOT VERIFY IF SITE IF VULNERABLE..." )

def get_version(target):
	version = None
	version_temp = None
	paths = [
			'CHANGELOG.txt',
			'core/CHANGELOG.txt',
			'includes/bootstrap.inc',
			'core/includes/bootstrap.inc',
			'includes/database.inc',
			'includes/database/database.inc',
			'core/includes/database.inc'
		]

	print("[~] Checking the version of " + target)
	for path in paths:
		url = target + path
		if verbose == True:
			print("[~] Checking " + url)
		r = requests.get(url, verify=False)
		if r.status_code == 200:
			if verbose == True:
				print("[+] Page Found!!!")
				print("[~] Checking for version")
			for line in r.text.splitlines():
				if "Drupal" in line:
					v = re.search(r"([\d][.][\d]?[.]?[\d])", line)
					if v is not None:
						if ("7." or "8." or "6.") not in v.group(0):
							version_temp = v.group(0)
						else:
							version = v.group(0)
							break
			if version is not None:
				break

	if version is not None:
		if verbose == True:
			print("[+] Version: " + version + " Found")
		return version
	elif version_temp is not None:
		print("[!] Version: " + version_temp + " Found")
		print("[!] This is more than likely WRONG!!!")
		while True:
			print("[?] Would You Like To Continue? [y/n]")
			choice = input("[#] => ")
			if choice == "y":
				return version_temp
			elif choice == "n":
				raise SystemExit
			else:
				print("[!] INVALID SELECTION.... Select [y/n]")
	else:
		raise SystemExit

def prep_target():
	target = args.target
	# Makes sure target url ends with /. If not append it
	if verbose == True:
		print("[~] Checking if url ends with '/'")
	if not (target.endswith("/")):
		if verbose == True:
			print("[!] Url Did Not End With '/'. Appending It Now.")
		target+=str("/")

	requests.packages.urllib3.disable_warnings()
	version = get_version(target)
	check_version(version)

def main():
	print ()
	print ('+=================================================================================+')
	print ('|                                     iDrupal                                     |')
	print ('|                                    by IAmG0d                                    |')
	print ('+=================================================================================+\n')
	prep_target()


if __name__ == '__main__':
	parser = argparse.ArgumentParser( prog="drupa7-CVE-2018-7602.py",
		formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=50),
		epilog= '''
			This script is used to identify Drupal Installations within a network
		''')

	parser.add_argument("target", help="URL of target Drupal site (ex: http://target.com/)")
	parser.add_argument("-u","--user", help="Username")
	parser.add_argument("-p","--password", help="Password")
	parser.add_argument("-c", "--command", default="id", help="Command to execute (default = id)")
	parser.add_argument("-f", "--function", default="passthru", help="Function to use as attack vector (default = passthru)")
	parser.add_argument("-x", "--proxy", default="", help="Configure a proxy in the format http://127.0.0.1:8080/ (default = none)")
	parser.add_argument("-i", "--input", default="", help="Custom list of files to search for")
	parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Increase output verbosity")
	args = parser.parse_args()

	if args.verbose:
		target = args.target
		verbose = True
	if args.user and args.password:
		user = args.user
		password = args.password
###### FIX PROXY
#	if args.proxy:
#		proxies = {'http': proxy, 'https': proxy}
	main()
