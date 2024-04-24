from scanClass import Scan
from XSSScan import XSSScan
from Subdomain import SubdomainsScan
from FasrPortScan import FNmapScan
from LFIScan import LFIScan
from SSLScan import SSLScan
from HiddenDirs import FfufScan
from firebase_reports import addNewScanData

import uuid
import time
import random

if __name__ == "__main__":
	scanid = random.randint(0,1000)	# uuid.uuid4()
	target = 'testphp.vulnweb.com'
	scans = [FfufScan(target,scanid), XSSScan(target, scanid), SubdomainsScan(target, scanid)]
	indices =[1,2,4,8,16]
	scancnt = len(scans)	#3

	# Start the scan threads
	for scan in scans:
		scan.start_scan_thread()
		print(f'{scan.scan_type} stared')

	# Do some other work on the main thread
	#print("Performing other tasks while scanning...")

	# Check if the scans are successful
	cnt=0
	while True:
		#print(f'cnt={cnt}')
		time.sleep(0.2)  # Poll every 0.2 second
		indx = 0
		for scan in scans:					
			if scan.done == False:
				if scan.is_ended_successfully():
				#if scan.is_process_running() == False:
					#addnew scan data
					results = scan.format_result()
					print (results)
					addNewScanData(scan.id, scan.scan_type, scan.target, results)
					#send mail

					#just know when to quit loop
					cnt = cnt | indices[indx]
					#set done to True so it will not happen twice
					scan.done = True
					print(f'{scan.scan_type} ended succecfully')
					
				else:
					print (f'scan {scan.scan_type} is running::::cnt={cnt}')	
			indx +=1		
		if cnt == (2**scancnt -1):
			#if all scan complted - break out of while true
			break
			
	#for scan in scans:
	#	results = scan.format_result()
	#	print (results)
	#	addNewScanData(scan.id, scan.scan_type, scan.target, results)
		 		
	print(f'mission accomplished. cnt:={cnt}')

