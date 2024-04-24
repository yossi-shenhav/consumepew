import threading
import time
import random
import nmap
import subprocess
import os
import uuid
import tldextract
from config1 import LIB_4_RESULTS


class Scan:
	scan_type = None
	
	def __init__(self, target, scanid, bitwise):
		if self.scan_type is None:
			raise NotImplementedError("Subclasses must implement scan_type")	

		#self.scan_type = self.getscan_type()
		self.id = scanid
		self.target = target
		self.bitwise = bitwise
		self.done = False
		self.result = {}
		self.scan_thread = None
		self.directory = f'{LIB_4_RESULTS}{self.id}/{self.scan_type}'

	def execute_scan(self):
		try:
			os.makedirs(self.directory)
		except FileExistsError:
			#messages can be read more then once
			print('dir exist... not a problem')
		except Exception as e:
			print(f'error building {self.directory}', e)
		
		self.run_command()
		#raise NotImplementedError("Subclasses must implement execute_scan method.")
	
	def start_scan_thread(self):
		self.scan_thread = threading.Thread(target=self.execute_scan)
		self.scan_thread.start()


	def is_ended_successfully(self):
		if self.scan_thread is not None:
			if self.scan_thread.is_alive():  # Check if thread has completed
				return False
			else:
				return True
		return False


	def is_process_running(self):
		if self.scan_thread is not None:
			if self.scan_thread.is_alive():  # Check if thread has completed
				return True
			
		return False


	
	def getCommands(self):
		raise NotImplementedError("Subclasses must implement getCommand method")
	
	
	def get_domain(self, subdomain):
		result = tldextract.extract(subdomain)
		domain = f'{result.domain}.{result.suffix}'
		return domain
		
	
	def run_command(self):
		commands = self.getCommands()
		#print(commands)
		for cmd in commands:
			try:
				# Execute the command in a shell
				process = subprocess.Popen(cmd, shell=True)
				# Wait for the command to complete for a maximum of 2 hours
				process.wait(timeout=7200) #2 hours
				print(f'{cmd} execution completed.')

			except subprocess.TimeoutExpired:
				 # Handle the case where the process did not finish within the timeout
				 print("execution timed out. Terminating the process.")
				 process.terminate()

			except Exception as e:
				print("An error occurred:", e)
		
	
	def format_result(self):
		raise NotImplementedError("Subclasses must implement format_result method.")




