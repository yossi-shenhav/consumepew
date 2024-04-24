from scanClass import Scan
from config1 import WORD_LIST, USER_AGENT, RECURSION_DEPTH


class NucleiScan(Scan):
	scan_type = 'FullScan'
	result_file = 'vuln.txt'
	wordlist = WORD_LIST	
		
	def format_result(self):
		result = {}
		try:
			# Open the file and read the JSON data
			with open(self.directory + "/" + self.result_file, 'r') as file:
				lines = [line.strip() for line in file]				
			indx = 0
			for ln in lines:
				words = ln.split()
				key = words[0]
				value = ' '.join(words[1:])
				result[key] = value
		except Exception as e:
			print("An error occurred:", e) 
			result['error'] = e.args[0]
		
		return result


	def getCommands(self):		
		commands = []
		commands = [f'nuclei -t {self.target} -o {self.directory}/{self.result_file} -es info']
		return commands


