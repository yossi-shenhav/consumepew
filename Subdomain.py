from scanClass import Scan

class SubdomainsScan(Scan):
	scan_type = 'Subdomains'
	result_file = 'subdomains.txt'
		
	def format_result(self):
		result = {}
		try:
			# Open the file and read the JSON data
			with open(self.directory + "/" + self.result_file, 'r') as file:
				lines = [line.strip() for line in file]				
			indx = 0
			for ln in lines:
				indx +=1
				key = f'subdomain{indx}'
				result[key] = ln
		except Exception as e:
			print("An error occurred:", e) 
			result['error'] = e.args[0]
		
		return result

	def getCommands(self):		
		commands = []
		domain = self.get_domain(self.target)
		commands = [f'assetfinder --subs-only {domain} > {self.directory}/{self.result_file}']
		return commands
		
