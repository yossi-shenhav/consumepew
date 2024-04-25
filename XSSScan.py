from scanClass import Scan

class XSSScan(Scan):
	scan_type = 'XSS'
	result_file = 'xss_results.txt'
	error_file = 'xss_erros.txt'
	
	
	def format_result(self):
		result = {}
		try:
			# Open the file and read the JSON data
			with open(self.directory + "/" + self.result_file, 'r') as file:
				lines = [line.strip() for line in file]	
			print (f'lines:={lines}')			
			indx = 0
			for ln in lines:
				print(f'ln:={ln}')
				arr = ln.split()
				key = arr[0][1:-1]
				print(f'key:={key}')
				keyarr = key.split("][")
				key = keyarr[-1]
				result[key] = arr[1]
		except Exception as e:
			print("An error occurred:", e) 
			result['error'] = e.args[0]
		
		return result

		
	def getCommands(self):
		#I can implement in the subclass later - see if it works
		
		commands = []
		commands = [f'katana -u https://{self.target} -o {self.directory}/katana.txt', f'cat {self.directory}/katana.txt | dalfox pipe | tee {self.directory}/{self.result_file}']	
		return commands



