from scanClass import Scan

class XSSScan(Scan):
	scan_type = 'XSS'
	result_file = 'xss_results.json'
	error_file = 'xss_erros.txt'
	
	def format_result(self):
		if self.done:
		    return f"{self.scan_type} scan result: {self.result}"
		else:
		    return f"{self.scan_type} scan failed."

	def getCommands(self):
		#I can implement in the subclass later - see if it works
		
		commands = []
		commands = [f'echo  "XSS Data" {self.directory}/lfi.txt', 'nuclei -l {} -o {self.direcory}/{self.result_file} -elog {self.direcory}/{self.error_file} -tags xss']	
		return commands
