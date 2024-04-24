from scanClass import Scan



class LFIScan(Scan):
	scan_type = 'LFI'
		
	def format_result(self):
		if self.done:
		    return f"{self.scan_type} scan result: {self.result}"
		else:
		    return f"{self.scan_type} scan failed."



	def getCommands(self):
		#I can implement in the subclass later - see if it works
		
		commands = []
		commands = [f'echo  "LFI Data" {self.directory}/lfi.txt', 'sleep 7']	
		return commands
