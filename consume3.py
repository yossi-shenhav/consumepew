# consume.py
# This is the consumer script
import pika
import json #to parse the message - did not write the code here
import firebase_admin
import time
from scanClass import Scan
from XSSScan import XSSScan
from Subdomain import SubdomainsScan
from FasrPortScan import FNmapScan
from LFIScan import LFIScan
from SSLScan import SSLScan
from NucleiScan import NucleiScan
from HiddenDirs import FfufScan
from firebase_reports import addNewScanData
#from upload import upload_file_to_s3
from smtpmail import sendEmail
from config1 import read_secret, RABBIT_MQ


def callback(ch, method, properties, body):
	print(" [x] Received " + str(body))
	email, scans = parse_message(body)
	indices =[1,2,4,8,16]
	scancnt = len(scans)	#3

	# Start the scan threads
	for scan in scans:
		scan.start_scan_thread()
		print(f'{scan.scan_type} started')

	# Check if the scans are successful
	cnt=0
	while True:
		#print(f'cnt={cnt}')
		time.sleep(0.2)  # Poll every 0.2 second
		
		for scan in scans:
			if scan.done == False:
				if scan.is_ended_successfully():
					print(f'{scan.scan_type} ended')
					cnt = cnt | scan.bitwise
					#set done to True so it will not happen twice
					scan.done = True
					#addnew scan data
					results = scan.format_result()
					print (results)
					addNewScanData(scan.id, scan.scan_type, scan.target, results)
					print ('added to db')
					#upload to S3
					s3obj = f'{scan.id}/{scan.scan_type}/{scan.result_file}'
					file2upload = f'{scan.directory}/{scan.result_file}'
					success = True #upload_file_to_s3(file2upload, s3obj)
						
					#send mail
					try:
						sendEmail(email, scan.id, scan.scan_type, success)
					except Exception as e:
						print('email was not sent: ' , e)

			
		if cnt == (2**scancnt -1):
			#if all scan complted - break out of while true
			break
	
	#maybe send zip file of all results together
	ch.basic_ack(delivery_tag=method.delivery_tag)
	print(f'mission accomplished. cnt:={cnt}')


def start_pulling():
	channel.basic_consume('nucleiscans',
		  	callback,
		  	auto_ack=False)

	print(' [*] Waiting for messages:')
	try:
		channel.start_consuming()
	except KeyboardInterrupt:
		# Handle KeyboardInterrupt to gracefully stop consuming messages
		channel.stop_consuming()
	except Exception as e:
		print('error pulling messages', e)
		channel.stop_consuming()
	
	print('connection closed!!')
	connection.close()
	

def parse_message(message):
	#print (message)
	msg = json.loads(message)
	s_type = msg['email']
	url =msg['tid']
	email = msg['type']	# we should use it to send notification
	tid = msg['url2scan']    # transction id

	scans = []
	#ALLOWED_TYPES = ['XSS', 'subdomain', 'PortScan', 'LFI', 'SSLScan', 'FullScan', 'hiddendir', 'FasrPortScan']
	match s_type:
		case 'XSS':
			scans = [XSSScan(url, tid, 1)]
		case 'subdomain':
			scans = [SubdomainsScan(url, tid, 1)]
		case 'PortScan':
			scans = [NmapScan(url, tid, 1)]
		case 'FastPortScan':
			scans = [FNmapScan(url, tid, 1)]
		case 'SSLScan':
			scans = [SSLScan(url, tid, 1)]
		case 'LFI':
			#for now I use LFI
			scans =  [FNmapScan(url, tid,1), SSLScan(url, tid,2)]
		case 'hiddendir':
			scans = [FfufScan(url, tid, 1)]
		case 'FullScan':
			#I think this should be nuclei
			scans = [NucleiScan(url, tid, 1)]		
	   	
	    #upload_to_firebase(tid, f'~/consume/{tid}/asset_finder.txt') # uploading file to Firebase.
	    
	return email, scans



def consume_messages():
    url = read_secret(RABBIT_MQ) 

    params = pika.URLParameters(url)

    #channel.queue_declare(queue='nucleiscans') # Declare a queue
    #start_pulling()
    
    while True:
        try:
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='nucleiscans', on_message_callback=callback, auto_ack=False)
            print("Consuming messages...")
            channel.start_consuming()
        except pika.exceptions.StreamLostError as e:
            print("Connection lost. Reconnecting...")
        except KeyboardInterrupt:
            print("Stopping consumer...")
            break
        except Exception as e:
            print("Error:", str(e))
        finally:
            try:
                connection.close()
            except:
                pass  # Connection may already be closed


if __name__ == "__main__":
    consume_messages()
 

