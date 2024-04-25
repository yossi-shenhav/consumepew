#!/usr/bin/env python

import smtplib
import email.mime.text
import os
#from upload import upload2_s3
from config1 import read_secret, GMAIL_ADDRESS, GMAIL_PASSWORD, BUCKET_URL, WEB_URL


from email.mime.text import MIMEText


def sendSMTP(to_email, subject, message):
	from_email = read_secret(GMAIL_ADDRESS)
	pwd = read_secret(GMAIL_PASSWORD)
	msg = MIMEText(message,'html')
	msg['Subject'] = subject
	msg['From'] = from_email
	msg['To'] = to_email
	try:
		s = smtplib.SMTP_SSL('smtp.gmail.com', '465')
		s.set_debuglevel(1)
		s.login(from_email, pwd)
		s.sendmail(from_email, to_email, msg.as_string())
		s.quit()
		print("Email sent successfully!")
	except Exception as e:
		print("Email sending failed:", e)
		#print(f'Email:={from_email},	PWD:={pwd}')		


def sendEmail(email, tid, scantype, success):

    subject = 'Scan results from PewPew'

    if success:
        message = f'<p>Scan results can be found on {BUCKET_URL}/{tid}</p><p>short reprt can be found on {WEB_URL}/reports/{tid}/{scantype}</p>' 
    else:
        print("{tid} Failed to upload file.")
        message = f'<p>Scan #{tid} did not suceeded </p>'

    sendSMTP(email, subject, message)

    return 1
