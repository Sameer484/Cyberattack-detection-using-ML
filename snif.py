import csv
import time
import traceback
import joblib
import subprocess
import socket 

from scapy.layers.inet import TCP
from scapy.sendrecv import sniff
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import os 
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import train
from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

import warnings

warnings.filterwarnings("ignore")

f = open("output_logs.csv", "w")
w = csv.writer(f)

current_flows = {}
FlowTimeout = 600

global X
global Y
global normalisation
global classifier

global previp

def get_local_ip():
    try:
        # This assumes that you have an active network connection
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error:
        return None

def send_email(subject, body):
    sender_email = "076bei031.sachin@pcampus.edu.np"  
    receiver_email = "sachinsapkota773@gmail.com"  
    password = "00019879@aA"      

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    message.attach(MIMEText(body, "plain"))

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())



def classify(features, srcip=None):
    # print(srcip)
    
    def blockip(ip):
        print("blocking ip " + str(ip))
        command = f"sudo iptables -I FORWARD -s {ip} -j DROP"
        subprocess.run(command , shell=True)

    # preprocess
    f = features
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features]

    if np.nan in features:
        return

    features = normalisation.transform([features])
    result = classifier.predict(features)


    feature_string = [str(i) for i in f]
    classification = [str(result[0])]
    if result != "Benign" and srcip != get_local_ip():

        print(str(classification[0]) + " from ip " + str(srcip))
        blockip(srcip)
        notify_message = f"Attack detected from IP {srcip}"
        os.system(f"notify-send 'Attack Detected' '{notify_message}'")
        subject = "Security Alert: Attack Detected"
        body = f"An attack has been detected from IP {srcip}. Take appropriate action."
        send_email(subject, body)


    w.writerow(feature_string + classification)

    return feature_string + classification


def newPacket(p):
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        # print(p[TCP].flags, packet.getFINFlag(), packet.getSYNFlag(), packet.getPSHFlag(), packet.getACKFlag(),packet.getURGFlag() )

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            # check for timeout
            # for some reason they only do it if packet count > 1
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            # check for fin flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, "fwd")
                classify(flow.terminated(), packet.getSrc())
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, "fwd")
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, "bwd")
                classify(flow.terminated(), packet.getSrc())
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, "bwd")
                current_flows[packet.getBwdID()] = flow
        else:
            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow
            # current flows put id, (new) flow

    except AttributeError:
        # not IP or TCP
        return

    except:
        traceback.print_exc()


def live():
    print("Begin Sniffing".center(20, " "))
    sniff(iface="wlan0", prn=newPacket)
    for f in current_flows.values():
        classify(f.terminated())


def pcap(f):
    sniff(offline=f, prn=newPacket)
    for flow in current_flows.values():
        classify(flow.terminated())


def main(mode, pcap_file):
    # print(" Training ".center(20, "~"))
    global X, Y, normalisation, classifier
    # x_train, y_train, min_max_scaler = train.dataset()
    # X = x_train
    # Y = y_train
    normalisation = joblib.load("normalisation_scaler.pkl")

    classifier = joblib.load("trained_model.pkl")

    print(" Sniffing ".center(20, "*"))
    if mode == 0:
        live()
    else:
        pcap(pcap_file)


if __name__ == "__main__":
    main()
    f.close()
