from pathlib import Path
import xml.etree.ElementTree as ET
import time
from dataclasses import dataclass

@dataclass
class EventData:
    event_id: str = None
    time: str = None
    user: str = None
    ip: str = None
    logon_type: str = None

def event_processing(event):
    event_data = EventData()
    
    data=event.find("{http://schemas.microsoft.com/win/2004/08/events/event}System")
    
    
    if data is not None:
        temp= data.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
        if temp is not None:
            event_data.event_id= temp.text
        
        temp= data.find("{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
        if temp is not None:
            event_data.time= temp.attrib.get("SystemTime")
    
    data=event.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventData")
    if data is not None:
        
        for elem in data.findall("{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
            name = elem.attrib.get("Name")
    
            if name == "TargetUserName":
                event_data.user = elem.text
        
            elif name == "IpAddress":
                event_data.ip = elem.text
        
            elif name == "LogonType":
                event_data.logon_type = elem.text
                
    return event_data


file_path = Path(__file__).parent / "SecurityLog.xml"

tree = ET.parse(file_path)
root = tree.getroot()

events = root.findall("{http://schemas.microsoft.com/win/2004/08/events/event}Event")

e_log_in = 0
e_log_try = 0
e_log_out = 0
e_log_admin = 0

for event in events:
    
    event_data = event_processing(event)
    
            
            
    if event_data.event_id == "4624":
        e_log_in +=1
    elif event_data.event_id=="4625":
        e_log_try+=1
    elif event_data.event_id=="4634":
        e_log_out+=1
    elif event_data.event_id=="4672":
        e_log_admin+=1

print(f"Sikeres Bejelentkezések száma: {e_log_in} \nSikertelen Bejelentkezések száma: {e_log_try}\nKijelentkezések száma: {e_log_out}\nAdmin bejelentkezések száma: {e_log_admin}")