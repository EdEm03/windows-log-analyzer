from pathlib import Path
import xml.etree.ElementTree as ET
import time
from datetime import datetime
from dataclasses import dataclass

@dataclass
class EventData:
    event_id: str = None
    time: datetime = None
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
            event_data.time= datetime.fromisoformat(\
                temp.attrib.get("SystemTime").replace("Z","")
            )
    
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


e_log_out = 0
e_log_admin = 0

failed_by_ip = {}

for event in events:
    
    event_data = event_processing(event)     
            
    if event_data.event_id == "4624":
        if event_data.ip in failed_by_ip:
            if failed_by_ip[event_data.ip]["count"] >= 10 and (event_data.time - failed_by_ip[event_data.ip]["start_time"]).total_seconds() <= 300:
                print(f"Successful Brute Forc attempt suspected | {event_data.ip} | {event_data.time}")
        
    elif event_data.event_id=="4625":
        if event_data.ip in failed_by_ip :
            if (event_data.time - failed_by_ip[event_data.ip]["start_time"]).total_seconds() <= 300:
                failed_by_ip[event_data.ip]["count"] += 1
                if failed_by_ip[event_data.ip]["count"] >= 10 and failed_by_ip[event_data.ip]["alerted"] == False:
                    print(f"Brute Force attempt suspected | 10 or more login attempts in a short timeframe | {event_data.ip} |{failed_by_ip[event_data.ip]['start_time']}")
                    failed_by_ip[event_data.ip]["alerted"] = True
            else:
                failed_by_ip[event_data.ip]["count"]=1
                failed_by_ip[event_data.ip]["start_time"]=event_data.time
                failed_by_ip[event_data.ip]["alerted"] = False
        else:
            failed_by_ip[event_data.ip] = {
                "count": 1,
                "start_time": event_data.time,
                "alerted": False
            }      
    elif event_data.event_id=="4634":
        e_log_out+=1
    elif event_data.event_id=="4672":
        e_log_admin+=1