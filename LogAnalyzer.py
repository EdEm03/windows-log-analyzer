from pathlib import Path
import xml.etree.ElementTree as ET

file_path = Path(__file__).parent / "SecurityLog.xml"

tree = ET.parse(file_path)
root = tree.getroot()

events = root.findall("{http://schemas.microsoft.com/win/2004/08/events/event}Event")

e_log_in = 0
e_log_try = 0
e_log_out = 0
e_log_admin = 0

for event in events:
    eventid = "szöveg"
    system=event.find("{http://schemas.microsoft.com/win/2004/08/events/event}System")
    
    if system is not None:
        eventid= system.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
        if eventid is not None:
            
            eventid= eventid.text
        else:
            continue
    else:
        continue
            
            
    if eventid == "4624":
        e_log_in +=1
    elif eventid=="4625":
        e_log_try+=1
    elif eventid=="4634":
        e_log_out+=1
    elif eventid=="4672":
        e_log_admin+=1

print(f"Sikeres Bejelentkezések száma: {e_log_in} \nSikertelen Bejelentkezések száma: {e_log_try}\nKijelentkezések száma: {e_log_out}\nAdmin bejelentkezések száma: {e_log_admin}")