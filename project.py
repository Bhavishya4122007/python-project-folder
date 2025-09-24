import nmap
import socket
def display_menu():
    print("\n Python Network scanner")
    print("____________________________")
    print("1. Port Scan using socket")
    print("2. Port Sweep using scapy")
    print("3. Port Scan using nmap")
    print("0. Exit")
    print("\n ------------------------------------")

def check_host(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        # socket.AF_INET = IPv4
        # socket.SOCK_STREAM = TCP
        sock.settimeout(1)  

        result = sock.connect_ex((ip, port))  # Try to connect
        if result == 0:
            print(f"Host {ip} is UP on port {port}")
        else:
            print(f"Host {ip} is DOWN on port {port}")
        sock.close()

    except Exception as e:
        print(f"Error: {e}")

from scapy.all import IP , ICMP, sr
def ping_sweep(network): #network = IP range
    active,_ = sr(IP(dst=network)/ICMP(), timeout=2, verbose=False)
#sr = send and receive
    for sent, received in active:
        print(f"Host {received.src} is UP")

def portscannmap(ip_add,port_no):
    nm = nmap.PortScanner()
    nm.scan(ip_add,port_no)
    for host in nm.all_hosts():
        print(f"Host:{host}({nm[host].hostname()})")
        print(f"state:{nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"________________________")
            print(f"Protocal:{proto}")
            lport = nm[host][proto].keys()

            for port in lport:
                state=nm[host][proto][port]['state']
                service=nm[host][proto][port]['name']
                version=nm[host][proto][port]['version']
                print(f"port:{port} \t state: {state} \t service:{service} \t version: {version}")


def main():
    while True:
        display_menu()
        choice = int(input("Enter your choice (0-3): "))
         
        if choice == 1:
            print("You Have Been Selsct :- Port Scan using socket")
            check_host((input("Enter Your Target IP : ")),( int(input("Enter Port No:."))))
        elif choice == 2:
            print("You Have Been select :- Port Sweep using scapy")
            ping_sweep((input("Enter Your Target IP : ")),( int(input("Enter Port No:."))))
        elif choice == 3:
            print("You Have Been Select :- Port Scan using nmap ")
            portscannmap((input("Enter Your IP : ")),(input("Enter Your Rang : ")))
        elif choice == 0:
            print("You have Been Exit")
            break
        else :
            print("Worng NO :- Choice Corrate No:")
        
if __name__ == "__main__":
    main()