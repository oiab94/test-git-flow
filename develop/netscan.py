#!bin/python3
import subprocess               # agregado para ip procesing
import ipaddress                # agregado para ip rage manage
import threading                # agregado para threading
import socket                   # agregado para el manejo de la ip y la subnetmask para optener el rango de la red 
import psutil                   # agregado para obener la subnet mask necesario instalar con pip install psutil
import tkinter as tk            # agregado para gui
import concurrent.futures       # agregado para thread pooling
from tkinter import filedialog  # agregado para guardado de texto
class NetScanner:
# funcion para la GUI
    def __init__(self, root):
        self.root = root
        #self.authenticated_username=authenticated_username
        root.title("NetScanner")
        root.geometry("330x480+800+200")

        self.ip_input_label = tk.Label(root, text="Ingrese un rango de red en formato CIDR (ej: 192.168.0.0/24)")
        self.ip_input_label.place(x=2, y=20)

        self.detect_ip_label = tk.Label(root, text="")
        self.detect_ip_label.place(x=20, y=3)

        self.ip_entry = tk.Entry(root)
        self.ip_entry.place(x=100, y=40)

        self.scan_button = tk.Button(root, text="Scan Network", command=self.scan_button_clicked)
        self.scan_button.place(x=10, y=40)

        self.pause_button = tk.Button(root, text="Pausa", command=self.pause_button_clicked)
        self.pause_button.place(x=50, y=71)  
        
        self.pause_button = tk.Button(root, text="Detectar", command=self.detect_button_clicked)
        self.pause_button.place(x=30, y=110)  

        self.reset_button = tk.Button(root, text="Reset", command=self.reset_button_clicked)
        self.reset_button.place(x=110, y=71) 

        self.reset_button = tk.Button(root, text="Ordenar", command=self.sort_button_clicked)
        self.reset_button.place(x=170, y=71)  

        self.reset_button = tk.Button(root, text="Guardar", command=self.save_button_clicked)
        self.reset_button.place(x=250, y=71)

        self.scan_button = tk.Button(root, text="Cargar", command=self.read_button_clicked)
        self.scan_button.place(x=250, y=40) 

        self.reset_button = tk.Button(root, text="Atras", command=self.back_button_clicked)
        self.reset_button.place(x=270, y=110)

        self.result_label = tk.Label(root, text="")
        self.result_label.place(x=100, y=110)  

        self.hosts_text = tk.Text(root, height=20, width=40)
        self.hosts_text.place(x=1, y=150)
        self.paused = False
        
        scrollbar = tk.Scrollbar(root, command=self.hosts_text.yview)
        scrollbar.place(x=310, y=150, height=320) 
        self.hosts_text.config(yscrollcommand=scrollbar.set)

# funcion para restaurar la ventana 
    def restore_dashboard(self):
        self.dash_window.destroy()


# funcion para el boton de guardado
    def save_button_clicked(self):
        lines = self.hosts_text.get("1.0", tk.END).splitlines()

        if not lines:
            self.result_label.config(text="No hay resultados para guardar.")
            return

        initial_dir = "C:/Users/*/Downloads"  

        file_path = filedialog.asksaveasfilename(
            initialdir=initial_dir,
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")])
        
        if file_path:
            with open(file_path, 'w') as file:
                for line in lines:
                    file.write(line + '\n')

            self.result_label.config(text="    Guardado")
        else:
            self.result_label.config(text="Operación cancelada.")


# funcion para el boton de carga
    def read_button_clicked(self):
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(
            title="Elija un lista",
            filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    saved_scans = file.read()
                    self.hosts_text.delete("1.0", tk.END)  
                    self.hosts_text.insert(tk.END, saved_scans)
            except FileNotFoundError:
                self.result_label.config(text="Lista no encontrada.")
        else:
            self.result_label.config(text="No se eligio la lista")


# funcion para el boton de atras
    def back_button_clicked(self):
        from Dashboard import Dashboard  
        self.dash_window = tk.Toplevel(self.root)  
        self.root.withdraw()
        dash = Dashboard(self.dash_window,self.authenticated_username)
        self.dash_window.protocol("WM_DELETE_WINDOW",self.restore_dashboard)


# funcion generar el rango de ip cidr
    def generate_cidr(self,interface_name="Ethernet"):
        try:
            interfaces = psutil.net_if_addrs()
            if interface_name in interfaces:
                for addr in interfaces[interface_name]:
                    if addr.family == socket.AF_INET:
                        ip, subnet_mask = addr.address, addr.netmask
                        break
                else:
                    self.result_label.config(text=f"Interfaz '{interface_name}' no encontrada")
                    return None
                
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
                    self.detect_ip_label.config(text=f"Ip: {ip}\t\tSubnet Mask: {subnet_mask}")
                    return str(network)
                except ValueError as e:
                        self.result_label.config(text=f"Error:{e}")
                        return None
            else:
                self.result_label.config(text=f"Interfaz '{interface_name}' no encontrada")
                return None
        except Exception as e:
            self.result_label.config(text=f"Ocurrio un error: {e}")
            return None
        
            
# funcion para el boton de generar rango
    def detect_button_clicked(self):
        cidr_format = self.generate_cidr(interface_name="Ethernet")
        if cidr_format:
             self.ip_entry.delete(0, tk.END) 
             self.ip_entry.insert(0, cidr_format)
             self.result_label.config(text="")
        else:
            self.result_label.config(text="Fallo al generar")


# funcion para el boton de escaneado
    def scan_button_clicked(self):
        self.paused = False 
        ip_subnet = self.ip_entry.get()
        thread = threading.Thread(target=self.perform_scan, args=(ip_subnet,))
        thread.start()

# funcion para el boton de reset
    def reset_button_clicked(self):
        self.result_label.config(text="")
        self.ip_entry.delete(0, tk.END) 
        self.hosts_text.delete("1.0", tk.END)

# funcion para el boton de ordenar
    def sort_button_clicked(self):
        current_text = self.hosts_text.get("1.0", tk.END)
        lines = [line.strip() for line in current_text.splitlines() if line.strip()]
        sorted_lines = sorted(lines, key=lambda x: ipaddress.IPv4Address(x.split()[0]))
        self.hosts_text.delete("1.0", tk.END)
        for line in sorted_lines:
            self.hosts_text.insert(tk.END, line + "\n")
    
    
# funcion para el boton de pausa
    def pause_button_clicked(self):
        self.paused = True
    
# funcion que realiza el escan
    def perform_scan(self, ip_subnet):
        self.result_label.config(text="Escaneo en progreso... 0%")
        self.hosts_text.delete("1.0", tk.END)

        try:
            network = ipaddress.ip_network(ip_subnet, strict=False)
        except ValueError:
            self.result_label.config(text="Formato de ip no valido.")
            return

        total_hosts = len(list(network.hosts()))
        scanned_hosts = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self.scan_host, str(ip)): ip for ip in network.hosts()}

                for future in concurrent.futures.as_completed(futures):
                    if self.paused:
                        self.result_label.config(text="Escaneo pausado")
                        break  
                    ip = futures[future]
                    scanned_hosts += 1
                    progress = int((scanned_hosts / total_hosts) * 100)
                    self.result_label.config(text=f"Escaneo en progreso...... {progress}%")
        if not self.paused:
            self.result_label.config(text="Escaneo completo!")

# funcuion que imprime los ips escaneados que responden
    def scan_host(self, ip):
        if ping_ip(ip):
            self.display_result(ip + " Responde")
        

# funcuion que imprime la lista de ips escaneados
    def display_result(self, message):
        self.hosts_text.insert(tk.END, message + "\n")


# funcion para ping
def ping_ip(ip):
    try:
        output = subprocess.check_output(['ping', '-n', '1', ip], universal_newlines=True)
        if "bytes=32" in output:  
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False


# funcion que da inicio al loop de la GUI 
def main():
    root = tk.Tk()
    scanner = NetScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()


