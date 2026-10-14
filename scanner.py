"""SimpleScanner v2.0 - Scanner de Porturi de Retea.

Folositi exclusiv pe sisteme pentru care aveti autorizatie explicita.
"""
import socket
import sys
from datetime import datetime
import concurrent.futures


def obtine_nume_serviciu(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "necunoscut"


def scaneaza_port(ip, port):
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(0.5)
    try:
        rezultat = scanner.connect_ex((ip, port))
        return port if rezultat == 0 else None
    except Exception:
        return None
    finally:
        scanner.close()


def afiseaza_banner():
    print("""
    ================================================
      ____  _                 _   ____
     / ___|(_)_ __ ___  _ __ | | / ___|  ___ __ _ _ __
     \\___ \\| | '_ ` _ \\| '_ \\| | \\___ \\ / __/ _` | '_ \\
      ___) | | | | | | | |_) | |  ___) | (_| (_| | | | |
     |____/|_|_| |_| |_| .__/|_| |____/ \\___\\__,_|_| |_|
                       |_|
    ================================================
    """)


if __name__ == "__main__":
    afiseaza_banner()
    domeniu_tinta = input("Introdu adresa IP sau Domeniul de scanat (ex: scanme.nmap.org): ")
    try:
        ip_tinta = socket.gethostbyname(domeniu_tinta)
    except socket.gaierror:
        print("\n[!] Eroare: Domeniul introdus nu a putut fi gasit.")
        sys.exit()

    print("-" * 50)
    print(f"[*] Tinta confirmata: {domeniu_tinta} ({ip_tinta})")
    timp_start = datetime.now()
    porturi_deschise = 0
    lista_rezultate = []

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            task_uri = [executor.submit(scaneaza_port, ip_tinta, port) for port in range(1, 1025)]
            for task in concurrent.futures.as_completed(task_uri):
                port_gasit = task.result()
                if port_gasit is not None:
                    nume_serv = obtine_nume_serviciu(port_gasit)
                    print(f"[+] Portul {port_gasit} ({nume_serv.upper()}) este DESCHIS")
                    porturi_deschise += 1
                    lista_rezultate.append((port_gasit, nume_serv))
    except KeyboardInterrupt:
        print("\n[!] Scanare intrerupta de utilizator. Se genereaza raportul partial...")

    timp_sfarsit = datetime.now()
    durata_totala = timp_sfarsit - timp_start
    print("-" * 50)
    print(f"[*] Scanare finalizata!")
    print(f"[*] Total porturi deschise gasite: {porturi_deschise}")
    print(f"[*] Timp total de executie: {durata_totala.total_seconds():.2f} secunde")

    if porturi_deschise > 0:
        nume_fisier = f"scanare_{ip_tinta}.txt"
        lista_rezultate.sort(key=lambda x: x[0])
        try:
            with open(nume_fisier, "w") as fisier:
                fisier.write(f"=== RAPORT SCANARE: {domeniu_tinta} ({ip_tinta}) ===\n")
                fisier.write(f"Data si ora: {timp_start.strftime('%d-%m-%Y %H:%M:%S')}\n")
                fisier.write("-" * 50 + "\n")
                for port, serviciu in lista_rezultate:
                    fisier.write(f"PORT: {port:<6} | SERVICIU: {serviciu.upper():<12} | STARE: DESCHIS\n")
                fisier.write("-" * 50 + "\n")
                fisier.write(f"Total porturi deschise: {porturi_deschise}\n")
                fisier.write(f"Durata scanarii: {durata_totala.total_seconds():.2f} secunde\n")
            print(f"[*] RAPORT SALVAT: Rezultatele au fost exportate in '{nume_fisier}'")
        except Exception as eroare:
            print(f"[!] Eroare la salvarea fisierului: {eroare}")

    print("=" * 48)
