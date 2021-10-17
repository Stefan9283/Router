# Tema 1 - PC
Toma Stefan-Madalin 323CC

Exista 3 variabile declarate in afara loop-ului:
- o tabela de routare constanta
- o tabela ARP dinamica
- un queue pentru pachetele care nu au fost trimise

La fiecare iteratie se obtine un nou pachet, se parseaza toate headerele
din pachetul primit si in functie de tipul pachetului se alege o ramura anume.

Ramurile si operatiile lor sunt:

- ICMP (se accepta doar daca sunt destinate router-ului) => trimite reply
- ARP (se accepta toate)
    - request => salveaza datele legate de sender apoi ii trimite adresa MAC
    - reply   => daca nu detine un entry in arp entry il salveaza si neaparat
                 trimite pachetele care aveau nevoie de adresa MAC primita
(verificari de ttl si checksum intre ARP si IP + update-ul celor doua campuri)
- IP
    - router-ul cunoaste adresa MAC a destinatarului => trimite pachetul
    - nu cunoaste destinatarul => salveaza in queue pachetul si trimite
       un ARP request pe cea mai buna interfata

Bonus:
    - cautarea in tabela de routare se face folosind binary search
    - incremental checksum (RFC 1624) folosit pentru a schimba checksum-ul
      dupa modificarea ttl-ului

