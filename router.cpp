extern "C"
{
    #include "skel.h"
}

#include <vector>
#include <queue>
#include <stdint.h>
#include <iostream>
#include <algorithm>
using namespace std;

struct arp_table_entry {
        uint32_t ip;
        uint8_t mac[6];
};
struct route_table_entry {
        uint32_t prefix;
        uint32_t next_hop;
        uint32_t mask;
        int interface;
};


/* pentru debugging */
void printMAC(uint8_t* mac) {
	for (size_t i = 0; i < 5; i++) {
		printf("%x:", mac[i]);
	}
	printf("%x\n", mac[5]);
}
void printIP(unsigned int ip) {
    struct in_addr obj;
    obj.s_addr = ip;
    printf("%s ", inet_ntoa(obj));
}

class ARP_Table {
private:
	vector<arp_table_entry> entries;
public:
	void addEntry(arp_table_entry e) {
		entries.push_back(e);
	}
	arp_table_entry* getEntry(uint32_t ip) {
		for (size_t i = 0; i < entries.size(); i++) {
			if (ip == entries[i].ip)
				return &entries[i];
		}
		return nullptr;
	}
	size_t getSize() { return entries.size(); }
	arp_table_entry* getEntryAt(int i) {return &entries[i]; }
};
class ROUTER_Table {
private:
  	vector<route_table_entry> entries;

public:
  	void addEntry(route_table_entry e) { entries.push_back(e); }
  	route_table_entry* getBestRoute(uint32_t dest_ip) {
	  	struct route_table_entry *bestMatch = nullptr;
		int left = 0, right = entries.size() - 1;
		while(left <= right) {
			int mid = (left + right) / 2;

			// daca se gaseste pe pozitia curenta voi cauta si in continuare
			// sperand sa gasesc un entry cu o masca mai mare
			if (entries[mid].prefix == (dest_ip & entries[mid].mask)) {
				bestMatch = &entries[mid];
				left = mid + 1;
			}
			if (entries[mid].prefix < (dest_ip & entries[mid].mask)) {
				left = mid + 1;
			} else {
				right = mid - 1;
			}
		}
		return bestMatch;
  }
  	static ROUTER_Table* parseRTable(char* filename) {
		ROUTER_Table* entryTable = new ROUTER_Table;

		FILE* f = fopen(filename, "r");

		char line[100];
		int pref[4], nexth[4], mask[4], interf;

		while (fgets(line, 100, f)) {
			sscanf(line, "%d.%d.%d.%d %d.%d.%d.%d %d.%d.%d.%d %d",
							&pref[0], &pref[1], &pref[2], &pref[3],
								&nexth[0], &nexth[1], &nexth[2], &nexth[3],
									&mask[0], &mask[1], &mask[2], &mask[3],
										&interf);

			entryTable->addEntry(route_table_entry{
				(uint32_t) (pref[3] << 24) + (pref[2] << 16) + (pref[1] <<  8) +  pref[0],
				(uint32_t) (nexth[3] << 24) + (nexth[2] << 16) + (nexth[1] <<  8) +  nexth[0],
				(uint32_t) (mask[3] << 24) + (mask[2] << 16) + (mask[1] <<  8) +  mask[0],
				interf});
		}

		// sortarea dupa prefix si dupa masca
		sort(entryTable->entries.begin(), entryTable->entries.end(),
			[](const route_table_entry& a, const route_table_entry& b) -> bool {
				if (a.prefix == b.prefix) {
					return a.mask < b.mask;
				} else return a.prefix < b.prefix;
			});


		fclose(f);

		return entryTable;
	}
};

/*
 * Implementare conform ecuatiei 4 din RFC 1624
 * (sursa https://tools.ietf.org/html/rfc1624)
 *
 *  HC' = HC - ~m - m'    --    [Eqn. 4]  unde
 *
 *  HC  - vechiul checksum
 *  HC' - noul checksum
 *  m   - vechea valoare a unui field oarecare pe 16 biti din header
 *  m'  - noua valoare a aceluiasi field pe 16 biti
 *
*/
uint16_t incrementalChecksum(uint16_t oldChecksum, uint16_t oldValue, uint16_t newValue) {
	return oldChecksum - ~(oldValue - 1) - newValue;
}

int main(int argc, char *argv[]) {
	setvbuf(stdout , NULL , _IONBF , 0);
	init(argc - 2, argv + 2);

	queue<packet> toBeSent;
  	ROUTER_Table* routerTable = ROUTER_Table::parseRTable(argv[1]);
	ARP_Table arpTable;

	while (true) {
		packet m;
		int rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *ethHDR = (struct ether_header *)m.payload;
		struct icmphdr* icmpHDR = parse_icmp(m.payload);
		struct arp_header *arpHDR = parse_arp(m.payload);
		struct iphdr *ipHDR =  (struct iphdr *)(m.payload + sizeof(struct ether_header));

		uint8_t mac[ETH_ALEN];
		const char *ip = get_interface_ip(m.interface);
		get_interface_mac(m.interface, mac);
		struct in_addr inp;
		inet_aton(ip, &inp);

		// pachet icmp echo
		if (icmpHDR && inp.s_addr == ipHDR->daddr && icmpHDR->type == ICMP_ECHO) {
			uint16_t checkSum = icmpHDR->checksum;
			icmpHDR->checksum = 0;
			if (checkSum != icmp_checksum((uint16_t *)icmpHDR, sizeof(struct icmphdr))) {
				continue;
			}

			send_icmp(ipHDR->saddr, ipHDR->daddr,
					ethHDR->ether_dhost, ethHDR->ether_shost,
					0, 0, m.interface, 0, 0);
			continue;
		}

		// pachet arp
		if (arpHDR) {
			if (arpHDR->op == htons(ARPOP_REQUEST)) {
				{
					arp_table_entry* e = arpTable.getEntry(arpHDR->spa);
					if (!e) {
						arp_table_entry newEntry{};
						newEntry.ip = arpHDR->spa;
						memcpy(newEntry.mac, arpHDR->sha, ETH_ALEN);
						arpTable.addEntry(newEntry);
					}
				}

				struct ether_header tmpEthHDR{};
				tmpEthHDR.ether_type = htons(ETHERTYPE_ARP);
				memcpy(tmpEthHDR.ether_dhost, ethHDR->ether_shost, ETH_ALEN);
				get_interface_mac(m.interface, tmpEthHDR.ether_shost);

				send_arp(arpHDR->spa, arpHDR->tpa, &tmpEthHDR, m.interface, htons(ARPOP_REPLY));
			} else if (arpHDR->op == htons(ARPOP_REPLY)) {
				{  // new device
					arp_table_entry* e = arpTable.getEntry(arpHDR->spa);
					if (e)
						continue;
				}

				arp_table_entry e;
				e.ip = arpHDR->spa;
				memcpy(e.mac, ethHDR->ether_shost, ETH_ALEN);
				arpTable.addEntry(e);

				// trimite pachetele ramase pe coada
				queue<packet> tmpQ;
				while (!toBeSent.empty()) {
					packet p = toBeSent.front();

					toBeSent.pop();

					struct iphdr *tmp_ipHDR = (struct iphdr *)(p.payload + sizeof(struct ether_header));

					route_table_entry* bestRoute = routerTable->getBestRoute(tmp_ipHDR->daddr);

					if (bestRoute->next_hop == arpHDR->spa) {
						struct ether_header *tmp_ethHDR = (struct ether_header *)p.payload;

						memcpy(tmp_ethHDR->ether_dhost, e.mac, ETH_ALEN);
						memcpy(tmp_ethHDR->ether_shost, mac, ETH_ALEN);

						send_packet(bestRoute->interface, &p);
					} else {
						tmpQ.push(p);
					}
				}
				toBeSent.swap(tmpQ);
			}
			continue;
		}

		// pachet expirat?
		if (ipHDR->ttl <= 1) {
			send_icmp(ipHDR->saddr, ipHDR->daddr,
					ethHDR->ether_dhost, ethHDR->ether_shost,
					ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, m.interface, 0, 0);
			continue;
		}

		// test checksum
		uint16_t checkSumIP = ipHDR->check;
		ipHDR->check = 0;
		if (checkSumIP != ip_checksum(ipHDR, sizeof(struct iphdr)))
			continue;


		// update
		ipHDR->ttl--;
		ipHDR->check = incrementalChecksum(checkSumIP, ipHDR->ttl + 1, ipHDR->ttl);


		// ip packet / forward
		if (ethHDR->ether_type == htons(ETHERTYPE_IP)) {
			route_table_entry* bestRoute = routerTable->getBestRoute(ipHDR->daddr);

			if (!bestRoute) { // destination unreachable / n-am ruta catre destinatie
				send_icmp_error(ipHDR->saddr, ipHDR->daddr,
					ethHDR->ether_dhost, ethHDR->ether_shost,
					ICMP_DEST_UNREACH, ICMP_NET_UNREACH, m.interface);
				continue;
			}
			printIP(bestRoute->prefix);
			printIP(bestRoute->next_hop);
			printIP(bestRoute->mask);
			cout << "\n";
			arp_table_entry* e = arpTable.getEntry(bestRoute->next_hop);

			if (e) { // am arp entry
				memcpy(ethHDR->ether_dhost, e->mac, ETH_ALEN);
				get_interface_mac(bestRoute->interface, ethHDR->ether_shost);

				send_packet(bestRoute->interface, &m);
			} else { // nu am arp entry
				toBeSent.push(m);

				struct ether_header tmpEthHDR{};
				tmpEthHDR.ether_type = htons(ETHERTYPE_ARP);
				get_interface_mac(bestRoute->interface, tmpEthHDR.ether_shost);
				hwaddr_aton("FF:FF:FF:FF:FF:FF", tmpEthHDR.ether_dhost);

				const char *ipBR = get_interface_ip(bestRoute->interface);
				struct in_addr inpBR;
				inet_aton(ipBR, &inpBR);

				send_arp(bestRoute->next_hop, inpBR.s_addr, &tmpEthHDR,
								bestRoute->interface, htons(ARPOP_REQUEST));
			}
		}
	}


  	delete routerTable;
	return 0;
}
