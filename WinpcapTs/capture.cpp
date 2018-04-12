#include <stdio.h>
#include <string.h>
#include <pcap.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

#define LINE_LEN 16
#define MAX_ADDR_LEN 16
FILE *file = 0;//��������ץ�����

//�Ը���Э������ݽṹ���з�װ

//��̫��Э���ʽ
typedef struct ether_header{
	u_char ether_dhost[6];	//Ŀ��mac��ַ
	u_char ether_shost[6];	//Դmac��ַ
	u_short ether_type;		//��̫������
}ether_header;
//IP��ַ
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

//IPV4���ݱ�ͷ��
typedef struct ip_header{
	u_char version_hlen;	//�ײ����ȡ��汾
	u_char tos;				//��������
	u_short tlen;			//�ܳ���
	u_short identification;	//���ʶ��
	u_short flags_offset;	//��ʶ ����ƫ��
	u_char ttl;				//����ʱ��
	u_char proto;			//Э������
	u_short checksum;		//ͷ��У���
	u_int saddr;			//ԴIP��ַ
	u_int daddr;			//Ŀ��IP��ַ
}ip_header;

//TCPͷ��
typedef struct tcp_header{
	u_short sport;			//Դ�˿ں�
	u_short dport;			//Ŀ�Ķ˿ں�
	u_int sequence;			//������
	u_int ack;				//�ظ���
	u_char hdrLen;			//�ײ����� ������
	u_char flags;			//��־
	u_short windows;		//���ڴ�С
	u_short checksum;		//У���
	u_short urgent_p;		//����ָ��
}tcp_header;

//UDPͷ��
typedef struct udp_header{
	u_short sport;			//Դ�˿ں�
	u_short dport;			//Ŀ�Ķ˿ں�
	u_short datalen;		//���ݳ���
	u_short checksum;		//У���
}udp_header;

//ICMPͷ��
typedef struct icmp_header{
	u_char type;			//ICMP����
	u_char code;			//����
	u_short checksum;		//У���
	u_short identification;	//��ʶ
	u_short sequence;		//���к�
	u_long timestamp;		//ʱ���
}icmp_header;

//ARPͷ��
typedef struct arp_header{
	u_short hardware_type;	//��ʽ����Ӳ����ַ
	u_short protocol_type;	//��ַЭ���ʽ
	u_char hardware_length;	//Ӳ����ַ����
	u_char protocol_length;	//��ַЭ�鳤��
	u_short operation_code;	//������
	u_char source_ethernet_address[6];//������Ӳ����ַ
	u_char source_ip_address[4];//������Э���ַ
	u_char destination_ethernet_address[6];//Ŀ�ķ�Ӳ����ַ
	u_char destination_ip_address[4];//Ŀ�ķ�Э���ַ
}arp_header;
/*
UDPЭ�鴦�����
u_short sport;			//Դ�˿ں�
u_short dport;			//Ŀ�Ķ˿ں�
u_short datalen;		//���ݳ���
u_short checksum;		//У���
*/

void handle_udp_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	udp_header *udp_protocol;
	udp_protocol = (udp_header*)(pkt_content + 14 + 20);
	printf("===================UDP Protocol=================\n");
	printf("Դ�˿ںţ�%i\n", ntohs(udp_protocol->sport));
	printf("Ŀ�Ķ˿ںţ�%i\n", ntohs(udp_protocol->dport));
	printf("���ݳ���:%i\n", ntohs(udp_protocol->datalen));
	printf("У��ͣ�0x%.4x\n", ntohs(udp_protocol->checksum));
}
/*
TCPЭ�鴦�����
u_short sport;			//Դ�˿ں�
u_short dport;			//Ŀ�Ķ˿ں�
u_int sequence;			//������
u_int ack;				//�ظ���
u_char hdrLen;			//�ײ����� ������
u_char flags;			//��־
u_short windows;		//���ڴ�С
u_short checksum;		//У���
u_short urgent_p;		//����ָ��
*/
void handle_tcp_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	tcp_header *tcp_protocol;
	tcp_protocol = (tcp_header*)(pkt_content + 14 + 20);
	printf("===================TCP Protocol=================\n");
	printf("Դ�˿ںţ�%i\n", ntohs(tcp_protocol->sport));
	printf("Ŀ�Ķ˿ںţ�%i\n", ntohs(tcp_protocol->dport));
	printf("�����룺%d\n", ntohl(tcp_protocol->sequence));
	printf("�ظ���: %d\n", ntohl(tcp_protocol->ack));
	printf("ͷ�����ȣ�%d\n", (tcp_protocol->hdrLen >> 4) * 4);
	printf("��־��0x%.3x", tcp_protocol->flags);
	if (tcp_protocol->flags & 0x08) printf("(PSH)");
	if (tcp_protocol->flags & 0x10) printf("(ACK)");
	if (tcp_protocol->flags & 0x02) printf("(SYN)");
	if (tcp_protocol->flags & 0x20) printf("(URG)");
	if (tcp_protocol->flags & 0x01) printf("(FIN)");
	if (tcp_protocol->flags & 0x04) printf("(RST)");
	printf("\n");
	printf("���ڴ�С��%i\n", ntohs(tcp_protocol->windows));
	printf("У��ͣ�0x%.4x\n", ntohs(tcp_protocol->checksum));
	printf("����ָ�룺%i\n", ntohs(tcp_protocol->urgent_p));
}
// ICMPЭ�鴦��
//u_char type;				// ICMP����
//u_char code;				// ����
//u_short checksum;			// У���
//u_short identification;	// ��ʶ
//u_short sequence;			// ���к�
//u_long timestamp;			// ʱ���
void handle_icmp_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	icmp_header *icmp_protocol;
	icmp_protocol = (icmp_header*)(pkt_content + 14 + 20);
	printf("==================ICMP Protocol=================\n");
	printf("����: %d", icmp_protocol->type);
	switch (icmp_protocol->type)
	{
		case 8:
			printf("(request)\n");
			break;
		case 0:
			printf("(reply)\n");
			break;
		default:
			printf("\n");
			break;
	}
	printf("���룺%d\n", icmp_protocol->code);
	printf("У���: 0x%.4x\n", ntohs(icmp_protocol->checksum));
	printf("��ʶ��0x%.4x\n", ntohs(icmp_protocol->identification));
	printf("���кţ�0x%.4x\n", ntohs(icmp_protocol->sequence));
}
// ARPЭ���������
//u_short hardware_type;					// ��ʽ����Ӳ����ַ
//u_short protocol_type;					// Э���ַ��ʽ
//u_char hardware_length;					// Ӳ����ַ����
//u_char protocol_length;					// Э���ַ����
//u_short operation_code;					// ������
//u_char source_ethernet_address[6];		// ������Ӳ����ַ
//u_char source_ip_address[4];				// ������Э���ַ
//u_char destination_ethernet_address[6];	// Ŀ�ķ�Ӳ����ַ
//u_char destination_ip_address[4];			// Ŀ�ķ�Э���ַ
void handle_arp_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	arp_header *arp_protocol;
	arp_protocol = (arp_header*)(pkt_content+14);
	printf("==================ARP Protocol==================\n");
	printf("Ӳ����ַ��");
	switch (ntohs(arp_protocol->hardware_type))
	{
		case 1:
			printf("Ethernet");
			break;
		default:
			break;
	}
	printf("(%d)\n", ntohs(arp_protocol->hardware_type));
	printf("Э���ַ��ʽ��");
	switch (ntohs(arp_protocol->protocol_type))
	{
		case 0x0800:
			printf("%s", "IP");
			break;
		case 0x0806:
			printf("%s", "ARP");
			break;
		case 0x0835:
			printf("%s", "RARP");
			break;
		default:
			printf("%s", "Unknown Protocol");
			break;
	}
	printf("(0x%04x)\n", ntohs(arp_protocol->protocol_type));
	printf("Ӳ����ַ���ȣ�%d\n", arp_protocol->hardware_length);
	printf("Э���ַ���ȣ�%d\n", arp_protocol->protocol_length);
	printf("�����룺");
	switch (ntohs(arp_protocol->operation_code))
	{
		case 1:
			printf("request");
			break;
		case 2:
			printf("reply");
		default:
			break;
	}
	printf("(%i)\n", ntohs(arp_protocol->operation_code));
}
/*
IPЭ���������
u_char version_hlen;	//�ײ����ȡ��汾
u_char tos;				//��������
u_short tlen;			//�ܳ���
u_short identification;	//���ʶ��
u_short flags_offset;	//��ʶ ����ƫ��
u_char ttl;				//����ʱ��
u_char proto;			//Э������
u_short checksum;		//ͷ��У���
u_int saddr;			//ԴIP��ַ
u_int daddr;			//Ŀ��IP��ַ
*/
void handle_ip_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	ip_header *ip_protocol;
	sockaddr_in source, dest;
	char sourceIP[MAX_ADDR_LEN], destIP[MAX_ADDR_LEN];
	ip_protocol = (ip_header*)(pkt_content + 14);
	source.sin_addr.s_addr = ip_protocol->saddr;
	dest.sin_addr.s_addr = ip_protocol->daddr;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), MAX_ADDR_LEN);
	strncpy(destIP, inet_ntoa(dest.sin_addr), MAX_ADDR_LEN);

	printf("===================IP Protocol==================\n");
	printf("�汾��: %d\n", ip_protocol->version_hlen >> 4);
	printf("ͷ�����ȣ�%d bytes\n", (ip_protocol->version_hlen & 0x0f) * 4);//��00001111B��λ������ǰ��λ��
	printf("����������%d\n", ip_protocol->tos);
	printf("�ܳ��ȣ�%d\n", ntohs(ip_protocol->tlen));
	printf("���ʶ��0x%.4x (%i) \n", ntohs(ip_protocol->identification), ntohs(ip_protocol->identification));
	printf("��ʶ��%d\n", ntohs(ip_protocol->flags_offset) >> 13);
	printf("---����λ��%d\n", (ntohs(ip_protocol->flags_offset) & 0x8000) >> 15);
	printf("---Don't fragment: %d\n", (ntohs(ip_protocol->flags_offset) & 0x4000) >> 14);
	printf("---More fragment: %d\n", (ntohs(ip_protocol->flags_offset) & 0x2000) >> 13);
	printf("�ֶ�ƫ�ƣ�%d\n", ntohs(ip_protocol->flags_offset) & 0x1fff);
	printf("����ʱ�䣺%d\n", ip_protocol->ttl);
	printf("Э�����ͣ�");
	switch (ip_protocol->proto)
	{
	case 1:
		printf("ICMP");
		break;
	case 6:
		printf("TCP");
		break;
	case 17:
		printf("UDP");

	default:
		break;
	}
	printf(" (%d)\n", ip_protocol->proto);
	printf("ͷ��У��ͣ� 0x%.4x\n", ntohs(ip_protocol->checksum));
	printf("Դ��ַ��%s\n", sourceIP);
	printf("Ŀ�ĵ�ַ��%s\n", destIP);
	if (ip_protocol->proto == htons(0x0600)){
		handle_tcp_packet(arg, pkt_header, pkt_content);
	}
	else if (ip_protocol->proto == htons(0x1100)){
		handle_udp_packet(arg, pkt_header, pkt_content);
	}
	else if (ip_protocol->proto == htons(0x0100)){
		handle_icmp_packet(arg,pkt_header,pkt_content);
	}

}
void handle_ethernet_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	ether_header *ethernet_protocol;	//��̫��Э��
	u_short ethernet_type;				//��̫������
	u_char	*mac_string;				//��̫����ַ
	//��ȡ��̫����������
	ethernet_protocol = (ether_header*)pkt_content;
	//��һ��16λ���������ֽ�˳��ת��Ϊ�����ֽ�˳�� 
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	printf("==============Ethernet Protocol=================\n");
	//��̫��Ŀ���ַ
	mac_string = ethernet_protocol->ether_dhost;
	printf("Ŀ��MAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x:\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5));
	//��̫��Դ��ַ
	mac_string = ethernet_protocol->ether_shost;
	printf("ԴMAC��ַ��%02x:%02x:%02x:%02x:%02x:%02x:\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5));
	printf("Ethernet type: ");
	switch (ethernet_type)
	{
	case 0x0800:
		printf("%s", "IP");
		break;
	case 0x0806:
		printf("%s", "ARP");
		break;
	case 0x0835:
		printf("%s", "RARP");
		break;
	default:
		printf("%s", "Unknown Protocol");
		break;
	}
	printf(" (0x%04x)\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		handle_ip_packet(arg, pkt_header, pkt_content);
		break;
	case 0x0806:
		handle_arp_packet(arg, pkt_header, pkt_content);
		break;
	case 0x0835:
		printf("==============RARP Protocol=================\n");
		printf("RARP\n");
		break;
	default:
		printf("==============Unknown Protocol==============\n");
		printf("Unknown Protocol\n");
		break;
	}

}


int main(){

	pcap_if_t *alldevs;//pcap_if_t��һ����������ݽṹ����������ӿڵ���Ϣ��
	pcap_if_t *adapter;//����ĳ��������
	pcap_t *fp;
	int res;
	struct pcap_pkthdr *header;//���ݰ���ͷ��
	const u_char *pkt_data;
	time_t local_tv_sec;//ʱ���
	struct tm *ltime;
	char timestr[16];

	int count = 1;
	int i = 0;
	int inum;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("�����������������б����£�\n");
	//��ȡ�������������б�
	if (pcap_findalldevs(&alldevs, errbuf) == -1){
		fprintf(stderr, "������������������ %s\n", errbuf);
		exit(1);
	}
	//��������������б���Ϣ
	for (adapter = alldevs; adapter != NULL; adapter = adapter->next){
		printf("%d. %s", ++i, adapter->name);
		if (adapter->description){
			printf("(%s)\n", adapter->description);
		}
		else{
			printf(" (No description)\n ");
		}
	}
	if (i == 0){
		printf("\n δ�ҵ���������������������ȷ���Ѱ�װ��WinPcap!\n");
		return -1;
	}
	//ѡ��������
	while (1)
	{
		printf("��ѡ����������ţ�1-%d): ", i);
		scanf("%d", &inum);
		if (inum > 0 && inum <= i){
			break;
		}
	}
	//��ת����ѡ���������
	for (adapter = alldevs, i = 0; i < inum - 1; ++i, adapter = adapter->next);
	//��������
	if ((fp = pcap_open_live(adapter->name, 65536, 1, 1000, errbuf)) == NULL){
		fprintf(stderr, "\n �����������ִ���%s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}
	//�����·�������
	if (pcap_datalink(fp) != DLT_EN10MB){
		fprintf(stderr, "������ֻ������̫������������\n");
		pcap_close(fp);
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("ץ��������������......\n");
	printf("�����ļ�����Ϊ\"data.txt\"\n");
	printf("���� \"ctrl+ C\" ��ֹץ��\n");
	if ((file = freopen("data.txt", "w", stdout)) == 0){
		printf("�޷����ĵ���/n");
	}
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (res == 0){
			//��ʱ�����
			continue;
		}
		//��ʱ���ת��Ϊ��ʶ��ĸ�ʽ
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
		//���ץȡ�İ��ı�š�ʱ�䡢����
		printf("==============================================================================\n");
		printf("NO.%d\ttime: %s\tlen:%ld\n", count++, timestr, header->len);
		printf("==============================================================================\n");
		char temp[LINE_LEN + 1];
		//�����
		for (i = 0; i < header->caplen; i++)
		{	//��ʮ���������
			printf("%.2x ", pkt_data[i]);
			if (isgraph(pkt_data[i]) || pkt_data[i] == ' '){
				temp[i%LINE_LEN] = pkt_data[i];
			}
			else{
				temp[i%LINE_LEN] = '.';
			}
			if (i%LINE_LEN == 15){
				temp[16] = '\0';
				printf("        ");
				printf("%s", temp);
				printf("\n");
				memset(temp, 0, LINE_LEN);
			}
		}
		printf("\n");
		//�������ݰ�
		handle_ethernet_packet(NULL, header, pkt_data);
	}

	if (res == -1){
		printf("��ȡ�����ִ���%s\n", pcap_geterr(fp));
		pcap_close(fp);
		pcap_freealldevs(alldevs);
		fclose(stdin);
		if (file){
			fclose(file);
		}
		return -1;
	}

	//�ͷ��豸���ļ���
	pcap_close(fp);
	pcap_freealldevs(alldevs);
	fclose(stdin);
	if (file)
	{
		fclose(file);
	}
	return 0;
}