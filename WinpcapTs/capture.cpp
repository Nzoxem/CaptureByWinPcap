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
		}else{
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
		if (inum > 0 && inum < i){
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
	while ((res=pcap_next_ex(fp,&header,&pkt_data)) >= 0)
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
		printf("NO.%d\ttime: %s\tlen:%ld\n",count++,timestr,header->len);
		char temp[LINE_LEN + 1];
		//�����
		for ( i = 0; i < header->caplen; i++)
		{	//��ʮ���������
			printf("%.2x ", pkt_data[i]);
			if (isgraph(pkt_data[i]) || pkt_data[i] == ' '){
				temp[i%LINE_LEN] = pkt_data[i];
			}else{
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