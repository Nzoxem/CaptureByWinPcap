#include <stdio.h>
#include <string.h>
#include <pcap.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

#define LINE_LEN 16
#define MAX_ADDR_LEN 16
FILE *file = 0;//用来保存抓包结果

//对各个协议的数据结构进行封装

//以太网协议格式
typedef struct ether_header{
	u_char ether_dhost[6];	//目的mac地址
	u_char ether_shost[6];	//源mac地址
	u_short ether_type;		//以太网类型
}ether_header;
//IP地址
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

//IPV4数据报头部
typedef struct ip_header{
	u_char version_hlen;	//首部长度、版本
	u_char tos;				//服务质量
	u_short tlen;			//总长度
	u_short identification;	//身份识别
	u_short flags_offset;	//标识 分钟偏移
	u_char ttl;				//生存时间
	u_char proto;			//协议类型
	u_short checksum;		//头部校验和
	u_int saddr;			//源IP地址
	u_int daddr;			//目的IP地址
}ip_header;

//TCP头部
typedef struct tcp_header{
	u_short sport;			//源端口号
	u_short dport;			//目的端口号
	u_int sequence;			//序列码
	u_int ack;				//回复码
	u_char hdrLen;			//首部长度 保留字
	u_char flags;			//标志
	u_short windows;		//窗口大小
	u_short checksum;		//校验和
	u_short urgent_p;		//紧急指针
}tcp_header;

//UDP头部
typedef struct udp_header{
	u_short sport;			//源端口号
	u_short dport;			//目的端口号
	u_short datalen;		//数据长度
	u_short checksum;		//校验和
}udp_header;

//ICMP头部
typedef struct icmp_header{
	u_char type;			//ICMP类型
	u_char code;			//代码
	u_short checksum;		//校验和
	u_short identification;	//标识
	u_short sequence;		//序列号
	u_long timestamp;		//时间戳
}icmp_header;

//ARP头部
typedef struct arp_header{
	u_short hardware_type;	//格式化的硬件地址
	u_short protocol_type;	//地址协议格式
	u_char hardware_length;	//硬件地址长度
	u_char protocol_length;	//地址协议长度
	u_short operation_code;	//操作码
	u_char source_ethernet_address[6];//发送者硬件地址
	u_char source_ip_address[4];//发送者协议地址
	u_char destination_ethernet_address[6];//目的方硬件地址
	u_char destination_ip_address[4];//目的方协议地址
}arp_header;
/*
UDP协议处理解析
u_short sport;			//源端口号
u_short dport;			//目的端口号
u_short datalen;		//数据长度
u_short checksum;		//校验和
*/

void handle_udp_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	udp_header *udp_protocol;
	udp_protocol = (udp_header*)(pkt_content + 14 + 20);
	printf("===================UDP Protocol=================\n");
	printf("源端口号：%i\n", ntohs(udp_protocol->sport));
	printf("目的端口号：%i\n", ntohs(udp_protocol->dport));
	printf("数据长度:%i\n", ntohs(udp_protocol->datalen));
	printf("校验和：0x%.4x\n", ntohs(udp_protocol->checksum));
}
/*
TCP协议处理解析
u_short sport;			//源端口号
u_short dport;			//目的端口号
u_int sequence;			//序列码
u_int ack;				//回复码
u_char hdrLen;			//首部长度 保留字
u_char flags;			//标志
u_short windows;		//窗口大小
u_short checksum;		//校验和
u_short urgent_p;		//紧急指针
*/
void handle_tcp_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	tcp_header *tcp_protocol;
	tcp_protocol = (tcp_header*)(pkt_content + 14 + 20);
	printf("===================TCP Protocol=================\n");
	printf("源端口号：%i\n", ntohs(tcp_protocol->sport));
	printf("目的端口号：%i\n", ntohs(tcp_protocol->dport));
	printf("序列码：%d\n", ntohl(tcp_protocol->sequence));
	printf("回复码: %d\n", ntohl(tcp_protocol->ack));
	printf("头部长度：%d\n", (tcp_protocol->hdrLen >> 4) * 4);
	printf("标志：0x%.3x", tcp_protocol->flags);
	if (tcp_protocol->flags & 0x08) printf("(PSH)");
	if (tcp_protocol->flags & 0x10) printf("(ACK)");
	if (tcp_protocol->flags & 0x02) printf("(SYN)");
	if (tcp_protocol->flags & 0x20) printf("(URG)");
	if (tcp_protocol->flags & 0x01) printf("(FIN)");
	if (tcp_protocol->flags & 0x04) printf("(RST)");
	printf("\n");
	printf("窗口大小：%i\n", ntohs(tcp_protocol->windows));
	printf("校验和：0x%.4x\n", ntohs(tcp_protocol->checksum));
	printf("紧急指针：%i\n", ntohs(tcp_protocol->urgent_p));
}
// ICMP协议处理
//u_char type;				// ICMP类型
//u_char code;				// 代码
//u_short checksum;			// 校验和
//u_short identification;	// 标识
//u_short sequence;			// 序列号
//u_long timestamp;			// 时间戳
void handle_icmp_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	icmp_header *icmp_protocol;
	icmp_protocol = (icmp_header*)(pkt_content + 14 + 20);
	printf("==================ICMP Protocol=================\n");
	printf("类型: %d", icmp_protocol->type);
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
	printf("代码：%d\n", icmp_protocol->code);
	printf("校验和: 0x%.4x\n", ntohs(icmp_protocol->checksum));
	printf("标识：0x%.4x\n", ntohs(icmp_protocol->identification));
	printf("序列号：0x%.4x\n", ntohs(icmp_protocol->sequence));
}
// ARP协议解析处理
//u_short hardware_type;					// 格式化的硬件地址
//u_short protocol_type;					// 协议地址格式
//u_char hardware_length;					// 硬件地址长度
//u_char protocol_length;					// 协议地址长度
//u_short operation_code;					// 操作码
//u_char source_ethernet_address[6];		// 发送者硬件地址
//u_char source_ip_address[4];				// 发送者协议地址
//u_char destination_ethernet_address[6];	// 目的方硬件地址
//u_char destination_ip_address[4];			// 目的方协议地址
void handle_arp_packet(u_char *arg, const struct pcap_pkthdr *pkt_header, const u_char *pkt_content){
	arp_header *arp_protocol;
	arp_protocol = (arp_header*)(pkt_content+14);
	printf("==================ARP Protocol==================\n");
	printf("硬件地址：");
	switch (ntohs(arp_protocol->hardware_type))
	{
		case 1:
			printf("Ethernet");
			break;
		default:
			break;
	}
	printf("(%d)\n", ntohs(arp_protocol->hardware_type));
	printf("协议地址格式：");
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
	printf("硬件地址长度：%d\n", arp_protocol->hardware_length);
	printf("协议地址长度：%d\n", arp_protocol->protocol_length);
	printf("操作码：");
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
IP协议解析处理
u_char version_hlen;	//首部长度、版本
u_char tos;				//服务质量
u_short tlen;			//总长度
u_short identification;	//身份识别
u_short flags_offset;	//标识 分组偏移
u_char ttl;				//生存时间
u_char proto;			//协议类型
u_short checksum;		//头部校验和
u_int saddr;			//源IP地址
u_int daddr;			//目的IP地址
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
	printf("版本号: %d\n", ip_protocol->version_hlen >> 4);
	printf("头部长度：%d bytes\n", (ip_protocol->version_hlen & 0x0f) * 4);//与00001111B按位与消除前四位后
	printf("服务质量：%d\n", ip_protocol->tos);
	printf("总长度：%d\n", ntohs(ip_protocol->tlen));
	printf("身份识别：0x%.4x (%i) \n", ntohs(ip_protocol->identification), ntohs(ip_protocol->identification));
	printf("标识：%d\n", ntohs(ip_protocol->flags_offset) >> 13);
	printf("---保留位：%d\n", (ntohs(ip_protocol->flags_offset) & 0x8000) >> 15);
	printf("---Don't fragment: %d\n", (ntohs(ip_protocol->flags_offset) & 0x4000) >> 14);
	printf("---More fragment: %d\n", (ntohs(ip_protocol->flags_offset) & 0x2000) >> 13);
	printf("分段偏移：%d\n", ntohs(ip_protocol->flags_offset) & 0x1fff);
	printf("生存时间：%d\n", ip_protocol->ttl);
	printf("协议类型：");
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
	printf("头部校验和： 0x%.4x\n", ntohs(ip_protocol->checksum));
	printf("源地址：%s\n", sourceIP);
	printf("目的地址：%s\n", destIP);
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
	ether_header *ethernet_protocol;	//以太网协议
	u_short ethernet_type;				//以太网类型
	u_char	*mac_string;				//以太网地址
	//获取以太网数据类型
	ethernet_protocol = (ether_header*)pkt_content;
	//将一个16位数由网络字节顺序转换为主机字节顺序 
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	printf("==============Ethernet Protocol=================\n");
	//以太网目标地址
	mac_string = ethernet_protocol->ether_dhost;
	printf("目标MAC地址：%02x:%02x:%02x:%02x:%02x:%02x:\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5));
	//以太网源地址
	mac_string = ethernet_protocol->ether_shost;
	printf("源MAC地址：%02x:%02x:%02x:%02x:%02x:%02x:\n",
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

	pcap_if_t *alldevs;//pcap_if_t是一个链表的数据结构，表明网络接口的信息，
	pcap_if_t *adapter;//保存某个适配器
	pcap_t *fp;
	int res;
	struct pcap_pkthdr *header;//数据包的头部
	const u_char *pkt_data;
	time_t local_tv_sec;//时间戳
	struct tm *ltime;
	char timestr[16];

	int count = 1;
	int i = 0;
	int inum;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("本机的网络适配器列表如下：\n");
	//获取网络适配器的列表
	if (pcap_findalldevs(&alldevs, errbuf) == -1){
		fprintf(stderr, "查找适配器发生错误： %s\n", errbuf);
		exit(1);
	}
	//输出网络适配器列表信息
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
		printf("\n 未找到网络适配器适配器，请确保已安装好WinPcap!\n");
		return -1;
	}
	//选择适配器
	while (1)
	{
		printf("请选择适配器编号（1-%d): ", i);
		scanf("%d", &inum);
		if (inum > 0 && inum <= i){
			break;
		}
	}
	//跳转到所选择的适配器
	for (adapter = alldevs, i = 0; i < inum - 1; ++i, adapter = adapter->next);
	//打开适配器
	if ((fp = pcap_open_live(adapter->name, 65536, 1, 1000, errbuf)) == NULL){
		fprintf(stderr, "\n 打开适配器出现错误：%s\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}
	//检查链路层的类型
	if (pcap_datalink(fp) != DLT_EN10MB){
		fprintf(stderr, "本程序只能在以太网网络上运行\n");
		pcap_close(fp);
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("抓包程序正在运行......\n");
	printf("捕获文件保存为\"data.txt\"\n");
	printf("按下 \"ctrl+ C\" 中止抓包\n");
	if ((file = freopen("data.txt", "w", stdout)) == 0){
		printf("无法打开文档。/n");
	}
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (res == 0){
			//超时的情况
			continue;
		}
		//将时间戳转化为可识别的格式
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
		//输出抓取的包的编号、时间、长度
		printf("==============================================================================\n");
		printf("NO.%d\ttime: %s\tlen:%ld\n", count++, timestr, header->len);
		printf("==============================================================================\n");
		char temp[LINE_LEN + 1];
		//输出包
		for (i = 0; i < header->caplen; i++)
		{	//以十六进制输出
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
		//分析数据包
		handle_ethernet_packet(NULL, header, pkt_data);
	}

	if (res == -1){
		printf("读取包出现错误：%s\n", pcap_geterr(fp));
		pcap_close(fp);
		pcap_freealldevs(alldevs);
		fclose(stdin);
		if (file){
			fclose(file);
		}
		return -1;
	}

	//释放设备和文件流
	pcap_close(fp);
	pcap_freealldevs(alldevs);
	fclose(stdin);
	if (file)
	{
		fclose(file);
	}
	return 0;
}