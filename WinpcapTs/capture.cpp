#include <stdio.h>
#include <string.h>
#include <pcap.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

#define LINE_LEN 16
#define MAX_ADDR_LEN 16
FILE *file = 0;//用来保存抓包结果

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
		}else{
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
		if (inum > 0 && inum < i){
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
	while ((res=pcap_next_ex(fp,&header,&pkt_data)) >= 0)
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
		printf("NO.%d\ttime: %s\tlen:%ld\n",count++,timestr,header->len);
		char temp[LINE_LEN + 1];
		//输出包
		for ( i = 0; i < header->caplen; i++)
		{	//以十六进制输出
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
		//分析数据包
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