#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap/pcap.h>
#include<time.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include<netinet/ip.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
//#define TYPE_IP 2048 

int main(int argc,char* argv[])
{
	//char *dev=NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char file[100];
	strcpy(file,argv[2]);
	int packet_num=0;
	//char filter_string[] = "port 23";
	//struct bpf_program fp;
	//bpf_u_int32 net;
	//bpf_u_int32 mask;
	pcap_t *handle=pcap_open_offline(file,errbuf);
	//pcap_t *handle=pcap_open_live(dev,65536,1,1000,errbuf);
	while(1){
		struct pcap_pkthdr *header=NULL;
		const u_char *packet=NULL;
		int flag=pcap_next_ex(handle,&header,&packet);
		if(flag==1){
			struct tm *packet_time;
			char str[30];
			time_t packet_sec;
			packet_sec = header->ts.tv_sec;
			packet_time = localtime(&packet_sec);
			strftime(str,sizeof str,"%F %I:%M%p",packet_time);
			printf("Time:%s\n",str);
			//printf("Capture length: %d bytes\n",header->caplen);
			/*for(int i=0;i<header->caplen;i++){
				printf("%02x",packet[i]);
			}*/
			struct ether_header *mac=(struct ether_header*)packet;
			//type=(struct ether_header*)packet;

			char src_mac[18]={};
			char des_mac[18]={};

			snprintf(des_mac,sizeof(des_mac),"%02x:%02x:%02x:%02x:%02x:%02x",mac->ether_dhost[0],mac->ether_dhost[1],mac->ether_dhost[2],mac->ether_dhost[3],mac->ether_dhost[4],mac->ether_dhost[5]);
			snprintf(src_mac,sizeof(src_mac),"%02x:%02x:%02x:%02x:%02x:%02x",mac->ether_shost[0],mac->ether_shost[1],mac->ether_shost[2],mac->ether_shost[3],mac->ether_shost[4],mac->ether_shost[5]);

			//strlcpy(des_mac,mac->ether_dhost,sizeof(des_mac));
			//strlcpy(src_mac,mac->ether_shost,sizeof(src_mac));
			printf("Source MAC Address: %17s\n",src_mac);
			printf("Destination MAC Address: %17s\n",des_mac);
			printf("Type:%d\n",ntohs(mac->ether_type));
			if(ntohs(mac->ether_type)==ETHERTYPE_IP)
			{
				struct ip *ip=(struct ip*)(packet+ETHER_HDR_LEN); 
				char src_ip[INET_ADDRSTRLEN]={};
				char des_ip[INET_ADDRSTRLEN]={};

				snprintf(src_ip,sizeof(src_ip),"%s",inet_ntoa(ip->ip_src));
				snprintf(des_ip,sizeof(des_ip),"%s",inet_ntoa(ip->ip_dst));
				//snprintf(src_ip,sizeof(src_ip),"%d",ip->ip_src);
				//snprintf(des_ip,sizeof(des_ip),"%d",ip->ip_dst);

				printf("Source IP Address: %s\n",src_ip);
				printf("Destination IP Address: %s\n",des_ip);

				u_char TU=ip->ip_p;
				if(TU==IPPROTO_UDP){
					printf("This is UDP:\n");
					struct udphdr *udp=(struct udphdr *)(packet+ETHER_HDR_LEN+(ip->ip_hl<<2));
					printf("Source Port: %d\n",ntohs(udp->uh_sport));
					printf("Destination Port: %d\n",ntohs(udp->uh_dport));	
				}
				else if(TU==IPPROTO_TCP){
					printf("This is TCP:\n");
					struct tcphdr *tcp=(struct tcphdr *)(packet+ETHER_HDR_LEN+(ip->ip_hl<<2));
					printf("Source Port: %d\n",ntohs(tcp->th_sport));
					printf("Destination Port: %d\n",ntohs(tcp->th_dport));
				}
				packet_num++;
			}
			else 
			{
				printf("Other protocol!\n\n");
			
			}				
			printf("\n\n");
		}
		else if(flag==0){
			printf("Timeout\n");
		}
		else if(flag==-1){
			fprintf(stderr,"pcap_next_ex(): %s\n",pcap_geterr(handle));
		}
		else if(flag==-2){
			printf("Packet number: %d\n",packet_num);
			printf("Error");
			printf("\n\n");
			break;
		}
	}
	pcap_close(handle);
	return 0;
}
