#include "header.h"
	
pcap_t *handle,*rhandle;                         /* packet capture handle */
struct ether_header header;
sndArray_t sArray[10];
sniff_ip iph;
char *dev;
char myID;

char Routing_Table[256][2];

void got_packet(struct pcap_pkthdr *header,const u_char *packet,char *dev,char *frame)
{
	char *dintf;
	uint8_t index=*(char *)packet;
	
	if(*(packet+index)!= 'R')
	{
		//printf("Unknown Hop \n");
		return;
	}
	index=index+1;
	char next_hop=*((char *)packet+index);
	*(char *)packet=index;
	
	int egress = Route(next_hop); //got dest intf here
	
	if(egress==-1) //route not found; drop packet
		return; 
	
	
	if (pcap_inject(sArray[egress].sndHandle,packet,MAX_PAYLOAD_SIZE)==-1)
	{
		pcap_perror(sArray[egress].sndHandle,0);
		pcap_close(sArray[egress].sndHandle);
		return;
	}
}


void * intfThd(void *name)
{
	name = (char *)name;
	pcap_t *rHandle = pcap_init(name);	
	printf("In thread %s\n", (char *)name);
	struct pcap_pkthdr header;
	const u_char *packet =NULL;		// The actual packet 
	char *frame = (char *)malloc(SIZE_ETHERNET+76);
	
	packet = pcap_next(rHandle,&header);
	while(1)
	{
		//if(strcmp(packet,""))
			got_packet(&header,packet,name,frame);
		//printf("Got packet on interface %s", name);
		packet = pcap_next(rHandle,&header);
		
	}
	free(frame);	
}	
	

int main(int argc, char* argv[])
{
		
	if(argc < 2)
	{
		printf("\n Usage ./<executable> myID \n");
		return -1;
	}
	myID=argv[2];
	pcap_if_t *alldevsp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int pid[MAX_NUM_OF_INTERFACES];
	
	/*Creating Routing tables. This populates the structure and updates head ptr*/
	CreateTable();
	
	int retval = pcap_findalldevs(&alldevsp,errbuf);
	if (retval == -1)
	{
		fprintf(stderr,"ERROR\n");
		exit(1);
	}
	int i =0;
	/*Creating send handles for all interfaces and stores both handles and their MACs in sArray*/
	pcap_if_t *temp = alldevsp; 
	while(temp)
	{
		if(strncmp(temp->name,"eth0",4) && strncmp(temp->name,"eth4",4) && (strncmp(temp->name,"eth3",4)))
		{
			temp=temp->next;
			continue;
		}
		/*Only eth devices*/
		
		int index = atoi(temp->name+3);
		strcpy(sArray[index].name,temp->name);//name
		sArray[index].sndHandle = pcap_inject_init(&sArray[index].name);//send handle
		unsigned char infMac[ETHER_ADDR_LEN];
		/*getsrcIpMac(&sArray[index].name,&sArray[index].ether_shost,&sArray[index].ip_src); // get src IP and MAC
		printf("Source IP for interface %s : %s\n",temp->name, inet_ntoa((sArray[index].ip_src)));
		#ifdef LOG 
		printf("infMac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , sArray[index].ether_shost[0], sArray[index].ether_shost[1], sArray[index].ether_shost[2], sArray[index].ether_shost[3], sArray[index].ether_shost[4], sArray[index].ether_shost[5]);	
		#endif
		//memcpy((sArray[index]).ether_shost,infMac,ETHER_ADDR_LEN); //src mac */
		
		int err = pthread_create(&pid[i],NULL,&intfThd,(void*)&sArray[index].name);
		if(err !=0)
		{
			printf("Error in thread creation");
			exit(0);
		}
		temp=temp->next;
		i++;
	}
	/*Start the dynamic thread* /
	pid_t dynThd;
	int err = pthread_create(&dynThd,NULL,dThd,NULL);
	if(err !=0)
	{
		printf("Error in thread creation");
		exit(0);
	} */
	
	while(1)
		sleep(20);
	//pthread_join(pid[0],NULL);
	return 0;
}
