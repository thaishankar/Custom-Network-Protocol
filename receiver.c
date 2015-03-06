#include "header.h"

pthread_t receive_ack_thread;
/*Global variables for pcap use*/
struct ether_header header;
struct in_addr dest_ip;
sniff_ip iph;
pcap_t *handle,*rhandle;  
pcap_t *handle1,*rhandle1;                       /* packet capture handle */

FILE *new_recv_file,*recv_file;
int fd,result,size_send_file,closeflg = 0,closeflg1 =0, probe_count = 0,max_flood=1;
struct timeval start_time,end_time;
char *dev,* base_ptr,*file_name,max;
long int number_of_packets;
char static hash_map[MAX_ALLOWED_PACKETS];
pthread_mutex_t hash_map_mutex = PTHREAD_MUTEX_INITIALIZER;

char myID;
uint8_t myPort;

uint16_t payload_size=0,prev_payload;

int hashMapFunc(char value, int key) 
{
	return (value >> key) & 0x01;
}


void got_packet(const struct pcap_pkthdr *header, const u_char *packet)		
{		
	packet = (char *)packet+34;
	unsigned int ack_seq_num = atol(packet);
	pthread_mutex_lock( &hash_map_mutex );
	hash_map[ack_seq_num/8] |= 1 << ack_seq_num%8;
	pthread_mutex_unlock( &hash_map_mutex );
	return;
}

int receive_ack_function()
{
	struct pcap_pkthdr header;
	const u_char *packet;		/* The actual packet */
	while(closeflg!=1)
	{
		packet = pcap_next(rhandle1, &header);
		got_packet(&header,packet);
	}
	return;
}

void receive_packet(const struct pcap_pkthdr *pheader, const u_char *packet)	    
{
	static int tcount =0;
	if(tcount == 0){
		gettimeofday(&start_time,NULL);
		printf("Start of the FTP Program: %Lf seconds \n",(long double)(start_time.tv_sec*1000000+start_time.tv_usec)/1000000);
		tcount++;
	}	
	
	uint16_t seq_num,length;
	int flood;
	
	//Check if packet is addressed to destination
	if(*((char*)packet+*(char *)packet) != myID){
		//printf("Unknown destination \n");
		return;
	}
	
	
	sndframe_t *fhead;
	fhead =((char*)packet+*(char *)packet+1);
	
	//Incorrect Port
	if(fhead->port != myPort){
		//printf("Unknown destination port \n");
		return;
	}
	
	u_char *pkt_data = (char*)packet+*(char *)packet+1+sizeof(sndframe_t);
	
	if(fhead->flag==LAST_PKT)
	{
		memcpy(&payload_size,pkt_data,2);
		pkt_data = pkt_data+2;
	}
	
	//char *last_pkt = (char *)packet+sizeof(struct myframe);
	/* This is the EOC packet */
	if( fhead->flag==EOF && fhead->seq_num == 7588)
	{
		gettimeofday(&end_time,NULL);
		printf("Time taken for one way file transfer: %Lf seconds\n",(long double)((end_time.tv_sec*1000000+end_time.tv_usec) - (start_time.tv_sec*1000000+start_time.tv_usec))/1000000);
		closeflg1 =1;
		return;
	}
	
	/* This is the first Packet */
	if((fhead->seq_num == 7588) &&(strcmp(pkt_data,"LENGTH") == 0))
	{
		payload_size = MAX_PAYLOAD_SIZE - (1+*(char *)packet+sizeof(sndframe_t));
		printf("payload_size is :%d\n",payload_size);
		size_send_file=atol(pkt_data+7);
		prev_payload = payload_size;
		base_ptr = (char*) malloc(size_send_file);
		if(base_ptr == NULL)
		{
			printf("Malloc failed\n");
			exit(0);
		}
		return;
	}
	
	/*if(probe_count >= 48){
		max_flood = 1; max = '1';}
	else if(probe_count >= 44 && probe_count < 48 ){
		max_flood = 2; max = '2';}
	else if(probe_count > 0 && probe_count < 44){
		max_flood = 3; max = '3';}
		
	//probe_count = 0;
	char *data = (char *)(packet+sizeof(myframe_t));
	char* seek_ptr = base_ptr + (frame->seq_num)*MAX_PAYLOAD_SIZE;
	memcpy(seek_ptr,data,frame->len);
	
	for(flood =0; flood < max_flood; flood++) 
	{	
		unsigned char frame[sizeof(struct ether_header)+sizeof(iph)+32];
		memcpy(frame,&header,sizeof(struct ether_header));
		memcpy(frame+sizeof(struct ether_header),&iph,sizeof(iph));
		char payload[32];
		sprintf(payload,"%u",seq_num);
		memcpy(frame+sizeof(struct ether_header)+sizeof(iph),payload,32);
		if (pcap_inject(handle,frame,32+sizeof(struct ether_header)+sizeof(iph))==-1) {
			pcap_perror(handle,0);
			pcap_close(handle);
			exit(1);
		}
	}*/
	//base_ptr = (char*) malloc(238);
	//char *data = (char *)packet+sizeof(struct myframe);
	char *seek_ptr = base_ptr + (fhead->seq_num)*prev_payload;
	memcpy(seek_ptr,pkt_data,payload_size);
	prev_payload = payload_size;
	return;
}


int main(int argc, char** argv)
{
	if(argc < 5)
	{
		printf("\n Usage ./<executable> dstFilename myPort myID ifname\n");
		return -1;
	}
	file_name = argv[1];
	myID=*argv[3];
	myPort=(uint8_t)*argv[2];
	
	//handle = pcap_inject_init();
	char interface[5]="eth";
	strcat(interface,argv[4]);
	rhandle = pcap_init(interface);
	//set_headers();	
	fd = open(file_name,O_CREAT | O_WRONLY | O_TRUNC);		
	struct pcap_pkthdr header;
	const u_char *packet;		/* The actual packet */
	//rhandle = pcap_init();
	while(closeflg1!=1)
	{
		packet = pcap_next(rhandle, &header);
		receive_packet(&header,packet);
	}
	//pcap_close(handle);
	pcap_close(rhandle);

	/*Can spawn a thread to parallelize this write*/
	write(fd,base_ptr,size_send_file);
	close(fd);
	free(base_ptr);	
	return 0;
}
