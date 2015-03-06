#include "header.h"

pthread_t sender_thread, receive_ack_thread;
char file_name[50];
char static hash_map[MAX_ALLOWED_PACKETS];
pthread_mutex_t hash_map_mutex = PTHREAD_MUTEX_INITIALIZER;
int size_send_file,max_flood =1,number_of_packets,closeflg = 0, recv_file; /*FD for received file*/

/*Global variables for pcap use*/
pcap_t *handle,*rhandle;                         /* packet capture handle */
pcap_t *handle1,*rhandle1;
struct ether_header header;
sniff_ip iph;
char *dev, *base_ptr;
char path[10];
uint8_t hop_count = 0;
char hop_index = 2;
char usage_port=100;
struct timeval start_time,end_time;

uint8_t dstPort;
char myID;

int hashMapFunc(char value, int key) {
    return (value >> key) & 0x01;
}

void path_loopkup(char *search_dst)
{
	char buf[100];
	char dst,route[10],src;
	uint8_t hop;
	int fd = fopen("sourceRT.txt","r");
	while(fgets(buf,100,fd) != NULL)
	{
		sscanf(buf,"%c %c %c %s",&dst,&src,&hop,route);
		if((dst==*search_dst)&&(src==myID))
		{
			strcpy(path,route);
			hop_count = hop-48;
		}
	}
}

void sender_function()
{
	gettimeofday(&start_time,NULL);
	printf("Start of the FTP Program: %Lf seconds \n",(long double)(start_time.tv_sec*1000000+start_time.tv_usec)/1000000);
	FILE *send_file;
    uint16_t result;
    int bit,flag=0;
    //struct sockaddr_in serv_addr;
    uint32_t counter;
	sndframe_t fhead;
	fhead.port = dstPort;
	fhead.flag = MORE_PKT;
	int fd = open(file_name,O_RDONLY);
	
	/*To calculate file size*/
    send_file = fopen(file_name,"rb");
    if(send_file == NULL)
        printf("Error: opening file\n");
    fseek(send_file, 0, SEEK_END); // seek to end of file
    size_send_file = ftell(send_file); // get current file pointer
	
	base_ptr = (char*)malloc(size_send_file);
	if(base_ptr  == NULL)
	{		printf("TODO: Malloc failed, switching to non-optimized mode\n");
		exit(0);
	
	}
	/*No of packets*/
	uint16_t payload_size = MAX_PAYLOAD_SIZE - (1 + hop_count + sizeof(sndframe_t));
    number_of_packets = size_send_file/payload_size + ((size_send_file%payload_size > 0) ? 1:0);
	/*Close the send_file pointer after transmission - f(time)*/
	
	/* Sending data packets */	
	char *seek_ptr;
	
	/*Write the entire file in the buffer. This is 1 window of transmission*/
	/*Loop here for file sizes greater than 2^31 */
	int bytes_read = read(fd,base_ptr,size_send_file);	
	if(bytes_read == 0)
		fprintf(stderr,"Error reading from file \n");
	
    for(counter =0 ; counter<number_of_packets; counter++)
    {  
		if (counter == 0)
		{
			/*Probing link for delay and sharing file size with the other node */
			fhead.seq_num = 7588;			
			char payload[32];
			sprintf(payload,"%u",size_send_file);
			//memcpy(frame+sizeof(struct ether_header)+sizeof(iph)+7,payload,32);
			
			char frame[MAX_PAYLOAD_SIZE] = {0};
			memset(frame,'\0',sizeof(frame));
			memcpy((void*)frame,(void*)&hop_index,sizeof(char));
			memcpy((void*)frame+sizeof(char),path,hop_count);
			memcpy((void*)frame+sizeof(char)+hop_count,&fhead,sizeof(sndframe_t));
			memcpy((void*)frame+sizeof(char)+hop_count+sizeof(sndframe_t),"LENGTH",7);			
			memcpy((void*)frame+sizeof(char)+hop_count+sizeof(sndframe_t)+7,payload,32);
			
			if (pcap_inject(handle,frame,sizeof(char)+hop_count+sizeof(sndframe_t)+7+32)==-1)
			{
				pcap_perror(handle,0);
				//pcap_close(handle);
				return -1;
			}
			
			/*int j;
			for(j=0;j<50;j++)
			{
				if (pcap_inject(handle,frame,32+7+sizeof(struct ether_header)+sizeof(iph))==-1)
				{
					pcap_perror(handle,0);
					pcap_close(handle);
					return -1;
				}
			}*/
		}
	
		//memcpy(&iph.ip_id,&counter,4);	
		seek_ptr = base_ptr + counter * payload_size;
		if(counter == number_of_packets - 1){
			result = size_send_file - ((counter) * payload_size);
			fhead.flag = LAST_PKT;
			}
		else
			result = payload_size;
		
		fhead.seq_num = counter;
	    //printf("SEQ : %d\n",fhead.seq_num);
		/*Construct the frame*/	
		char frame[MAX_PAYLOAD_SIZE];	
		memset(frame,'\0',sizeof(frame));
		memcpy((void*)frame,(void*)&hop_index,sizeof(char));
		memcpy((void*)frame+sizeof(char),path,hop_count);
		memcpy((void*)frame+sizeof(char)+hop_count,&fhead,sizeof(sndframe_t));
		if(fhead.flag == LAST_PKT) // fix corner case where result = payload_size -1 as a result of adding 2 bytes for len;
		{
			memcpy((void*)frame+sizeof(char)+hop_count+sizeof(sndframe_t),&result,sizeof(uint16_t));
			memcpy((void*)frame+sizeof(char)+hop_count+sizeof(sndframe_t)+sizeof(uint16_t),(void*)seek_ptr,result);
			if (pcap_inject(handle,frame,sizeof(char)+hop_count+sizeof(sndframe_t)+payload_size)==-1)
			{
				pcap_perror(handle,0);
				//pcap_close(handle);
				return -1;
			}
		}	
		else
		{		
			memcpy((void*)frame+sizeof(char)+hop_count+sizeof(sndframe_t),(void*)seek_ptr,result);	
			if (pcap_inject(handle,frame,sizeof(char)+hop_count+sizeof(sndframe_t)+result)==-1)
			{
				pcap_perror(handle,0);
				//pcap_close(handle);
				return -1;
			}
		}
	}
	/*End of 1 window transmission*/
	
	/*Start retransmission (loop till all packets have been ackd)*/
    /*while(1)
	{
        flag=0;
        for(counter =0 ; counter<number_of_packets; counter++)
        {
            pthread_mutex_lock( &hash_map_mutex );
            bit = hashMapFunc(hash_map[counter/8],counter%8);
            pthread_mutex_unlock( &hash_map_mutex );
            if(!bit)
            {
				flag = 1;
                //memcpy(&iph.ip_id,&counter,4);
				seek_ptr = base_ptr + counter * MAX_PAYLOAD_SIZE;
				if(counter == number_of_packets - 1)
					result = size_send_file - ((counter) * MAX_PAYLOAD_SIZE);		
				else
					result = MAX_PAYLOAD_SIZE;
				//iph.ip_len = result;	
				sndframe.seq_num = counter;	
				sndframe.len = result;
				
				/*Construct frame*/	
				/*char frame[sizeof(struct myframe)+MAX_PAYLOAD_SIZE]; 
				memcpy((void*)frame,(void*)&sndframe,sizeof(struct myframe));
				memcpy((void*)frame+sizeof(struct myframe),(void*)seek_ptr,result);
				
				if (pcap_inject(handle,frame,result+sizeof(struct myframe))==-1)
				{
					pcap_perror(handle,0);
					pcap_close(handle);
					return -1;
				}
			}
		}*/
		/*if(flag == 0)
		{
			//All packts have been ack'd
			break;
        }
	}*/	
		/*Done with sending*/
		close(fd); 
		char eof[4] ="NULL";
		fhead.seq_num = 7588;
		fhead.flag = EOF;
		
		char frame[MAX_PAYLOAD_SIZE] = {0};
		memset(frame,'\0',sizeof(frame));
		memcpy((void*)frame,(void*)&hop_index,sizeof(char));
		memcpy((void*)frame+sizeof(char),path,hop_count);
		memcpy((void*)frame+sizeof(char)+hop_count,&fhead,sizeof(sndframe_t));
		memcpy((void*)frame+sizeof(char)+hop_count+sizeof(sndframe_t),(void*)eof,4);	
		
		if (pcap_inject(handle,frame,sizeof(char)+hop_count+sizeof(sndframe_t)+4)==-1)
		{
			pcap_perror(handle,0);
			//pcap_close(handle);
			return -1;
		}
		
        gettimeofday(&end_time,NULL);
		/*Clear the buffer*/
		memset(base_ptr, 0, size_send_file);
		fclose(send_file);
        printf("Time taken to send the file: %Lf seconds \n",(long double)((end_time.tv_sec*1000000+end_time.tv_usec) - (start_time.tv_sec*1000000+start_time.tv_usec))/1000000);
		closeflg = 1;
        //pthread_exit(0);
		return;
}


/*void got_packet(const struct pcap_pkthdr *header, const u_char *packet)		
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
	const u_char *packet;		
	while(closeflg!=1)
	{
		packet = pcap_next(rhandle, &header);
		got_packet(&header,packet);
	}
	pthread_exit(0);
}*/


int main(int argc, char* argv[])
{
	if(argc < 5)
    {
        printf("\n Usage ./<executable> srcFilename srcName DstName DstPort ifname\n");
        return -1;
    }
	myID=*argv[2];
	
	dstPort=(uint8_t)*argv[4];
	int err;
	char interface[5]="eth";
	strcat(interface,argv[5]);
	handle = pcap_inject_init(interface);
	//rhandle = pcap_send_init();
    strcpy(file_name,argv[1]);
	path_loopkup(argv[3]);
	if(hop_count==0)
	{
		printf("Path Lookup failed");
		exit(-1);
	}
    sender_function();
   
	pcap_close(handle);
	//pcap_close(rhandle);
    return 0;
}

