#include <stdio.h>
#include <pcap.h>
#include <string.h>

//#define DEBUG ;
int main(int argc, char *argv[])
{
	if (argc<2){
		printf("./sniffer \"sniffing device\" \"search phrase\" pcap filter rules\n");
		return 1;
	}
	//local vars
	char filter [255],*buff, dev[255], errbuf[PCAP_ERRBUF_SIZE];
	int i=0;

	pcap_t *handle;				// pcap handle
	struct bpf_program fp;		//  compiled filter expression
	bpf_u_int32 mask;		//  netmask of our sniffing device
	bpf_u_int32 net;		//  IP of our sniffing device
	const u_char *packet;		// actual packet
	struct pcap_pkthdr header;	// header from pcap

	if(0 == strcmp( "",  argv[1] )){//if no device is specified use default
		buff = pcap_lookupdev(errbuf);//look up default device
	} else {
		strcpy(  dev, argv[1] );
		buff = dev;//use user defined interface
	}

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
#if defined DEBUG
	printf("%s",dev);
#endif

	for(i=3;i<argc;i++){//convert argument to filter
		strcat( filter, argv[i] );
		strcat( filter, " " );
#if defined DEBUG
		printf("%s\n",filter);
#endif
	}

	printf("Using  device: %s\n", buff);
	handle = pcap_open_live(buff, BUFSIZ, 1, 1000, errbuf);//open default device
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", buff, errbuf);
		return(2);
	} else printf("Device opened.\n");
	if (pcap_lookupnet(buff, &net, &mask, errbuf) == -1) {//get network info from dev
		fprintf(stderr, "Can't get netmask for device %s\n", buff);
		net = 0;
		mask = 0;
	}
	if ( pcap_compile(handle, &fp, filter, 0, net) == -1) {// compile filter
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		 return(2);
	 }
	char  results;
	while (1){//loop while gtting packets
		packet = pcap_next(handle, &header);
#if defined DEBUG
		printf("comparing: packet[%s]argv[%s]*\n",  packet,argv[2]);
#endif
		results = strstr(   (char *)packet,   (char *)argv[2]); // this does not work
		if(results)printf("results[%s]\n",  &results);
	}
	pcap_close(handle);

	return(0);
}
