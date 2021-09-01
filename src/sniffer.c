#include <stdio.h>
#include <pcap.h>
#include <string.h>
#define DEBUG ;
int main(int argc, char *argv[])
{
	if (argc<2){
		printf("./sniffer \"search phrase\" pcap filter rules\n ");
		return 1;
	}
	//local vars
	char filter [255], *dev, errbuf[PCAP_ERRBUF_SIZE];
	int i=0;

	pcap_t *handle;				// pcap handle
	struct bpf_program fp;		//  compiled filter expression
	bpf_u_int32 mask;		//  netmask of our sniffing device
	bpf_u_int32 net;		//  IP of our sniffing device
	const u_char *packet;		// actual packet
	struct pcap_pkthdr header;	// header from pcap
	dev = pcap_lookupdev(errbuf);//look up default device
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	for(i=2;i<argc;i++){//convert argument to filter
		strcat( filter, argv[i] );
		strcat( filter, " " );
#if defined DEBUG
		printf("%s\n",filter);
#endif
	}
	printf("Using default device: %s\n", dev);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);//open default device
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	} else printf("Device opened.\n");
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {//get network info from dev
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}
	if ( pcap_compile(handle, &fp, filter, 0, net) == -1) {// compile filter
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		 return(2);
	 }
	while (1){//loop while gtting packets
		packet = pcap_next(handle, &header);
		char results;
		results = strstr(   packet,   argv[1]);
		if (results) printf("[%s]\n", results);
	}
	pcap_close(handle);

	return(0);
}
