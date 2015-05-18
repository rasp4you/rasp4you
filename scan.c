#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <malloc.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <linux/sockios.h>
#include <sys/wait.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>

#include "rasp4you.h"

static pthread_mutex_t mutex_ports;
static pthread_cond_t condition_ports;
static pthread_mutex_t mutex_ips;
static pthread_cond_t condition_ips;

static unsigned short *ports;
static int ports_size;

struct sockaddr_in server_tcp;
struct sockaddr_in server_udp;
unsigned LOCAL_ADDR;
unsigned short LOCAL_PORT, REMOTE_PORT;
unsigned local_addresses[17];
unsigned router;

struct lan *root_lan;
volatile int restart_scan;

volatile int ips_in_progress;
volatile int ports_in_progress;

static char *skip_blank(char *s)
{
        while(*s == ' ' || *s == '\t')
                s++;
        return s;
}
static char *skip_to_blank(char *s)
{
        while(*s != ' ' && *s != '\t' && *s)
                s++;
        return s;
}
static void ips_sleep(void)
{
        pthread_mutex_lock(&mutex_ips);
	if(ips_in_progress)
        	pthread_cond_wait(&condition_ips,&mutex_ips);
        pthread_mutex_unlock(&mutex_ips);
}
static void ips_wakeup(void)
{
        pthread_mutex_lock(&mutex_ips);
	ips_in_progress = 0;
        pthread_cond_signal(&condition_ips);
        pthread_mutex_unlock(&mutex_ips);
}
static void ports_sleep(void)
{
        pthread_mutex_lock(&mutex_ports);
	if(ports_in_progress)
        	pthread_cond_wait(&condition_ports,&mutex_ports);
        pthread_mutex_unlock(&mutex_ports);
}
static void ports_wakeup(void)
{
        pthread_mutex_lock(&mutex_ports);
	ports_in_progress = 0;
        pthread_cond_signal(&condition_ports);
        pthread_mutex_unlock(&mutex_ports);
}
void get_local_addresses(void)
{
	unsigned ip, mask, brd, local;
	int j, size, i, n;
	struct ifreq *ifp;
	struct ifconf ifc;
	struct ifreq ifr;
	int sd, index;
	struct lan *p;
	char buf[4096];
	char hw[6];

	n = LOCAL_ADDR = 0;
	ifc.ifc_len = 4096;
	ifc.ifc_ifcu.ifcu_buf = buf;
	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ioctl(sd, SIOCGIFCONF, &ifc);
	size = ifc.ifc_len / sizeof(struct ifreq);
	for (j = 0; j < size; j++) {
		ifp = &ifc.ifc_ifcu.ifcu_req[j];
		if(ifp->ifr_addr.sa_family != AF_INET)
			continue;
		strcpy(ifr.ifr_name,ifp->ifr_name);
		ioctl(sd,SIOCGIFFLAGS,&ifr);
		if(!(ifr.ifr_flags & IFF_UP))
			continue;
		if(ifr.ifr_flags & IFF_LOOPBACK)
			continue;
		ioctl(sd,SIOCGIFADDR,&ifr);
		local_addresses[n++] = local = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

		ioctl(sd,SIOCGIFINDEX,&ifr);
		index = ifr.ifr_ifindex;
		ioctl(sd,SIOCGIFHWADDR,&ifr);
		memcpy(hw,ifr.ifr_hwaddr.sa_data,6);

		ioctl(sd,SIOCGIFBRDADDR,&ifr);
		brd = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

		ioctl(sd,SIOCGIFNETMASK,&ifr);
		mask = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

		if((local & mask) == (router & mask))
			LOCAL_ADDR = local;
		if(!LOCAL_ADDR) {
			if(strcmp(ifp->ifr_name,"eth0") == 0)
				LOCAL_ADDR = local;
			else if(!LOCAL_ADDR)
				LOCAL_ADDR = local;
		}


		mask |= 0xFFFFFF;
		n = ~mask;
		n = ntohl(n);
		for(i = n;i >= 0;i--) {
			ip = (local & mask) | htonl(i);
			if(brd == ip)
				continue;
			for(p = root_lan;p != NULL;p = p->next)
				if(p->ip == ip)
					break;
			if(p != NULL)
				continue;
			p = calloc(1,sizeof(struct lan));
			p->local  = local;
			p->index  = index;
			p->ip     = ip;
			memcpy(p->hw,hw,6);
			p->next = root_lan;
			root_lan = p;
		}
	}
	close(sd);
}
void get_router(void)
{
	unsigned ip, flags;
	char buf[512];
	FILE *fp;
	char *s;

	fp = fopen("/proc/net/route","r");
	while(fgets(buf,512,fp) != NULL) {
		s = skip_to_blank(buf);
		s = skip_blank(s);
		if(!isxdigit(*s))
			continue;
		if(strncmp(s,"00000000",8))
			continue;
		s = skip_to_blank(s);
		s = skip_blank(s);
		if(sscanf(s,"%x",&ip) != 1)
			continue;
		s = skip_to_blank(s);
		s = skip_blank(s);
		if(sscanf(s,"%x",&flags) != 1)
			continue;
		if(flags & 3) {
			router = ip;
			break;
		}
	}
	fclose(fp);
}
void gracefulshut(int handle)
{
	struct timeval tv;
	int i, size;

	for(i = 0;i < 10;i++) {
		ioctl(handle,SIOCOUTQ,&size);
		if(size == 0)
			break;
		tv.tv_usec = 100*1000;
		tv.tv_sec = 0;
		select(0,NULL,NULL,NULL,&tv);
	}
	shutdown(handle,SHUT_WR);
}
static void gracefulclose(int left)
{
	struct timeval tv;
	fd_set rdset;

	gracefulshut(left);
	tv.tv_usec = 0;
	tv.tv_sec = 1;
	FD_ZERO(&rdset);
	FD_SET(left,&rdset);
	select(left+1,&rdset,NULL,NULL,&tv);
	close(left);
}
static void delay_ms(int ms)
{
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = ms * 1000;
	select(0,NULL,NULL,NULL,&tv);
}
static int arp_response(struct arp *resp,int log)
{
	struct lan *p;
	time_t now;
	int ret;

	ret = 0;
	resp = (struct arp *)((char *)resp - 14);
	if(resp->code[0] != 0 || resp->code[1] != 2)
		return 0;
	now = time(NULL);
	for(p = root_lan;p != NULL;p = p->next) {
		if(memcmp(&p->ip,resp->ip_src,4) == 0) {
			if(!p->alive || memcmp(p->mac,resp->eth_src,6)) {
				if(log)
					printf("Now alive %s\n",inet_ntoa(*((struct in_addr *)&p->ip)));
				memcpy(p->mac,resp->eth_src,6);
				p->tested = 0;
				ret = 1;
			} else if(log)
				printf("Still alive %s\n",inet_ntoa(*((struct in_addr *)&p->ip)));
			p->last_contacted = now;
			p->alive = now;
			p->todo = 0;
			break;
		}
	}
	return ret;
}
static unsigned short *get_ports(int tcp, int *SIZE)
{
	unsigned short *p, *ports, *q,  port;
	char buf[512];
	unsigned ip;
	FILE *fp;
	int size;
	char *s;

	size = MIN_PORTS_SIZE * sizeof(short);
	p = ports = malloc(size + sizeof(short));
	if(tcp)
		fp = fopen("/proc/net/tcp","r");
	else
		fp = fopen("/proc/net/udp","r");
	if(fp == NULL) {
		fprintf(stderr,"Panic read ports\n");
		exit(1);
	}
	while(fgets(buf,512,fp) != NULL) {
		s = strchr(buf,':');
		if(s++ == NULL)
			continue;
		while(*s == ' ' || *s == '\t')
			s++;
		if(strncmp(s,"0100007F",8) == 0)		// 127.0.0.1
			continue;
		s = strchr(s,':');
		if(s++ == NULL)
			continue;
		if(sscanf(s,"%hx",p) != 1)
			continue;
		*p = htons(*p);
		if(!tcp && (*p == LOCAL_PORT || *p == REMOTE_PORT))
			continue;
		s = strchr(s,' ');
		if(s++ == NULL)
			continue;
		while(*s == ' ' || *s == '\t')
			s++;
		if(sscanf(s,"%x",&ip) != 1 || ip)
			continue;
		if(sscanf(s,"%hx",&port) != 1 || port)
			continue;
		for(q = ports;q < p;q++)
			if(*q == *p)
				break;
		if(q != p)
			continue;
		if(p++ - ports > size/sizeof(short)) {
			p = malloc(size * 2 + sizeof(short));
			memcpy(p,ports,size);
			p = ports + size;
			size *= 2;
			if(size > 128)
				break;
		}
	}
	*p++ = 0;
	*SIZE = (char *)p - (char *)ports;
	fclose(fp);
	return ports;
}
static unsigned short *tcp_listen_ports(int *SIZE)
{
	unsigned short *p, *ports, *q;
	char buf[512];
	FILE *fp;
	int size;
	char *s;

	ports = get_ports(1,&size);
	fp = fopen("/proc/net/tcp6","r");
	if(fp == NULL) {
		*SIZE = size;
		return ports;
	}
	p = ports + size/sizeof(unsigned short);
	if(size < MIN_PORTS_SIZE)
		size = MIN_PORTS_SIZE;
	while(fgets(buf,512,fp) != NULL) {
		s = strchr(buf,':');
		if(s++ == NULL)
			continue;
		while(*s == ' ' || *s == '\t')
			s++;
	     	if(strncmp(s,"00000000000000000000000001000000",32) == 0)		// local address 127.0.0.1
			continue;
		s = strchr(s,':');
		if(s++ == NULL)
			continue;
		if(sscanf(s,"%hx",p) != 1)
			continue;
		*p = htons(*p);
		s = strchr(s,' ');
		if(s++ == NULL)
			continue;
		while(*s == ' ' || *s == '\t')
			s++;
		if(strncmp(s,"00000000000000000000000000000000:0000",37))
			continue;
		for(q = ports;q < p;q++)
			if(*q == *p)
				break;
		if(q != p)
			continue;
		if(p++ - ports > size/sizeof(short)) {
			p = malloc(size * 2 + sizeof(short));
			memcpy(p,ports,size);
			p = ports + size;
			size *= 2;
			if(size > 128)
				break;
		}
	}
	*p++ = 0;
	*SIZE = (char *)p - (char *)ports;
	fclose(fp);
	return ports;
}
static unsigned short *udp_listen_ports(int *size)
{
	return get_ports(0,size);
}
static unsigned short *listen_ports(int *size)
{
	unsigned short *t, *u, *p;
	int sizet, sizeu;

	t = tcp_listen_ports(&sizet);
	u = udp_listen_ports(&sizeu);
	p = calloc(1,sizet + sizeu);
	memcpy(p,t,sizet);
	memcpy(p+sizet/sizeof(short),u,sizeu);
	*size = sizet + sizeu;
	free(t);
	free(u);
	return p;
}
static unsigned short *sort(unsigned short *q)
{
	unsigned short *t, tmp;

	for(;*q != 0;q++) {
		for(t = q+1;*t != 0;t++) {
			if(ntohs(*q) < ntohs(*t)) {
				tmp = *q;
				*q = *t;
				*t = tmp;
			}
		}
	}
	return q+1;
}
static int test_http(unsigned ip,unsigned short port,int local)
{
	struct sockaddr_in from;
	struct timeval tv;
	fd_set rdset;
	char buf[512];
	int fd, ret;
	int on = 1;

	ret = 0;
	from.sin_addr.s_addr = ip;
	from.sin_port        = port;
	from.sin_family      = AF_INET;
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	fcntl(fd,FIONBIO,&on);
	fcntl(fd,F_SETFL,O_NONBLOCK);
	if(connect(fd,(struct sockaddr *)&from,sizeof(from)) < 0) {
		if(errno != EINPROGRESS) {
			close(fd);
			return 0;
		}
		if(local)
			tv.tv_sec = 2;
		else
			tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&rdset);
		FD_SET(fd,&rdset);
		if(select(fd+1,NULL,&rdset,NULL,&tv) <= 0) {
			close(fd);
			return 0;
		}
	}
	FD_ZERO(&rdset);
	FD_SET(fd,&rdset);
	if(local) {
		tv.tv_sec  = 2;
		tv.tv_usec = 0;
		write(fd,TEST_HTTP_LOCAL,strlen(TEST_HTTP_LOCAL));
	} else {
		tv.tv_sec  = 0;
		tv.tv_usec = 1000*200;
					//printf("Test %s\n",inet_ntoa(*((struct in_addr *)&ip)));
		write(fd,TEST_HTTP,strlen(TEST_HTTP));
	}

	on = 0;
	fcntl(fd,FIONBIO,&on);
	fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) & ~O_NONBLOCK);
	if(select(fd+1,&rdset,NULL,NULL,&tv) > 0) {
		int n = read(fd,buf,511);
		if(n > 0) {
			buf[n] = 0;
			if(strncmp(buf,"HTTP/1",6) == 0)
				ret = 1;
			else if(strncmp(buf,"PTTH/1",6) == 0) {
				ret = 2;
			}
		}
	}
	close(fd);
	return ret;
}
static void *process_send_ips(void * param)
{
	struct lan *p, **q, **best, *ordered;
	unsigned short port;
	int alive, death;
	char secret[128];
	char *s, *init;
	//int option = 0;
	char buf[512];
	unsigned now;
	int total;
	int left;
	int size;

	left = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(connect(left,(struct sockaddr *)&server_tcp,sizeof(server_tcp)) < 0) {
		close(left);
		ips_wakeup();
		return NULL;
	}
	alive = death = 0;
	ordered = NULL;
     	for(q = &root_lan;*q != NULL;q = &root_lan) {
                best = q;
                while(*q != NULL) {
			unsigned a, b;

                        a = (*q)->ip;
                        b = (*best)->ip;
                        if(ntohl(a) > ntohl(b))
                                best = q;
                        q = &((*q)->next);
                }
                p = *best;
                *best = p->next;
                p->next = ordered;
                ordered = p;
		if(memcmp(p->mac,"\x00\x00\x00\x00\x00\x00",6)) {
			if(p->alive)
				alive++;
			else
				death++;
		}
			
        }
	if(alive + death > 256) {
		if(alive >= 256) {
			alive = 256;
			death = 0;
		} else
			death = 256 - alive;
	}
		
	size = alive + death;
	now = time(NULL);
	root_lan = ordered;
	init = s = malloc(size * (6+4+4+2+2+2+2));
	for(p = root_lan;p != NULL;p = p->next) {
		unsigned short flag;
		unsigned elapsed;

		if(memcmp(p->mac,"\x00\x00\x00\x00\x00\x00",6) == 0)
			continue;
		if(p->alive) {
			if(!alive)
				continue;
			alive--;
		} else {
			if(!death)
				continue;
			death--;
		}
		memcpy(s,&p->ip,4); s += 4;
		if(now > p->last_contacted)
			elapsed = now - p->last_contacted;
		else
			elapsed = 0;
		elapsed = htonl(elapsed);
		memcpy(s,&elapsed,4); s += 4;
		memcpy(s,p->mac,6); s += 6;
		flag = 0;
		if(p->alive)
			flag = 1;
		if(p->ip == router)
			flag |= 2;
		flag = htons(flag);
		memcpy(s,&flag,2); s += 2;
		if(p->novemila) {
			port = htons(9000);
			memcpy(s,&port,2); s += 2;
		}
		if(p->ottantaottanta) {
			port = htons(8080);
			memcpy(s,&port,2); s += 2;
		}
		if(p->ottomila) {
			port = htons(8000);
			memcpy(s,&port,2); s += 2;
		}
		if(p->ottanta) {
			port = htons(80);
			memcpy(s,&port,2); s += 2;
		}
		port = htons(0);
		memcpy(s,&port,2);
		size++;
		s += 2;
	}
	total = size;
	size = s - init;
	sprintf(buf,"IPS|%x|%d|%d",serial,total,size);
	create_secret(secret,serial,key,buf);
	sprintf(buf+strlen(buf),"?%s",secret);

	write(left,buf,strlen(buf) + 1);
	write(left,init,size);

	free(init);

	gracefulclose(left);

	ips_wakeup();
	return NULL;
}
static void *process_send_ports(void * param)
{
	unsigned short *v, *q, *new, *p, *tmp, *vchiq, *vc;
	char secret[128];
	char buf[512];
	int size;
	int left;
	int ret;

	left = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(connect(left,(struct sockaddr *)&server_tcp,sizeof(server_tcp)) < 0) {
		close(left);
		ports_wakeup();
		return NULL;
	}
	size = ports_size;
	size += sizeof(unsigned short);
	q = new = calloc(1,size * 2);
	tmp = calloc(1,size);
	memcpy(tmp,ports,size);

	vchiq = vc = calloc(1,size);

	for(p = tmp;*p != 0;) {
		ret = test_http(LOCAL_ADDR,*p,1);
		if(ret) {
			*q++ = *p;
			if(ret == 2)
				*vc++ = *p;
			*p++ = 0;
		} else
			p++;
	}
	*vc = 0;

	*q++ = 0;
	for(v = tmp;v < p;v++)
		if(*v)
			*q++ = *v;
	*q++ = 0;
	v++;
	while(*v)
		*q++ = *v++;
	*q++ = 0;

	q = sort(new);
	q = sort(q);
	v = q = sort(q);

	for(vc = vchiq;*vc;) {
		size += sizeof(unsigned short);
		*v++ = *vc++;
	}
	*v = 0;
	sort(q);

	sprintf(buf,"PORTS|%x|%d",serial,size);
	create_secret(secret,serial,key,buf);
	sprintf(buf+strlen(buf),"?%s",secret);

	write(left,buf,strlen(buf) + 1);
	write(left,new,size);

	free(vchiq);
	free(new);
	free(tmp);

	gracefulclose(left);

	ports_wakeup();
	return NULL;
}
int alive_ips(int timescan,int log)
{
	struct sockaddr_ll addr;
	struct arp arp, *resp;
	int len, wesd, resd;
	struct lan *p, *q;
	char buffer[2048];
	struct timeval tv;
	int index, max;
	socklen_t size;
	int modified;
	fd_set rdset;
	time_t now;
	int some;
	int i;

	arp.type[0]    = 0x08;		// ARP
	arp.type[1]    = 0x06;
	arp.hw_fmt     = 0;
	arp.pr_fmt     = 1;
	arp.proto[0]   = 0x08;		// IP
	arp.proto[1]   = 0x00;
	arp.sz_addr    = 6;
	arp.sz_proto   = 4;
	arp.code[0]    = 0;
	arp.code[1]    = 1;
	memcpy(arp.dst,"\xFF\xFF\xFF\xFF\xFF\xFF",6);
	memcpy(addr.sll_addr,"\xFF\xFF\xFF\xFF\xFF\xFF",6);
	memcpy(arp.eth_dst,"\x00\x00\x00\x00\x00\x00",6);


	some = modified = 0;
	resp = (struct arp *)buffer;
	wesd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

	for(i = max = 0,p = root_lan;p != NULL;p = p->next, i++)
		if(p->index > max)
			max = p->index;

	for(index = 0;index <= max;index++) {
		resd = socket(PF_PACKET,SOCK_DGRAM,htons(ETH_P_ALL));

		memset(&addr, 0, sizeof(addr));
		addr.sll_family          = AF_PACKET;
		addr.sll_ifindex         = index;
		addr.sll_protocol        = htons(ETH_P_ALL);
		bind(resd, (struct sockaddr *) &addr, sizeof(addr));

		addr.sll_protocol = htons(0x806);
		addr.sll_family   = PF_PACKET;
		addr.sll_hatype   = 1;
		addr.sll_halen    = ETH_ALEN;
		addr.sll_pkttype  = PACKET_BROADCAST;

		for(i = 0,p = root_lan;p != NULL;p = p->next, i++) {
			int j;

			if(p->index != index)
				continue;

			p->todo = 0;
			for(j = 0;j < 16;j++)
				if(local_addresses[j] == 0 || local_addresses[j] == p->ip)
					break;
			if(local_addresses[j] == p->ip)
				continue;

			now = time(NULL);
			if(p->time) {
				if(memcmp(p->mac,"\x00\x00\x00\x00\x00\x00",6) == 0) {
					if(now - p->time < (5*60+i/10))
						continue;
				} else {
					if(now - p->time < timescan)
						continue;
					if(p->time - p->alive > 90) {
						if(p->alive) {
							if(log)
								printf("Now dead %s\n",inet_ntoa(*((struct in_addr *)&p->ip)));
							modified = 1;
							p->alive = 0;
						} else if(log)
							printf("Test but not responding %s\n",inet_ntoa(*((struct in_addr *)&p->ip)));
						p->tested = 0;
					} else if(log)
						printf("Test %s\n",inet_ntoa(*((struct in_addr *)&p->ip)));
				}
			}
			p->todo = 1;
			p->time = now;
			memcpy(arp.src,p->hw,6);
			memcpy(arp.eth_src,p->hw,6);
			memcpy(arp.ip_src,&p->local,4);
			memcpy(arp.ip_dst,&p->ip,4);
			addr.sll_ifindex = p->index;

			sendto(wesd,(char *)&arp,42,0,(struct sockaddr *)&addr,sizeof(addr));

			delay_ms(10);

			tv.tv_sec  = 0;
			tv.tv_usec = 0;
			FD_ZERO(&rdset);
			FD_SET(resd,&rdset);
			if(select(resd+1,&rdset,NULL,NULL,&tv) <= 0)
				continue;
			size = sizeof(addr);
			len = recvfrom(resd,(char *)resp,2048,0,(struct sockaddr *)&addr,&size);
			if(len > 0 && ntohs(addr.sll_protocol) == 0x806)
				modified |= arp_response(resp,log);
			some = 1;
		}
		if(some) {
			for(;;) {
				tv.tv_sec  = 0;
				tv.tv_usec = 100*1000;
				FD_ZERO(&rdset);
				FD_SET(resd,&rdset);
				if(select(resd+1,&rdset,NULL,NULL,&tv) <= 0)
					break;
				size = sizeof(addr);
				len = recvfrom(resd,(char *)resp,2048,0,(struct sockaddr *)&addr,&size);
				if(len > 0 && ntohs(addr.sll_protocol) == 0x806)
					modified |= arp_response(resp,log);
			}
			for(p = root_lan;p != NULL;p = p->next) {
				if(!p->todo)
					continue;
				now = time(NULL);
				p->time = now;
				memcpy(arp.src,p->hw,6);
				memcpy(arp.eth_src,p->hw,6);
				memcpy(arp.ip_src,&p->local,4);
				memcpy(arp.ip_dst,&p->ip,4);
				addr.sll_ifindex = p->index;
				sendto(wesd,(char *)&arp,42,0,(struct sockaddr *)&addr,sizeof(addr));
				delay_ms(10);
			}
			for(;;) {
				tv.tv_sec  = 0;
				tv.tv_usec = 100*1000;
				FD_ZERO(&rdset);
				FD_SET(resd,&rdset);
				if(select(resd+1,&rdset,NULL,NULL,&tv) <= 0)
					break;
				size = sizeof(addr);
				len = recvfrom(resd,(char *)resp,2048,0,(struct sockaddr *)&addr,&size);
				if(len > 0 && ntohs(addr.sll_protocol) == 0x806)
					modified |= arp_response(resp,log);
			}
		}
		close(resd);
	}
	close(wesd);
	for(p = root_lan;p != NULL;p = p->next) {
		if(memcmp(p->mac,"\x00\x00\x00\x00\x00\x00",6) == 0)
			continue;
		if(p->alive) {
			int test;

			now = time(NULL);
			if(now - p->tested > 15*60) {
				test = test_http(p->ip,htons(80),0);
				if(test != p->ottanta) {
					p->ottanta = test;
					modified = 1;
				}
				test = test_http(p->ip,htons(8080),0);
				if(test != p->ottantaottanta) {
					p->ottantaottanta = test;
					modified = 1;
				}
				test = test_http(p->ip,htons(9000),0);
				if(test != p->novemila) {
					p->novemila = test;
					modified = 1;
				}
				test = test_http(p->ip,htons(8000),0);
				if(test != p->ottomila) {
					p->ottomila = test;
					modified = 1;
				}
				p->alive = p->tested = now;
			}
			continue;
		}
		for(q = root_lan;q != NULL;q = q->next) {
			if(q == p || memcmp(q->mac,p->mac,6))
				continue;
			if(q->alive)
				memset(p->mac,0,6);
		}
	}
	return modified;
}
void *scan_loop(void * param)
{
	time_t now, checked_ports, checked_ips;
	pthread_t thread;
	int size;


	pthread_mutex_init(&mutex_ports,NULL);
	pthread_cond_init(&condition_ports,NULL);
	pthread_mutex_init(&mutex_ips,NULL);
	pthread_cond_init(&condition_ips,NULL);

	checked_ips = checked_ports = 0;
	for(;;) {
		if(was_unreach) {
			checked_ips = checked_ports = 0;
			reachable_sleep();
		}
		now = time(NULL);
		if(ports_in_progress == 0 && now - checked_ports >= 15*60) {
			unsigned short *p = listen_ports(&size);
			if(!checked_ports || ports_size != size || memcmp(p,ports,size) || now - checked_ports >= 15*60) {
				if(checked_ports)
					free(ports);

				ports = p;
				ports_size = size;
				ports_in_progress = 1;
				pthread_create(&thread, NULL, process_send_ports, (void*)NULL);
			} else {
				free(p);
			}
			checked_ports = now;
		}
		if(ips_in_progress == 0 && (alive_ips(10,0) || now - checked_ips >= 15*60)) {
			ips_in_progress = 1;
			pthread_create(&thread, NULL, process_send_ips, (void*)NULL);
			checked_ips = now;
		}
		if(param != NULL) {
			ports_sleep();
			ips_sleep();
			break;
		}
		sleep(10);
	}
	return NULL;
}
