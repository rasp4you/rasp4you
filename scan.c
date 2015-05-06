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

unsigned LOCAL_ADDR;
unsigned local_addresses[17];
unsigned router;

struct lan *root_lan;


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
static void delay_ms(int ms)
{
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = ms * 1000;
	select(0,NULL,NULL,NULL,&tv);
}
static int arp_response(struct arp *resp)
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
				memcpy(p->mac,resp->eth_src,6);
				p->tested = 0;
				ret = 1;
			}
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
static int test_http(unsigned ip,unsigned short port)
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
		tv.tv_sec = 0;
		tv.tv_usec = 1000*1000;
		FD_ZERO(&rdset);
		FD_SET(fd,&rdset);
		if(select(fd+1,NULL,&rdset,NULL,&tv) <= 0) {
			close(fd);
			return 0;
		}
	}
	tv.tv_sec  = 0;
	tv.tv_usec = 1000*200;
	FD_ZERO(&rdset);
	FD_SET(fd,&rdset);
	write(fd,TEST_HTTP,strlen(TEST_HTTP));

	on = 0;
	fcntl(fd,FIONBIO,&on);
	fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) & ~O_NONBLOCK);
	if(select(fd+1,&rdset,NULL,NULL,&tv) > 0) {
		int n = read(fd,buf,511);
		if(n > 0) {
			buf[n] = 0;
			if(strncmp(buf,"HTTP/1",6) == 0) {
				ret = 1;
			}
		}
	}
	close(fd);
	return ret;
}
static void process_send_ips(void)
{
	struct lan *p, **q, **best, *ordered;
	unsigned short port;
	struct timeval tv;
	int alive, death;
	char secret[128];
	char *s, *init;
	//int option = 0;
	char buf[512];
	fd_set rdset;
	unsigned now;
	int total;
	int left;
	int size;

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
		
	size = 0;
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
	left = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(connect(left,(struct sockaddr *)&server_tcp,sizeof(server_tcp)) < 0)
		exit(0);
	total = size;
	size = s - init;
	sprintf(buf,"IPS|%x|%d|%d",serial,total,size);
	create_secret(secret,serial,key,buf);
	sprintf(buf+strlen(buf),"?%s",secret);

	write(left,buf,strlen(buf) + 1);
	write(left,init,size);

	gracefulshut(left);
	tv.tv_usec = 0;
	tv.tv_sec = 1;
	FD_ZERO(&rdset);
	FD_SET(left,&rdset);
	select(left+1,&rdset,NULL,NULL,&tv);
	//setsockopt(left,SOL_SOCKET,SO_KEEPALIVE,(char *)&option,sizeof(option));
	exit(0);
}
static void process_send_ports(unsigned short *ports,int size)
{

	unsigned short *v, *q, *new, *p;
	struct timeval tv;
	char secret[128];
	//int option = 0;
	fd_set rdset;
	char buf[512];
	int left;

	size += sizeof(unsigned short);
	q = new = calloc(1,size);
	for(p = ports;*p != 0;) {
		if(test_http(LOCAL_ADDR,*p)) {
			*q++ = *p;
			*p++ = 0;
		} else
			p++;
	}
	*q++ = 0;
	for(v = ports;v < p;v++)
		if(*v)
			*q++ = *v;
	*q++ = 0;
	v++;
	while(*v)
		*q++ = *v++;
	*q++ = 0;

	q = sort(new);
	q = sort(q);
	q = sort(q);

	left = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(connect(left,(struct sockaddr *)&server_tcp,sizeof(server_tcp)) < 0)
		exit(0);
	sprintf(buf,"PORTS|%x|%d",serial,size);
	create_secret(secret,serial,key,buf);
	sprintf(buf+strlen(buf),"?%s",secret);

	write(left,buf,strlen(buf) + 1);
	write(left,new,size);

	gracefulshut(left);
	tv.tv_usec = 0;
	tv.tv_sec = 1;
	FD_ZERO(&rdset);
	FD_SET(left,&rdset);
	select(left+1,&rdset,NULL,NULL,&tv);
	//setsockopt(left,SOL_SOCKET,SO_KEEPALIVE,(char *)&option,sizeof(option));
	exit(0);
}
int alive_ips(void)
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
					if(now - p->time < 10)
						continue;
					if(p->time - p->alive > 90) {
						if(p->alive) {
							modified = 1;
							p->alive = 0;
						}
						p->tested = 0;
					}
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
				modified |= arp_response(resp);
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
					modified |= arp_response(resp);
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
					modified |= arp_response(resp);
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
			if(now - p->tested > 5*60) {
				test = test_http(p->ip,htons(80));
				if(test != p->ottanta) {
					p->ottanta = test;
					modified = 1;
				}
				test = test_http(p->ip,htons(8080));
				if(test != p->ottantaottanta) {
					p->ottantaottanta = test;
					modified = 1;
				}
				test = test_http(p->ip,htons(8000));
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
void scan_loop(int esc)
{
	time_t now, checked_ports, checked_ips;
	unsigned short *ports;
	int size, ports_size;
	pid_t pid, forked;
	char msg[256];
	int status;

	sprintf(msg,"%s: scan home network",RASP4YOU);
	write_on_console(msg);

	forked = -1;


	checked_ips = checked_ports = 0;
	for(;;) {
		pid = waitpid(-1,&status,WNOHANG);
		if(pid > 0) {
			if(pid == forked)
				forked = -1;
		}
		now = time(NULL);
		if(forked < 0 && now - checked_ports >= 60) {
			unsigned short *p = listen_ports(&size);
			if(!checked_ports || ports_size != size || memcmp(p,ports,size) || now - checked_ports >= 15*60) {
				if(checked_ports)
					free(ports);
				forked = fork();
				if(forked == 0) {
					sprintf(msg,"%s: send services",RASP4YOU);
					write_on_console(msg);
					process_send_ports(p,size);
					exit(0);
				}
				ports_size = size;
				ports = p;
			}
			checked_ports = now;
			if(esc) {
				wait(&status);
				forked = -1;
			}
		}
		if(forked < 0 && (alive_ips() || now - checked_ips >= 15*60)) {
			forked = fork();
			if(forked == 0) {
				sprintf(msg,"%s: send machines",RASP4YOU);
				write_on_console(msg);
				process_send_ips();
				exit(0);
			}
			checked_ips = now;
			if(esc) {
				wait(&status);
				forked = -1;
			}
		}
		if(esc)
			exit(0);
		sleep(10);
		if(getppid() == 1) {
			if(forked > 0)
				kill(forked,SIGKILL);
			exit(0);
		}
	}
}
