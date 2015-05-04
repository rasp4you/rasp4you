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

static char **ARGV;

static struct udp_request *root_udp_request;
static struct old_lan *old_lan;

static char email[128];
static int iam_a_daemon;
static int email_chk;
static int with_test;
static int sd_local;
static int sd_7766;

struct sockaddr_in server_tcp;
struct sockaddr_in server_udp;

unsigned short LOCAL_PORT, REMOTE_PORT;

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
static int readstring(int fd,char *buf,int n)
{
	buf[0] = 0;
	while(n--) {
		if(read(fd,buf,1) != 1)
			return 0;
		if(*buf++ == 0)
			return 1;
		*buf = 0;
	}
	return 0;
}
static void receive_firmware(char *left_buf)
{
	int left, fd, n, len;
	char secret[512];

	left = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(connect(left,(struct sockaddr *)&server_tcp,sizeof(server_tcp)) < 0)
		return;
	sprintf(left_buf,"FIRMWARE|%x",serial);
	create_secret(secret,serial,key,left_buf);
	sprintf(left_buf+strlen(left_buf),"?%s",secret);

	write(left,left_buf,strlen(left_buf)+1);

	if(!readstring(left,left_buf,1024) || sscanf(left_buf,"FIRMWARE|%d",&len) != 1) {
		close(left);
		return;
	}
	fd = open(TMP_FILE,O_WRONLY|O_CREAT,0600);
	while(len > 0) {
		n = read(left,left_buf,4096);
		if(n <= 0)
			break;
		if(write(fd,left_buf,n) != n)
			break;
		len -= n;
	}
	close(left);
	close(fd);
	if(len > 0) {
		unlink(TMP_FILE);
		return;
	}
	install_exe(TMP_FILE);
	unlink(TMP_FILE);
	for(n = 0;n < 1024;n++)
		close(n);
	unlink(PID_FILE);
	execl(EXE_FILE,PROGRAM_NAME,"--firmware",NULL);
}
static void process_tcp(char *header,unsigned ip,unsigned short port)
{
	int left, right, left_count, right_count;
	char *left_buf, *right_buf;
	struct sockaddr_in from;
	fd_set rdset, wrset;
	int not_connected;
	socklen_t len;
	int status;
	pid_t pid;
	int i;

	pid = fork();
	if(pid > 0) {
		waitpid(pid,&status,0);
		return;
	}
	if(fork() != 0)
		exit(0);

	for(i = 0;i < 1024;i++)
		close(i);
	left_buf  = malloc(16*1024);
	right_buf = malloc(16*1024);

	left = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(connect(left,(struct sockaddr *)&server_tcp,sizeof(server_tcp)) < 0)
		exit(0);

	right = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(ip == 0) {
		len = sizeof(from);
		getsockname(left,(struct sockaddr *)&from,&len);
	} else
		from.sin_addr.s_addr = ip;
	from.sin_family = AF_INET;
	from.sin_port = port;

	if(connect(right,(struct sockaddr *)&from,sizeof(from)) < 0) {
		not_connected = 1;
		right_count = -1;
		for(i = 0;i <= 16;i++) {
			if(!local_addresses[i])
				break;
			if(from.sin_addr.s_addr == local_addresses[i])
				break;
		}
		if(local_addresses[i]) {
			int j;

			for(j = 0;j <= 16;j++) {
				if(!local_addresses[j])
					break;
				if(i == j)
					continue;
				close(right);
				right = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
				from.sin_addr.s_addr = local_addresses[j];
				if(connect(right,(struct sockaddr *)&from,sizeof(from)) >= 0) {
					not_connected = 0;
					right_count = 0;
					break;
				}
			}
		}
	} else {
		not_connected = 0;
		right_count = 0;
	}
	if(right_count < 0)
		gracefulshut(left);
	write(left,header,strlen(header)+1);

	if(strncmp(header,"GET / HTTP/1",12) != 0) {
		int option = 1;
		setsockopt(left,IPPROTO_TCP,TCP_NODELAY,(char*)&option,sizeof(option));
	}

	left_count = 0;
	for(;;) {
		int max = 0;
		FD_ZERO(&rdset);
		FD_ZERO(&wrset);
		if(right_count == 0) {
			FD_SET(right,&rdset);
			max = right;
		} else if(right_count > 0) {
			FD_SET(left,&wrset);
			max = left;
		}
		if(left_count == 0) {
			FD_SET(left,&rdset);
			if(left > max)
				max = left;
		} else if(left_count > 0) {
			FD_SET(right,&wrset);
			if(right > max)
				max = right;
		}
		if(select(max+1,&rdset,&wrset,NULL,NULL) <= 0)
			continue;
		if(FD_ISSET(left,&rdset)) {
			left_count = read(left,left_buf,16*1024);
			if(left_count <= 0) {
				if(right_count < 0) {
					exit(0);
				}
				gracefulshut(right);
				left_count = -1;
			} else if(not_connected)
				left_count = 0;
		} else if(FD_ISSET(right,&wrset)) {
			if(write(right,left_buf,left_count) < 0)
				left_count = -1;
			else
				left_count = 0;
		}
		if(FD_ISSET(right,&rdset)) {
			right_count = read(right,right_buf,16*1024);
			if(right_count <= 0) {
				if(left_count < 0) {
					exit(0);
				}
				gracefulshut(left);
				right_count = -1;
			}
		} else if(FD_ISSET(left,&wrset)) {
			if(write(left,right_buf,right_count) < 0)
				right_count = -1;
			else
				right_count = 0;
		}
	}
	exit(0);
}
static void read_email_address(char *s,int n)
{
	while(n--) {
		*s = getc(stdin);
		if(*s == '\n')
			break;
		s++;
	}
	*s = 0;
}
void write_on_console(char *msg)
{
	if(iam_a_daemon) {
		sprintf(ARGV[0],"%s (%d.%d)",msg,release,build);
		return;
	}
#ifdef notdef
	{
	static int len;
	int n;

	printf("%s",msg);
	for(n = strlen(msg);n < len;n++)
		putchar(' ');
	putchar('\r');
	fflush(stdout);
	len = strlen(msg);
	}
#endif
}
static int register_machine(int fd,unsigned ip)
{
	char secret[128];
	char buf[512];
	int ok_key;
	int size;
	FILE *fp;
	char **q;
	char *s;

	ok_key = check_key();
	if(!ok_key) {
		if(iam_a_daemon) {
			return 0;
		}
		for(q = license;*q != NULL;q++)
			printf("%s\n",*q);
		printf("\n");
		printf("Type a valid email address for registration: ");
		fflush(stdout);
initialize:
		read_email_address(email,120);
		fp = fopen("LICENSE.TXT","w");
		for(q = license;*q != NULL;q++)
			fprintf(fp,"%s\n",*q);
		fclose(fp);
		printf("A copy of MIT license saved in file LICENSE.TXT\n");
		printf("Email validation in progress ...\r");
		fflush(stdout);
		sprintf(buf,"INIT|%d|%s|%s|%d.%d",arch,machine_id,email,release,build);
		make_key();
		s = buf + strlen(buf);
		*s++ = '|';
		strcpy(s,key);
	} else {
		sprintf(buf,"REGISTER|%x|%x|%d.%d",serial,ip,release,build);
		//if(raspberry_id != NULL)
			//sprintf(buf+strlen(buf),"|%s",raspberry_id);
		create_secret(secret,serial,key,buf);
		sprintf(buf+strlen(buf),"?%s",secret);
	}
	write(fd,buf,strlen(buf)+1);
	if(!readstring(fd,buf,512) || strncmp(buf,"REGISTER|",9)) {
		if(iam_a_daemon) {
			return 0;
		}
		if(strncmp(buf,"RETSIGER|",9) == 0) {
			fprintf(stderr,"Your raspberry is already registered with another email address !\nContact support@rasp4you.com\n");
		} else if(errno == ENETUNREACH && !router) {
			fprintf(stderr,"Cannot connect to \"%s\"\nYou must configure router on Raspbian!\n",RASP4YOU);
		} else if(errno == ECONNREFUSED || errno == ENETUNREACH) {
			if(router)
				fprintf(stderr,"Cannot connect to \"%s:%hu\". Check router %s or adsl line!\n",RASP4YOU,SNAT_PORT,inet_ntoa(*((struct in_addr *)&router)));
			else
				fprintf(stderr,"Cannot connect to \"%s:%hu\"\nYou must configure router on Raspbian!\n",RASP4YOU,SNAT_PORT);
		}
		else
			fprintf(stderr,"Communication error with %s\n",RASP4YOU);
		exit(1);
	}
	s = skip(buf,1);
	if(s == NULL) {
		if(iam_a_daemon) {
			return -1;
		}
		fprintf(stderr,"Communication error with %s\n",RASP4YOU);
		exit(1);
	}
	if(sscanf(s,"%x|%d|%x|%hx|%d",&serial,&email_chk,&server_tcp.sin_addr.s_addr,&server_tcp.sin_port,&size) != 5) {
		if(iam_a_daemon) {
			return 0;
		}
		for(q = license;*q != NULL;q++)
			printf("%s\n",*q);
		printf("\n");
		printf("%s must be registered. Type a valid email address: ",PROGRAM_NAME);
		fflush(stdout);
		goto initialize;
	}
	s = skip(buf,6);
	if(s == NULL) {
		if(iam_a_daemon) {
			return -1;
		}
		fprintf(stderr,"Communication error with %s\n",RASP4YOU);
		exit(1);
	}
	strcpy(email,s);
	if(size > 0) {
		struct old_lan *q;
		char *tmp, *s;

		s = tmp = calloc(1,size);
		if(read(fd,tmp,size) == size) {
			while(size > 0) {
				q = malloc(sizeof(struct old_lan));
				memcpy(&q->ip,s,4); s += 4;
				memcpy(q->mac,s,6); s += 6;
				q->next = old_lan;
				old_lan = q;
				size -= 10;
			}
		} 
		free(tmp);
	}
	return 1;
}
static void decode_time(char *buf,unsigned t)
{
	if(t > 86400*2) {
		sprintf(buf,"%d days",t / 86400);
		return;
	}
	if(t > 3600*2) {
		sprintf(buf,"%d hours",t / 3600);
		return;
	}
	if(t > 60*2) {
		sprintf(buf,"%d minutes",t / 60);
		return;
	}
	sprintf(buf,"%d seconds",t);
}
static void get_local_addresses(void)
{
	unsigned ip, mask, brd, local;
	int j, size, i, n;
	struct old_lan *q;
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

		if((local & ~mask) == (router & ~mask))
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
	if(old_lan == NULL)
		return;
	for(q = old_lan;q->ip != 0;q++) {
		for(p = root_lan;p != NULL;p = p->next) {
			if(q->ip == p->ip) {
				memcpy(p->mac,q->mac,6);
				break;
			}
		}
	}
}
static void get_router(void)
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
static void connect_to_server(struct hostent *h)
{
	struct sockaddr_in from;
	struct timeval tv;
	char msg[128];
	socklen_t len;
	fd_set rdset;
	int on, fd;
	int ret;


	server_tcp.sin_family = AF_INET;
	server_tcp.sin_port   = htons(SNAT_PORT);
	server_tcp.sin_addr.s_addr = *((unsigned *)h->h_addr);
	server_udp.sin_family = AF_INET;
	server_udp.sin_addr.s_addr = *((unsigned *)h->h_addr);
	server_udp.sin_port = htons(SNAT_PORT);

again:
	sprintf(msg,"Connecting to %s ....",RASP4YOU);
	write_on_console(msg);
	on = 1;
	for(;;) {
		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		fcntl(fd,F_SETFL,O_NONBLOCK);
		fcntl(fd,FIONBIO,&on);
		if(connect(fd,(struct sockaddr *)&server_tcp,sizeof(server_tcp)) >= 0)
			break;
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		FD_ZERO(&rdset);
		FD_SET(fd,&rdset);
		if(select(fd+1,NULL,&rdset,NULL,&tv) > 0)
			break;
		if(!iam_a_daemon) {
			if(!router)
				fprintf(stderr,"Cannot connect to \"%s\"\nYou must configure router on Raspbian!\n",RASP4YOU);
			else
				fprintf(stderr,"Cannot connect to \"%s:%hu\". Check router %s or adsl line!\n",RASP4YOU,SNAT_PORT,inet_ntoa(*((struct in_addr *)&router)));
			exit(1);
		}
		close(fd);
		sprintf(msg,"Connecting to %s ....",RASP4YOU);
		write_on_console(msg);
		sleep(20);
	}
	on = 0;
	fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) & ~O_NONBLOCK);
	fcntl(fd,FIONBIO,&on);
	len = sizeof(from);
	getsockname(fd,(struct sockaddr *)&from,&len);
	ret = register_machine(fd,LOCAL_ADDR);
	if(ret <= 0) {
		close(fd);
		if(ret < 0)
			sprintf(msg,"%s is unreachable",RASP4YOU);
		else
			sprintf(msg,"%s: please reinstall",PROGRAM_NAME);
		write_on_console(msg);
		sleep(20);
		goto again;
	}
	close(fd);

	if(server_tcp.sin_addr.s_addr !=  *((unsigned *)h->h_addr) || server_tcp.sin_port != htons(SNAT_PORT)) {
		int on = 1;

		server_udp.sin_port  = server_tcp.sin_port;
		server_udp.sin_addr.s_addr = server_tcp.sin_addr.s_addr;
		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		fcntl(fd,F_SETFL,O_NONBLOCK);
		fcntl(fd,FIONBIO,&on);
		if(connect(fd,(struct sockaddr *)&server_tcp,sizeof(server_tcp)) < 0) {
			tv.tv_sec = 5;
			tv.tv_usec = 0;
			FD_ZERO(&rdset);
			FD_SET(fd,&rdset);
			if(select(fd+1,NULL,&rdset,NULL,&tv) <= 0) {
				server_tcp.sin_port   = htons(SNAT_PORT);
				server_tcp.sin_addr.s_addr = *((unsigned *)h->h_addr);
			}
		}
		close(fd);
	}
	from.sin_family      = AF_INET;
	from.sin_addr.s_addr = INADDR_ANY;
	from.sin_port        = htons(0);
	sd_7766 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	bind(sd_7766,(struct sockaddr *)&from,sizeof(from));
	len = sizeof(from);
	getsockname(sd_7766,(struct sockaddr *)&from,&len);
	REMOTE_PORT = from.sin_port;

	from.sin_addr.s_addr = INADDR_ANY;
	from.sin_port        = htons(0);
	sd_local = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	bind(sd_local,(struct sockaddr *)&from,sizeof(from));
	len = sizeof(from);
	getsockname(sd_local,(struct sockaddr *)&from,&len);
	LOCAL_PORT = from.sin_port;
}
static void main_loop(struct hostent *h)
{
	time_t now, last_rx, last_tx;
	unsigned freetime, paidtime;
	struct sockaddr_in from;
	struct udp_request *u;
	unsigned nonce, NONCE;
	pid_t pid_scan = -1;
	int first_time = 1;
	int was_unreach = 0;
	struct timeval tv;
	char secret[512];
	unsigned SERIAL;
	socklen_t len;
	char msg[128];
	fd_set rdset;
	unsigned ip;
	char *rxbuf;
	char *txbuf;
	int n, max;
	int size;
	char *s;

	nonce = 0;

	from.sin_family      = AF_INET;
	rxbuf = malloc(4096);
	txbuf = malloc(4096);
	last_tx = last_rx = 0;
	for(;;) {
		now = time(NULL);
		// PLEASE DON'T CHANGE
		if(now - last_tx >= 10) {
			sprintf(rxbuf,"ALIVE|%08x|%08x",serial,++nonce);
			create_secret(secret,serial,key,rxbuf);
			sprintf(rxbuf+strlen(rxbuf),"?%s",secret);
			sendto(sd_7766,rxbuf,strlen(rxbuf)+1,0,(struct sockaddr *)&server_udp,sizeof(server_udp));
			last_tx = now;
			if(!last_rx)
				last_rx = now;
			check_pid_file();
		}
		if(now - last_rx >= 40 && (server_udp.sin_addr.s_addr !=  *((unsigned *)h->h_addr) || server_udp.sin_port != htons(SNAT_PORT))) {
			server_udp.sin_addr.s_addr = *((unsigned *)h->h_addr);
			server_udp.sin_port = htons(SNAT_PORT);
			last_tx = 0;
			continue;
		}
		if(now - last_rx >= 60) {
			if(first_time && !iam_a_daemon) {
				static int gia;
				if(!gia) {
					fprintf(stderr,"Cannot connect to \"%s:%hu\". Check router/firewall %s: udp port %hu must be opened!\n",RASP4YOU,SNAT_PORT,inet_ntoa(*((struct in_addr *)&router)),SNAT_PORT);
					gia = 1;
				}
			}
			close(sd_7766);
			from.sin_addr.s_addr = INADDR_ANY;
			from.sin_port = htons(0);
			sd_7766 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			bind(sd_7766,(struct sockaddr *)&from,sizeof(from));
			last_tx = last_rx = 0;
			sprintf(msg,"%s is unreachable",RASP4YOU);
			write_on_console(msg);
			was_unreach = 1;
		}
		tv.tv_usec = 0;
		tv.tv_sec  = 10;
		max = sd_local;
		if(sd_7766 > max)
			max = sd_7766;
		FD_ZERO(&rdset);
		FD_SET(sd_7766,&rdset);
		FD_SET(sd_local,&rdset);
		if(select(max+1,&rdset,NULL,NULL,&tv) <= 0)
			continue;
		if(FD_ISSET(sd_local,&rdset)) {
			len = sizeof(from);
			size = recvfrom(sd_local,(char *)rxbuf,MAX_UDP_SIZE,0,(struct sockaddr *)&from,&len);
			if(size > 0) {
				for(u = root_udp_request;u != NULL;u = u->next)
					if(u->local_port == from.sin_port)
						break;
				if(u != NULL) {
					sprintf(txbuf,"UDP|%08X|%08x:%04hx->%04hx|%x|%d",serial,u->ip,u->server_port,u->local_port,u->fd,size);
					create_secret(secret,serial,key,txbuf);
					sprintf(txbuf+strlen(txbuf),"?%s|",secret);
					n = strlen(txbuf);
					memcpy(txbuf+n,rxbuf,size);
					size += n;
					if(size <= MAX_UDP_SIZE) {
						sendto(sd_7766,txbuf,size,0,(struct sockaddr *)&server_udp,sizeof(server_udp));
					}
				}
			}
		}
		if(!FD_ISSET(sd_7766,&rdset))
			continue;
		len = sizeof(from);
		n = recvfrom(sd_7766,(char *)rxbuf,MAX_UDP_SIZE,0,(struct sockaddr *)&from,&len);
		if(n <= 0)
			continue;
		rxbuf[n] = 0;
		if(strncmp(rxbuf,"REG|",4) == 0) {
			if(sscanf(rxbuf+4,"%x",&SERIAL) != 1)
				continue;
			if(serial != SERIAL || !check_secret(serial,key,rxbuf))
				continue;
			sprintf(rxbuf,"REG|%08x",serial);
			create_secret(secret,serial,key,rxbuf);
			sprintf(rxbuf+strlen(rxbuf),"?%s",secret);
			sendto(sd_7766,rxbuf,strlen(rxbuf)+1,0,(struct sockaddr *)&server_udp,sizeof(server_udp));
			continue;
		}
		if(strncmp(rxbuf,"GER|",4) == 0) {
			if(sscanf(rxbuf+4,"%x",&SERIAL) != 1)
				continue;
			if(serial != SERIAL || !check_secret(serial,key,rxbuf))
				continue;
			sprintf(rxbuf,"GER|%08x",serial);
			create_secret(secret,serial,key,rxbuf);
			sprintf(rxbuf+strlen(rxbuf),"?%s",secret);
			sendto(sd_7766,rxbuf,strlen(rxbuf)+1,0,(struct sockaddr *)&server_udp,sizeof(server_udp));
			continue;
		}
		if(strncmp(rxbuf,"ACK|",4) == 0 || strncmp(rxbuf,"KCA|",4) == 0) {
			int status, quality, todo;
			char *name, *s;
			int cloned;


			cloned = strncmp(rxbuf,"KCA|",4) == 0;

			if(was_unreach) {
				if(pid_scan > 0) {
					kill(pid_scan,SIGKILL);
					wait(&pid_scan);
					pid_scan = fork();
					if(pid_scan == 0) {
						scan_loop(0);
						exit(0);
					}
				}
				was_unreach = 0;
			}
			if(sscanf(rxbuf+4,"%x|%x|%d|%x|%x|%d|%d",&SERIAL,&NONCE,&todo,&paidtime,&freetime,&status,&quality) != 7)
				continue;
			name = skip(rxbuf,8);
			if(name == NULL)
				continue;
			if(serial != SERIAL || !check_secret(serial,key,rxbuf))
				continue;
			s = strchr(name,'?');
			if(s != NULL)
				*s = 0;
			decode_time(rxbuf,paidtime);
			if(freetime)
				decode_time(txbuf,freetime);
			nonce = NONCE;
			last_rx = time(NULL);
			if(iam_a_daemon) {
				if(!status) {
					sprintf(msg,"Waiting for registration ....");
					write_on_console(msg);
					continue;
				}
				if(todo) {
					receive_firmware(rxbuf);
					continue;
				}
				if(first_time) {
					pid_scan = fork();
					if(pid_scan == 0) {
						scan_loop(0);
						exit(0);
					}
					first_time = 0;
				}
				if(quality >= 90) {
					if(freetime)
						sprintf(msg,"%s.%s is waiting %s for free %s or pay now at https://%s",name,RASP4YOU,rxbuf,txbuf,PAYSITE);
					else if(paidtime)
						sprintf(msg,"%s.%s is available for %s",name,RASP4YOU,rxbuf);
					else if(!cloned)
						sprintf(msg,"%s.%s is available",name,RASP4YOU);
					else
						sprintf(msg,"%s.%s is cloned. Repeat installation",name,RASP4YOU);
				} else 
					sprintf(msg,"Please check your ADSL because quality %d%% is low !",quality);
				write_on_console(msg);
				continue;
			}
			if(status) {
				if(!with_test) {
					printf("\rWait a moment please, finishing installation.\n");
					install_exe("/proc/self/exe");
					install_initd(1);
					printf("\nInstallation is complete !\n");
					exit(0);
				} else {
					if(pid_scan < 0) {
						pid_scan = fork();
						if(pid_scan == 0) {
							scan_loop(0);
							exit(0);
						}
					}
					if(quality >= 90) {
						if(freetime)
							printf("%s.%s is waiting %s for free %s or pay now at https://%s",name,RASP4YOU,rxbuf,txbuf,PAYSITE);
						else if(paidtime)
							printf("%s.%s is available for %s",name,RASP4YOU,rxbuf);
						else
							printf("%s.%s is available",name,RASP4YOU);
					} else 
						printf("Please check your ADSL because quality %d%% is low !",quality);
					printf("\n");
				}
			} else {
				if(first_time) {
					if(email_chk == 1) {
						printf("Email %s seems not be valid !!\n",email);
						exit(0);
					}
					if(email_chk == 2 || email_chk == 3) {
						printf("Email %s temporarily unavailable. Retry later !!\n",email);
						exit(0);
					}
/**
					if(email_chk == 3) {
						printf("Server %s temporarily unavailable. Retry later !!\n",RASP4YOU);
						exit(0);
					}
**/
					printf("Read email sent to %s for finish registration\n",email);
					printf("Waiting for registration ....");
					fflush(stdout);
					if(fork() == 0) {
						scan_loop(1);
						exit(0);
					}
					first_time = 0;
					wait(&status);
					if(with_test) {
						install_exe("/proc/self/exe");
						pid_scan = fork();
						if(pid_scan == 0) {
							scan_loop(0);
							exit(0);
						}
					}
				}
			}
			continue;
		}
		if(strncmp(rxbuf,"TCP|",4) == 0) {
			unsigned short port;
			unsigned ip;

			if(sscanf(rxbuf+4,"%x|%x.%hx<-",&SERIAL,&ip,&port) != 3)
				continue;
			if(serial == SERIAL && check_secret(serial,key,rxbuf))
				process_tcp(rxbuf,ip,port);
			continue;
		}
		if(strncmp(rxbuf,"UDP|",4) == 0) {
			unsigned short local_port, server_port;
			int fd;

			if(sscanf(rxbuf+4,"%x|%x:%hx->%hx|%x|%d?",&SERIAL,&ip,&server_port,&local_port,&fd,&size) != 6)
				continue;
			s = skip(rxbuf,5);
			if(s == NULL)
				continue;
			*(s-1) = 0;
			if(serial != SERIAL || !check_secret(serial,key,rxbuf))
				continue;
			*(s-1) = '|';
			for(u = root_udp_request;u != NULL;u = u->next)
				if(u->local_port == local_port)
					break;
			if(u == NULL) {
				u = malloc(sizeof(struct udp_request));
				u->next = root_udp_request;
				root_udp_request = u;
			}
			u->ip = ip;
			u->fd = fd;
			u->server_port = server_port;
			u->local_port = from.sin_port = local_port;
			from.sin_addr.s_addr = LOCAL_ADDR;
			sendto(sd_local,s,size,0,(struct sockaddr *)&from,sizeof(from));
		}
	}
}
int main(int argc,char **argv)
{
	sigset_t sig_to_block;
	struct hostent *h;
	char msg[128];
	int n;

        sigemptyset(&sig_to_block);
        sigaddset(&sig_to_block, SIGPIPE);
	sigprocmask(SIG_BLOCK, &sig_to_block, NULL);

#ifdef TEST
	if(argc > 1 && strcmp(argv[1],"-k") == 0) {
		get_machine_id();
		make_key();
		printf("1|%s|%s|%s|%d\n",machine_id,"rasp4you@rasp4you.com",key,2);
		exit(0);
	}
	if(argc > 1 && strcmp(argv[1],"-t") == 0) {
		with_test = 1;
		argc++;
		argv++;
	}
#endif
	if(geteuid() != 0) {
		fprintf(stderr,"You must be root\n");
		exit(1);
	}
	if(!get_machine_id()) {
		fprintf(stderr,"Cannot get machine id\n");
		exit(1);
	}
	if((n = readlink("/proc/self/exe",msg,128)) <= 0 || msg[0] != '/') {
		fprintf(stderr,"Panic readlink /proc/self/exe");
		exit(1);
	}
	msg[n] = 0;
	iam_a_daemon = 0;
	if(argc == 2 && strcmp(msg,EXE_FILE) == 0) {
		if(strcmp(argv[1],"--firmware") == 0) {
			install_initd(1);
			exit(0);
		}
		else if(strcmp(argv[1],"--daemonize") == 0) {
			iam_a_daemon = 1;
		}
	}
	if(argc == 2 && strcmp(argv[1],"--uninstall") == 0) {
		install_initd(0);
		printf("\nUninstall is complete !\n");
		exit(0);
	}
	if(!iam_a_daemon) {
		system("sh -c \"if which invoke-rc.d >/dev/null 2>&1; then invoke-rc.d rasp4you stop; else /etc/init.d/rasp4you stop ; fi\" > /dev/null 2>&1");
		system("update-rc.d -f rasp4you remove > /dev/null 2>&1");
	}
	kill_the_rival();
	if(iam_a_daemon) {
		if(fork())
			exit(0);
		create_pid_file();
		ARGV = argv;
	}
	for(;;) {
		h = gethostbyname(RASP4YOU);
		if(h != NULL)
			break;
		if(!iam_a_daemon) {
			fprintf(stderr,"Cannot connect to \"%s\"\nYou must configure router on Raspbian!\n",RASP4YOU);
			exit(1);
		}
		sprintf(msg,"getting %s address ...",RASP4YOU);
		write_on_console(msg);
		sleep(10);
	}
	get_router();
	get_local_addresses();
	connect_to_server(h);
	main_loop(h);
	return 0;
}
