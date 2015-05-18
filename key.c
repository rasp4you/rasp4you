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

static unsigned char marker[65+4+32] = "rasp4you for udp  channel  ready";
static char *keybin;

char *machine_id;
unsigned serial;
//char *raspberry_id;
char key[65];
char yek[65];

int get_machine_id(void)
{
	char *s, *t, *v;
	char line[512];
	FILE *fp;
	int fd;

	s = machine_id = malloc(128);
	fd = open("/etc/machine-id",O_RDONLY);
	if(fd >= 0) {
		if(read(fd,s,32) == 32)
			s += 32;
		close(fd);
	}
	fd = open("/sys/class/net/eth0/address",O_RDONLY);
	if(fd >= 0) {
		if(read(fd,s,17) == 17)
			s += 17;
		close(fd);
	} else if(s == machine_id) {
		fd = open("/sys/class/net/wlan0/address",O_RDONLY);
		if(fd >= 0) {
			if(read(fd,s,17) == 17)
				s += 17;
			close(fd);
		}
	}
	*s = 0;

	fp = fopen("/proc/cpuinfo","r");
	if(fp != NULL) {
		while(fgets(line,512,fp) != NULL) {
			if(strncmp(line,"Serial",6) == 0) {
				v = strchr(line,':');
				if(v++ != NULL) {
					while(*v == ' ' || *v == '\t')
						v++;
					t = strchr(v,'\n');
					if(t != NULL)
						*t = 0;
					strcpy(s,v);
					//raspberry_id = malloc(strlen(s)+1);
					//strcpy(raspberry_id,s);
				}
				break;
			}
		}
		fclose(fp);
	}
	return s > machine_id;
}
static void do_key()
{
	unsigned char *k;
	char *t = key;
	int i;

	for(k = (unsigned char *)keybin, i = 0;i < 32;i++) {
		unsigned n = *k++;
		sprintf(t,"%02x",n);
		t += 2;
	}
	k += 4;
	t = yek;
	for(i = 0;i < 32;i++) {
		unsigned n = *k++;
		sprintf(t,"%02x",n);
		t += 2;
	}
}
void make_key(void)
{
	unsigned char *s;
	int i, fd, n;

	s = &marker[LENMARK];
	fd = open("/dev/random",O_RDONLY);
	for(i = 32;i > 0;s += n, i -= n) {
		n = read(fd,s,i);
		if(n <= 0)
			break;
	}
	close(fd);
	if(marker[LENMARK] == 0)
		marker[LENMARK] = 0xFF;
	keybin = (char *)&marker[LENMARK];
	do_key();
}
int check_key(void)
{
	static int checked = -1;
	
	if(checked >= 0)
		return checked;
	keybin = (char *)&marker[LENMARK];
	if(with_test)
		memcpy(&serial,&with_test,4);
	else {
		memcpy(&serial,keybin + LENKEY,4);
		if(*keybin == 0)
			return checked = 0;
	}
	do_key();
	return checked = 1;
}
void install_initd(int install)
{
	char **q;
	FILE *fp;


     	system("sh -c \"if which invoke-rc.d >/dev/null 2>&1; then invoke-rc.d rasp4you stop; else /etc/init.d/rasp4you stop ; fi\" > /dev/null 2>&1");
	system("update-rc.d -f rasp4you remove > /dev/null 2>&1");
	unlink(INITD_FILE);
	if(!install)
		return;
	fp = fopen(INITD_FILE,"w");
	if(fp == NULL) {
		fprintf(stderr,"Panic create %s\n",INITD_FILE);
		exit(1);
	}
	for(q = skeleton;*q != NULL;q++)
		fprintf(fp,"%s\n",*q);
	fclose(fp);
	chown(INITD_FILE,0,0);
	chmod(INITD_FILE,0755);
	system("update-rc.d -f rasp4you defaults > /dev/null 2>&1");
     	system("sh -c \"if which invoke-rc.d >/dev/null 2>&1; then invoke-rc.d rasp4you start; else /etc/init.d/rasp4you start ; fi\" > /dev/null 2>&1");
}
void install_exe(char *name)
{
	unsigned char *t, *s;
	int found, n, size;
	int fdin, fdout;
	char yekbin[33];
	char buf[2048];
	int written;
	unsigned u;

	size = found = 0;
	fdin = open(name,O_RDONLY);
	fdout = open(EXE_TMP_FILE,O_WRONLY|O_CREAT,0700);
	if(fdout < 0) {
		fprintf(stderr,"Panic create %s\n",EXE_TMP_FILE);
		exit(1);
	}
	for(n = 0;n < 32;n++) {
		sscanf(&yek[n*2],"%2x",&u);
		yekbin[n] = u;
	}
	written = 0;
	for(;;) {
		n = read(fdin,buf+size,1024);
		if(n <= 0) {
			if(size)
				write(fdout,buf,size);
			break;
		}
		size += n;
		if(written) {
			write(fdout,buf,size);
			size = 0;
			continue;
		}

		found = 0;
		t = marker;
		s = (unsigned char *)buf;
		for(n = 0;n < size;n++) {
			if(*s++ == *t++) {
				if(++found == LENMARK)
					break;
			} else {
				t = marker;
				found = 0;
			}
		}
		if(!found) {
			write(fdout,buf,size);
			size = 0;
			continue;
		}
		if(found == LENMARK) {
			n = read(fdin,buf+size,LENKEY+4+LENKEY);
			size += n;
			memcpy(s,keybin,LENKEY);
			memcpy(s + LENKEY,&serial,4);
			memcpy(s + LENKEY + 4,yekbin,LENKEY);
			write(fdout,buf,size);
			written = 1;
			size = 0;
		} else {
			size -= found;
			if(size)
				write(fdout,buf,size);
			memcpy(buf,marker,size = found);
			found = 0;
		}
	}
	fchmod(fdout,0744);
	fchown(fdout,0,0);
	close(fdout);
	close(fdin);
	unlink(EXE_FILE);
	rename(EXE_TMP_FILE,EXE_FILE);
}
void kill_the_rival(void)
{
	char rival[64];
	char buf[256];
	pid_t pid;
	FILE *fp;
	int size;

	fp = fopen(PID_FILE,"r");
	if(fp == NULL)
		return;
	if(fgets(buf,128,fp) != NULL && sscanf(buf,"%u",&pid) == 1) {
		sprintf(rival,"/proc/%u/exe",pid);
		size = readlink(rival,buf,128);
		if(size > 0) {
			buf[size] = 0;
			if(strcmp(buf,EXE_FILE) == 0) {
				if(pid == getpid()) {
					fclose(fp);
					return;
				}
				kill(pid,SIGKILL);
			}
		}
	}
	fclose(fp);
	unlink(PID_FILE);
	return;
}
void check_pid_file(void)
{
	char buf[256];
	pid_t pid;
	FILE *fp;

	fp = fopen(PID_FILE,"r");
	if(fp == NULL)
		return;
	if(fgets(buf,128,fp) != NULL && sscanf(buf,"%u",&pid) == 1) {
		if(pid != getpid())
			exit(0);
	}
	fclose(fp);
}
void create_pid_file(void)
{
	FILE *fp;

	fp = fopen(PID_FILE,"w");
	fprintf(fp,"%u\n",getpid());
	fclose(fp);
}
