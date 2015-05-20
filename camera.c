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
#include <pthread.h>
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

#define MAX_CONNECTED 8

#define DQT      0xDB   // Define Quantization Table
#define SOF      0xC0   // Start of Frame (size information)
#define DHT      0xC4   // Huffman Table
#define SOI      0xD8   // Start of Image
#define SOS      0xDA   // Start of Scan
#define EOI      0xD9   // End of Image, or End of File
#define APP0     0xE0

#define HEADER     "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nCache-Control: private\r\nPragma: no-cache\r\nContent-type: multipart/x-mixed-replace; boundary=__rasp4you__easy__access__\r\n\r\n"
#define HTML       "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nCache-Control: private\r\nPragma: no-cache\r\nContent-type: text/html\r\nContent-Length: %d\r\n\r\n"
#define ICO_HEADER "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nCache-Control: private\r\nPragma: no-cache\r\nContent-type: image/x-icon\r\nContent-Length: %d\r\n\r\n"
#define PNG_HEADER "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nCache-Control: private\r\nPragma: no-cache\r\nContent-type: image/png\r\nContent-Length: %d\r\n\r\n"
#define JPG_HEADER "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nCache-Control: private\r\nPragma: no-cache\r\nContent-type: image/jpeg\r\nContent-Length: %d\r\n\r\n"

#define HEADER_TEST "PTTH/1.1 200 OK\r\n\r\n"
#define HEADER_NOTFOUND "HTTP/1.1 404 KO\r\n\r\n"
#define BOUNDARY "--__rasp4you__easy__access__\r\n"
#define REDAEH     "Content-type: image/jpeg\r\nContent-Length:%d\r\n\r\n"

#define SEGATOR 1

static pthread_mutex_t mutex;
struct channel {
	int sd;
	int ready;
	int jpg;
	char *got;
};
static struct channel channels[MAX_CONNECTED];

static pthread_t thread_camerata;
unsigned short camerata_port;
static char *html;

static void load_html(void)
{
	char **s, *t;

	int size = 0;

	for(s = mjpeg;*s != NULL;s++)
		size += strlen(*s) + 1;
	t = html = malloc(size+strlen(HTML)+16);
	t += sprintf(t,HTML,size);
	for(s = mjpeg;*s != NULL;s++)
		t += sprintf(t,"%s\n",*s);
}
static int test_camera(void)
{
	int status;
	pid_t pid;

	pid = fork();
	if(pid == 0) {
		close(1);
		close(2);
		execlp("raspistill","raspistill", "-t","30", NULL);
		exit(70);
	}
	wait(&status);
	if(!WIFEXITED(status))
		return 0;
	if(WEXITSTATUS(status) != 0)
		return 0;
	return 1;
}
static void camerata_lock(void)
{
        pthread_mutex_lock(&mutex);
}
static void camerata_unlock(void)
{
        pthread_mutex_unlock(&mutex);
}
void camerata_connect(int left,char *header)
{
	struct channel *c = channels;
	int n;

	camerata_lock();
	for(n = 0;n < MAX_CONNECTED;n++, c++)
		if(c->sd < 0)
			break;
	if(n == MAX_CONNECTED) {
		camerata_unlock();
		close(left);
		return;
	}
	c->sd = left;
	c->ready = 0;
	write(left,header,strlen(header)+1);
	pthread_kill(thread_camerata,SIGUSR1);
	camerata_unlock();
}
static void hdl(int signo)
{
}
static void close_channel(struct channel *c)
{
	if(c->got) {
		free(c->got);
		c->got = NULL;
	}
	close(c->sd);
	c->sd = -1;
}
static unsigned char *collaer(unsigned char *buf,int gross,unsigned char **s,unsigned char **sm)
{
	unsigned char *new = realloc(buf,gross);

	if(new != buf) {
		if(s)
			*s = new + (*s - buf);
		if(sm)
			*sm = new + (*sm - buf);
	}
	return new;
}
void *process_camerata(void * param)
{
	int ok, used, n, size, len, found, max, some;
	unsigned char *buf, *s, marker, *sm;
	int WIDTH, HEIGHT, QUALITY;
	struct sockaddr_in from;
	struct sigaction act;
	int scan_active = 0;
	unsigned short port;
	fd_set rdset, wrset;
	struct channel *c;
	int start, status;
	pthread_t thread;
	int connected;
	int fdv[2];
	int bufsiz;
	pid_t pid;
	char *t;
	int sd;

	buf = NULL;
	pthread_mutex_init(&mutex,NULL);
again:
	camerata_lock();
	for(;;) {
		if(test_camera())
			break;
		if(!scan_active) {
			pthread_create(&thread, NULL, scan_loop, (void*)NULL);
			scan_active = 1;
		}
		sleep(5*60);
	}
	n = 1;
	from.sin_family = AF_INET;
	from.sin_addr.s_addr = INADDR_ANY;
	sd = socket(AF_INET,SOCK_STREAM,0);
	setsockopt(sd,SOL_SOCKET,SO_REUSEADDR,(char*)&n,sizeof(n));
	for(port = 9000;port < 9000+1024;port++) {
		from.sin_port = htons(port);
		if(bind(sd,(struct sockaddr *)&from,sizeof(from)) >= 0)
			break;
	}
	if(port == 9000+1024) {
		if(!scan_active) {
			pthread_create(&thread, NULL, scan_loop, (void*)NULL);
			scan_active = 1;
		}
		close(sd);
		camerata_unlock();
		return NULL;
	}
	memset(&act,0,sizeof(act));
	act.sa_handler = &hdl;
	sigaction(SIGUSR1,&act,NULL);

	listen(sd,MAX_CONNECTED);
	if(!scan_active) {
		pthread_create(&thread, NULL, scan_loop, (void*)NULL);
		scan_active = 1;
	}

	if(html == NULL)
		load_html();

	ok = pid = 0;
	for(n = 0, c = channels;n < MAX_CONNECTED;n++, c++)
		c->sd = -1;
	WIDTH = HEIGHT = QUALITY = 0;
	camerata_port = from.sin_port;
	thread_camerata = pthread_self();
	for(;;) {
next:
		if(!cameras) {
			for(n = 0, c = channels;n < MAX_CONNECTED;n++, c++) {
				if(c->sd >= 0 && c->ready) {
					close(c->sd);
					c->sd = -1;
				}
			}
			if(pid > 0) {
				close(fdv[0]);
				kill(pid,SIGKILL);
				wait(&status);
				pid = 0;
			}
		}
		some = 0;
		max = 0;
		FD_ZERO(&rdset);
		FD_ZERO(&wrset);
		for(connected = n = 0, c = channels;n < MAX_CONNECTED;n++, c++) {
			if(c->sd < 0) {
				c->ready = 0;
				some = 1;
				continue;
			}
			if(c->ready) {
				ioctl(c->sd,SIOCOUTQ,&size);
				if(!size)
					FD_SET(c->sd,&wrset);
				connected++;
			}
			FD_SET(c->sd,&rdset);
			if(c->sd > max)
				max = c->sd;
		}
		if(!connected && pid > 0) {
			close(fdv[0]);
			kill(pid,SIGKILL);
			wait(&status);
			ok = pid = 0;
		}
		if(some) {
			FD_SET(sd,&rdset);
			if(sd > max)
				max = sd;
		}
		if(pid > 0) {
			FD_SET(fdv[0],&rdset);
			if(fdv[0] > max)
				max = fdv[0];
		}
		camerata_unlock();
		if(select(max+1,&rdset,&wrset,NULL,NULL) < 0)
			continue;
		camerata_lock();
		if(FD_ISSET(sd,&rdset)) {
			int fd;

			fd = accept(sd,NULL,NULL);
			if(fd < 0)
				continue;
			for(n = 0, c = channels;n < MAX_CONNECTED;n++, c++)
				if(c->sd < 0)
					break;
			if(n == MAX_CONNECTED) {
				close(fd);
				continue;
			}
			c->sd = fd;
		}
		for(n = 0, c = channels;n < MAX_CONNECTED;n++, c++) {
			if(c->sd >= 0 && FD_ISSET(c->sd,&rdset)) {
				int width, height, quality, rem;

				if(buf == NULL)
					buf = malloc(bufsiz = 4096);

				ioctl(c->sd,FIONREAD,&size);
				if(c->got != NULL) {
					rem = strlen(c->got);
					strcpy((char *)buf,c->got);
					free(c->got);
					c->got = NULL;
				}
				else
					rem = 0;
				size = read(c->sd,buf+rem,size);
				if(size <= 0) {
					close_channel(c);
					continue;
				}
				size += rem;
				buf[size] = 0;
				if(strncmp((char *)buf,TEST_HTTP_LOCAL,strlen(TEST_HTTP_LOCAL)) == 0) {
					write(c->sd,HEADER_TEST,strlen(HEADER_TEST));
					shutdown(c->sd,SHUT_WR);
					continue;
				}
				if(!cameras) {
					close_channel(c);
					continue;
				}
				s = (unsigned char *)strstr((char *)buf,"\r\n\r\n");
				if(s == NULL) {
					c->got = malloc(size + 1);
					strcpy(c->got,(char *)buf);
					continue;
				}
				
				s = (unsigned char *)strstr((char *)buf,"\r\n");
				if(s == NULL || strncmp((char *)buf,"GET",3)) {
					close_channel(c);
					continue;
				}
				*s = 0;
				for(s = buf+4;*s == ' ' || *s == '\t';s++)
					;
				for(sm = s;*sm && *sm != ' ' && *sm != '\t';sm++)
					;
				*sm = 0;

				
				width = 320;
				height = 240;
				quality = 90;
				sm = (unsigned char *)strchr((char *)s,'?');
				if(sm != NULL) {
					*sm++ = 0;
					for(;;) {
						t = strchr((char *)sm,'&');
						if(t != NULL)
							*t++ = 0;
						if(strncmp((char *)sm,"q=",2) == 0)
							quality = atoi((char *)sm + 2);
						else if(strncmp((char *)sm,"w=",2) == 0)
							width = atoi((char *)sm + 2);
						else if(strncmp((char *)sm,"h=",2) == 0)
							height = atoi((char *)sm + 2);
						if(t == NULL)
							break;
						sm = (unsigned char *)t;
					}
				}
				if(quality < 1)
					quality = 1;
				else if(quality > 100)
					quality = 100;
				if(strcmp((char *)s,"/") == 0 || strcmp((char *)s,"/index.html") == 0 || strcmp((char *)s,"/index.htm") == 0) {
					sprintf((char *)buf,html,width,height,quality);
					write(c->sd,(char *)buf,strlen((char *)buf));
				} else if(strcmp((char *)s,"/logo.ico") == 0 || strcmp((char *)s,"/favicon.ico") == 0) {
					sprintf((char *)buf,ICO_HEADER,ico_size);
					write(c->sd,(char *)buf,strlen((char *)buf));
					write(c->sd,ico,ico_size);
				} else if(strcmp((char *)s,"/logo-80x47.png") == 0) {
					sprintf((char *)buf,PNG_HEADER,logo_size);
					write(c->sd,(char *)buf,strlen((char *)buf));
					write(c->sd,logo,logo_size);
				} else if(strstr((char *)s,".jpeg") != NULL || strstr((char *)s,".mjpeg") != NULL || strstr((char *)s,".jpg") != NULL || strstr((char *)s,".mpg") != NULL) {
					if(strstr((char *)s,".mjpeg") != NULL || strstr((char *)s,".mjpg") != NULL) {
						write(c->sd,HEADER,strlen(HEADER));
						c->jpg = 0;
					} else {
						c->jpg = 1;
					}
					c->ready = 1;
					if(quality != QUALITY || width != WIDTH || height != HEIGHT) {
						if(pid > 0) {
							close(fdv[0]);
							kill(pid,SIGKILL);
							wait(&status);
							ok = pid = 0;
						}
						QUALITY = quality;
						WIDTH   = width;
						HEIGHT  = height;
					}
				} else {
					write(c->sd,HEADER_NOTFOUND,strlen(HEADER_NOTFOUND));
					shutdown(c->sd,SHUT_WR);
				}
			}
		}
		for(n = connected = 0, c = channels;n < MAX_CONNECTED;n++, c++)
			if(c->sd >= 0 && c->ready)
				connected++;
		if(!connected)  {
			if(pid == 0 || !FD_ISSET(fdv[0],&rdset))
				continue;
		}
		if(pid == 0) {
			pipe(fdv);
			pid = fork();
			if(pid == 0) {
				char h[16], w[16], q[16];

				sprintf(w,"%d",WIDTH);
				sprintf(h,"%d",HEIGHT);
				sprintf(q,"%d",QUALITY);

				close(1);
				dup(fdv[1]);
				close(fdv[0]);
				close(fdv[1]);
				close(2);
				execlp("raspistill","raspistill","-th","none","-bm", "-n", "-o", "-", "-t","99999999","-tl","0","-w",w,"-h",h, "-q", q, NULL);
				exit(1);
			}
			close(fdv[1]);
		}
		if(ok + 2048 >= bufsiz)
			buf = collaer(buf,bufsiz += 4096,NULL,NULL);
		size = read(fdv[0],buf + ok,2048);
		if(size <= 0)
			goto shut;
		size += ok;
		start = -1;
		used = ok = 0;
		for(sm = s = buf;used++ < size;s++) {
			if(ok && *s == 0xD8) {
				start = used - 2;
				s++;
				break;
			}
			ok = *s == 0xFF;
		}
		if(start < 0) {
			ok = 0;
			kill(pid,SIGKILL);
			wait(&status);
			pid = 0;
			continue;
		}
		ok = 0;
		if(start > 0) {
			size -= start;
			memcpy(buf,buf+start,size);
			s -= start;
		}
		used = s - buf;
		for(;;) {
			if(used == size) {
				if(size + 2048 >= bufsiz)
					buf = collaer(buf,bufsiz += 4096,&s,&sm);
				n = read(fdv[0],buf + size,2048);
				if(n <= 0)
					goto shut;
				size += n;
			}
			sm = s;
			used++;
			if(*s++ != 0xFF) {
				ok = size - used;
				if(ok > 0)
					memcpy(buf,s,ok);
				goto next;
			}
			for(;;) {
				if(used == size) {
					if(size + 2048 >= bufsiz)
						buf = collaer(buf,bufsiz += 4096,&s,&sm);
					n = read(fdv[0],buf + size,2048);
					if(n <= 0)
						goto shut;
					size += n;
				}
				used++;
				marker = *s++;
				if(marker != 0xFF)
					break;
			}
			if(marker == SOS)
				break;
			if(marker == SOI) {
				ok = size - used + 2;
				memcpy(buf,s-2,ok);
				goto next;
			}
			if(marker == EOI) {
				ok = size - used;
				if(ok > 0)
					memcpy(buf,s,ok);
				goto next;
			}
			if(size - used < 2) {
				if(size + 2048 >= bufsiz)
					buf = collaer(buf,bufsiz += 4096,&s,&sm);
				n = read(fdv[0],buf + size,2048);
				if(n <= 0)
					goto shut;
				size += n;
			}
			len = (s[0] << 8);
			len |= s[1];

			if(SEGATOR && (marker & 0xE0) == 0xE0 && size >= 4 && (len - (size - used)) > 0) {
				int skip = len - (size - used);

				s = sm;
				used = size = s - buf;
				while(skip > 0) {
					if(skip > 2048)
						n = 2048;
					else
						n = skip;
					if(size + 2048 >= bufsiz)
						buf = collaer(buf,bufsiz += 4096,&s,&sm);
					n = read(fdv[0],buf + size,n);
					if(n <= 0)
						goto shut;
					skip -= n;
				}

			} else {
				while(size - used < len) {
					n = len - (size - used);
					if(n > 2048)
						n = 2048;
					if(size + 2048 >= bufsiz)
						buf = collaer(buf,bufsiz += 4096,&s,&sm);
					n = read(fdv[0],buf + size,n);
					if(n <= 0)
						goto shut;
					size += n;
				}
				s += len;
				used += len;
			}
		}
		found = 0;
		for(;;) {
			if(used == size) {
				if(size + 2048 >= bufsiz)
					buf = collaer(buf,bufsiz += 4096,&s,&sm);
				n = read(fdv[0],buf + size,2048);
				if(n <= 0)
					goto shut;
				size += n;
			}
			used++;
			if(found && *s == 0xD9) {
				s++;
				break;
			}
			found = *s == 0xFF;
			s++;
		}
		len = used;

		for(n = 0, c = channels;n < MAX_CONNECTED;n++, c++) {
			if(c->sd >= 0 && FD_ISSET(c->sd,&wrset)) {
				char header[128];

				if(c->jpg)
					sprintf(header,JPG_HEADER,len);
				else
					sprintf(header,REDAEH,len);
				if(write(c->sd,header,strlen(header)) < 0)
					close_channel(c);
			}
		}
		sm = buf;
		while(len > 0) {
			if(len > 2048)
				ok = 2048;
			else
				ok = len;
			for(n = 0, c = channels;n < MAX_CONNECTED;n++, c++)
				if(c->sd >= 0 && FD_ISSET(c->sd,&wrset))
					if(write(c->sd,sm,ok) < 0)
						close_channel(c);
			len -= ok;
			sm += ok;
		}
		for(n = 0, c = channels;n < MAX_CONNECTED;n++, c++)
			if(c->sd >= 0 && FD_ISSET(c->sd,&wrset))
				if(!c->jpg)
					if(write(c->sd,BOUNDARY,strlen(BOUNDARY)) < 0)
						close_channel(c);
		ok = size - used;
		if(ok > 0)
			memcpy(buf,s,ok);
	}
shut:
	for(n = 0, c = channels;n < MAX_CONNECTED;n++, c++)
		if(c->sd >= 0)
			close_channel(c);
	close(sd);
	if(pid > 0) {
		kill(pid,SIGKILL);
		wait(&status);
		pid = 0;
	}
	goto again;

	return NULL;
}
