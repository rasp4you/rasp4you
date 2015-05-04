#ifndef __RASP4YOU_H
#define __RASP4YOU_H

#define RASP4YOU "server.rasp4you.com"
#define RASPBIAN 1
#define LINUX_64_BIT 2
#define LINUX_32_BIT 3

#define MIN_PORTS_SIZE 32

#define TEST_HTTP "GET / HTTP/1.0\r\nConnection:close\r\nContent-Length:0\r\n\r\n"

#define PID_FILE "/var/run/rasp4you.pid"
#define EXE_FILE "/usr/sbin/rasp4you"
#define EXE_TMP_FILE "/usr/sbin/rasp4you.tmp"
#define TMP_FILE "/tmp/rasp4you.tmp"
#define INITD_FILE "/etc/init.d/rasp4you"
#define RCD_FILE "/etc/rc2.d/rasp4you"
#define PAYSITE "https://pay.rasp4you.com"
#define PROGRAM_NAME "rasp4you"

#define LENKEY 32
#define LENMARK 32
enum {
	STATUS_BORN = 0,
	STATUS_REGISTERED = 1,
	WAITING_REGISTERED_ACK = 2
};

struct udp_request
{
	int fd;
	unsigned ip;
	unsigned short server_port;
	unsigned short local_port;
	struct udp_request *next;
};
struct lan
{
	char hw[6];	// indirizzo scheda
	char mac[6];
	char ottanta;
	char ottomila;
	char ottantaottanta;
	char index;
	char todo;
	unsigned local;
	unsigned ip;
	time_t time;
	time_t alive;
	time_t last_contacted;
	time_t tested;
	struct lan *next;
};
struct arp {
	unsigned char dst[6];
	unsigned char src[6];
	unsigned char type[2];
	unsigned char hw_fmt;
	unsigned char pr_fmt;
	unsigned char proto[2];
	unsigned char  sz_addr;
	unsigned char  sz_proto;
	unsigned char code[2];
	unsigned char eth_src[6];
	unsigned char ip_src[4];
	unsigned char eth_dst[6];
	unsigned char ip_dst[4];
};
#define ARP_REQUEST		1
#define ARP_REPLY		2

struct old_lan {
	unsigned ip;
	char mac[6];
	struct old_lan *next;
};

#define MAX_UDP_SIZE (1500-28)
#define SNAT_PORT 9999


extern struct sockaddr_in server_tcp;
extern struct sockaddr_in server_udp;
extern char key[];
extern char *raspberry_id;
extern unsigned short LOCAL_PORT, REMOTE_PORT;
extern struct lan *root_lan;
extern char *skeleton[];
extern unsigned LOCAL_ADDR;
extern unsigned local_addresses[];
extern unsigned serial;
extern char *machine_id;
extern unsigned router;
extern char *license[];
extern int arch;
extern int release;
extern int build;

extern void create_secret(char *secret,unsigned serial,char *key,char *header);
extern int check_secret(unsigned serial,char *key,char *header);
extern char *skip(char *s,int n);
extern void create_password(char *secret,unsigned serial,char *user,char *passwd);
extern int digest_check(char *email,char *url,char *nonce,char *digest,char *password);
extern void xteab64enc(char *dec,char *s,char *pwd);
extern void xteab64dec(char *dec,char *s,char *pwd);
extern int without_digest;

extern void make_key(void);
extern int check_key(void);
extern void install_initd(int install);
extern void install_exe(char *name);
extern void kill_the_rival(void);
extern void check_pid_file(void);
extern void create_pid_file(void);
extern int get_machine_id(void);
extern void gracefulshut(int handle);
extern void scan_loop(int esc);
extern void write_on_console(char *msg);


#endif

