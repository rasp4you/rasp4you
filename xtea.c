#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <memory.h>

#define XTDELTA  0x9e3779b9
#define XTSUM    0xC6EF3720
#define ROUNDS   32

typedef unsigned XTeaKeyBlock_t[4];
static char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
static void XTeaCrypt(unsigned *w,  unsigned *v, XTeaKeyBlock_t k)
{
	unsigned y=v[0];
	unsigned z=v[1];
	unsigned sum=0;
	int n=ROUNDS;

	while (n-- > 0) {
		y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + k[sum&3]);
		sum += XTDELTA;
		z += (((y << 4) ^ (y >> 5)) + y) ^ (sum + k[sum>>11 & 3]);
	}
	w[0]=y; w[1]=z;
}
static void XTeaDecrypt(unsigned *w, unsigned *v, XTeaKeyBlock_t k)
{
	unsigned y=v[0];
	unsigned z=v[1];
	unsigned sum=XTSUM;
	int n=ROUNDS;

	while (n-- > 0) {
		z -= (((y << 4) ^ (y >> 5)) + y) ^ (sum + k[sum>>11 & 3]);
		sum -= XTDELTA;
		y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + k[sum&3]);
	}
	w[0]=y; w[1]=z;
//printf("Y=%u,Z=%u\n",y,z);
}
static int xteaenc( char *dst, char *src, char *pass)
{
	XTeaKeyBlock_t K = { 0,0,0,0};
	char tmp[257];
	int l, i;

/* Prepare pass as XTEA Key Block */
	l = strlen(pass);
	if( l>sizeof( XTeaKeyBlock_t))
		l = sizeof( XTeaKeyBlock_t);
	memcpy( K, pass, l);

	i = 0;
	l = strlen( src);
	if(l & 7) {
		memcpy(tmp,src,l);
		memset(tmp+l,0,l&7);
		l = (l+8) & ~7;
		src = tmp;
	}
	while (i<l) {
		XTeaCrypt( (unsigned*)dst, (unsigned*)src, K);
		src+=8; dst+=8; i+=8;
	}
	return l;
}
static void xteadec( char * dst, char *src, int len, char *pass)
{
	XTeaKeyBlock_t K = { 0,0,0,0};
	int l, i;

/* Prepare pass as XTEA Key Block */
	l = strlen(pass);
	if( l>sizeof( XTeaKeyBlock_t))
		l = sizeof( XTeaKeyBlock_t);
	memcpy( K, pass, l);

	i = 0;
	if(len & 7)
		len = (len+8) & ~7;
	while (i<len) {
		XTeaDecrypt( (unsigned*)dst, (unsigned *)src, K);
		src+=8; dst+=8; i+=8;
	}
}
void xteab64dec(char *dec,char *s,char *pwd)
{
	unsigned char chr1, chr2, chr3;
	unsigned char init[257], *enc;
	int enc1, enc2, enc3, enc4;
	int len;

	enc = init;
	len = strlen(s);
	while(len-- > 0) {
		enc1 = strchr(b64,*s++) - b64;
		if(len-- > 0) {
			enc2 = strchr(b64,*s++) - b64;
			if(len-- > 0) {
				enc3 = strchr(b64,*s++) - b64;
				if(len-- > 0)
					enc4 = strchr(b64,*s++) - b64;
				else
					enc4 = 0;
			} else
				enc3 = 0;
		} else
			enc2 = 0;

		chr1 = (enc1 << 2) | (enc2 >> 4);
		chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
		chr3 = ((enc3 & 3) << 6) | enc4;

		*enc++ = chr1;

		if (enc3 != 64)
		    *enc++ = chr2;
		if (enc4 != 64)
		    *enc++ = chr3;
	}
	*enc = 0;
	xteadec(dec,(char *)init,enc - init,pwd);
}
void xteab64enc(char *dec,char *s,char *pwd)
{
	unsigned char chr1, chr2, chr3;
	int enc1, enc2, enc3, enc4;
	char enc[257];
	int len;

	len = xteaenc(enc,s,pwd);

	s = enc;
	while(len-- > 0) {
		chr1 = *s++;
		if(len-- > 0) {
			chr2 = *s++;
			if(len-- > 0)
				chr3 = *s++;
			else
				chr3 = 0;
		} else
			chr2 = 0;

		enc1 = chr1 >> 2;
		enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
		enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
		enc4 = chr3 & 63;

		*dec++ = b64[enc1];
		*dec++ = b64[enc2];
		*dec++ = b64[enc3];
		*dec++ = b64[enc4];
	}
	*dec = 0;
}
