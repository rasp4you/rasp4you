#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "rasp4you.h"

#define HASHLEN 16

#ifdef __STDC__
#define UL(x)   x##U
#else
#define UL(x)   x
#endif

typedef unsigned U32BIT;
typedef struct {
  U32BIT i[2];                   /* number of _bits_ handled mod 2^64 */
  U32BIT buf[4];                                    /* scratch buffer */
  unsigned char in[64];                              /* input buffer */
} MD5_CTX;

static const unsigned char PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G, H and I are basic MD5 functions */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (U32BIT)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (U32BIT)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (U32BIT)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (U32BIT)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }


void bin2hex(unsigned char *Bin,unsigned char *Hex,unsigned char len)
{
	unsigned char i, j;

	for (i = 0; i < len; i++) {
		j = (*Bin >> 4) & 0xf;
		if (j <= 9)
			*Hex++ = (j + '0');
		else
			*Hex++ = (j + 'a' - 10);
		j = *Bin++ & 0xf;
		if(j <= 9)
			*Hex++ = (j + '0');
		else
			*Hex++ = (j + 'a' - 10);
	}
	*Hex = '\0';
}
static void Transform (U32BIT *buf,U32BIT *in)
{
	U32BIT a = buf[0], b = buf[1], c = buf[2], d = buf[3];

	/* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
	FF ( a, b, c, d, in[ 0], S11, UL(3614090360)); /* 1 */
	FF ( d, a, b, c, in[ 1], S12, UL(3905402710)); /* 2 */
	FF ( c, d, a, b, in[ 2], S13, UL( 606105819)); /* 3 */
	FF ( b, c, d, a, in[ 3], S14, UL(3250441966)); /* 4 */
	FF ( a, b, c, d, in[ 4], S11, UL(4118548399)); /* 5 */
	FF ( d, a, b, c, in[ 5], S12, UL(1200080426)); /* 6 */
	FF ( c, d, a, b, in[ 6], S13, UL(2821735955)); /* 7 */
	FF ( b, c, d, a, in[ 7], S14, UL(4249261313)); /* 8 */
	FF ( a, b, c, d, in[ 8], S11, UL(1770035416)); /* 9 */
	FF ( d, a, b, c, in[ 9], S12, UL(2336552879)); /* 10 */
	FF ( c, d, a, b, in[10], S13, UL(4294925233)); /* 11 */
	FF ( b, c, d, a, in[11], S14, UL(2304563134)); /* 12 */
	FF ( a, b, c, d, in[12], S11, UL(1804603682)); /* 13 */
	FF ( d, a, b, c, in[13], S12, UL(4254626195)); /* 14 */
	FF ( c, d, a, b, in[14], S13, UL(2792965006)); /* 15 */
	FF ( b, c, d, a, in[15], S14, UL(1236535329)); /* 16 */

	/* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
	GG ( a, b, c, d, in[ 1], S21, UL(4129170786)); /* 17 */
	GG ( d, a, b, c, in[ 6], S22, UL(3225465664)); /* 18 */
	GG ( c, d, a, b, in[11], S23, UL( 643717713)); /* 19 */
	GG ( b, c, d, a, in[ 0], S24, UL(3921069994)); /* 20 */
	GG ( a, b, c, d, in[ 5], S21, UL(3593408605)); /* 21 */
	GG ( d, a, b, c, in[10], S22, UL(  38016083)); /* 22 */
	GG ( c, d, a, b, in[15], S23, UL(3634488961)); /* 23 */
	GG ( b, c, d, a, in[ 4], S24, UL(3889429448)); /* 24 */
	GG ( a, b, c, d, in[ 9], S21, UL( 568446438)); /* 25 */
	GG ( d, a, b, c, in[14], S22, UL(3275163606)); /* 26 */
	GG ( c, d, a, b, in[ 3], S23, UL(4107603335)); /* 27 */
	GG ( b, c, d, a, in[ 8], S24, UL(1163531501)); /* 28 */
	GG ( a, b, c, d, in[13], S21, UL(2850285829)); /* 29 */
	GG ( d, a, b, c, in[ 2], S22, UL(4243563512)); /* 30 */
	GG ( c, d, a, b, in[ 7], S23, UL(1735328473)); /* 31 */
	GG ( b, c, d, a, in[12], S24, UL(2368359562)); /* 32 */

	/* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
	HH ( a, b, c, d, in[ 5], S31, UL(4294588738)); /* 33 */
	HH ( d, a, b, c, in[ 8], S32, UL(2272392833)); /* 34 */
	HH ( c, d, a, b, in[11], S33, UL(1839030562)); /* 35 */
	HH ( b, c, d, a, in[14], S34, UL(4259657740)); /* 36 */
	HH ( a, b, c, d, in[ 1], S31, UL(2763975236)); /* 37 */
	HH ( d, a, b, c, in[ 4], S32, UL(1272893353)); /* 38 */
	HH ( c, d, a, b, in[ 7], S33, UL(4139469664)); /* 39 */
	HH ( b, c, d, a, in[10], S34, UL(3200236656)); /* 40 */
	HH ( a, b, c, d, in[13], S31, UL( 681279174)); /* 41 */
	HH ( d, a, b, c, in[ 0], S32, UL(3936430074)); /* 42 */
	HH ( c, d, a, b, in[ 3], S33, UL(3572445317)); /* 43 */
	HH ( b, c, d, a, in[ 6], S34, UL(  76029189)); /* 44 */
	HH ( a, b, c, d, in[ 9], S31, UL(3654602809)); /* 45 */
	HH ( d, a, b, c, in[12], S32, UL(3873151461)); /* 46 */
	HH ( c, d, a, b, in[15], S33, UL( 530742520)); /* 47 */
	HH ( b, c, d, a, in[ 2], S34, UL(3299628645)); /* 48 */

	/* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
	II ( a, b, c, d, in[ 0], S41, UL(4096336452)); /* 49 */
	II ( d, a, b, c, in[ 7], S42, UL(1126891415)); /* 50 */
	II ( c, d, a, b, in[14], S43, UL(2878612391)); /* 51 */
	II ( b, c, d, a, in[ 5], S44, UL(4237533241)); /* 52 */
	II ( a, b, c, d, in[12], S41, UL(1700485571)); /* 53 */
	II ( d, a, b, c, in[ 3], S42, UL(2399980690)); /* 54 */
	II ( c, d, a, b, in[10], S43, UL(4293915773)); /* 55 */
	II ( b, c, d, a, in[ 1], S44, UL(2240044497)); /* 56 */
	II ( a, b, c, d, in[ 8], S41, UL(1873313359)); /* 57 */
	II ( d, a, b, c, in[15], S42, UL(4264355552)); /* 58 */
	II ( c, d, a, b, in[ 6], S43, UL(2734768916)); /* 59 */
	II ( b, c, d, a, in[13], S44, UL(1309151649)); /* 60 */
	II ( a, b, c, d, in[ 4], S41, UL(4149444226)); /* 61 */
	II ( d, a, b, c, in[11], S42, UL(3174756917)); /* 62 */
	II ( c, d, a, b, in[ 2], S43, UL( 718787259)); /* 63 */
	II ( b, c, d, a, in[ 9], S44, UL(3951481745)); /* 64 */

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}
static void MD5Init (MD5_CTX *ctx)
{
	memset(ctx,'\0',sizeof(*ctx));
	ctx->i[0]   = ctx->i[1] = (U32BIT)0;
	ctx->buf[0] = (U32BIT)0x67452301;
	ctx->buf[1] = (U32BIT)0xefcdab89;
	ctx->buf[2] = (U32BIT)0x98badcfe;
	ctx->buf[3] = (U32BIT)0x10325476;
}
static void MD5Update(MD5_CTX *ctx,unsigned char *inBuf)
{
	unsigned short inLen;
	unsigned char mdi;
	//U32BIT in[16];

	inLen = strlen((char *)inBuf);
	mdi   = (unsigned char)((ctx->i[0] >> 3) & 0x3F);
	if ((ctx->i[0] + ((U32BIT)inLen << 3)) < ctx->i[0])
		ctx->i[1]++;
	ctx->i[0] += ((U32BIT)inLen << 3);
	ctx->i[1] += ((U32BIT)inLen >> 29);
	while (inLen--) {
		ctx->in[mdi++] = *inBuf++;
		if (mdi == 0x40) {
			U32BIT INNE[16];

			memcpy((void *)INNE,(void *)ctx->in,16 * sizeof(U32BIT));
			Transform (ctx->buf, INNE);
			mdi = 0;
		}
	}
}
static void MD5UpdateWithLen (MD5_CTX *ctx,const unsigned char *inBuf,unsigned short inLen)
{
	//U32BIT in[16];
	unsigned char mdi;

	mdi   = (unsigned char)((ctx->i[0] >> 3) & 0x3F);
	if ((ctx->i[0] + ((U32BIT)inLen << 3)) < ctx->i[0])
		ctx->i[1]++;
	ctx->i[0] += ((U32BIT)inLen << 3);
	ctx->i[1] += ((U32BIT)inLen >> 29);
	while (inLen--) {
		ctx->in[mdi++] = *inBuf++;
		if (mdi == 0x40) {
			U32BIT INNE[16];

			memcpy((void *)INNE,(void *)ctx->in,16 * sizeof(U32BIT));
			Transform (ctx->buf, INNE);
			mdi = 0;
		}
	}
}

/* The routine MD5Final terminates the message-digest computation and
   ends with the desired message digest in mdContext->digest[0...15].
 */
static void MD5Final (MD5_CTX *ctx,unsigned char hash[])
{
	unsigned char padLen, mdi;

	U32BIT i14, i15;
	U32BIT INNE[16];

	i14 = ctx->i[0];
	i15 = ctx->i[1];
	mdi    = (unsigned char)((ctx->i[0] >> 3) & 0x3F);
	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
	MD5UpdateWithLen (ctx,PADDING, padLen);
	memcpy((void *)INNE,(void *)ctx->in,14 * sizeof(U32BIT));
	INNE[14] = i14;
	INNE[15] = i15;
	Transform (ctx->buf, INNE);
	memcpy((void *)hash,(void *)ctx->buf,16);
}
static void _create_secret(char *secret,unsigned serial,char *key,char *header,char *time)
{
	unsigned char HA[HASHLEN];
	char tmp1[HASHLEN*2+3];
	char tmp2[HASHLEN*2+3];
	char user[9], *s;
	MD5_CTX ctx;

	sprintf(user,"%08x",serial);


        MD5Init(&ctx);
	MD5Update(&ctx,(unsigned char *)user);
	MD5Update(&ctx,(unsigned char *)key);
	MD5Final(&ctx,HA);
	bin2hex(HA,(unsigned char *)tmp1,HASHLEN);

        MD5Init(&ctx);

	s = skip(header,1);
	*(s-1) = 0;
	MD5Update(&ctx,(unsigned char *)header);		// tutto l'header meno il serial
	*(s-1) = '|';
	s = skip(header,2);
	if(s != NULL) {
		MD5Update(&ctx,(unsigned char *)s);
	}

	MD5Final(&ctx,HA);
	bin2hex(HA, (unsigned char *)tmp2,HASHLEN);

        MD5Init(&ctx);
	MD5Update(&ctx,(unsigned char *)tmp1);
	MD5Update(&ctx,(unsigned char *)time);
	MD5Update(&ctx,(unsigned char *)tmp2);
	MD5Final(&ctx,HA);

	strcpy(secret,time);
	bin2hex(HA, (unsigned char *)(secret+8),HASHLEN);
	secret[HASHLEN*2+8] = 0;
}
void create_secret(char *secret,unsigned serial,char *key,char *header)
{
	char buf[16];
	sprintf(buf,"%08x",(unsigned)time(NULL));
	_create_secret(secret,serial,key,header,buf);
}
int check_secret(unsigned serial,char *key,char *header)
{
	char secret[129], time[16];
	char *s, *t;
	int ret;

	s = strchr(header,'?');
	if(s == NULL)
		return 0;
	*s = 0;
	memcpy(time,s+1,8);
	time[8] = 0;
	_create_secret(secret,serial,key,header,time);
	t = strchr(s+1,'|');
	if(t != NULL)
		*t = 0;
	ret = strcmp(secret,s+1) == 0;
	if(t != NULL)
		*t = '|';
	*s = '?';
	return ret;
}
int digest_check(char *email,char *url,char *nonce,char *digest,char *password)
{
	unsigned char HA[HASHLEN];
	char tmp1[HASHLEN*2+3];
	char tmp2[HASHLEN*2+3];
	char secret[129];
	MD5_CTX ctx;

	if(password == NULL)
		return 0;
	xteab64dec(secret,password,email);
        MD5Init(&ctx);
	MD5Update(&ctx,(unsigned char *)email);
	MD5Update(&ctx,(unsigned char *)secret);
	MD5Final(&ctx,HA);
	bin2hex(HA,(unsigned char *)tmp1,HASHLEN);

        MD5Init(&ctx);
	MD5Update(&ctx,(unsigned char *)url);
	MD5Final(&ctx,HA);
	bin2hex(HA, (unsigned char *)tmp2,HASHLEN);

        MD5Init(&ctx);
	MD5Update(&ctx,(unsigned char *)tmp1);
	MD5Update(&ctx,(unsigned char *)tmp2);
	MD5Update(&ctx,(unsigned char *)nonce);
	MD5Final(&ctx,HA);

	bin2hex(HA, (unsigned char *)secret,HASHLEN);
	return strcmp(secret,digest) == 0;
}
char *skip(char *s,int n)
{
	char *t;

	while(n--) {
		t = strchr(s,'|');
		if(t == NULL)
			return NULL;
		s = t + 1;
	}
	return s;
}
