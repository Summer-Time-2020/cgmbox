/* ====================================================================
 * Copyright (c) Summer-Time-2020。 All rights reserved.
 *Licensed under the Apache License, Version 2.0 (the "License");
 *you may not use this file except in compliance with the License.
 *You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 *Unless required by applicable law or agreed to in writing, software
 *distributed under the License is distributed on an "AS IS" BASIS,
 *WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *See the License for the specific language governing permissions and
 *limitations under the License.
 * ====================================================================
*/
#include <string.h>
#include <stdlib.h>
#include "cgmbox/cgmbox_sm3.h"

#ifdef CPU_BIGENDIAN

#define cpu_to_be16(v) (v)
#define cpu_to_be32(v) (v)
#define be16_to_cpu(v) (v)
#define be32_to_cpu(v) (v)

#else

#define cpu_to_le16(v) (v)
#define cpu_to_le32(v) (v)
#define le16_to_cpu(v) (v)
#define le32_to_cpu(v) (v)

#define cpu_to_be16(v) (((v)<< 8) | ((v)>>8))
#define cpu_to_be32(v) (((v)>>24) | (((v)>>8)&0xff00) | (((v)<<8)&0xff0000) | ((v)<<24))
#define be16_to_cpu(v) cpu_to_be16(v)
#define be32_to_cpu(v) cpu_to_be32(v)

#endif

#define ROTATELEFT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x),9)  ^ ROTATELEFT((x),17))
#define P1(x) ((x) ^  ROTATELEFT((x),15) ^ ROTATELEFT((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


static void sm3_compress(unsigned int digest[8], const unsigned char block[64])
{
	int j;
	unsigned int W[68], W1[64];
	const unsigned int *pblock = (const unsigned int *)block;

	unsigned int A = digest[0];
	unsigned int B = digest[1];
	unsigned int C = digest[2];
	unsigned int D = digest[3];
	unsigned int E = digest[4];
	unsigned int F = digest[5];
	unsigned int G = digest[6];
	unsigned int H = digest[7];
	unsigned int SS1,SS2,TT1,TT2,T[64];

	for (j = 0; j < 16; j++) {
		W[j] = cpu_to_be32(pblock[j]);
	}
	for (j = 16; j < 68; j++) {
		W[j] = P1( W[j-16] ^ W[j-9] ^ ROTATELEFT(W[j-3],15)) ^ ROTATELEFT(W[j - 13],7 ) ^ W[j-6];;
	}
	for( j = 0; j < 64; j++) {
		W1[j] = W[j] ^ W[j+4];
	}

	for(j =0; j < 16; j++) {

		T[j] = 0x79CC4519;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	for(j =16; j < 64; j++) {

		T[j] = 0x7A879D8A;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j%32)), 7);
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}

CGMBOX_EXPORT void cgmbox_sm3_init(cgmbox_sm3_ctx_t *ctx)
{
	/* 
	初始IV = 7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e
	 */
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;
}

CGMBOX_EXPORT void cgmbox_sm3_update(cgmbox_sm3_ctx_t *ctx, const unsigned char* data, unsigned int data_len)
{
	if (ctx->num) {
		unsigned int left = CGMBOX_SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}
	while (data_len >= CGMBOX_SM3_BLOCK_SIZE) {
		sm3_compress(ctx->digest, data);
		ctx->nblocks++;
		data += CGMBOX_SM3_BLOCK_SIZE;
		data_len -= CGMBOX_SM3_BLOCK_SIZE;
	}
	ctx->num = data_len;
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
}

CGMBOX_EXPORT void cgmbox_sm3_final(cgmbox_sm3_ctx_t *ctx, unsigned char *digest)
{
	int i;
	unsigned int *pdigest = (unsigned int *)digest;
	unsigned int *count = (unsigned int *)(ctx->block + CGMBOX_SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= CGMBOX_SM3_BLOCK_SIZE) {
		memset(ctx->block + ctx->num + 1, 0, CGMBOX_SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, CGMBOX_SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress(ctx->digest, ctx->block);
		memset(ctx->block, 0, CGMBOX_SM3_BLOCK_SIZE - 8);
	}

	count[0] = cpu_to_be32((ctx->nblocks) >> 23);
	count[1] = cpu_to_be32((ctx->nblocks << 9) + (ctx->num << 3));

	sm3_compress(ctx->digest, ctx->block);
	for (i = 0; i < sizeof(ctx->digest)/sizeof(ctx->digest[0]); i++) {
		pdigest[i] = cpu_to_be32(ctx->digest[i]);
	}
}

CGMBOX_EXPORT void cgmbox_sm3(const unsigned char *msg, unsigned int msglen,
	unsigned char dgst[CGMBOX_SM3_DIGEST_LENGTH])
{
	cgmbox_sm3_ctx_t ctx;

	cgmbox_sm3_init(&ctx);
	cgmbox_sm3_update(&ctx, msg, msglen);
	cgmbox_sm3_final(&ctx, dgst);
}


#define IPAD	0x36
#define OPAD	0x5C

CGMBOX_EXPORT void cgmbox_sm3_hmac_init(cgmbox_sm3_hmac_ctx_t *ctx, const unsigned char *key, unsigned int key_len)
{
	int i;

	if (key_len <= CGMBOX_SM3_BLOCK_SIZE) {
		memcpy(ctx->key, key, key_len);
		memset(ctx->key + key_len, 0, CGMBOX_SM3_BLOCK_SIZE - key_len);
	} else {
		cgmbox_sm3_init(&ctx->sm3_ctx);
		cgmbox_sm3_update(&ctx->sm3_ctx, key, key_len);
		cgmbox_sm3_final(&ctx->sm3_ctx, ctx->key);
		memset(ctx->key + CGMBOX_SM3_DIGEST_LENGTH, 0,
			CGMBOX_SM3_BLOCK_SIZE - CGMBOX_SM3_DIGEST_LENGTH);
	}
	for (i = 0; i < CGMBOX_SM3_BLOCK_SIZE; i++) {
		ctx->key[i] ^= IPAD;
	}

	cgmbox_sm3_init(&ctx->sm3_ctx);
	cgmbox_sm3_update(&ctx->sm3_ctx, ctx->key, CGMBOX_SM3_BLOCK_SIZE);
}

CGMBOX_EXPORT void cgmbox_sm3_hmac_update(cgmbox_sm3_hmac_ctx_t *ctx,
	const unsigned char *data, unsigned int data_len)
{
	cgmbox_sm3_update(&ctx->sm3_ctx, data, data_len);
}

CGMBOX_EXPORT void cgmbox_sm3_hmac_final(cgmbox_sm3_hmac_ctx_t *ctx, unsigned char mac[CGMBOX_SM3_HMAC_SIZE])
{
	int i;
	for (i = 0; i < CGMBOX_SM3_BLOCK_SIZE; i++) {
		ctx->key[i] ^= (IPAD ^ OPAD);
	}
	cgmbox_sm3_final(&ctx->sm3_ctx, mac);
	cgmbox_sm3_init(&ctx->sm3_ctx);
	cgmbox_sm3_update(&ctx->sm3_ctx, ctx->key, CGMBOX_SM3_BLOCK_SIZE);
	cgmbox_sm3_update(&ctx->sm3_ctx, mac, CGMBOX_SM3_DIGEST_LENGTH);
	cgmbox_sm3_final(&ctx->sm3_ctx, mac);
}

CGMBOX_EXPORT void cgmbox_sm3_hmac(const unsigned char *data, unsigned int data_len,
	const unsigned char *key, unsigned int key_len,
	unsigned char mac[CGMBOX_SM3_HMAC_SIZE])
{
	cgmbox_sm3_hmac_ctx_t ctx;
	cgmbox_sm3_hmac_init(&ctx, key, key_len);
	cgmbox_sm3_hmac_update(&ctx, data, data_len);
	cgmbox_sm3_hmac_final(&ctx, mac);
	memset(&ctx, 0, sizeof(ctx));
}

/*******************************************************************************
* Function Name  : cgmbox_sm3_preprocess
* Description    : 执行 SM2 算法签名预处理 1 操作,计算过程遵循《公钥密码基础设施应用技术体系 SM2 算法密码使用规范》
* Input          : data           ：数据
*                ：data_len       ：数据长度
*                ：public_key     ：签名公钥, 格式4个字节模长实际的位数+64字节X坐标数组+64字节Y坐标数组
*                ：public_key_len ：签名公钥长度
*                ：signer_id      ：签名者ID
*                ：signer_id_len  ：签名者ID长度
* Output         : digest         : 杂凑值
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int cgmbox_sm3_preprocess(const unsigned char *data, unsigned int data_len, const unsigned char *public_key, unsigned int public_key_len,
	const unsigned char *signer_id, unsigned int signer_id_len, unsigned char digest[CGMBOX_SM3_DIGEST_LENGTH])
{
	unsigned short ID_bit_len;
	unsigned char *step1_input;
	unsigned int step1_input_byte_len;
	unsigned char step1_output[32];
	unsigned char *step2_input;
	unsigned int step2_input_byte_len;

	unsigned char a[32] = { 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC };

	unsigned char b[32] = { 0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
		0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
		0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
		0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0xE,  0x93 };

	unsigned char x_G[32] = { 0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
		0x5F, 0x99, 0x4,  0x46, 0x6A, 0x39, 0xC9, 0x94,
		0x8F, 0xE3, 0xB,  0xBF, 0xF2, 0x66, 0xB,  0xE1,
		0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7 };

	unsigned char y_G[32] = { 0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
		0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
		0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
		0x2,  0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0 };

	// 下面定义的结构体 x 用于判断当前环境是 big-endian 还是 little-endian
	union {
		int i;
		char c[sizeof(int)];
	} x;

	if ((!public_key) || (!public_key_len) || (!signer_id) || (!signer_id_len))
	{
		cgmbox_sm3(data, data_len, digest);
		return 0;
	}

	// 下面为满足 SM2 签名的要求，做预处理操作
	step1_input_byte_len = (2 + signer_id_len + 32 * 6);
	if (!(step1_input = (unsigned char *)calloc(1, step1_input_byte_len)))
	{
		return -1;
	}

	// 预处理1 
	ID_bit_len = (unsigned short)(signer_id_len * 8);

	/* 
	判断当前环境是 big-endian 还是 little-endian。
	国密规范中要求把 ENTL(用 2 个字节表示的 ID 的比特长度)
	以 big-endian 方式作为预处理 1 输入的前两个字节
	*/
	x.i = 1;
	if (x.c[0] == 1)  /* little-endian */
	{
		memcpy(step1_input, (unsigned char *)(&ID_bit_len) + 1, 1);
		memcpy((step1_input + 1), (unsigned char *)(&ID_bit_len), 1);
	}
	else  /* big-endian */
	{
		memcpy(step1_input, (unsigned char *)(&ID_bit_len), 1);
		memcpy((step1_input + 1), (unsigned char *)(&ID_bit_len) + 1, 1);
	}

	memcpy((step1_input + 2), signer_id, signer_id_len);
	memcpy((step1_input + 2) + signer_id_len, a, 32);
	memcpy((step1_input + 2) + signer_id_len + 32, b, 32);
	memcpy((step1_input + 2 + signer_id_len + 64), x_G, 32);
	memcpy((step1_input + 2 + signer_id_len + 96), y_G, 32);
	memcpy((step1_input + 2 + signer_id_len + 128), (public_key + 4 + 32), 32);
	memcpy((step1_input + 2 + signer_id_len + 160), (public_key + 4 + 64 + 32), 32);
	cgmbox_sm3(step1_input, step1_input_byte_len, step1_output);

	// 预处理2 
	step2_input_byte_len = (32 + data_len);
	if (!(step2_input = (unsigned char *)calloc(1, step2_input_byte_len)))
	{
		free(step1_input);
		return -1;
	}
	memcpy(step2_input, step1_output, 32);
	memcpy((step2_input + 32), data, data_len);
	cgmbox_sm3(step2_input, step2_input_byte_len, digest);

	free(step1_input);
	free(step2_input);

	return 0;
}

/*******************************************************************************
* Function Name  : cgmbox_sm3_x9_63_kdf
* Description    : SM2 密钥派生函数，从共享密钥比特串中派生出密钥数据
* Input          : share          ：共享密钥比特串
*                ：data_len       ：共享密钥比特串长度
*                ：keylen         ：派生出的密钥数据长度
* Output         : outkey         : 派生出的密钥数据
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int cgmbox_sm3_x9_63_kdf(const unsigned char *share, unsigned int sharelen, unsigned char *outkey, unsigned int keylen)
{
	int ret = 0;
	cgmbox_sm3_ctx_t ctx;
	unsigned int new_counter = 1;
	unsigned char new_counter_be_[4] = { 0, 0, 0, 1 };
	unsigned char dgst[32];
	unsigned int dgstlen = 32;
	int rlen = (int)keylen;
	unsigned char *pp;

	if ((NULL == outkey) || (0 == keylen))
	{
		//printf("invalid parameter, null\n");
		return -1;
	}

	pp = outkey;
	while (rlen > 0)
	{
		new_counter_be_[0] = (unsigned char)((new_counter >> 24) & 0xFF);
		new_counter_be_[1] = (unsigned char)((new_counter >> 16) & 0xFF);
		new_counter_be_[2] = (unsigned char)((new_counter >> 8) & 0xFF);
		new_counter_be_[3] = (unsigned char)(new_counter & 0xFF);

		cgmbox_sm3_init(&ctx);
		cgmbox_sm3_update(&ctx, (unsigned char *)share, sharelen);
		cgmbox_sm3_update(&ctx, new_counter_be_, 4);
		cgmbox_sm3_final(&ctx, dgst);

		if (keylen > dgstlen)
		{
			memcpy(pp, dgst, dgstlen);
			pp += dgstlen;
			keylen -= dgstlen;
		}
		else
		{
			memcpy(pp, dgst, keylen);
			memset(dgst, 0, dgstlen);
			break;
		}
		new_counter++;
	}

	return 0;
}

