﻿/* ====================================================================
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
#include <stdio.h>
#include "cgmbox/cgmbox_sm4.h"

/*
* 32-bit integer manipulation macros (big endian)
*/
#ifndef CGMBOX_SM4_GET_ULONG_BE
#define CGMBOX_SM4_GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef CGMBOX_SM4_PUT_ULONG_BE
#define CGMBOX_SM4_PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
*rotate shift left marco definition/home/tim/work/sm4/rand_sim/sm4/testbench/dpi_c
*/
#define CGMBOX_SM4_SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define CGMBOX_SM4_ROTL(x,n) (CGMBOX_SM4_SHL((x),n) | ((x) >> (32 - n)))

#define CGMBOX_SM4_SWAP(a,b) { unsigned long t = a; a = b; b = t; t = 0; }

#define CGMBOX_SM4_ENCRYPT_PARAM (0)
#define CGMBOX_SM4_DECRYPT_PARAM (1)

/*
* Expanded SM4 S-boxes
* Sbox table: 8bits input convert to 8 bits output
*/
static const unsigned char cgmbox_sm4_SboxTable[16][16] =
{
	{ 0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05 },
	{ 0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99 },
	{ 0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62 },
	{ 0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6 },
	{ 0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8 },
	{ 0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35 },
	{ 0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87 },
	{ 0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e },
	{ 0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1 },
	{ 0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3 },
	{ 0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f },
	{ 0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51 },
	{ 0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8 },
	{ 0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0 },
	{ 0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84 },
	{ 0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48 }
};

/* System parameter */
static const unsigned long cgmbox_sm4_FK[4] = { 0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc };

/* fixed parameter */
static const unsigned long cgmbox_sm4_CK[32] =
{
	0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
	0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
	0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
	0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
	0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
	0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
	0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
	0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

/*
* private function:
* look up in cgmbox_sm4_SboxTable and get the related value.
* args:    [in] inch: 0x00~0xFF (8 bits unsigned value).
*/
static unsigned char cgmbox_sm4_sm4Sbox(unsigned char inch)
{
	unsigned char *pTable = (unsigned char *)cgmbox_sm4_SboxTable;
	unsigned char retVal = (unsigned char)(pTable[inch]);
	return retVal;
}

/*
* private F(Lt) function:
* "T algorithm" == "L algorithm" + "t algorithm".
* args:    [in] a: a is a 32 bits unsigned value;
* return: c: c is calculated with line algorithm "L" and nonline algorithm "t"
*/
static unsigned long cgmbox_sm4_sm4Lt(unsigned long ka)
{
	unsigned long bb = 0;
	unsigned long c = 0;
	unsigned char a[4];
	unsigned char b[4];
	CGMBOX_SM4_PUT_ULONG_BE(ka, a, 0)
		b[0] = cgmbox_sm4_sm4Sbox(a[0]);
	b[1] = cgmbox_sm4_sm4Sbox(a[1]);
	b[2] = cgmbox_sm4_sm4Sbox(a[2]);
	b[3] = cgmbox_sm4_sm4Sbox(a[3]);
	CGMBOX_SM4_GET_ULONG_BE(bb, b, 0)
		c = bb ^ (CGMBOX_SM4_ROTL(bb, 2)) ^ (CGMBOX_SM4_ROTL(bb, 10)) ^ (CGMBOX_SM4_ROTL(bb, 18)) ^ (CGMBOX_SM4_ROTL(bb, 24));
	return c;
}

/*
* private F function:
* Calculating and getting encryption/decryption contents.
* args:    [in] x0: original contents;
* args:    [in] x1: original contents;
* args:    [in] x2: original contents;
* args:    [in] x3: original contents;
* args:    [in] rk: encryption/decryption key;
* return the contents of encryption/decryption contents.
*/
static unsigned long cgmbox_sm4_sm4F(unsigned long x0, unsigned long x1, unsigned long x2, unsigned long x3, unsigned long rk)
{
	return (x0^cgmbox_sm4_sm4Lt(x1^x2^x3^rk));
}


/* 
* private function:
* Calculating round encryption key.
* args:    [in] a: a is a 32 bits unsigned value;
* return: g_cgmbox_sm4_sk[i]: i{0,1,2,3,...31}.
*/
static unsigned long cgmbox_sm4_sm4CalciRK(unsigned long ka)
{
	unsigned long bb = 0;
	unsigned long rk = 0;
	unsigned char a[4];
	unsigned char b[4];
	CGMBOX_SM4_PUT_ULONG_BE(ka, a, 0)
		b[0] = cgmbox_sm4_sm4Sbox(a[0]);
	b[1] = cgmbox_sm4_sm4Sbox(a[1]);
	b[2] = cgmbox_sm4_sm4Sbox(a[2]);
	b[3] = cgmbox_sm4_sm4Sbox(a[3]);
	CGMBOX_SM4_GET_ULONG_BE(bb, b, 0)
		rk = bb ^ (CGMBOX_SM4_ROTL(bb, 13)) ^ (CGMBOX_SM4_ROTL(bb, 23));
	return rk;
}


static void cgmbox_sm4_setkey(unsigned long cgmbox_sm4_sk[32], unsigned char key[16])
{
	unsigned long MK[4];
	unsigned long k[36];
	unsigned long i = 0;

	CGMBOX_SM4_GET_ULONG_BE(MK[0], key, 0);
	CGMBOX_SM4_GET_ULONG_BE(MK[1], key, 4);
	CGMBOX_SM4_GET_ULONG_BE(MK[2], key, 8);
	CGMBOX_SM4_GET_ULONG_BE(MK[3], key, 12);
	k[0] = MK[0] ^ cgmbox_sm4_FK[0];
	k[1] = MK[1] ^ cgmbox_sm4_FK[1];
	k[2] = MK[2] ^ cgmbox_sm4_FK[2];
	k[3] = MK[3] ^ cgmbox_sm4_FK[3];
	for (; i<32; i++)
	{
		k[i + 4] = k[i] ^ (cgmbox_sm4_sm4CalciRK(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ cgmbox_sm4_CK[i]));
		cgmbox_sm4_sk[i] = k[i + 4];
	}
}

/*
* SM4 standard one round processing
*/
static void cgmbox_sm4_one_round(unsigned long cgmbox_sm4_sk[32],
	unsigned char input[16],
	unsigned char output[16])
{
	unsigned long i = 0;
	unsigned long ulbuf[36];

	memset(ulbuf, 0, sizeof(ulbuf));
	CGMBOX_SM4_GET_ULONG_BE(ulbuf[0], input, 0)
		CGMBOX_SM4_GET_ULONG_BE(ulbuf[1], input, 4)
		CGMBOX_SM4_GET_ULONG_BE(ulbuf[2], input, 8)
		CGMBOX_SM4_GET_ULONG_BE(ulbuf[3], input, 12)
		while (i<32)
		{
			ulbuf[i + 4] = cgmbox_sm4_sm4F(ulbuf[i], ulbuf[i + 1], ulbuf[i + 2], ulbuf[i + 3], cgmbox_sm4_sk[i]);
			i++;
		}
	CGMBOX_SM4_PUT_ULONG_BE(ulbuf[35], output, 0);
	CGMBOX_SM4_PUT_ULONG_BE(ulbuf[34], output, 4);
	CGMBOX_SM4_PUT_ULONG_BE(ulbuf[33], output, 8);
	CGMBOX_SM4_PUT_ULONG_BE(ulbuf[32], output, 12);
}

//static unsigned char g_cgmbox_sm4_pbIV[16];
//static unsigned long g_cgmbox_sm4_sk[32];

static void cgmbox_sm4_enc_128bit(unsigned long cgmbox_sm4_sk[32],
	unsigned char input[16],
	unsigned char output[16])
{
	cgmbox_sm4_one_round(cgmbox_sm4_sk, input, output);
}

static void cgmbox_sm4_dec_128bit(unsigned long cgmbox_sm4_sk[32],
	unsigned char input[16],
	unsigned char output[16])
{
	int i;
	unsigned long sk_temp[32];

	for (i = 0; i < 32; i++)
	{
		sk_temp[i] = cgmbox_sm4_sk[31 - i];
	}
	cgmbox_sm4_one_round(sk_temp, input, output);
}



/*
* SM4 ecb mode
*/
static int cgmbox_sm4_ecb(unsigned char key[16],
	int dec_en,
	int flag,
	unsigned char iv[16],
	unsigned char pbiv[16],
	unsigned long sk[32],
	unsigned char *input,
	unsigned char *output)
{
	// cgmbox_sm4_setkey( g_cgmbox_sm4_sk, key );
	if (flag)
	{
		cgmbox_sm4_setkey(sk, key);
	}

	if (dec_en == 0)
	{           
		// encryption
		cgmbox_sm4_enc_128bit(sk, input, output);
	}
	else 
	{                 
		// decryption
		cgmbox_sm4_dec_128bit(sk, input, output);
	}

	return 0;
}

/*
* SM4 cbc mode
*/
static int cgmbox_sm4_cbc(unsigned char key[16],
	int dec_en,
	int flag,
	unsigned char iv[16],
	unsigned char pbiv[16],
	unsigned long sk[32],
	unsigned char *input,
	unsigned char *output)
{
	int i = 0;
	unsigned char temp[16] = { 0 };

	if (flag)
	{
		memcpy(pbiv, iv, 16);
		cgmbox_sm4_setkey(sk, key);
	}

	if (dec_en == 0)   //encryption
	{

		for (i = 0; i < 16; i++)
		{
			temp[i] = (unsigned char)(input[i] ^ pbiv[i]);
		}
		cgmbox_sm4_enc_128bit(sk, temp, output);
		memcpy(pbiv, output, 16);
	}
	else //dencryption
	{
		memcpy(temp, input, 16);
		cgmbox_sm4_dec_128bit(sk, input, output);

		for (i = 0; i < 16; i++)
		{
			output[i] = (unsigned char)(output[i] ^ pbiv[i]);
		}
		memcpy(pbiv, temp, 16);
	}

	return 0;
}


/*
* SM4 cfb mode
*/
static int cgmbox_sm4_cfb(unsigned char key[16],
	int dec_en,
	int flag,
	unsigned char iv[16],
	unsigned char pbiv[16],
	unsigned long sk[32],
	unsigned char *input,
	unsigned char *output)
{
	int i = 0;
	unsigned char temp[16] = { 0 };
	if (flag)
	{
		memcpy(pbiv, iv, 16);
		cgmbox_sm4_setkey(sk, key);
	}

	if (dec_en == 0)
	{
		// encryption
		cgmbox_sm4_enc_128bit(sk, pbiv, temp);

		for (i = 0; i < 16; i++)
		{
			output[i] = (unsigned char)(temp[i] ^ input[i]);
		}
			
		memcpy(pbiv, output, 16);
	}
	else 
	{
		// dencryption
		cgmbox_sm4_enc_128bit(sk, pbiv, temp);
		memcpy(pbiv, input, 16);
		for (i = 0; i < 16; i++)
		{
			output[i] = (unsigned char)(temp[i] ^ input[i]);
		}
	}

	return 0;
}

/*
* SM4 ofb mode
*/
static int cgmbox_sm4_ofb(unsigned char key[16],
	int dec_en,
	int flag,
	unsigned char iv[16],
	unsigned char pbiv[16],
	unsigned long sk[32],
	unsigned char *input,
	unsigned char *output)
{
	int i = 0;
	unsigned char temp[16] = { 0 };

	if (flag)
	{
		memcpy(pbiv, iv, 16);
		cgmbox_sm4_setkey(sk, key);
	}

	if (dec_en == 0)  
	{
		//encryption
		cgmbox_sm4_enc_128bit(sk, pbiv, temp);
		memcpy(pbiv, temp, 16);

		for (i = 0; i < 16; i++)
		{
			output[i] = (unsigned char)(temp[i] ^ input[i]);
		}	
	}

	else
	{
		//dencryption
		cgmbox_sm4_enc_128bit(sk, pbiv, temp);
		memcpy(pbiv, temp, 16);

		for (i = 0; i < 16; i++)
		{
			output[i] = (unsigned char)(temp[i] ^ input[i]);
		}		
	}

	return 0;
}

/*
* SM4 ctr mode
*/
static int cgmbox_sm4_ctr(unsigned char key[16],
	int dec_en,
	int flag,
	unsigned char counter[16],
	unsigned char pbiv[16],
	unsigned long sk[32],
	unsigned char *input,
	unsigned char *output)
{
	int i = 0;
	unsigned char temp[16] = { 0 };

	if (flag)
	{
		memcpy(pbiv, counter, 16);
		cgmbox_sm4_setkey(sk, key);
	}
	if (dec_en == 0)  
	{
		// encryption
		cgmbox_sm4_enc_128bit(sk, pbiv, temp);

		for (i = 0; i < 16; i++)
		{
			output[i] = (unsigned char)(temp[i] ^ input[i]);
		}
			
		//count ++
		for (i = 0; i<16; i++)
		{
			pbiv[i] ++;
			if (pbiv[i] != 0)
			{
				break;
			}	
		}
	}
	else //dencryption
	{
		cgmbox_sm4_enc_128bit(sk, pbiv, temp);
		for (i = 0; i < 16; i++)
		{
			output[i] = (unsigned char)(temp[i] ^ input[i]);
		}
		
		//count ++
		for (i = 0; i<16; i++)
		{
			pbiv[i] ++;
			if (pbiv[i] != 0)
			{
				break;
			}	
		}
	}

	return 0;
}


/*
* SM4 xts mode
*/
static int cgmbox_sm4_xts(unsigned char key2[16],
	unsigned char key1[16],
	int dec_en,
	int flag,
	unsigned char tweak[16],
	unsigned char pbiv[16],
	unsigned long sk[32],
	unsigned char *input,
	unsigned char *output)
{

	int i = { 0 };
	//unsigned char g_cgmbox_sm4_pbIV[16];
	unsigned char C_temp[16] = { 0 };
	unsigned char P_temp[16] = { 0 };
	unsigned char Cin = { 0 };
	unsigned char Cout = { 0 };
	if (flag)
	{
		//get key2
		cgmbox_sm4_setkey(sk, key2);
		//enc tweak
		cgmbox_sm4_enc_128bit(sk, tweak, pbiv);
		//get key1
		cgmbox_sm4_setkey(sk, key1);
	}

	if (dec_en == 0)   //encryption
	{
		//input xor T
		for (i = 0; i < 16; i++)
		{
			C_temp[i] = (unsigned char)(pbiv[i] ^ input[i]);
		}
			
		//enc C get P
		cgmbox_sm4_enc_128bit(sk, C_temp, P_temp);
		//T xor P
		for (i = 0; i < 16; i++)
		{
			output[i] = (unsigned char)(pbiv[i] ^ P_temp[i]);
		}
			
		//LSFR
		Cin = 0;
		for (i = 0; i<16; i++) 
		{
			Cout = (pbiv[i] >> 7) & 1;
			pbiv[i] = ((pbiv[i] << 1) + Cin) & 0xff;
			Cin = Cout;
		}
		if (Cout)
		{
			pbiv[0] ^= 0x87;
		}		
	}
	else //dencryption
	{
		//input xor T
		for (i = 0; i < 16; i++)
		{
			C_temp[i] = (unsigned char)(pbiv[i] ^ input[i]);
		}
			
		//dec C get P
		cgmbox_sm4_dec_128bit(sk, C_temp, P_temp);
		//T xor P
		for (i = 0; i < 16; i++)
		{
			output[i] = (unsigned char)(pbiv[i] ^ P_temp[i]);
		}
			
		//LSFR
		Cin = 0;
		for (i = 0; i<16; i++)
		{
			Cout = (pbiv[i] >> 7) & 1;
			pbiv[i] = ((pbiv[i] << 1) + Cin) & 0xff;
			Cin = Cout;
		}
		if (Cout)
		{
			pbiv[0] ^= 0x87;
		}	
	}

	return 0;
}

CGMBOX_EXPORT int  cgmbox_sm4_pkcs5_padding(const unsigned char *in, unsigned long in_len, unsigned char *out, unsigned long *out_len)
{
	unsigned char padding_data[CGMBOX_SM4_BLOCK_SIZE] = { 0 };
	unsigned long padding_len = 0; 

	padding_len = CGMBOX_SM4_BLOCK_SIZE - in_len%CGMBOX_SM4_BLOCK_SIZE;

	if (*out_len < in_len + padding_len)
	{
		return -1;
	}

	memcpy(out, in, in_len);
	memset(padding_data, padding_len, padding_len);
	memcpy(out + in_len, padding_data, padding_len);
	return 0;
}

CGMBOX_EXPORT int  cgmbox_sm4_pkcs5_deslodge(const unsigned char *in, unsigned long in_len, unsigned char *out, unsigned long *out_len)
{
	unsigned char padding[CGMBOX_SM4_BLOCK_SIZE] = {0};
	unsigned long padding_len = in[in_len - 1];

	memset(padding, in[in_len - 1], CGMBOX_SM4_BLOCK_SIZE);

	if (in_len < CGMBOX_SM4_BLOCK_SIZE)
	{
		return -1;
	}
	
	if (memcmp(in + in_len - padding_len, padding, padding_len) != 0)
	{
		return -1;
	}

	*out_len = in_len - padding_len;
	memcpy(out, in, *out_len);
	
	return 0;
}

CGMBOX_EXPORT int cgmbox_sm4_encrypt_init(cgmbox_sm4_ctx_t *ctx, const unsigned char key[CGMBOX_SM4_KEY_SIZE], cgmbox_sm4_block_cipher_param param)
{
	if (ctx == 0)
	{
		return -1;
	}

	memset(ctx, 0, sizeof(cgmbox_sm4_ctx_t));
	memcpy(ctx->key, key, CGMBOX_SM4_KEY_SIZE);
	memcpy(&ctx->param, &param, sizeof(cgmbox_sm4_block_cipher_param));

	switch (param.alg_id)
	{
	case CGMBOX_SM4_SMS4_ECB:
		ctx->fun = cgmbox_sm4_ecb;
		break;
	case CGMBOX_SM4_SMS4_CBC:
		ctx->fun = cgmbox_sm4_cbc;
		break;
	case CGMBOX_SM4_SMS4_CFB:
		ctx->fun = cgmbox_sm4_cfb;
		break;
	case CGMBOX_SM4_SMS4_OFB:
		ctx->fun = cgmbox_sm4_ofb;
		break;
	default:
		return -1;
	}

	return 0;
}

CGMBOX_EXPORT int cgmbox_sm4_encrypt_update(cgmbox_sm4_ctx_t *ctx, const unsigned char *data, unsigned long data_len, unsigned char *encrypt_data, unsigned long *encrypt_data_len)
{
	unsigned char in[CGMBOX_SM4_BLOCK_SIZE] = { 0 }, out[CGMBOX_SM4_BLOCK_SIZE] = { 0 };
	unsigned int in_len = 0, out_lens = 0, used_len = 0;

	if (ctx == 0 || data_len == 0 || encrypt_data_len == 0)
	{
		return -1;
	}

	if (*encrypt_data_len < data_len - (data_len) % 16)
	{
		*encrypt_data_len = data_len - (data_len) % 16;
		return -1;
	}

	in_len = ctx->block_len;
	memcpy(in, ctx->block, in_len);

	while (data_len)
	{
		if (in_len + data_len < CGMBOX_SM4_BLOCK_SIZE)
		{
			ctx->block_len = data_len + in_len;
			memcpy(ctx->block, in, in_len);
			memcpy(ctx->block + in_len, data + used_len, data_len);
			break;
		}
		memcpy(in + in_len, data + used_len, CGMBOX_SM4_BLOCK_SIZE - in_len);
		if (ctx->num == 0)
		{
			ctx->fun(ctx->key, CGMBOX_SM4_ENCRYPT_PARAM, 1, ctx->param.iv, ctx->cgmbox_sm4_pbIV, ctx->cgmbox_sm4_sk, in, out);
		}
		else
		{
			ctx->fun(ctx->key, CGMBOX_SM4_ENCRYPT_PARAM, 0, ctx->param.iv, ctx->cgmbox_sm4_pbIV, ctx->cgmbox_sm4_sk, in, out);
		}

		ctx->num++;
		memcpy(encrypt_data + out_lens, out, CGMBOX_SM4_BLOCK_SIZE);
		out_lens += CGMBOX_SM4_BLOCK_SIZE;
		data_len -= (CGMBOX_SM4_BLOCK_SIZE - in_len);
		used_len += (CGMBOX_SM4_BLOCK_SIZE - in_len);
		memset(in, 0, CGMBOX_SM4_BLOCK_SIZE);
		ctx->block_len = 0;
		in_len = 0;
	}
	*encrypt_data_len = out_lens;
	return 0;
}

CGMBOX_EXPORT int  cgmbox_sm4_encrypt_final(cgmbox_sm4_ctx_t *ctx, unsigned char *encrypt_data, unsigned long *encrypt_data_len)
{
	unsigned char in[CGMBOX_SM4_BLOCK_SIZE] = { 0 }, out[CGMBOX_SM4_BLOCK_SIZE] = { 0 };
	unsigned long in_len = CGMBOX_SM4_BLOCK_SIZE, out_len = CGMBOX_SM4_BLOCK_SIZE;
	if (ctx == 0)
	{
		return -1;
	}

	if (ctx->param.padding_type == 0)
	{
		*encrypt_data_len = 0;
		return 0;
	}

	if (*encrypt_data_len < 16)
	{
		return -1;
	}

	cgmbox_sm4_pkcs5_padding(ctx->block, ctx->block_len, in, &in_len);
	if (ctx->num == 0)
	{
		ctx->fun(ctx->key, CGMBOX_SM4_ENCRYPT_PARAM, 1, ctx->param.iv, ctx->cgmbox_sm4_pbIV, ctx->cgmbox_sm4_sk, in, out);
	}
	else
	{
		ctx->fun(ctx->key, CGMBOX_SM4_ENCRYPT_PARAM, 0, ctx->param.iv, ctx->cgmbox_sm4_pbIV, ctx->cgmbox_sm4_sk, in, out);
	}

	memcpy(encrypt_data, out, out_len);
	*encrypt_data_len = out_len;

	return 0;
}

CGMBOX_EXPORT int  cgmbox_sm4_encrypt(const unsigned char key[CGMBOX_SM4_KEY_SIZE], cgmbox_sm4_block_cipher_param param, const unsigned char *data, unsigned long data_len, unsigned char *encrypt_data, unsigned long *encrypt_data_len)
{
	int ret = 0;
	unsigned long encrypt_data_update_len = *encrypt_data_len;
	unsigned long encrypt_data_final_len = 0;
	cgmbox_sm4_ctx_t ctx;

	ret = cgmbox_sm4_encrypt_init(&ctx, key, param);
	if (ret)
	{
		return ret;
	}
	
	ret = cgmbox_sm4_encrypt_update(&ctx, data, data_len, encrypt_data, &encrypt_data_update_len);
	if (ret)
	{
		return ret;
	}

	encrypt_data_final_len = *encrypt_data_len - encrypt_data_update_len;
	ret = cgmbox_sm4_encrypt_final(&ctx, encrypt_data + encrypt_data_update_len, &encrypt_data_final_len);
	if (ret)
	{
		return ret;
	}

	*encrypt_data_len = encrypt_data_final_len + encrypt_data_update_len;
	return 0;
}

CGMBOX_EXPORT int  cgmbox_sm4_decrypt_init(cgmbox_sm4_ctx_t *ctx, const unsigned char key[CGMBOX_SM4_KEY_SIZE], cgmbox_sm4_block_cipher_param param)
{
	if (ctx == 0)
	{
		return -1;
	}

	memset(ctx, 0, sizeof(cgmbox_sm4_ctx_t));
	memcpy(ctx->key, key, CGMBOX_SM4_KEY_SIZE);
	memcpy(&ctx->param, &param, sizeof(cgmbox_sm4_block_cipher_param));

	switch (param.alg_id)
	{
	case CGMBOX_SM4_SMS4_ECB:
		ctx->fun = cgmbox_sm4_ecb;
		break;
	case CGMBOX_SM4_SMS4_CBC:
		ctx->fun = cgmbox_sm4_cbc;
		break;
	case CGMBOX_SM4_SMS4_CFB:
		ctx->fun = cgmbox_sm4_cfb;
		break;
	case CGMBOX_SM4_SMS4_OFB:
		ctx->fun = cgmbox_sm4_ofb;
		break;
	default:
		return -1;
	}

	return 0;
}

CGMBOX_EXPORT int  cgmbox_sm4_decrypt_update(cgmbox_sm4_ctx_t *ctx, const unsigned char *data, unsigned long data_len, unsigned char *decrypt_data, unsigned long *decrypt_data_len)
{
	unsigned char in[CGMBOX_SM4_BLOCK_SIZE] = { 0 }, out[CGMBOX_SM4_BLOCK_SIZE] = { 0 };
	unsigned int in_len = 0, out_lens = 0, used_len = 0;

	if (ctx == 0 || data_len == 0 || decrypt_data_len == 0)
	{
		return -1;
	}

	if (*decrypt_data_len < data_len - (data_len) % 16)
	{
		*decrypt_data_len = data_len - (data_len) % 16;
		return -1;
	}

	in_len = ctx->block_len;
	memcpy(in, ctx->block, in_len);

	while (data_len)
	{
		if (ctx->param.padding_type == 1 && in_len + data_len == CGMBOX_SM4_BLOCK_SIZE)
		{	
			ctx->block_len = data_len + in_len;
			memcpy(ctx->block, in, in_len);
			memcpy(ctx->block + in_len, data + used_len, data_len);
			break;
		}
		if (in_len + data_len < CGMBOX_SM4_BLOCK_SIZE)
		{
			ctx->block_len = data_len + in_len;
			memcpy(ctx->block, in, in_len);
			memcpy(ctx->block + in_len, data + used_len, data_len);
			break;
		}
		memcpy(in + in_len, data + used_len, CGMBOX_SM4_BLOCK_SIZE - in_len);
		if (ctx->num == 0)
		{
			ctx->fun(ctx->key, CGMBOX_SM4_DECRYPT_PARAM, 1, ctx->param.iv, ctx->cgmbox_sm4_pbIV, ctx->cgmbox_sm4_sk, in, out);
		}
		else
		{
			ctx->fun(ctx->key, CGMBOX_SM4_DECRYPT_PARAM, 0, ctx->param.iv, ctx->cgmbox_sm4_pbIV, ctx->cgmbox_sm4_sk, in, out);
		}

		ctx->num++;
		memcpy(decrypt_data + out_lens, out, CGMBOX_SM4_BLOCK_SIZE);
		out_lens += CGMBOX_SM4_BLOCK_SIZE;
		data_len -= (CGMBOX_SM4_BLOCK_SIZE - in_len);
		used_len += (CGMBOX_SM4_BLOCK_SIZE - in_len);
		memset(in, 0, CGMBOX_SM4_BLOCK_SIZE);
		ctx->block_len = 0;
		in_len = 0;
	}

	*decrypt_data_len = out_lens;
	return 0;
}

CGMBOX_EXPORT int  cgmbox_sm4_decrypt_final(cgmbox_sm4_ctx_t *ctx, unsigned char *decrypt_data, unsigned long *decrypt_data_len)
{
	unsigned char out[CGMBOX_SM4_BLOCK_SIZE] = { 0 };
	
	if (ctx == 0)
	{
		return -1;
	}

	if (ctx->param.padding_type == 0)
	{
		*decrypt_data_len = 0;
		return 0;
	}

	if (ctx->block_len != CGMBOX_SM4_BLOCK_SIZE)
	{
		return -1;
	}

	if (ctx->num == 0)
	{
		ctx->fun(ctx->key, CGMBOX_SM4_DECRYPT_PARAM, 1, ctx->param.iv, ctx->cgmbox_sm4_pbIV, ctx->cgmbox_sm4_sk, ctx->block, out);
	}
	else
	{
		ctx->fun(ctx->key, CGMBOX_SM4_DECRYPT_PARAM, 0, ctx->param.iv, ctx->cgmbox_sm4_pbIV, ctx->cgmbox_sm4_sk, ctx->block, out);
	}
	
	return cgmbox_sm4_pkcs5_deslodge(out, CGMBOX_SM4_BLOCK_SIZE, decrypt_data, decrypt_data_len);
}

CGMBOX_EXPORT int  cgmbox_sm4_decrypt(const unsigned char key[CGMBOX_SM4_KEY_SIZE], cgmbox_sm4_block_cipher_param param, const unsigned char *data, unsigned long data_len, unsigned char *decrypt_data, unsigned long *decrypt_data_len)
{
	int ret = 0;
	unsigned long update_len = *decrypt_data_len, final_len = 0;
	cgmbox_sm4_ctx_t ctx;

	ret = cgmbox_sm4_decrypt_init(&ctx, key, param);
	if (ret)
	{
		return ret;
	}

	ret = cgmbox_sm4_decrypt_update(&ctx, data, data_len, decrypt_data, &update_len);
	if (ret)
	{
		return ret;
	}

	final_len = *decrypt_data_len - update_len;
	ret = cgmbox_sm4_decrypt_final(&ctx, decrypt_data + update_len, &final_len);
	if (ret)
	{
		return ret;
	}

	*decrypt_data_len = final_len + update_len;
	return 0;
}



