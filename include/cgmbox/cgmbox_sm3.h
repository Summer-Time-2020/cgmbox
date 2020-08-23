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
#ifndef CGMBOX_SM3_H
#define CGMBOX_SM3_H

#define CGMBOX_SM3_DIGEST_LENGTH	(32)
#define CGMBOX_SM3_BLOCK_SIZE     (64)
#define CGMBOX_SM3_CBLOCK		    (CGMBOX_SM3_BLOCK_SIZE)
#define CGMBOX_SM3_HMAC_SIZE		(CGMBOX_SM3_DIGEST_LENGTH)

#if(defined WIN32 || defined_WIN32 || defined WINCE)
#ifndef CGMBOX_EXPORT
#define CGMBOX_EXPORT __declspec(dllexport)
#endif
#else
#ifndef CGMBOX_EXPORT
#define CGMBOX_EXPORT __attribute__ ((visibility("default")))
#endif
#endif

typedef struct {
	unsigned int digest[8];
	int nblocks;
	unsigned char block[64];
	int num;
} cgmbox_sm3_ctx_t;

typedef struct {
	cgmbox_sm3_ctx_t sm3_ctx;
	unsigned char key[CGMBOX_SM3_BLOCK_SIZE];
} cgmbox_sm3_hmac_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
* Function Name  : cgmbox_sm3_init
* Description    : SM3流数据杂凑初始化
* Input          : ctx           ：待初始化SM3上下文缓存地址
* Output         : ctx           : 已初始化SM3上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_sm3_init(cgmbox_sm3_ctx_t *ctx);

/*******************************************************************************
* Function Name  : cgmbox_sm3_update
* Description    : SM3流数据杂凑
* Input          : ctx           ：SM3上下文
*                : data          : 数据
*                ：data_len      ：数据长度
* Output         : ctx           : SM3上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_sm3_update(cgmbox_sm3_ctx_t *ctx, const unsigned char* data, unsigned int data_len);

/*******************************************************************************
* Function Name  : cgmbox_sm3_final
* Description    : 结束SM3流数据杂凑
* Input          : ctx           ：SM3上下文
* Output         : digest        : 杂凑值
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_sm3_final(cgmbox_sm3_ctx_t *ctx, unsigned char digest[CGMBOX_SM3_DIGEST_LENGTH]);

/*******************************************************************************
* Function Name  : cgmbox_sm3
* Description    : SM3数据杂凑
* Input          : ctx           ：SM3上下文
*                : data          : 数据
*                ：data_len      ：数据长度
* Output         : digest        : 杂凑值
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_sm3(const unsigned char *data, unsigned int datalen, unsigned char digest[CGMBOX_SM3_DIGEST_LENGTH]);


/*******************************************************************************
* Function Name  : cgmbox_sm3_hmac_init
* Description    : SM3 HMAC 流数据认证码初始化
* Input          : ctx           ：待初始化SM3 HMAC上下文缓存地址
*                : key           : 密钥
*                ：keylen        : 密钥长度
* Output         : ctx           : 已初始化SM3 HMAC上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_sm3_hmac_init(cgmbox_sm3_hmac_ctx_t *ctx, const unsigned char *key, unsigned int key_len);

/*******************************************************************************
* Function Name  : cgmbox_sm3_hmac_update
* Description    : SM3 HMAC流数据认证码
* Input          : ctx           ：SM3 HMAC 上下文
*                : data          : 数据
*                ：data_len      ：数据长度
* Output         : ctx           : SM3 HMAC 上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_sm3_hmac_update(cgmbox_sm3_hmac_ctx_t *ctx, const unsigned char *data, unsigned int data_len);

/*******************************************************************************
* Function Name  : cgmbox_sm3_hmac_final
* Description    : 结束SM3 HMAC流数据认证码
* Input          : ctx           ：SM3 HMAC上下文
* Output         : mac           : 数据认证码
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_sm3_hmac_final(cgmbox_sm3_hmac_ctx_t *ctx, unsigned char mac[CGMBOX_SM3_BLOCK_SIZE]);

/*******************************************************************************
* Function Name  : cgmbox_sm3_hmac
* Description    : SM3 HMAC数据认证码
* Input          : ctx           ：SM3 HMAC上下文
*                : data          : 数据
*                ：data_len      ：数据长度
*                : key           : 密钥
*                ：keylen        : 密钥长度
* Output         : mac           : 数据认证码
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_sm3_hmac(const unsigned char *data, unsigned int data_len, const unsigned char *key, unsigned int key_len, unsigned char mac[CGMBOX_SM3_BLOCK_SIZE]);

/*******************************************************************************
* Function Name  : cgmbox_sm3_preprocess
* Description    : 执行 SM2 算法签名预处理 1 操作,计算过程遵循《公钥密码基础设施应用技术体系 SM2 算法密码使用规范》
* Input          : data           ：数据
*                ：data_len       ：数据长度
*                ：public_key     ：签名公钥, 格式4个字节模长实际的位数+64字节X坐标数组+64字节Y坐标数组，参考cgmbox_cm2_public_key结构体
*                ：public_key_len ：签名公钥长度
*                ：signer_id      ：签名者ID
*                ：signer_id_len  ：签名者ID长度
* Output         : digest         : 杂凑值
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int cgmbox_sm3_preprocess(const unsigned char *data, unsigned int data_len, const unsigned char *public_key, unsigned int public_key_len,
	const unsigned char *signer_id, unsigned int signer_id_len, unsigned char digest[CGMBOX_SM3_DIGEST_LENGTH]);

/*******************************************************************************
* Function Name  : cgmbox_sm3_x9_63_kdf
* Description    : SM2 密钥派生函数，从共享密钥比特串中派生出密钥数据
* Input          : share          ：共享密钥比特串
*                ：data_len       ：共享密钥比特串长度
*                ：keylen         ：派生出的密钥数据长度
* Output         : outkey         : 派生出的密钥数据
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int cgmbox_sm3_x9_63_kdf(const unsigned char *share, unsigned int sharelen, unsigned char *outkey, unsigned int keylen);


#ifdef __cplusplus
}
#endif

#endif