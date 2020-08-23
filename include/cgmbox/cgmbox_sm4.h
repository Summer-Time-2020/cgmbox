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
#ifndef CGMBOX_SM4_H
#define CGMBOX_SM4_H

#if(defined WIN32 || defined_WIN32 || defined WINCE)
#ifndef CGMBOX_EXPORT
#define CGMBOX_EXPORT __declspec(dllexport)
#endif
#else
#ifndef CGMBOX_EXPORT
#define CGMBOX_EXPORT __attribute__ ((visibility("default")))
#endif
#endif

#define CGMBOX_SM4_MAX_IV_LEN     (16)
#define CGMBOX_SM4_SK_SIZE        (32)
#define CGMBOX_SM4_PBIV_SIZE      (32)
#define CGMBOX_SM4_KEY_SIZE       (16)
#define CGMBOX_SM4_BLOCK_SIZE     (16)
#define CGMBOX_SM4_SMS4_ECB       (1)  // SMS4 算法 ECB 加密模式 不推荐使用
#define CGMBOX_SM4_SMS4_CBC       (2)  // SMS4 算法 CBC 加密模式
#define CGMBOX_SM4_SMS4_CFB       (4)  // SMS4 算法 CFB 加密模式 128bit调用一次加密器
#define CGMBOX_SM4_SMS4_OFB       (8)  // SMS4 算法 OFB 加密模式 128bit调用一次加密器

typedef int(*cgmbox_sm4_alg_fun)(unsigned char key[16], int dec_en, int flag, unsigned char iv[CGMBOX_SM4_MAX_IV_LEN], unsigned char pbiv[CGMBOX_SM4_MAX_IV_LEN], unsigned long sk[CGMBOX_SM4_SK_SIZE], unsigned char *input, unsigned char *output);

typedef struct {
	unsigned char iv[CGMBOX_SM4_MAX_IV_LEN];  // 初始向量
	unsigned long padding_type;             // 填充方式，0 表示不填充，1 表示按照PKCS#5 方式进行填充
	//unsigned long free_bit_len;           // 反馈值的位长度（按位计算）,只针对 OFB、CFB 模式
	unsigned long alg_id;                   // 算法模式
}cgmbox_sm4_block_cipher_param;

typedef struct {
	cgmbox_sm4_block_cipher_param param;
	cgmbox_sm4_alg_fun fun;
	unsigned char cgmbox_sm4_pbIV[CGMBOX_SM4_MAX_IV_LEN];
	unsigned long cgmbox_sm4_sk[CGMBOX_SM4_PBIV_SIZE];
	unsigned char key[CGMBOX_SM4_KEY_SIZE];
	unsigned char block[CGMBOX_SM4_BLOCK_SIZE];
	unsigned long block_len;
	unsigned long num;
} cgmbox_sm4_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
* Function Name  : cgmbox_sm4_pkcs5_padding
* Description    : PKCS#5填充
* Input          : in            ：待填充数据
*                ：in_len        ：待填充数据长度
* Output         : out           : 填充数据
*                ：out_len       : 填充数据长度
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_pkcs5_padding(const unsigned char *in, unsigned long in_len, unsigned char *out, unsigned long *out_len);

/*******************************************************************************
* Function Name  : cgmbox_sm4_pkcs5_deslodge
* Description    : PKCS#5去填充
* Input          : in            ：填充数据
*                ：in_len        ：填充数据长度
* Output         : out           : 去填充数据
*                ：out_len       : 去填充数据长度
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_pkcs5_deslodge(const unsigned char *in, unsigned long in_len, unsigned char *out, unsigned long *out_len);

/*******************************************************************************
* Function Name  : cgmbox_sm4_encrypt_init
* Description    : SM4流加密初始化
* Input          : ctx           ：待初始化SM4上下文缓存地址
*                ：key           ：SM4密钥
*                ：param         ：SM4参数
* Output         : ctx           : 已初始化SM4上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_encrypt_init(cgmbox_sm4_ctx_t *ctx, const unsigned char key[CGMBOX_SM4_KEY_SIZE], cgmbox_sm4_block_cipher_param param);

/*******************************************************************************
* Function Name  : cgmbox_sm4_encrypt_update
* Description    : SM4流加密
* Input          : ctx              ：SM4上下文
*                ：data             ：待加密数据
*                ：data_len         ：待加密数据长度
*                ：encrypt_data     ：密文数据缓存地址
*                ：encrypt_data_len ：密文数据缓存地址长度, 长度不足会接口会返回失败
* Output         : encrypt_data     : 密文数据
*                ：encrypt_data_len ：密文数据长度
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_encrypt_update(cgmbox_sm4_ctx_t *ctx, const unsigned char *data, unsigned long data_len, unsigned char *encrypt_data, unsigned long *encrypt_data_len);

/*******************************************************************************
* Function Name  : cgmbox_sm4_encrypt_final
* Description    : 结束SM4流加密,SM4参数选择填充时，会输出填充后的密文数据
* Input          : ctx              ：SM4上下文
*                ：encrypt_data     ：密文数据缓存地址
*                ：encrypt_data_len ：密文数据缓存地址长度, 长度不足会接口会返回失败
* Output         : encrypt_data     : 密文数据
*                ：encrypt_data_len ：密文数据长度
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_encrypt_final(cgmbox_sm4_ctx_t *ctx, unsigned char *encrypt_data, unsigned long *encrypt_data_len);

/*******************************************************************************
* Function Name  : cgmbox_sm4_encrypt
* Description    : SM4加密
* Input          : key              ：SM4密钥
*                ：data             ：待加密数据
*                ：data_len         ：待加密数据长度
*                ：encrypt_data     ：密文数据缓存地址
*                ：encrypt_data_len ：密文数据缓存地址长度, 长度不足会接口会返回失败
* Output         : encrypt_data     : 密文数据
*                ：encrypt_data_len ：密文数据长度
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_encrypt(const unsigned char key[CGMBOX_SM4_KEY_SIZE], cgmbox_sm4_block_cipher_param param, const unsigned char *data, unsigned long data_len, unsigned char *encrypt_data, unsigned long *encrypt_data_len);



/*******************************************************************************
* Function Name  : cgmbox_sm4_decrypt_init
* Description    : SM4流解密初始化
* Input          : ctx           ：待初始化SM4上下文缓存地址
*                ：key           ：SM4密钥
*                ：param         ：SM4参数
* Output         : ctx           : 已初始化SM4上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_decrypt_init(cgmbox_sm4_ctx_t *ctx, const unsigned char key[CGMBOX_SM4_KEY_SIZE], cgmbox_sm4_block_cipher_param param);

/*******************************************************************************
* Function Name  : cgmbox_sm4_decrypt_update
* Description    : SM4流解密
* Input          : ctx              ：SM4上下文
*                ：data             ：待解密数据
*                ：data_len         ：待解密数据长度
*                ：decrypt_data     ：明文数据缓存地址
*                ：decrypt_data_len ：明文数据缓存地址长度, 长度不足会接口会返回失败
* Output         : decrypt_data     : 明文数据
*                ：decrypt_data_len ：明文数据长度
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_decrypt_update(cgmbox_sm4_ctx_t *ctx, const unsigned char *data, unsigned long data_len, unsigned char *decrypt_data, unsigned long *decrypt_data_len);

/*******************************************************************************
* Function Name  : cgmbox_sm4_decrypt_final
* Description    : 结束SM4流解密,SM4参数选择填充时，会输出去填充后的明文数据
* Input          : ctx              ：SM4上下文
*                ：decrypt_data     ：明文数据缓存地址
*                ：decrypt_data_len ：明文数据缓存地址长度, 长度不足会接口会返回失败
* Output         : decrypt_data     : 明文数据
*                ：decrypt_data_len ：明文数据长度
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_decrypt_final(cgmbox_sm4_ctx_t *ctx, unsigned char *decrypt_data, unsigned long *decrypt_data_len);

/*******************************************************************************
* Function Name  : cgmbox_sm4_decrypt
* Description    : SM4解密
* Input          : key              ：SM4密钥
*                ：data             ：待解密数据
*                ：data_len         ：待解密数据长度
*                ：decrypt_data     ：明文数据缓存地址
*                ：decrypt_data_len ：明文数据缓存地址长度, 长度不足会接口会返回失败
* Output         : decrypt_data     : 明文数据
*                ：decrypt_data_len ：明文数据长度
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int  cgmbox_sm4_decrypt(const unsigned char key[CGMBOX_SM4_KEY_SIZE], cgmbox_sm4_block_cipher_param param, const unsigned char *data, unsigned long data_len, unsigned char *decrypt_data, unsigned long *decrypt_data_len);

#ifdef __cplusplus
}
#endif

#endif