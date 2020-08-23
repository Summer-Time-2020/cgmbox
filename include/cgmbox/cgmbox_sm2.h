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

#ifndef CGMBOX_SM2_H
#define CGMBOX_SM2_H

#if(defined WIN32 || defined_WIN32 || defined WINCE)
#ifndef CGMBOX_EXPORT
#define CGMBOX_EXPORT __declspec(dllexport)
#endif
#else
#ifndef CGMBOX_EXPORT
#define CGMBOX_EXPORT __attribute__ ((visibility("default")))
#endif
#endif

#define CGMBOX_SM2_MAX_XCOORDINATE_BYTE_LEN (64)
#define CGMBOX_SM2_MAX_YCOORDINATE_BYTE_LEN (64)
#define CGMBOX_SM2_MAX_MODULUS_BYTE_LEN     (64)
#define CGMBOX_SM2_MAX_COORDINATE_LEN       (64)
#define CGMBOX_SM2_CIPHER_DIGEST_LENGTH	    (32)

typedef struct
{
	unsigned int bit_len;  // 模数的实际位长度
	unsigned char x[CGMBOX_SM2_MAX_XCOORDINATE_BYTE_LEN]; // 曲线上点的X坐标
	unsigned char y[CGMBOX_SM2_MAX_YCOORDINATE_BYTE_LEN]; // 曲线上点的Y坐标
}cgmbox_cm2_public_key;

typedef struct
{
	unsigned int bit_len;  // 模数的实际位长度
	unsigned char private_key[CGMBOX_SM2_MAX_MODULUS_BYTE_LEN]; // 私有密钥
}cgmbox_cm2_private_key;

typedef struct {
	unsigned char  r[CGMBOX_SM2_MAX_COORDINATE_LEN];  // 签名结果的 r 部分
	unsigned char  s[CGMBOX_SM2_MAX_COORDINATE_LEN];  // 签名结果的 s 部分
}cgmbox_sm2_sign_data;

typedef struct {
	unsigned char  x[CGMBOX_SM2_MAX_COORDINATE_LEN]; // 与 y 组成椭圆曲线C1上的点（x，y）
	unsigned char  y[CGMBOX_SM2_MAX_COORDINATE_LEN]; // 与 x 组成椭圆曲线C1上的点（x，y）
	unsigned char  digest[CGMBOX_SM2_CIPHER_DIGEST_LENGTH]; // 明文的杂凑值C3
	unsigned int   cipher_len; // 密文数据长度，长度等于明文数据长度
	unsigned char  *cipher; // 密文数据C2, 该指针指向的缓存区空间由调用者申请 
}cgmbox_sm2_cipher_bolb;

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
* Function Name  : cgmbox_sm2_keygen
* Description    : 生成SM2公私钥对
* Output         : public_key       : sm2公钥
*                : private_key      : sm2私钥
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int cgmbox_sm2_keygen(cgmbox_cm2_public_key *public_key, cgmbox_cm2_private_key *private_key);

/*******************************************************************************
* Function Name  : cgmbox_sm2_sign
* Description    : sm2签名
* Input          : private_key     : 签名私钥
*                : data            : 待签名数据, 经过cgmbox_sm3_preprocess函数签名预处理后的数据
*                : data_len        : 待签名数据长度，值应该为CGMBOX_SM3_DIGEST_LENGTH 32字节
* Output         : sign_data       : 签名值
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int cgmbox_sm2_sign(cgmbox_cm2_private_key private_key, const unsigned char *data, unsigned int data_len, cgmbox_sm2_sign_data *sign_data);

/*******************************************************************************
* Function Name  : cgmbox_sm2_verify
* Description    : sm2验签
* Input          : public_key      : 签名私钥
*                : data            : 待签名数据, 经过cgmbox_sm3_preprocess函数签名预处理后的数据
*                : data_len        : 待签名数据长度，值应该为CGMBOX_SM3_DIGEST_LENGTH 32字节
*                : sign_data       : 签名值
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int cgmbox_sm2_verify(cgmbox_cm2_public_key public_key, const unsigned char *data, unsigned int data_len, cgmbox_sm2_sign_data sign_data);

/*******************************************************************************
* Function Name  : cgmbox_sm2_encrypt
* Description    : sm2加密
* Input          : public_key      : 签名私钥
*                : data            : 待加密的明文数据
*                : data_len        : 待加密的明文数据长度
*                : cipher          : 密文数据缓存地址, cipher的参数cipher指针指向的缓存地址长度应大于等于data_len
* Output         : cipher          : 密文数据
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int cgmbox_sm2_encrypt(cgmbox_cm2_public_key public_key, const unsigned char *data, unsigned int data_len, cgmbox_sm2_cipher_bolb *cipher);

/*******************************************************************************
* Function Name  : cgmbox_sm2_decrypt
* Description    : sm2解密
* Input          : private_key     : 签名公钥
*                : cipher          : 密文数据
*                : plain_text      : 密文数据缓存地址，缓存地址长度应大于等于cipher的参数cipher_len的值
* Output         : plain_text      : 明文数据
*                : plain_text_len  : 明文数据长度。
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT int cgmbox_sm2_decrypt(cgmbox_cm2_private_key private_key, const cgmbox_sm2_cipher_bolb *cipher, unsigned char *plain_text, unsigned int *plain_text_len);


#ifdef __cplusplus
}
#endif

#endif