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
#ifndef CGMBOX_PRNG_H
#define CGMBOX_PRNG_H

#if(defined WIN32 || defined_WIN32 || defined WINCE)
#ifndef CGMBOX_EXPORT
#define CGMBOX_EXPORT __declspec(dllexport)
#endif
#else
#ifndef CGMBOX_EXPORT
#define CGMBOX_EXPORT __attribute__ ((visibility("default")))
#endif
#endif

/* Rn+1 = ( A x Rn + C )modM A、C、M为常量，A<M,C<M */
typedef struct {
	unsigned int A;
	unsigned int C;
	unsigned int M;
	unsigned int Rn;
} cgmbox_linear_congruential_method_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
* Function Name  : cgmbox_prng_genrnd_by_system
* Description    : 通过系统API rand()函数 生成伪随机数
* Input          : data          ：待填充随机数缓存地址
*                : data_len      : 生成随机数长度
* Output         : data          : 已初始化SM3上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_prng_genrnd_by_system(unsigned char *data, unsigned int data_len);

/*******************************************************************************
* Function Name  : cgmbox_prng_genrnd_by_linear_congruential_method
* Description    : 通过（线性同余法）Rn+1 = ( A x Rn + C )modM 生成伪随机数
* Input          : data          ：待填充随机数缓存地址
*                : data_len      : 生成随机数长度
* Output         : data          : 已初始化SM3上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_prng_genrnd_by_linear_congruential_method(unsigned char *data, unsigned int data_len);

/*******************************************************************************
* Function Name  : cgmbox_prng_genrnd_by_sm3
* Description    : 通过（SM3）单向散列函数生成伪随机数
* Input          : data          ：待填充随机数缓存地址
*                : data_len      : 生成随机数长度
* Output         : data          : 已初始化SM3上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_prng_genrnd_by_sm3(unsigned char *data, unsigned int data_len);


#ifdef __cplusplus
}
#endif

#endif