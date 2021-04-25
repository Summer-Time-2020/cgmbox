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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "cgmbox/cgmbox_sm3.h"

/* 线性同余参数 Rn+1 = ( A x Rn + C )modM A、C、M为常量，A<M,C<M */
#define LINEAR_CONGRUENTIAL_METHOD_A (0x87)
#define LINEAR_CONGRUENTIAL_METHOD_C (0x32)
#define LINEAR_CONGRUENTIAL_METHOD_M (0x91)

/*******************************************************************************
* Function Name  : cgmbox_prng_genrnd_by_system
* Description    : 通过系统API rand()函数 生成伪随机数
* Input          : data          ：待填充随机数缓存地址
*                : data_len      : 生成随机数长度
* Output         : data          : 已初始化SM3上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_prng_genrnd_by_system(unsigned char *data, unsigned int data_len)
{
	unsigned int i = 0;
	unsigned int j = 0;
	
	/* 随机数函数初始化，以系统时间为种子 */
	srand((unsigned int)time(NULL)); 
	
	for ( i = 0; i < data_len; i++)
	{
		j = rand();
		memcpy(data + i, &j, 1);
	}
}


/*******************************************************************************
* Function Name  : cgmbox_prng_genrnd_by_system
* Description    : 通过（线性同余法）Rn+1 = ( A x Rn + C )modM 生成伪随机数
* Input          : data          ：待填充随机数缓存地址
*                : data_len      : 生成随机数长度
* Output         : data          : 已初始化SM3上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_prng_genrnd_by_linear_congruential_method(unsigned char *data, unsigned int data_len)
{
	unsigned int i = 0;
	unsigned int a = LINEAR_CONGRUENTIAL_METHOD_A;
	unsigned int c = LINEAR_CONGRUENTIAL_METHOD_C;
	unsigned int m = LINEAR_CONGRUENTIAL_METHOD_M;
	unsigned int r0 = (unsigned int)time(NULL); // 以系统时间为种子
	unsigned int r1 = 0;
	
	for ( i = 0; i < data_len; i++)
	{
		r1 = (r0*a + c)%m;
		memcpy(data + i, &r1, 1);
		r0 = r1;
	}	
}

/*******************************************************************************
* Function Name  : cgmbox_prng_genrnd_by_sm3
* Description    : 通过（SM3）单向散列函数生成伪随机数
* Input          : data          ：待填充随机数缓存地址
*                : data_len      : 生成随机数长度
* Output         : data          : 已初始化SM3上下文
* Return         : 成功返回 0
*******************************************************************************/
CGMBOX_EXPORT void cgmbox_prng_genrnd_by_sm3(unsigned char *data, unsigned int data_len)
{
	unsigned int seed = (unsigned int)time(NULL); // 以系统时间为种子
	unsigned char digest[CGMBOX_SM3_DIGEST_LENGTH] = { 0 };
	unsigned int copy_len = 0;

	while (data_len)
	{
		cgmbox_sm3(&seed, sizeof(unsigned int), digest);
		seed++;
		copy_len = data_len > CGMBOX_SM3_DIGEST_LENGTH ? CGMBOX_SM3_DIGEST_LENGTH : data_len;
		memcpy(data, digest, copy_len);
		data_len -= copy_len;
		data += copy_len;
	}
}







