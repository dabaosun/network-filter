/*
 * @Author: sunzhenbao && sunzhenbao@live.com
 * @Date: 2023-09-10 22:02:30
 * @LastEditors: sunzhenbao sunzhenbao@live.com
 * @LastEditTime: 2023-09-11 14:45:03
 * @FilePath: /network-filter/src/user_prog/err.h
 * @Description: 
 * 
 * Copyright (c) 2023 by sunzhenbao.live.com, All Rights Reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __LINUX_ERR_H
#define __LINUX_ERR_H

#include <linux/types.h>
#include <asm/errno.h>

#define MAX_ERRNO       4095

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

static inline void * ERR_PTR(long error_)
{
	return (void *) error_;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return (!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

static inline long PTR_ERR_OR_ZERO(const void *ptr)
{
	return IS_ERR(ptr) ? PTR_ERR(ptr) : 0;
}

#endif
