/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#ifndef MACRO_H
#define MACRO_H 1

#include <netdb.h>

#define aitoin6(ai) &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr)

#endif /* MACRO_H */
