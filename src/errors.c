/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net> */

#include <librecast/errors.h>

char *lc_error_msg(int e)
{
	switch (e) {
		LC_ERROR_CODES(LC_ERROR_MSG)
	}
	return "Unknown error";
}
