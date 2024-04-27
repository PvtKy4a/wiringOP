/*
 * wiringPiSPI.c:
 *	Simplified SPI access routines
 *	Copyright (c) 2012-2015 Gordon Henderson
 ***********************************************************************
 * This file is part of wiringPi:
 *	https://projects.drogon.net/raspberry-pi/wiringpi/
 *
 *    wiringPi is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU Lesser General Public License as
 *    published by the Free Software Foundation, either version 3 of the
 *    License, or (at your option) any later version.
 *
 *    wiringPi is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General Public
 *    License along with wiringPi.
 *    If not, see <http://www.gnu.org/licenses/>.
 ***********************************************************************
 */

#ifndef	__WIRING_PI_CAN_H__
#define	__WIRING_PI_CAN_H__

#include <linux/can.h>

#ifdef __cplusplus
extern "C" {
#endif

int wiringPiCANWrite(int s, struct can_frame *frame);
int wiringPiCANRead(int s, struct can_frame *frame);
int wiringPiCANSetFilter(int s, unsigned int id, unsigned int mask);
int wiringPiCANSetBitrate(const char *name, unsigned int bitrate);
int wiringPiCANSetupInterface(const char *name, unsigned int bitrate);
int wiringPiCANClose(const char *name);

#ifdef __cplusplus
}
#endif

#endif
