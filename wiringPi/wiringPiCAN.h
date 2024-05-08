/*
 * wiringPiCAN.c:
 *	Simplified CAN access routines
 *	Copyright (c) 2024 Vladislav Pavlov
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

#ifdef __cplusplus
extern "C" {
#endif

int wiringPiCANWrite(int s, unsigned int id, const unsigned char *data, int length);
int wiringPiCANRead(int s, unsigned int *id, unsigned char *data, int *length);
int wiringPiCANSetFilter(int s, unsigned int id, unsigned int mask);
int wiringPiCANSetupInterface(const char *name, unsigned int bitrate, unsigned int loopback);
int wiringPiCANSetup(unsigned int bitrate, unsigned int loopback);

#ifdef __cplusplus
}
#endif

#endif
