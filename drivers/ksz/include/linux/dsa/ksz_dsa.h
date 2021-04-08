/* SPDX-License-Identifier: GPL-2.0
 *
 * Microchip KSZ series switch common definitions
 *
 * Copyright (C) 2017-2020 Microchip Technology Inc.
 */

struct ksz_device;

struct ksz_tag_ops {
	int (*get_len)(struct ksz_device *dev);
	int (*get_tag)(struct ksz_device *dev, u8 *tag, int *port);
	void (*set_tag)(struct ksz_device *dev, void *ptr, u8 *addr, int p);
};
