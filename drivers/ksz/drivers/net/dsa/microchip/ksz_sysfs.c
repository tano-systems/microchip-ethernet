// SPDX-License-Identifier: GPL-2.0
/*
 * Microchip KSZ Series Switch DSA Driver sysfs interface
 *
 * Copyright (C) 2021 Tano Systems LLC
 * Anton Kikin <a.kikin@tano-systems.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/if_bridge.h>

#include "ksz_priv.h"

struct ksz_sysfs {
	struct semaphore sem;
	struct kobject **kobj_ports;
	struct bin_attribute registers_attr;
};

static int parse_number(const char *buf)
{
	int num = 0;

	if ('0' == buf[0] && 'x' == buf[1]) {
		/* Hex (0x...) */
		sscanf(&buf[2], "%x", (unsigned int *)&num);
	}
	else if ('0' == buf[0] && 'b' == buf[1]) {
		/* Binary (0b...) */
		int i = 2;

		num = 0;
		while (buf[i]) {
			num <<= 1;
			num |= buf[i] - '0';
			i++;
		}
	}
	else if ('0' == buf[0] && 'd' == buf[1]) {
		/* Decimal (0d...) */
		sscanf(&buf[2], "%u", (unsigned int *)&num);
	}
	else {
		/* Default (decimal) */
		sscanf(buf, "%d", &num);
	}

	return num;
}

static ssize_t ksz_sysfs_registers_read(
	struct file *filp, struct kobject *kobj,
	struct bin_attribute *bin_attr, char *buf,
	loff_t off, size_t count)
{
	size_t i;
	u32 reg;
	struct device *dev;
	struct ksz_device *swdev;

	dev = container_of(kobj, struct device, kobj);
	swdev = dev_get_drvdata(dev);

	if (unlikely(off >= swdev->regs_size))
		return 0;

	if ((off + count) >= swdev->regs_size)
		count = swdev->regs_size - off;

	if (unlikely(!count))
		return count;

	reg = off;
	if (swdev->dev_ops->get)
		i = swdev->dev_ops->get(swdev, reg, buf, count);
	else
		i = regmap_bulk_read(swdev->regmap[0], reg, buf, count);
	i = count;
	return i;
}

static ssize_t ksz_sysfs_registers_write(
	struct file *filp, struct kobject *kobj,
	struct bin_attribute *bin_attr, char *buf,
	loff_t off, size_t count)
{
	size_t i;
	u32 reg;
	struct device *dev;
	struct ksz_device *swdev;

	dev = container_of(kobj, struct device, kobj);
	swdev = dev_get_drvdata(dev);

	if (unlikely(off >= swdev->regs_size))
		return -EFBIG;

	if ((off + count) >= swdev->regs_size)
		count = swdev->regs_size - off;

	if (unlikely(!count))
		return count;

	reg = off;
	if (swdev->dev_ops->set)
		i = swdev->dev_ops->set(swdev, reg, buf, count);
	else
		i = regmap_bulk_write(swdev->regmap[0], reg, buf, count);
	i = count;
	return i;
}

static ssize_t ksz_sysfs_sw_attr_read(struct ksz_device *swdev,
	int attr_id, ssize_t len, char *buf);

static int ksz_sysfs_sw_attr_write(struct ksz_device *swdev,
	int attr_id, int val_number, const char *val_buffer);


static ssize_t ksz_sysfs_sw_port_attr_read(struct ksz_device *swdev, int port,
	int attr_id, ssize_t len, char *buf);

static int ksz_sysfs_sw_port_attr_write(struct ksz_device *swdev, int port,
	int attr_id, int val_number, const char *val_buffer);


static ssize_t ksz_sysfs_sw_attr_show(
	struct kobject          *kobj,
	struct kobj_attribute   *attr,
	char                    *buf,
	int                      attr_id,
	bool                     is_port_attr)
{
	int len = -EINVAL;

	int port = -1;
	struct device *dev;
	struct ksz_device *swdev;

	if (is_port_attr) {
		dev = container_of(kobj->parent, struct device, kobj);
		swdev = dev_get_drvdata(dev);

		for (port = 0; port < swdev->mib_port_cnt; port++) {
			if (kobj == swdev->sysfs->kobj_ports[port])
				break;
		}

		/* Can't find port */
		if (port > swdev->mib_port_cnt)
			return len;
	}
	else {
		dev = (struct device *)kobj;
		swdev = dev_get_drvdata(dev);
	}

	if (down_interruptible(&swdev->sysfs->sem))
		return -ERESTARTSYS;

	if (is_port_attr)
		len = ksz_sysfs_sw_port_attr_read(swdev, port, attr_id, 0, buf);
	else
		len = ksz_sysfs_sw_attr_read(swdev, attr_id, 0, buf);

	up(&swdev->sysfs->sem);

	return len;
}

static ssize_t ksz_sysfs_sw_attr_store(
	struct kobject          *kobj,
	struct kobj_attribute   *attr,
	const char              *buf,
	size_t                   count,
	int                      attr_id,
	bool                     is_port_attr)
{
	int port = -1;
	struct device *dev;
	struct ksz_device *swdev;

	if (is_port_attr) {
		dev = container_of(kobj->parent, struct device, kobj);
		swdev = dev_get_drvdata(dev);

		for (port = 0; port < swdev->mib_port_cnt; port++) {
			if (kobj == swdev->sysfs->kobj_ports[port])
				break;
		}

		/* Can't find port */
		if (port > swdev->mib_port_cnt)
			return count;
	}
	else {
		dev = (struct device *)kobj;
		swdev = dev_get_drvdata(dev);
	}

	if (down_interruptible(&swdev->sysfs->sem))
		return -ERESTARTSYS;

	if (is_port_attr)
		ksz_sysfs_sw_port_attr_write(swdev, port, attr_id, parse_number(buf), buf);
	else
		ksz_sysfs_sw_attr_write(swdev, attr_id, parse_number(buf), buf);

	up(&swdev->sysfs->sem);

	return count;
}

#define KSZ_SYSFS_SW_ATTR(_name, _mode, _show, _store) \
	struct kobj_attribute ksz_attr_##_name = \
		__ATTR(_name, _mode, _show, _store)

/* Generate a read-only attribute */
#define KSZ_SYSFS_SW_RO_ENTRY(name, is_port_attr) \
	static ssize_t ksz_sysfs_show_##name( \
		struct kobject *kobj, struct kobj_attribute *attr, char *buf) { \
		return ksz_sysfs_sw_attr_show( \
			kobj, attr, buf, \
			offsetof(struct ksz_attributes, name) / sizeof(int), is_port_attr); \
	} \
	static KSZ_SYSFS_SW_ATTR(name, S_IRUGO, \
		ksz_sysfs_show_##name, NULL)

/* Generate a write-only attribute */
#define KSZ_SYSFS_SW_WO_ENTRY(name, is_port_attr) \
	static ssize_t ksz_sysfs_store_##name( \
		struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) { \
		return ksz_sysfs_sw_attr_store( \
			kobj, attr, buf, count, \
			offsetof(struct ksz_attributes, name) / sizeof(int), is_port_attr); \
	} \
	static KSZ_SYSFS_SW_ATTR(name, S_IWUSR, \
		NULL, ksz_sysfs_store_##name)

/* Generate a writeable attribute */
#define KSZ_SYSFS_SW_RW_ENTRY(name, is_port_attr) \
	static ssize_t ksz_sysfs_show_##name( \
		struct kobject *kobj, struct kobj_attribute *attr, char *buf) { \
		return ksz_sysfs_sw_attr_show( \
			kobj, attr, buf, \
			offsetof(struct ksz_attributes, name) / sizeof(int), is_port_attr); \
	} \
	static ssize_t ksz_sysfs_store_##name( \
		struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) { \
		return ksz_sysfs_sw_attr_store( \
			kobj, attr, buf, count, \
			offsetof(struct ksz_attributes, name) / sizeof(int), is_port_attr); \
	} \
	static KSZ_SYSFS_SW_ATTR(name, S_IRUGO | S_IWUSR, \
		ksz_sysfs_show_##name, ksz_sysfs_store_##name)

enum
{
	/* Global switch attributes */
	KSZ_SYSFS_SW_ATTR_CHIP_ID,
	KSZ_SYSFS_SW_ATTR_CHIP_NAME,
	KSZ_SYSFS_SW_ATTR_NUM_VLANS,
	KSZ_SYSFS_SW_ATTR_NUM_ALUS,
	KSZ_SYSFS_SW_ATTR_NUM_STATICS,
	KSZ_SYSFS_SW_ATTR_NUM_PORTS,
	KSZ_SYSFS_SW_ATTR_CPU_PORT,
	KSZ_SYSFS_SW_ATTR_MAC,
	KSZ_SYSFS_SW_ATTR_BROADCAST_STORM_RATE,
	KSZ_SYSFS_SW_ATTR_BROADCAST_STORM_MULTICAST,
	KSZ_SYSFS_SW_ATTR_MTU,

	/* Port attributes */
	KSZ_SYSFS_SW_PORT_ATTR_INDEX,
	KSZ_SYSFS_SW_PORT_ATTR_ENABLE,
	KSZ_SYSFS_SW_PORT_ATTR_MEMBER,
	KSZ_SYSFS_SW_PORT_ATTR_VID_MEMBER,
	KSZ_SYSFS_SW_PORT_ATTR_STP_STATE,
	KSZ_SYSFS_SW_PORT_ATTR_SGMII,
	KSZ_SYSFS_SW_PORT_ATTR_FIBER,
	KSZ_SYSFS_SW_PORT_ATTR_MIB,
	KSZ_SYSFS_SW_PORT_ATTR_BROADCAST_STORM_ENABLE,
	KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_UP,
	KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_SPEED,
	KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_DUPLEX,
	KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_AUTONEG,
	KSZ_SYSFS_SW_PORT_ATTR_RX,
	KSZ_SYSFS_SW_PORT_ATTR_TX,
	KSZ_SYSFS_SW_PORT_ATTR_LEARNING,
};

struct ksz_attributes
{
	/* Global switch attributes */
	int sw_chip_id;
	int sw_chip_name;
	int sw_num_vlans;
	int sw_num_alus;
	int sw_num_statics;
	int sw_num_ports;
	int sw_cpu_port;
	int sw_mac;
	int sw_broadcast_storm_rate;
	int sw_broadcast_storm_multicast;
	int sw_mtu;

	/* Port attributes */
	int index;
	int enable;
	int member;
	int vid_member;
	int stp_state;
	int sgmii;
	int fiber;
	int mib;
	int broadcast_storm_enable;
	int phy_link_up;
	int phy_link_speed;
	int phy_link_duplex;
	int phy_link_autoneg;
	int rx;
	int tx;
	int learning;
};

/* Global switch attributes */
KSZ_SYSFS_SW_RO_ENTRY(sw_chip_id, false);
KSZ_SYSFS_SW_RO_ENTRY(sw_chip_name, false);
KSZ_SYSFS_SW_RO_ENTRY(sw_num_vlans, false);
KSZ_SYSFS_SW_RO_ENTRY(sw_num_alus, false);
KSZ_SYSFS_SW_RO_ENTRY(sw_num_statics, false);
KSZ_SYSFS_SW_RO_ENTRY(sw_num_ports, false);
KSZ_SYSFS_SW_RO_ENTRY(sw_cpu_port, false);
KSZ_SYSFS_SW_RO_ENTRY(sw_mac, false);
KSZ_SYSFS_SW_RW_ENTRY(sw_broadcast_storm_rate, false);
KSZ_SYSFS_SW_RW_ENTRY(sw_broadcast_storm_multicast, false);
KSZ_SYSFS_SW_RW_ENTRY(sw_mtu, false);

static const struct attribute *ksz_attrs[] = {
	&ksz_attr_sw_chip_id.attr,
	&ksz_attr_sw_chip_name.attr,
	&ksz_attr_sw_num_vlans.attr,
	&ksz_attr_sw_num_alus.attr,
	&ksz_attr_sw_num_statics.attr,
	&ksz_attr_sw_num_ports.attr,
	&ksz_attr_sw_cpu_port.attr,
	&ksz_attr_sw_mac.attr,
	&ksz_attr_sw_broadcast_storm_rate.attr,
	&ksz_attr_sw_broadcast_storm_multicast.attr,
	&ksz_attr_sw_mtu.attr,
	NULL,
};

/* Port attributes */
KSZ_SYSFS_SW_RO_ENTRY(index, true);
KSZ_SYSFS_SW_RW_ENTRY(enable, true);
KSZ_SYSFS_SW_RO_ENTRY(member, true);
KSZ_SYSFS_SW_RO_ENTRY(vid_member, true);
KSZ_SYSFS_SW_RO_ENTRY(stp_state, true);
KSZ_SYSFS_SW_RO_ENTRY(sgmii, true);
KSZ_SYSFS_SW_RO_ENTRY(fiber, true);
KSZ_SYSFS_SW_RO_ENTRY(mib, true);
KSZ_SYSFS_SW_RW_ENTRY(broadcast_storm_enable, true);
KSZ_SYSFS_SW_RO_ENTRY(phy_link_up, true);
KSZ_SYSFS_SW_RO_ENTRY(phy_link_speed, true);
KSZ_SYSFS_SW_RO_ENTRY(phy_link_duplex, true);
KSZ_SYSFS_SW_RO_ENTRY(phy_link_autoneg, true);
KSZ_SYSFS_SW_RO_ENTRY(rx, true);
KSZ_SYSFS_SW_RO_ENTRY(tx, true);
KSZ_SYSFS_SW_RO_ENTRY(learning, true);

static const struct attribute *ksz_port_attrs[] = {
	&ksz_attr_index.attr,
	&ksz_attr_enable.attr,
	&ksz_attr_member.attr,
	&ksz_attr_vid_member.attr,
	&ksz_attr_stp_state.attr,
	&ksz_attr_sgmii.attr,
	&ksz_attr_fiber.attr,
	&ksz_attr_mib.attr,
	&ksz_attr_broadcast_storm_enable.attr,
	&ksz_attr_phy_link_up.attr,
	&ksz_attr_phy_link_speed.attr,
	&ksz_attr_phy_link_duplex.attr,
	&ksz_attr_phy_link_autoneg.attr,
	&ksz_attr_rx.attr,
	&ksz_attr_tx.attr,
	&ksz_attr_learning.attr,
	NULL,
};

static ssize_t ksz_sysfs_sw_attr_read(struct ksz_device *swdev,
	int attr_id, ssize_t len, char *buf)
{
	switch(attr_id) {
		case KSZ_SYSFS_SW_ATTR_CHIP_ID:
			len += sprintf(buf + len, "0x%x\n", swdev->chip_id);
			break;

		case KSZ_SYSFS_SW_ATTR_CHIP_NAME:
			len += sprintf(buf + len, "%s\n", swdev->name);
			break;

		case KSZ_SYSFS_SW_ATTR_NUM_VLANS:
			len += sprintf(buf + len, "%d\n", swdev->num_vlans);
			break;

		case KSZ_SYSFS_SW_ATTR_NUM_ALUS:
			len += sprintf(buf + len, "%d\n", swdev->num_alus);
			break;

		case KSZ_SYSFS_SW_ATTR_NUM_STATICS:
			len += sprintf(buf + len, "%d\n", swdev->num_statics);
			break;

		case KSZ_SYSFS_SW_ATTR_NUM_PORTS:
			len += sprintf(buf + len, "%d\n", swdev->mib_port_cnt);
			break;

		case KSZ_SYSFS_SW_ATTR_CPU_PORT:
			len += sprintf(buf + len, "%d\n", swdev->cpu_port);
			break;

		case KSZ_SYSFS_SW_ATTR_MAC: {
			u8 mac_addr[ETH_ALEN];

			if (!swdev->dev_ops->r_switch_mac)
				break;

			swdev->dev_ops->r_switch_mac(swdev, mac_addr);
			len += sprintf(buf + len, "%pM\n", mac_addr);
			break;
		}

		case KSZ_SYSFS_SW_ATTR_BROADCAST_STORM_RATE:
			if (swdev->dev_ops->get_broadcast_storm) {
				u8 rate_percent;
				swdev->dev_ops->get_broadcast_storm(swdev, &rate_percent);
				len += sprintf(buf + len, "%u\n", rate_percent);
			}

			break;

		case KSZ_SYSFS_SW_ATTR_BROADCAST_STORM_MULTICAST:
			if (swdev->dev_ops->get_broadcast_multicast_storm) {
				bool enabled;
				swdev->dev_ops->get_broadcast_multicast_storm(swdev, &enabled);
				len += sprintf(buf + len, "%d\n", enabled);
			}

			break;

		case KSZ_SYSFS_SW_ATTR_MTU:
			if (swdev->dev_ops->get_mtu) {
				u16 mtu;
				swdev->dev_ops->get_mtu(swdev, &mtu);
				len += sprintf(buf + len, "%u\n", mtu);
			}

			break;

		default:
			break;
	}

	return len;
}

static int ksz_sysfs_sw_attr_write(struct ksz_device *swdev,
	int attr_id, int val_number, const char *val_buffer)
{
	int ret = -ENOTSUPP;

	switch(attr_id) {
		case KSZ_SYSFS_SW_ATTR_BROADCAST_STORM_RATE:
			if (swdev->dev_ops->cfg_broadcast_storm) {
				swdev->dev_ops->cfg_broadcast_storm(swdev, val_number);
				return 0;
			}

			break;

		case KSZ_SYSFS_SW_ATTR_BROADCAST_STORM_MULTICAST:
			if (swdev->dev_ops->cfg_broadcast_multicast_storm) {
				swdev->dev_ops->cfg_broadcast_multicast_storm(swdev, val_number);
				return 0;
			}

			break;

		case KSZ_SYSFS_SW_ATTR_MTU:
			if (swdev->dev_ops->cfg_mtu) {
				swdev->dev_ops->cfg_mtu(swdev, val_number);
				return 0;
			}

			break;

		default:
			ret = -EINVAL;
			break;
	}

	return ret;
}

static ssize_t ksz_sysfs_sw_port_attr_read(struct ksz_device *swdev,
	int port, int attr_id, ssize_t len, char *buf)
{
	struct ksz_port *p;

	if (port < 0 || port >= swdev->mib_port_cnt)
		return len;

	p = &swdev->ports[port];

	switch(attr_id) {
		case KSZ_SYSFS_SW_PORT_ATTR_INDEX:
			len += sprintf(buf + len, "%d\n", port);
			break;

		case KSZ_SYSFS_SW_PORT_ATTR_ENABLE:
			if (swdev->dev_ops->get_port_enable) {
				bool enable;
				swdev->dev_ops->get_port_enable(swdev, port, &enable);
				len += sprintf(buf + len, "%d\n", enable);
			}
			break;

		case KSZ_SYSFS_SW_PORT_ATTR_MEMBER:
			len += sprintf(buf + len, "0x%x\n", p->member);
			break;

		case KSZ_SYSFS_SW_PORT_ATTR_VID_MEMBER:
			len += sprintf(buf + len, "0x%x\n", p->vid_member);
			break;

		case KSZ_SYSFS_SW_PORT_ATTR_STP_STATE: {
			char *statestr = "unknown";

			switch(p->stp_state) {
				case BR_STATE_DISABLED:   statestr = "disabled";   break;
				case BR_STATE_LISTENING:  statestr = "listening";  break;
				case BR_STATE_LEARNING:   statestr = "learning";   break;
				case BR_STATE_FORWARDING: statestr = "forwarding"; break;
				case BR_STATE_BLOCKING:   statestr = "blocking";   break;
				default:
					break;
			}

			len += sprintf(buf + len, "%s (%d)\n", statestr, p->stp_state);
			break;
		}

		case KSZ_SYSFS_SW_PORT_ATTR_SGMII:
			len += sprintf(buf + len, "%d\n", p->sgmii);
			break;

		case KSZ_SYSFS_SW_PORT_ATTR_FIBER:
			len += sprintf(buf + len, "%d\n", p->fiber);
			break;

		case KSZ_SYSFS_SW_PORT_ATTR_MIB: {
			int cnt;
			mutex_lock(&p->mib.cnt_mutex);

			for (cnt = 0; cnt < swdev->mib_cnt; cnt++) {
				len += sprintf(buf + len, "%s = %llu\n",
					swdev->mib_names[cnt].string,
					(unsigned long long)p->mib.counters[cnt]);
			}

			mutex_unlock(&p->mib.cnt_mutex);
			break;
		}

		case KSZ_SYSFS_SW_PORT_ATTR_BROADCAST_STORM_ENABLE:
			if (swdev->dev_ops->get_port_broadcast_storm) {
				bool enabled;
				swdev->dev_ops->get_port_broadcast_storm(swdev, port, &enabled);
				len += sprintf(buf + len, "%d\n", enabled);
			}

			break;

		case KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_UP:     /* fallthrough */
		case KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_SPEED:  /* fallthrough */
		case KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_DUPLEX: /* fallthrough */
		case KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_AUTONEG:
			if ((attr_id == KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_UP) &&
			    (port >= swdev->phy_port_cnt))
				break;

			if (swdev->dev_ops->get_port_link) {
				struct ksz_port_link link;
				swdev->dev_ops->get_port_link(swdev, port, &link);

				switch(attr_id) {
					case KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_UP:
						len += sprintf(buf + len, "%d\n", link.link);
						break;

					case KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_SPEED:
						len += sprintf(buf + len, "%d\n", link.speed);
						break;

					case KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_DUPLEX:
						len += sprintf(buf + len, "%d\n", link.duplex);
						break;

					case KSZ_SYSFS_SW_PORT_ATTR_PHY_LINK_AUTONEG:
						len += sprintf(buf + len, "%d\n", link.autoneg);
						break;

					default:
						break;
				}
			}

			break;

		case KSZ_SYSFS_SW_PORT_ATTR_RX: /* fallthrough */
		case KSZ_SYSFS_SW_PORT_ATTR_TX: /* fallthrough */
		case KSZ_SYSFS_SW_PORT_ATTR_LEARNING:
			if (swdev->dev_ops->get_port_stp_state) {
				bool rx;
				bool tx;
				bool learning;
				bool enabled;

				swdev->dev_ops->get_port_stp_state(swdev, port, &rx, &tx, &learning);

				if (attr_id == KSZ_SYSFS_SW_PORT_ATTR_RX)
					enabled = rx;
				else if (attr_id == KSZ_SYSFS_SW_PORT_ATTR_TX)
					enabled = tx;
				else
					enabled = learning;

				len += sprintf(buf + len, "%d\n", enabled);
			}

			break;

		default:
			break;
	}

	return len;
}

static int ksz_sysfs_sw_port_attr_write(struct ksz_device *swdev,
	int port, int attr_id, int val_number, const char *val_buffer)
{
	int ret = -ENOTSUPP;
	struct ksz_port *p;

	if (port < 0 || port >= swdev->mib_port_cnt)
		return -EINVAL;

	p = &swdev->ports[port];

	switch(attr_id) {
		case KSZ_SYSFS_SW_PORT_ATTR_ENABLE:
			if (swdev->dev_ops->cfg_port_enable) {
				swdev->dev_ops->cfg_port_enable(swdev, port, val_number);
				return 0;
			}

			break;

		case KSZ_SYSFS_SW_PORT_ATTR_BROADCAST_STORM_ENABLE:
			if (swdev->dev_ops->cfg_port_broadcast_storm) {
				swdev->dev_ops->cfg_port_broadcast_storm(swdev, port, val_number);
				return 0;
			}

			break;

		default:
			ret = -EINVAL;
			break;
	}

	return ret;
}

int ksz_sysfs_init(struct ksz_device *dev)
{
	int ret;
	int i;
	struct ksz_sysfs *sysfs = NULL;

	if (dev->sysfs)
		return 0;

	sysfs = devm_kzalloc(dev->dev, sizeof(struct ksz_sysfs), GFP_KERNEL);
	if (!sysfs)
		return -ENOMEM;

	/* Create root sysfs directories */
	sysfs->kobj_ports = devm_kcalloc(dev->dev,
		sizeof(struct kobject *), dev->mib_port_cnt, GFP_KERNEL);

	if (!sysfs->kobj_ports) {
		devm_kfree(dev->dev, sysfs);
		return -ENOMEM;
	}

	/* Create sysfs root entries */
	ret = sysfs_create_files(&dev->dev->kobj, ksz_attrs);
	if (ret)
		return ret;

	/* Create sysfs groups for switch ports */
	for (i = 0; i < dev->mib_port_cnt; i++) {
		char kobj_name[16];

		if (!(dev->port_mask & BIT(i)))
			continue;

		if (dev->host_mask & BIT(i))
			strcpy(kobj_name, "sw_port_cpu");
		else
			snprintf(kobj_name, sizeof(kobj_name), "sw_port_%d", i);

		sysfs->kobj_ports[i] = kobject_create_and_add(
			kobj_name, &dev->dev->kobj);

		if (!sysfs->kobj_ports[i])
			return -ENOMEM;

		ret = sysfs_create_files(sysfs->kobj_ports[i], ksz_port_attrs);
		if (ret)
			return ret;
	}

	/* Create registers attribute */
	sysfs_bin_attr_init(sysfs->registers_attr);

	sysfs->registers_attr.attr.name = "registers";
	sysfs->registers_attr.attr.mode = 00600;
	sysfs->registers_attr.size = dev->regs_size;
	sysfs->registers_attr.read = ksz_sysfs_registers_read;
	sysfs->registers_attr.write = ksz_sysfs_registers_write;

	ret = sysfs_create_bin_file(&dev->dev->kobj,
		&sysfs->registers_attr);

	sema_init(&sysfs->sem, 1);

	dev->sysfs = sysfs;

	dev_info(dev->dev, "Created sysfs entries\n");
	return ret;
}
EXPORT_SYMBOL(ksz_sysfs_init);

int ksz_sysfs_remove(struct ksz_device *dev)
{
	int i;

	if (!dev->sysfs)
		return 0;

	sysfs_remove_bin_file(&dev->dev->kobj, &dev->sysfs->registers_attr);

	/* Remove sysfs port entries */
	for (i = 0; i < dev->mib_port_cnt; i++)
	{
		if (!dev->sysfs->kobj_ports[i])
			continue;

		sysfs_remove_files(dev->sysfs->kobj_ports[i], ksz_port_attrs);

		kobject_put(dev->sysfs->kobj_ports[i]);
		dev->sysfs->kobj_ports[i] = NULL;
	}

	/* Remove root sysfs entries */
	sysfs_remove_files(&dev->dev->kobj, ksz_attrs);
	devm_kfree(dev->dev, dev->sysfs->kobj_ports);
	devm_kfree(dev->dev, dev->sysfs);
	dev->sysfs = NULL;
	return 0;
}
EXPORT_SYMBOL(ksz_sysfs_remove);

MODULE_AUTHOR("Anton Kikin <a.kikin@tano-systems.com>");
MODULE_DESCRIPTION("Microchip KSZ Series Switch DSA Driver sysfs interface");
MODULE_LICENSE("GPL");
