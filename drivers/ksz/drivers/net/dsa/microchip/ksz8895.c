// SPDX-License-Identifier: GPL-2.0
/*
 * Microchip KSZ8895 switch driver
 *
 * Copyright (C) 2017-2020 Microchip Technology Inc.
 *	Tristram Ha <Tristram.Ha@microchip.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/iopoll.h>
#include <linux/platform_data/microchip-ksz.h>
#include <linux/phy.h>
#include <linux/gpio.h>
#include <linux/if_bridge.h>
#include <net/dsa.h>
#include <net/switchdev.h>

#include "ksz_priv.h"
#include "ksz8895_reg.h"
#include "ksz_common.h"

static const struct ksz_mib_info ksz8895_mib_names[TOTAL_SWITCH_COUNTER_NUM] = {
	{ 0x00, "rx" },
	{ 0x01, "rx_hi" },
	{ 0x02, "rx_undersize" },
	{ 0x03, "rx_fragments" },
	{ 0x04, "rx_oversize" },
	{ 0x05, "rx_jabbers" },
	{ 0x06, "rx_symbol_err" },
	{ 0x07, "rx_crc_err" },
	{ 0x08, "rx_align_err" },
	{ 0x09, "rx_mac_ctrl" },
	{ 0x0a, "rx_pause" },
	{ 0x0b, "rx_bcast" },
	{ 0x0c, "rx_mcast" },
	{ 0x0d, "rx_ucast" },
	{ 0x0e, "rx_64_or_less" },
	{ 0x0f, "rx_65_127" },
	{ 0x10, "rx_128_255" },
	{ 0x11, "rx_256_511" },
	{ 0x12, "rx_512_1023" },
	{ 0x13, "rx_1024_1522" },
	{ 0x14, "tx" },
	{ 0x15, "tx_hi" },
	{ 0x16, "tx_late_col" },
	{ 0x17, "tx_pause" },
	{ 0x18, "tx_bcast" },
	{ 0x19, "tx_mcast" },
	{ 0x1a, "tx_ucast" },
	{ 0x1b, "tx_deferred" },
	{ 0x1c, "tx_total_col" },
	{ 0x1d, "tx_exc_col" },
	{ 0x1e, "tx_single_col" },
	{ 0x1f, "tx_mult_col" },
	{ 0x20, "rx_discards" },
	{ 0x21, "tx_discards" },
};

static int ksz8895_reset_switch(struct ksz_device *dev)
{
	mutex_lock(&dev->reg_lock);

	/* reset switch */
	ksz_write8(dev, REG_POWER_MANAGEMENT_1,
		   SW_SOFTWARE_POWER_DOWN << SW_POWER_MANAGEMENT_MODE_S);
	ksz_write8(dev, REG_POWER_MANAGEMENT_1, 0);

	mutex_unlock(&dev->reg_lock);

	udelay(dev->reset_delay_after);

	return 0;
}

static void __ksz8895_set_prio_queue(struct ksz_device *dev, int port, int queue)
{
	u8 hi;
	u8 lo;

	/* Number of queues can only be 1, 2, or 4. */
	switch (queue) {
	case 4:
		queue = PORT_QUEUE_SPLIT_4;
		break;
	case 2:
		queue = PORT_QUEUE_SPLIT_2;
		break;
	default:
		queue = PORT_QUEUE_SPLIT_1;
	}
	ksz_pread8(dev, port, REG_PORT_CTRL_0, &lo);
	ksz_pread8(dev, port, P_DROP_TAG_CTRL, &hi);
	lo &= ~PORT_QUEUE_SPLIT_L;
	if (queue & PORT_QUEUE_SPLIT_2)
		lo |= PORT_QUEUE_SPLIT_L;
	hi &= ~PORT_QUEUE_SPLIT_H;
	if (queue & PORT_QUEUE_SPLIT_4)
		hi |= PORT_QUEUE_SPLIT_H;
	ksz_pwrite8(dev, port, REG_PORT_CTRL_0, lo);
	ksz_pwrite8(dev, port, P_DROP_TAG_CTRL, hi);

	/* Default is port based for egress rate limit. */
	if (queue != PORT_QUEUE_SPLIT_1)
		ksz_cfg8(dev, REG_SW_CTRL_19, SW_OUT_RATE_LIMIT_QUEUE_BASED,
			true);
}

static void ksz8895_r_mib_cnt(struct ksz_device *dev, int port, u16 addr,
			      u64 *cnt)
{
	u32 data;
	u16 ctrl_addr;
	u8 check;
	int loop;

	ctrl_addr = addr + SWITCH_COUNTER_NUM * port;
	ctrl_addr |= IND_ACC_TABLE(TABLE_MIB | TABLE_READ);

	mutex_lock(&dev->reg_lock);
	ksz_write16(dev, REG_IND_CTRL_0, ctrl_addr);

	/* It is almost guaranteed to always read the valid bit because of
	 * slow SPI speed.
	 */
	for (loop = 2; loop > 0; loop--) {
		ksz_read8(dev, REG_IND_MIB_CHECK, &check);

		if (check & MIB_COUNTER_VALID) {
			ksz_read32(dev, REG_IND_DATA_LO, &data);
			if (check & MIB_COUNTER_OVERFLOW)
				*cnt += MIB_COUNTER_VALUE + 1;
			*cnt += data & MIB_COUNTER_VALUE;
			break;
		}
	}
	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_r_mib_pkt(struct ksz_device *dev, int port, u16 addr,
			      u64 *dropped, u64 *cnt)
{
	u32 cur;
	u32 data;
	u16 ctrl_addr;
	u32 *last = (u32 *)dropped;

	addr -= SWITCH_COUNTER_NUM;
	ctrl_addr = addr ? KS_MIB_PACKET_DROPPED_TX_0 :
			   KS_MIB_PACKET_DROPPED_RX_0;
	ctrl_addr += port;
	ctrl_addr |= IND_ACC_TABLE(TABLE_MIB | TABLE_READ);

	mutex_lock(&dev->reg_lock);
	ksz_write16(dev, REG_IND_CTRL_0, ctrl_addr);
	ksz_read32(dev, REG_IND_DATA_LO, &data);
	mutex_unlock(&dev->reg_lock);

	data &= MIB_PACKET_DROPPED;
	cur = last[addr];
	if (data != cur) {
		last[addr] = data;
		if (data < cur)
			data += MIB_PACKET_DROPPED + 1;
		data -= cur;
		*cnt += data;
	}
}

static void ksz8895_port_init_cnt(struct ksz_device *dev, int port)
{
	struct ksz_port_mib *mib = &dev->ports[port].mib;
	u64 *dropped;

	mib->cnt_ptr = 0;

	/* Some ports may not have MIB counters before SWITCH_COUNTER_NUM. */
	while (mib->cnt_ptr < dev->reg_mib_cnt) {
		dev->dev_ops->r_mib_cnt(dev, port, mib->cnt_ptr,
					&mib->counters[mib->cnt_ptr]);
		++mib->cnt_ptr;
	}

	/* last one in storage */
	dropped = &mib->counters[dev->mib_cnt];

	/* Some ports may not have MIB counters after SWITCH_COUNTER_NUM. */
	while (mib->cnt_ptr < dev->mib_cnt) {
		dev->dev_ops->r_mib_pkt(dev, port, mib->cnt_ptr,
					dropped, &mib->counters[mib->cnt_ptr]);
		++mib->cnt_ptr;
	}
	mib->cnt_ptr = 0;
	memset(mib->counters, 0, dev->mib_cnt * sizeof(u64));
}

static void __ksz8895_r_table(struct ksz_device *dev, int table, u16 addr,
			    u64 *data)
{
	u16 ctrl_addr;

	ctrl_addr = IND_ACC_TABLE(table | TABLE_READ) | addr;

	ksz_write16(dev, REG_IND_CTRL_0, ctrl_addr);
	ksz_get(dev, REG_IND_DATA_HI, data, sizeof(u64));
	*data = be64_to_cpu(*data);
}

static void __ksz8895_w_table(struct ksz_device *dev, int table, u16 addr,
			    u64 data)
{
	u16 ctrl_addr;

	ctrl_addr = IND_ACC_TABLE(table) | addr;
	data = cpu_to_be64(data);

	ksz_set(dev, REG_IND_DATA_HI, &data, sizeof(u64));
	ksz_write16(dev, REG_IND_CTRL_0, ctrl_addr);
}

#define read8_op(addr)	\
({ \
	u8 data8; \
	ksz_read8(dev, addr, &data8); \
	data8; \
})

static u8 __ksz8895_get_fid(u16 vid)
{
	u8 fid;

	/* Need to find a way to map VID to FID. */
	if (vid <= 1) {
		fid = 0;
	} else {
		fid = vid & VLAN_TABLE_FID;
		if (fid == 0)
			fid = VLAN_TABLE_FID;
	}
	return fid;
}

static int __ksz8895_valid_dyn_entry(struct ksz_device *dev, u8 *data)
{
	readx_poll_timeout(read8_op, REG_IND_DATA_CHECK, *data,
			   !(*data & DYNAMIC_MAC_TABLE_NOT_READY), 0, 100);

	/* Entry is not ready for accessing. */
	if (*data & DYNAMIC_MAC_TABLE_NOT_READY) {
		return -EAGAIN;
	/* Entry is ready for accessing. */
	} else {
		ksz_read8(dev, REG_IND_DATA_8, data);

		/* There is no valid entry in the table. */
		if (*data & DYNAMIC_MAC_TABLE_MAC_EMPTY)
			return -ENXIO;
	}
	return 0;
}

static int ksz8895_r_dyn_mac_table(struct ksz_device *dev, u16 addr,
				   u8 *mac_addr, u8 *fid, u8 *src_port,
				   u8 *timestamp, u16 *entries)
{
	u32 data_hi;
	u32 data_lo;
	u16 ctrl_addr;
	int rc;
	u8 data;

	ctrl_addr = IND_ACC_TABLE(TABLE_DYNAMIC_MAC | TABLE_READ) | addr;

	mutex_lock(&dev->reg_lock);

	ksz_write16(dev, REG_IND_CTRL_0, ctrl_addr);

	rc = __ksz8895_valid_dyn_entry(dev, &data);
	if (rc == -EAGAIN) {
		if (addr == 0)
			*entries = 0;
	} else if (rc == -ENXIO) {
		*entries = 0;
	/* At least one valid entry in the table. */
	} else {
		u64 buf;
		int cnt;

		ksz_get(dev, REG_IND_DATA_HI, &buf, sizeof(buf));
		buf = be64_to_cpu(buf);
		data_hi = (u32)(buf >> 32);
		data_lo = (u32)buf;

		/* Check out how many valid entry in the table. */
		cnt = data & DYNAMIC_MAC_TABLE_ENTRIES_H;
		cnt <<= DYNAMIC_MAC_ENTRIES_H_S;
		cnt |= (data_hi & DYNAMIC_MAC_TABLE_ENTRIES) >>
			DYNAMIC_MAC_ENTRIES_S;
		*entries = cnt + 1;

		*fid = (data_hi & DYNAMIC_MAC_TABLE_FID) >>
			DYNAMIC_MAC_FID_S;
		*src_port = (data_hi & DYNAMIC_MAC_TABLE_SRC_PORT) >>
			DYNAMIC_MAC_SRC_PORT_S;
		*timestamp = (data_hi & DYNAMIC_MAC_TABLE_TIMESTAMP) >>
			DYNAMIC_MAC_TIMESTAMP_S;

		mac_addr[5] = (u8)data_lo;
		mac_addr[4] = (u8)(data_lo >> 8);
		mac_addr[3] = (u8)(data_lo >> 16);
		mac_addr[2] = (u8)(data_lo >> 24);

		mac_addr[1] = (u8)data_hi;
		mac_addr[0] = (u8)(data_hi >> 8);
		rc = 0;
	}
	mutex_unlock(&dev->reg_lock);

	return rc;
}

static int ksz8895_r_sta_mac_table(struct ksz_device *dev, u16 addr,
				   struct alu_struct *alu)
{
	u64 data;
	u32 data_hi;
	u32 data_lo;

	mutex_lock(&dev->reg_lock);
	__ksz8895_r_table(dev, TABLE_STATIC_MAC, addr, &data);
	mutex_unlock(&dev->reg_lock);

	data_hi = data >> 32;
	data_lo = (u32)data;
	if (data_hi & (STATIC_MAC_TABLE_VALID | STATIC_MAC_TABLE_OVERRIDE)) {
		alu->mac[5] = (u8)data_lo;
		alu->mac[4] = (u8)(data_lo >> 8);
		alu->mac[3] = (u8)(data_lo >> 16);
		alu->mac[2] = (u8)(data_lo >> 24);
		alu->mac[1] = (u8)data_hi;
		alu->mac[0] = (u8)(data_hi >> 8);
		alu->port_forward = (data_hi & STATIC_MAC_TABLE_FWD_PORTS) >>
			STATIC_MAC_FWD_PORTS_S;
		alu->is_override =
			(data_hi & STATIC_MAC_TABLE_OVERRIDE) ? 1 : 0;
		data_hi >>= 1;
		alu->is_use_fid = (data_hi & STATIC_MAC_TABLE_USE_FID) ? 1 : 0;
		alu->fid = (data_hi & STATIC_MAC_TABLE_FID) >>
			STATIC_MAC_FID_S;
		return 0;
	}
	return -ENXIO;
}

static void ksz8895_w_sta_mac_table(struct ksz_device *dev, u16 addr,
				    struct alu_struct *alu)
{
	u64 data;
	u32 data_hi;
	u32 data_lo;
	u8 fid = __ksz8895_get_fid(alu->fid);

	data_lo = ((u32)alu->mac[2] << 24) |
		((u32)alu->mac[3] << 16) |
		((u32)alu->mac[4] << 8) | alu->mac[5];
	data_hi = ((u32)alu->mac[0] << 8) | alu->mac[1];
	data_hi |= (u32)alu->port_forward << STATIC_MAC_FWD_PORTS_S;

	if (alu->is_override)
		data_hi |= STATIC_MAC_TABLE_OVERRIDE;
	if (alu->is_use_fid) {
		data_hi |= STATIC_MAC_TABLE_USE_FID;
		data_hi |= (u32)fid << STATIC_MAC_FID_S;
	}
	if (alu->is_static)
		data_hi |= STATIC_MAC_TABLE_VALID;
	else
		data_hi &= ~STATIC_MAC_TABLE_OVERRIDE;

	data = (u64)data_hi << 32 | data_lo;

	mutex_lock(&dev->reg_lock);
	__ksz8895_w_table(dev, TABLE_STATIC_MAC, addr, data);
	mutex_unlock(&dev->reg_lock);
}

static int ksz8895_ins_sta_mac_table(struct ksz_device *dev,
				struct alu_struct *alu, u16 *addr)
{
	// TODO:
	return 0;
}

static int ksz8895_del_sta_mac_table(struct ksz_device *dev,
				struct alu_struct *alu)
{
	// TODO:
	return 0;
}

static void ksz8895_from_vlan(u16 vlan, u8 *fid, u8 *member, u8 *valid)
{
	*fid = vlan & VLAN_TABLE_FID;
	*member = (vlan & VLAN_TABLE_MEMBERSHIP) >> VLAN_TABLE_MEMBERSHIP_S;
	*valid = !!(vlan & VLAN_TABLE_VALID);
}

static void ksz8895_to_vlan(u8 fid, u8 member, u8 valid, u16 *vlan)
{
	*vlan = fid;
	*vlan |= (u16)member << VLAN_TABLE_MEMBERSHIP_S;
	if (valid)
		*vlan |= VLAN_TABLE_VALID;
}

static void __ksz8895_r_vlan_entries(struct ksz_device *dev, u16 addr)
{
	u64 data;
	int i;

	__ksz8895_r_table(dev, TABLE_VLAN, addr, &data);

	addr *= 4;
	for (i = 0; i < 4; i++) {
		dev->vlan_cache[addr + i].table[0] = data & VLAN_TABLE_M;
		data >>= VLAN_TABLE_S;
	}
}

static void __ksz8895_r_vlan_table(struct ksz_device *dev, u16 vid, u16 *vlan)
{
	u64 buf;
	u16 addr;
	int index;

	addr = vid / 4;
	index = vid & 3;
	__ksz8895_r_table(dev, TABLE_VLAN, addr, &buf);
	buf >>= VLAN_TABLE_S * index;
	*vlan = buf & VLAN_TABLE_M;
}

static void __ksz8895_w_vlan_table(struct ksz_device *dev, u16 vid, u16 vlan)
{
	u64 buf;
	u16 addr;
	int index;

	addr = vid / 4;
	index = vid & 3;
	__ksz8895_r_table(dev, TABLE_VLAN, addr, &buf);
	index *= VLAN_TABLE_S;
	buf &= ~(VLAN_TABLE_M << index);
	buf |= (u64)vlan << index;
	dev->vlan_cache[vid].table[0] = vlan;
	__ksz8895_w_table(dev, TABLE_VLAN, addr, buf);
}

#define KSZ8895_SW_ID		0x8895
#define PHY_ID_KSZ8895_SW	((KSZ8895_ID_HI << 16) | KSZ8895_SW_ID)

static bool ksz8895_v_phy(struct ksz_device *dev, u16 phy, u16 reg, u16 *val)
{
	struct ksz_port *p = &dev->ports[phy];

	if (p->phy)
		return false;
	switch (reg) {
	case MII_BMCR:
		*val = 0x1140;
		break;
	case MII_BMSR:
		*val = 0x796d;
		break;
	case MII_PHYSID1:
		*val = KSZ8895_ID_HI;
		break;
	case MII_PHYSID2:
		*val = KSZ8895_SW_ID;
		break;
	case MII_ADVERTISE:
		*val = 0x05e1;
		break;
	case MII_LPA:
		*val = 0xc5e1;
		break;
	}
	return true;
}

static void ksz8895_r_phy(struct ksz_device *dev, u16 phy, u16 reg, u16 *val)
{
	u8 ctrl;
	u8 restart;
	u8 link;
	u8 speed;
	u8 p = phy;
	u16 data = 0;
	int processed = true;

	mutex_lock(&dev->reg_lock);

	if (phy >= dev->mib_port_cnt)
		return;
	if (ksz8895_v_phy(dev, phy, reg, val))
		return;
	switch (reg) {
	case PHY_REG_CTRL:
		ksz_pread8(dev, p, P_LOCAL_CTRL, &ctrl);
		ksz_pread8(dev, p, P_NEG_RESTART_CTRL, &restart);
		ksz_pread8(dev, p, P_SPEED_STATUS, &speed);
		if (restart & PORT_PHY_LOOPBACK)
			data |= PHY_LOOPBACK;
		if (ctrl & PORT_FORCE_100_MBIT)
			data |= PHY_SPEED_100MBIT;
		if (!(ctrl & PORT_AUTO_NEG_DISABLE))
			data |= PHY_AUTO_NEG_ENABLE;
		if (restart & PORT_POWER_DOWN)
			data |= PHY_POWER_DOWN;
		if (restart & PORT_AUTO_NEG_RESTART)
			data |= PHY_AUTO_NEG_RESTART;
		if (ctrl & PORT_FORCE_FULL_DUPLEX)
			data |= PHY_FULL_DUPLEX;
		if (speed & PORT_HP_MDIX)
			data |= PHY_HP_MDIX;
		if (restart & PORT_FORCE_MDIX)
			data |= PHY_FORCE_MDIX;
		if (restart & PORT_AUTO_MDIX_DISABLE)
			data |= PHY_AUTO_MDIX_DISABLE;
		if (restart & PORT_TX_DISABLE)
			data |= PHY_TRANSMIT_DISABLE;
		if (restart & PORT_LED_OFF)
			data |= PHY_LED_DISABLE;
		break;
	case PHY_REG_STATUS:
		ksz_pread8(dev, p, P_LINK_STATUS, &link);
		data = PHY_100BTX_FD_CAPABLE |
		       PHY_100BTX_CAPABLE |
		       PHY_10BT_FD_CAPABLE |
		       PHY_10BT_CAPABLE |
		       PHY_AUTO_NEG_CAPABLE;
		if (link & PORT_AUTO_NEG_COMPLETE)
			data |= PHY_AUTO_NEG_ACKNOWLEDGE;
		if (link & PORT_STAT_LINK_GOOD)
			data |= PHY_LINK_STATUS;
		break;
	case PHY_REG_ID_1:
		data = KSZ8895_ID_HI;
		break;
	case PHY_REG_ID_2:
		data = KSZ8895_ID_LO;
		data = KSZ8895_SW_ID;
		break;
	case PHY_REG_AUTO_NEGOTIATION:
		ksz_pread8(dev, p, P_LOCAL_CTRL, &ctrl);
		data = PHY_AUTO_NEG_802_3;
		if (ctrl & PORT_AUTO_NEG_SYM_PAUSE)
			data |= PHY_AUTO_NEG_SYM_PAUSE;
		if (ctrl & PORT_AUTO_NEG_100BTX_FD)
			data |= PHY_AUTO_NEG_100BTX_FD;
		if (ctrl & PORT_AUTO_NEG_100BTX)
			data |= PHY_AUTO_NEG_100BTX;
		if (ctrl & PORT_AUTO_NEG_10BT_FD)
			data |= PHY_AUTO_NEG_10BT_FD;
		if (ctrl & PORT_AUTO_NEG_10BT)
			data |= PHY_AUTO_NEG_10BT;
		break;
	case PHY_REG_REMOTE_CAPABILITY:
		ksz_pread8(dev, p, P_REMOTE_STATUS, &link);
		data = PHY_AUTO_NEG_802_3;
		if (link & PORT_REMOTE_SYM_PAUSE)
			data |= PHY_AUTO_NEG_SYM_PAUSE;
		if (link & PORT_REMOTE_100BTX_FD)
			data |= PHY_AUTO_NEG_100BTX_FD;
		if (link & PORT_REMOTE_100BTX)
			data |= PHY_AUTO_NEG_100BTX;
		if (link & PORT_REMOTE_10BT_FD)
			data |= PHY_AUTO_NEG_10BT_FD;
		if (link & PORT_REMOTE_10BT)
			data |= PHY_AUTO_NEG_10BT;
		if (data & ~PHY_AUTO_NEG_802_3)
			data |= PHY_REMOTE_ACKNOWLEDGE_NOT;
		break;
	default:
		processed = false;
		break;
	}
	if (processed)
		*val = data;

	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_w_phy(struct ksz_device *dev, u16 phy, u16 reg, u16 val)
{
	u8 ctrl;
	u8 restart;
	u8 speed;
	u8 data;
	u8 p = phy;

	if (phy >= dev->mib_port_cnt)
		return;
	do {
		struct ksz_port *port = &dev->ports[phy];

		if (!port->phy)
			return;
	} while (0);

	mutex_lock(&dev->reg_lock);

	switch (reg) {
	case PHY_REG_CTRL:

		/* Do not support PHY reset function. */
		if (val & PHY_RESET)
			break;
		ksz_pread8(dev, p, P_SPEED_STATUS, &speed);
		data = speed;
		if (val & PHY_HP_MDIX)
			data |= PORT_HP_MDIX;
		else
			data &= ~PORT_HP_MDIX;
		if (data != speed)
			ksz_pwrite8(dev, p, P_SPEED_STATUS, data);
		ksz_pread8(dev, p, P_FORCE_CTRL, &ctrl);
		data = ctrl;
		if (!(val & PHY_AUTO_NEG_ENABLE))
			data |= PORT_AUTO_NEG_DISABLE;
		else
			data &= ~PORT_AUTO_NEG_DISABLE;

		/* Fiber port does not support auto-negotiation. */
		if (dev->ports[p].fiber)
			data |= PORT_AUTO_NEG_DISABLE;
		if (val & PHY_SPEED_100MBIT)
			data |= PORT_FORCE_100_MBIT;
		else
			data &= ~PORT_FORCE_100_MBIT;
		if (val & PHY_FULL_DUPLEX)
			data |= PORT_FORCE_FULL_DUPLEX;
		else
			data &= ~PORT_FORCE_FULL_DUPLEX;
		if (data != ctrl)
			ksz_pwrite8(dev, p, P_FORCE_CTRL, data);
		ksz_pread8(dev, p, P_NEG_RESTART_CTRL, &restart);
		data = restart;
		if (val & PHY_LED_DISABLE)
			data |= PORT_LED_OFF;
		else
			data &= ~PORT_LED_OFF;
		if (val & PHY_TRANSMIT_DISABLE)
			data |= PORT_TX_DISABLE;
		else
			data &= ~PORT_TX_DISABLE;
		if (val & PHY_AUTO_NEG_RESTART)
			data |= PORT_AUTO_NEG_RESTART;
		else
			data &= ~(PORT_AUTO_NEG_RESTART);
		if (val & PHY_POWER_DOWN)
			data |= PORT_POWER_DOWN;
		else
			data &= ~PORT_POWER_DOWN;
		if (val & PHY_AUTO_MDIX_DISABLE)
			data |= PORT_AUTO_MDIX_DISABLE;
		else
			data &= ~PORT_AUTO_MDIX_DISABLE;
		if (val & PHY_FORCE_MDIX)
			data |= PORT_FORCE_MDIX;
		else
			data &= ~PORT_FORCE_MDIX;
		if (val & PHY_LOOPBACK)
			data |= PORT_PHY_LOOPBACK;
		else
			data &= ~PORT_PHY_LOOPBACK;
		if (data != restart)
			ksz_pwrite8(dev, p, P_NEG_RESTART_CTRL, data);
		break;
	case PHY_REG_AUTO_NEGOTIATION:
		ksz_pread8(dev, p, P_LOCAL_CTRL, &ctrl);
		data = ctrl;
		data &= ~(PORT_AUTO_NEG_SYM_PAUSE |
			  PORT_AUTO_NEG_100BTX_FD |
			  PORT_AUTO_NEG_100BTX |
			  PORT_AUTO_NEG_10BT_FD |
			  PORT_AUTO_NEG_10BT);
		if (val & PHY_AUTO_NEG_SYM_PAUSE)
			data |= PORT_AUTO_NEG_SYM_PAUSE;
		if (val & PHY_AUTO_NEG_100BTX_FD)
			data |= PORT_AUTO_NEG_100BTX_FD;
		if (val & PHY_AUTO_NEG_100BTX)
			data |= PORT_AUTO_NEG_100BTX;
		if (val & PHY_AUTO_NEG_10BT_FD)
			data |= PORT_AUTO_NEG_10BT_FD;
		if (val & PHY_AUTO_NEG_10BT)
			data |= PORT_AUTO_NEG_10BT;
		if (data != ctrl)
			ksz_pwrite8(dev, p, P_LOCAL_CTRL, data);
		break;
	default:
		break;
	}

	mutex_unlock(&dev->reg_lock);
}

static enum dsa_tag_protocol ksz8895_get_tag_protocol(struct dsa_switch *ds,
						      int port)
{
	return DSA_TAG_PROTO_KSZ;
}

static void ksz8895_get_strings(struct dsa_switch *ds, int port,
				u32 stringset, uint8_t *buf)
{
	int i;

	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < TOTAL_SWITCH_COUNTER_NUM; i++) {
		memcpy(buf + i * ETH_GSTRING_LEN, ksz8895_mib_names[i].string,
		       ETH_GSTRING_LEN);
	}
}

static inline void __ksz8895_cfg_port_member(struct ksz_device *dev, int port,
				    u8 member)
{
	u8 data;

	dev_dbg(dev->dev, "%s: port = %d, member = 0x%x\n",
		__FUNCTION__, port, member);

	ksz_pread8(dev, port, P_MIRROR_CTRL, &data);
	data &= ~PORT_VLAN_MEMBERSHIP;
	data |= (member & dev->port_mask);
	ksz_pwrite8(dev, port, P_MIRROR_CTRL, data);
	dev->ports[port].member = member;
}

static void ksz8895_cfg_port_member(struct ksz_device *dev, int port,
				    u8 member)
{
	mutex_lock(&dev->reg_lock);
	__ksz8895_cfg_port_member(dev, port, member);
	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_port_stp_state_set(struct dsa_switch *ds, int port,
				       u8 state)
{
	struct ksz_device *dev = ds->priv;
	struct ksz_port *p = &dev->ports[port];
	u8 data;
	u8 flush_br_fdb = 0;

	mutex_lock(&dev->reg_lock);
	ksz_pread8(dev, port, P_STP_CTRL, &data);
	mutex_unlock(&dev->reg_lock);

	data &= ~(PORT_TX_ENABLE | PORT_RX_ENABLE | PORT_LEARN_DISABLE);

	switch (state) {
	case BR_STATE_DISABLED:
		data |= PORT_LEARN_DISABLE;
		break;
	case BR_STATE_LISTENING:
		data |= PORT_LEARN_DISABLE;
		break;
	case BR_STATE_LEARNING:
		if (p->bridged && (p->stp_state == BR_STATE_BLOCKING))
			flush_br_fdb = 1;
		break;
	case BR_STATE_FORWARDING:
		data |= (PORT_TX_ENABLE | PORT_RX_ENABLE);
		break;
	case BR_STATE_BLOCKING:
		data |= PORT_LEARN_DISABLE;
		break;
	default:
		dev_err(ds->dev, "invalid STP state: %d\n", state);
		return;
	}

	/* Always disable learning for non-bridged ports */
	if (!p->bridged)
		data |= PORT_LEARN_DISABLE;

	mutex_lock(&dev->reg_lock);
	ksz_pwrite8(dev, port, P_STP_CTRL, data);
	mutex_unlock(&dev->reg_lock);

	p->stp_state = state;

	if (data & PORT_RX_ENABLE)
		dev->rx_ports |= (1 << port);
	else
		dev->rx_ports &= ~(1 << port);

	if (data & PORT_TX_ENABLE)
		dev->tx_ports |= (1 << port);
	else
		dev->tx_ports &= ~(1 << port);

	/* When topology has changed the function ksz_update_port_member
	 * should be called to modify port forwarding behavior.
	 */
	ksz_port_based_vlan_update(ds);

	if (flush_br_fdb)
		ksz_port_flush_br_fdb(ds, port);
}

static void __ksz8895_flush_dyn_mac_table(struct ksz_device *dev, int port)
{
	int cnt;
	int first;
	int index;
	u8 learn[TOTAL_PORT_NUM];

	if ((uint)port < TOTAL_PORT_NUM) {
		first = port;
		cnt = port + 1;
	} else {
		/* Flush all ports. */
		first = 0;
		if (dev->chip_id == 0x8864)
			first = 1;
		cnt = dev->mib_port_cnt;
	}

	mutex_lock(&dev->reg_lock);

	for (index = first; index < cnt; index++) {
		ksz_pread8(dev, index, P_STP_CTRL, &learn[index]);
		if (!(learn[index] & PORT_LEARN_DISABLE))
			ksz_pwrite8(dev, index, P_STP_CTRL,
				    learn[index] | PORT_LEARN_DISABLE);
	}
	ksz_cfg8(dev, S_FLUSH_TABLE_CTRL, SW_FLUSH_DYN_MAC_TABLE, true);
	for (index = first; index < cnt; index++) {
		if (!(learn[index] & PORT_LEARN_DISABLE))
			ksz_pwrite8(dev, index, P_STP_CTRL, learn[index]);
	}

	mutex_unlock(&dev->reg_lock);
}

static inline void ksz8895_flush_dyn_mac_table(struct ksz_device *dev, int port)
{
	mutex_lock(&dev->reg_lock);
	__ksz8895_flush_dyn_mac_table(dev, port);
	mutex_unlock(&dev->reg_lock);
}

static int ksz8895_port_vlan_filtering(struct dsa_switch *ds, int port,
				       bool flag)
{
	struct ksz_device *dev = ds->priv;
	u16 vlan_ports = dev->vlan_ports;

	if (flag)
		dev->vlan_ports |= (1 << port);
	else
		dev->vlan_ports &= ~(1 << port);

	if ((flag && !vlan_ports) ||
	    (!flag && !dev->vlan_ports && dev->vlan_up)) {
		mutex_lock(&dev->reg_lock);
		ksz_cfg8(dev, S_MIRROR_CTRL, SW_VLAN_ENABLE, flag);
		ksz_port_cfg8(dev, dev->cpu_port, P_TAG_CTRL, PORT_INSERT_TAG,
			     false);
		mutex_unlock(&dev->reg_lock);
		dev->vlan_up = flag;
	}


	return 0;
}

static void ksz8895_port_vlan_add(struct dsa_switch *ds, int port,
				  const struct switchdev_obj_port_vlan *vlan)
{
	struct ksz_device *dev = ds->priv;
	u16 data;
	u16 vid;
	u8 fid;
	u8 member;
	u8 valid;
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	bool pvid = vlan->flags & BRIDGE_VLAN_INFO_PVID;
	u16 new_pvid = 1;

	if (!dev->vlan_up)
		return;

	mutex_lock(&dev->reg_lock);

	ksz_port_cfg8(dev, port, P_TAG_CTRL, PORT_REMOVE_TAG, untagged);

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {

		/* VID 1 is reserved. */
		if (vid == 1)
			continue;

		/* change PVID */
		if (pvid)
			new_pvid = vid;
		__ksz8895_r_vlan_table(dev, vid, &data);
		ksz8895_from_vlan(data, &fid, &member, &valid);

		fid = __ksz8895_get_fid(vid);

		/* First time to setup the VLAN entry. */
		if (!valid) {
			valid = 1;
		}
		member |= BIT(port);
		member |= dev->host_mask;

		ksz8895_to_vlan(fid, member, valid, &data);
		__ksz8895_w_vlan_table(dev, vid, data);
	}

	ksz_pread16(dev, port, REG_PORT_CTRL_VID, &vid);
	if (new_pvid != (vid & 0xfff)) {
		vid &= ~0xfff;
		vid |= new_pvid;
		ksz_pwrite16(dev, port, REG_PORT_CTRL_VID, vid);

		/* Switch may use lookup to forward unicast frame. */
		__ksz8895_flush_dyn_mac_table(dev, port);

		if (!dev->vid_ports)
			ksz_port_cfg8(dev, dev->cpu_port, P_TAG_CTRL,
				     PORT_INSERT_TAG, true);
		dev->vid_ports |= (1 << port);
	}

	mutex_unlock(&dev->reg_lock);
}

static int ksz8895_port_vlan_del(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_vlan *vlan)
{
	struct ksz_device *dev = ds->priv;
	u16 data;
	u16 vid;
	u16 pvid;
	u8 fid;
	u8 member;
	u8 valid;
	u16 new_pvid = 0;

	if (!dev->vlan_up)
		return 0;

	mutex_lock(&dev->reg_lock);

	ksz_pread16(dev, port, REG_PORT_CTRL_VID, &pvid);
	pvid = pvid & 0xFFF;

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {

		/* VID 1 is reserved. */
		if (vid == 1)
			continue;
		__ksz8895_r_vlan_table(dev, vid, &data);
		ksz8895_from_vlan(data, &fid, &member, &valid);

		member &= ~BIT(port);

		/* Invalidate the entry if no more member. */
		if (!(member & ~dev->host_mask)) {
			fid = 0;
			valid = 0;
		}

		if (pvid == vid)
			new_pvid = 1;

		ksz8895_to_vlan(fid, member, valid, &data);
		__ksz8895_w_vlan_table(dev, vid, data);
	}

	if (new_pvid && new_pvid != pvid) {
		ksz_pwrite16(dev, port, REG_PORT_CTRL_VID, new_pvid);

		/* Switch may use lookup to forward unicast frame. */
		__ksz8895_flush_dyn_mac_table(dev, port);

		dev->vid_ports &= ~(1 << port);
		if (!dev->vid_ports)
			ksz_port_cfg8(dev, dev->cpu_port, P_TAG_CTRL,
				     PORT_INSERT_TAG, false);
	}

	mutex_unlock(&dev->reg_lock);

	return 0;
}

static int ksz8895_port_mirror_add(struct dsa_switch *ds, int port,
				   struct dsa_mall_mirror_tc_entry *mirror,
				   bool ingress)
{
	struct ksz_device *dev = ds->priv;

	mutex_lock(&dev->reg_lock);

	if (ingress) {
		ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX, true);
		dev->mirror_rx |= (1 << port);
	} else {
		ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX, true);
		dev->mirror_tx |= (1 << port);
	}

	ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_SNIFFER, false);

	/* configure mirror port */
	if (dev->mirror_rx || dev->mirror_tx)
		ksz_port_cfg8(dev, mirror->to_local_port, P_MIRROR_CTRL,
			     PORT_MIRROR_SNIFFER, true);

	mutex_unlock(&dev->reg_lock);

	return 0;
}

static void ksz8895_port_mirror_del(struct dsa_switch *ds, int port,
				    struct dsa_mall_mirror_tc_entry *mirror)
{
	struct ksz_device *dev = ds->priv;
	u8 data;

	mutex_lock(&dev->reg_lock);

	if (mirror->ingress) {
		ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX, false);
		dev->mirror_rx &= ~(1 << port);
	} else {
		ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX, false);
		dev->mirror_tx &= ~(1 << port);
	}

	ksz_pread8(dev, port, P_MIRROR_CTRL, &data);

	if (!dev->mirror_rx && !dev->mirror_tx)
		ksz_port_cfg8(dev, mirror->to_local_port, P_MIRROR_CTRL,
			     PORT_MIRROR_SNIFFER, false);

	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_phy_setup(struct ksz_device *dev, int port,
			      struct phy_device *phy)
{
	/* SUPPORTED_Pause can be removed to disable flow control when
	 * rate limiting is used.
	 */
	phy->supported &= ~SUPPORTED_Asym_Pause;
	phy->supported |= SUPPORTED_Pause;
	phy->advertising = phy->supported;
}

static void __ksz8895_cfg_port_broadcast_storm(struct ksz_device *dev, int port, bool enable);
static void __ksz8895_cfg_broadcast_storm(struct ksz_device *dev, u8 rate_percent);

static void ksz8895_port_setup(struct ksz_device *dev, int port, bool cpu_port)
{
	u8 member;
	struct ksz_port *p = &dev->ports[port];

	mutex_lock(&dev->reg_lock);

	/* enable broadcast storm limit */
	__ksz8895_cfg_port_broadcast_storm(dev, port, true);

	__ksz8895_set_prio_queue(dev, port, 4);

	/* disable DiffServ priority */
	ksz_port_cfg8(dev, port, P_PRIO_CTRL, PORT_DIFFSERV_ENABLE, false);

	/* replace priority */
	ksz_port_cfg8(dev, port, P_802_1P_CTRL, PORT_802_1P_REMAPPING, false);

	/* enable 802.1p priority */
	ksz_port_cfg8(dev, port, P_PRIO_CTRL, PORT_802_1P_ENABLE, true);

	if (cpu_port) {
		member = dev->port_mask;
		dev->on_ports = dev->host_mask;
		dev->live_ports = dev->host_mask;
	} else {
		member = dev->host_mask | p->vid_member;
		dev->on_ports |= (1 << port);

		/* Link was detected before port is enabled. */
		if (p->phydev.link)
			dev->live_ports |= (1 << port);
	}

	__ksz8895_cfg_port_member(dev, port, member);

	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_config_cpu_port(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	struct ksz_port *p;
	int i;
	u8 remote;

	mutex_lock(&dev->reg_lock);
	ksz_cfg8(dev, S_TAIL_TAG_CTRL, SW_TAIL_TAG_ENABLE, true);
	mutex_unlock(&dev->reg_lock);

	p = &dev->ports[dev->cpu_port];
	p->vid_member = dev->port_mask;
	p->on = 1;

	ksz8895_port_setup(dev, dev->cpu_port, true);
	/*dev->member = dev->host_mask;*/

	for (i = 0; i < SWITCH_PORT_NUM; i++) {
		p = &dev->ports[i];

		/* Initialize to non-zero so that ksz_cfg_port_member() will
		 * be called.
		 */
		p->vid_member = (1 << i);
		p->member = dev->port_mask;
		ksz8895_port_stp_state_set(ds, i, BR_STATE_DISABLED);

		/* First port is disabled in KSZ8864. */
		if (dev->chip_id == 0x8864 && i == 0)
			continue;
		p->on = 1;

		/* Port uses external PHY. */
		if (dev->chip_id == 0x8864 && i == 3)
			continue;
		p->phy = 1;
	}

	mutex_lock(&dev->reg_lock);
	ksz_read8(dev, REG_SW_CFG, &remote);
	if (remote & SW_PORT_3_FIBER)
		dev->ports[2].fiber = 1;
	for (i = 0; i < dev->phy_port_cnt; i++) {
		p = &dev->ports[i];
		if (!p->on)
			continue;
		if (p->fiber)
			ksz_port_cfg8(dev, i, P_STP_CTRL, PORT_FORCE_FLOW_CTRL,
				     true);
		else
			ksz_port_cfg8(dev, i, P_STP_CTRL, PORT_FORCE_FLOW_CTRL,
				     false);
	}
	mutex_unlock(&dev->reg_lock);
}

static int ksz8895_setup(struct dsa_switch *ds)
{
	u8 data8;
	int i;
	struct ksz_device *dev = ds->priv;
	int ret = 0;

	dev->vlan_cache = devm_kcalloc(dev->dev, sizeof(struct vlan_table),
				       dev->num_vlans, GFP_KERNEL);
	if (!dev->vlan_cache)
		return -ENOMEM;

	ret = ksz8895_reset_switch(dev);
	if (ret) {
		dev_err(ds->dev, "failed to reset switch\n");
		return ret;
	}

	ksz8895_config_cpu_port(ds);

	ret = ksz_setup_sta_mac_table(dev);
	if (ret) {
		dev_err(ds->dev, "Failed to setup static MAC address table\n");
		return ret;
	}

	mutex_lock(&dev->reg_lock);

	ksz_cfg8(dev, S_REPLACE_VID_CTRL, SW_FLOW_CTRL, true);

	/* Enable automatic fast aging when link changed detected. */
	ksz_cfg8(dev, S_LINK_AGING_CTRL, SW_LINK_AUTO_AGING, true);

	ksz_read8(dev, REG_SW_CTRL_1, &data8);

	/* Enable aggressive back off algorithm in half duplex mode. */
	data8 |= SW_AGGR_BACKOFF;
	ksz_write8(dev, REG_SW_CTRL_1, data8);

	ksz_read8(dev, REG_SW_CTRL_2, &data8);

	/* Make sure unicast VLAN boundary is set as default. */
	data8 |= UNICAST_VLAN_BOUNDARY;

	/* Enable no excessive collision drop. */
	data8 |= NO_EXC_COLLISION_DROP;
	ksz_write8(dev, REG_SW_CTRL_2, data8);

	ksz_cfg8(dev, REG_SW_CTRL_2, MULTICAST_STORM_DISABLE, true);

	ksz_cfg8(dev, S_REPLACE_VID_CTRL, SW_REPLACE_VID, false);

	ksz_cfg8(dev, S_MIRROR_CTRL, SW_MIRROR_RX_TX, false);

	/* set broadcast storm protection 10% rate */
	__ksz8895_cfg_broadcast_storm(dev, 10);

	for (i = 0; i < VLAN_TABLE_ENTRIES; i++)
		__ksz8895_r_vlan_entries(dev, i);

	ksz_write8(dev, REG_CHIP_ID1, SW_START);

	mutex_unlock(&dev->reg_lock);

	ksz_init_mib_timer(dev);

	return 0;
}

static struct dsa_switch_ops ksz8895_switch_ops = {
	.get_tag_protocol	= ksz8895_get_tag_protocol,
	.setup			= ksz8895_setup,
	.phy_read		= ksz_phy_read16,
	.phy_write		= ksz_phy_write16,
	.adjust_link		= ksz_adjust_link,
	.port_enable		= ksz_enable_port,
	.port_disable		= ksz_disable_port,
	.get_strings		= ksz8895_get_strings,
	.get_ethtool_stats	= ksz_get_ethtool_stats,
	.get_sset_count		= ksz_sset_count,
	.port_bridge_join	= ksz_port_bridge_join,
	.port_bridge_leave	= ksz_port_bridge_leave,
	.port_stp_state_set	= ksz8895_port_stp_state_set,
	.port_fast_age		= ksz_port_fast_age,
	.port_vlan_filtering	= ksz8895_port_vlan_filtering,
	.port_vlan_prepare	= ksz_port_vlan_prepare,
	.port_vlan_add		= ksz8895_port_vlan_add,
	.port_vlan_del		= ksz8895_port_vlan_del,
	.port_fdb_dump		= ksz_port_fdb_dump,
	.port_mdb_prepare       = ksz_port_mdb_prepare,
	.port_mdb_add           = ksz_port_mdb_add,
	.port_mdb_del           = ksz_port_mdb_del,
	.port_mirror_add	= ksz8895_port_mirror_add,
	.port_mirror_del	= ksz8895_port_mirror_del,
};

#define KSZ8895_REGS_SIZE		0x100
#define KSZ_CHIP_NAME_SIZE		25

static const char *ksz8895_chip_names[KSZ_CHIP_NAME_SIZE] = {
	"Microchip KSZ8895 Switch",
	"Microchip KSZ8864 Switch",
};

enum {
	KSZ8895_SW_CHIP,
	KSZ8864_SW_CHIP,
};

static int kszphy_config_init(struct phy_device *phydev)
{
	return 0;
}

static struct phy_driver ksz8895_phy_driver[] = {
{
	.phy_id		= PHY_ID_KSZ8895_SW,
	.phy_id_mask	= 0x00ffffff,
	.name		= "Microchip KSZ8895",
	.features	= PHY_BASIC_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_init	= kszphy_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
}};

static int ksz8895_switch_detect(struct ksz_device *dev)
{
	u16 id16;
	u8 id1;
	u8 id2;
	int ret;
	int chip = -1;

	/* read chip id */
	mutex_lock(&dev->reg_lock);
	ret = ksz_read16(dev, REG_CHIP_ID0, &id16);
	mutex_unlock(&dev->reg_lock);
	if (ret)
		return ret;

	id1 = id16 >> 8;
	id2 = id16 & SW_CHIP_ID_M;
	if (id1 != FAMILY_ID ||
	    (id2 != CHIP_ID_95 && id2 != CHIP_ID_95R))
		return -ENODEV;

	dev->mib_port_cnt = TOTAL_PORT_NUM;
	dev->phy_port_cnt = SWITCH_PORT_NUM;
	dev->port_cnt = SWITCH_PORT_NUM;

	mutex_lock(&dev->reg_lock);
	ksz_read8(dev, REG_KSZ8864_CHIP_ID, &id2);
	mutex_unlock(&dev->reg_lock);
	if (id2 & SW_KSZ8864) {
		dev->port_cnt--;
		id2 = 0x64;
		chip = KSZ8864_SW_CHIP;
	} else {
		id2 = 0x95;
		chip = KSZ8895_SW_CHIP;
	}
	if (chip >= 0) {
		strlcpy(ksz8895_phy_driver[0].name, ksz8895_chip_names[chip],
			KSZ_CHIP_NAME_SIZE);
	}

	id16 = 0x8800;
	id16 |= id2;
	dev->chip_id = id16;

	dev->cpu_port = dev->mib_port_cnt - 1;
	dev->host_mask = (1 << dev->cpu_port);

	dev->chip_series = KSZ_CHIP_8895_SERIES;
	dev->last_port = dev->mib_port_cnt - 1;

	return 0;
}

struct ksz_chip_data {
	u16 chip_id;
	const char *dev_name;
	int num_vlans;
	int num_alus;
	int num_statics;
	int cpu_ports;
	int port_cnt;
};

static const struct ksz_chip_data ksz8895_switch_chips[] = {
	{
		.chip_id = 0x8895,
		.dev_name = "KSZ8895",
		.num_vlans = 4096,
		.num_alus = 0,
		.num_statics = 32,
		.cpu_ports = 0x10,	/* can be configured as cpu port */
		.port_cnt = 4,		/* total physical port count */
	},
	{
		.chip_id = 0x8864,
		.dev_name = "KSZ8864",
		.num_vlans = 4096,
		.num_alus = 0,
		.num_statics = 32,
		.cpu_ports = 0x10,	/* can be configured as cpu port */
		.port_cnt = 3,		/* total physical port count */
	},
};

static int ksz8895_switch_init(struct ksz_device *dev)
{
	int i;

	dev->ds->ops = &ksz8895_switch_ops;

	for (i = 0; i < ARRAY_SIZE(ksz8895_switch_chips); i++) {
		const struct ksz_chip_data *chip = &ksz8895_switch_chips[i];

		if (dev->chip_id == chip->chip_id) {
			dev->name = chip->dev_name;
			dev->num_vlans = chip->num_vlans;
			dev->num_alus = chip->num_alus;
			dev->num_statics = chip->num_statics;
			dev->port_cnt = chip->port_cnt;
			dev->cpu_ports = chip->cpu_ports;

			break;
		}
	}

	/* no switch found */
	if (!dev->cpu_ports)
		return -ENODEV;

	dev->port_mask = (1 << dev->port_cnt) - 1;
	if (dev->chip_id == 0x8864)
		dev->port_mask <<= 1;
	dev->port_mask |= dev->host_mask;

	dev->reg_mib_cnt = SWITCH_COUNTER_NUM;
	dev->mib_cnt = TOTAL_SWITCH_COUNTER_NUM;
	dev->mib_names = ksz8895_mib_names;

	i = dev->mib_port_cnt;
	dev->ports = devm_kzalloc(dev->dev, sizeof(struct ksz_port) * i,
				  GFP_KERNEL);
	if (!dev->ports)
		return -ENOMEM;
	for (i = 0; i < dev->mib_port_cnt; i++) {
		mutex_init(&dev->ports[i].mib.cnt_mutex);
		dev->ports[i].mib.counters =
			devm_kzalloc(dev->dev,
				     sizeof(u64) *
				     (TOTAL_SWITCH_COUNTER_NUM + 1),
				     GFP_KERNEL);
		if (!dev->ports[i].mib.counters)
			return -ENOMEM;
	}
	i = phy_drivers_register(ksz8895_phy_driver,
				 ARRAY_SIZE(ksz8895_phy_driver), THIS_MODULE);
	if (i < 0)
		return -ENODEV;

	dev->regs_size = KSZ8895_REGS_SIZE;
	return 0;
}

static void ksz8895_switch_exit(struct ksz_device *dev)
{
	phy_drivers_unregister(ksz8895_phy_driver,
			       ARRAY_SIZE(ksz8895_phy_driver));
	ksz8895_reset_switch(dev);
	ksz_write8(dev, REG_CHIP_ID1, SW_START);
}

static int ksz8895_w_switch_mac(struct ksz_device *dev, const u8 *mac_addr)
{
	int ret;

	mutex_lock(&dev->reg_lock);
	ret = ksz_set(dev, REG_SW_MAC_ADDR_0, (void *)mac_addr, ETH_ALEN);
	mutex_unlock(&dev->reg_lock);

	return ret;
}

static int ksz8895_r_switch_mac(struct ksz_device *dev, u8 *mac_addr)
{
	int ret;

	mutex_lock(&dev->reg_lock);
	ret = ksz_get(dev, REG_SW_MAC_ADDR_0, mac_addr, ETH_ALEN);
	mutex_unlock(&dev->reg_lock);

	return ret;
}

#define KSZ8895_BROADCAST_STORM_50MS_DIV  7440    /* 144880 * 50 ms */
#define KSZ8895_BROADCAST_STORM_RATE_MAX  0x7ff

static void __ksz8895_cfg_broadcast_storm(struct ksz_device *dev, u8 rate_percent)
{
	u16 data16;
	u32 storm_rate;

	storm_rate = (KSZ8895_BROADCAST_STORM_50MS_DIV * rate_percent) / 100;

	if (storm_rate > KSZ8895_BROADCAST_STORM_RATE_MAX)
		storm_rate = KSZ8895_BROADCAST_STORM_RATE_MAX;

	/* Set broadcast storm protection rate */
	ksz_read16(dev, S_REPLACE_VID_CTRL, &data16);
	data16 &= ~BROADCAST_STORM_RATE;
	data16 |= storm_rate;
	ksz_write16(dev, S_REPLACE_VID_CTRL, data16);
}

static inline void ksz8895_cfg_broadcast_storm(struct ksz_device *dev, u8 rate_percent)
{
	mutex_lock(&dev->reg_lock);
	__ksz8895_cfg_broadcast_storm(dev, rate_percent);
	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_get_broadcast_storm(struct ksz_device *dev, u8 *rate_percent)
{
	u16 data16;

	mutex_lock(&dev->reg_lock);
	ksz_read16(dev, S_REPLACE_VID_CTRL, &data16);
	mutex_unlock(&dev->reg_lock);

	data16 &= BROADCAST_STORM_RATE;

	*rate_percent = (u8)(((u32)data16 * 100) / (KSZ8895_BROADCAST_STORM_50MS_DIV));

	if (*rate_percent < 1)
		*rate_percent = 1;
}

static void ksz8895_cfg_broadcast_multicast_storm(struct ksz_device *dev, bool enable)
{
	mutex_lock(&dev->reg_lock);
	ksz_cfg8(dev, REG_SW_CTRL_2, MULTICAST_STORM_DISABLE, !enable);
	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_get_broadcast_multicast_storm(struct ksz_device *dev, bool *enabled)
{
	u8 data8;
	mutex_lock(&dev->reg_lock);
	ksz_read8(dev, REG_SW_CTRL_2, &data8);
	mutex_unlock(&dev->reg_lock);
	*enabled = !(data8 & MULTICAST_STORM_DISABLE);
}

static void __ksz8895_cfg_port_broadcast_storm(struct ksz_device *dev, int port, bool enable)
{
	ksz_port_cfg8(dev, port, P_BCAST_STORM_CTRL, PORT_BROADCAST_STORM, enable);
}

static inline void ksz8895_cfg_port_broadcast_storm(struct ksz_device *dev, int port, bool enable)
{
	mutex_lock(&dev->reg_lock);
	__ksz8895_cfg_port_broadcast_storm(dev, port, enable);
	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_get_port_broadcast_storm(struct ksz_device *dev, int port, bool *enabled)
{
	u8 data8;
	mutex_lock(&dev->reg_lock);
	ksz_pread8(dev, port, P_BCAST_STORM_CTRL, &data8);
	mutex_unlock(&dev->reg_lock);
	*enabled = !!(data8 & PORT_BROADCAST_STORM);
}

static void ksz8895_cfg_port_enable(struct ksz_device *dev, int port, bool enable)
{
	mutex_lock(&dev->reg_lock);
	ksz_port_cfg8(dev, port, REG_PORT_CTRL_6, PORT_POWER_DOWN, !enable);
	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_get_port_enable(struct ksz_device *dev, int port, bool *enabled)
{
	u8 data8;
	mutex_lock(&dev->reg_lock);
	ksz_pread8(dev, port, REG_PORT_CTRL_6, &data8);
	mutex_unlock(&dev->reg_lock);
	*enabled = !(data8 & PORT_POWER_DOWN);
}

static void ksz8895_get_port_link(struct ksz_device *dev, int port, struct ksz_port_link *link)
{
	u8 data8;

	mutex_lock(&dev->reg_lock);

	ksz_pread8(dev, port, REG_PORT_STATUS_0, &data8);

	if (data8 & PORT_STAT_SPEED_100MBIT)
		link->speed = 100;
	else
		link->speed = 10;

	link->duplex = !!(data8 & PORT_STAT_FULL_DUPLEX);
	link->link = 0;
	link->autoneg = 0;

	if (port < dev->phy_port_cnt) {
		u8 data8;

		ksz_pread8(dev, port, REG_PORT_STATUS_1, &data8);
		link->link = !!(data8 & PORT_STAT_LINK_GOOD);

		link->autoneg = 1; /* TODO: Fix this */
	}

	mutex_unlock(&dev->reg_lock);
}

static void ksz8895_get_port_stp_state(struct ksz_device *dev, int port, bool *rx, bool *tx, bool *learning)
{
	u8 data;

	mutex_lock(&dev->reg_lock);
	ksz_pread8(dev, port, REG_PORT_CTRL_2, &data);
	mutex_unlock(&dev->reg_lock);

	if (rx)
		*rx = !!(data & PORT_RX_ENABLE);
	if (tx)
		*tx = !!(data & PORT_TX_ENABLE);
	if (learning)
		*learning = !(data & PORT_LEARN_DISABLE);
}

static const struct ksz_dev_ops ksz8895_dev_ops = {
	.cfg_port_member = ksz8895_cfg_port_member,
	.flush_dyn_mac_table = ksz8895_flush_dyn_mac_table,
	.phy_setup = ksz8895_phy_setup,
	.port_setup = ksz8895_port_setup,
	.r_phy = ksz8895_r_phy,
	.w_phy = ksz8895_w_phy,
	.r_switch_mac = ksz8895_r_switch_mac,
	.w_switch_mac = ksz8895_w_switch_mac,
	.r_dyn_mac_table = ksz8895_r_dyn_mac_table,
	.r_sta_mac_table = ksz8895_r_sta_mac_table,
	.w_sta_mac_table = ksz8895_w_sta_mac_table,
	.ins_sta_mac_table = ksz8895_ins_sta_mac_table,
	.del_sta_mac_table = ksz8895_del_sta_mac_table,
	.r_mib_cnt = ksz8895_r_mib_cnt,
	.r_mib_pkt = ksz8895_r_mib_pkt,
	.port_init_cnt = ksz8895_port_init_cnt,
	.shutdown = ksz8895_reset_switch,
	.detect = ksz8895_switch_detect,
	.init = ksz8895_switch_init,
	.exit = ksz8895_switch_exit,

	/* Port STP states */
	.get_port_stp_state = ksz8895_get_port_stp_state,

	/* Speed/duplex/autonegotiation */
	.get_port_link = ksz8895_get_port_link,

	/* Broadcast/multicast storm protection control */
	.cfg_broadcast_storm = ksz8895_cfg_broadcast_storm,
	.get_broadcast_storm = ksz8895_get_broadcast_storm,
	.cfg_broadcast_multicast_storm = ksz8895_cfg_broadcast_multicast_storm,
	.get_broadcast_multicast_storm = ksz8895_get_broadcast_multicast_storm,
	.cfg_port_broadcast_storm = ksz8895_cfg_port_broadcast_storm,
	.get_port_broadcast_storm = ksz8895_get_port_broadcast_storm,

	/* Port enable */
	.cfg_port_enable = ksz8895_cfg_port_enable,
	.get_port_enable = ksz8895_get_port_enable,
};

static int ksz8895_get_len(struct ksz_device *dev)
{
	int len = 1;
	return len;
}

static int ksz8895_get_tag(struct ksz_device *dev, u8 *tag, int *port)
{
	int len = 1;
	*port = tag[0] & 3;
	return len;
}

#define KSZ8895_TAIL_TAG_OVERRIDE	BIT(6)
#define KSZ8895_TAIL_TAG_LOOKUP		BIT(7)

static void ksz8895_set_tag(struct ksz_device *dev, void *ptr, u8 *addr, int p)
{
	u8 *tag = (u8 *)ptr;
	u8 val;

	val = (1 << p); /* Port */

	if (is_link_local_ether_addr(addr))
		val |= KSZ8895_TAIL_TAG_OVERRIDE; /* Anyhow send packets to specified port in bits [3:0] */

	*tag = val;
}

static const struct ksz_tag_ops ksz8895_tag_ops = {
	.get_len = ksz8895_get_len,
	.get_tag = ksz8895_get_tag,
	.set_tag = ksz8895_set_tag,
};

int ksz8895_switch_register(struct ksz_device *dev)
{
	return ksz_switch_register(dev, &ksz8895_dev_ops, &ksz8895_tag_ops);
}
EXPORT_SYMBOL(ksz8895_switch_register);

MODULE_AUTHOR("Tristram Ha <Tristram.Ha@microchip.com>");
MODULE_AUTHOR("Anton Kikin <a.kikin@tano-systems.com>");
MODULE_DESCRIPTION("Microchip KSZ8895 Series Switch DSA Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(KSZ_DRIVER_VERSION);
