// SPDX-License-Identifier: GPL-2.0
/*
 * Microchip KSZ9477 switch driver main logic
 *
 * Copyright (C) 2017-2020 Microchip Technology Inc.
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
#include "ksz9477_reg.h"
#include "ksz_common.h"

static void __ksz9477_cfg_broadcast_storm(struct ksz_device *dev, u8 rate_percent);

static inline void __ksz9477_cfg_port_broadcast_storm(
	struct ksz_device *dev, int port, bool enable);

/* features flags */
#define GBIT_SUPPORT			BIT(0)
#define NEW_XMII			BIT(1)
#define IS_9893				BIT(2)

/* overrides flags */
#define PTP_TAG				BIT(0)

static const struct ksz_mib_info ksz9477_mib_names[TOTAL_SWITCH_COUNTER_NUM] = {
	{ 0x00, "rx_hi" },
	{ 0x01, "rx_undersize" },
	{ 0x02, "rx_fragments" },
	{ 0x03, "rx_oversize" },
	{ 0x04, "rx_jabbers" },
	{ 0x05, "rx_symbol_err" },
	{ 0x06, "rx_crc_err" },
	{ 0x07, "rx_align_err" },
	{ 0x08, "rx_mac_ctrl" },
	{ 0x09, "rx_pause" },
	{ 0x0A, "rx_bcast" },
	{ 0x0B, "rx_mcast" },
	{ 0x0C, "rx_ucast" },
	{ 0x0D, "rx_64_or_less" },
	{ 0x0E, "rx_65_127" },
	{ 0x0F, "rx_128_255" },
	{ 0x10, "rx_256_511" },
	{ 0x11, "rx_512_1023" },
	{ 0x12, "rx_1024_1522" },
	{ 0x13, "rx_1523_2000" },
	{ 0x14, "rx_2001" },
	{ 0x15, "tx_hi" },
	{ 0x16, "tx_late_col" },
	{ 0x17, "tx_pause" },
	{ 0x18, "tx_bcast" },
	{ 0x19, "tx_mcast" },
	{ 0x1A, "tx_ucast" },
	{ 0x1B, "tx_deferred" },
	{ 0x1C, "tx_total_col" },
	{ 0x1D, "tx_exc_col" },
	{ 0x1E, "tx_single_col" },
	{ 0x1F, "tx_mult_col" },
	{ 0x80, "rx_total" },
	{ 0x81, "tx_total" },
	{ 0x82, "rx_discards" },
	{ 0x83, "tx_discards" },
};

#define read8_op(addr)	\
({ \
	u8 data; \
	ksz_read8(dev, addr, &data); \
	data; \
})

#define read32_op(addr)	\
({ \
	u32 data; \
	ksz_read32(dev, addr, &data); \
	data; \
})

#define pread32_op(addr)	\
({ \
	u32 data; \
	ksz_pread32(dev, port, addr, &data); \
	data; \
})

static u16 __ksz9477_get_fid(u16 vid)
{
	u16 fid;

	/* Need to find a way to map VID to FID. */
	if (vid <= 1) {
		fid = 0;
	} else {
		fid = vid & VLAN_FID_M;
		if (fid == 0)
			fid = VLAN_FID_M;
	}
	return fid;
}

static int __ksz9477_get_vlan_table(struct ksz_device *dev, u16 vid,
				  u32 *vlan_table)
{
	int ret;
	u8 data;

	mutex_lock(&dev->vlan_mutex);

	ksz_write16(dev, REG_SW_VLAN_ENTRY_INDEX__2, vid & VLAN_INDEX_M);
	ksz_write8(dev, REG_SW_VLAN_CTRL, VLAN_READ | VLAN_START);

	/* wait to be cleared */
	ret = readx_poll_timeout(read8_op, REG_SW_VLAN_CTRL, data,
				 !(data & VLAN_START), 10, 1000);
	if (ret < 0) {
		dev_dbg(dev->dev, "Failed to read vlan table\n");
		goto exit;
	}

	ksz_read32(dev, REG_SW_VLAN_ENTRY__4, &vlan_table[0]);
	ksz_read32(dev, REG_SW_VLAN_ENTRY_UNTAG__4, &vlan_table[1]);
	ksz_read32(dev, REG_SW_VLAN_ENTRY_PORTS__4, &vlan_table[2]);

	ksz_write8(dev, REG_SW_VLAN_CTRL, 0);

exit:
	mutex_unlock(&dev->vlan_mutex);

	return ret;
}

static int __ksz9477_set_vlan_table(struct ksz_device *dev, u16 vid,
				  u32 *vlan_table)
{
	int ret;
	u8 data;

	mutex_lock(&dev->vlan_mutex);

	ksz_write32(dev, REG_SW_VLAN_ENTRY__4, vlan_table[0]);
	ksz_write32(dev, REG_SW_VLAN_ENTRY_UNTAG__4, vlan_table[1]);
	ksz_write32(dev, REG_SW_VLAN_ENTRY_PORTS__4, vlan_table[2]);

	ksz_write16(dev, REG_SW_VLAN_ENTRY_INDEX__2, vid & VLAN_INDEX_M);
	ksz_write8(dev, REG_SW_VLAN_CTRL, VLAN_START | VLAN_WRITE);

	/* wait to be cleared */
	ret = readx_poll_timeout(read8_op, REG_SW_VLAN_CTRL, data,
				 !(data & VLAN_START), 10, 1000);
	if (ret < 0) {
		dev_dbg(dev->dev, "Failed to write vlan table\n");
		goto exit;
	}

	ksz_write8(dev, REG_SW_VLAN_CTRL, 0);

	/* update vlan cache table */
	dev->vlan_cache[vid].table[0] = vlan_table[0];
	dev->vlan_cache[vid].table[1] = vlan_table[1];
	dev->vlan_cache[vid].table[2] = vlan_table[2];

exit:
	mutex_unlock(&dev->vlan_mutex);

	return ret;
}

static void __ksz9477_read_table(struct ksz_device *dev, u32 *table)
{
	ksz_read32(dev, REG_SW_ALU_VAL_A, &table[0]);
	ksz_read32(dev, REG_SW_ALU_VAL_B, &table[1]);
	ksz_read32(dev, REG_SW_ALU_VAL_C, &table[2]);
	ksz_read32(dev, REG_SW_ALU_VAL_D, &table[3]);
}

static void __ksz9477_write_table(struct ksz_device *dev, u32 *table)
{
	ksz_write32(dev, REG_SW_ALU_VAL_A, table[0]);
	ksz_write32(dev, REG_SW_ALU_VAL_B, table[1]);
	ksz_write32(dev, REG_SW_ALU_VAL_C, table[2]);
	ksz_write32(dev, REG_SW_ALU_VAL_D, table[3]);
}

#define KSZ9477_AGEING_COUNT_MIN   1
#define KSZ9477_AGEING_COUNT_MAX   7
#define KSZ9477_AGEING_PERIOD_MIN  1
#define KSZ9477_AGEING_PERIOD_MAX  255

#define KSZ9477_AGEING_TIME_MIN_SECONDS \
	(KSZ9477_AGEING_COUNT_MIN * KSZ9477_AGEING_PERIOD_MIN)

#define KSZ9477_AGEING_TIME_MAX_SECONDS \
	(KSZ9477_AGEING_COUNT_MAX * KSZ9477_AGEING_PERIOD_MAX)

static int ksz9477_set_ageing_time(struct dsa_switch *ds, unsigned int msecs)
{
	u8 data8;

	unsigned int ageing_time = msecs / 1000;
	unsigned int ageing_count;
	unsigned int ageing_period;

	struct ksz_device *dev = ds->priv;

	if (ageing_time < KSZ9477_AGEING_TIME_MIN_SECONDS)
		ageing_time = KSZ9477_AGEING_TIME_MIN_SECONDS;
	else if (ageing_time > KSZ9477_AGEING_TIME_MAX_SECONDS)
		ageing_time = KSZ9477_AGEING_TIME_MAX_SECONDS;

	for (ageing_count = KSZ9477_AGEING_COUNT_MIN;
	     ageing_count <= KSZ9477_AGEING_COUNT_MAX;
	     ageing_count++) {
		ageing_period = ageing_time / ageing_count;

		if (ageing_period > KSZ9477_AGEING_PERIOD_MAX)
			continue;

		if ((ageing_count * ageing_period) >= ageing_time)
			break;
	}

	mutex_lock(&dev->reg_lock);

	ksz_read8(dev, REG_SW_LUE_CTRL_0, &data8);
	data8 &= ~(SW_AGE_CNT_M << SW_AGE_CNT_S);
	data8 |= (ageing_count << SW_AGE_CNT_S);
	ksz_write8(dev, REG_SW_LUE_CTRL_0, data8);

	data8 = ageing_period;
	ksz_write8(dev, REG_SW_LUE_CTRL_3, data8);

	mutex_unlock(&dev->reg_lock);

	return 0;
}

static int ksz9477_reset_switch(struct ksz_device *dev)
{
	u8 data8;
	u32 data32;

	/* reset switch */
	mutex_lock(&dev->reg_lock);
	ksz_cfg8(dev, REG_SW_OPERATION, SW_RESET, true);
	mutex_unlock(&dev->reg_lock);

	udelay(dev->reset_delay_after);

	mutex_lock(&dev->reg_lock);

	/* turn off SPI DO Edge select */
	ksz_read8(dev, REG_SW_GLOBAL_SERIAL_CTRL_0, &data8);
	data8 &= ~SPI_AUTO_EDGE_DETECTION;
	ksz_write8(dev, REG_SW_GLOBAL_SERIAL_CTRL_0, data8);

	/* default configuration */
	ksz_read8(dev, REG_SW_LUE_CTRL_1, &data8);
	data8 = SW_AGING_ENABLE | SW_LINK_AUTO_AGING |
	      SW_SRC_ADDR_FILTER | SW_FLUSH_STP_TABLE | SW_FLUSH_MSTP_TABLE |
	      SW_FWD_MCAST_SRC_ADDR;
	ksz_write8(dev, REG_SW_LUE_CTRL_1, data8);

	/* disable interrupts */
	ksz_write32(dev, REG_SW_INT_MASK__4, SWITCH_INT_MASK);
	ksz_write32(dev, REG_SW_PORT_INT_MASK__4, 0x7F);
	ksz_read32(dev, REG_SW_PORT_INT_STATUS__4, &data32);

	/* set broadcast storm protection 10% rate */
	__ksz9477_cfg_broadcast_storm(dev, 10);

	mutex_unlock(&dev->reg_lock);

	return 0;
}

static void ksz9477_r_mib_cnt(struct ksz_device *dev, int port, u16 addr,
			      u64 *cnt)
{
	u32 data;
	int ret;
	struct ksz_port *p = &dev->ports[port];

	mutex_lock(&dev->reg_lock);

	/* retain the flush/freeze bit */
	data = p->freeze ? MIB_COUNTER_FLUSH_FREEZE : 0;
	data |= MIB_COUNTER_READ;
	data |= (addr << MIB_COUNTER_INDEX_S);
	ksz_pwrite32(dev, port, REG_PORT_MIB_CTRL_STAT__4, data);

	/* failed to read MIB. get out of loop */
	ret = readx_poll_timeout(pread32_op, REG_PORT_MIB_CTRL_STAT__4, data,
				 !(data & MIB_COUNTER_READ), 10, 1000);
	if (ret < 0) {
		dev_dbg(dev->dev, "Failed to get MIB\n");
		goto exit;
	}

	/* count resets upon read */
	ksz_pread32(dev, port, REG_PORT_MIB_DATA, &data);
	*cnt += data;

exit:
	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_r_mib_pkt(struct ksz_device *dev, int port, u16 addr,
			      u64 *dropped, u64 *cnt)
{
	addr = ksz9477_mib_names[addr].index;
	ksz9477_r_mib_cnt(dev, port, addr, cnt);
}

static void ksz9477_freeze_mib(struct ksz_device *dev, int port, bool freeze)
{
	struct ksz_port *p = &dev->ports[port];
	u32 val = freeze ? MIB_COUNTER_FLUSH_FREEZE : 0;

	/* enable/disable the port for flush/freeze function */
	mutex_lock(&p->mib.cnt_mutex);

	mutex_lock(&dev->reg_lock);
	ksz_pwrite32(dev, port, REG_PORT_MIB_CTRL_STAT__4, val);
	mutex_unlock(&dev->reg_lock);

	/* used by MIB counter reading code to know freeze is enabled */
	p->freeze = freeze;
	mutex_unlock(&p->mib.cnt_mutex);
}

static void ksz9477_port_init_cnt(struct ksz_device *dev, int port)
{
	struct ksz_port_mib *mib = &dev->ports[port].mib;

	/* flush all enabled port MIB counters */
	mutex_lock(&mib->cnt_mutex);

	mutex_lock(&dev->reg_lock);
	ksz_pwrite32(dev, port, REG_PORT_MIB_CTRL_STAT__4,
		     MIB_COUNTER_FLUSH_FREEZE);
	ksz_write8(dev, REG_SW_MAC_CTRL_6, SW_MIB_COUNTER_FLUSH);
	ksz_pwrite32(dev, port, REG_PORT_MIB_CTRL_STAT__4, 0);
	mutex_unlock(&dev->reg_lock);

	mutex_unlock(&mib->cnt_mutex);

	mib->cnt_ptr = 0;
	memset(mib->counters, 0, dev->mib_cnt * sizeof(u64));
}

static enum dsa_tag_protocol ksz9477_get_tag_protocol(struct dsa_switch *ds,
						      int port)
{
	return DSA_TAG_PROTO_KSZ;
}

#define KSZ989X_SW_ID		0x9897
#define KSZ889X_SW_ID		0x8897
#define PHY_ID_KSZ989X_SW	((KSZ9477_ID_HI << 16) | KSZ989X_SW_ID)
#define PHY_ID_KSZ889X_SW	((KSZ9477_ID_HI << 16) | KSZ889X_SW_ID)

static int ksz9477_phy_read16(struct dsa_switch *ds, int addr, int reg)
{
	struct ksz_device *dev = ds->priv;
	u16 val = 0xffff;

	/* No real PHY after this. Simulate the PHY.
	 * A fixed PHY can be setup in the device tree, but this function is
	 * still called for that port during initialization.
	 * For RGMII PHY there is no way to access it so the fixed PHY should
	 * be used.  For SGMII PHY the supporting code will be added later.
	 */
	if (addr >= dev->phy_port_cnt) {
		struct ksz_port *p = &dev->ports[addr];

		switch (reg) {
		case MII_BMCR:
			val = 0x1140;
			break;
		case MII_BMSR:
			val = 0x796d;
			break;
		case MII_PHYSID1:
			val = KSZ9477_ID_HI;
			break;
		case MII_PHYSID2:
			val = 0x1631;
			break;
		case MII_ADVERTISE:
			val = 0x05e1;
			break;
		case MII_LPA:
			val = 0xc5e1;
			break;
		case MII_CTRL1000:
			val = 0x0700;
			break;
		case MII_STAT1000:
			if (p->phydev.speed == SPEED_1000)
				val = 0x3800;
			else
				val = 0;
			break;
		}
	} else {
		mutex_lock(&dev->reg_lock);
		ksz_pread16(dev, addr, 0x100 + (reg << 1), &val);
		mutex_unlock(&dev->reg_lock);
	}
	if (reg == MII_PHYSID2) {
		if (dev->features & GBIT_SUPPORT)
			val = KSZ989X_SW_ID;
		else
			val = KSZ889X_SW_ID;
	}

	return val;
}

static int ksz9477_phy_write16(struct dsa_switch *ds, int addr, int reg,
			       u16 val)
{
	struct ksz_device *dev = ds->priv;

	/* No real PHY after this. */
	if (addr >= dev->phy_port_cnt)
		return 0;

	/* No gigabit support.  Do not write to this register. */
	if (!(dev->features & GBIT_SUPPORT) && reg == MII_CTRL1000)
		return 0;

	mutex_lock(&dev->reg_lock);
	ksz_pwrite16(dev, addr, 0x100 + (reg << 1), val);
	mutex_unlock(&dev->reg_lock);

	return 0;
}

static void ksz9477_get_strings(struct dsa_switch *ds, int port,
				u32 stringset, uint8_t *buf)
{
	int i;

	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < TOTAL_SWITCH_COUNTER_NUM; i++) {
		memcpy(buf + i * ETH_GSTRING_LEN, ksz9477_mib_names[i].string,
		       ETH_GSTRING_LEN);
	}
}

static inline void __ksz9477_cfg_port_member(struct ksz_device *dev, int port,
				    u8 member)
{
	ksz_pwrite32(dev, port, REG_PORT_VLAN_MEMBERSHIP__4, member);
	dev->ports[port].member = member;
}

static void ksz9477_cfg_port_member(struct ksz_device *dev, int port,
				    u8 member)
{
	dev_dbg(dev->dev, "%s: port = %d, member = 0x%x\n",
		__FUNCTION__, port, member);

	mutex_lock(&dev->reg_lock);
	__ksz9477_cfg_port_member(dev, port, member);
	mutex_unlock(&dev->reg_lock);
}

static const char *const br_port_state_names[] = {
	[BR_STATE_DISABLED]   = "disabled",
	[BR_STATE_LISTENING]  = "listening",
	[BR_STATE_LEARNING]   = "learning",
	[BR_STATE_FORWARDING] = "forwarding",
	[BR_STATE_BLOCKING]   = "blocking",
};

static void ksz9477_port_stp_state_set(struct dsa_switch *ds, int port,
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
		dev_err(ds->dev, "port %d: invalid STP state: %d\n", port, state);
		return;
	}

	dev_dbg(dev->dev, "%s: port %d: new STP state %s, brdev = %p\n",
		__FUNCTION__, port, br_port_state_names[state],
		dsa_to_port(ds, port)->bridge_dev);

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

static void __ksz9477_flush_dyn_mac_table(struct ksz_device *dev, int port)
{
	u8 data;

	ksz_read8(dev, REG_SW_LUE_CTRL_2, &data);
	data &= ~(SW_FLUSH_OPTION_M << SW_FLUSH_OPTION_S);
	data |= (SW_FLUSH_OPTION_DYN_MAC << SW_FLUSH_OPTION_S);
	ksz_write8(dev, REG_SW_LUE_CTRL_2, data);
	if (port < dev->mib_port_cnt) {
		/* flush individual port */
		ksz_pread8(dev, port, P_STP_CTRL, &data);
		if (!(data & PORT_LEARN_DISABLE))
			ksz_pwrite8(dev, port, P_STP_CTRL,
				    data | PORT_LEARN_DISABLE);
		ksz_cfg8(dev, S_FLUSH_TABLE_CTRL, SW_FLUSH_DYN_MAC_TABLE, true);
		ksz_pwrite8(dev, port, P_STP_CTRL, data);
	} else {
		/* flush all */
		ksz_cfg8(dev, S_FLUSH_TABLE_CTRL, SW_FLUSH_STP_TABLE, true);
	}
}

static void ksz9477_flush_dyn_mac_table(struct ksz_device *dev, int port)
{
	mutex_lock(&dev->reg_lock);
	__ksz9477_flush_dyn_mac_table(dev, port);
	mutex_unlock(&dev->reg_lock);
}

static int ksz9477_port_vlan_filtering(struct dsa_switch *ds, int port,
				       bool flag)
{
	struct ksz_device *dev = ds->priv;
	u16 vlan_ports = dev->vlan_ports;

	mutex_lock(&dev->reg_lock);

	if (flag)
		dev->vlan_ports |= (1 << port);
	else
		dev->vlan_ports &= ~(1 << port);
	if ((flag && !vlan_ports) ||
	    (!flag && !dev->vlan_ports && dev->vlan_up)) {
		if (flag) {
			u32 vlan_table[3];

			vlan_table[0] = VLAN_VALID | 0;
			vlan_table[1] = 0;
			vlan_table[2] = dev->port_mask;
			if (__ksz9477_set_vlan_table(dev, 0, vlan_table)) {
				dev_dbg(dev->dev, "Failed to set vlan table\n");
				goto exit;
			}
			vlan_table[0] = VLAN_VALID | 0;
			vlan_table[1] = dev->port_mask;
			vlan_table[2] = dev->port_mask;
			if (__ksz9477_set_vlan_table(dev, 1, vlan_table)) {
				dev_dbg(dev->dev, "Failed to set vlan table\n");
				goto exit;
			}
		} else {
			int i;

			for (i = 0; i < dev->port_cnt; i++) {
				if (i == dev->cpu_port)
					continue;
				ksz_pwrite16(dev, i, REG_PORT_DEFAULT_VID, 1);
			}
			dev->vid_ports = 0;
		}
		ksz_cfg8(dev, REG_SW_LUE_CTRL_0, SW_VLAN_ENABLE, flag);
		dev->vlan_up = flag;
	}
	if (vlan_ports != dev->vlan_ports) {
		ksz_port_cfg8(dev, port, REG_PORT_LUE_CTRL,
			     (PORT_VLAN_LOOKUP_VID_0 | PORT_INGRESS_FILTER),
			     flag);
	}

exit:
	mutex_unlock(&dev->reg_lock);
	return 0;
}

static void ksz9477_port_vlan_add(struct dsa_switch *ds, int port,
				  const struct switchdev_obj_port_vlan *vlan)
{
	struct ksz_device *dev = ds->priv;
	u32 vlan_table[3];
	u16 fid;
	u16 vid;
	bool untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	bool pvid = vlan->flags & BRIDGE_VLAN_INFO_PVID;
	u16 new_pvid = 1;

	if (!dev->vlan_up)
		return;

	mutex_lock(&dev->reg_lock);

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {
		if (__ksz9477_get_vlan_table(dev, vid, vlan_table)) {
			dev_dbg(dev->dev, "Failed to get vlan table\n");
			goto exit;
		}

		fid = __ksz9477_get_fid(vid);
		vlan_table[0] = VLAN_VALID | fid;
		if (untagged)
			vlan_table[1] |= BIT(port);
		else
			vlan_table[1] &= ~BIT(port);

		/* Keep host port untagged when setting pvid. */
		if (untagged && vid == 1)
			vlan_table[1] |= BIT(dev->cpu_port);
		else
			vlan_table[1] &= ~(BIT(dev->cpu_port));

		vlan_table[2] |= BIT(port) | BIT(dev->cpu_port);

		if (__ksz9477_set_vlan_table(dev, vid, vlan_table)) {
			dev_dbg(dev->dev, "Failed to set vlan table\n");
			goto exit;
		}

		/* change PVID */
		if (pvid)
			new_pvid = vid;
	}

	ksz_pread16(dev, port, REG_PORT_DEFAULT_VID, &vid);
	if (new_pvid != (vid & 0xfff)) {
		vid &= ~0xfff;
		vid |= new_pvid;
		ksz_pwrite16(dev, port, REG_PORT_DEFAULT_VID, vid);

		/* Switch may use lookup to forward unicast frame. */
		__ksz9477_flush_dyn_mac_table(dev, port);
		dev->vid_ports |= (1 << port);
	}

exit:
	mutex_unlock(&dev->reg_lock);
}

static int ksz9477_port_vlan_del(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_vlan *vlan)
{
	struct ksz_device *dev = ds->priv;
	u32 vlan_table[3];
	u16 vid;
	u16 pvid;
	u16 new_pvid = 0;
	int ret = 0;

	if (!dev->vlan_up)
		return 0;

	mutex_lock(&dev->reg_lock);

	ksz_pread16(dev, port, REG_PORT_DEFAULT_VID, &pvid);
	pvid = pvid & 0xFFF;

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {
		if (__ksz9477_get_vlan_table(dev, vid, vlan_table)) {
			dev_dbg(dev->dev, "Failed to get vlan table\n");
			ret = -ETIMEDOUT;
			goto exit;
		}

		vlan_table[2] &= ~BIT(port);

		/* Invalidate the entry if no more member. */
		if (!(vlan_table[2] & ~dev->host_mask))
			vlan_table[0] &= ~VLAN_VALID;

		vlan_table[1] &= ~BIT(port);

		if (pvid == vid)
			new_pvid = 1;

		if (__ksz9477_set_vlan_table(dev, vid, vlan_table)) {
			dev_dbg(dev->dev, "Failed to set vlan table\n");
			ret = -ETIMEDOUT;
			goto exit;
		}
	}

	if (new_pvid && new_pvid != pvid) {
		ksz_pwrite16(dev, port, REG_PORT_DEFAULT_VID, new_pvid);

		/* Switch may use lookup to forward unicast frame. */
		__ksz9477_flush_dyn_mac_table(dev, port);
		dev->vid_ports &= ~(1 << port);
	}

exit:
	mutex_unlock(&dev->reg_lock);
	return ret;
}

static int ksz9477_port_fdb_add(struct dsa_switch *ds, int port,
				const unsigned char *addr, u16 vid)
{
	struct ksz_device *dev = ds->priv;
	u32 alu_table[4];
	u32 data;
	int ret = 0;
	u16 fid = __ksz9477_get_fid(vid);

	dev_dbg(dev->dev, "%s: port %d: Adding %pM, vid %u\n",
		__FUNCTION__, port, addr, vid);

	mutex_lock(&dev->alu_mutex);
	mutex_lock(&dev->reg_lock);

	/* find any entry with mac & vid */
	data = fid << ALU_FID_INDEX_S;
	data |= ((addr[0] << 8) | addr[1]);
	ksz_write32(dev, REG_SW_ALU_INDEX_0, data);

	data = ((addr[2] << 24) | (addr[3] << 16));
	data |= ((addr[4] << 8) | addr[5]);
	ksz_write32(dev, REG_SW_ALU_INDEX_1, data);

	/* start read operation */
	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_READ | ALU_START);

	/* wait to be finished */
	ret = readx_poll_timeout(read32_op, REG_SW_ALU_CTRL__4, data,
				 !(data & ALU_START), 10, 1000);
	if (ret < 0) {
		dev_dbg(dev->dev, "Failed to read ALU\n");
		goto exit;
	}

	/* read ALU entry */
	__ksz9477_read_table(dev, alu_table);

	/* update ALU entry */
	alu_table[0] = ALU_V_STATIC_VALID;
	alu_table[1] |= BIT(port);
#if 1
	/* Host port can never be specified!? */
	alu_table[1] |= dev->host_mask;
#endif
	if (fid)
		alu_table[1] |= ALU_V_USE_FID;
	alu_table[2] = (fid << ALU_V_FID_S);
	alu_table[2] |= ((addr[0] << 8) | addr[1]);
	alu_table[3] = ((addr[2] << 24) | (addr[3] << 16));
	alu_table[3] |= ((addr[4] << 8) | addr[5]);

	__ksz9477_write_table(dev, alu_table);

	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_WRITE | ALU_START);

	/* wait to be finished */
	ret = readx_poll_timeout(read32_op, REG_SW_ALU_CTRL__4, data,
				 !(data & ALU_START), 10, 1000);
	if (ret < 0)
		dev_dbg(dev->dev, "Failed to write ALU\n");

exit:
	mutex_unlock(&dev->reg_lock);
	mutex_unlock(&dev->alu_mutex);
	return ret;
}

static int ksz9477_port_fdb_del(struct dsa_switch *ds, int port,
				const unsigned char *addr, u16 vid)
{
	struct ksz_device *dev = ds->priv;
	u32 alu_table[4];
	u32 data;
	u32 mask = 0;
	int ret = 0;
	u16 fid = __ksz9477_get_fid(vid);

	dev_dbg(dev->dev, "%s: port %d: Deleting %pM, vid %u\n",
		__FUNCTION__, port, addr, vid);

	mutex_lock(&dev->alu_mutex);
	mutex_lock(&dev->reg_lock);

	/* read any entry with mac & vid */
	data = fid << ALU_FID_INDEX_S;
	data |= ((addr[0] << 8) | addr[1]);
	ksz_write32(dev, REG_SW_ALU_INDEX_0, data);

	data = ((addr[2] << 24) | (addr[3] << 16));
	data |= ((addr[4] << 8) | addr[5]);
	ksz_write32(dev, REG_SW_ALU_INDEX_1, data);

	/* start read operation */
	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_READ | ALU_START);

	/* wait to be finished */
	ret = readx_poll_timeout(read32_op, REG_SW_ALU_CTRL__4, data,
				 !(data & ALU_START), 10, 1000);
	if (ret < 0) {
		dev_dbg(dev->dev, "Failed to read ALU\n");
		goto exit;
	}

	ksz_read32(dev, REG_SW_ALU_VAL_A, &alu_table[0]);
	if (alu_table[0] & ALU_V_STATIC_VALID) {
		ksz_read32(dev, REG_SW_ALU_VAL_B, &alu_table[1]);
		ksz_read32(dev, REG_SW_ALU_VAL_C, &alu_table[2]);
		ksz_read32(dev, REG_SW_ALU_VAL_D, &alu_table[3]);

		/* clear forwarding port */
		alu_table[1] &= ~BIT(port);

#if 1
		/* Host port may never get called to remove the entry. */
		mask = dev->host_mask;
#endif

		/* if there is no port to forward, clear table */
		if (!((alu_table[1] & ALU_V_PORT_MAP) & ~mask)) {
			alu_table[0] = 0;
			alu_table[1] = 0;
			alu_table[2] = 0;
			alu_table[3] = 0;
		}
	} else {
		alu_table[0] = 0;
		alu_table[1] = 0;
		alu_table[2] = 0;
		alu_table[3] = 0;
	}

	__ksz9477_write_table(dev, alu_table);

	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_WRITE | ALU_START);

	/* wait to be finished */
	ret = readx_poll_timeout(read32_op, REG_SW_ALU_CTRL__4, data,
				 !(data & ALU_START), 10, 1000);
	if (ret < 0)
		dev_dbg(dev->dev, "Failed to write ALU\n");

exit:
	mutex_unlock(&dev->reg_lock);
	mutex_unlock(&dev->alu_mutex);

	return ret;
}

static void ksz9477_convert_alu(struct alu_struct *alu, u32 *alu_table)
{
	alu->is_static = !!(alu_table[0] & ALU_V_STATIC_VALID);
	alu->is_src_filter = !!(alu_table[0] & ALU_V_SRC_FILTER);
	alu->is_dst_filter = !!(alu_table[0] & ALU_V_DST_FILTER);
	alu->prio_age = (alu_table[0] >> ALU_V_PRIO_AGE_CNT_S) &
			ALU_V_PRIO_AGE_CNT_M;
	alu->mstp = alu_table[0] & ALU_V_MSTP_M;

	alu->is_override = !!(alu_table[1] & ALU_V_OVERRIDE);
	alu->is_use_fid = !!(alu_table[1] & ALU_V_USE_FID);
	alu->port_forward = alu_table[1] & ALU_V_PORT_MAP;

	alu->fid = (alu_table[2] >> ALU_V_FID_S) & ALU_V_FID_M;

	alu->mac[0] = (alu_table[2] >> 8) & 0xFF;
	alu->mac[1] = alu_table[2] & 0xFF;
	alu->mac[2] = (alu_table[3] >> 24) & 0xFF;
	alu->mac[3] = (alu_table[3] >> 16) & 0xFF;
	alu->mac[4] = (alu_table[3] >> 8) & 0xFF;
	alu->mac[5] = alu_table[3] & 0xFF;
}

static int ksz9477_port_fdb_dump(struct dsa_switch *ds, int port,
				 dsa_fdb_dump_cb_t *cb, void *data)
{
	struct ksz_device *dev = ds->priv;
	int ret = 0;
	u32 index;
	u32 ksz_data;
	u32 alu_table[4];
	struct alu_struct alu;
	int timeout;
	u32 cnt = 0;

	dev_dbg(dev->dev, "%s: port %d: Dumping FDB\n", __FUNCTION__, port);

	mutex_lock(&dev->alu_mutex);
	mutex_lock(&dev->reg_lock);

	/* start ALU search */
	ksz_write32(dev, REG_SW_ALU_CTRL__4, ALU_START | ALU_SEARCH);

	do {
		timeout = 1000;
		do {
			ksz_read32(dev, REG_SW_ALU_CTRL__4, &ksz_data);
			if ((ksz_data & ALU_VALID) || !(ksz_data & ALU_START))
				break;
			usleep_range(1, 10);
		} while (timeout-- > 0);

		if (!timeout) {
			dev_dbg(dev->dev, "Failed to search ALU\n");
			ret = -ETIMEDOUT;
			goto exit;
		}

		if (!(ksz_data & ALU_VALID))
			goto exit;
		++cnt;
		index = ksz_data;
		index >>= ALU_VALID_CNT_S;
		index &= ALU_VALID_CNT_M;
		if (index != cnt) {
			dev_dbg(dev->dev, "index not matched: %d %d\n",
				index, cnt);
			cnt = index;
		}

		/* read ALU table */
		__ksz9477_read_table(dev, alu_table);

		ksz9477_convert_alu(&alu, alu_table);

		if (alu.port_forward & BIT(port)) {
			ret = cb(alu.mac, alu.fid, alu.is_static, data);
			if (ret)
				goto exit;
		}
	} while (ksz_data & ALU_START);

exit:

	/* stop ALU search */
	ksz_write32(dev, REG_SW_ALU_CTRL__4, 0);
	ksz_data >>= ALU_VALID_CNT_S;
	ksz_data &= ALU_VALID_CNT_M;
	if (ksz_data != cnt)
		dev_dbg(dev->dev, "count not matched: %d %d\n",
			ksz_data, cnt);

	mutex_unlock(&dev->reg_lock);
	mutex_unlock(&dev->alu_mutex);

	return ret;
}

static void ksz9477_port_mdb_add(struct dsa_switch *ds, int port,
				 const struct switchdev_obj_port_mdb *mdb)
{
	ksz9477_port_fdb_add(ds, port, mdb->addr, mdb->vid);
}

static int ksz9477_port_mdb_del(struct dsa_switch *ds, int port,
				const struct switchdev_obj_port_mdb *mdb)
{
	return ksz9477_port_fdb_del(ds, port, mdb->addr, mdb->vid);
}

static int ksz9477_r_sta_mac_table(struct ksz_device *dev, u16 addr,
				   struct alu_struct *alu)
{
	u32 static_table[4];
	u32 data;
	int ret;

	mutex_lock(&dev->alu_mutex);
	mutex_lock(&dev->reg_lock);

	data = (addr << ALU_STAT_INDEX_S) |
		ALU_STAT_READ | ALU_STAT_START;

	ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);

	/* wait to be finished */
	ret = readx_poll_timeout(read32_op, REG_SW_ALU_STAT_CTRL__4,
				data, !(data & ALU_STAT_START),
				10, 1000);
	if (ret < 0) {
		dev_dbg(dev->dev, "Failed to read ALU STATIC\n");
		goto exit;
	}

	/* read ALU static table */
	__ksz9477_read_table(dev, static_table);

	if (static_table[0] & ALU_V_STATIC_VALID) {
		ksz9477_convert_alu(alu, static_table);
	}
	else {
		ret = -ENXIO;
	}

exit:
	mutex_unlock(&dev->reg_lock);
	mutex_unlock(&dev->alu_mutex);
	return ret;
}

/*
 * dev->alu_mutex must be locked
 */
static int __ksz9477_sta_mac_table_find_addr(
	struct ksz_device *dev, int fid, u32 mac_hi, u32 mac_lo, u16 *addr)
{
	int index;
	u32 data;
	int ret;
	u32 static_table[4];

	for (index = 0; index < dev->num_statics; index++) {
		/* find empty slot first */
		data = (index << ALU_STAT_INDEX_S) |
			ALU_STAT_READ | ALU_STAT_START;

		mutex_lock(&dev->reg_lock);
		ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);

		/* wait to be finished */
		ret = readx_poll_timeout(read32_op, REG_SW_ALU_STAT_CTRL__4,
					data, !(data & ALU_STAT_START),
					10, 1000);
		if (ret < 0) {
			dev_dbg(dev->dev, "Failed to read ALU STATIC\n");
			mutex_unlock(&dev->reg_lock);
			return -1;
		}

		/* read ALU static table */
		__ksz9477_read_table(dev, static_table);

		mutex_unlock(&dev->reg_lock);

		if (static_table[0] & ALU_V_STATIC_VALID) {
			/* check this has same vid & mac address */
			if (((static_table[2] >> ALU_V_FID_S) == fid) &&
			    ((static_table[2] & ALU_V_MAC_ADDR_HI) == mac_hi) &&
			    static_table[3] == mac_lo) {
				/* found matching one */
				*addr = index;
				return 0;
			}
		} else {
			/* found empty one */
			*addr = index;
			return 0;
		}
	}

	/* no available entry */
	return -1;
}

/*
 * dev->alu_mutex must be locked
 */
static void __ksz9477_w_sta_mac_table(struct ksz_device *dev, u16 addr,
				    struct alu_struct *alu)
{
	u32 static_table[4];
	u32 data;
	int ret;
	u32 mac_hi, mac_lo;

	mac_hi  = ((alu->mac[0] << 8)  |  alu->mac[1]);
	mac_lo  = ((alu->mac[2] << 24) | (alu->mac[3] << 16));
	mac_lo |= ((alu->mac[4] << 8)  |  alu->mac[5]);

	/* add entry */
	static_table[0] = alu->is_static ? ALU_V_STATIC_VALID : 0;

	if (alu->is_src_filter)
		static_table[0] |= ALU_V_SRC_FILTER;

	if (alu->is_dst_filter)
		static_table[0] |= ALU_V_DST_FILTER;

	static_table[0] |= ((alu->prio_age & ALU_V_PRIO_AGE_CNT_M) << ALU_V_PRIO_AGE_CNT_S);
	static_table[0] |= alu->mstp & ALU_V_MSTP_M;

	static_table[1] = alu->port_forward;

	if (alu->is_override)
		static_table[1] |= ALU_V_OVERRIDE;

	if (alu->is_use_fid)
		static_table[1] |= ALU_V_USE_FID;

	static_table[2] = (alu->fid << ALU_V_FID_S);
	static_table[2] |= mac_hi;
	static_table[3] = mac_lo;

	mutex_lock(&dev->reg_lock);

	__ksz9477_write_table(dev, static_table);

	data = (addr << ALU_STAT_INDEX_S) | ALU_STAT_START;
	ksz_write32(dev, REG_SW_ALU_STAT_CTRL__4, data);

	/* wait to be finished */
	ret = readx_poll_timeout(read32_op, REG_SW_ALU_STAT_CTRL__4, data,
				!(data & ALU_STAT_START), 10, 1000);
	if (ret < 0) {
		dev_err(dev->dev, "Failed to write ALU STATIC %02x:%02x:%02x:%02x:%02x:%02x to address %u\n",
			alu->mac[0], alu->mac[1], alu->mac[2], alu->mac[3], alu->mac[4], alu->mac[5], addr);
	}

	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_w_sta_mac_table(struct ksz_device *dev, u16 addr,
				    struct alu_struct *alu)
{
	mutex_lock(&dev->alu_mutex);
	__ksz9477_w_sta_mac_table(dev, addr, alu);
	mutex_unlock(&dev->alu_mutex);
}

static int ksz9477_ins_sta_mac_table(struct ksz_device *dev,
				struct alu_struct *alu, u16 *addr)
{
	int ret = 0;
	u16 table_addr = 0;
	u32 mac_hi;
	u32 mac_lo;

	mac_hi  = ((alu->mac[0] << 8)  |  alu->mac[1]);
	mac_lo  = ((alu->mac[2] << 24) | (alu->mac[3] << 16));
	mac_lo |= ((alu->mac[4] << 8)  |  alu->mac[5]);

	mutex_lock(&dev->alu_mutex);

	ret = __ksz9477_sta_mac_table_find_addr(dev, alu->fid, mac_hi, mac_lo, &table_addr);

	if (ret) {
		/* no available entry */
		goto exit;
	}

	__ksz9477_w_sta_mac_table(dev, table_addr, alu);

	if (addr)
		*addr = table_addr;

exit:
	mutex_unlock(&dev->alu_mutex);
	return ret;
}

static int ksz9477_del_sta_mac_table(struct ksz_device *dev, struct alu_struct *alu)
{
	/* Mark for deletion */
	alu->is_static = 0;
	alu->port_forward = 0;
	alu->is_override = 0;

	return ksz9477_ins_sta_mac_table(dev, alu, NULL);
}

static int ksz9477_port_mirror_add(struct dsa_switch *ds, int port,
				   struct dsa_mall_mirror_tc_entry *mirror,
				   bool ingress)
{
	struct ksz_device *dev = ds->priv;

	mutex_lock(&dev->reg_lock);

	if (ingress)
		ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX, true);
	else
		ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX, true);

	ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_SNIFFER, false);

	/* configure mirror port */
	ksz_port_cfg8(dev, mirror->to_local_port, P_MIRROR_CTRL,
		     PORT_MIRROR_SNIFFER, true);

	ksz_cfg8(dev, S_MIRROR_CTRL, SW_MIRROR_RX_TX, false);

	mutex_unlock(&dev->reg_lock);

	return 0;
}

static void ksz9477_port_mirror_del(struct dsa_switch *ds, int port,
				    struct dsa_mall_mirror_tc_entry *mirror)
{
	struct ksz_device *dev = ds->priv;
	u8 data;

	mutex_lock(&dev->reg_lock);

	if (mirror->ingress)
		ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_RX, false);
	else
		ksz_port_cfg8(dev, port, P_MIRROR_CTRL, PORT_MIRROR_TX, false);

	ksz_pread8(dev, port, P_MIRROR_CTRL, &data);

	if (!(data & (PORT_MIRROR_RX | PORT_MIRROR_TX)))
		ksz_port_cfg8(dev, mirror->to_local_port, P_MIRROR_CTRL,
			     PORT_MIRROR_SNIFFER, false);

	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_phy_setup(struct ksz_device *dev, int port,
			      struct phy_device *phy)
{
	if (port < dev->phy_port_cnt) {
		/* SUPPORTED_Asym_Pause and SUPPORTED_Pause can be removed to
		 * disable flow control when rate limiting is used.
		 */
		phy->supported |= SUPPORTED_Pause;
		phy->advertising = phy->supported;
	}
}

static bool ksz9477_get_gbit(struct ksz_device *dev, u8 data)
{
	bool gbit;

	if (dev->features & NEW_XMII)
		gbit = !(data & PORT_MII_NOT_1GBIT);
	else
		gbit = !!(data & PORT_MII_1000MBIT_S1);
	return gbit;
}

static void ksz9477_set_gbit(struct ksz_device *dev, bool gbit, u8 *data)
{
	if (dev->features & NEW_XMII) {
		if (gbit)
			*data &= ~PORT_MII_NOT_1GBIT;
		else
			*data |= PORT_MII_NOT_1GBIT;
	} else {
		if (gbit)
			*data |= PORT_MII_1000MBIT_S1;
		else
			*data &= ~PORT_MII_1000MBIT_S1;
	}
}

static int ksz9477_get_xmii(struct ksz_device *dev, u8 data)
{
	int mode;

	if (dev->features & NEW_XMII) {
		switch (data & PORT_MII_SEL_M) {
		case PORT_MII_SEL:
			mode = 0;
			break;
		case PORT_RMII_SEL:
			mode = 1;
			break;
		case PORT_GMII_SEL:
			mode = 2;
			break;
		default:
			mode = 3;
		}
	} else {
		switch (data & PORT_MII_SEL_M) {
		case PORT_MII_SEL_S1:
			mode = 0;
			break;
		case PORT_RMII_SEL_S1:
			mode = 1;
			break;
		case PORT_GMII_SEL_S1:
			mode = 2;
			break;
		default:
			mode = 3;
		}
	}
	return mode;
}

static void ksz9477_set_xmii(struct ksz_device *dev, int mode, u8 *data)
{
	u8 xmii;

	if (dev->features & NEW_XMII) {
		switch (mode) {
		case 0:
			xmii = PORT_MII_SEL;
			break;
		case 1:
			xmii = PORT_RMII_SEL;
			break;
		case 2:
			xmii = PORT_GMII_SEL;
			break;
		default:
			xmii = PORT_RGMII_SEL;
			break;
		}
	} else {
		switch (mode) {
		case 0:
			xmii = PORT_MII_SEL_S1;
			break;
		case 1:
			xmii = PORT_RMII_SEL_S1;
			break;
		case 2:
			xmii = PORT_GMII_SEL_S1;
			break;
		default:
			xmii = PORT_RGMII_SEL_S1;
			break;
		}
	}
	*data &= ~PORT_MII_SEL_M;
	*data |= xmii;
}

static phy_interface_t ksz9477_get_interface(struct ksz_device *dev, int port)
{
	bool gbit;
	int mode;
	u8 data8;
	phy_interface_t interface;

	if (port < dev->phy_port_cnt)
		return PHY_INTERFACE_MODE_NA;

	mutex_lock(&dev->reg_lock);
	ksz_pread8(dev, port, REG_PORT_XMII_CTRL_1, &data8);
	mutex_unlock(&dev->reg_lock);

	gbit = ksz9477_get_gbit(dev, data8);
	mode = ksz9477_get_xmii(dev, data8);
	switch (mode) {
	case 2:
		interface = PHY_INTERFACE_MODE_GMII;
		if (gbit)
			break;
	case 0:
		interface = PHY_INTERFACE_MODE_MII;
		break;
	case 1:
		interface = PHY_INTERFACE_MODE_RMII;
		break;
	default:
		interface = PHY_INTERFACE_MODE_RGMII;
		if (data8 & PORT_RGMII_ID_EG_ENABLE)
			interface = PHY_INTERFACE_MODE_RGMII_TXID;
		if (data8 & PORT_RGMII_ID_IG_ENABLE) {
			interface = PHY_INTERFACE_MODE_RGMII_RXID;
			if (data8 & PORT_RGMII_ID_EG_ENABLE)
				interface = PHY_INTERFACE_MODE_RGMII_ID;
		}
		break;
	}

	return interface;
}

static void ksz9477_port_mmd_write(struct ksz_device *dev, int port,
				   u8 dev_addr, u16 reg_addr, u16 val)
{
	ksz_pwrite16(dev, port, REG_PORT_PHY_MMD_SETUP,
		     MMD_SETUP(PORT_MMD_OP_INDEX, dev_addr));
	ksz_pwrite16(dev, port, REG_PORT_PHY_MMD_INDEX_DATA, reg_addr);
	ksz_pwrite16(dev, port, REG_PORT_PHY_MMD_SETUP,
		     MMD_SETUP(PORT_MMD_OP_DATA_NO_INCR, dev_addr));
	ksz_pwrite16(dev, port, REG_PORT_PHY_MMD_INDEX_DATA, val);
}

static void ksz9477_phy_errata_setup(struct ksz_device *dev, int port)
{
	/* Apply PHY settings to address errata listed in
	 * KSZ9477, KSZ9897, KSZ9896, KSZ9567, KSZ8565
	 * Silicon Errata and Data Sheet Clarification documents:
	 *
	 * Register settings are needed to improve PHY receive performance
	 */
	ksz9477_port_mmd_write(dev, port, 0x01, 0x6f, 0xdd0b);
	ksz9477_port_mmd_write(dev, port, 0x01, 0x8f, 0x6032);
	ksz9477_port_mmd_write(dev, port, 0x01, 0x9d, 0x248c);
	ksz9477_port_mmd_write(dev, port, 0x01, 0x75, 0x0060);
	ksz9477_port_mmd_write(dev, port, 0x01, 0xd3, 0x7777);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x06, 0x3008);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x08, 0x2001);

	/* Transmit waveform amplitude can be improved
	 * (1000BASE-T, 100BASE-TX, 10BASE-Te)
	 */
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x04, 0x00d0);

	/* Energy Efficient Ethernet (EEE) feature select must
	 * be manually disabled (except on KSZ8565 which is 100Mbit)
	 */
	if (dev->features & GBIT_SUPPORT)
		ksz9477_port_mmd_write(dev, port, 0x07, 0x3c, 0x0000);

	/* Register settings are required to meet data sheet
	 * supply current specifications
	 */
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x13, 0x6eff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x14, 0xe6ff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x15, 0x6eff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x16, 0xe6ff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x17, 0x00ff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x18, 0x43ff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x19, 0xc3ff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x1a, 0x6fff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x1b, 0x07ff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x1c, 0x0fff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x1d, 0xe7ff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x1e, 0xefff);
	ksz9477_port_mmd_write(dev, port, 0x1c, 0x20, 0xeeee);
}

static void ksz9477_port_setup(struct ksz_device *dev, int port, bool cpu_port)
{
	u8 data8;
	u8 member;
	u16 data16;
	struct ksz_port *p = &dev->ports[port];

	mutex_lock(&dev->reg_lock);

	/* enable tag tail for host port */
	if (cpu_port) {
		ksz_port_cfg8(dev, port, REG_PORT_CTRL_0, PORT_TAIL_TAG_ENABLE, true);
		dev_info(dev->dev, "Port %d: Enabled tail tagging\n", port);

		/* Enable Tx, Rx and disable learning on CPU port */
		ksz_pread8(dev, port, P_STP_CTRL, &data8);
		data8 |= (PORT_TX_ENABLE | PORT_RX_ENABLE | PORT_LEARN_DISABLE);
		ksz_pwrite8(dev, port, P_STP_CTRL, data8);
	}

	ksz_port_cfg8(dev, port, REG_PORT_CTRL_0, PORT_MAC_LOOPBACK, false);

	/* set back pressure */
	ksz_port_cfg8(dev, port, REG_PORT_MAC_CTRL_1, PORT_BACK_PRESSURE, true);

	/* enable broadcast storm limit */
	__ksz9477_cfg_port_broadcast_storm(dev, port, true);

	/* disable DiffServ priority */
	ksz_port_cfg8(dev, port, P_PRIO_CTRL, PORT_DIFFSERV_PRIO_ENABLE, false);

	/* replace priority */
	ksz_port_cfg8(dev, port, REG_PORT_MRI_MAC_CTRL, PORT_USER_PRIO_CEILING,
		     false);
	ksz_port_cfg32(dev, port, REG_PORT_MTI_QUEUE_CTRL_0__4,
			   MTI_PVID_REPLACE, false);

	/* enable 802.1p priority */
	ksz_port_cfg8(dev, port, P_PRIO_CTRL, PORT_802_1P_PRIO_ENABLE, true);

	if (port < dev->phy_port_cnt) {
		/* do not force flow control */
		ksz_port_cfg8(dev, port, REG_PORT_CTRL_0,
			     PORT_FORCE_TX_FLOW_CTRL | PORT_FORCE_RX_FLOW_CTRL,
			     false);

		if (dev->phy_errata_9477)
			ksz9477_phy_errata_setup(dev, port);
	} else {
		/* force flow control */
		ksz_port_cfg8(dev, port, REG_PORT_CTRL_0,
			     PORT_FORCE_TX_FLOW_CTRL | PORT_FORCE_RX_FLOW_CTRL,
			     true);

		/* configure MAC to 1G & RGMII mode */
		ksz_pread8(dev, port, REG_PORT_XMII_CTRL_1, &data8);
		switch (dev->interface) {
		case PHY_INTERFACE_MODE_MII:
			ksz9477_set_xmii(dev, 0, &data8);
			ksz9477_set_gbit(dev, false, &data8);
			p->phydev.speed = SPEED_100;
			break;
		case PHY_INTERFACE_MODE_RMII:
			ksz9477_set_xmii(dev, 1, &data8);
			ksz9477_set_gbit(dev, false, &data8);
			p->phydev.speed = SPEED_100;
			break;
		case PHY_INTERFACE_MODE_GMII:
			ksz9477_set_xmii(dev, 2, &data8);
			ksz9477_set_gbit(dev, true, &data8);
			p->phydev.speed = SPEED_1000;
			break;
		default:
			ksz9477_set_xmii(dev, 3, &data8);
			ksz9477_set_gbit(dev, true, &data8);
			data8 &= ~PORT_RGMII_ID_IG_ENABLE;
			data8 &= ~PORT_RGMII_ID_EG_ENABLE;
			if (dev->interface == PHY_INTERFACE_MODE_RGMII_ID ||
			    dev->interface == PHY_INTERFACE_MODE_RGMII_RXID)
				data8 |= PORT_RGMII_ID_IG_ENABLE;
			if (dev->interface == PHY_INTERFACE_MODE_RGMII_ID ||
			    dev->interface == PHY_INTERFACE_MODE_RGMII_TXID)
				data8 |= PORT_RGMII_ID_EG_ENABLE;
			p->phydev.speed = SPEED_1000;
			break;
		}
		ksz_pwrite8(dev, port, REG_PORT_XMII_CTRL_1, data8);
		p->phydev.duplex = 1;
	}
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
	__ksz9477_cfg_port_member(dev, port, member);

	/* clear pending interrupts */
	if (port < dev->phy_port_cnt)
		ksz_pread16(dev, port, REG_PORT_PHY_INT_ENABLE, &data16);

	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_config_cpu_port(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	struct ksz_port *p;
	int i;

	for (i = 0; i < dev->port_cnt; i++) {
		if (dsa_is_cpu_port(ds, i) && (dev->cpu_ports & (1 << i))) {
			phy_interface_t interface;

			dev->cpu_port = i;
			dev->host_mask = (1 << dev->cpu_port);
			dev->port_mask |= dev->host_mask;

			interface = ksz9477_get_interface(dev, i);
			if (!dev->interface && interface)
				dev->interface = interface;
			if (interface && interface != dev->interface)
				dev_info(dev->dev,
					 "Use %s instead of %s\n",
					  phy_modes(dev->interface),
					  phy_modes(interface));
			else
				dev_info(dev->dev,
					 "Use %s\n", phy_modes(interface));

			/* enable cpu port */
			ksz9477_port_setup(dev, i, true);
			p = &dev->ports[dev->cpu_port];
			p->vid_member = dev->port_mask;
			p->on = 1;
		}
	}

	for (i = 0; i < dev->mib_port_cnt; i++) {
		if (i == dev->cpu_port)
			continue;
		p = &dev->ports[i];

		/* Initialize to non-zero so that ksz_cfg_port_member() will
		 * be called.
		 */
		p->vid_member = (1 << i);
		p->member = dev->port_mask;
		ksz9477_port_stp_state_set(ds, i, BR_STATE_DISABLED);
		p->on = 1;
		if (i < dev->phy_port_cnt)
			p->phy = 1;
		if (dev->chip_id == 0x00947700 && i == 6) {
			p->sgmii = 1;

			/* SGMII PHY detection code is not implemented yet. */
			p->phy = 0;
		}
	}
}

static int ksz9477_setup(struct dsa_switch *ds)
{
	struct ksz_device *dev = ds->priv;
	int ret = 0;

	dev->vlan_cache = devm_kcalloc(dev->dev, sizeof(struct vlan_table),
				       dev->num_vlans, GFP_KERNEL);
	if (!dev->vlan_cache)
		return -ENOMEM;

	ret = ksz9477_reset_switch(dev);
	if (ret) {
		dev_err(ds->dev, "failed to reset switch\n");
		return ret;
	}

	ksz9477_config_cpu_port(ds);

	if (dev->dev_ops->cfg_broadcast_multicast_storm)
		dev->dev_ops->cfg_broadcast_multicast_storm(dev, false);

	ret = ksz_setup_sta_mac_table(dev);
	if (ret) {
		dev_err(ds->dev, "Failed to setup static MAC address table\n");
		return ret;
	}

	/* Configure MTU */
	if (dev->dev_ops->cfg_mtu)
		dev->dev_ops->cfg_mtu(dev, 0x2328);

	mutex_lock(&dev->reg_lock);

	/* Do not work correctly with tail tagging. */
	ksz_cfg8(dev, REG_SW_MAC_CTRL_0, SW_CHECK_LENGTH, false);

	/* accept packet up to 2000bytes */
	ksz_cfg8(dev, REG_SW_MAC_CTRL_1, SW_LEGAL_PACKET_DISABLE, true);

	/* Required for port partitioning. */
	ksz_cfg32(dev, REG_SW_QM_CTRL__4, UNICAST_VLAN_BOUNDARY,
		      true);

	/* queue based egress rate limit */
	ksz_cfg8(dev, REG_SW_MAC_CTRL_5, SW_OUT_RATE_LIMIT_QUEUE_BASED, true);

	/* enable global MIB counter freeze function */
	ksz_cfg8(dev, REG_SW_MAC_CTRL_6, SW_MIB_COUNTER_FREEZE, true);

	/* Enable jumbo frames */
	ksz_cfg8(dev, REG_SW_MAC_CTRL_1, SW_JUMBO_PACKET, true);

	dev_info(ds->dev, "Enabled jumbo frames support\n");

	/* start switch */
	ksz_cfg8(dev, REG_SW_OPERATION, SW_START, true);

	mutex_unlock(&dev->reg_lock);

	dev_info(ds->dev, "The switch has been successfully started\n");

	ksz_init_mib_timer(dev);

	return 0;
}

static struct dsa_switch_ops ksz9477_switch_ops = {
	.get_tag_protocol	= ksz9477_get_tag_protocol,
	.setup			= ksz9477_setup,
	.phy_read		= ksz9477_phy_read16,
	.phy_write		= ksz9477_phy_write16,
	.adjust_link		= ksz_adjust_link,
	.port_enable		= ksz_enable_port,
	.port_disable		= ksz_disable_port,
	.get_strings		= ksz9477_get_strings,
	.get_ethtool_stats	= ksz_get_ethtool_stats,
	.get_sset_count		= ksz_sset_count,
	.set_ageing_time    = ksz9477_set_ageing_time,
	.port_bridge_join	= ksz_port_bridge_join,
	.port_bridge_leave	= ksz_port_bridge_leave,
	.port_stp_state_set	= ksz9477_port_stp_state_set,
	.port_fast_age		= ksz_port_fast_age,
	.port_vlan_filtering	= ksz9477_port_vlan_filtering,
	.port_vlan_prepare	= ksz_port_vlan_prepare,
	.port_vlan_add		= ksz9477_port_vlan_add,
	.port_vlan_del		= ksz9477_port_vlan_del,
	.port_fdb_dump		= ksz9477_port_fdb_dump,
	.port_fdb_add		= ksz9477_port_fdb_add,
	.port_fdb_del		= ksz9477_port_fdb_del,
	.port_mdb_prepare       = ksz_port_mdb_prepare,
	.port_mdb_add           = ksz9477_port_mdb_add,
	.port_mdb_del           = ksz9477_port_mdb_del,
	.port_mirror_add	= ksz9477_port_mirror_add,
	.port_mirror_del	= ksz9477_port_mirror_del,
};

#define KSZ9477_REGS_SIZE		0x8000
#define KSZ_CHIP_NAME_SIZE		25

static const char *ksz9477_chip_names[KSZ_CHIP_NAME_SIZE] = {
	"Microchip KSZ9897 Switch",
	"Microchip KSZ9896 Switch",
	"Microchip KSZ9567 Switch",
	"Microchip KSZ8567 Switch",
	"Microchip KSZ8565 Switch",
	"Microchip KSZ9477 Switch",
	"Microchip KSZ9893 Switch",
	"Microchip KSZ9563 Switch",
	"Microchip KSZ8563 Switch",
};

enum {
	KSZ9897_SW_CHIP,
	KSZ9896_SW_CHIP,
	KSZ9567_SW_CHIP,
	KSZ8567_SW_CHIP,
	KSZ8565_SW_CHIP,
	KSZ9477_SW_CHIP,
	KSZ9893_SW_CHIP,
	KSZ9563_SW_CHIP,
	KSZ8563_SW_CHIP,
};

static int kszphy_config_init(struct phy_device *phydev)
{
	return 0;
}

static struct phy_driver ksz9477_phy_driver[] = {
{
	.phy_id		= PHY_ID_KSZ989X_SW,
	.phy_id_mask	= 0x00ffffff,
	.name		= "Microchip KSZ989X",
	.features	= PHY_GBIT_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_init	= kszphy_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.config_aneg	= genphy_config_aneg,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
}, {
	.phy_id		= PHY_ID_KSZ889X_SW,
	.phy_id_mask	= 0x00ffffff,
	.name		= "Microchip KSZ889X",
	.features	= PHY_BASIC_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.config_init	= kszphy_config_init,
	.config_aneg	= genphy_config_aneg,
	.read_status	= genphy_read_status,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
},
};

static int ksz9477_switch_detect(struct ksz_device *dev)
{
	u8 data8;
	u8 id_hi;
	u8 id_lo;
	u32 id32;
	int ret;
	int chip = -1;

	/* turn off SPI DO Edge select */
	mutex_lock(&dev->reg_lock);

	ret = ksz_read8(dev, REG_SW_GLOBAL_SERIAL_CTRL_0, &data8);
	if (ret) {
		mutex_unlock(&dev->reg_lock);
		return ret;
	}

	if (data8 == 0 || data8 == 0xff) {
		mutex_unlock(&dev->reg_lock);
		return -ENODEV;
	}

	data8 &= ~SPI_AUTO_EDGE_DETECTION;
	ret = ksz_write8(dev, REG_SW_GLOBAL_SERIAL_CTRL_0, data8);
	if (ret) {
		mutex_unlock(&dev->reg_lock);
		return ret;
	}

	/* read chip id */
	ret = ksz_read32(dev, REG_CHIP_ID0__1, &id32);
	if (ret) {
		mutex_unlock(&dev->reg_lock);
		return ret;
	}

	ret = ksz_read8(dev, REG_GLOBAL_OPTIONS, &data8);
	if (ret) {
		mutex_unlock(&dev->reg_lock);
		return ret;
	}

	mutex_unlock(&dev->reg_lock);

	/* Number of ports can be reduced depending on chip. */
	dev->mib_port_cnt = TOTAL_PORT_NUM;
	dev->phy_port_cnt = 5;
	dev->features = GBIT_SUPPORT;

	id_hi = (u8)(id32 >> 16);
	id_lo = (u8)(id32 >> 8);
	if ((id_lo & 0xf) == 3) {
		dev->features |= IS_9893;
		if (data8 & SW_QW_ABLE)
			dev->features &= ~GBIT_SUPPORT;
		dev->mib_port_cnt = 3;
		dev->phy_port_cnt = 2;
		if (!(data8 & SW_AVB_ABLE))
			chip = KSZ9893_SW_CHIP;
		else if (data8 & SW_QW_ABLE)
			chip = KSZ8563_SW_CHIP;
		else
			chip = KSZ9563_SW_CHIP;
	} else {
		dev->features |= NEW_XMII;
		if (!(data8 & SW_GIGABIT_ABLE))
			dev->features &= ~GBIT_SUPPORT;
		if ((id_lo & 0xf) == 6)
			dev->mib_port_cnt = 6;
		if (id_hi == FAMILY_ID_94)
			chip = KSZ9477_SW_CHIP;
		else if (id_hi == FAMILY_ID_98 && id_lo == CHIP_ID_97)
			chip = KSZ9897_SW_CHIP;
		else if (id_hi == FAMILY_ID_98 && id_lo == CHIP_ID_96)
			chip = KSZ9896_SW_CHIP;
		else if (id_hi == FAMILY_ID_95 && id_lo == CHIP_ID_67)
			chip = KSZ9567_SW_CHIP;
		else if (id_hi == FAMILY_ID_85 && id_lo == CHIP_ID_67)
			chip = KSZ8567_SW_CHIP;
		if (id_lo == CHIP_ID_67) {
			id_hi = FAMILY_ID_98;
			id_lo = CHIP_ID_97;
		} else if (id_lo == CHIP_ID_66) {
			id_hi = FAMILY_ID_98;
			id_lo = CHIP_ID_96;
		}
	}
	if (dev->dev->of_node) {
		char name[80];

		if (!of_modalias_node(dev->dev->of_node, name, sizeof(name))) {
			if (!strcmp(name, "ksz8565")) {
				chip = KSZ8565_SW_CHIP;
				id_hi = FAMILY_ID_98;
				id_lo = 0x95;
			}
		}
	}
	id32 = (id_hi << 16) | (id_lo << 8);

	dev->chip_id = id32;
	if (chip >= 0) {
		int id;

		dev->name = ksz9477_chip_names[chip];
		if (dev->features & GBIT_SUPPORT)
			id = 0;
		else
			id = 1;
		strlcpy(ksz9477_phy_driver[id].name, ksz9477_chip_names[chip],
			KSZ_CHIP_NAME_SIZE);
	}

	dev->chip_series = KSZ_CHIP_9477_SERIES;
	dev->last_port = dev->mib_port_cnt - 1;

	return 0;
}

struct ksz_chip_data {
	u32 chip_id;
	const char *dev_name;
	int num_vlans;
	int num_alus;
	int num_statics;
	int cpu_ports;
	int port_cnt;
	bool phy_errata_9477;
};

static const struct ksz_chip_data ksz9477_switch_chips[] = {
	{
		.chip_id = 0x00947700,
		.dev_name = "KSZ9477",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x7F,	/* can be configured as cpu port */
		.port_cnt = 7,		/* total physical port count */
		.phy_errata_9477 = true,
	},
	{
		.chip_id = 0x00989700,
		.dev_name = "KSZ9897",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x7F,	/* can be configured as cpu port */
		.port_cnt = 7,		/* total physical port count */
		.phy_errata_9477 = true,
	},
	{
		.chip_id = 0x00989600,
		.dev_name = "KSZ9896",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x3F,	/* can be configured as cpu port */
		.port_cnt = 6,		/* total port count */
	},
	{
		.chip_id = 0x00989300,
		.dev_name = "KSZ9893",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x07,	/* can be configured as cpu port */
		.port_cnt = 3,		/* total port count */
	},
	{
		.chip_id = 0x00989500,
		.dev_name = "KSZ8565",
		.num_vlans = 4096,
		.num_alus = 4096,
		.num_statics = 16,
		.cpu_ports = 0x4F,	/* can be configured as cpu port */
		.port_cnt = 7,		/* total port count */
	},
};

static int ksz9477_switch_init(struct ksz_device *dev)
{
	int i;

	dev->ds->ops = &ksz9477_switch_ops;

	for (i = 0; i < ARRAY_SIZE(ksz9477_switch_chips); i++) {
		const struct ksz_chip_data *chip = &ksz9477_switch_chips[i];

		if (dev->chip_id == chip->chip_id) {
			if (!dev->name)
				dev->name = chip->dev_name;
			dev->num_vlans = chip->num_vlans;
			dev->num_alus = chip->num_alus;
			dev->num_statics = chip->num_statics;
			dev->port_cnt = chip->port_cnt;
			dev->cpu_ports = chip->cpu_ports;
			dev->phy_errata_9477 = chip->phy_errata_9477;

			break;
		}
	}

	/* no switch found */
	if (!dev->port_cnt)
		return -ENODEV;

	dev_info(dev->dev, "%s (%d ports)\n", dev->name, dev->port_cnt);

	dev->port_mask = (1 << dev->port_cnt) - 1;

	dev->reg_mib_cnt = SWITCH_COUNTER_NUM;
	dev->mib_cnt = TOTAL_SWITCH_COUNTER_NUM;
	dev->mib_names = ksz9477_mib_names;

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
	i = phy_drivers_register(ksz9477_phy_driver,
				 ARRAY_SIZE(ksz9477_phy_driver), THIS_MODULE);
	if (i < 0)
		return -ENODEV;

	dev->regs_size = KSZ9477_REGS_SIZE;
	return 0;
}

static void ksz9477_switch_exit(struct ksz_device *dev)
{
	phy_drivers_unregister(ksz9477_phy_driver,
			       ARRAY_SIZE(ksz9477_phy_driver));
	ksz9477_reset_switch(dev);
}

static int ksz9477_w_switch_mac(struct ksz_device *dev, const u8 *mac_addr)
{
	int ret;

	mutex_lock(&dev->reg_lock);
	ret = ksz_set(dev, REG_SW_MAC_ADDR_0, (void *)mac_addr, ETH_ALEN);
	mutex_unlock(&dev->reg_lock);

	return ret;
}

static int ksz9477_r_switch_mac(struct ksz_device *dev, u8 *mac_addr)
{
	int ret;

	mutex_lock(&dev->reg_lock);
	ret = ksz_get(dev, REG_SW_MAC_ADDR_0, mac_addr, ETH_ALEN);
	mutex_unlock(&dev->reg_lock);

	return ret;
}

#define KSZ9477_BROADCAST_STORM_50MS_DIV  7440    /* 144880 * 50 ms */
#define KSZ9477_BROADCAST_STORM_RATE_MAX  0x7ff

static void __ksz9477_cfg_broadcast_storm(struct ksz_device *dev, u8 rate_percent)
{
	u16 data16;
	u32 storm_rate;

	storm_rate = (KSZ9477_BROADCAST_STORM_50MS_DIV * rate_percent) / 100;

	if (storm_rate > KSZ9477_BROADCAST_STORM_RATE_MAX)
		storm_rate = KSZ9477_BROADCAST_STORM_RATE_MAX;

	/* Set broadcast storm protection rate */
	ksz_read16(dev, REG_SW_MAC_CTRL_2, &data16);
	data16 &= ~BROADCAST_STORM_RATE;
	data16 |= storm_rate;
	ksz_write16(dev, REG_SW_MAC_CTRL_2, data16);
}

static void ksz9477_cfg_broadcast_storm(struct ksz_device *dev, u8 rate_percent)
{
	mutex_lock(&dev->reg_lock);
	__ksz9477_cfg_broadcast_storm(dev, rate_percent);
	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_get_broadcast_storm(struct ksz_device *dev, u8 *rate_percent)
{
	u16 data16;

	mutex_lock(&dev->reg_lock);
	ksz_read16(dev, REG_SW_MAC_CTRL_2, &data16);
	mutex_unlock(&dev->reg_lock);

	data16 &= BROADCAST_STORM_RATE;

	*rate_percent = (u8)(((u32)data16 * 100) / (KSZ9477_BROADCAST_STORM_50MS_DIV));

	if (*rate_percent < 1)
		*rate_percent = 1;
}

static void ksz9477_cfg_broadcast_multicast_storm(struct ksz_device *dev, bool enable)
{
	mutex_lock(&dev->reg_lock);
	ksz_cfg8(dev, REG_SW_MAC_CTRL_1, MULTICAST_STORM_DISABLE, !enable);
	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_get_broadcast_multicast_storm(struct ksz_device *dev, bool *enabled)
{
	u8 data8;
	mutex_lock(&dev->reg_lock);
	ksz_read8(dev, REG_SW_MAC_CTRL_1, &data8);
	mutex_unlock(&dev->reg_lock);
	*enabled = !(data8 & MULTICAST_STORM_DISABLE);
}

static inline void __ksz9477_cfg_port_broadcast_storm(
	struct ksz_device *dev, int port, bool enable)
{
	ksz_port_cfg8(dev, port, P_BCAST_STORM_CTRL, PORT_BROADCAST_STORM, enable);
}

static void ksz9477_cfg_port_broadcast_storm(struct ksz_device *dev, int port, bool enable)
{
	mutex_lock(&dev->reg_lock);
	__ksz9477_cfg_port_broadcast_storm(dev, port, enable);
	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_get_port_broadcast_storm(struct ksz_device *dev, int port, bool *enabled)
{
	u8 data8;
	mutex_lock(&dev->reg_lock);
	ksz_pread8(dev, port, P_BCAST_STORM_CTRL, &data8);
	mutex_unlock(&dev->reg_lock);
	*enabled = !!(data8 & PORT_BROADCAST_STORM);
}

static void ksz9477_cfg_mtu(struct ksz_device *dev, u16 mtu)
{
	if (mtu > 0x2328)
		mtu = 0x2328;

	mutex_lock(&dev->reg_lock);
	ksz_write16(dev, REG_SW_MTU__2, mtu);
	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_get_mtu(struct ksz_device *dev, u16 *mtu)
{
	u16 data16;
	mutex_lock(&dev->reg_lock);
	ksz_read16(dev, REG_SW_MTU__2, &data16);
	mutex_unlock(&dev->reg_lock);
	*mtu = data16 & 0x3FFF;
}

static void ksz9477_cfg_port_enable(struct ksz_device *dev, int port, bool enable)
{
	mutex_lock(&dev->reg_lock);
	ksz_port_cfg16(dev, port, REG_PORT_PHY_CTRL, PORT_POWER_DOWN, !enable);
	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_get_port_enable(struct ksz_device *dev, int port, bool *enabled)
{
	u16 data16;
	mutex_lock(&dev->reg_lock);
	ksz_pread16(dev, port, REG_PORT_PHY_CTRL, &data16);
	mutex_unlock(&dev->reg_lock);
	*enabled = !(data16 & PORT_POWER_DOWN);
}

static void ksz9477_get_port_link(struct ksz_device *dev, int port, struct ksz_port_link *link)
{
	u8 data8;
	
	mutex_lock(&dev->reg_lock);

	ksz_pread8(dev, port, REG_PORT_STATUS_0, &data8);

	switch ((data8 >> PORT_INTF_SPEED_S) & PORT_INTF_SPEED_M) {
		case 0: link->speed = 10;   break;
		case 1: link->speed = 100;  break;
		case 2: link->speed = 1000; break;
		default:
			link->speed = 10;
			break;
	}

	link->duplex = !!(data8 & PORT_INTF_FULL_DUPLEX);
	link->link = 0;
	link->autoneg = 0;

	if (port < dev->phy_port_cnt) {
		u16 data16;

		ksz_pread16(dev, port, REG_PORT_PHY_STATUS, &data16);
		link->link = !!(data16 & PORT_LINK_STATUS);

		ksz_pread16(dev, port, REG_PORT_PHY_CTRL, &data16);
		link->autoneg = !!(data16 & PORT_AUTO_NEG_ENABLE);
	}

	mutex_unlock(&dev->reg_lock);
}

static void ksz9477_get_port_stp_state(struct ksz_device *dev, int port, bool *rx, bool *tx, bool *learning)
{
	u8 data;

	mutex_lock(&dev->reg_lock);
	ksz_pread8(dev, port, P_STP_CTRL, &data);
	mutex_unlock(&dev->reg_lock);

	if (rx)
		*rx = !!(data & PORT_RX_ENABLE);
	if (tx)
		*tx = !!(data & PORT_TX_ENABLE);
	if (learning)
		*learning = !(data & PORT_LEARN_DISABLE);
}

static const struct ksz_dev_ops ksz9477_dev_ops = {
	.cfg_port_member = ksz9477_cfg_port_member,
	.flush_dyn_mac_table = ksz9477_flush_dyn_mac_table,
	.phy_setup = ksz9477_phy_setup,
	.port_setup = ksz9477_port_setup,
	.r_mib_cnt = ksz9477_r_mib_cnt,
	.r_mib_pkt = ksz9477_r_mib_pkt,
	.freeze_mib = ksz9477_freeze_mib,
	.port_init_cnt = ksz9477_port_init_cnt,
	.shutdown = ksz9477_reset_switch,
	.detect = ksz9477_switch_detect,
	.init = ksz9477_switch_init,
	.exit = ksz9477_switch_exit,
	.r_switch_mac = ksz9477_r_switch_mac,
	.w_switch_mac = ksz9477_w_switch_mac,
	.r_sta_mac_table = ksz9477_r_sta_mac_table,
	.w_sta_mac_table = ksz9477_w_sta_mac_table,
	.ins_sta_mac_table = ksz9477_ins_sta_mac_table,
	.del_sta_mac_table = ksz9477_del_sta_mac_table,

	/* Port STP states */
	.get_port_stp_state = ksz9477_get_port_stp_state,

	/* Speed/duplex/autonegotiation */
	.get_port_link = ksz9477_get_port_link,

	/* Broadcast/multicast storm protection control */
	.cfg_broadcast_storm = ksz9477_cfg_broadcast_storm,
	.get_broadcast_storm = ksz9477_get_broadcast_storm,
	.cfg_broadcast_multicast_storm = ksz9477_cfg_broadcast_multicast_storm,
	.get_broadcast_multicast_storm = ksz9477_get_broadcast_multicast_storm,
	.cfg_port_broadcast_storm = ksz9477_cfg_port_broadcast_storm,
	.get_port_broadcast_storm = ksz9477_get_port_broadcast_storm,

	/* MTU */
	.cfg_mtu = ksz9477_cfg_mtu,
	.get_mtu = ksz9477_get_mtu,

	/* Port enable */
	.cfg_port_enable = ksz9477_cfg_port_enable,
	.get_port_enable = ksz9477_get_port_enable,
};

/* For Ingress (Host -> KSZ), 2 bytes are added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag0(1byte)|tag1(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag0 : Prioritization (not used now)
 * tag1 : each bit represents port (eg, 0x01=port1, 0x02=port2, 0x10=port5)
 *
 * For switch with 3 ports only one byte is needed.
 * When PTP function is enabled additional 4 bytes are needed.
 *
 * For Egress (KSZ -> Host), 1 byte is added before FCS.
 * ---------------------------------------------------------------------------
 * DA(6bytes)|SA(6bytes)|....|Data(nbytes)|tag0(1byte)|FCS(4bytes)
 * ---------------------------------------------------------------------------
 * tag0 : zero-based value represents port
 *	  (eg, 0x00=port1, 0x02=port3, 0x06=port7)
 *
 * When PTP function is enabled BIT 7 indicates the received frame is a PTP
 * message and so there are 4 additional bytes for the receive timestamp.
 */

static int ksz9477_get_len(struct ksz_device *dev)
{
	int len = 1;

	if (!(dev->features & IS_9893))
		len += 1;
	if (dev->overrides & PTP_TAG)
		len += 4;
	return len;
}

static int ksz9477_get_tag(struct ksz_device *dev, u8 *tag, int *port)
{
	int len = 1;

	if (tag[0] & BIT(7))
		len += 4;
	*port = tag[0] & 7;
	return len;
}

#define KSZ9477_TAIL_TAG_OVERRIDE	BIT(9)
#define KSZ9477_TAIL_TAG_LOOKUP		BIT(10)

#define KSZ9893_TAIL_TAG_OVERRIDE	BIT(5)
#define KSZ9893_TAIL_TAG_LOOKUP		BIT(6)

static void ksz9477_set_tag(struct ksz_device *dev, void *ptr, u8 *addr, int p)
{
	if (dev->overrides & PTP_TAG) {
		u32 *timestamp = (u32 *)ptr;

		*timestamp = 0;
		ptr = timestamp + 1;
	}

	if (dev->features & IS_9893) {
		u8 *tag = (u8 *)ptr;
		u8 val;

		val = BIT(p);

		if (is_link_local_ether_addr(addr))
			val |= KSZ9893_TAIL_TAG_OVERRIDE;

		*tag = val;
	} else {
		__be16 *tag = (__be16 *)ptr;
		u16 val;

		val = BIT(p);

		if (is_link_local_ether_addr(addr))
			val |= KSZ9477_TAIL_TAG_OVERRIDE;

		*tag = cpu_to_be16(val);
	}
}

static const struct ksz_tag_ops ksz9477_tag_ops = {
	.get_len = ksz9477_get_len,
	.get_tag = ksz9477_get_tag,
	.set_tag = ksz9477_set_tag,
};

int ksz9477_switch_register(struct ksz_device *dev)
{
	return ksz_switch_register(dev, &ksz9477_dev_ops, &ksz9477_tag_ops);
}
EXPORT_SYMBOL(ksz9477_switch_register);

MODULE_AUTHOR("Woojung Huh <Woojung.Huh@microchip.com>");
MODULE_AUTHOR("Anton Kikin <a.kikin@tano-systems.com>");
MODULE_DESCRIPTION("Microchip KSZ9477 Series Switch DSA Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(KSZ_DRIVER_VERSION);
