// SPDX-License-Identifier: GPL-2.0
/*
 * Microchip switch driver main logic
 *
 * Copyright (C) 2017-2020 Microchip Technology Inc.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/platform_data/microchip-ksz.h>
#include <linux/phy.h>
#include <linux/if_bridge.h>
#include <linux/of_net.h>
#include <net/dsa.h>
#include <net/switchdev.h>

#include "ksz_priv.h"

void ksz_update_port_member(struct ksz_device *dev, int port)
{
	struct ksz_port *p;
	int i;

	for (i = 0; i < dev->mib_port_cnt; i++) {
		if (i == port || i == dev->cpu_port)
			continue;
		p = &dev->ports[i];
		if (!p->on)
			continue;
		if (!(dev->member & (1 << i)))
			continue;

		/* Port is a member of the bridge and is forwarding. */
		if (p->stp_state == BR_STATE_FORWARDING &&
		    p->member != dev->member)
			dev->dev_ops->cfg_port_member(dev, i, dev->member);
	}
}
EXPORT_SYMBOL_GPL(ksz_update_port_member);

static void port_r_cnt(struct ksz_device *dev, int port)
{
	struct ksz_port_mib *mib = &dev->ports[port].mib;
	u64 *dropped;

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
}

static void ksz_mib_read_work(struct work_struct *work)
{
	struct ksz_device *dev =
		container_of(work, struct ksz_device, mib_read);
	struct ksz_port *p;
	struct ksz_port_mib *mib;
	int i;

	for (i = 0; i < dev->mib_port_cnt; i++) {
		p = &dev->ports[i];
		if (!p->on)
			continue;
		mib = &p->mib;
		mutex_lock(&mib->cnt_mutex);

		/* read only dropped counters when link is not up */
		if (p->link_just_down)
			p->link_just_down = 0;
		else if (!p->phydev.link)
			mib->cnt_ptr = dev->reg_mib_cnt;
		port_r_cnt(dev, i);
		mutex_unlock(&mib->cnt_mutex);
	}
}

static void mib_monitor(struct timer_list *t)
{
	struct ksz_device *dev = from_timer(dev, t, mib_read_timer);

	mod_timer(&dev->mib_read_timer, jiffies + dev->mib_read_interval);
	schedule_work(&dev->mib_read);
}

static u8 sta_mac_table_entries[][ETH_ALEN + 1] = {
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 1 }, /* STP BPDU */
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 1 }, /* LLDP */
	{ 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc, 1 }, /* CDP */
	{ 0x01, 0xe0, 0x52, 0xcc, 0xcc, 0xcc, 1 }, /* FDP */
	{ 0x01, 0x00, 0x81, 0x00, 0x01, 0x00, 1 }, /* SONMP */
	{ 0x00, 0xe0, 0x2b, 0x00, 0x00, 0x00, 1 }, /* EDP */
};

int ksz_setup_sta_mac_table(struct ksz_device *dev)
{
	int i;
	struct alu_struct alu;

	if (!dev->dev_ops->ins_sta_mac_table) {
		dev_err(dev->dev, "ins_sta_mac_table operation is not available\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(sta_mac_table_entries); i++) {
		memset(&alu, 0, sizeof(alu));
		memcpy(alu.mac, sta_mac_table_entries[i], ETH_ALEN);
		alu.is_static = true;
		alu.is_override = sta_mac_table_entries[i][ETH_ALEN];
		alu.port_forward = dev->host_mask;

		if (dev->dev_ops->ins_sta_mac_table(dev, &alu, NULL)) {
			dev_err(dev->dev,
				"Failed to add %02x:%02x:%02x:%02x:%02x:%02x to static MAC table\n",
				alu.mac[0], alu.mac[1], alu.mac[2],
				alu.mac[3], alu.mac[4], alu.mac[5]);

			return -1;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ksz_setup_sta_mac_table);

void ksz_init_mib_timer(struct ksz_device *dev)
{
	int i;

	/* Read MIB counters every 30 seconds to avoid overflow. */
	dev->mib_read_interval = msecs_to_jiffies(30000);

	INIT_WORK(&dev->mib_read, ksz_mib_read_work);
	timer_setup(&dev->mib_read_timer, mib_monitor, 0);

	for (i = 0; i < dev->mib_port_cnt; i++)
		dev->dev_ops->port_init_cnt(dev, i);

	/* Start the timer 2 seconds later. */
	dev->mib_read_timer.expires = jiffies + msecs_to_jiffies(2000);
	add_timer(&dev->mib_read_timer);
}
EXPORT_SYMBOL_GPL(ksz_init_mib_timer);

int ksz_phy_read16(struct dsa_switch *ds, int addr, int reg)
{
	struct ksz_device *dev = ds->priv;
	u16 val = 0xffff;

	dev->dev_ops->r_phy(dev, addr, reg, &val);

	return val;
}
EXPORT_SYMBOL_GPL(ksz_phy_read16);

int ksz_phy_write16(struct dsa_switch *ds, int addr, int reg, u16 val)
{
	struct ksz_device *dev = ds->priv;

	dev->dev_ops->w_phy(dev, addr, reg, val);

	return 0;
}
EXPORT_SYMBOL_GPL(ksz_phy_write16);

void ksz_adjust_link(struct dsa_switch *ds, int port,
		     struct phy_device *phydev)
{
	struct ksz_device *dev = ds->priv;
	struct ksz_port *p = &dev->ports[port];

	if (phydev->link) {
		dev->live_ports |= (1 << port) & dev->on_ports;
	} else if (p->phydev.link) {
		p->link_just_down = 1;
		dev->live_ports &= ~(1 << port);
	}
	p->phydev = *phydev;
}
EXPORT_SYMBOL_GPL(ksz_adjust_link);

int ksz_sset_count(struct dsa_switch *ds, int port, int sset)
{
	struct ksz_device *dev = ds->priv;

	if (sset != ETH_SS_STATS)
		return 0;

	return dev->mib_cnt;
}
EXPORT_SYMBOL_GPL(ksz_sset_count);

void ksz_get_ethtool_stats(struct dsa_switch *ds, int port, uint64_t *buf)
{
	struct ksz_device *dev = ds->priv;
	struct ksz_port_mib *mib;

	mib = &dev->ports[port].mib;
	mutex_lock(&mib->cnt_mutex);
	port_r_cnt(dev, port);
	memcpy(buf, mib->counters, dev->mib_cnt * sizeof(u64));
	mutex_unlock(&mib->cnt_mutex);
}
EXPORT_SYMBOL_GPL(ksz_get_ethtool_stats);

int ksz_port_bridge_join(struct dsa_switch *ds, int port,
			 struct net_device *br)
{
	struct ksz_device *dev = ds->priv;

	dev->br_member |= (1 << port);

	/* port_stp_state_set() will be called after to put the port in
	 * appropriate state so there is no need to do anything.
	 */

	return 0;
}
EXPORT_SYMBOL_GPL(ksz_port_bridge_join);

void ksz_port_bridge_leave(struct dsa_switch *ds, int port,
			   struct net_device *br)
{
	struct ksz_device *dev = ds->priv;

	dev->br_member &= ~(1 << port);
	dev->member &= ~(1 << port);

	/* port_stp_state_set() will be called after to put the port in
	 * forwarding state so there is no need to do anything.
	 */
}
EXPORT_SYMBOL_GPL(ksz_port_bridge_leave);

void ksz_port_fast_age(struct dsa_switch *ds, int port)
{
	struct ksz_device *dev = ds->priv;

	dev->dev_ops->flush_dyn_mac_table(dev, port);
}
EXPORT_SYMBOL_GPL(ksz_port_fast_age);

int ksz_port_vlan_prepare(struct dsa_switch *ds, int port,
			  const struct switchdev_obj_port_vlan *vlan)
{
	/* nothing needed */

	return 0;
}
EXPORT_SYMBOL_GPL(ksz_port_vlan_prepare);

int ksz_port_fdb_dump(struct dsa_switch *ds, int port,
		      dsa_fdb_dump_cb_t *cb, void *data)
{
	struct ksz_device *dev = ds->priv;
	int ret = 0;
	u16 i = 0;
	u16 entries = 0;
	u8 timestamp = 0;
	u8 fid;
	u8 member;
	struct alu_struct alu;

	do {
		alu.is_static = false;
		ret = dev->dev_ops->r_dyn_mac_table(dev, i, alu.mac, &fid,
						    &member, &timestamp,
						    &entries);
		if (!ret && (member & BIT(port))) {
			ret = cb(alu.mac, alu.fid, alu.is_static, data);
			if (ret)
				break;
		}
		i++;
	} while (i < entries);
	if (i >= entries)
		ret = 0;

	return ret;
}
EXPORT_SYMBOL_GPL(ksz_port_fdb_dump);

int ksz_port_mdb_prepare(struct dsa_switch *ds, int port,
			 const struct switchdev_obj_port_mdb *mdb)
{
	/* nothing to do */
	return 0;
}
EXPORT_SYMBOL_GPL(ksz_port_mdb_prepare);

void ksz_port_mdb_add(struct dsa_switch *ds, int port,
		      const struct switchdev_obj_port_mdb *mdb)
{
	struct ksz_device *dev = ds->priv;
	struct alu_struct alu;
	int index;
	int empty = 0;

	alu.port_forward = 0;
	for (index = 0; index < dev->num_statics; index++) {
		if (!dev->dev_ops->r_sta_mac_table(dev, index, &alu)) {
			/* Found one already in static MAC table. */
			if (!memcmp(alu.mac, mdb->addr, ETH_ALEN) &&
			    alu.fid == mdb->vid)
				break;
		/* Remember the first empty entry. */
		} else if (!empty) {
			empty = index + 1;
		}
	}

	/* no available entry */
	if (index == dev->num_statics && !empty)
		return;

	/* add entry */
	if (index == dev->num_statics) {
		index = empty - 1;
		memset(&alu, 0, sizeof(alu));
		memcpy(alu.mac, mdb->addr, ETH_ALEN);
		alu.is_static = true;
	}
	alu.port_forward |= BIT(port);
#if 1
	/* Host port can never be specified!? */
	alu.port_forward |= dev->host_mask;
#endif
	if (mdb->vid) {
		alu.is_use_fid = true;

		/* Need a way to map VID to FID. */
		alu.fid = mdb->vid;
	}
	dev->dev_ops->w_sta_mac_table(dev, index, &alu);
}
EXPORT_SYMBOL_GPL(ksz_port_mdb_add);

int ksz_port_mdb_del(struct dsa_switch *ds, int port,
		     const struct switchdev_obj_port_mdb *mdb)
{
	struct ksz_device *dev = ds->priv;
	struct alu_struct alu;
	int index;
	int ret = 0;

	for (index = 0; index < dev->num_statics; index++) {
		if (!dev->dev_ops->r_sta_mac_table(dev, index, &alu)) {
			/* Found one already in static MAC table. */
			if (!memcmp(alu.mac, mdb->addr, ETH_ALEN) &&
			    alu.fid == mdb->vid)
				break;
		}
	}

	/* no available entry */
	if (index == dev->num_statics)
		goto exit;

	/* clear port */
	alu.port_forward &= ~BIT(port);
	if (!(alu.port_forward & ~dev->host_mask))
		alu.is_static = false;
	dev->dev_ops->w_sta_mac_table(dev, index, &alu);

exit:
	return ret;
}
EXPORT_SYMBOL_GPL(ksz_port_mdb_del);

int ksz_enable_port(struct dsa_switch *ds, int port, struct phy_device *phy)
{
	struct ksz_device *dev = ds->priv;

	/* setup slave port */
	dev->dev_ops->port_setup(dev, port, false);
	dev->dev_ops->phy_setup(dev, port, phy);
#if 1
	dev->dev_ops->port_init_cnt(dev, port);
#endif

	/* port_stp_state_set() will be called after to enable the port so
	 * there is no need to do anything.
	 */

	return 0;
}
EXPORT_SYMBOL_GPL(ksz_enable_port);

void ksz_disable_port(struct dsa_switch *ds, int port, struct phy_device *phy)
{
	struct ksz_device *dev = ds->priv;

	dev->on_ports &= ~(1 << port);
	dev->live_ports &= ~(1 << port);

	/* port_stp_state_set() will be called after to disable the port so
	 * there is no need to do anything.
	 */
}
EXPORT_SYMBOL_GPL(ksz_disable_port);

ssize_t ksz_registers_read(struct file *filp, struct kobject *kobj,
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
EXPORT_SYMBOL_GPL(ksz_registers_read);

ssize_t ksz_registers_write(struct file *filp, struct kobject *kobj,
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
EXPORT_SYMBOL_GPL(ksz_registers_write);

struct ksz_device *ksz_switch_alloc(struct device *base)
{
	struct dsa_switch *ds;
	struct ksz_device *swdev;

	ds = dsa_switch_alloc(base, DSA_MAX_PORTS);
	if (!ds)
		return NULL;

	swdev = devm_kzalloc(base, sizeof(*swdev), GFP_KERNEL);
	if (!swdev)
		return NULL;

	ds->dev = base;

	ds->priv = swdev;
	swdev->dev = base;

	swdev->ds = ds;

	return swdev;
}
EXPORT_SYMBOL(ksz_switch_alloc);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,0,11))
/**
 * Increment the given MAC address
 */
static inline void eth_addr_inc(u8 *addr)
{
	u64 u = ether_addr_to_u64(addr);
	u++;
	u64_to_ether_addr(u, addr);
}
#endif

/**
 * Find network device with the given MAC address
 */
static struct net_device *__netdev_find_by_mac(u8 *mac_addr)
{
	struct net_device *dev = 0;

	read_lock(&dev_base_lock);

	dev = first_net_device(&init_net);
	while (dev) {
		if (dev->addr_len >= ETH_ALEN) {
			if (ether_addr_equal(mac_addr, dev->dev_addr)) {
				read_unlock(&dev_base_lock);
				return dev;
			}
		}

		dev = next_net_device(dev);
	}

	read_unlock(&dev_base_lock);

	return 0;
}

static int dsa_multi_macs = 1;
module_param(dsa_multi_macs, int, 0);
MODULE_PARM_DESC(dsa_multi_macs, "Use different MAC addresses for slave DSA devices");

/**
 * Initialze MAC addresses for DSA ports of the switch
 */
static int ksz_dsa_init_ports_macs(struct ksz_device *dev)
{
	int p;
	int ret = 0;

	u32 ports_mask;

	u8 port_addr[ETH_ALEN];
	u8 master_addr[ETH_ALEN];

	ports_mask = 0;

	for (p = 0; p < DSA_MAX_PORTS; p++) {
		if (dsa_is_user_port(dev->ds, p))
			ports_mask |= BIT(p);
	}

	dev_info(dev->dev, "User ports mask is 0x%02x\n", ports_mask);

	/* Setup unique MAC address for CPU port (master netdev) */
	ether_addr_copy(master_addr, dev->ds->dst->cpu_dp->master->dev_addr);

	dev_info(dev->dev,
		"CPU port MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		master_addr[0], master_addr[1], master_addr[2],
		master_addr[3], master_addr[4], master_addr[5]);

	if (dev->dev_ops->w_switch_mac)
		dev->dev_ops->w_switch_mac(dev, master_addr);

	ether_addr_copy(port_addr, master_addr);

	/* Setup MAC's for other ports */
	for (p = 0; p < DSA_MAX_PORTS; p++) {
		struct sockaddr addr;
		struct net_device *netdev;

		if (!(ports_mask & BIT(p)))
			continue;

		netdev = dsa_to_port(dev->ds, p)->slave;
		if (!netdev)
			continue;

		addr.sa_family = netdev->type;

		/*
		 * Generate MAC for port
		 * First DSA port has MAC from master netdev
		 * For single MAC mode all ports has master netdev MAC
		 */
		if (dsa_multi_macs)
		{
			int attempts = 10;

			eth_addr_inc(port_addr);

			while (attempts-- && __netdev_find_by_mac(port_addr))
				eth_addr_inc(port_addr);

			if (!attempts)
			{
				dev_err(dev->dev,
					"Failed to generate unique MAC for DSA port %d [%s]\n",
					p + 1, netdev_name(netdev));

				BUG();
			}
		}

		ether_addr_copy(addr.sa_data, port_addr);

		rtnl_lock();
		ret = dev_set_mac_address(netdev, &addr);
		rtnl_unlock();

		if (ret) {
			dev_err(dev->dev,
				"Failed to setup MAC for port %d [%s] (%d)\n",
				p + 1, netdev_name(netdev), ret);
			break;
		}
		else {
			dev_info(dev->dev,
				"Port %d [%s] MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
				p + 1, netdev_name(netdev),
				addr.sa_data[0], addr.sa_data[1], addr.sa_data[2],
				addr.sa_data[3], addr.sa_data[4], addr.sa_data[5]);
		}
	}

	return ret;
}

static void ksz_dsa_dump_info(struct ksz_device *dev)
{
	int p;
	u32 ports_mask = 0;
	u32 cpu_port_mask = 0;
	u32 dsa_port_mask = 0;
	u32 user_port_mask = 0;

	for (p = 0; p < dev->ds->num_ports; p++) {
		if (dsa_is_cpu_port(dev->ds, p))
			cpu_port_mask |= BIT(p);
		else if (dsa_is_dsa_port(dev->ds, p))
			dsa_port_mask |= BIT(p);
		else if (dsa_is_user_port(dev->ds, p))
			user_port_mask |= BIT(p);
	}

	ports_mask = dsa_port_mask | cpu_port_mask | user_port_mask;

	dev_info(dev->dev,
		"Port mask: 0x%x, CPU mask: 0x%x, DSA mask: 0x%x, user mask: 0x%x\n",
		ports_mask,
		cpu_port_mask,
		dsa_port_mask,
		user_port_mask);

	for (p = 0; p < DSA_MAX_PORTS; p++) {
		if (!(ports_mask & (1 << p)))
			continue;

		dev_info(dev->dev,
			"Port %d [%s]: %s\n",
			p + 1,
			dsa_port_mask  & (1 << p) ? "DSA" :
			cpu_port_mask  & (1 << p) ? "CPU" :
			user_port_mask & (1 << p) ? "USER" : "Unknown",
			dsa_to_port(dev->ds, p)->slave
				? netdev_name(dsa_to_port(dev->ds, p)->slave)
				: "-- no slave device --");
	}
}

int ksz_switch_register(struct ksz_device *dev,
			const struct ksz_dev_ops *ops,
			const struct ksz_tag_ops *tag_ops)
{
	int ret;

	if (dev->pdata)
		dev->chip_id = dev->pdata->chip_id;

	mutex_init(&dev->stats_mutex);
	mutex_init(&dev->alu_mutex);
	mutex_init(&dev->vlan_mutex);

	dev->dev_ops = ops;
	dev->tag_ops = tag_ops;

	if (dev->dev_ops->detect(dev))
		return -EINVAL;

	ret = dev->dev_ops->init(dev);
	if (ret)
		return ret;

	if (dev->dev->of_node) {
		ret = of_get_phy_mode(dev->dev->of_node);
		if (ret >= 0)
			dev->interface = ret;
	}

	dev->ds->num_ports = dev->mib_port_cnt;
	ret = dsa_register_switch(dev->ds);
	if (ret) {
		dev->dev_ops->exit(dev);
		return ret;
	}

	ret = ksz_dsa_init_ports_macs(dev);
	if (ret) {
		dev_warn(dev->dev,
			"Failed to setup MAC addresses for the DSA switch ports (%d)\n", ret);
	}

	ksz_dsa_dump_info(dev);

	dev_info(dev->dev, "DSA switch registered\n");

	return 0;
}
EXPORT_SYMBOL(ksz_switch_register);

void ksz_switch_remove(struct ksz_device *dev)
{
	/* timer started */
	if (dev->mib_read_timer.expires) {
		del_timer_sync(&dev->mib_read_timer);
		flush_work(&dev->mib_read);
	}

	dev->dev_ops->exit(dev);
	dsa_unregister_switch(dev->ds);
}
EXPORT_SYMBOL(ksz_switch_remove);

MODULE_AUTHOR("Woojung Huh <Woojung.Huh@microchip.com>");
MODULE_DESCRIPTION("Microchip KSZ Series Switch DSA Driver");
MODULE_LICENSE("GPL");