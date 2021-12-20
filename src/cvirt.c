#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/moduleparam.h>
#include <linux/inetdevice.h>
#include <net/arp.h>
#include <net/ip.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

static struct node {
    u32 address;
    u32 mask; // size in bits
    struct net_device *device;
    struct node *next;
};

#define ERR(...) printk(KERN_ERR "! "__VA_ARGS__)
#define LOG(...) printk(KERN_INFO "! "__VA_ARGS__)

static u32 apply_mask(u32 addr, u32 mask)
{
    return (addr & mask);
}
static char *strIP(u32 addr);
static struct net_device *find_device_sub(struct node *subs, u32 addr)
{
    struct net_device *device = NULL;
    while (subs && !device)
    {
        u32 res = apply_mask(subs->mask, addr);
        LOG("Apply mask %s %s   res %s", strIP(subs->mask), strIP(addr), strIP(res));
        if (res == subs->address)
        {
            device = subs->device;
        }
        else
        {
            subs = subs->next;
        }
    }

    return device;
}


static char *link = "enp0s3"; // имя родительского интерфейса
module_param(link, charp, 0);
static char *link2 = "tun0"; // имя родительского интерфейса
module_param(link2, charp, 0);

static char *ifname = "virt"; // имя создаваемого интерфейса
module_param(ifname, charp, 0);

static struct net_device *child = NULL;
static u32 child_ip = 0;
static int child_ip_set = 0;
struct priv
{
    struct net_device_stats stats;
    struct net_device *parent;
    struct node *next;
};

struct arp_eth_body {
   unsigned char  ar_sha[ ETH_ALEN ];     // sender hardware address      
   unsigned char  ar_sip[ 4 ];            // sender IP address            
   unsigned char  ar_tha[ ETH_ALEN ];     // target hardware address      
   unsigned char  ar_tip[ 4 ];            // target IP address            
};

static char *strIP(u32 addr)
{ // диагностика IP в точечной нотации
    static char saddr[MAX_ADDR_LEN];
    sprintf(saddr, "%d.%d.%d.%d",
            (addr)&0xFF, (addr >> 8) & 0xFF,
            (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
    return saddr;
}

static char* strAR_IP( unsigned char addr[ 4 ] ) {
   static char saddr[ MAX_ADDR_LEN ];
   sprintf( saddr, "%d.%0d.%d.%d",
            addr[ 0 ], addr[ 1 ], addr[ 2 ], addr[ 3 ] );
   return saddr;
}

static void print_ip(struct sk_buff *skb)
{
    if (skb->protocol == htons(ETH_P_IP))
    {
        struct iphdr *ip = ip_hdr(skb);
        char daddr[MAX_ADDR_LEN], saddr[MAX_ADDR_LEN];
        strcpy(daddr, strIP(ip->daddr));
        strcpy(saddr, strIP(ip->saddr));
        LOG("re: from IP=%s to IP=%s with length: %u", saddr, daddr, skb->len);
    }
    else if (skb->protocol == htons(ETH_P_ARP))
    {
        struct arphdr *arp = arp_hdr(skb);
        struct arp_eth_body *body = (void *)arp + sizeof(struct arphdr);
        LOG("re: ARP for %s", strAR_IP(body->ar_tip));
    }
    return 0;
}

static u32 charToIP( unsigned char fir, unsigned char sec, unsigned char thd, unsigned char frth ) {
    u32 fourth = frth;
    u32 third = thd;
    u32 second = sec;
    u32 first = fir;
    LOG("%d %d", (fourth << 24) | (third << 16), (second << 8) | first);
   return  (fourth << 24)  | (third << 16) | (second << 8) | (first);
}

static u32 get_ip(struct sk_buff *skb)
{
    if (skb->protocol == htons(ETH_P_IP))
    {
        struct iphdr *ip = ip_hdr(skb);
        return (ip->daddr);//&0xFF | (ip->daddr >> 8) & 0xFF |
            //(ip->daddr >> 16) & 0xFF | (ip->daddr >> 24) & 0xFF;
    }
    else if (skb->protocol == htons(ETH_P_ARP))
    {
        struct arphdr *arp = arp_hdr(skb);
        struct arp_eth_body *body = (void *)arp + sizeof(struct arphdr);

        return (body->ar_tip[0]) | (body->ar_tip[1] << 8) | (body->ar_tip[2] << 16) | (body->ar_tip[3] << 24);
    }
}

static rx_handler_result_t handle_frame(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb;
    LOG("COME: %d", skb->protocol);
    if (skb->protocol == htons(ETH_P_IP))
    {
        struct iphdr *ip = ip_hdr(skb);
        LOG("INCOME: IP4 to IP=%s", strIP(ip->daddr));
        if (!child_ip_set || ip->daddr != child_ip) {
            return RX_HANDLER_PASS;
        }
        LOG("INCOME: PASS");
    }
    else if (skb->protocol == htons(ETH_P_ARP))
    {
        struct arphdr *arp = arp_hdr(skb);
        struct arp_eth_body *body = (void *)arp + sizeof(struct arphdr);
        int i, ip = child_ip;
        LOG("INCOME: ARP for %s", strAR_IP(body->ar_tip));
        for (i = 0; i < sizeof(body->ar_tip); i++)
        {
            if ((ip & 0xFF) != body->ar_tip[i])
                break;
            ip = ip >> 8;
        }
        if (!child_ip_set || i < sizeof(body->ar_tip))
            return RX_HANDLER_PASS;
        LOG("INCOME: PASS");
    }
    else if (skb->protocol == htons(0xCC88)) {

    }
    else
    {
        return RX_HANDLER_PASS;
    }
    
    struct priv *priv = netdev_priv(child);
    priv->stats.rx_packets++;
    priv->stats.rx_bytes += skb->len;
    skb->dev = child;
    return RX_HANDLER_ANOTHER;
}

static int open( struct net_device *dev ) {
   LOG( "%s: device opened", dev->name );
   netif_start_queue( dev );
   return 0;
}

static int stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    LOG("%s: device closed", dev->name);
    return 0;
}

static netdev_tx_t start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct in_device *in_dev = child->ip_ptr;
    struct in_ifaddr *ifa = in_dev->ifa_list;      /* IP ifaddr chain */
    if (ifa && !child_ip_set) {
        child_ip = ifa->ifa_address;
        child_ip_set = 1;
        LOG("%s: IP SET %d", child->name, ifa);
    }
    else if (!ifa && child_ip_set) {
        child_ip_set = 0;
    }

    struct priv *priv = netdev_priv(dev);
    priv->stats.tx_packets++;
    priv->stats.tx_bytes += skb->len;
    LOG("GET IP %d, %s", get_ip(skb), strIP(get_ip(skb)));
    LOG("NEXT %d, ", priv->next);
    if (priv->next)
    {
        LOG("NEXT NET %s, MASK %s %d %d", strIP(priv->next->address), strIP(priv->next->mask), priv->next->device, priv->next->next);
    }
    struct net_device *device = find_device_sub(priv->next, get_ip(skb));
    if (device)
    {
        skb->dev = device;
        skb->priority = 1;
        dev_queue_xmit(skb);
        LOG("OUT: %d", skb->protocol);
        LOG("OUTPUT: injecting frame from %s to %s", dev->name, skb->dev->name);
        return NETDEV_TX_OK;
    }
    return NETDEV_TX_OK;
}

static struct net_device_stats *get_stats(struct net_device *dev)
{
    return &((struct priv *)netdev_priv(dev))->stats;
}

static struct net_device_ops crypto_net_device_ops = {
    .ndo_open = open,
    .ndo_stop = stop,
    .ndo_get_stats = get_stats,
    .ndo_start_xmit = start_xmit,
};

static void setup(struct net_device *dev)
{
    int j;
    ether_setup(dev);
    memset(netdev_priv(dev), 0, sizeof(struct priv));
    dev->netdev_ops = &crypto_net_device_ops;
    for (j = 0; j < ETH_ALEN; ++j) // fill in the MAC address with a phoney
        dev->dev_addr[j] = (char)j;
}

int __init init(void)
{
    int err = 0;
    struct priv *priv;
    char ifstr[40];
    sprintf(ifstr, "%s%s", ifname, "%d");

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0))
    child = alloc_netdev(sizeof(struct priv), ifstr, setup);
#else
    child = alloc_netdev(sizeof(struct priv), ifstr, NET_NAME_UNKNOWN, setup);
#endif
    if (child == NULL)
    {
        ERR("%s: allocate error", THIS_MODULE->name);
        return -ENOMEM;
    }
    priv = netdev_priv(child);
    priv->parent = __dev_get_by_name(&init_net, link); // parent interface
    if (!priv->parent)
    {
        ERR("%s: no such net: %s", THIS_MODULE->name, link);
        err = -ENODEV;
        goto err;
    }

    if (priv->parent->type != ARPHRD_ETHER && priv->parent->type != ARPHRD_LOOPBACK)
    {
        ERR("%s: illegal net type", THIS_MODULE->name);
        err = -EINVAL;
        goto err;
    }

    struct node *second = kmalloc(sizeof(struct node), GFP_KERNEL);
    second->address = charToIP(0, 0, (char)0, (char)0);
    second->mask = charToIP(0, 0, (char)0, (char)0);
    second->device = priv->parent;
    second->next = NULL;

    struct node *first = kmalloc(sizeof(struct node), GFP_KERNEL);
    first->address = charToIP(192, 168, (char)1, (char)0);
    first->mask = charToIP(255, 255, (char)255, (char)0);
    first->device = priv->parent;
    first->next = second;

    LOG("firts rec %d %s", charToIP(192, 168, (char)1, (char)0), strIP(charToIP(192, 168, 1, 0)));

    priv->next = first;

    /* also, and clone its IP, MAC and other information */
    LOG("%d: dev", priv->parent);
    struct in_device *in_dev = priv->parent->ip_ptr;
    LOG("%d: parent dev", in_dev);
    struct in_ifaddr *ifa = in_dev->ifa_list;      /* IP ifaddr chain */
    LOG("%d: parent dev", ifa);
    memcpy(child->dev_addr, priv->parent->dev_addr, ETH_ALEN);
    memcpy(child->broadcast, priv->parent->broadcast, ETH_ALEN);
    if ((err = dev_alloc_name(child, child->name)))
    {
        ERR("%s: allocate name, error %i", THIS_MODULE->name, err);
        err = -EIO;
        goto err;
    }
    register_netdev(child);
    rtnl_lock();
    netdev_rx_handler_register(priv->parent, &handle_frame, NULL);
    rtnl_unlock();
    LOG("module %s loaded", THIS_MODULE->name);
    LOG("%s: create link %s", THIS_MODULE->name, child->name);
    LOG("%s: registered rx handler for %s", THIS_MODULE->name, priv->parent->name);
    return 0;
err:
    free_netdev(child);
    return err;
}

void __exit exit(void)
{
    struct priv *priv = netdev_priv(child);
    if (priv->parent)
    {
        rtnl_lock();
        netdev_rx_handler_unregister(priv->parent);
        rtnl_unlock();
        LOG("unregister rx handler for %s\n", priv->parent->name);
    }
    unregister_netdev(child);
    free_netdev(child);
    LOG("module %s unloaded", THIS_MODULE->name);
}

module_init(init);
module_exit(exit);

MODULE_AUTHOR("Pavel Khetagurov");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.1");