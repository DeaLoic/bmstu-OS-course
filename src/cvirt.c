#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/inetdevice.h> //if_addr
#include <net/ip.h>

static char *link = "enp0s3"; // имя родительского интерфейса
module_param(link, charp, 0);

static char *ifname = "virt"; // имя создаваемого интерфейса
module_param(ifname, charp, 0);

static struct net_device *child = NULL;
struct interfaces {
    u32 address; // адрес подсети
    u32 mask;    // маска подсети
    struct net_device *device; // ссылка на интерфейс
    struct interfaces *next;   // следующий узел
};

struct priv
{
    struct net_device_stats stats;
    struct interfaces *next;
};

struct arp_eth_body {
   unsigned char  ar_sha[ ETH_ALEN ];     // sender hardware address      
   unsigned char  ar_sip[ 4 ];            // sender IP address            
   unsigned char  ar_tha[ ETH_ALEN ];     // target hardware address      
   unsigned char  ar_tip[ 4 ];            // target IP address            
};

#define ERR(...) printk(KERN_ERR "! "__VA_ARGS__)
#define LOG(...) printk(KERN_INFO "! "__VA_ARGS__)

static u32 apply_mask(u32 addr, u32 mask)
{
    return (addr & mask);
}
static char *strIP(u32 addr);
static struct net_device *find_device_sub(struct interfaces *subs, u32 addr)
{
    struct net_device *device = NULL;
    int i = -1;
    while (subs && !device)
    {
        i += 1;
        u32 res = apply_mask(subs->mask, addr);
        if (res == subs->address)
        {
            device = subs->device;
        }
        else
        {
            subs = subs->next;
        }
    }

    if (i >= 0)
    {
        LOG("Device number %d choosed", i);
    }

    return device;
}



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
    struct in_device *in_dev = child->ip_ptr;
    struct in_ifaddr *ifa = in_dev->ifa_list;
    if (!ifa)
    {
        return RX_HANDLER_PASS;
    }
    u32 child_ip = ifa->ifa_address;
    if (skb->protocol == htons(ETH_P_IP))
    {
        struct iphdr *ip = ip_hdr(skb);
        LOG("INCOME: IP to IP=%s", strIP(ip->daddr));
        if (!ifa || ip->daddr != child_ip)
        {
            return RX_HANDLER_PASS;
        }
    }
    else if (skb->protocol == htons(ETH_P_ARP))
    {
        struct arphdr *arp = arp_hdr(skb);
        struct arp_eth_body *body = (void *)arp + sizeof(struct arphdr);
        int i, ip = child_ip;
        LOG("INCOME: ARP for IP=%s", strAR_IP(body->ar_tip));
        for (i = 0; i < sizeof(body->ar_tip); i++)
        {
            if ((ip & 0xFF) != body->ar_tip[i])
                break;
            ip = ip >> 8;
        }
        if (i < sizeof(body->ar_tip))
            return RX_HANDLER_PASS;
    }
    else if (skb->protocol != htons(0xCC88))
    {
        return RX_HANDLER_PASS;
    }
    
    LOG("INCOME: PASS");
    struct priv *priv = netdev_priv(child);
    priv->stats.rx_packets++;
    priv->stats.rx_bytes += skb->len;
    skb->dev = child;
    return RX_HANDLER_ANOTHER;
}

static int open( struct net_device *dev ) {
   netif_start_queue( dev );
   LOG( "%s: device opened", dev->name );
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
    struct in_ifaddr *ifa = in_dev->ifa_list;
    if (ifa) 
    {
        struct priv *priv = netdev_priv(dev);
        priv->stats.tx_packets++;
        priv->stats.tx_bytes += skb->len;
        LOG("GET IP %d, %s", get_ip(skb), strIP(get_ip(skb)));
        struct net_device *device = find_device_sub(priv->next, get_ip(skb));
        if (device)
        {
            skb->dev = device;
            skb->priority = 1;
            dev_queue_xmit(skb);
            LOG("OUTPUT: injecting frame from %s to %s. Target IP: %s", dev->name, skb->dev->name, strIP(get_ip(skb)));
            return NETDEV_TX_OK;
        }
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
    for (j = 0; j < ETH_ALEN; ++j) // Заполнить MAC адрес
    {
        dev->dev_addr[j] = (char)j;
    }
}

int __init init(void)
{
    int err = 0;
    struct priv *priv;
    char ifstr[40];
    sprintf(ifstr, "%s%s", ifname, "%d");

    child = alloc_netdev(sizeof(struct priv), ifstr, NET_NAME_UNKNOWN, setup);
    if (child == NULL)
    {
        ERR("%s: allocate error", THIS_MODULE->name);
        return -ENOMEM;
    }
    priv = netdev_priv(child);
    struct net_device *device = __dev_get_by_name(&init_net, link); // parent interface
    if (!device)
    {
        ERR("%s: no such net: %s", THIS_MODULE->name, link);
        err = -ENODEV;
        free_netdev(child);
        return err;
    } else if (device->type != ARPHRD_ETHER && device->type != ARPHRD_LOOPBACK)
    {
        ERR("%s: illegal net type", THIS_MODULE->name);
        err = -EINVAL;
        free_netdev(child);
        return err;
    }

    struct interfaces *second = kmalloc(sizeof(struct interfaces), GFP_KERNEL);
    second->address = charToIP(0, 0, (char)0, (char)0);
    second->mask = charToIP(0, 0, (char)0, (char)0);
    second->device = device;
    second->next = NULL;

    struct interfaces *first = kmalloc(sizeof(struct interfaces), GFP_KERNEL);
    first->address = charToIP(192, 168, (char)1, (char)0);
    first->mask = charToIP(255, 255, (char)255, (char)0);
    first->device = device;
    first->next = second;

    priv->next = first;
    memcpy(child->dev_addr, device->dev_addr, ETH_ALEN);
    memcpy(child->broadcast, device->broadcast, ETH_ALEN);
    if ((err = dev_alloc_name(child, child->name)))
    {
        ERR("%s: allocate name, error %i", THIS_MODULE->name, err);
        err = -EIO;
        free_netdev(child);
        return err;
    }
    register_netdev(child);
    rtnl_lock();
    netdev_rx_handler_register(device, &handle_frame, NULL);
    rtnl_unlock();
    LOG("module %s loaded", THIS_MODULE->name);
    LOG("%s: create link %s", THIS_MODULE->name, child->name);
    LOG("%s: registered rx handler for %s", THIS_MODULE->name, priv->next->device->name);
    return 0;
}

void __exit exit(void)
{
    struct priv *priv = netdev_priv(child);
    struct interfaces *next = priv->next;
    while (next)
    {
        rtnl_lock();
        netdev_rx_handler_unregister(next->device);
        rtnl_unlock();
        LOG("unregister rx handler for %s\n", next->device->name);
        next = next->next;
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