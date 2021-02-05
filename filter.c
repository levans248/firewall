#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops filterHook;

// prints out dropped packet to and ip
void dropPacketTo(const struct iphdr *iph) {
    printk(KERN_INFO "Dropping packet TO %d.%d.%d.%d\n",
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);

    return NF_DROP;
}

// prints out dropped from and ip
void dropPacketFrom(const struct iphdr *iph) {
    printk(KERN_INFO "Dropping packet FROM %d.%d.%d.%d\n",
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);

    return NF_DROP;
}

unsigned int filter(unsigned int hooknum, struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out,
    int (*okfn)(struct sk_buff *)) {

    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *) iph + (iph->ihl * 4);

    // prevent telnet to other machines
    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23)) {
        dropPacketTo(iph);
    } 
    // prevent telnet from other machines
    else if (iph->protocol == IPPROTO_TCP && tcph->source == htons(23)) {
        dropPacketFrom(iph);
    }
    // prevent visting http websites
    else if (tcph->dest == htons(80)) {
        dropPacketTo(iph);
    }
    // prevent visiting https websites
    else if (tcph->dest == htons(443)) {
        dropPacketTo(iph);
    }
    // prevent ICMP
    else if (iph->protocol == IPPROTO_ICMP) {
        dropPacketFrom(iph);
    }
    // allow all other packet types
    else {
        return NF_ACCEPT;
    }
}

int setUpFilter(void) {
    printk(KERN_INFO "Registering a filter.\n");
    filterHook.hook = (unsigned int) filter;
    filterHook.hooknum = NF_INET_POST_ROUTING;
    filterHook.pf = PF_INET;
    filterHook.priority = NF_IP_PRI_FIRST;

    // register the hook
    nf_register_hook(&filterHook);

    return 0;
}

void removeFilter(void) {
    printk(KERN_INFO "Filter is being removed.\n");
    nf_unregister_hook(&filterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");