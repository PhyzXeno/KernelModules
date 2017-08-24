#ifndef __KERNEL__
    #define __KERNEL__
#endif
#ifndef MODULE
    #define MODULE
#endif
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops netfilter_ops_in;
static struct nf_hook_ops netfilter_ops_out;

// unsigned int main_hook(
//     unsigned int hooknum,
//     struct sk_buff **skb,
//     const struct net_device *in,
//     const struct net_device *out,
//     int (*okfn)(struct sk_buff*)
// )
// {
//     printk(KERN_INFO "Packet Dropped.");
//     return NF_DROP;
// }

/*
In the (IMHO) latest (released) netfilter version, nf_hookfn (the base type of nf_hook_ops.hook) is defined as follows:

typedef unsigned int nf_hookfn(void *priv,
                   struct sk_buff *skb,
                   const struct nf_hook_state *state);

Your function hook_func_incoming does not match this signature, you should adopt it.
*/

unsigned int main_hook(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state 
)
{
    printk(KERN_INFO "Packet Dropped.");
    return NF_DROP;
}

static int __init drop_init(void)
{
    netfilter_ops_in.hook               =               main_hook;
    netfilter_ops_in.pf                 =               PF_INET;
    netfilter_ops_in.hooknum            =               NF_INET_PRE_ROUTING;
    netfilter_ops_in.priority           =               NF_IP_PRI_FIRST;
    
    netfilter_ops_out.hook               =               main_hook;
    netfilter_ops_out.pf                 =               PF_INET;
    netfilter_ops_out.hooknum            =               NF_INET_POST_ROUTING;
    netfilter_ops_out.priority           =               NF_IP_PRI_FIRST;

    nf_register_hook(&netfilter_ops_in);
    nf_register_hook(&netfilter_ops_out);

    return 0;
}

static void __exit drop_exit(void)
{
    nf_unregister_hook(&netfilter_ops_in);
    nf_unregister_hook(&netfilter_ops_out);
}

module_init(drop_init);
module_exit(drop_exit);
