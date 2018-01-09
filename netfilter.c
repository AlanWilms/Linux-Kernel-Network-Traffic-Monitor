#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <stdbool.h>
#include <uapi/linux/string.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/inet.h>

static struct nf_hook_ops nfho_in;   // netfilter hook option struct for incoming traffic
static struct nf_hook_ops nfho_out;  // netfilter hook option struct for outgoing traffic

struct firewall_rule {
    char in_or_out; // incoming vs outgoing: 0 for incoming traffic, 1 for outgoing traffic
    char block_or_unblock; // filtering action: 0 for block, 1 for unblock
    char *src_ip; // source ip address
    char *dest_ip; // destination ip address
    // for the ip addresses, a value of 0 means not specified, used for all traffic
    struct list_head list; // how to implement lists in kernel modules
};

struct monitor {
    char *src_ip;
    int num_received;
    int num_dropped;
    struct list_head list;
};

// lists of addresses to monitor and rule
static struct firewall_rule runtime_policies;
static struct monitor monitor_list;

//Proc filesystem portion of module
int len, temp;
static char *msg = 0;

// forward declarations
void add_rule(struct firewall_rule* rule);
void add_monitor(char *str);
void delete_monitor(char *str);

static ssize_t read_proc (struct file *filp, char __user * buf, size_t count, loff_t * offp)
{
    if (count > temp)
    {
      count = temp;
    }
    temp = temp - count;
    copy_to_user (buf, msg, count);
    if (count == 0)
    temp = len;

    return count;
}

static ssize_t write_proc (struct file *filp, const char __user * buf, size_t count,
	    loff_t * offp)
{
    //clearing
    memset(msg, 0, 1000*sizeof(char));
    // you have to move data from user space to kernel buffer
    copy_from_user (msg, buf, count);
    len = count;
    temp = len;
    if (len == 1) {
        if (msg[0] == 'b') {
            // this blocks all incoming packets
            struct firewall_rule block_in;
            // printk(KERN_INFO "add a test rule: blocking all incoming\n");
            block_in.in_or_out = 0;
            block_in.src_ip = NULL; // everything
            block_in.dest_ip = NULL;
            block_in.block_or_unblock = 0; // block
            add_rule(&block_in);

            // this blocks all outgoing packets
            struct firewall_rule block_out;
            // printk(KERN_INFO "add a test rule: blocking all incoming\n");
            block_out.in_or_out = 1;
            block_out.src_ip = NULL; // everything
            block_out.dest_ip = NULL; // everything
            block_out.block_or_unblock = 0; // block
            add_rule(&block_out);
        }
        else if (msg[0] == 'u'){
            // this unblocks all incoming packets
            struct firewall_rule unblock_in;
            unblock_in.in_or_out = 0;
            unblock_in.src_ip = NULL; // everything
            unblock_in.dest_ip = NULL;
            unblock_in.block_or_unblock = 1; // block
            add_rule(&unblock_in);

            // this unblocks all outgoing packets
            struct firewall_rule unblock_out;
            unblock_out.in_or_out = 1;
            unblock_out.src_ip = NULL; // everything
            unblock_out.dest_ip = NULL; // everything
            unblock_out.block_or_unblock = 1; // unblock
            add_rule(&unblock_out);
        }
    }
    else {
        if (*msg == 'b'){
            ++msg;
            // this blocks all incoming packets from a specific address
            struct firewall_rule b1;
            b1.in_or_out = 0;
            b1.src_ip = (char *)kmalloc(16, GFP_KERNEL);
            strcpy(b1.src_ip, msg);
            b1.dest_ip = NULL; // everything
            b1.block_or_unblock = 0; // block
            add_rule(&b1);

            // this blocks all outgoing packets from a specific address
            struct firewall_rule b2;
            b2.in_or_out = 1;
            b2.dest_ip = (char *)kmalloc(16, GFP_KERNEL);
            strcpy(b2.dest_ip, msg);
            b2.src_ip = NULL; // everything
            b2.block_or_unblock = 0; // unblock
            add_rule(&b2);
            --msg;
        }
        else if (*msg == 'u'){
            ++msg;
            // this unblocks all incoming packets from a specific address
            struct firewall_rule b1;
            b1.in_or_out = 0;
            b1.src_ip = (char *)kmalloc(16, GFP_KERNEL);
            strcpy(b1.src_ip, msg);
            b1.dest_ip = NULL; // everything
            b1.block_or_unblock = 1; // block
            add_rule(&b1);

            // this unblocks all outgoing packets from a specific address
            struct firewall_rule b2;
            b2.in_or_out = 1;
            b2.dest_ip = (char *)kmalloc(16, GFP_KERNEL);
            strcpy(b2.dest_ip, msg);
            b2.src_ip = NULL; // everything
            b2.block_or_unblock = 1; // unblock
            add_rule(&b2);
            --msg;
        }
        else if (*msg == 'm'){
            ++msg;
            add_monitor(msg);
            --msg;
        }
        else if (*msg == 'n'){
            ++msg;
            delete_monitor(msg);
            --msg;
        }
        else{
          //print status (to user space)
            strcpy(msg, "Monitoring List: \n");
            struct list_head *pos;
            struct monitor *m;

            list_for_each(pos, &monitor_list.list) {
                char buffer[60];
                m = list_entry(pos, struct monitor, list);
                snprintf(buffer, 60, "IP address: %s, Received: %d, Dropped: %d\n", m->src_ip, m->num_received, m->num_dropped);
                printk("%s\n", buffer);
                strcat(msg, buffer);
            }
            printk("%s\n", msg);
        }
    }
    return count;
}

static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read = read_proc,
    .write = write_proc,
};

void create_new_proc_entry (void)
{
    proc_create ("firewall_rules", 0, NULL, &proc_fops);
    msg = kmalloc (1000 * sizeof (char), GFP_KERNEL);
    if (msg == 0)
    {
      printk (KERN_INFO "why is msg 0 \n");
    }
}
//End of proc portion

// helper function to compare ip addresses (one from packet, other from rule)
bool ip_comparison(const char *ip_from_rule, unsigned int ip_from_packet) {
    printk(KERN_INFO "ip_comparison called\n");

    char *str = (char *)kmalloc(16, GFP_KERNEL);

    unsigned char ip_array[4];
    memset(ip_array, 0, 4);

    // htonl changes byte order
    ip_array[0] = (ip_array[0] | (htonl(ip_from_packet) >> 24));
    ip_array[1] = (ip_array[1] | (htonl(ip_from_packet) >> 16));
    ip_array[2] = (ip_array[2] | (htonl(ip_from_packet) >> 8));
    ip_array[3] = (ip_array[3] | htonl(ip_from_packet));

    sprintf(str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2], ip_array[3]);

    //  snprintf(str, 16, "%pI4", ip_from_packet);
    printk("ip from int: %u\n", ip_from_packet);
    printk("ip from packet: %s\n", str);
    printk("ip from rule: %s\n", ip_from_rule);
    return (!strcmp(ip_from_rule, str)); // returns true if equal, otherwise returns false
}

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct list_head *p;
    struct firewall_rule *rule;

    int i = 0;
    // obtain source and destination ip addresses
    unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned int dest_ip = (unsigned int)ip_header->daddr;

    list_for_each(p, &runtime_policies.list) {
        i++; // current rule number
        rule = list_entry(p, struct firewall_rule, list);

        printk(KERN_INFO "rule %d: in_or_out = %u; src_ip = %s; dest_ip = %s; block_or_unblock = %u\n", i, rule->in_or_out, rule->src_ip, rule->dest_ip, rule->block_or_unblock);

        if (rule->in_or_out != 1) { // check if rule is for outgoing traffic
            printk(KERN_INFO "rule %d (rule->in_or_out: %u) not applicable: out packet but rule not out\n", i, rule->in_or_out);
            continue;
        } else {
            // src ip specified in rule (non-zero) and doesn't match
            if (rule->src_ip != 0 && !ip_comparison(rule->src_ip, src_ip)) {
                printk(KERN_INFO "rule %d not applicable: src ip mismatch\n", i);
                continue;
            }
            // dest ip specified in rule (non-zero) and doesn't match
            if (rule->dest_ip != 0 && !ip_comparison(rule->dest_ip, dest_ip)) {
                printk(KERN_INFO "rule %d not applicable: dest ip mismatch\n", i);
                continue;
            }
            //a match is found: block or unblock depending on block_or_unblock
            if (rule->block_or_unblock == 0) {
                printk(KERN_INFO "***rule %d matched: drop the packet\n", i);
                return NF_DROP;
            } else {
                printk(KERN_INFO "***rule %d matched: accept the packet\n", i);
                return NF_ACCEPT;
            }
        }
    }
    printk(KERN_INFO "***no rule matched: accept the packet\n");
    return NF_ACCEPT;
}

unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct list_head *p;
    struct firewall_rule *rule;

    int i = 0;
    // obtain source and destination ip addresses
    unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned int dest_ip = (unsigned int)ip_header->daddr;

    bool is_monitored = false;

    struct list_head *pos;
    struct monitor *m;

    list_for_each(pos, &monitor_list.list) {
        m = list_entry(pos, struct monitor, list);
        printk(KERN_INFO "IP address: %s, Received: %d, Dropped: %d\n", m->src_ip, m->num_received, m->num_dropped);
        if (ip_comparison(m->src_ip, src_ip)) {
            is_monitored = true;
            break;
        }
    } // m points monitor struct

    list_for_each(p, &runtime_policies.list) {
        i++; // current rule number
        rule = list_entry(p, struct firewall_rule, list);

        printk(KERN_INFO "rule %d: in_or_out = %u; src_ip = %s; dest_ip = %s; block_or_unblock = %u\n", i, rule->in_or_out, rule->src_ip, rule->dest_ip, rule->block_or_unblock);

        if (rule->in_or_out != 0) { // check if rule is for incoming traffic
            printk(KERN_INFO "rule %d (rule->in_or_out: %u) not applicable: in packet but rule not in\n", i, rule->in_or_out);
            continue;
        } else {
            // src ip specified in rule (non-zero) and doesn't match
            if (rule->src_ip != 0 && !ip_comparison(rule->src_ip, src_ip)) {
                printk(KERN_INFO "rule %d not applicable: src ip mismatch\n", i);
                continue;
            }
            // dest ip specified in rule (non-zero) and doesn't match
            if (rule->dest_ip != 0 && !ip_comparison(rule->dest_ip, dest_ip)) {
                printk(KERN_INFO "rule %d not applicable: dest ip mismatch\n", i);
                continue;
            }
            //a match is found: block or unblock depending on block_or_unblock
            if (rule->block_or_unblock == 0) {
                printk(KERN_INFO "***rule %d matched: drop the packet\n", i);
                if (is_monitored)
                    ++(m->num_dropped);
                return NF_DROP;
            } else {
                printk(KERN_INFO "***rule %d matched: accept the packet\n", i);
                if (is_monitored)
                    ++(m->num_received);
                return NF_ACCEPT;
            }
        }
    }
    printk(KERN_INFO "***no rule matched: accept the packet\n");
    if (is_monitored)
        ++(m->num_received);
    return NF_ACCEPT;
}

void add_rule(struct firewall_rule* rule) {
    struct firewall_rule* new_rule;
    new_rule = kmalloc(sizeof(*new_rule), GFP_KERNEL);

    if (new_rule != NULL) {
        new_rule->in_or_out = rule->in_or_out;
        new_rule->src_ip = rule->src_ip;
        new_rule->dest_ip = rule->dest_ip;
        new_rule->block_or_unblock = rule->block_or_unblock;
        printk(KERN_INFO "added a rule: in_or_out = %u, src_ip = %s, dest_ip = %s, block_or_unblock = %u\n",
                rule->in_or_out, rule->src_ip, rule->dest_ip, rule->block_or_unblock);
        INIT_LIST_HEAD(&(new_rule->list));
        list_add(&(new_rule->list), &(runtime_policies.list));
        // this adds it to the front, so that most recent rules get checked that first
        // this allows unblocking from blocking
    } else // dynamic memory allocation in the kernel failed
        printk(KERN_INFO "error: kernel memory allocation failed for new rule\n");
}

void add_monitor(char *str) {
    struct monitor* new_monitor;
    new_monitor = kmalloc(sizeof(*new_monitor), GFP_KERNEL);
    printk(KERN_INFO "added a new monitor: ip = %s" , str);

    if (new_monitor != NULL) {
        new_monitor->src_ip = (char *)kmalloc(16, GFP_KERNEL);
        strcpy(new_monitor->src_ip, str);
        new_monitor->num_received = 0;
        new_monitor->num_dropped = 0;
        INIT_LIST_HEAD(&(new_monitor->list));
        list_add(&(new_monitor->list), &(monitor_list.list));
    } else
        printk(KERN_INFO "error: kernel memory allocation failed for new monitor\n");
}

void delete_monitor(char *str) {
    struct list_head *pos, *n;
    struct monitor *m;

    list_for_each_safe(pos, n, &monitor_list.list) {
        m = list_entry(pos, struct monitor, list);
        if (!strcmp(m->src_ip, str)) { // they are equal
            list_del(pos);
            kfree(m);
            break;
        }
    }
    printk(KERN_INFO "unmonitored %s\n", str);
}

int init_module()
{
    printk(KERN_INFO "loading netfilter kernel module\n");
    INIT_LIST_HEAD(&(runtime_policies.list));
    INIT_LIST_HEAD(&(monitor_list.list));

    // hook structure for incoming packets
    nfho_in.hook = hook_func_in;
    nfho_in.hooknum = NF_INET_LOCAL_IN;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_in);     // Register the hook

    // hook structure for outgoing packets
    nfho_out.hook = hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_out);    // Register the hook
    
    create_new_proc_entry ();

    return 0;
}

void cleanup_module()
{
    nf_unregister_hook(&nfho_in);
    nf_unregister_hook(&nfho_out);

    struct list_head *pos, *n;
    struct firewall_rule *rule;

    // freeing runtime policies list
    list_for_each_safe(pos, n, &runtime_policies.list) {
        printk(KERN_INFO "freeing rule\n");
        rule = list_entry(pos, struct firewall_rule, list);
        list_del(pos);
        kfree(rule);
    }

    // freeing monitor list
    struct list_head *pos2, *n2;
    struct monitor *m;
    list_for_each_safe(pos2, n2, &runtime_policies.list) {
        printk(KERN_INFO "freeing rule\n");
        m = list_entry(pos2, struct monitor, list);
        list_del(pos2);
        kfree(m);
    }
    remove_proc_entry ("firewall_rules", NULL);
    printk(KERN_INFO "netfilter kernel module unloaded\n");
}
