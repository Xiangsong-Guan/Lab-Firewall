#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "labfw.h"

MODULE_AUTHOR("Xiangsong-Guan");
MODULE_DESCRIPTION("Student's lab firewall " VERSION " for Linux 4.16.");
MODULE_LICENSE("GPL");

/* some uilt function for string to net struct */
static unsigned int port_str_to_int(char *port_str);
static void port_int_to_str(unsigned int port, char *port_str);
static unsigned int ip_str_to_hl(char *ip_str);
static void ip_hl_to_str(unsigned int ip, char *ip_str);

/* some prototype for denys linked list */
static int make_deny(char lines[4][MAX_RULE_LEN]);

/* some prototype for packet check */
static int juge(const struct net_device *in, struct sk_buff *skb,
                struct deny *d);
static int check_ip_packet(struct sk_buff *skb, unsigned int ipaddr);
static int check_trans_packet(struct sk_buff *skb, unsigned int dport,
                              enum lab_fw_protocols p);

/* prototype for file operation */
static ssize_t lab_fw_procf_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *ppos);
/* prototype for net hook */
static unsigned int lab_fw_hookfn(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state);

/* netfilter's hook options */
static const struct nf_hook_ops nfkiller = {
    .hook = lab_fw_hookfn,
    .hooknum = NF_INET_PRE_ROUTING, /* First stage hook */
    .pf = PF_INET,                  /* IPV4 protocol hook */
    .priority = NF_IP_PRI_FIRST     /* Hook to come first */
};
/* memory-in-kernel-space stored rules chain */
static struct deny *tail, *head = NULL;
/* proc file struct*/
static const struct file_operations lab_fw_proc_fops = {
    .owner = THIS_MODULE, .write = lab_fw_procf_write};
static struct proc_dir_entry *fw_proc_file;
static char *procf_buffer;

/******************************************************************************
 *                        firewall check function here                        *
 ******************************************************************************/
/* hook function, called when a packet is arrived. this packet will though
 * the deny-rules-chain */
static unsigned int lab_fw_hookfn(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state) {
  struct deny *adv;

  if (!skb) {
#ifdef DEBUG
    printk(PROCF_NAME ": null skb");
#endif
    return NF_ACCEPT;
  }

  adv = head;
  while (adv) {
    if (juge(state->in, skb, adv) == NF_DROP) {
      return NF_DROP;
    }
    adv = adv->next;
  }
  return NF_ACCEPT; /* We are happy to keep the packet */
}

/* jugement function, compare a packet and a deny rule. return verdict. */
static int juge(const struct net_device *in, struct sk_buff *skb,
                struct deny *r) {
#ifdef DEBUG
  printk(PROCF_NAME ": packet from %s", in->name);
#endif

  /* Check the interface deny first */
  if (r->ifs[0] != '-') {
    if (strcmp(in->name, r->ifs) != 0) {
      return NF_ACCEPT;
    }
  }

  /* Check the IP address deny */
  if (r->ip != 0 && NF_ACCEPT == check_ip_packet(skb, r->ip)) {
    return NF_ACCEPT;
  }

  /* Finally, check the tcp/udp port deny */
  return check_trans_packet(skb, r->dport, r->prtc);
}

/* Function that compares a received TCP packet's destination port
 * with the port specified in the Port Deny Rule. If a processing
 * error occurs, NF_ACCEPT will be returned so that the packet is
 * not lost. */
static int check_trans_packet(struct sk_buff *skb, unsigned int dport,
                              enum lab_fw_protocols p) {
  /* Seperately defined pointers to header structures are used
   * to access the TCP fields because it seems that the so-called
   * transport header from skb is the same as its network header TCP packets.
   * If you don't believe me then print the addresses of skb->nh.iph
   * and skb->h.th.
   * It would have been nicer if the network header only was IP and
   * the transport header was TCP but what can you do? */
  struct tcphdr *thead;
  struct udphdr *uhead;

  /* We don't want any NULL pointers in the chain to the TCP header. */
  struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
  if (!iph) {
#ifdef DEBUG
    printk(PROCF_NAME ": null iph");
#endif
    return NF_ACCEPT;
  }

  /* Be sure this is a its packet first */
  if (iph->protocol != p) {
    return NF_ACCEPT;
  }
  if (dport == 0) {
    return NF_DROP;
  }

  /* Now check the destination port */
  if (p == LAB_FW_TCP) {
    thead = (struct tcphdr *)(skb_transport_header(skb) + 20);
    if ((unsigned int)ntohs(thead->dest) == dport) {
      return NF_DROP;
    }
  } else {
    uhead = (struct udphdr *)(skb_transport_header(skb) + 20);
    if ((unsigned int)ntohs(uhead->dest) == dport) {
      return NF_DROP;
    }
  }

  return NF_ACCEPT;
}

/* Function that compares a received IPv4 packet's source address
 * with the address specified in the IP Deny Rule. If a processing
 * error occurs, NF_ACCEPT will be returned so that the packet is
 * not lost. */
static int check_ip_packet(struct sk_buff *skb, unsigned int ipaddr) {
  struct iphdr *iph = (struct iphdr *)skb_network_header(skb);

  if (!iph) {
    return NF_ACCEPT;
  }

  if (ntohl(iph->saddr) == ipaddr) { /* Matches the address. Barf. */
    return NF_DROP;
  }
  return NF_ACCEPT;
}

/******************************************************************************
 *                        deny linked list function here                      *
 ******************************************************************************/
/* deny rule generetor, return null if memory-request failed */
static int make_deny(char lines[4][MAX_RULE_LEN]) {
  int i;
  struct deny *new_one =
      (struct deny *)kmalloc(sizeof(struct deny), GFP_KERNEL);
  if (!new_one) {
    return -1;
  }

  for (i = 0; i < MAX_RULE_LEN; i = i + 1) {
    new_one->ifs[i] = lines[0][i];
  }

  if (lines[1][0] != '-') {
    new_one->ip = ip_str_to_hl(lines[1]);
  } else {
    new_one->ip = 0;
  }

  if (lines[2][0] != '-') {
    new_one->dport = port_str_to_int(lines[2]);
  } else {
    new_one->dport = 0;
  }

  if (lines[3][0] == 't') {
    new_one->prtc = LAB_FW_TCP;
  } else {
    new_one->prtc = LAB_FW_UDP;
  }

  new_one->next = NULL;
  if (head) {
    tail->next = new_one;
    tail = new_one;
  } else {
    head = new_one;
    tail = new_one;
  }

  return 0;
}

/* proc file control function */
static ssize_t lab_fw_procf_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *ppos) {
  int i, j;
  char lines[4][MAX_RULE_LEN]; /* magic */
  memset(lines, 0, 4 * MAX_RULE_LEN);

  /*read the write content into the storage buffer*/
  printk(PROCF_NAME ": count: %ld", count);
  if (count > PROCF_MAX_SIZE) {
    printk(PROCF_NAME ": not enough space for new deny");
    return -ENOSPC;
  }
  if (copy_from_user(procf_buffer, buffer, count)) {
    printk(PROCF_NAME ": memory copy failed");
    return -EFAULT;
  }

  i = 0;
  /* interface */
  j = 0;
  while (procf_buffer[i + j] != ' ' && (i + j) < count &&
         j < MAX_RULE_LEN - 1) {
    lines[0][j] = procf_buffer[i + j];
    j = j + 1;
  }
  printk(KERN_INFO "interface: %s", lines[0]);
  i = i + j + 1;

  /* ip */
  j = 0;
  while (procf_buffer[i + j] != ' ' && (i + j) < count &&
         j < MAX_RULE_LEN - 1) {
    lines[1][j] = procf_buffer[i + j];
    j = j + 1;
  }
  printk(KERN_INFO "ip: %s", lines[1]);
  i = i + j + 1;

  /* dport number */
  j = 0;
  while (procf_buffer[i + j] != ' ' && (i + j) < count &&
         j < MAX_RULE_LEN - 1) {
    lines[2][j] = procf_buffer[i + j];
    j = j + 1;
  }
  printk(KERN_INFO "dport: %s", lines[2]);
  i = i + j + 1;

  /* proto */
  j = 0;
  while (j < 3 && (j + i) < count && j < MAX_RULE_LEN - 1) { /* another magic */
    lines[3][j] = procf_buffer[i + j];
    j = j + 1;
  }
  printk(KERN_INFO "protocols: %s", lines[3]);

  if (0 != make_deny(lines)) {
    printk(PROCF_NAME ": no kernel memory");
    return -ENOMEM;
  }
  return count;
}

/******************************************************************************
 *                             module function here                           *
 ******************************************************************************/
/* module initial function */
static int __init lab_fw_init(void) {
  /* Now register the network hooks */
  nf_register_net_hook(&init_net, &nfkiller);

  /* creat proc file */
  fw_proc_file = proc_create(PROCF_NAME, 0200, NULL, &lab_fw_proc_fops);
  if (!fw_proc_file) {
    printk(PROCF_NAME ": Error: could not initialize /proc/", PROCF_NAME);
    return -EAGAIN;
  }
  procf_buffer = (char *)kmalloc(PROCF_MAX_SIZE);
  if (!procf_buffer) {
    printk(PROCF_NAME ": Error: could not initialize memory");
    return -ENOMEM;
  }

  printk(PROCF_NAME ": Network hooks successfully installed.\n");
  printk(PROCF_NAME ": Module installation successful.\n");
  return 0;
}
module_init(lab_fw_init);

/* module remove function */
static void __exit lab_fw_exit(void) {
  /* free memory in kernel here */
  struct deny *adv = head;
  struct deny *pre = head;
  while (adv) {
    adv = pre->next;
    kfree(pre);
    pre = adv;
  }
  /* remove proc file */
  remove_proc_entry(PROCF_NAME, NULL);
  kfree(procf_buffer);
  /* Remove IPV4 hook */
  nf_unregister_net_hook(&init_net, &nfkiller);
  printk(PROCF_NAME ": Removal of module successful.\n");
}
module_exit(lab_fw_exit);

/******************************************************************************
 *               net struct and string convert functions here                 *
 ******************************************************************************/
static unsigned int port_str_to_int(char *port_str) {
  unsigned int port = 0;
  int i = 0;
  if (port_str == NULL) {
    return 0;
  }
  while (port_str[i] != '\0') {
    port = port * 10 + (port_str[i] - '0');
    ++i;
  }
  return port;
}

static void port_int_to_str(unsigned int port, char *port_str) {
  sprintf(port_str, "%u", port);
}

/*convert from byte array to host long integer format*/
static unsigned int ip_str_to_hl(char *ip_str) {
  /* convert the string to byte array first, e.g.: from "131.132.162.25" to
   * [131][132][162][25]*/
  unsigned char ip_array[4];
  int i = 0;
  unsigned int ip = 0;
  if (ip_str == NULL) {
    return 0;
  }
  memset(ip_array, 0, 4);
  while (ip_str[i] != '.') {
    ip_array[0] = ip_array[0] * 10 + (ip_str[i++] - '0');
  }
  ++i;
  while (ip_str[i] != '.') {
    ip_array[1] = ip_array[1] * 10 + (ip_str[i++] - '0');
  }
  ++i;
  while (ip_str[i] != '.') {
    ip_array[2] = ip_array[2] * 10 + (ip_str[i++] - '0');
  }
  ++i;
  while (ip_str[i] != '\0') {
    ip_array[3] = ip_array[3] * 10 + (ip_str[i++] - '0');
  }

  ip = (ip_array[0] << 24);
  ip = (ip | (ip_array[1] << 16));
  ip = (ip | (ip_array[2] << 8));
  ip = (ip | ip_array[3]);
  return ip;
}

/*convert hl to byte array first*/
static void ip_hl_to_str(unsigned int ip, char *ip_str) {
  unsigned char ip_array[4];
  memset(ip_array, 0, 4);
  ip_array[0] = (ip_array[0] | (ip >> 24));
  ip_array[1] = (ip_array[1] | (ip >> 16));
  ip_array[2] = (ip_array[2] | (ip >> 8));
  ip_array[3] = (ip_array[3] | ip);
  sprintf(ip_str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2],
          ip_array[3]);
}