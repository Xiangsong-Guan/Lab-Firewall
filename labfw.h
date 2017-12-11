#ifndef LAB_FW_H
#define LAB_FW_H

/* some version info */
#define MAJOR_VERSION "0"
#define MINOR_VERSION "1"
#define VERSION MAJOR_VERSION "." MINOR_VERSION

/* limit of rules numbers and rule's length */
#define MAX_RULE_LEN 16

/* some const for proc file control */
#define PROCF_NAME "lab-fw"
#define PROCF_MAX_SIZE 64

/* according to linux kernel's defination, we only concern about tcp and udp */
enum lab_fw_protocols { LAB_FW_UDP = 17, LAB_FW_TCP = 6 };

/* the rule for deny, we default accpet all packet, only drop when a rule
 * is speciafied. */
struct deny {
  char ifs[MAX_RULE_LEN];     /* the packet come-in-interface's name 10 */
  unsigned int ip;            /* source ip address in version 4 15 */
  unsigned int dport;         /* destination port 5 */
  enum lab_fw_protocols prtc; /* trans-layer protocols 3 */
  struct deny *next;          /* linked list */
};

/* for debug */
#define DEBUG

#endif /* LAB_FW_H */