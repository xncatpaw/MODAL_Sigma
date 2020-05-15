# MODAL_Sigma
This is the project of MODAL INF473XHACKING of École Polytechnique. 

In this project, I defined the necessary functions for TCP-SYN-FLOODING attack and L2-FLOODING attack which is used to do the kill-switch-kill operation.

The DNS-Hijacking, DHCP-Spoofing functions will be added then.

And, the current structure of project is not so well-defined. I will update it then (if I still have the will..).


## Tools built:
### tcp_syn_flooding

This is the tool to execute the TCP-SYN-FLOODING attack. 

-How to build? \
`$> make tcp_syn_flooding`

-How to use?   
`$> sudo ./tcp_syn_flooding dst_ip dst_port [num_repeat [PRINT]]`\
e.g.: `$> sudo ./tcp_syn_flooding 127.0.0.1 8080 50 PRINT`\
This command allows you to attack yourself by the port 8080 (if it is listened to).

### l2_flooding

This is the tool to execute the Switch-Kill-Switch attack.

-How to build? \
`$> make l2_flooding`

-How to use?   
`$> sudo ./l2_flooding [num_repeat [PRINT]]`


### dns_hijack

This is the tool to execute the DNS-Hijacking attack, by taking place the UDP answer.

-How to build? \
`$> make dns_hijack`

-How to use?   
`$> sudo ./dns_hijack [pattern_file [PRINT]]`
Where pattern_file is a pre-defined host file. For example, if you'd like to re-direct the IP of facebook to moodle, you shall add this line to the file: \
`129.104.30.30 www.facebook.com.`\
Remark: donot forget the '.' at the end of host name, since we have not added pattern match function yet.

## REMARK:
Some part of the codes are built by the teacher team of MODAL INF473X, and those files are marked at their begining by comment.