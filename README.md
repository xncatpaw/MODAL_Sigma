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
`$> sudo tcp_syn_flooding dst_ip dst_port [[num_repeat] PRINT]`\
e.g.: `$> sudo tcp_syn_flooding 127.0.0.1 8080 50 PRINT`\
This command allows you to attack yourself by the port 8080.
### l2_flooding