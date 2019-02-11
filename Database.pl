/* The order in which the constraints will be stated below : is the same order they will be checked*/
action(5,drop).
action(4,accept).
action(3,reject).
action(2,drop).
action(1,accept).

/*local ip constraints database*/
local_ip(1, [172,168,17,0]).
local_ip(2, [172,168,17,0,24]).
local_ip(5, any).

/*remote ip constraints*/
remote_ip(1, [192,16,10,0],[192,16,10,16]).
remote_ip(3,[[192, 16, 10, 4],[192, 16, 10, 7],[192, 16, 10, 8]] ).
remote_ip(4,[[192, 16, 10, 4],[192, 16, 10, 7],[192, 16, 10, 8]] ).

/*protocol constraints*/
proto(1,6).
proto(2,17).
proto(3,1).
proto(4,1).
proto(5,[6,17]).

/*Destination Conditions*/
tcp_local_port(1,5540,5545).
icmp_type(3,3).
icmp_type(4,3).
tcp_local_port(5,any).
udp_local_port(5,any).

/*Source conditions*/
udp_remote_port(2,80).
icmp_code(4,1,5).
tcp_remote_port(5,[20,21]).
udp_remote_port(5,[20,21]).

/*EtherType constraints*/
ether(1,any).
ether(2,2048).
ether(4,any).

/*vlan constraints*/
vlan(1,3,99).
vlan(2,[3,5]).
vlan(3,7).
vlan(4,7).
vlan(5,any).

/* adapter constraints*/
adapter(2,'A').
adapter(3,'A','C').
adapter(4,'A','C').
adapter(5,['A','D']).
