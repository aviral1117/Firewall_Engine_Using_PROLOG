/*Supressing 'clause not together' 'WARNING' */
:- style_check(-discontiguous).
/*end*/

/* Rules Database : Constraints as stated by a user (Latest Rule has highest priority)
    a. The following line includes the database for the engine into the prolog knowledge base. */

:- include('Database').

/*
    b. To add rule constraints here itself do the following :
        1. Comment the above 'include' command.
        2. Add your rule just after this block ends.

end*/

/* Sample rule syntax if part 'b' above is to be executed :
    action(1,drop).
    local_ip(1, [172,168,17,0]).
    remote_ip(1, [192,16,10,0],[192,16,10,16]).
    proto(1,6).
    tcp_local_port(1,5540,5545).
    udp_remote_port(1,80).
    ether(1,any).
    vlan(1,3,99).
    adapter(1,'A').
*/

/* Suppressing 'predicate not defined' 'ERROR' */

/* Arity : 2 Predicates */
    action(0,_).
    local_ip(0, _).
    remote_ip(0,_).
    adapter(0,_).
    proto(0,_).
    tcp_local_port(0,_).
    udp_local_port(0,_).
    tcp_remote_port(0,_).
    udp_remote_port(0,_).
    ether(0,_).
    vlan(0,_).
    icmp_type(0,_).
    icmp_code(0,_).

/* Arity : 3 Predicates */
    local_ip(0,_,_).
    remote_ip(0,_,_).
    adapter(0,_,_).
    proto(0,_,_).
    tcp_local_port(0,_,_).
    udp_local_port(0,_,_).
    tcp_remote_port(0,_,_).
    udp_remote_port(0,_,_).
    ether(0,_,_).
    vlan(0,_,_).
    icmp_type(0,_,_).
    icmp_code(0,_,_).
/*end*/

/* adapter_decoder predicate is used to map letters to numbers*/
adapter_decoder('A',1).
adapter_decoder('B',2).
adapter_decoder('C',3).
adapter_decoder('D',4).
adapter_decoder('E',5).
adapter_decoder('F',6).
adapter_decoder('G',7).
adapter_decoder('H',8).
adapter_decoder('I',9).
adapter_decoder('J',10).
adapter_decoder('K',11).
adapter_decoder('L',12).
adapter_decoder('M',13).
adapter_decoder('N',14).
adapter_decoder('O',15).
adapter_decoder('P',16).
/*end*/

/*member predicate is used to check membership relation for a list*/
member(X, [X|_]).
member(X, [_|T]):- member(X, T).
/*end*/

/*checking whether the input ip address is within the specified range*/
is_ip_in_range(T0,[A1,B1,C1,D1],[A2,B2,C2,D2]):- T0 = [I1,I2,I3,I4],
                                                 A2*2**24+B2*2**16+C2*2**8+D2>=I1*2**24+I2*2**16+I3*2**8+I4,
                                                 A1*2**24 + B1*2**16 +C1*2**8 + D1=<I1*2**24+I2*2**16+I3*2**8+I4.
/*end*/

/*Validating IP address*/
is_ip_valid(IP) :- IP = [K1,K2,K3,K4],
                              is_num_in_range(K1,0,255),
                              is_num_in_range(K2,0,255),
                              is_num_in_range(K3,0,255),
                              is_num_in_range(K4,0,255).

/*checking whether the given ip address is within the specified ip address block*/
is_ip_in_subnet_block(T1 ,[A,B,C,D,E]):- T1 = [J1,J2,J3,J4],
                                 J1*2**24 +J2*2**16 +J3*2**8 + J4>=A*2**24 + B*2**16 +C*2**8 + D,
                                 J1*2**24 + J2*2**16 +J3*2**8 + J4<A*2**24 + B*2**16 +C*2**8 + D + 2**(32-E).
/*end*/

/*checking whether the input adapter is within the specified range using adapter_decoder predicate*/
is_adapter_in_range(T2,L,H):- adapter_decoder(T2,Code1), adapter_decoder(L,Code2),adapter_decoder(H,Code3),Code2=<Code1, Code3>=Code1.
/*end*/

/*checking whether the input is within the specified range*/
is_num_in_range(T3,L,H):- T3>=L, T3=<H.
/*end*/

/*deciding message to be displayed if the incoming packet is encapsulating icmp protocol*/
icmp_response(Local_port,Message):- (Local_port=:=0,Message='reject: Echo reply');
(Local_port=:=3,Message='reject: Destination unreachable');
(Local_port=:=4,Message='reject: Source quench');
(Local_port=:=5,Message='reject: Redirect');
(Local_port=:=8,Message='reject: Echo');
(Local_port=:=9,Message='reject: Router Advertisement');
(Local_port=:=10,Message='reject: Router Selection');
(Local_port=:=11,Message='reject: Time exceeded');
(Local_port=:=12,Message='reject: Parameter problem');
(Local_port=:=13,Message='reject: Timestamp');
(Local_port=:=14,Message='reject: Timestamp reply');
(Local_port=:=15,Message='reject: Information request');
(Local_port=:=16,Message='reject: Information reply');
(Local_port=:=17,Message='reject: Address mask request');
(Local_port=:=18,Message='reject: Address mask reply');
(Local_port=:=30,Message='reject: Traceroute').
/*end*/

/*deciding action to be taken for the incoming packet*/
message(Type,Message,Proto,Local_port):- (Type=accept,Message= 'packet accepted');
(Type=drop,Message= 'packet dropped');
(Type=reject,Proto=:=1,icmp_response(Local_port,Message);
(Type=reject,Message= 'reject: packet rejected')).
/*end*/

/* Evaluating rule constraints on Incoming Packet */
local_ip_check(Arule, Local_ip):-
                           local_ip(Arule, any);
                           local_ip(Arule, Local_ip);
                          (local_ip(Arule, Local_ip_list),member(Local_ip, Local_ip_list));
                          (local_ip(Arule, [LA1,LB1,LC1,LD1], [LA2,LB2,LC2,LD2]),is_ip_in_range(Local_ip,[LA1,LB1,LC1,LD1], [LA2,LB2,LC2,LD2]));
                          (local_ip(Arule, [LA,LB,LC,LD,LE]), is_ip_in_subnet_block(Local_ip, [LA,LB,LC,LD,LE]));
                          (\+local_ip(Arule,_),\+local_ip(Arule,_,_)).

remote_ip_check(Arule, Remote_ip):-
                            remote_ip(Arule, any);
                            remote_ip(Arule, Remote_ip);
                            (remote_ip(Arule, Remote_ip_list),member(Remote_ip, Remote_ip_list));
                            (remote_ip(Arule, [RA1,RB1,RC1,RD1], [RA2,RB2,RC2,RD2]),is_ip_in_range(Remote_ip,[RA1,RB1,RC1,RD1], [RA2,RB2,RC2,RD2]));
                            (remote_ip(Arule, [RA,RB,RC,RD,RE]), is_ip_in_subnet_block(Remote_ip, [RA,RB,RC,RD,RE]));
                            (\+remote_ip(Arule,_),\+remote_ip(Arule,_,_)).

adapter_check(Arule, Adapter):-
                         adapter(Arule, any);
                         adapter(Arule, Adapter);
                         (adapter(Arule, Adapter_list), member(Adapter,Adapter_list));
                         (adapter(Arule,AL,AH),is_adapter_in_range(Adapter,AL,AH));
                         (\+adapter(Arule,_),\+adapter(Arule,_,_)).

proto_check(Arule, Proto):-
                            proto(Arule, any);
                            proto(Arule,Proto);
                           (proto(Arule, Proto_list), member(Proto,Proto_list));
                           (proto(Arule,PL,PH),is_num_in_range(Proto,PL,PH));
                           (\+proto(Arule,_),\+proto(Arule,_,_)).

tcp_local_port_check(Arule, Local_port):-
                                  tcp_local_port(Arule, any);
                                  tcp_local_port(Arule,Local_port);
                                  (tcp_local_port(Arule, Tcp_local_port_list), member(Local_port,Tcp_local_port_list));
                                  (tcp_local_port(Arule,TLL,TLH),is_num_in_range(Local_port,TLL,TLH));
                                  (\+tcp_local_port(Arule,_),\+tcp_local_port(Arule,_,_)).

udp_local_port_check(Arule, Local_port):-
                                  udp_local_port(Arule, any);
                                  udp_local_port(Arule,Local_port);
                                  (udp_local_port(Arule, Udp_local_port_list), member(Local_port,Udp_local_port_list));
                                  (udp_local_port(Arule,ULL,ULH),is_num_in_range(Local_port,ULL,ULH));
                                  (\+udp_local_port(Arule,_),\+udp_local_port(Arule,_,_)).

icmp_type_check(Arule, Local_port):-
                                  icmp_type(Arule, any);
                                  icmp_type(Arule,Local_port);
                                  (icmp_type(Arule, Icmp_type_list), member(Local_port,Icmp_type_list));
                                  (icmp_type(Arule,IL,IH),is_num_in_range(Local_port,IL,IH));
                                  (\+icmp_type(Arule,_),\+icmp_type(Arule,_,_)).

tcp_remote_port_check(Arule, Remote_port):-
                                  tcp_remote_port(Arule, any);
                                  tcp_remote_port(Arule,Remote_port);
                                  (tcp_remote_port(Arule, Tcp_remote_port_list), member(Remote_port,Tcp_remote_port_list));
                                  (tcp_remote_port(Arule,TRL,TRH),is_num_in_range(Remote_port,TRL,TRH));
                                  (\+tcp_remote_port(Arule,_),\+tcp_remote_port(Arule,_,_)).

udp_remote_port_check(Arule, Remote_port):-
                                  udp_remote_port(Arule, any);
                                  udp_remote_port(Arule,Remote_port);
                                  (udp_remote_port(Arule, Udp_remote_port_list), member(Remote_port,Udp_remote_port_list));
                                  (udp_remote_port(Arule,URL,URH),is_num_in_range(Remote_port,URL,URH));
                                  (\+udp_remote_port(Arule,_),\+udp_remote_port(Arule,_,_)).

icmp_code_check(Arule, Remote_port):-
                                 icmp_code(Arule, any);
                                 icmp_code(Arule,Remote_port);
                                 (icmp_code(Arule, Icmp_code_list), member(Remote_port,Icmp_code_list));
                                 (icmp_code(Arule,CL,CH),is_num_in_range(Remote_port,CL,CH));
                                 (\+icmp_code(Arule,_),\+icmp_code(Arule,_,_)).


ether_check(Arule, Ether):-
                                  ether(Arule, any);
                                  ether(Arule,Ether);
                                  (ether(Arule, Ether_list), member(Ether,Ether_list));
                                  (ether(Arule,EL,EH),is_num_in_range(Ether,EL,EH));
                                  (\+ether(Arule,_),\+ether(Arule,_,_)).

vlan_check(Arule, Vlan):-
                                  vlan(Arule, any);
                                  vlan(Arule,Vlan);
                                  (vlan(Arule, Vlan_list), member(Vlan,Vlan_list));
                                  (vlan(Arule,VL,VH),is_num_in_range(Vlan,VL,VH));
                                  (\+vlan(Arule,_),\+vlan(Arule,_,_)).
/*end*/


/*rule_checker decides the action to taken for a particular incoming packet based the rule it matched*/
rule_checker(Local_ip, Remote_ip, Proto, Local_port, Remote_port, Ether, Vlan, Adapter, Message):-
                                                                                  action(Rule,Type),Rule>0,
                                                                                  local_ip_check(Rule, Local_ip),
                                                                                  remote_ip_check(Rule, Remote_ip),
                                                                                  adapter_check(Rule, Adapter),
                                                                                  proto_check(Rule, Proto),
                                                                                 ((Proto=:=6,tcp_local_port_check(Rule, Local_port));
                                                                                 (Proto=:=17,udp_local_port_check(Rule, Local_port));
                                                                                 (Proto=:=1,icmp_type_check(Rule, Local_port));
                                                                                 \+member(Proto,[1,6,17])),
                                                                                 ((Proto=:=6,tcp_remote_port_check(Rule, Remote_port));
                                                                                 (Proto=:=17,udp_remote_port_check(Rule, Remote_port));
                                                                                 (Proto=:=1, icmp_code_check(Rule, Remote_port));
                                                                                 \+member(Proto,[1,6,17])),
                                                                                 ether_check(Rule, Ether),
                                                                                 vlan_check(Rule, Vlan),
                                                                                 message(Type,Message,Proto,Local_port).
/*end*/


/* Validating Incoming Packet information*/
packet(Local_ip, Remote_ip, Proto, Local_port, Remote_port, Ether, Vlan, Adapter):-
   (\+is_ip_valid(Local_ip);
    \+is_ip_valid(Remote_ip);
   \+is_num_in_range(Proto,0,255);
   ((Proto=:=6;Proto=:=17),\+is_num_in_range(Local_port,0,65535));
   (Proto=:=1,\+is_num_in_range(Local_port,0,255));
   ((Proto=:=6;Proto=:=17),\+is_num_in_range(Remote_port,0,65535));
   (Proto=:=1,\+is_num_in_range(Remote_port,0,255));
   \+is_num_in_range(Ether,0,65535);
   \+is_num_in_range(Vlan,0,4095);
   \+member(Adapter,['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P'])),
   write('Invalid packet : Please check the inputs').
/*end*/

/*calls rule_checker to evaluate which rule is applicable*/
packet(Local_ip, Remote_ip, Proto, Local_port, Remote_port, Ether, Vlan, Adapter) :-
                                     rule_checker(Local_ip, Remote_ip, Proto, Local_port, Remote_port, Ether, Vlan, Adapter,Message),write(Message).
/*end*/

/*default policy is to drop the packet if no rule is matched*/
packet(_,_,_,_,_,_,_,_):-  write('packet dropped').
/*end*/




