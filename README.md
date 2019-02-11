# Firewall Engine using Prolog
The following file gives a detailed description of the working and implementation of the project. 

- **f2016532_f2016601_Firewall_Engine.pl** : Contains the code for the firewall engine.
- **f2016532_f2016601_Database.pl** : Contains the firewall rules which acts as the database for the engine.
- **Sample_Test_Input.txt** : Contains sample inputs in the format described later in this file. And also the database initially fed to the engine using the Database.pl file.

## System Requirements
    The program should be run using swi-prolog and the input instructions should be followed as given further for successful working of the engine.

--------------------------------------------------------------------------------------------------
## Some points to take note before you proceed

- Creating a new query :It is assumed that the packet details are entered completely and no fields are left blank i.e. a packet is always assumed to be complete in its architecture. See details further in 'Query Format' section.

- The two prolog files should always be in the same directory. Else complete path for the database should be stated in the include predicate in Firewall_Engine file.

- New rules should always be added using the procedure as described under the 'Adding a new Rule ' section.

- The Ref_Number argument of the predicates given below acts as a reference to a particular rule which has been loaded in the prolog database. The higher the reference number the more latest the corressponding rule is.

- In case of multiple rule matching the rule with the highest reference number overrides other rules.

- Any numerical entry made for any argument should be made in decimal i.e. base 10 format only.

- If a rule contains no constraints with respect to a field except for 'Action' then it is advisable to fill the entry with 'any'. Nevertheless, not stating it will also work. 

- Unless specified , a packet that doesnot match any of the rules is 'dropped' i.e 'drop' is default policy.

- In case of ICMP protocol, local_port field recieves ICMP-type and remote_port field recieves ICMP-Code.

- For predicates listed under the 'Predicates and their description' -> 'Loading rules in the database' section :
    - Arity 2 predicates can take inputs in the form of a list or as a fix entry or 'any' for the corresponding predicate type.
    - Arity 3 predicates can take ranges as inputs with 2nd argument being the lower bound and 3rd argument being the upper bound(Both Inclusive). 

- Whenever an IP address is to be used always use comma separated list to encode it. For instance: 
    - Without subnet mask : 192.168.7.1 should be encoded as [192,168,7,1]. 
    - With subnet mask : 192.168.7.0/24 should be encoded as [192,168,7,0,24].

------------------------------------------------------------------------------------------------------

## Predicates and their Description

### Loading rules in the database

- **action**(Ref_Number, Type).
    - arity : 2
    - meaning : This predicate defines the action for the given rule Ref_Number.

- **local_ip**(Ref_Number,Finite). OR **local_ip**(Ref_number,Lower_Bound ,Upper_Bound).
    - arity: 2 OR 3
    - meaning : This predicate loads the destination ip address constraints with respect to a rule.

- **remote_ip**(Ref_Number,Finite). OR **local_ip**(Ref_number,Lower_Bound,Upper_Bound).
    - arity: 1 OR 2
    - meaning : This predicate loads the source ip address constraints with respect to a rule in the prolog database.

- **adapter**(Ref_Number, Adapter_type). OR **adapter**(Ref_Number,Lower_Bound,Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the adapter constraints with respect to a rule in the prolog database.

- **proto**(Ref_Number , Protocol_Number). OR **proto**(Ref_Number, Lower_Bound, Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the protocol constraints with respect to a rule in the prolog database. It can be a list or a range of protocols.

- **tcp_local_port**(Ref_Number, Port_Number). OR **tcp_local_port**(Ref_Number,Lower_Bound,Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the local_port constraints with respect to a rule in the prolog database.Tcp indicates that the protocol is tcp.

-  **tcp_remote_port**(Ref_Number, Port_Number). OR **tcp_remote_port**(Ref_Number,Lower_Bound,Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the destination port constraints with respect to a rule in the prolog database.Tcp indicates that the protocol is tcp.

- **udp_local_port**(Ref_Number, Port_Number). OR **udp_local_port**(Ref_Number,Lower_Bound,Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the local_port constraints with respect to a rule in the prolog database. udp indicates that the protocol is udp.

-  **udp_remote_port**(Ref_Number, Port_Number). OR **udp_remote_port**(Ref_Number,Lower_Bound,Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the destination port constraints with respect to a rule in the prolog database. udp indicates that the protocol is udp.

-  **ether**(Ref_Number, Ether_Number). OR **ether**(Ref_Number,Lower_Bound,Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the ethernet clasue constraints with respect to a rule in the prolog database.

-   **vlan**(Ref_Number, Vlan_Number). OR **vlan**(Ref_Number,Lower_Bound,Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the vlan constraints with respect to a rule in the prolog database.

-   **icmp_type**(Ref_Number , ICMP-type). OR **icmp_type**(Ref_Number,Lower_Bound,Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the ICMP-type constraints with respect to a rule in the prolog database.

-   **icmp_code**(Ref_Number , ICMP-Code).OR **icmp_code**(Ref_Number,Lower_Bound,Upper_Bound).
    - arity : 2 OR 3
    - meaning : This predicate loads the ICMP-code constraints with respect to a rule in the prolog database.

---
### Helper Predicates

- **adapter_decoder**(Type,Number).
    - arity : 2
    - meaning : This maps the adapters from A-P to 1-16 respectively.

- **member**(X,List).
    - arity : 2
    - meaning : This predicate is used to ascertain if X is a member of the list List.

- **is_ip_in_range**(Test_ip , Lower_Bound , Upper_Bound).
    - arity : 3
    - meaning : checks if the ip denoted by Test_ip lies within the given bounds.

- **is_ip_valid**(IP).
    - arity: 1
    - meaning : This checks if the ip entered is valid or not.

- **is_ip_in_subnet_block**(Test_ip, Subnet_ip).
    - arity : 2
    - meaning : checks if the ip denoted by Test_ip lies within the subnet mask block denoted by Subnet_ip.

- **is_adapter_in_range**(Test_adpater , Lower_Bound , Upper_Bound).
    - arity : 3
    - meaning : checks if the Test_adapter is within the range given by the bounds.

- **is_num_in_range**(Test_Number , Lower_Bound , Upper_Bound).
    - arity : 3
    - meaning : checks if the Test_Number is within the range given by the bounds.
       
---
### Matching with a rule

-   **local_ip_check**(Ref_Number, Local_ip).
    - arity : 2
    - meaning : Checks if a rule constraints match packet local ip.

-   **remote_ip_check**(Ref_Number, Remote_ip).
    - arity : 2
    - meaning : Checks if a rule constraints match packet remote ip.

-   **adapter_check**(Ref_Number, Adapter).
    - arity : 2
    - meaning : Checks if a rule constraints match packet adapter.

-   **proto_check**(Ref_Number, Protocol_Number).
    - arity : 2
    - meaning : Checks if a rule constraints match packet protocol number.

-   **tcp_local_port_check**(Ref_Number, Local_port).
    - arity : 2
    - meaning : Checks if a rule constraints match packet local port when protocol was tcp.

-   **udp_local_port_check**(Ref_Number,Local_port).
    - arity : 2
    - meaning : Checks if a rule constraints match packet local port when protocol was udp.

-   **icmp_type_check**(Ref_Number, ICMP-type).
    - arity : 2
    - meaning : Checks if a rule constraints match packet icmp-type when protocol was icmp.

-   **tcp_remote_port_check**(Ref_Number,Remote_port).
    - arity :
    - meaning : Checks if a rule constraints match packet remote port when protocol was tcp.

-   **udp_remote_port_check**(Ref_Number,Remote_port).
    - arity :
    - meaning : Checks if a rule constraints match packet remote port when protocol was udp. 

-   **icmp_code_check**(Ref_Number,ICMP-code).
    - arity : 2
    - meaning : Checks if a rule constraints match packet icmp-code when protocol was icmp.

-   **ether_check**(Ref_Number,Ethernet_Number).
    - arity : 2
    - meaning : Checks if a rule constraints match packet ethernet number.

-   **vlan_check**(Ref_Number,Vlan_Number).
    - arity : 2
    - meaning : Checks if a rule constraints match packet vlan number.

---
### Other Utilities 

- **icmp_response**(Local_port,Message).
    - arity : 2
    - meaning : This predicate is called if protocol type is ICMP with action(X,reject). If this is called then the ICMP message corresponding to Local_port(that is the ICMP-type) is stored in the variable Message.

- **message**(Type,Message,Proto,Local_port).
    - arity : 4
    - meaning : It initializes the message to be given as the output after the firewall has completed its checking on the input packet.

---
### Main Engine

- **rule_checker**(Local_ip, Remote_ip, Proto, Local_port, Remote_port, Ether, Vlan, Adapter, Message).
    - arity : 9
    - meaning : This predicate matches an input packet to a rule.

- **packet**(Local_ip, Remote_ip, Proto, Local_port, Remote_port, Ether, Vlan, Adapter).
    - arity : 8
    - meaning : This predicate serves as the input to the engine. That is a query for an incoming packet is made using this predicate.
        - Local_ip : Destination IP for the incoming packet in the form of a list as stated above.
        - Remote_ip : Source IP for the incoming packet in the form of a list as stated above.
        - Proto : Protocol Number for the incoming packet.
        - Local_port : ICMP-type if incoming packet's protocol is ICMP, destination port number if incoming packet's protocol is tcp/udp , else any decimal number.
        - Remote_port : ICMP-code if incoming packet's protocol is ICMP, source port number if incoming packet's protocol is tcp/udp , else any decimal number.
        - Ether : Ether type for the incoming packet.
        - Vlan : Vlan Number for the incoming packet.
        - Adapter : Adapter for the incoming packet in uppercase and enclosed in single quotes (from A-P).

------------------------------------------------------------------------------------------------------

## Query Format (How can a user use the engine for an incoming packet?)

Any query for a packet should be given in the understated format only.

1. Create a predicate term 'packet' with its 8 arguments taking in the information for the incoming packet. No field should be left blank or filled with 'any' as an entry.

2. Using the predicate 'packet' make a query of the form :
    packet(_,_,_,_,_,_,_,_).

    -> The action taken by the firewall will be displayed on the prolog prompt.
    -> The examples may be viewed in the 'Sample_Test_Input.txt' file.

-------------------------------------------------------------------------------------------------------

## Adding a new Rule

- The new rule should either be added in the file named 'f2016532_f2016601_Database.pl' or in the engine file after commenting out the file includer statement.

- Rules should be entered in decreasing order of Ref_Number from top to bottom.

If a user wishes to add a new rule he/she may follow the following steps:

1. Use the predicate 'action' to feed the action with respect to the new rule you want to add and insert it in the beginning of the prolog file.

2. Using the predicates which load the various fields in the prolog knowledge base load your constraints into the knowledge base of prolog.

    - Format for unique entry :
        - ether(Ref_Number , 101), local_ip(Ref_Number ,[192,168,7,1]), adapter(Ref_Number ,'A').\
    - Format for list entry :
        - ether(Ref_Number , [101,114,....]), local_ip(Ref_Number ,[[192,168,7,1],[192,168,8,1],....]), adapter(Ref_Number ,['A','B',....]).
    - Format for giving a range (use 3 arity predicates) :
        - ether(Ref_Number , 101 ,114), local_ip(Ref_Number ,[192,168,7,1],[192,168,8,1]), adapter(Ref_Number ,'A','C').

3. Test using a possible sample input in the given format for your rule.

-----------------------------------------------------------------------------------------------------------

# Developers 

- Sanjeet Malhotra
    - 2016B4A70601P
- Aviral Sethi
    - 2016B3A70532P


