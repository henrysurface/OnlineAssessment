# Online Assessment

This repo is for Firewall implementation.

## Getting Started

Please clone and download this repo to your computer.

### Installing

1. Please install ruby with following link:
https://www.ruby-lang.org/en/documentation/installation/

2. Open OnlineAccessment90min.rb and change "your path file" to the testing files in your computer.
```
fw = Firewall.new("your path file")
```

3. Run the 90 min version with command line interface:
```
ruby OnlineAccessment90min.rb
```

4. Run the 5 hours version with following:
```
ruby OnlineAccessment5hours.rb
```

5. The rules are recorded in path.csv file for evaluation of code.

## Test Results

### Rule Type

1. Signal IP address and port with direction and protocol:
```
inbound,tcp,80,192.168.1.2
```
2. Range of port and signal IP address with direction and protocol:
```
outbound,tcp,10000-20000,192.168.10.11
```
3. Range of port and Range of IP address with direction and protocol:
```
outbound,tcp,2100-3000,192.168.15.0-192.168.16.3
```
### Results
1. The first version "OnlineAccessment90min.rb" can pass the rule type 1 and 2.

2. The Second version "OnlineAccessment5hours.rb" can pass all types of rule.

## Coding, Design, and Algorithmic choices
### Algorithmic choices
This Online assessment is implemented with Rudy script. Since the requirements for this assessment is reducing the latency of response for Firewall. 
### IP address part
I choose the Trie structure to store information of each rule. Although this selection will increase memory cost after applying rules, the cost of each query is faster than the others data structure. The algorithm will quickly respond when the node does not exist or the value in node does not match with input. Typically, it will take O (1) to check each connection.
### Port part:
To reduce memory cost, I utilize the Interval class to record the range of port. When the ranges of ports is overlapped, it will merge the ranges of ports as a new Interval class. Otherwise, it stores Interval class directly. For port searching, I majorly depend on the BinarySeaching for the Interval class in a list.
### Direction and protocol;
Since the direction and protocol can be a key for matching input, I select the combination of direction and protocol as a key and store in every node of Trie. When the node dose not contains the key, the program will return false.
### Design:
The Trie Class is employed with IP address storage. Each digit of IP is a node in the Trie. The direction is combined with the protocol as an key recorded in the node, and the ports is stored with Interval Class with addRange method, which is used to reduce the memory cost of port range storage. Also, the method of queryPorts is utilized to match the port from Interval list. 

The Firewall Class is designed with building the Trie with rules and querying the connection. In initialize method, the IP address input will be categorized to signal IP address and range of IP address For adding signal IP address, it build nodes with iterative method. On the other hand, for adding range of IP addresses, the allow_range_ip and insert_ip_recursive will build nodes in Trie recursively.

The accept_packet method in Firewall class is employed for querying input connection with nodes traverse in the tries. When it reach end of Trie, it will return "true". Otherwise it will return "false".

## Optimizations and Debugging

The first implement of 90 min version build the Trie iteratively and contains bugs for add a range of IP address.

I optimize it to second version that adding node in the Tries recursively. It is able to correctly plant nodes in tree with overlapping ranges of IP addresses.

Performance after optimization for each query(unit: second):
```
  user     system      total        real
  0.000000   0.000000   0.000000  (0.000059)  
```
## The interested Area Rank

1. Data team

2. Policy team
3. Platform team

## Author

Heng-Yi, Lin

