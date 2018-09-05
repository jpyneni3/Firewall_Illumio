# Illumio Firewall Coding Challenge- Jaswanth Sai Pyneni

##To Run:
Open a command prompt and change directory into "Firewall_Illumio". <br>
Install ipaddress with one of the following: <br>
```pip install ipaddress```  <br> <br>
```conda install ipaddress```  <br> <br>
Command to run: </br>
python test.py

I completed the challenge in Python 2 and created a Firewall class that accepts a rules csv (Rules.csv), as described in the challenge, with the assumption that all content within is valid.

I made of python's ipaddress module to handle the IP addresses. Make sure to install with either of the following two commands stated above.

The most important factor in this challenge, as in most technical decisions, was looking at the performance tradeoff between efficient storage and efficient speed.

I made the decision of taking the necessary time O(mn) and space O(mn) to store the given rules, while gaining ability to have very fast look up to decide whether or packets are not accepted O(1).

m = number of ports specified
n = number of addresses specified

I was able to do this by having a nested dictionary, that maps from given direction, protocol, and port to a set of ip address value.  I was initially going to use 4 different dictionaries, one per direction_protocol pair, but realized that would require an extra computation in the accept_packet() method to determine which dictionary to go into.

My biggest concern right now is, my code is very slow if a certain rules maps a range of ports to a range of addresses- I am not sure if that is good implementation for a firewall but wanted to handle that case anyways.

I tested my code with the given default test cases, test cases with poorly formed packets, the bounds on the ports, the bounds on the addresses, and ability to handle ranges for ports and addresses at the same time.

If I had more time, I would try to make a more efficient way to store the ranges and single mappings to addresses from ports, instead of storing every single address with in the given range as this would make the initial set of rules much faster.

I would address the issue, perhaps by using a search tree that maps each port node to the ranges of addresses it covers, so look up will be a bit slower, but establishing the rules framework would be faster.

Team Preferences:
1-Data Team
2-Policy
3-Platform
