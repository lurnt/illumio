# Firewall takehome assignment

## Implementation:
The Firewall class contains a dictionary of lists as its main internal data structure, mapping from a tuple of (direction, protocol) [of which there are four possible combinations] to a respective list of Range objects, which takes in ip and protocol strings and handles them as ranges accordingly. 

The overall implementation takes O(n) space. Inserting a rule is operates around a modified binary search, in which rules are sorted by the lower port bound. As such, runtime for inserting new rules is O(logn) (so inserting k rules has complexity O(klogn)). However, checking if a matching rule exists through accept_packet is O(n), since in the worst case every rule in the list we are searching happens to have a port lower bound that is smaller than the queried port number. 

As I was doing this assignment, I also considered having a hash table mapping from port number to a 3-tuple of direction, protocol, and ip. The issue is handling ranges of port numbers. I considered having a key for every number within a given port range, but this is horrible for extremely large ranges (i.e., if we had a rule where the port could be from 1 to 65535 -- we would need 65535 values). I opted to optimizie space over performance instead of vice versa.

## Room for improvement:
An additional data structure that I found useful was the interval tree, but I decided I did not have enough time to implement this. Given more time, I would have attempted to do so.
Additionally, if I had more time, I would have made a more comprehensive test base with many more rules. 

## Team of interest:
I am interested in all of the teams, although as of completing this assignment, I am aware that only the policy team has open positions.
