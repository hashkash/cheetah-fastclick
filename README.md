# FastClick with support for the Cheetah Load Balancer

This repository is a modified version of FastClick (see README.fastclick.md)
that embeds all the elements to build a full-featured Cheetah load-balancer
(check out our NSDI'20 paper).

## Installation

One should follow the FastClick tutorial, but the main steps are taken here:

 * Install DPDK's dependencies (sudo apt install libelf-dev build-essential pkg-config zlib1g-dev libnuma-dev)
 * Install DPDK (http://core.dpdk.org/doc/quick-start/), but add O=x86_64-native-linuxapp-gcc at the end of "make config T=x86_64-native-linuxapp-gcc" to allow DPDK to be linked against external apps. This is not needed if you used the DPDK menu, or meson. Do not forget to set up a few hugepages, and mount them
 * Export RTE\_SDK (path to your checked-out DPDK) and RTE\_TARGET (probably x86_64-native-linuxapp-gcc if you followed the tutorial)
 * Build FastClick, enabling Cheetah with the following command:

```
./configure --enable-dpdk --enable-multithread --disable-linuxmodule --enable-intel-cpu --enable-user-multithread --verbose --enable-select=poll CFLAGS="-O3" CXXFLAGS="-std=c++11 -O3"  --disable-dynamic-linking --enable-poll --enable-bound-port-transfer --enable-local --enable-flow --enable-cheetah --disable-task-stats --enable-cpu-load
```

## Running Cheetah

Two samples configuration are provided for the stateless and stateful versions in conf/cheetah/. Some steps to configure the load-balancer are common to both parts, hence we'll start with that.

### Common parts
First, open the configuration file and change the constants defined in the header to match your testbed, particularly:

```
define( $verbose 0,       //Verbosity of Cheetah
        $threads 4,       //Number of threads/cores to use
        $left 1,          //Index of the interface facing clients
        $leftip  10.220.0.1,   //IP of the left interface, it is also the VIP
        $rightip 10.221.0.1,   //IP of the right interface
        $right 0,         //Index of the interface facing servers
        $mode "rr",       //Load-balancing mode (rr is round robin)
        $resettime 5,     //Time to reset statistics counted on the LB
        $clientgw 10.220.0.5,  //Gateway to clients
        $leastmode "conn" //Metric used for pow2, least loaded and AWRR
)
```

### Stateless
The heart of the configuration is the CheetahStateless element:

```
   -> [0] cheetah :: CheetahStateless(VIP $leftip,
                        DST 10.221.0.5, DST 10.221.0.6, DST 10.221.0.7, DST 10.221.0.8,
                        BUCKETS 256, FIX_TS_ECR true, SET_TS_VAL true, FIX_IP true,
                        LB_MODE $mode, RESET_TIME $resettime, HASH true,
                        LST_MODE $leastmode, VERBOSE $verbose)[0]
```

The list of servers is given by the DST parameter. You may use the `NSERVER N` parameters to utilize only the first N servers, then use the add_server and/or remove_server handlers to start/stop utilizing some servers. The number of buckets is the maximal amount of servers. FIX_TS_ECR means the LB fixes the ECR field of packets passing by so the TS the server receives is not corrupted. SET_TS_VAL fixes backward packets so the VAL encodes the cookie. Both those options are to use in pair. FIX_IP allows to set the destination IP of the server, else only the MAC is resolved but the VIP IP is kept. Other parameters are discussed above. `HASH true` enables obfuscation.

The arguments of the elments are further described in the documentation of the class in elements/cheetah/cheetahstateless.hh

### Stateful
In the stateful configuration, the IPs parameters of the define are directly replaced inline.
Stateful configurations (Cuckoo or Cheetah) are split in two parts : the classifier, either CheetahStateful or FlowIPManager. Then, the FlowIPLoadBalancer that uses the flow space set by the classifier to write down the server choice, and then read it back for packets of established connections. Except from that, configurations are very identical.
The only difference is that the cookie cannot be fixed in the LB, because the LB cannot "set back" the index of the flow space. So the server must echo it back.

## Understanding Cheetah
The Cheetah stateless element is implemented in elements/cheetah/cheetahstateless.{cc,hh}.
The element follows the (Fast)Click conventions. Packets are pushed to the element through push_batch. Carefully read the documentation of the hh. The push_batch function will call handle_from_server or handle_from_client according to the input port. Documentation of the functions and inline comments should be sufficient to understand.
