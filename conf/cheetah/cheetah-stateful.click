//Configuration
define( $verbose 0,       //Verbosity of Cheetah
	$threads 4,       //Number of threads/cores to use
        $left 1,          //Index of the interface facing clients
        $right 0,         //Index of the interface facing servers
        $mode "rr",       //Load-balancing mode (rr is round robin)
	$resettime 5,     //Time to reset statistics counted on the LB
	$leastmode "conn" //Metric used for pow2, least loaded and AWRR
)

//Spawn an HTTP server to read and write handlers
HTTPServer()

fd0 :: FromDPDKDevice(  $left, VERBOSE 2, MAXTHREADS $threads, RSS_AGGREGATE true, PREFETCH_SECOND 1,
                        SCALE parallel
                         )
    -> Print(LEFT,-1,ACTIVE $print)
    -> c :: Classifier(
        12/0806 20/0001, //ARP request
        12/0806 20/0002, //ARP replies
        12/0800,         //IP packets
        -);

c[2]
    -> Strip(14)
    -> CheckIPHeader(CHECKSUM false)
    //Filter non-TCP traffic
    -> tcl ::  IPClassifier(tcp, -)

    //Used for the cycles graph, counts cycles
    -> accum_start :: RoundTripCycleCount

    -> cheetahful :: CheetahStateful(RESERVE 32, VERBOSE $verbose, BACKWARD_RESERVE -1, BLOCKS 512  )
    -> cheetah :: FlowIPLoadBalancer(DST 10.180.250.5 ,
DST 10.180.250.6 ,
DST 10.180.250.7 ,
DST 10.180.250.8 ,
DST 10.180.250.9 ,
DST 10.180.250.10 ,
DST 10.180.250.11 ,
DST 10.180.250.12 ,
DST 10.180.250.13 ,
DST 10.180.250.14 ,
DST 10.180.250.15 ,
DST 10.180.250.16 ,
DST 10.180.250.17 ,
DST 10.180.250.18 ,
DST 10.180.250.19 ,
DST 10.180.250.20 ,
DST 10.180.250.21 ,
DST 10.180.250.22 ,
DST 10.180.250.23 ,
DST 10.180.250.24 ,
DST 10.180.250.25 ,
DST 10.180.250.26 ,
DST 10.180.250.27 ,
DST 10.180.250.28 ,
DST 10.180.250.29 ,
DST 10.180.250.30 ,
DST 10.180.250.31 ,
DST 10.180.250.32 ,
DST 10.180.250.33 ,
DST 10.180.250.34 ,
DST 10.180.250.35 ,
DST 10.180.250.36 , VIP 10.2.0.1, LB_MODE rr, NSERVER 0) 
    -> accum_stop :: RoundTripCycleCount
    
    -> ResetIPChecksum(L4 true)
    -> arpright :: ARPQuerier(IP 10.180.250.1, ETH $macright, CACHE true)
    -> Print("TORIGHT", -1, ACTIVE $print)
    -> td1 :: ToDPDKDevice($right, TCO true);

tcl[1] -> Print("NOT TCP", ACTIVE 0) -> Discard;

arprespleft :: ARPResponder(10.2.0.1 $macleft)

c[0] -> arprespleft;

c[3] -> Print("Unknown packet type") -> Discard;


fd1 :: FromDPDKDevice($right, VERBOSE 2, MAXTHREADS $threads,
                      RSS_AGGREGATE true, PREFETCH_SECOND 1,
                      SCALE parallel)
    -> Print(RIGHT,-1, ACTIVE $print)
    -> cr :: Classifier(
        12/0806 20/0001,
        12/0806 20/0002,
        12/0800,
        -);
cr[2]
    -> Strip(14)
    -> CheckIPHeader(CHECKSUM false)
    -> tcr ::  IPClassifier(tcp, -)
    -> accumbw_start :: RoundTripCycleCount
    -> FlowIPLoadBalancerReverse(LB cheetah)
    -> accumbw_stop :: RoundTripCycleCount
//    -> SetIPChecksum
//    -> SetTCPChecksum
    -> ResetIPChecksum(L4 true)
//    -> SetIPAddress(10.2.5) //Address of the gateway to left
    -> arpleft :: ARPQuerier(IP 10.2.0.1, ETH $macleft, CACHE true)
    -> Print("TOLEFT", -1, ACTIVE $print)
    -> td0 :: ToDPDKDevice($left, TCO true);

arprespright :: ARPResponder(10.180.250.1 $macright); 

cr[0] -> arprespright;


cr[3] -> Print("Unknown packet type") -> Discard;

arprespleft[0] -> td0;
arprespright[0] -> td1;

c[1] -> [1]arpleft;
cr[1] -> [1]arpright;

tcr[1] -> Print("NOT TCP") -> Discard;

//arpleft[1] -> td1;
//arpright[1] -> Print("ARPReqRight") -> td0;


Script(TYPE ACTIVE,
        wait 10s,
        set t $(now),
        print "Time is $t, ceil $(ceil $t)",
        wait $(sub $(ceil $t) $t), 
        set start $(now),
        print "Starting at $start",
        label loop,
        //set elapsed $(sub $(now) $start),
        set elapsed $(now),
        print "LBSTAT-$elapsed-RESULT-NBSRV $(cheetah.nb_active_servers)",
        set l $(load),
        print $l,
        print "LBSTAT-$elapsed-RESULT-LOAD $(add $l)",
        wait 1s,
        goto loop);

DriverManager(  wait,
                print "RESULT-LB_DROPPED $(add $(fd0.hw_dropped) $(fd1.hw_dropped))",
                set tuse $(add $(useful_kcycles)),
                set pcount $(add $(fd0.hw_count) $(fd1.hw_count)),
                print "RESULT-LB_FLOW $(flowmanager.count)",
                set cproof 0,
                set cycles $(sub $(accum_start.cycles) $(accum_stop.cycles) $cproof),
                print "RESULT-LB_CYCLESPP $(div $cycles $(accum_start.packets))",
                print "RESULT-LB_CYCLES $cycles",
                set cbwproof 0,
                set cyclesbw $(sub $(accumbw_start.cycles) $(accumbw_stop.cycles) $cbwproof),
                print "RESULT-LB_CYCLESBWPP $(div $cyclesbw $(accumbw_start.packets))",
                print "RESULT-LB_CYCLESBW $cyclesbw",
                print "RESULT-LB_COUNT $pcount",
                print "RESULT-LB_USEFUL $tuse",
                print "RESULT-LB_USEFUL_PP $(div $tuse $(div $pcount 1000))",
                print "This is the end\n",
            )
