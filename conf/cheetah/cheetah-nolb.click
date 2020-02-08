define($verbose 0,
       $left 1,
       $right 0)

FromDPDKDevice($left)
 //   -> Print(LEFT,-1)
    -> c :: Classifier(
        12/0806 20/0001,
        12/0806 20/0002,
        12/0800,
        -);
c[2]
    -> Strip(14)
    -> CheckIPHeader
    -> tcl ::  IPClassifier(tcp, -)
//    -> IPPrint("TORIGHT")
    -> SetIPAddress(10.221.0.5)
    -> arpright :: ARPQuerier(IP 10.221.0.1, ETH $macright)
 //   -> Print("TORIGHT", -1)
    -> td1 :: ToDPDKDevice($right,TCO false);

tcl[1] -> Print("NOT TCP") -> Discard;

arprespleft :: ARPResponder(10.220.0.1 $macleft)

c[0] -> arprespleft;

c[3] -> Print("Unknown packet type") -> Discard;


FromDPDKDevice($right)
 //   -> Print(RIGHT,-1)
    -> cr :: Classifier(
        12/0806 20/0001,
        12/0806 20/0002,
        12/0800,
        -);
cr[2]
    -> Strip(14)
    -> CheckIPHeader
    -> tcr ::  IPClassifier(tcp, -)
    -> SetIPAddress(10.220.0.5)
    -> arpleft :: ARPQuerier(IP 10.220.0.1, ETH $macleft)
//    -> Print("TOLEFT", -1)
    -> td0 :: ToDPDKDevice($left,TCO false);

arprespright :: ARPResponder(10.221.0.1 $macright);

cr[0] -> arprespright;


cr[3] -> Print("Unknown packet type") -> Discard;

arprespleft[0] -> td0;
arprespright[0] -> td1;

c[1] -> [1]arpleft;
cr[1] -> [1]arpright;

tcr[1] -> Print("NOT TCP") -> Discard;

//arpleft[1] -> td1;
//arpright[1] -> Print("ARPReqRight") -> td0;
