//
// Copyright (C) 2014 OpenSim Ltd.
// Author: Benjamin Seregi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//


#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/HopLimitTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/L3Tools.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/ipv4/IcmpHeader.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4Route.h"
#include "inet/routing/aodv/Aodv.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo.h"

#include "math.h" /*beratovic*/


namespace inet {
namespace aodv {

Define_Module(Aodv);

const int KIND_DELAYEDSEND = 100;


void Aodv::initialize(int stage)
{
    if (stage == INITSTAGE_ROUTING_PROTOCOLS)
        addressType = getSelfIPAddress().getAddressType();  // needed for handleStartOperation()

    RoutingProtocolBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        lastBroadcastTime = SIMTIME_ZERO;
        rebootTime = SIMTIME_ZERO;
        rreqId = sequenceNum = 0;
        rreqCount = rerrCount = 0;
        host = getContainingNode(this);
        routingTable = getModuleFromPar<IRoutingTable>(par("routingTableModule"), this);
        interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        networkProtocol = getModuleFromPar<INetfilter>(par("networkProtocolModule"), this);

        aodvUDPPort = par("udpPort");
        askGratuitousRREP = par("askGratuitousRREP");
        useHelloMessages = par("useHelloMessages");
        destinationOnlyFlag = par("destinationOnlyFlag");
        activeRouteTimeout = par("activeRouteTimeout");
        helloInterval = par("helloInterval");
        allowedHelloLoss = par("allowedHelloLoss");
        netDiameter = par("netDiameter");
        nodeTraversalTime = par("nodeTraversalTime");
        rerrRatelimit = par("rerrRatelimit");
        rreqRetries = par("rreqRetries");
        rreqRatelimit = par("rreqRatelimit");
        timeoutBuffer = par("timeoutBuffer");
        ttlStart = par("ttlStart");
        ttlIncrement = par("ttlIncrement");
        ttlThreshold = par("ttlThreshold");
        localAddTTL = par("localAddTTL");
        jitterPar = &par("jitter");
        periodicJitter = &par("periodicJitter");

        myRouteTimeout = par("myRouteTimeout");
        deletePeriod = par("deletePeriod");
        blacklistTimeout = par("blacklistTimeout");
        netTraversalTime = par("netTraversalTime");
        nextHopWait = par("nextHopWait");
        pathDiscoveryTime = par("pathDiscoveryTime");
        expungeTimer = new cMessage("ExpungeTimer");
        counterTimer = new cMessage("CounterTimer");
        rrepAckTimer = new cMessage("RrepAckTimer");
        blacklistTimer = new cMessage("BlackListTimer");
        sdnControllerTimer = new cMessage("SdnTimer");
        sdnControllerTimer2 = new cMessage("SdnTimer2");
#if 1
        sdnNodeSourceTimer = new cMessage("sdnNodeSourceTimer");
        sdnNodeATimer = new cMessage("sdnNodeATimer");
        sdnNodeBTimer = new cMessage("sdnNodeBTimer");
        sdnNodeFTimer = new cMessage("sdnNodeFTimer");
        sdnNodeETimer = new cMessage("sdnNodeETimer");

#endif
        if (useHelloMessages)
            helloMsgTimer = new cMessage("HelloMsgTimer");
    }
    else if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        networkProtocol->registerHook(0, this);
        host->subscribe(linkBrokenSignal, this);
        usingIpv6 = (routingTable->getRouterIdAsGeneric().getType() == L3Address::IPv6);
    }


    /* beratovic starts */
#ifdef CONTROLLER_MODE_ENABLED
    /*First positions of the nodes*/
    nodePosition[NODE_A].node_Xcoord = 1494;
    nodePosition[NODE_A].node_Ycoord = 776;

    nodePosition[NODE_B].node_Xcoord = 1751;
    nodePosition[NODE_B].node_Ycoord = 776;

    nodePosition[NODE_SOURCE].node_Xcoord = 1278;
    nodePosition[NODE_SOURCE].node_Ycoord = 654;

    nodePosition[NODE_DESTINATION].node_Xcoord = 2377;
    nodePosition[NODE_DESTINATION].node_Ycoord = 513;

    nodePosition[NODE_E].node_Xcoord = 1278;
    nodePosition[NODE_E].node_Ycoord = 958;

    nodePosition[NODE_F].node_Xcoord = 1992;
    nodePosition[NODE_F].node_Ycoord = 958;
#endif
    /* beratovic ends */


}

void Aodv::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (auto waitForRrep = dynamic_cast<WaitForRrep *>(msg))
            handleWaitForRREP(waitForRrep);
        else if (msg == helloMsgTimer)
            sendHelloMessagesIfNeeded();
        else if (msg == expungeTimer)
            expungeRoutes();
        else if (msg == counterTimer) {
            rreqCount = rerrCount = 0;
            scheduleAt(simTime() + 1, counterTimer);
        }
        else if (msg == rrepAckTimer)
            handleRREPACKTimer();
        else if (msg == blacklistTimer)
            handleBlackListTimer();
#ifdef CONTROLLER_MODE_ENABLED
        else if (msg == sdnControllerTimer)/*beratovic*/
        {
            handleSdnControllerTimer();
        }
        else if (msg == sdnControllerTimer2)
        {
            handleSdnControllerTimer2();
        }
        else if(msg == sdnNodeSourceTimer)
        {
            handleSdnNodeSourceTimer();
        }
        else if(msg == sdnNodeATimer)
        {
            handleSdnNodeATimer();
        }
        else if(msg == sdnNodeBTimer)
        {
            handleSdnNodeBTimer();
        }
        else if(msg == sdnNodeFTimer)
        {
            handleSdnNodeFTimer();
        }
        else if(msg == sdnNodeETimer)
        {
            handleSdnNodeETimer();
        }
#endif
        else if (msg->getKind() == KIND_DELAYEDSEND) {
            auto timer = check_and_cast<PacketHolderMessage*>(msg);
            socket.send(timer->dropOwnedPacket());
            delete timer;
        }
        else
            throw cRuntimeError("Unknown self message");
    }
    else
        socket.processMessage(msg);
}

void Aodv::checkIpVersionAndPacketTypeCompatibility(AodvControlPacketType packetType)
{
    switch (packetType) {
        case RREQ:
        case RREP:
        case RERR:
        case RREPACK:
            if (usingIpv6)
                throw cRuntimeError("AODV Control Packet arrived with non-IPv6 packet type %d, but AODV configured for IPv6 routing", packetType);
            break;

        case RREQ_IPv6:
        case RREP_IPv6:
        case RERR_IPv6:
        case RREPACK_IPv6:
            if (!usingIpv6)
                throw cRuntimeError("AODV Control Packet arrived with IPv6 packet type %d, but AODV configured for non-IPv6 routing", packetType);
            break;

        default:
            throw cRuntimeError("AODV Control Packet arrived with undefined packet type: %d", packetType);
    }
}

void Aodv::processPacket(Packet *packet)
{
#if 1
    /* 2 ve 5. saniyeler arasýnda paket gelse dahi iþlemeden siliyoruz! Process time kýsalýyor. Zaten böyle bir durum olmamalý!
     * 2'ye kadar hello paketleri gelebilir. 10.saniye ve devamýnda route request'ler gelebilir */
    if((simtime_t(2) < simTime() ) && (simTime() < simtime_t(5)))
    {
        /* Hello mesajlarý 2. saniyeye kadar gönderilmeli. Route request paketleri 5. saniyeden sonra gelecek. Dolayýsýyla bu 2
         * zaman aralýðýnda bu metod öyle ya da böyle çalýþmamalý!*/
        delete packet;
        return;
    }
#endif
    L3Address sourceAddr = packet->getTag<L3AddressInd>()->getSrcAddress();
    // KLUDGE: I added this -1 after TTL decrement has been moved in Ipv4
    unsigned int arrivalPacketTTL = packet->getTag<HopLimitInd>()->getHopLimit() - 1;
    const auto& aodvPacket = packet->popAtFront<AodvControlPacket>();
    auto packetType = aodvPacket->getPacketType();
    //TODO aodvPacket->copyTags(*udpPacket);
#ifdef  CONTROLLER_MODE_ENABLED
    /* beratovic */
#warning "FAST simulation type aborts here I guess!"
    uint8_t testBuf[10];
    auto beratovicDeneme = packet->popAtBack<BytesChunk>(B(10));
    beratovicDeneme->copyToBuffer(testBuf, 10);
#endif
    /* beratovic */
    switch (packetType) {
        case RREQ:
        case RREQ_IPv6:
            checkIpVersionAndPacketTypeCompatibility(packetType);
#ifndef  CONTROLLER_MODE_ENABLED
            handleRREQ(CHK(dynamicPtrCast<Rreq>(aodvPacket->dupShared())), sourceAddr, arrivalPacketTTL);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
            /*Hello mesajlarý ve route request mesajlarý farklý deðerlendirilecek. Hello mesajlarýnda sorun olmamasý durumunda node'lara mesaj gönderilmeyecek*/
            /* This part for the hello messages. Check incoming hello messages content in here */
            if((simTime() < simtime_t(2)) && (OFPT_HELLO == testBuf[1])) /* OFPT_HELLO == testBuf[1] */
            {
                /*
                 * rawBytesData->setBytes({nodeSpecificHelloMessage.helloMsg.header.version,
                nodeSpecificHelloMessage.helloMsg.header.type,
                nodeSpecificHelloMessage.helloMsg.header.xid,
                nodeSpecificHelloMessage.helloMsg.header.length,
                nodeSpecificHelloMessage.helloMsg.mobilityType,
                nodeSpecificHelloMessage.helloMsg.reqType,
                nodeSpecificHelloMessage.datapath_id,
                nodeSpecificHelloMessage.n_tables,
                nodeSpecificHelloMessage.capabilities, nodeSpecificHelloMessage.helloMsg.nodeId});
                */
                if((testBuf[0] == UNKNOWN_INDEX) && (testBuf[1] == UNKNOWN_INDEX) && (testBuf[3] == UNKNOWN_INDEX) && (testBuf[5] == UNKNOWN_INDEX) && (testBuf[7] == UNKNOWN_INDEX) && (testBuf[9] == UNKNOWN_INDEX) )
                {
                    /*ERROR!*/
                    throw cRuntimeError("Topology error!", packetType);
                }
                else
                {
                    switch (testBuf[9])
                    {
                        case 1:
                        {
                            EV_INFO << "Node ID: 1 is ready to work!" << endl;
                            break;
                        }
                        case 2:
                        {
                            EV_INFO << "Node ID: 2 is ready to work!" << endl;
                            break;
                        }
                        case 3:
                        {
                            EV_INFO << "Node ID: 3 is ready to work!" << endl;
                            break;
                        }
                        case 4:
                        {
                            EV_INFO << "Node ID: 4 is ready to work!" << endl;
                            break;
                        }
                        case 5:
                        {
                            EV_INFO << "Node ID: 5 is ready to work!" << endl;
                            break;
                        }
                        case 6:
                        {
                            EV_INFO << "Node ID: 6 is ready to work!" << endl;
                            break;
                        }
                        default:
                            EV_ERROR << "Node ID: UNKNOWN is ready to work! Incoming packet: "<< beratovicDeneme << endl;
                            break;
                    }
                }
                delete packet;
                return;
            }
            else if(OFPT_ERROR == testBuf[1])
            {
                /*rawBytesDataErr->setBytes({nodeSpecificErrMsg.header.length,
                                            nodeSpecificErrMsg.header.type,
                                            nodeSpecificErrMsg.header.version,
                                            nodeSpecificErrMsg.header.xid,
                                            nodeSpecificErrMsg.errMsgContent,
                                            nodeSpecificErrMsg.nodeId}); */
                /* This packet type is an error type! Log it and stop topology execution */
                EV_ERROR << "Node ID: " << testBuf[5] << " topology error!" << endl;
                throw cRuntimeError("Topology error! Check last log!", packetType);

            }

            handleRREQ(CHK(dynamicPtrCast<Rreq>(aodvPacket->dupShared())), sourceAddr, arrivalPacketTTL, testBuf[0] /* for now lets assume the first byte stands for request type */);
#endif
            delete packet;
            return;

        case RREP:
        case RREP_IPv6:
            checkIpVersionAndPacketTypeCompatibility(packetType);
#ifndef  CONTROLLER_MODE_ENABLED
            handleRREP(CHK(dynamicPtrCast<Rrep>(aodvPacket->dupShared())), sourceAddr);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
            handleRREP(CHK(dynamicPtrCast<Rrep>(aodvPacket->dupShared())), sourceAddr, testBuf[8], testBuf[9]);
#endif
            delete packet;
            return;

        case RERR:
        case RERR_IPv6:
            checkIpVersionAndPacketTypeCompatibility(packetType);
            handleRERR(CHK(dynamicPtrCast<const Rerr>(aodvPacket)), sourceAddr);
            delete packet;
            return;

        case RREPACK:
        case RREPACK_IPv6:
            checkIpVersionAndPacketTypeCompatibility(packetType);
            handleRREPACK(CHK(dynamicPtrCast<const RrepAck>(aodvPacket)), sourceAddr);
            delete packet;
            return;

        default:
            throw cRuntimeError("AODV Control Packet arrived with undefined packet type: %d", packetType);
    }
}

INetfilter::IHook::Result Aodv::ensureRouteForDatagram(Packet *datagram)
{
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& destAddr = networkHeader->getDestinationAddress();
    const L3Address& sourceAddr = networkHeader->getSourceAddress();

    if (destAddr.isBroadcast() || routingTable->isLocalAddress(destAddr) || destAddr.isMulticast())
        return ACCEPT;
    else {
        EV_INFO << "Finding route for source " << sourceAddr << " with destination " << destAddr << endl;
        IRoute *route = routingTable->findBestMatchingRoute(destAddr);
        AodvRouteData *routeData = route ? dynamic_cast<AodvRouteData *>(route->getProtocolData()) : nullptr;

        bool isActive = routeData && routeData->isActive();
        if (isActive && !route->getNextHopAsGeneric().isUnspecified()) {
            EV_INFO << "Active route found: " << route << endl;

            // Each time a route is used to forward a data packet, its Active Route
            // Lifetime field of the source, destination and the next hop on the
            // path to the destination is updated to be no less than the current
            // time plus ACTIVE_ROUTE_TIMEOUT.

            updateValidRouteLifeTime(destAddr, simTime() + activeRouteTimeout);
            updateValidRouteLifeTime(route->getNextHopAsGeneric(), simTime() + activeRouteTimeout);

            return ACCEPT;
        }
        else {
            bool isInactive = routeData && !routeData->isActive();
            // A node disseminates a RREQ when it determines that it needs a route
            // to a destination and does not have one available.  This can happen if
            // the destination is previously unknown to the node, or if a previously
            // valid route to the destination expires or is marked as invalid.

            EV_INFO << (isInactive ? "Inactive" : "Missing") << " route for destination " << destAddr << endl;

            delayDatagram(datagram);

            if (!hasOngoingRouteDiscovery(destAddr)) {
                // When a new route to the same destination is required at a later time
                // (e.g., upon route loss), the TTL in the RREQ IP header is initially
                // set to the Hop Count plus TTL_INCREMENT.
                if (isInactive)
                    startRouteDiscovery(destAddr, route->getMetric() + ttlIncrement);
                else
                    startRouteDiscovery(destAddr);
            }
            else
            {
                EV_DETAIL << "Route discovery is in progress, originator " << getSelfIPAddress() << " target " << destAddr << endl;
            }
            return QUEUE;
        }
    }
}

Aodv::Aodv()
{
}

bool Aodv::hasOngoingRouteDiscovery(const L3Address& target)
{
    return waitForRREPTimers.find(target) != waitForRREPTimers.end();
}

void Aodv::startRouteDiscovery(const L3Address& target, unsigned timeToLive) /* SDN Controller için tablo isteði metodu */
{
#ifndef  CONTROLLER_MODE_ENABLED
    EV_INFO << "Starting route discovery with originator " << getSelfIPAddress() << " and destination " << target << endl;




    ASSERT(!hasOngoingRouteDiscovery(target));
    auto rreq = createRREQ(target);
    addressToRreqRetries[target] = 0;
    sendRREQ(rreq, addressType->getBroadcastAddress(), timeToLive);
#endif
#ifdef  CONTROLLER_MODE_ENABLED

    /**********************************************************************/
    /* HELLO MESSAGE SENDING */
    /**********************************************************************/
    /* 1- Hello mesajlarýný burada gerçekleyeceðiz. Zaman eðer 2.saniyeden küçükse bu isteklerin yol bulmak amaçlý olduðunu bilmeliyiz
     * 2- Herkes Controller node ile haberleþebiliyor. Bu en önemli varsayýmýmýz! */
    if(simTime() < simtime_t(2))
    {
        static uint8 oneTimeHelloChance_A = 0;
        static uint8 oneTimeHelloChance_B = 0;
        static uint8 oneTimeHelloChance_E = 0;
        static uint8 oneTimeHelloChance_F = 0;
        static uint8 oneTimeHelloChance_S = 0;
        static uint8 oneTimeHelloChance_D = 0;
        static uint8 oneTimeHelloChance_C = 0;

        if((getSelfIPAddress() == testDestAddr1) && (0 == oneTimeHelloChance_A)/*A node*/)
        {
            oneTimeHelloChance_A++;
            //createRoute(testDestAddrController, testDestAddr1, 1, false, 0, true, simtime_t(2.0)); /*Node can directly communicate with the controller*/
            /* Each method is modified */
            auto helloNodeA = createRREQ(target);
            /*ASLINDA BURADA GÖNDERÝLEN MESAJLAR ROUTE MESAJLARI DEÐÝL. HELLO MESAJLARI. ÝLK 2 SANÝYEDE HELLO MESAJLARI HER NODE TARAFINDAN CONTROLLER NODE'A GONDERILIYOR*/
            sendRREQ(helloNodeA, testDestAddrController, 0);
            return;
        }
        else if((getSelfIPAddress() == testDestAddr2)  && (0 == oneTimeHelloChance_B)/*B node*/)
        {
            oneTimeHelloChance_B++;
            //createRoute(testDestAddrController, testDestAddr2, 1, false, 0, true, simtime_t(2.0)); /*Node can directly communicate with the controller*/
            /* Each method is modified */
            auto helloNodeB = createRREQ(target);
            /*ASLINDA BURADA GÖNDERÝLEN MESAJLAR ROUTE MESAJLARI DEÐÝL. HELLO MESAJLARI. ÝLK 2 SANÝYEDE HELLO MESAJLARI HER NODE TARAFINDAN CONTROLLER NODE'A GONDERILIYOR*/
            sendRREQ(helloNodeB, testDestAddrController, 0);
            return;
        }

        else if((getSelfIPAddress() == testDestAddr3)  && (0 == oneTimeHelloChance_S)/*S node*/)
        {
            oneTimeHelloChance_S++;
            //createRoute(testDestAddrController, testDestAddrController, 1, true, 0, true, simtime_t(3.0)); /*Node can directly communicate with the controller*/
            /* Each method is modified */
            auto helloNodeS = createRREQ(target);
            /*ASLINDA BURADA GÖNDERÝLEN MESAJLAR ROUTE MESAJLARI DEÐÝL. HELLO MESAJLARI. ÝLK 2 SANÝYEDE HELLO MESAJLARI HER NODE TARAFINDAN CONTROLLER NODE'A GONDERILIYOR*/
            sendRREQ(helloNodeS, testDestAddrController, 0);
            return;
        }

        else if((getSelfIPAddress() == testDestAddr4)  && (0 == oneTimeHelloChance_D)/*D node*/)
        {
            oneTimeHelloChance_D++;
            //createRoute(testDestAddrController, testDestAddr1, 1, false, 0, true, simtime_t(2.0)); /*Node can directly communicate with the controller*/
            /* Each method is modified */
            auto helloNodeD = createRREQ(target);
            /*ASLINDA BURADA GÖNDERÝLEN MESAJLAR ROUTE MESAJLARI DEÐÝL. HELLO MESAJLARI. ÝLK 2 SANÝYEDE HELLO MESAJLARI HER NODE TARAFINDAN CONTROLLER NODE'A GONDERILIYOR*/
            sendRREQ(helloNodeD, testDestAddrController, 0);
            return;
        }

        else if((getSelfIPAddress() == testDestAddr5)  && (0 == oneTimeHelloChance_E)/*E node*/)
        {
            oneTimeHelloChance_E++;
            //createRoute(testDestAddrController, testDestAddr1, 1, false, 0, true, simtime_t(2.0)); /*Node can directly communicate with the controller*/
            /* Each method is modified */
            auto helloNodeE = createRREQ(target);
            /*ASLINDA BURADA GÖNDERÝLEN MESAJLAR ROUTE MESAJLARI DEÐÝL. HELLO MESAJLARI. ÝLK 2 SANÝYEDE HELLO MESAJLARI HER NODE TARAFINDAN CONTROLLER NODE'A GONDERILIYOR*/
            sendRREQ(helloNodeE, testDestAddrController, 0);
            return;
        }

        else if((getSelfIPAddress() == testDestAddr6)  && (0 == oneTimeHelloChance_F)/*F node*/)
        {
            oneTimeHelloChance_F++;
            //createRoute(testDestAddrController, testDestAddr1, 1, false, 0, true, simtime_t(2.0)); /*Node can directly communicate with the controller*/
            /* Each method is modified */
            auto helloNodeF = createRREQ(target);
            /*ASLINDA BURADA GÖNDERÝLEN MESAJLAR ROUTE MESAJLARI DEÐÝL. HELLO MESAJLARI. ÝLK 2 SANÝYEDE HELLO MESAJLARI HER NODE TARAFINDAN CONTROLLER NODE'A GONDERILIYOR*/
            sendRREQ(helloNodeF, testDestAddrController, 0);
            return;
        }

        else if((getSelfIPAddress() == testDestAddrController)  && (0 == oneTimeHelloChance_C)/*C node*/)
        {
            oneTimeHelloChance_C++;
            /*Controller only receives hello messages. Not send them*/
            return;
        }
        else
        {
            return;
        }
    }
    else if((simtime_t(2) < simTime() ) && (simTime() < simtime_t(5)))
    {
        /* Hello mesajlarý 2. saniyeye kadar gönderilmeli. Route request paketleri 5. saniyeden sonra gelecek. Dolayýsýyla bu 2
         * zaman aralýðýnda bu metod öyle ya da böyle çalýþmamalý!*/
        return;
    }
#if 1
    /*do not use this method after periodic calls are started to operating*/
    else if(simTime() > simtime_t(15))
    {
        return;
    }
#endif
    /**********************************************************************/
    /* ROUTE REQUEST MESSAGES SENDING */
    /**********************************************************************/
    EV_INFO << "Starting route discovery with originator " << getSelfIPAddress() << " and destination " << "(SDN Controller)" << endl;
    static unsigned int testHopCount = 0;
    static unsigned int sdnControllerTimerCont = 0;

#if 1 /*beratovic*/
    static unsigned int sdnSourceNodeTimerCont = 0;
    static unsigned int sdnNodeATimerCont = 0;
    static unsigned int sdnNodeBTimerCont = 0;
    static unsigned int sdnNodeFTimerCont = 0;
    static unsigned int sdnNodeETimerCont = 0;


    /*Source node- Start its periodic route control mechanism*/
    if((getSelfIPAddress() == testDestAddr5/*E node*/) && (0 == sdnNodeETimerCont))
    {
        createRoute(testDestAddrController, testDestAddrController, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/

        scheduleAt(simTime() + simtime_t(6.4),sdnNodeETimer); /*start after controller handler in case of topology change*/
        sdnNodeETimerCont++;

    }


    /*Source node- Start its periodic route control mechanism*/
    if((getSelfIPAddress() == testDestAddr6/*F node*/) && (0 == sdnNodeFTimerCont))
    {
        createRoute(testDestAddrController, testDestAddrController, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/

        scheduleAt(simTime() + simtime_t(6.4),sdnNodeFTimer); /*start after controller handler in case of topology change*/
        sdnNodeFTimerCont++;
    }

    /*Source node- Start its periodic route control mechanism*/
    if((getSelfIPAddress() == testDestAddr3/*source node*/) && (0 == sdnSourceNodeTimerCont))
    {
        createRoute(testDestAddrController, testDestAddrController, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/

        scheduleAt(simTime() + simtime_t(6.4),sdnNodeSourceTimer); /*start after controller handler in case of topology change*/
        sdnSourceNodeTimerCont++;
    }

    /*A node- Start its periodic route control mechanism*/
    if((getSelfIPAddress() == testDestAddr1/*A node*/) && (0 == sdnNodeATimerCont))
    {
        createRoute(testDestAddrController, testDestAddrController, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/

        scheduleAt(simTime() + simtime_t(6.4),sdnNodeATimer); /*start after controller handler in case of topology change*/
        sdnNodeATimerCont++;
    }

    /*B node- Start its periodic route control mechanism*/
    if((getSelfIPAddress() == testDestAddr2/*B node*/) && (0 == sdnNodeBTimerCont))
    {
        createRoute(testDestAddrController, testDestAddrController, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/

        scheduleAt(simTime() + simtime_t(6.4),sdnNodeBTimer); /*start after controller handler in case of topology change*/
        sdnNodeBTimerCont++;
    }

#endif
    if(getSelfIPAddress() == testDestAddrController)
    {
        /*Should happen once*/
        if(0 == sdnControllerTimerCont)
        {
            /* When the route request first arrives, schedule timer for SDN Controller */
            scheduleAt(simTime() + simtime_t(3), sdnControllerTimer);
            scheduleAt(simTime() + simtime_t(3), sdnControllerTimer2);
            sdnControllerTimerCont++;
            createRoute(testDestAddr1, testDestAddr1, testHopCount, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
            createRoute(testDestAddr2, testDestAddr2, testHopCount, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
            createRoute(testDestAddr3, testDestAddr3, testHopCount, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
            createRoute(testDestAddr4, testDestAddr4, testHopCount, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
            createRoute(testDestAddr5, testDestAddr5, testHopCount, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
            createRoute(testDestAddr6, testDestAddr6, testHopCount, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
            testHopCount++;
            return;
        }
    }

    /* Each method is modified */
    auto rreq = createRREQ(target);
    addressToRreqRetries[target] = 0;
    sendRREQ(rreq, testDestAddrController, 0);

#endif
}

#if 0
/* beratovic */
void Aodv::SDN_UpdateRoutingTable(/*const L3Address& destAddr, const L3Address& nextHop, unsigned int hopCount, bool hasValidDestNum, unsigned int destSeqNum,
                                  bool isActive, simtime_t lifeTime*/)
{
    unsigned int testHopCount = 0;
    L3Address testDestAddrController = L3Address(Ipv4Address(20,0,0,0)); /*CONTROLLER*/
    L3Address testDestAddr1 = L3Address(Ipv4Address(20,0,0,1));
    L3Address testDestAddr2 = L3Address(Ipv4Address(20,0,0,2));
    L3Address testDestAddr3 = L3Address(Ipv4Address(20,0,0,3));
    L3Address testDestAddr4 = L3Address(Ipv4Address(20,0,0,4));
    L3Address testDestAddr5 = L3Address(Ipv4Address(20,0,0,5));
    L3Address testDestAddr6 = L3Address(Ipv4Address(20,0,0,6));

    if(getSelfIPAddress() == testDestAddr1)
    {
        createRoute(testDestAddr4, testDestAddr2, testHopCount, false, 0, true, simTime()+50.0); /*ok*/
        testHopCount++;
    }
    else if(getSelfIPAddress() == testDestAddr2)
    {
        createRoute(testDestAddr4, testDestAddr6, testHopCount, false, 0, true, simTime()+50.0); /*ok*/
        testHopCount++;
    }
    else if(getSelfIPAddress() == testDestAddr3)
    {
        createRoute(testDestAddr4, testDestAddr5, testHopCount, false, 0, true, simTime()+50.0); /*ok*/
        testHopCount++;
    }
    else if(getSelfIPAddress() == testDestAddr4)
    {
       /*dest*/
    }
    else if(getSelfIPAddress() == testDestAddr5)
    {
        createRoute(testDestAddr4, testDestAddr1, testHopCount, false, 0, true, simTime()+50.0); /*ok*/
        testHopCount++;
    }
    else if(getSelfIPAddress() == testDestAddr6)
    {
        createRoute(testDestAddr4, testDestAddr4, testHopCount, false, 0, true, simTime()+50.0); /*ok*/
        testHopCount++;
    }
    else
    {
        EV_ERROR << "Bu nedir " << endl;
    }
}
#endif



L3Address Aodv::getSelfIPAddress() const
{
    return routingTable->getRouterIdAsGeneric();
}

void Aodv::delayDatagram(Packet *datagram)
{
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    EV_DETAIL << "Queuing datagram, source " << networkHeader->getSourceAddress() << ", destination " << networkHeader->getDestinationAddress() << endl;
    const L3Address& target = networkHeader->getDestinationAddress();
    targetAddressToDelayedPackets.insert(std::pair<L3Address, Packet *>(target, datagram));
}

void Aodv::sendRREQ(const Ptr<Rreq>& rreq, const L3Address& destAddr, unsigned int timeToLive)
{
#ifndef  CONTROLLER_MODE_ENABLED
    // In an expanding ring search, the originating node initially uses a TTL =
    // TTL_START in the RREQ packet IP header and sets the timeout for
    // receiving a RREP to RING_TRAVERSAL_TIME milliseconds.
    // RING_TRAVERSAL_TIME is calculated as described in section 10.  The
    // TTL_VALUE used in calculating RING_TRAVERSAL_TIME is set equal to the
    // value of the TTL field in the IP header.  If the RREQ times out
    // without a corresponding RREP, the originator broadcasts the RREQ
    // again with the TTL incremented by TTL_INCREMENT.  This continues
    // until the TTL set in the RREQ reaches TTL_THRESHOLD, beyond which a
    // TTL = NET_DIAMETER is used for each attempt.

    if (rreqCount >= rreqRatelimit) {
        EV_WARN << "A node should not originate more than RREQ_RATELIMIT RREQ messages per second. Canceling sending RREQ" << endl;
        return;
    }

    auto rrepTimer = waitForRREPTimers.find(rreq->getDestAddr());
    WaitForRrep *rrepTimerMsg = nullptr;
    if (rrepTimer != waitForRREPTimers.end()) {
        rrepTimerMsg = rrepTimer->second;
        unsigned int lastTTL = rrepTimerMsg->getLastTTL();
        rrepTimerMsg->setDestAddr(rreq->getDestAddr());

        // The Hop Count stored in an invalid routing table entry indicates the
        // last known hop count to that destination in the routing table.  When
        // a new route to the same destination is required at a later time
        // (e.g., upon route loss), the TTL in the RREQ IP header is initially
        // set to the Hop Count plus TTL_INCREMENT.  Thereafter, following each
        // timeout the TTL is incremented by TTL_INCREMENT until TTL =
        // TTL_THRESHOLD is reached.  Beyond this TTL = NET_DIAMETER is used.
        // Once TTL = NET_DIAMETER, the timeout for waiting for the RREP is set
        // to NET_TRAVERSAL_TIME, as specified in section 6.3.

        if (timeToLive != 0) {
            rrepTimerMsg->setLastTTL(timeToLive);
            rrepTimerMsg->setFromInvalidEntry(true);
            cancelEvent(rrepTimerMsg);
        }
        else if (lastTTL + ttlIncrement < ttlThreshold) {
            ASSERT(!rrepTimerMsg->isScheduled());
            timeToLive = lastTTL + ttlIncrement;
            rrepTimerMsg->setLastTTL(lastTTL + ttlIncrement);
        }
        else {
            ASSERT(!rrepTimerMsg->isScheduled());
            timeToLive = netDiameter;
            rrepTimerMsg->setLastTTL(netDiameter);
        }
    }
    else {
        rrepTimerMsg = new WaitForRrep();
        waitForRREPTimers[rreq->getDestAddr()] = rrepTimerMsg;
        ASSERT(hasOngoingRouteDiscovery(rreq->getDestAddr()));

        timeToLive = ttlStart;
        rrepTimerMsg->setLastTTL(ttlStart);
        rrepTimerMsg->setFromInvalidEntry(false);
        rrepTimerMsg->setDestAddr(rreq->getDestAddr());
    }

    // Each time, the timeout for receiving a RREP is RING_TRAVERSAL_TIME.
    simtime_t ringTraversalTime = 2.0 * nodeTraversalTime * (timeToLive + timeoutBuffer);
    scheduleAt(simTime() + ringTraversalTime, rrepTimerMsg);

    EV_INFO << "Sending a Route Request with target " << rreq->getDestAddr() << " and TTL= " << timeToLive << endl;
    sendAODVPacket(rreq, destAddr, timeToLive, *jitterPar);
    rreqCount++;
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    // In an expanding ring search, the originating node initially uses a TTL =
    // TTL_START in the RREQ packet IP header and sets the timeout for
    // receiving a RREP to RING_TRAVERSAL_TIME milliseconds.
    // RING_TRAVERSAL_TIME is calculated as described in section 10.  The
    // TTL_VALUE used in calculating RING_TRAVERSAL_TIME is set equal to the
    // value of the TTL field in the IP header.  If the RREQ times out
    // without a corresponding RREP, the originator broadcasts the RREQ
    // again with the TTL incremented by TTL_INCREMENT.  This continues
    // until the TTL set in the RREQ reaches TTL_THRESHOLD, beyond which a
    // TTL = NET_DIAMETER is used for each attempt.

    if (rreqCount >= rreqRatelimit) {
        EV_WARN << "A node should not originate more than RREQ_RATELIMIT RREQ messages per second. Canceling sending RREQ" << endl;
        return;
    }

    /* I am working with the same time parameters for controller and rreq*/
    auto rrepTimer = waitForRREPTimers.find(rreq->getDestAddr());
    WaitForRrep *rrepTimerMsg = nullptr;
    if (rrepTimer != waitForRREPTimers.end())
    {
        rrepTimerMsg = rrepTimer->second;
        unsigned int lastTTL = rrepTimerMsg->getLastTTL();
        rrepTimerMsg->setDestAddr(rreq->getDestAddr());

        // The Hop Count stored in an invalid routing table entry indicates the
        // last known hop count to that destination in the routing table.  When
        // a new route to the same destination is required at a later time
        // (e.g., upon route loss), the TTL in the RREQ IP header is initially
        // set to the Hop Count plus TTL_INCREMENT.  Thereafter, following each
        // timeout the TTL is incremented by TTL_INCREMENT until TTL =
        // TTL_THRESHOLD is reached.  Beyond this TTL = NET_DIAMETER is used.
        // Once TTL = NET_DIAMETER, the timeout for waiting for the RREP is set
        // to NET_TRAVERSAL_TIME, as specified in section 6.3.

        if (timeToLive != 0) {
            rrepTimerMsg->setLastTTL(timeToLive);
            rrepTimerMsg->setFromInvalidEntry(true);
            cancelEvent(rrepTimerMsg);
        }
        else if (lastTTL + ttlIncrement < ttlThreshold) {
            ASSERT(!rrepTimerMsg->isScheduled());
            timeToLive = lastTTL + ttlIncrement;
            rrepTimerMsg->setLastTTL(lastTTL + ttlIncrement);
        }
        else {
            ASSERT(!rrepTimerMsg->isScheduled());
            timeToLive = netDiameter;
            rrepTimerMsg->setLastTTL(netDiameter);
        }
    }
    else
    {
        rrepTimerMsg = new WaitForRrep();
        waitForRREPTimers[rreq->getDestAddr()] = rrepTimerMsg;
        ASSERT(hasOngoingRouteDiscovery(rreq->getDestAddr()));

        timeToLive = ttlStart;
        rrepTimerMsg->setLastTTL(ttlStart);
        rrepTimerMsg->setFromInvalidEntry(false);
        rrepTimerMsg->setDestAddr(rreq->getDestAddr());
    }

    // Each time, the timeout for receiving a RREP is RING_TRAVERSAL_TIME.
    simtime_t ringTraversalTime = 2.0 * nodeTraversalTime * (timeToLive + timeoutBuffer);
    scheduleAt(simTime() + ringTraversalTime, rrepTimerMsg);

    EV_INFO << "Sending a Route Request with target " << rreq->getDestAddr() << " and TTL= " << timeToLive << endl;
    sendAODVPacket(rreq, destAddr, timeToLive, /* *jitterPar */ 0.0, SENDER_IS_NODE, MESSAGE_TYPE_HELLO);
    rreqCount++;
#endif
}

void Aodv::sendRREP(const Ptr<Rrep>& rrep, const L3Address& destAddr, unsigned int timeToLive)
{
    EV_INFO << "Sending Route Reply to " << destAddr << endl;
#ifndef  CONTROLLER_MODE_ENABLED
    // When any node transmits a RREP, the precursor list for the
    // corresponding destination node is updated by adding to it
    // the next hop node to which the RREP is forwarded.

    IRoute *destRoute = routingTable->findBestMatchingRoute(destAddr);
    const L3Address& nextHop = destRoute->getNextHopAsGeneric();
    AodvRouteData *destRouteData = check_and_cast<AodvRouteData *>(destRoute->getProtocolData());
    destRouteData->addPrecursor(nextHop);

    // The node we received the Route Request for is our neighbor,
    // it is probably an unidirectional link
    if (destRoute->getMetric() == 1) {
        // It is possible that a RREP transmission may fail, especially if the
        // RREQ transmission triggering the RREP occurs over a unidirectional
        // link.

        rrep->setAckRequiredFlag(true);

        // when a node detects that its transmission of a RREP message has failed,
        // it remembers the next-hop of the failed RREP in a "blacklist" set.

        failedNextHop = nextHop;

        if (rrepAckTimer->isScheduled())
            cancelEvent(rrepAckTimer);

        scheduleAt(simTime() + nextHopWait, rrepAckTimer);
    }

    sendAODVPacket(rrep, nextHop, timeToLive, 0);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rrep, destAddr/*nextHop*/, timeToLive, 0, SENDER_IS_CONTROLLER, MESSAGE_TYPE_UNDEFINED);
#endif
}

const Ptr<Rreq> Aodv::createRREQ(const L3Address& destAddr)
{
#ifndef  CONTROLLER_MODE_ENABLED
    auto rreqPacket = makeShared<Rreq>(); // TODO: "AODV-RREQ");
    rreqPacket->setPacketType(usingIpv6 ? RREQ_IPv6 : RREQ);
    rreqPacket->setChunkLength(usingIpv6 ? B(48) : B(24));

    rreqPacket->setGratuitousRREPFlag(askGratuitousRREP);
    IRoute *lastKnownRoute = routingTable->findBestMatchingRoute(destAddr);

    // The Originator Sequence Number in the RREQ message is the
    // node's own sequence number, which is incremented prior to
    // insertion in a RREQ.
    sequenceNum++;

    rreqPacket->setOriginatorSeqNum(sequenceNum);

    if (lastKnownRoute && lastKnownRoute->getSource() == this) {
        // The Destination Sequence Number field in the RREQ message is the last
        // known destination sequence number for this destination and is copied
        // from the Destination Sequence Number field in the routing table.

        AodvRouteData *routeData = check_and_cast<AodvRouteData *>(lastKnownRoute->getProtocolData());
        if (routeData && routeData->hasValidDestNum()) {
            rreqPacket->setDestSeqNum(routeData->getDestSeqNum());
            rreqPacket->setUnknownSeqNumFlag(false);
        }
        else
            rreqPacket->setUnknownSeqNumFlag(true);
    }
    else
        rreqPacket->setUnknownSeqNumFlag(true); // If no sequence number is known, the unknown sequence number flag MUST be set.

    rreqPacket->setOriginatorAddr(getSelfIPAddress());
    rreqPacket->setDestAddr(destAddr);

    // The RREQ ID field is incremented by one from the last RREQ ID used
    // by the current node. Each node maintains only one RREQ ID.
    rreqId++;
    rreqPacket->setRreqId(rreqId);

    // The Hop Count field is set to zero.
    rreqPacket->setHopCount(0);

    // Destination only flag (D) indicates that only the
    // destination may respond to this RREQ.
    rreqPacket->setDestOnlyFlag(destinationOnlyFlag);

    // Before broadcasting the RREQ, the originating node buffers the RREQ
    // ID and the Originator IP address (its own address) of the RREQ for
    // PATH_DISCOVERY_TIME.
    // In this way, when the node receives the packet again from its neighbors,
    // it will not reprocess and re-forward the packet.

    RreqIdentifier rreqIdentifier(getSelfIPAddress(), rreqId);
    rreqsArrivalTime[rreqIdentifier] = simTime();
    return rreqPacket;
#endif


#ifdef  CONTROLLER_MODE_ENABLED
    auto rreqPacket = makeShared<Rreq>(); // TODO: "AODV-RREQ");
    rreqPacket->setPacketType(usingIpv6 ? RREQ_IPv6 : RREQ);        //TODO : CONTROLLER_ROUTEREQ
    rreqPacket->setChunkLength(usingIpv6 ? B(48) : B(24));          //TODO : Always ipv4

    rreqPacket->setOriginatorAddr(getSelfIPAddress());
    rreqPacket->setDestAddr(destAddr);

    /*always 0 for now*/
    rreqPacket->setRreqId(/*rreqId*/ 0 );

    // The Hop Count field is set to zero.
    rreqPacket->setHopCount(0);

    // Destination only flag (D) indicates that only the
    // destination may respond to this RREQ.
    rreqPacket->setDestOnlyFlag(/*destinationOnlyFlag*/ true);

    return rreqPacket;
#endif
}
#ifndef  CONTROLLER_MODE_ENABLED
const Ptr<Rrep> Aodv::createRREP(const Ptr<Rreq>& rreq, IRoute *destRoute, IRoute *originatorRoute, const L3Address& lastHopAddr)
{
    auto rrep = makeShared<Rrep>(); // TODO: "AODV-RREP");
    rrep->setPacketType(usingIpv6 ? RREP_IPv6 : RREP);
    rrep->setChunkLength(usingIpv6 ? B(44) : B(20));

    // When generating a RREP message, a node copies the Destination IP
    // Address and the Originator Sequence Number from the RREQ message into
    // the corresponding fields in the RREP message.

    rrep->setDestAddr(rreq->getDestAddr());

    // OriginatorAddr = The IP address of the node which originated the RREQ
    // for which the route is supplied.
    rrep->setOriginatorAddr(rreq->getOriginatorAddr());

    // Processing is slightly different, depending on whether the node is
    // itself the requested destination (see section 6.6.1), or instead
    // if it is an intermediate node with an fresh enough route to the destination
    // (see section 6.6.2).

    if (rreq->getDestAddr() == getSelfIPAddress()) {    // node is itself the requested destination
        // 6.6.1. Route Reply Generation by the Destination

        // If the generating node is the destination itself, it MUST increment
        // its own sequence number by one if the sequence number in the RREQ
        // packet is equal to that incremented value.

        if (!rreq->getUnknownSeqNumFlag() && sequenceNum + 1 == rreq->getDestSeqNum())
            sequenceNum++;

        // The destination node places its (perhaps newly incremented)
        // sequence number into the Destination Sequence Number field of
        // the RREP,
        rrep->setDestSeqNum(sequenceNum);

        // and enters the value zero in the Hop Count field
        // of the RREP.
        rrep->setHopCount(0);

        // The destination node copies the value MY_ROUTE_TIMEOUT
        // into the Lifetime field of the RREP.
        rrep->setLifeTime(myRouteTimeout.trunc(SIMTIME_MS));
    }
    else {    // intermediate node
        // 6.6.2. Route Reply Generation by an Intermediate Node

        // it copies its known sequence number for the destination into
        // the Destination Sequence Number field in the RREP message.
        AodvRouteData *destRouteData = check_and_cast<AodvRouteData *>(destRoute->getProtocolData());
        AodvRouteData *originatorRouteData = check_and_cast<AodvRouteData *>(originatorRoute->getProtocolData());
        rrep->setDestSeqNum(destRouteData->getDestSeqNum());

        // The intermediate node updates the forward route entry by placing the
        // last hop node (from which it received the RREQ, as indicated by the
        // source IP address field in the IP header) into the precursor list for
        // the forward route entry -- i.e., the entry for the Destination IP
        // Address.
        destRouteData->addPrecursor(lastHopAddr);

        // The intermediate node also updates its route table entry
        // for the node originating the RREQ by placing the next hop towards the
        // destination in the precursor list for the reverse route entry --
        // i.e., the entry for the Originator IP Address field of the RREQ
        // message data.

        originatorRouteData->addPrecursor(destRoute->getNextHopAsGeneric());

        // The intermediate node places its distance in hops from the
        // destination (indicated by the hop count in the routing table)
        // Hop Count field in the RREP.

        rrep->setHopCount(destRoute->getMetric());

        // The Lifetime field of the RREP is calculated by subtracting the
        // current time from the expiration time in its route table entry.

        rrep->setLifeTime((destRouteData->getLifeTime() - simTime()).trunc(SIMTIME_MS));
    }

    return rrep;
}
#endif
#ifdef  CONTROLLER_MODE_ENABLED
const Ptr<Rrep> Aodv::createRREP(const Ptr<Rreq>& rreq, const L3Address& sourceAddr)
{
    auto rrep = makeShared<Rrep>(); // TODO: "AODV-RREP");
    rrep->setPacketType(usingIpv6 ? RREP_IPv6 : RREP);
    rrep->setChunkLength(usingIpv6 ? B(44) : B(20));

    // When generating a RREP message, a node copies the Destination IP
    // Address and the Originator Sequence Number from the RREQ message into
    // the corresponding fields in the RREP message.

    rrep->setDestAddr(rreq->getDestAddr());

    // OriginatorAddr = The IP address of the node which originated the RREQ
    // for which the route is supplied.
    rrep->setOriginatorAddr(rreq->getOriginatorAddr());

    // Processing is slightly different, depending on whether the node is
    // itself the requested destination (see section 6.6.1), or instead
    // if it is an intermediate node with an fresh enough route to the destination
    // (see section 6.6.2).

    if (rreq->getDestAddr() == getSelfIPAddress()) {    // node is itself the requested destination
        // 6.6.1. Route Reply Generation by the Destination

        // If the generating node is the destination itself, it MUST increment
        // its own sequence number by one if the sequence number in the RREQ
        // packet is equal to that incremented value.

        if (!rreq->getUnknownSeqNumFlag() && sequenceNum + 1 == rreq->getDestSeqNum())
            sequenceNum++;

        // The destination node places its (perhaps newly incremented)
        // sequence number into the Destination Sequence Number field of
        // the RREP,
        rrep->setDestSeqNum(sequenceNum);

        // and enters the value zero in the Hop Count field
        // of the RREP.
        rrep->setHopCount(0);

        // The destination node copies the value MY_ROUTE_TIMEOUT
        // into the Lifetime field of the RREP.
        rrep->setLifeTime(myRouteTimeout.trunc(SIMTIME_MS));
    }
    else {
#if 0
        // intermediate node
        // 6.6.2. Route Reply Generation by an Intermediate Node

        // it copies its known sequence number for the destination into
        // the Destination Sequence Number field in the RREP message.
        AodvRouteData *destRouteData = check_and_cast<AodvRouteData *>(destRoute->getProtocolData());
        AodvRouteData *originatorRouteData = check_and_cast<AodvRouteData *>(originatorRoute->getProtocolData());
        rrep->setDestSeqNum(destRouteData->getDestSeqNum());

        // The intermediate node updates the forward route entry by placing the
        // last hop node (from which it received the RREQ, as indicated by the
        // source IP address field in the IP header) into the precursor list for
        // the forward route entry -- i.e., the entry for the Destination IP
        // Address.
        destRouteData->addPrecursor(lastHopAddr);

        // The intermediate node also updates its route table entry
        // for the node originating the RREQ by placing the next hop towards the
        // destination in the precursor list for the reverse route entry --
        // i.e., the entry for the Originator IP Address field of the RREQ
        // message data.

        originatorRouteData->addPrecursor(destRoute->getNextHopAsGeneric());

        // The intermediate node places its distance in hops from the
        // destination (indicated by the hop count in the routing table)
        // Hop Count field in the RREP.

        rrep->setHopCount(destRoute->getMetric());

        // The Lifetime field of the RREP is calculated by subtracting the
        // current time from the expiration time in its route table entry.

        rrep->setLifeTime((destRouteData->getLifeTime() - simTime()).trunc(SIMTIME_MS));
#endif
    }

    return rrep;
}
#endif




const Ptr<Rrep> Aodv::createGratuitousRREP(const Ptr<Rreq>& rreq, IRoute *originatorRoute)
{
    ASSERT(originatorRoute != nullptr);
    auto grrep = makeShared<Rrep>(); // TODO: "AODV-GRREP");
    grrep->setPacketType(usingIpv6 ? RREP_IPv6 : RREP);
    grrep->setChunkLength(usingIpv6 ? B(44) : B(20));

    AodvRouteData *routeData = check_and_cast<AodvRouteData *>(originatorRoute->getProtocolData());

    // Hop Count                        The Hop Count as indicated in the
    //                                  node's route table entry for the
    //                                  originator
    //
    // Destination IP Address           The IP address of the node that
    //                                  originated the RREQ
    //
    // Destination Sequence Number      The Originator Sequence Number from
    //                                  the RREQ
    //
    // Originator IP Address            The IP address of the Destination
    //                                  node in the RREQ
    //
    // Lifetime                         The remaining lifetime of the route
    //                                  towards the originator of the RREQ,
    //                                  as known by the intermediate node.

    grrep->setHopCount(originatorRoute->getMetric());
    grrep->setDestAddr(rreq->getOriginatorAddr());
    grrep->setDestSeqNum(rreq->getOriginatorSeqNum());
    grrep->setOriginatorAddr(rreq->getDestAddr());
    grrep->setLifeTime(routeData->getLifeTime());
    return grrep;
}

#ifndef  CONTROLLER_MODE_ENABLED
void Aodv::handleRREP(const Ptr<Rrep>& rrep, const L3Address& sourceAddr)
{
    // 6.7. Receiving and Forwarding Route Replies

    EV_INFO << "AODV Route Reply arrived with source addr: " << sourceAddr << " originator addr: " << rrep->getOriginatorAddr()
            << " destination addr: " << rrep->getDestAddr() << endl;

    if (rrep->getOriginatorAddr().isUnspecified()) {
        EV_INFO << "This Route Reply is a Hello Message" << endl;
        handleHelloMessage(rrep);
        return;
    }
    // When a node receives a RREP message, it searches (using longest-
    // prefix matching) for a route to the previous hop.

    // If needed, a route is created for the previous hop,
    // but without a valid sequence number (see section 6.2)

    IRoute *previousHopRoute = routingTable->findBestMatchingRoute(sourceAddr);

    if (!previousHopRoute || previousHopRoute->getSource() != this) {
        // create without valid sequence number
        previousHopRoute = createRoute(sourceAddr, sourceAddr, 1, false, rrep->getDestSeqNum(), true, simTime() + activeRouteTimeout);
    }
    else
        updateRoutingTable(previousHopRoute, sourceAddr, 1, false, rrep->getDestSeqNum(), true, simTime() + activeRouteTimeout);

    // Next, the node then increments the hop count value in the RREP by one,
    // to account for the new hop through the intermediate node
    unsigned int newHopCount = rrep->getHopCount() + 1;
    rrep->setHopCount(newHopCount);

    // Then the forward route for this destination is created if it does not
    // already exist.

    IRoute *destRoute = routingTable->findBestMatchingRoute(rrep->getDestAddr());
    AodvRouteData *destRouteData = nullptr;
    simtime_t lifeTime = rrep->getLifeTime();
    unsigned int destSeqNum = rrep->getDestSeqNum();

    if (destRoute && destRoute->getSource() == this) {    // already exists
        destRouteData = check_and_cast<AodvRouteData *>(destRoute->getProtocolData());
        // Upon comparison, the existing entry is updated only in the following circumstances:

        // (i) the sequence number in the routing table is marked as
        //     invalid in route table entry.

        if (!destRouteData->hasValidDestNum()) {
            updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);

            // If the route table entry to the destination is created or updated,
            // then the following actions occur:
            //
            // -  the route is marked as active,
            //
            // -  the destination sequence number is marked as valid,
            //
            // -  the next hop in the route entry is assigned to be the node from
            //    which the RREP is received, which is indicated by the source IP
            //    address field in the IP header,
            //
            // -  the hop count is set to the value of the New Hop Count,
            //
            // -  the expiry time is set to the current time plus the value of the
            //    Lifetime in the RREP message,
            //
            // -  and the destination sequence number is the Destination Sequence
            //    Number in the RREP message.
        }
        // (ii) the Destination Sequence Number in the RREP is greater than
        //      the node's copy of the destination sequence number and the
        //      known value is valid, or
        else if (destSeqNum > destRouteData->getDestSeqNum()) {
            updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
        }
        else {
            // (iii) the sequence numbers are the same, but the route is
            //       marked as inactive, or
            if (destSeqNum == destRouteData->getDestSeqNum() && !destRouteData->isActive()) {
                updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
            }
            // (iv) the sequence numbers are the same, and the New Hop Count is
            //      smaller than the hop count in route table entry.
            else if (destSeqNum == destRouteData->getDestSeqNum() && newHopCount < (unsigned int)destRoute->getMetric()) {
                updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
            }
        }
    }
    else {    // create forward route for the destination: this path will be used by the originator to send data packets
        destRoute = createRoute(rrep->getDestAddr(), sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
        destRouteData = check_and_cast<AodvRouteData *>(destRoute->getProtocolData());
    }

    // If the current node is not the node indicated by the Originator IP
    // Address in the RREP message AND a forward route has been created or
    // updated as described above, the node consults its route table entry
    // for the originating node to determine the next hop for the RREP
    // packet, and then forwards the RREP towards the originator using the
    // information in that route table entry.

    IRoute *originatorRoute = routingTable->findBestMatchingRoute(rrep->getOriginatorAddr());
    if (getSelfIPAddress() != rrep->getOriginatorAddr()) {
        // If a node forwards a RREP over a link that is likely to have errors or
        // be unidirectional, the node SHOULD set the 'A' flag to require that the
        // recipient of the RREP acknowledge receipt of the RREP by sending a RREP-ACK
        // message back (see section 6.8).

        if (originatorRoute && originatorRoute->getSource() == this) {
            AodvRouteData *originatorRouteData = check_and_cast<AodvRouteData *>(originatorRoute->getProtocolData());

            // Also, at each node the (reverse) route used to forward a
            // RREP has its lifetime changed to be the maximum of (existing-
            // lifetime, (current time + ACTIVE_ROUTE_TIMEOUT).

            simtime_t existingLifeTime = originatorRouteData->getLifeTime();
            originatorRouteData->setLifeTime(std::max(simTime() + activeRouteTimeout, existingLifeTime));

            if (simTime() > rebootTime + deletePeriod || rebootTime == 0) {
                // If a node forwards a RREP over a link that is likely to have errors
                // or be unidirectional, the node SHOULD set the 'A' flag to require that
                // the recipient of the RREP acknowledge receipt of the RREP by sending a
                // RREP-ACK message back (see section 6.8).

                if (rrep->getAckRequiredFlag()) {
                    auto rrepACK = createRREPACK();
                    sendRREPACK(rrepACK, sourceAddr);
                    rrep->setAckRequiredFlag(false);
                }

                // When any node transmits a RREP, the precursor list for the
                // corresponding destination node is updated by adding to it
                // the next hop node to which the RREP is forwarded.

                destRouteData->addPrecursor(originatorRoute->getNextHopAsGeneric());

                // Finally, the precursor list for the next hop towards the
                // destination is updated to contain the next hop towards the
                // source (originator).

                IRoute *nextHopToDestRoute = routingTable->findBestMatchingRoute(destRoute->getNextHopAsGeneric());
                if (nextHopToDestRoute && nextHopToDestRoute->getSource() == this) {
                    AodvRouteData *nextHopToDestRouteData = check_and_cast<AodvRouteData *>(nextHopToDestRoute->getProtocolData());
                    nextHopToDestRouteData->addPrecursor(originatorRoute->getNextHopAsGeneric());
                }
                auto outgoingRREP = dynamicPtrCast<Rrep>(rrep->dupShared());
                forwardRREP(outgoingRREP, originatorRoute->getNextHopAsGeneric(), 100);
            }
        }
        else
            EV_ERROR << "Reverse route doesn't exist. Dropping the RREP message" << endl;
    }
    else {
        if (hasOngoingRouteDiscovery(rrep->getDestAddr())) {
            EV_INFO << "The Route Reply has arrived for our Route Request to node " << rrep->getDestAddr() << endl;
            updateRoutingTable(destRoute, sourceAddr, newHopCount, true, destSeqNum, true, simTime() + lifeTime);
            completeRouteDiscovery(rrep->getDestAddr());
        }
    }
}
#endif
#ifdef  CONTROLLER_MODE_ENABLED
void Aodv::handleRREP(const Ptr<Rrep>& rrep, const L3Address& sourceAddr,unsigned int destinationHop, unsigned int nextHop)
{
    L3Address testDestNext = L3Address(Ipv4Address(20,0,0,nextHop));

    switch (destinationHop)
    {
        /*beratovic TODO: ben kimin hangi adrese sahip olduðunu þuanda biliyorum. demo sonrasýnda bütün bu çalýþmalar genelleþtirilmeli. */
        case 4:
        {
            createRoute(testDestAddr4, testDestNext, 0/*testHopCount*/, false, 0, true, simTime()+11.0); /*beratovic TODO: 11.0 deðeri, kontrolcü tarafýndan belirlenmeli*/
        }
        default:
            break;
    }
}
#endif

void Aodv::updateRoutingTable(IRoute *route, const L3Address& nextHop, unsigned int hopCount, bool hasValidDestNum, unsigned int destSeqNum, bool isActive, simtime_t lifeTime)
{
    EV_DETAIL << "Updating existing route: " << route << endl;
#ifdef  CONTROLLER_MODE_ENABLED
    if(simTime() > simtime_t(14.5))
    {
        return;
    }
#endif
    route->setNextHop(nextHop);
    route->setMetric(hopCount);
    AodvRouteData *routingData = check_and_cast<AodvRouteData *>(route->getProtocolData());

    ASSERT(routingData != nullptr);

    routingData->setLifeTime(lifeTime);
    routingData->setDestSeqNum(destSeqNum);
    routingData->setIsActive(isActive);
    routingData->setHasValidDestNum(hasValidDestNum);

    EV_DETAIL << "Route updated: " << route << endl;

    scheduleExpungeRoutes();
}


#ifdef CONTROLLER_MODE_ENABLED
/*Declared since AODV default function had been disabled! This function must be used whenever user want to update routing tables!*/
void Aodv::updateRoutingTableSDNSpecific(IRoute *route, const L3Address& nextHop, unsigned int hopCount, bool hasValidDestNum, unsigned int destSeqNum, bool isActive, simtime_t lifeTime)
{
    route->setNextHop(nextHop);
    route->setMetric(hopCount);
    AodvRouteData *routingData = check_and_cast<AodvRouteData *>(route->getProtocolData());


    ASSERT(routingData != nullptr);

    routingData->setLifeTime(lifeTime);
    routingData->setDestSeqNum(destSeqNum);
    routingData->setIsActive(isActive);
    routingData->setHasValidDestNum(hasValidDestNum);

    scheduleExpungeRoutes();
}

#endif








#ifndef  CONTROLLER_MODE_ENABLED
void Aodv::sendAODVPacket(const Ptr<AodvControlPacket>& aodvPacket, const L3Address& destAddr, unsigned int timeToLive, double delay)
{
    ASSERT(timeToLive != 0);

    const char *className = aodvPacket->getClassName();
    Packet *packet = new Packet(!strncmp("inet::", className, 6) ? className + 6 : className);
    packet->insertAtBack(aodvPacket);

    int interfaceId = CHK(interfaceTable->findInterfaceByName(par("interface")))->getInterfaceId(); // TODO: Implement: support for multiple interfaces
    packet->addTag<InterfaceReq>()->setInterfaceId(interfaceId);
    packet->addTag<HopLimitReq>()->setHopLimit(timeToLive);
    packet->addTag<L3AddressReq>()->setDestAddress(destAddr);
    packet->addTag<L4PortReq>()->setDestPort(aodvUDPPort);

    if (destAddr.isBroadcast())
        lastBroadcastTime = simTime();

    if (delay == 0)
        socket.send(packet);
    else
    {
        auto *timer = new PacketHolderMessage("aodv-send-jitter", KIND_DELAYEDSEND);
        timer->setOwnedPacket(packet);
        scheduleAt(simTime()+delay, timer);
    }
}
#endif

#ifdef  CONTROLLER_MODE_ENABLED
void Aodv::sendAODVPacket(const Ptr<AodvControlPacket>& aodvPacket, const L3Address& destAddr, unsigned int timeToLive, double delay, SDN_CONTROLLER_SENDER_TYPE senderType, SDN_CONTROLLER_MESSAGE_TYPE msgType)
{
    ASSERT(timeToLive != 0);

    const char *className = aodvPacket->getClassName();
    Packet *packet = new Packet(!strncmp("inet::", className, 6) ? className + 6 : className);
    packet->insertAtBack(aodvPacket);

    int interfaceId = CHK(interfaceTable->findInterfaceByName(par("interface")))->getInterfaceId(); // TODO: Implement: support for multiple interfaces
    packet->addTag<InterfaceReq>()->setInterfaceId(interfaceId);
    packet->addTag<HopLimitReq>()->setHopLimit(timeToLive);
    packet->addTag<L3AddressReq>()->setDestAddress(destAddr);
    packet->addTag<L4PortReq>()->setDestPort(aodvUDPPort);

    /* 18.05.2021: ileride burasý kalkacak. þimdilik tüm gelen istekler route requestmiþ gibi iþleme alýnýyor, deneme amaçlý.*/
    /* 18.09.2021: hello mesajlarý(1) ilk 2 saniye, diðerleri route request(0) olarak nitelendirilecek */
    unsigned int controllerRequestType = 0;

    OPENFLOW_HELLO_PACKET_EXTENDED_CONTENT_STRUCT nodeSpecificHelloMessage; /*will be used in case of HELLO Message transfer*/
    OPENFLOW_ERROR_MSG_STRUCT nodeSpecificErrMsg; /*will be used in case of ERROR Message transfer*/

    switch (senderType)
    {
        case SENDER_IS_CONTROLLER:
        {
            auto replyRouteMsg = makeShared<BytesChunk>();
               switch (controllerRequestType)
               {
                    /* Paket kimden geliyor ise ona geri gönderileceði için destAddr ile source address ayný olacaktýr. (Route isteðinin Source'dan geldiði biliniyor)
                    * Bu assumption'ýn sebebi destinationOnlyFlag'ýn direkt 1 olarak set edilmesi: line 674*/

                   /* Henüz sendAODVPacket() kullanmadýðým için burada tablolarý statik yüklüyorum.  */
                   /* Paket gönderecek olsam tüm birimler controller node'a paket gönderirlerdi (rreeq - rrep mantýðý). Routing table'larý bu þekilde güncellenmeliydi.*/
                   case 0: /* let 0 be the route request */
                   {
                       if(destAddr == testDestAddr1)
                       {
                           //createRoute(testDestAddr4/*destination addr*/, testDestAddr2/*next hop addr*/, testHopCount, false, 0, true, simTime()+50.0);
                           replyRouteMsg->setBytes({0,0,0,0,0,0,0,0,testDestAddr1_Destination_Index,testDestAddr1_NextHop_Index}); /*4'e 2 üzerinden gidilecek*/
                           packet->insertAtBack(replyRouteMsg);
                       }
                       else if(destAddr == testDestAddr2)
                       {
                           //createRoute(testDestAddr4, testDestAddr6, testHopCount, false, 0, true, simTime()+50.0); /*ok*/
                           replyRouteMsg->setBytes({0,0,0,0,0,0,0,0,testDestAddr2_Destination_Index,testDestAddr2_NextHop_Index});/*4'e 6 üzerinden gidilecek*/
                           packet->insertAtBack(replyRouteMsg);
                       }
                       else if(destAddr == testDestAddr3)
                       {
                           //createRoute(testDestAddr4, testDestAddr5, testHopCount, false, 0, true, simTime()+50.0); /*ok*/
                           //replyRouteMsg->setBytes({0,0,0,0,0,0,0,0,4,5});
                           replyRouteMsg->setBytes({0,0,0,0,0,0,0,0,testDestAddr3_Destination_Index,testDestAddr3_NextHop_Index});/*4'e 4 üzerinden gidilecek -> direkt gidilebilir*/
                           packet->insertAtBack(replyRouteMsg);
                       }
                       else if(destAddr == testDestAddr4)
                       {
                          /*dest*/
                           //replyRouteMsg->setBytes({0,0,0,0,0,0,0,0,0,0});
                           replyRouteMsg->setBytes({9,9,9,9,9,9,9,9,testDestAddr4_Destination_Index,testDestAddr4_NextHop_Index});
                           packet->insertAtBack(replyRouteMsg);
                           /*when nothing is set, line 162 gives error*/
                       }
                       else if(destAddr == testDestAddr5)
                       {
                           //createRoute(testDestAddr4, testDestAddr1, testHopCount, false, 0, true, simTime()+50.0); /*ok*/
                           replyRouteMsg->setBytes({0,0,0,0,0,0,0,0,testDestAddr5_Destination_Index,testDestAddr5_NextHop_Index});/*4'e 1 üzerinden gidilecek*/
                           packet->insertAtBack(replyRouteMsg);
                       }
                       else if(destAddr == testDestAddr6)
                       {
                           //createRoute(testDestAddr4, testDestAddr4, testHopCount, false, 0, true, simTime()+50.0); /*ok*/
                           replyRouteMsg->setBytes({0,0,0,0,0,0,0,0,testDestAddr6_Destination_Index,testDestAddr6_NextHop_Index});/*4'e 4 üzerinden gidilecek*/
                           packet->insertAtBack(replyRouteMsg);
                       }
                       else if(destAddr == testDestAddrController)
                       {
                           /*Controller loopback, this case should be prevented. Controller için farklý mekanizma düþünülecek ilerde*/
                           replyRouteMsg->setBytes({0,0,0,0,0,0,0,0,testDestAddrController_Destination_Index,testDestAddrController_NextHop_Index});
                           packet->insertAtBack(replyRouteMsg);
                       }
                       break;
                   }
                   default:
                   {
                       break;
                   }
               }
            break;
        }
        case SENDER_IS_NODE:
        {
            switch (msgType)
            {
                /* Hello messages */
                case MESSAGE_TYPE_HELLO:
                {
                    /*First fill header and other contents */
                    nodeSpecificHelloMessage.helloMsg.header.version = OFP_VERSION_FANET_v_0;
                    nodeSpecificHelloMessage.helloMsg.header.type = OFPT_HELLO;
                    nodeSpecificHelloMessage.helloMsg.header.xid = UNKNOWN_INDEX;
                    nodeSpecificHelloMessage.helloMsg.header.length = 10; /* 10 byte header length - Design consideration */
                    nodeSpecificHelloMessage.helloMsg.mobilityType = SDN_MOBILITY_TYPE_NONSENSE;
                    nodeSpecificHelloMessage.helloMsg.reqType = OPENFLOW_REQUEST_TYPE_NO_REQUEST;
                    nodeSpecificHelloMessage.datapath_id = UNKNOWN_INDEX;
                    nodeSpecificHelloMessage.n_tables = 1; /*1 tablo düþünüyorum þimdilik - Design consideration*/
                    nodeSpecificHelloMessage.capabilities = UNKNOWN_INDEX;

                    if((getSelfIPAddress() == testDestAddr1)/*A node*/)
                    {
                        nodeSpecificHelloMessage.helloMsg.nodeId = NODE_A_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr2)  /*B node*/)
                    {
                        nodeSpecificHelloMessage.helloMsg.nodeId = NODE_B_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr3)  /*S node*/)
                    {
                        nodeSpecificHelloMessage.helloMsg.nodeId = NODE_SOURCE_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr4) /*D node*/)
                    {
                        nodeSpecificHelloMessage.helloMsg.nodeId = NODE_DESTINATION_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr5)  /*E node*/)
                    {
                        nodeSpecificHelloMessage.helloMsg.nodeId = NODE_E_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr6)  /*F node*/)
                    {
                        nodeSpecificHelloMessage.helloMsg.nodeId = NODE_F_NODE_NUMBER_DEF;
                    }
                    else /*Not supported*/
                    {
                        nodeSpecificHelloMessage.helloMsg.nodeId = UNKNOWN_INDEX;
                    }

                    auto rawBytesData = makeShared<BytesChunk>(); // 10 raw bytes
                    /*Filling Hello message content*/
                    rawBytesData->setBytes({nodeSpecificHelloMessage.helloMsg.header.version,
                                            nodeSpecificHelloMessage.helloMsg.header.type, /*DO NOT CHANGE HEADER.TYPE ORDER*/
                                            nodeSpecificHelloMessage.helloMsg.header.xid,
                                            nodeSpecificHelloMessage.helloMsg.header.length,
                                            nodeSpecificHelloMessage.helloMsg.mobilityType,
                                            nodeSpecificHelloMessage.helloMsg.reqType,
                                            nodeSpecificHelloMessage.datapath_id,
                                            nodeSpecificHelloMessage.n_tables,
                                            nodeSpecificHelloMessage.capabilities,
                                            nodeSpecificHelloMessage.helloMsg.nodeId});
                    packet->insertAtBack(rawBytesData);
                    break;
                }

                /* Error messages */
                case MESSAGE_TYPE_ERROR:
                {
                    nodeSpecificErrMsg.header.length = 6; /*6 byte header length*/
                    nodeSpecificErrMsg.header.type = OFPT_ERROR;
                    nodeSpecificErrMsg.header.version = OFP_VERSION_FANET_v_0;
                    nodeSpecificErrMsg.header.xid = UNKNOWN_INDEX;
                    nodeSpecificErrMsg.errMsgContent = OPENFLOW_ERROR_MALFORMED_PACKET; /* It is fixed for now! User can change it according to the design decision */
                    if((getSelfIPAddress() == testDestAddr1)/*A node*/)
                    {
                        nodeSpecificErrMsg.nodeId = NODE_A_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr2)  /*B node*/)
                    {
                        nodeSpecificErrMsg.nodeId = NODE_B_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr3)  /*S node*/)
                    {
                        nodeSpecificErrMsg.nodeId = NODE_SOURCE_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr4) /*D node*/)
                    {
                        nodeSpecificErrMsg.nodeId = NODE_DESTINATION_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr5)  /*E node*/)
                    {
                        nodeSpecificErrMsg.nodeId = NODE_E_NODE_NUMBER_DEF;
                    }
                    else if((getSelfIPAddress() == testDestAddr6)  /*F node*/)
                    {
                        nodeSpecificErrMsg.nodeId = NODE_F_NODE_NUMBER_DEF;
                    }
                    else /*Not supported*/
                    {
                        nodeSpecificErrMsg.nodeId = UNKNOWN_INDEX;
                    }
                    auto rawBytesDataErr = makeShared<BytesChunk>();
                    /*Filling Error message content*/
                    rawBytesDataErr->setBytes({nodeSpecificErrMsg.header.length,
                                                nodeSpecificErrMsg.header.type, /*DO NOT CHANGE HEADER.TYPE ORDER*/
                                                nodeSpecificErrMsg.header.version,
                                                nodeSpecificErrMsg.header.xid,
                                                nodeSpecificErrMsg.errMsgContent,
                                                nodeSpecificErrMsg.nodeId});
                    packet->insertAtBack(rawBytesDataErr);
                    break;
                }
                default:
                {
                    /* This part for the route request */
                    auto rawBytesDataR = makeShared<BytesChunk>(); // 10 raw bytes
                    /*Filling Hello message content*/
                    rawBytesDataR->setBytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 0}); /* buraya route request mesajý girilecek. for now, it is dummy sequence */
                    packet->insertAtBack(rawBytesDataR);
                    /* beratovic */
                    break;
                }
            break;
            }
        break;
        }

        default:
        {
            /*Others are not defined*/
            break;
        }
    }
    socket.send(packet);
}
#endif

void Aodv::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    // process incoming packet
    processPacket(packet);
}

void Aodv::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void Aodv::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

#ifndef  CONTROLLER_MODE_ENABLED
void Aodv::handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive)
{
    EV_INFO << "AODV Route Request arrived with source addr: " << sourceAddr << " originator addr: " << rreq->getOriginatorAddr()
            << " destination addr: " << rreq->getDestAddr() << endl;

    // A node ignores all RREQs received from any node in its blacklist set.

    auto blackListIt = blacklist.find(sourceAddr);
    if (blackListIt != blacklist.end()) {
        EV_INFO << "The sender node " << sourceAddr << " is in our blacklist. Ignoring the Route Request" << endl;
        return;
    }

    // When a node receives a RREQ, it first creates or updates a route to
    // the previous hop without a valid sequence number (see section 6.2).

    IRoute *previousHopRoute = routingTable->findBestMatchingRoute(sourceAddr);

    if (!previousHopRoute || previousHopRoute->getSource() != this) {
        // create without valid sequence number
        previousHopRoute = createRoute(sourceAddr, sourceAddr, 1, false, rreq->getOriginatorSeqNum(), true, simTime() + activeRouteTimeout);
    }
    else
        updateRoutingTable(previousHopRoute, sourceAddr, 1, false, rreq->getOriginatorSeqNum(), true, simTime() + activeRouteTimeout);

    // then checks to determine whether it has received a RREQ with the same
    // Originator IP Address and RREQ ID within at least the last PATH_DISCOVERY_TIME.
    // If such a RREQ has been received, the node silently discards the newly received RREQ.

    RreqIdentifier rreqIdentifier(rreq->getOriginatorAddr(), rreq->getRreqId());
    auto checkRREQArrivalTime = rreqsArrivalTime.find(rreqIdentifier);
    if (checkRREQArrivalTime != rreqsArrivalTime.end() && simTime() - checkRREQArrivalTime->second <= pathDiscoveryTime) {
        EV_WARN << "The same packet has arrived within PATH_DISCOVERY_TIME= " << pathDiscoveryTime << ". Discarding it" << endl;
        return;
    }

    // update or create
    rreqsArrivalTime[rreqIdentifier] = simTime();

    // First, it first increments the hop count value in the RREQ by one, to
    // account for the new hop through the intermediate node.

    rreq->setHopCount(rreq->getHopCount() + 1);

    // Then the node searches for a reverse route to the Originator IP Address (see
    // section 6.2), using longest-prefix matching.

    IRoute *reverseRoute = routingTable->findBestMatchingRoute(rreq->getOriginatorAddr());

    // If need be, the route is created, or updated using the Originator Sequence Number from the
    // RREQ in its routing table.
    //
    // When the reverse route is created or updated, the following actions on
    // the route are also carried out:
    //
    //   1. the Originator Sequence Number from the RREQ is compared to the
    //      corresponding destination sequence number in the route table entry
    //      and copied if greater than the existing value there
    //
    //   2. the valid sequence number field is set to true;
    //
    //   3. the next hop in the routing table becomes the node from which the
    //      RREQ was received (it is obtained from the source IP address in
    //      the IP header and is often not equal to the Originator IP Address
    //      field in the RREQ message);
    //
    //   4. the hop count is copied from the Hop Count in the RREQ message;
    //
    //   Whenever a RREQ message is received, the Lifetime of the reverse
    //   route entry for the Originator IP address is set to be the maximum of
    //   (ExistingLifetime, MinimalLifetime), where
    //
    //   MinimalLifetime = (current time + 2*NET_TRAVERSAL_TIME - 2*HopCount*NODE_TRAVERSAL_TIME).

    unsigned int hopCount = rreq->getHopCount();
    simtime_t minimalLifeTime = simTime() + 2 * netTraversalTime - 2 * hopCount * nodeTraversalTime;
    simtime_t newLifeTime = std::max(simTime(), minimalLifeTime);
    int rreqSeqNum = rreq->getOriginatorSeqNum();
    if (!reverseRoute || reverseRoute->getSource() != this) {    // create
        // This reverse route will be needed if the node receives a RREP back to the
        // node that originated the RREQ (identified by the Originator IP Address).
        reverseRoute = createRoute(rreq->getOriginatorAddr(), sourceAddr, hopCount, true, rreqSeqNum, true, newLifeTime);
    }
    else {
        AodvRouteData *routeData = check_and_cast<AodvRouteData *>(reverseRoute->getProtocolData());
        int routeSeqNum = routeData->getDestSeqNum();
        int newSeqNum = std::max(routeSeqNum, rreqSeqNum);
        int newHopCount = rreq->getHopCount();    // Note: already incremented by 1.
        int routeHopCount = reverseRoute->getMetric();
        // The route is only updated if the new sequence number is either
        //
        //   (i)       higher than the destination sequence number in the route
        //             table, or
        //
        //   (ii)      the sequence numbers are equal, but the hop count (of the
        //             new information) plus one, is smaller than the existing hop
        //             count in the routing table, or
        //
        //   (iii)     the sequence number is unknown.

        if (rreqSeqNum > routeSeqNum ||
            (rreqSeqNum == routeSeqNum && newHopCount < routeHopCount) ||
            rreq->getUnknownSeqNumFlag())
        {
            updateRoutingTable(reverseRoute, sourceAddr, hopCount, true, newSeqNum, true, newLifeTime);
        }
    }

    // A node generates a RREP if either:
    //
    // (i)       it is itself the destination, or
    //
    // (ii)      it has an active route to the destination, the destination
    //           sequence number in the node's existing route table entry
    //           for the destination is valid and greater than or equal to
    //           the Destination Sequence Number of the RREQ (comparison
    //           using signed 32-bit arithmetic), and the "destination only"
    //           ('D') flag is NOT set.

    // After a node receives a RREQ and responds with a RREP, it discards
    // the RREQ.  If the RREQ has the 'G' flag set, and the intermediate
    // node returns a RREP to the originating node, it MUST also unicast a
    // gratuitous RREP to the destination node.

    IRoute *destRoute = routingTable->findBestMatchingRoute(rreq->getDestAddr());
    AodvRouteData *destRouteData = destRoute ? dynamic_cast<AodvRouteData *>(destRoute->getProtocolData()) : nullptr;

    // check (i)
    if (rreq->getDestAddr() == getSelfIPAddress()) {
        EV_INFO << "I am the destination node for which the route was requested" << endl;

        // create RREP
        auto rrep = createRREP(rreq, destRoute, reverseRoute, sourceAddr);

        // send to the originator
        sendRREP(rrep, rreq->getOriginatorAddr(), 255);

        return;    // discard RREQ, in this case, we do not forward it.
    }

    // check (ii)
    if (destRouteData && destRouteData->isActive() && destRouteData->hasValidDestNum() &&
        destRouteData->getDestSeqNum() >= rreq->getDestSeqNum())
    {
        EV_INFO << "I am an intermediate node who has information about a route to " << rreq->getDestAddr() << endl;

        if (destRoute->getNextHopAsGeneric() == sourceAddr) {
            EV_WARN << "This RREP would make a loop. Dropping it" << endl;
            return;
        }

        // we respond to the RREQ, if the D (destination only) flag is not set
        if(!rreq->getDestOnlyFlag())
        {
            // create RREP
            auto rrep = createRREP(rreq, destRoute, reverseRoute, sourceAddr);

            // send to the originator
            sendRREP(rrep, rreq->getOriginatorAddr(), 255);

            if (rreq->getGratuitousRREPFlag()) {
                // The gratuitous RREP is then sent to the next hop along the path to
                // the destination node, just as if the destination node had already
                // issued a RREQ for the originating node and this RREP was produced in
                // response to that (fictitious) RREQ.

                IRoute *originatorRoute = routingTable->findBestMatchingRoute(rreq->getOriginatorAddr());
                auto grrep = createGratuitousRREP(rreq, originatorRoute);
                sendGRREP(grrep, rreq->getDestAddr(), 100);
            }

            return;    // discard RREQ, in this case, we also do not forward it.
        }
        else
            EV_INFO << "The originator indicated that only the destination may respond to this RREQ (D flag is set). Forwarding ..." << endl;
    }

    // If a node does not generate a RREP (following the processing rules in
    // section 6.6), and if the incoming IP header has TTL larger than 1,
    // the node updates and broadcasts the RREQ to address 255.255.255.255
    // on each of its configured interfaces (see section 6.14).  To update
    // the RREQ, the TTL or hop limit field in the outgoing IP header is
    // decreased by one, and the Hop Count field in the RREQ message is
    // incremented by one, to account for the new hop through the
    // intermediate node. (!) Lastly, the Destination Sequence number for the
    // requested destination is set to the maximum of the corresponding
    // value received in the RREQ message, and the destination sequence
    // value currently maintained by the node for the requested destination.
    // However, the forwarding node MUST NOT modify its maintained value for
    // the destination sequence number, even if the value received in the
    // incoming RREQ is larger than the value currently maintained by the
    // forwarding node.

    if (timeToLive > 0 && (simTime() > rebootTime + deletePeriod || rebootTime == 0)) {
        if (destRouteData)
            rreq->setDestSeqNum(std::max(destRouteData->getDestSeqNum(), rreq->getDestSeqNum()));
        rreq->setUnknownSeqNumFlag(false);

        auto outgoingRREQ = dynamicPtrCast<Rreq>(rreq->dupShared());
        forwardRREQ(outgoingRREQ, timeToLive);
    }
    else
        EV_WARN << "Can't forward the RREQ because of its small (<= 1) TTL: " << timeToLive << " or the AODV reboot has not completed yet" << endl;
}
#endif
#ifdef  CONTROLLER_MODE_ENABLED
void Aodv::handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive, unsigned int controllerRequestType)
{
    // create RREP
    auto rrep = createRREP(rreq, sourceAddr);

    /* TODO: controllerRequestType burada sendRREP içine input olarak verilebilir. Route request mi baska bir istek mi bu parametre ile anlaþýlacak
     * 18.05.2021: þuanda bu parametre buradan itibaren kullanýlmýyor. ileride aktif edilmesi gerekecek */

    // send to the originator
    sendRREP(rrep, rreq->getOriginatorAddr(), 255);
}
#endif

IRoute *Aodv::createRoute(const L3Address& destAddr, const L3Address& nextHop,
        unsigned int hopCount, bool hasValidDestNum, unsigned int destSeqNum,
        bool isActive, simtime_t lifeTime)
{

#ifdef CONTROLLER_MODE_ENABLED
    if(simTime() > simtime_t(14.5))
    {
        if((routingTable->getRouterIdAsGeneric() == testDestAddr2) && (nodeB_aodvRouteCreationDisabled) )
        {
            nodeB_aodvRouteCreationDisabled = false;
        }
        else if( (routingTable->getRouterIdAsGeneric() == testDestAddr1) && (nodeA_aodvRouteCreationDisabled) )
        {
            nodeA_aodvRouteCreationDisabled = false;
        }
        else if( (routingTable->getRouterIdAsGeneric() == testDestAddr6) && (nodeF_aodvRouteCreationDisabled) )
        {
            nodeF_aodvRouteCreationDisabled = false;
        }
        else if( (routingTable->getRouterIdAsGeneric() == testDestAddr5) && (nodeE_aodvRouteCreationDisabled) )
        {
            nodeE_aodvRouteCreationDisabled = false;
        }
        else if( (routingTable->getRouterIdAsGeneric() == testDestAddr3) && (nodeSource_aodvRouteCreationDisabled) )
        {
            nodeSource_aodvRouteCreationDisabled = false;
        }
        else if((routingTable->getRouterIdAsGeneric() == testDestAddrController) && (nodeController_aodvRouteCreationDisabled))
        {
            nodeController_aodvRouteCreationDisabled = false;
        }
        else
        {
            return nullptr;
        }
    }
#endif

    // create a new route
    IRoute *newRoute = routingTable->createRoute();

    // adding generic fields
    newRoute->setDestination(destAddr);
    newRoute->setNextHop(nextHop);
    newRoute->setPrefixLength(addressType->getMaxPrefixLength());    // TODO:
    newRoute->setMetric(hopCount);
    InterfaceEntry *ifEntry = interfaceTable->findInterfaceByName(par("interface"));    // TODO: IMPLEMENT: multiple interfaces
    if (ifEntry)
        newRoute->setInterface(ifEntry);
    newRoute->setSourceType(IRoute::AODV);
    newRoute->setSource(this);

    // A route towards a destination that has a routing table entry
    // that is marked as valid.  Only active routes can be used to
    // forward data packets.

    // adding protocol-specific fields
    AodvRouteData *newProtocolData = new AodvRouteData();
    newProtocolData->setIsActive(isActive);
    newProtocolData->setHasValidDestNum(hasValidDestNum);
    newProtocolData->setDestSeqNum(destSeqNum);
    newProtocolData->setLifeTime(lifeTime);
    newRoute->setProtocolData(newProtocolData);
//#ifndef CONTROLLER_MODE_ENABLED
    EV_DETAIL << "Adding new route " << newRoute << endl;
    routingTable->addRoute(newRoute);

    scheduleExpungeRoutes();
//#endif
    return newRoute;
}

void Aodv::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details)
{
    Enter_Method("receiveChangeNotification");
    if (signalID == linkBrokenSignal) {
        EV_DETAIL << "Received link break signal" << endl;
        Packet *datagram = check_and_cast<Packet *>(obj);
        const auto& networkHeader = findNetworkProtocolHeader(datagram);
        if (networkHeader != nullptr) {
            L3Address unreachableAddr = networkHeader->getDestinationAddress();
            if (unreachableAddr.getAddressType() == addressType) {
                // A node initiates processing for a RERR message in three situations:
                //
                //   (i)     if it detects a link break for the next hop of an active
                //           route in its routing table while transmitting data (and
                //           route repair, if attempted, was unsuccessful), or

                // TODO: Implement: local repair

                IRoute *route = routingTable->findBestMatchingRoute(unreachableAddr);

                if (route && route->getSource() == this)
                    handleLinkBreakSendRERR(route->getNextHopAsGeneric());
            }
        }
    }
}

void Aodv::handleLinkBreakSendRERR(const L3Address& unreachableAddr)
{
    // For case (i), the node first makes a list of unreachable destinations
    // consisting of the unreachable neighbor and any additional
    // destinations (or subnets, see section 7) in the local routing table
    // that use the unreachable neighbor as the next hop.

    // Just before transmitting the RERR, certain updates are made on the
    // routing table that may affect the destination sequence numbers for
    // the unreachable destinations.  For each one of these destinations,
    // the corresponding routing table entry is updated as follows:
    //
    // 1. The destination sequence number of this routing entry, if it
    //    exists and is valid, is incremented for cases (i) and (ii) above,
    //    and copied from the incoming RERR in case (iii) above.
    //
    // 2. The entry is invalidated by marking the route entry as invalid
    //
    // 3. The Lifetime field is updated to current time plus DELETE_PERIOD.
    //    Before this time, the entry SHOULD NOT be deleted.

    IRoute *unreachableRoute = routingTable->findBestMatchingRoute(unreachableAddr);

    if (!unreachableRoute || unreachableRoute->getSource() != this)
        return;

    std::vector<UnreachableNode> unreachableNodes;
    AodvRouteData *unreachableRouteData = check_and_cast<AodvRouteData *>(unreachableRoute->getProtocolData());


    if (unreachableRouteData->isActive()) {
        UnreachableNode node;
        node.addr = unreachableAddr;
        node.seqNum = unreachableRouteData->getDestSeqNum();
        unreachableNodes.push_back(node);
    }

    // For case (i), the node first makes a list of unreachable destinations
    // consisting of the unreachable neighbor and any additional destinations
    // (or subnets, see section 7) in the local routing table that use the
    // unreachable neighbor as the next hop.

    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute *route = routingTable->getRoute(i);

        AodvRouteData *routeData = dynamic_cast<AodvRouteData *>(route->getProtocolData());

        if (routeData && routeData->isActive() && route->getNextHopAsGeneric() == unreachableAddr) {
            if (routeData->hasValidDestNum())
                routeData->setDestSeqNum(routeData->getDestSeqNum() + 1);

            EV_DETAIL << "Marking route to " << route->getDestinationAsGeneric() << " as inactive" << endl;

            routeData->setIsActive(false);
            routeData->setLifeTime(simTime() + deletePeriod);
            scheduleExpungeRoutes();

            UnreachableNode node;
            node.addr = route->getDestinationAsGeneric();
            node.seqNum = routeData->getDestSeqNum();
            unreachableNodes.push_back(node);
        }
    }

    // The neighboring node(s) that should receive the RERR are all those
    // that belong to a precursor list of at least one of the unreachable
    // destination(s) in the newly created RERR.  In case there is only one
    // unique neighbor that needs to receive the RERR, the RERR SHOULD be
    // unicast toward that neighbor.  Otherwise the RERR is typically sent
    // to the local broadcast address (Destination IP == 255.255.255.255,
    // TTL == 1) with the unreachable destinations, and their corresponding
    // destination sequence numbers, included in the packet.

    if (rerrCount >= rerrRatelimit) {
        EV_WARN << "A node should not generate more than RERR_RATELIMIT RERR messages per second. Canceling sending RERR" << endl;
        return;
    }

    if (unreachableNodes.empty())
        return;

    auto rerr = createRERR(unreachableNodes);
    rerrCount++;

    // broadcast
    EV_INFO << "Broadcasting Route Error message with TTL=1" << endl;
#ifndef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rerr, addressType->getBroadcastAddress(), 1, *jitterPar);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rerr, addressType->getBroadcastAddress(), 1, *jitterPar, (SDN_CONTROLLER_SENDER_TYPE)99, MESSAGE_TYPE_UNDEFINED);
#endif
}

const Ptr<Rerr> Aodv::createRERR(const std::vector<UnreachableNode>& unreachableNodes)
{
    auto rerr = makeShared<Rerr>(); // TODO: "AODV-RERR");
    rerr->setPacketType(usingIpv6 ? RERR_IPv6 : RERR);

    unsigned int destCount = unreachableNodes.size();
    rerr->setUnreachableNodesArraySize(destCount);

    for (unsigned int i = 0; i < destCount; i++) {
        UnreachableNode node;
        node.addr = unreachableNodes[i].addr;
        node.seqNum = unreachableNodes[i].seqNum;
        rerr->setUnreachableNodes(i, node);
    }

    rerr->setChunkLength(B(4 + destCount * (usingIpv6 ? (4 + 16) : (4 + 4))));

    return rerr;
}

void Aodv::handleRERR(const Ptr<const Rerr>& rerr, const L3Address& sourceAddr)
{
    EV_INFO << "AODV Route Error arrived with source addr: " << sourceAddr << endl;

    // A node initiates processing for a RERR message in three situations:
    // (iii)   if it receives a RERR from a neighbor for one or more
    //         active routes.
    unsigned int unreachableArraySize = rerr->getUnreachableNodesArraySize();
    std::vector<UnreachableNode> unreachableNeighbors;

    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute *route = routingTable->getRoute(i);
        AodvRouteData *routeData = route ? dynamic_cast<AodvRouteData *>(route->getProtocolData()) : nullptr;


        if (!routeData)
            continue;

        // For case (iii), the list should consist of those destinations in the RERR
        // for which there exists a corresponding entry in the local routing
        // table that has the transmitter of the received RERR as the next hop.

        if (routeData->isActive() && route->getNextHopAsGeneric() == sourceAddr) {
            for (unsigned int j = 0; j < unreachableArraySize; j++) {
                if (route->getDestinationAsGeneric() == rerr->getUnreachableNodes(j).addr) {
                    // 1. The destination sequence number of this routing entry, if it
                    // exists and is valid, is incremented for cases (i) and (ii) above,
                    // ! and copied from the incoming RERR in case (iii) above.

                    routeData->setDestSeqNum(rerr->getUnreachableNodes(j).seqNum);
                    routeData->setIsActive(false);    // it means invalid, see 3. AODV Terminology p.3. in RFC 3561
                    routeData->setLifeTime(simTime() + deletePeriod);

                    // The RERR should contain those destinations that are part of
                    // the created list of unreachable destinations and have a non-empty
                    // precursor list.

                    if (routeData->getPrecursorList().size() > 0) {
                        UnreachableNode node;
                        node.addr = route->getDestinationAsGeneric();
                        node.seqNum = routeData->getDestSeqNum();
                        unreachableNeighbors.push_back(node);
                    }
                    scheduleExpungeRoutes();
                }
            }
        }
    }

    if (rerrCount >= rerrRatelimit) {
        EV_WARN << "A node should not generate more than RERR_RATELIMIT RERR messages per second. Canceling sending RERR" << endl;
        return;
    }

    if (unreachableNeighbors.size() > 0 && (simTime() > rebootTime + deletePeriod || rebootTime == 0)) {
        EV_INFO << "Sending RERR to inform our neighbors about link breaks." << endl;
        auto newRERR = createRERR(unreachableNeighbors);
#ifndef  CONTROLLER_MODE_ENABLED
        sendAODVPacket(newRERR, addressType->getBroadcastAddress(), 1, 0);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
        sendAODVPacket(newRERR, addressType->getBroadcastAddress(), 1, 0, (SDN_CONTROLLER_SENDER_TYPE)99, MESSAGE_TYPE_UNDEFINED);
#endif
        rerrCount++;
    }
}

void Aodv::handleStartOperation(LifecycleOperation *operation)
{
    rebootTime = simTime();

    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(L3Address(), aodvUDPPort);
    socket.setBroadcast(true);

    // RFC 5148:
    // Jitter SHOULD be applied by reducing this delay by a random amount, so that
    // the delay between consecutive transmissions of messages of the same type is
    // equal to (MESSAGE_INTERVAL - jitter), where jitter is the random value.
    if (useHelloMessages)
        scheduleAt(simTime() + helloInterval - *periodicJitter, helloMsgTimer);

    scheduleAt(simTime() + 1, counterTimer);
}

void Aodv::handleStopOperation(LifecycleOperation *operation)
{
    socket.close();
    clearState();
}

void Aodv::handleCrashOperation(LifecycleOperation *operation)
{
    socket.destroy();
    clearState();
}

void Aodv::clearState()
{
    rerrCount = rreqCount = rreqId = sequenceNum = 0;
    addressToRreqRetries.clear();
    for (auto & elem : waitForRREPTimers)
        cancelAndDelete(elem.second);

    // FIXME: Drop the queued datagrams.
    //for (auto it = targetAddressToDelayedPackets.begin(); it != targetAddressToDelayedPackets.end(); it++)
    //    networkProtocol->dropQueuedDatagram(const_cast<const Packet *>(it->second));

    targetAddressToDelayedPackets.clear();

    waitForRREPTimers.clear();
    rreqsArrivalTime.clear();

    if (useHelloMessages)
        cancelEvent(helloMsgTimer);
    if (expungeTimer)
        cancelEvent(expungeTimer);
    if (counterTimer)
        cancelEvent(counterTimer);
    if (blacklistTimer)
        cancelEvent(blacklistTimer);
    if (rrepAckTimer)
        cancelEvent(rrepAckTimer);
    if(sdnControllerTimer)
        cancelEvent(sdnControllerTimer); /*beratovic*/
    if(sdnControllerTimer2)
        cancelEvent(sdnControllerTimer2);
#if 1
    if(sdnNodeSourceTimer)
        cancelEvent(sdnNodeSourceTimer); /* beratovic */
    if(sdnNodeATimer)
        cancelEvent(sdnNodeATimer);
    if(sdnNodeBTimer)
        cancelEvent(sdnNodeBTimer);
    if(sdnNodeFTimer)
        cancelEvent(sdnNodeFTimer);
    if(sdnNodeETimer)
        cancelEvent(sdnNodeETimer);
#endif
}

void Aodv::handleWaitForRREP(WaitForRrep *rrepTimer)
{
    EV_INFO << "We didn't get any Route Reply within RREP timeout" << endl;
    L3Address destAddr = rrepTimer->getDestAddr();

#ifdef CONTROLLER_MODE_ENABLED
    if(simTime() < simtime_t(2))
    {
    }
    else
    {
        ASSERT(addressToRreqRetries.find(destAddr) != addressToRreqRetries.end());
    }
#endif
#ifndef CONTROLLER_MODE_ENABLED
    ASSERT(addressToRreqRetries.find(destAddr) != addressToRreqRetries.end());
#endif
    if (addressToRreqRetries[destAddr] == rreqRetries) {
        cancelRouteDiscovery(destAddr);
        EV_WARN << "Re-discovery attempts for node " << destAddr << " reached RREQ_RETRIES= " << rreqRetries << " limit. Stop sending RREQ." << endl;
        return;
    }

    auto rreq = createRREQ(destAddr);

    // the node MAY try again to discover a route by broadcasting another
    // RREQ, up to a maximum of RREQ_RETRIES times at the maximum TTL value.
    if (rrepTimer->getLastTTL() == netDiameter) // netDiameter is the maximum TTL value
        addressToRreqRetries[destAddr]++;

    sendRREQ(rreq, addressType->getBroadcastAddress(), 0);
}

void Aodv::forwardRREP(const Ptr<Rrep>& rrep, const L3Address& destAddr, unsigned int timeToLive)
{
    EV_INFO << "Forwarding the Route Reply to the node " << rrep->getOriginatorAddr() << " which originated the Route Request" << endl;

    // RFC 5148:
    // When a node forwards a message, it SHOULD be jittered by delaying it
    // by a random duration.  This delay SHOULD be generated uniformly in an
    // interval between zero and MAXJITTER.
#ifndef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rrep, destAddr, 100, *jitterPar);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rrep, destAddr, 100, *jitterPar, (SDN_CONTROLLER_SENDER_TYPE)99, MESSAGE_TYPE_UNDEFINED);
#endif
}

void Aodv::forwardRREQ(const Ptr<Rreq>& rreq, unsigned int timeToLive)
{
    EV_INFO << "Forwarding the Route Request message with TTL= " << timeToLive << endl;
#ifndef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rreq, addressType->getBroadcastAddress(), timeToLive, *jitterPar);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rreq, addressType->getBroadcastAddress(), timeToLive, *jitterPar, (SDN_CONTROLLER_SENDER_TYPE)99, MESSAGE_TYPE_UNDEFINED);
#endif
}

void Aodv::completeRouteDiscovery(const L3Address& target)
{
    EV_DETAIL << "Completing route discovery, originator " << getSelfIPAddress() << ", target " << target << endl;
    ASSERT(hasOngoingRouteDiscovery(target));

    auto lt = targetAddressToDelayedPackets.lower_bound(target);
    auto ut = targetAddressToDelayedPackets.upper_bound(target);

    // reinject the delayed datagrams
    for (auto it = lt; it != ut; it++) {
        Packet *datagram = it->second;
        const auto& networkHeader = getNetworkProtocolHeader(datagram);
        EV_DETAIL << "Sending queued datagram: source " << networkHeader->getSourceAddress() << ", destination " << networkHeader->getDestinationAddress() << endl;
        networkProtocol->reinjectQueuedDatagram(const_cast<const Packet *>(datagram));
    }

    // clear the multimap
    targetAddressToDelayedPackets.erase(lt, ut);

    // we have a route for the destination, thus we must cancel the WaitForRREPTimer events
    auto waitRREPIter = waitForRREPTimers.find(target);
    ASSERT(waitRREPIter != waitForRREPTimers.end());
    cancelAndDelete(waitRREPIter->second);
    waitForRREPTimers.erase(waitRREPIter);
}

void Aodv::sendGRREP(const Ptr<Rrep>& grrep, const L3Address& destAddr, unsigned int timeToLive)
{
    EV_INFO << "Sending gratuitous Route Reply to " << destAddr << endl;

    IRoute *destRoute = routingTable->findBestMatchingRoute(destAddr);
    const L3Address& nextHop = destRoute->getNextHopAsGeneric();
#ifndef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(grrep, nextHop, timeToLive, 0);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(grrep, nextHop, timeToLive, 0, (SDN_CONTROLLER_SENDER_TYPE)99, MESSAGE_TYPE_UNDEFINED);
#endif
}

const Ptr<Rrep> Aodv::createHelloMessage()
{
    // called a Hello message, with the RREP
    // message fields set as follows:
    //
    //    Destination IP Address         The node's IP address.
    //
    //    Destination Sequence Number    The node's latest sequence number.
    //
    //    Hop Count                      0
    //
    //    Lifetime                       ALLOWED_HELLO_LOSS *HELLO_INTERVAL

    auto helloMessage = makeShared<Rrep>(); // TODO: "AODV-HelloMsg");
    helloMessage->setPacketType(usingIpv6 ? RREP_IPv6 : RREP);
    helloMessage->setChunkLength(usingIpv6 ? B(44) : B(20));

    helloMessage->setDestAddr(getSelfIPAddress());
    helloMessage->setDestSeqNum(sequenceNum);
    helloMessage->setHopCount(0);
    helloMessage->setLifeTime(allowedHelloLoss * helloInterval);

    return helloMessage;
}

void Aodv::sendHelloMessagesIfNeeded()
{
    ASSERT(useHelloMessages);
    // Every HELLO_INTERVAL milliseconds, the node checks whether it has
    // sent a broadcast (e.g., a RREQ or an appropriate layer 2 message)
    // within the last HELLO_INTERVAL.  If it has not, it MAY broadcast
    // a RREP with TTL = 1

    // A node SHOULD only use hello messages if it is part of an
    // active route.
    bool hasActiveRoute = false;

    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() == this) {
            AodvRouteData *routeData = check_and_cast<AodvRouteData *>(route->getProtocolData());
            if (routeData->isActive()) {
                hasActiveRoute = true;
                break;
            }
        }
    }

    if (hasActiveRoute && (lastBroadcastTime == 0 || simTime() - lastBroadcastTime > helloInterval)) {
        EV_INFO << "It is hello time, broadcasting Hello Messages with TTL=1" << endl;
        auto helloMessage = createHelloMessage();
#ifndef  CONTROLLER_MODE_ENABLED
        sendAODVPacket(helloMessage, addressType->getBroadcastAddress(), 1, 0);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
        sendAODVPacket(helloMessage, addressType->getBroadcastAddress(), 1, 0, (SDN_CONTROLLER_SENDER_TYPE)99, MESSAGE_TYPE_UNDEFINED);
#endif
    }

    scheduleAt(simTime() + helloInterval - *periodicJitter, helloMsgTimer);
}

void Aodv::handleHelloMessage(const Ptr<Rrep>& helloMessage)
{
    const L3Address& helloOriginatorAddr = helloMessage->getDestAddr();
    IRoute *routeHelloOriginator = routingTable->findBestMatchingRoute(helloOriginatorAddr);

    // Whenever a node receives a Hello message from a neighbor, the node
    // SHOULD make sure that it has an active route to the neighbor, and
    // create one if necessary.  If a route already exists, then the
    // Lifetime for the route should be increased, if necessary, to be at
    // least ALLOWED_HELLO_LOSS * HELLO_INTERVAL.  The route to the
    // neighbor, if it exists, MUST subsequently contain the latest
    // Destination Sequence Number from the Hello message.  The current node
    // can now begin using this route to forward data packets.  Routes that
    // are created by hello messages and not used by any other active routes
    // will have empty precursor lists and would not trigger a RERR message
    // if the neighbor moves away and a neighbor timeout occurs.

    unsigned int latestDestSeqNum = helloMessage->getDestSeqNum();
    simtime_t newLifeTime = simTime() + allowedHelloLoss * helloInterval;

    if (!routeHelloOriginator || routeHelloOriginator->getSource() != this)
        createRoute(helloOriginatorAddr, helloOriginatorAddr, 1, true, latestDestSeqNum, true, newLifeTime);
    else {
        AodvRouteData *routeData = check_and_cast<AodvRouteData *>(routeHelloOriginator->getProtocolData());
        simtime_t lifeTime = routeData->getLifeTime();
        updateRoutingTable(routeHelloOriginator, helloOriginatorAddr, 1, true, latestDestSeqNum, true, std::max(lifeTime, newLifeTime));
    }

    // TODO: This feature has not implemented yet.
    // A node MAY determine connectivity by listening for packets from its
    // set of neighbors.  If, within the past DELETE_PERIOD, it has received
    // a Hello message from a neighbor, and then for that neighbor does not
    // receive any packets (Hello messages or otherwise) for more than
    // ALLOWED_HELLO_LOSS * HELLO_INTERVAL milliseconds, the node SHOULD
    // assume that the link to this neighbor is currently lost.  When this
    // happens, the node SHOULD proceed as in Section 6.11.
}

void Aodv::expungeRoutes()
{
    for (int i = 0; i < routingTable->getNumRoutes(); i++) {
        IRoute *route = routingTable->getRoute(i);
        //EV_DETAIL << "i: " << i << " and routingTable->getNumRoutes(): " << routingTable->getNumRoutes() << " and route->getProtocolData() : " << route->getProtocolData() << endl;
        if (route->getSource() == this) {
            AodvRouteData *routeData = check_and_cast<AodvRouteData *>(route->getProtocolData());
            ASSERT(routeData != nullptr);
            if (routeData->getLifeTime() <= simTime()) {
                if (routeData->isActive()) {
                    EV_DETAIL << "Route to " << route->getDestinationAsGeneric() << " expired and set to inactive. It will be deleted after DELETE_PERIOD time" << endl;
                    // An expired routing table entry SHOULD NOT be expunged before
                    // (current_time + DELETE_PERIOD) (see section 6.11).  Otherwise, the
                    // soft state corresponding to the route (e.g., last known hop count)
                    // will be lost.
                    routeData->setIsActive(false);
                    routeData->setLifeTime(simTime() + deletePeriod);
                }
                else {
                    // Any routing table entry waiting for a RREP SHOULD NOT be expunged
                    // before (current_time + 2 * NET_TRAVERSAL_TIME).
                    if (hasOngoingRouteDiscovery(route->getDestinationAsGeneric())) {
                        EV_DETAIL << "Route to " << route->getDestinationAsGeneric() << " expired and is inactive, but we are waiting for a RREP to this destination, so we extend its lifetime with 2 * NET_TRAVERSAL_TIME" << endl;
                        routeData->setLifeTime(simTime() + 2 * netTraversalTime);
                    }
                    else {
                        EV_DETAIL << "Route to " << route->getDestinationAsGeneric() << " expired and is inactive and we are not expecting any RREP to this destination, so we delete this route" << endl;
                        routingTable->deleteRoute(route);
                    }
                }
            }
        }
    }
    scheduleExpungeRoutes();
}

void Aodv::scheduleExpungeRoutes()
{
#ifndef CONTROLLER_MODE_ENABLED
    simtime_t nextExpungeTime = SimTime::getMaxTime();
    for (int i = 0; i < routingTable->getNumRoutes(); i++)
    {
        IRoute *route = routingTable->getRoute(i);
        if (route->getSource() == this)
        {
            AodvRouteData *routeData = check_and_cast<AodvRouteData *>(route->getProtocolData());
            ASSERT(routeData != nullptr);

            if (routeData->getLifeTime() < nextExpungeTime)
                nextExpungeTime = routeData->getLifeTime();
        }
    }

    if (nextExpungeTime == SimTime::getMaxTime()) {
        if (expungeTimer->isScheduled())
            cancelEvent(expungeTimer);
    }
    else {
        if (!expungeTimer->isScheduled())
            scheduleAt(nextExpungeTime, expungeTimer);
        else {
            if (expungeTimer->getArrivalTime() != nextExpungeTime) {
                cancelEvent(expungeTimer);
                scheduleAt(nextExpungeTime, expungeTimer);
            }
        }
    }
#endif

#ifdef CONTROLLER_MODE_ENABLED
#warning "is this place correct? control it"
    simtime_t nextExpungeTime = SimTime::getMaxTime();

    if (nextExpungeTime == SimTime::getMaxTime()) {
        if (expungeTimer->isScheduled())
            cancelEvent(expungeTimer);
    }
    else {
        if (!expungeTimer->isScheduled())
            scheduleAt(nextExpungeTime, expungeTimer);
        else {
            if (expungeTimer->getArrivalTime() != nextExpungeTime) {
                cancelEvent(expungeTimer);
                scheduleAt(nextExpungeTime, expungeTimer);
            }
        }
    }
#endif
}

INetfilter::IHook::Result Aodv::datagramForwardHook(Packet *datagram)
{
    // TODO: Implement: Actions After Reboot
    // If the node receives a data packet for some other destination, it SHOULD
    // broadcast a RERR as described in subsection 6.11 and MUST reset the waiting
    // timer to expire after current time plus DELETE_PERIOD.

    Enter_Method("datagramForwardHook");
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& destAddr = networkHeader->getDestinationAddress();
    const L3Address& sourceAddr = networkHeader->getSourceAddress();
    IRoute *ipSource = routingTable->findBestMatchingRoute(sourceAddr);

    if (destAddr.isBroadcast() || routingTable->isLocalAddress(destAddr) || destAddr.isMulticast()) {
        if (routingTable->isLocalAddress(destAddr) && ipSource && ipSource->getSource() == this)
            updateValidRouteLifeTime(ipSource->getNextHopAsGeneric(), simTime() + activeRouteTimeout);

        return ACCEPT;
    }

    // TODO: IMPLEMENT: check if the datagram is a data packet or we take control packets as data packets

    IRoute *routeDest = routingTable->findBestMatchingRoute(destAddr);
    AodvRouteData *routeDestData = routeDest ? dynamic_cast<AodvRouteData *>(routeDest->getProtocolData()) : nullptr;
    // Each time a route is used to forward a data packet, its Active Route
    // Lifetime field of the source, destination and the next hop on the
    // path to the destination is updated to be no less than the current
    // time plus ACTIVE_ROUTE_TIMEOUT

    updateValidRouteLifeTime(sourceAddr, simTime() + activeRouteTimeout);
    updateValidRouteLifeTime(destAddr, simTime() + activeRouteTimeout);

    if (routeDest && routeDest->getSource() == this)
        updateValidRouteLifeTime(routeDest->getNextHopAsGeneric(), simTime() + activeRouteTimeout);

    // Since the route between each originator and destination pair is expected
    // to be symmetric, the Active Route Lifetime for the previous hop, along the
    // reverse path back to the IP source, is also updated to be no less than the
    // current time plus ACTIVE_ROUTE_TIMEOUT.

    if (ipSource && ipSource->getSource() == this)
        updateValidRouteLifeTime(ipSource->getNextHopAsGeneric(), simTime() + activeRouteTimeout);

    EV_INFO << "We can't forward datagram because we have no active route for " << destAddr << endl;
    if (routeDest && routeDestData && !routeDestData->isActive()) {    // exists but is not active
        // A node initiates processing for a RERR message in three situations:
        // (ii)      if it gets a data packet destined to a node for which it
        //           does not have an active route and is not repairing (if
        //           using local repair)

        // TODO: check if it is not repairing (if using local repair)

        // 1. The destination sequence number of this routing entry, if it
        // exists and is valid, is incremented for cases (i) and (ii) above,
        // and copied from the incoming RERR in case (iii) above.

        if (routeDestData->hasValidDestNum())
            routeDestData->setDestSeqNum(routeDestData->getDestSeqNum() + 1);

        // 2. The entry is invalidated by marking the route entry as invalid <- it is invalid

        // 3. The Lifetime field is updated to current time plus DELETE_PERIOD.
        //    Before this time, the entry SHOULD NOT be deleted.
        routeDestData->setLifeTime(simTime() + deletePeriod);

        sendRERRWhenNoRouteToForward(destAddr);
    }
    else if (!routeDest || routeDest->getSource() != this) // doesn't exist at all
        sendRERRWhenNoRouteToForward(destAddr);

    return ACCEPT;
}

void Aodv::sendRERRWhenNoRouteToForward(const L3Address& unreachableAddr)
{
    if (rerrCount >= rerrRatelimit) {
        EV_WARN << "A node should not generate more than RERR_RATELIMIT RERR messages per second. Canceling sending RERR" << endl;
        return;
    }
    std::vector<UnreachableNode> unreachableNodes;
    UnreachableNode node;
    node.addr = unreachableAddr;

    IRoute *unreachableRoute = routingTable->findBestMatchingRoute(unreachableAddr);
    AodvRouteData *unreachableRouteData = unreachableRoute ? dynamic_cast<AodvRouteData *>(unreachableRoute->getProtocolData()) : nullptr;

    if (unreachableRouteData && unreachableRouteData->hasValidDestNum())
        node.seqNum = unreachableRouteData->getDestSeqNum();
    else
        node.seqNum = 0;

    unreachableNodes.push_back(node);
    auto rerr = createRERR(unreachableNodes);

    rerrCount++;
    EV_INFO << "Broadcasting Route Error message with TTL=1" << endl;
#ifndef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rerr, addressType->getBroadcastAddress(), 1, *jitterPar);    // TODO: unicast if there exists a route to the source
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rerr, addressType->getBroadcastAddress(), 1, *jitterPar, (SDN_CONTROLLER_SENDER_TYPE)99, MESSAGE_TYPE_UNDEFINED);
#endif
}

void Aodv::cancelRouteDiscovery(const L3Address& destAddr)
{
    ASSERT(hasOngoingRouteDiscovery(destAddr));
    auto lt = targetAddressToDelayedPackets.lower_bound(destAddr);
    auto ut = targetAddressToDelayedPackets.upper_bound(destAddr);
    for (auto it = lt; it != ut; it++)
        networkProtocol->dropQueuedDatagram(const_cast<const Packet *>(it->second));

    targetAddressToDelayedPackets.erase(lt, ut);

    auto waitRREPIter = waitForRREPTimers.find(destAddr);
    ASSERT(waitRREPIter != waitForRREPTimers.end());
    cancelAndDelete(waitRREPIter->second);
    waitForRREPTimers.erase(waitRREPIter);
}

bool Aodv::updateValidRouteLifeTime(const L3Address& destAddr, simtime_t lifetime)
{
#ifdef CONTROLLER_MODE_ENABLED
#if 1
    if(simTime() < simtime_t(14.5))
    {

    }
    else
    {
        lifetime = simtime_t(SIMULATION_RUN_TIME); /*20.saniyeden sonra güncellemeler tüm çalýþma sürecini kapsayacak*/
    }
#endif
#if 0
    if(true == routeHasChanged)
    {
        if(simTime() < simtime_t(20))
        {
            lifetime = simtime_t(0);
        }
        else
        {
            lifetime = simtime_t(SIMULATION_RUN_TIME); /*20.saniyeden sonra güncellemeler tüm çalýþma sürecini kapsayacak*/
        }
    }
#endif
#endif
    IRoute *route = routingTable->findBestMatchingRoute(destAddr);

    if (route && route->getSource() == this) {
        AodvRouteData *routeData = check_and_cast<AodvRouteData *>(route->getProtocolData());
        if (routeData->isActive()) {
            simtime_t newLifeTime = std::max(routeData->getLifeTime(), lifetime);
            EV_DETAIL << "Updating " << route << " lifetime to " << newLifeTime << endl;
            routeData->setLifeTime(newLifeTime);
            return true;
        }
    }
    return false;


}

const Ptr<RrepAck> Aodv::createRREPACK()
{
    auto rrepAck = makeShared<RrepAck>(); // TODO: "AODV-RREPACK");
    rrepAck->setPacketType(usingIpv6 ? RREPACK_IPv6 : RREPACK);
    return rrepAck;
}

void Aodv::sendRREPACK(const Ptr<RrepAck>& rrepACK, const L3Address& destAddr)
{
    EV_INFO << "Sending Route Reply ACK to " << destAddr << endl;
#ifndef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rrepACK, destAddr, 100, 0);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    sendAODVPacket(rrepACK, destAddr, 100, 0, (SDN_CONTROLLER_SENDER_TYPE)99, MESSAGE_TYPE_UNDEFINED);
#endif
}

void Aodv::handleRREPACK(const Ptr<const RrepAck>& rrepACK, const L3Address& neighborAddr)
{
    // Note that the RREP-ACK packet does not contain any information about
    // which RREP it is acknowledging.  The time at which the RREP-ACK is
    // received will likely come just after the time when the RREP was sent
    // with the 'A' bit.
    if (rrepAckTimer->isScheduled()) {
        EV_INFO << "RREP-ACK arrived from " << neighborAddr << endl;

        IRoute *route = routingTable->findBestMatchingRoute(neighborAddr);
        if (route && route->getSource() == this) {
            EV_DETAIL << "Marking route " << route << " as active" << endl;
            AodvRouteData *routeData = check_and_cast<AodvRouteData *>(route->getProtocolData());
            routeData->setIsActive(true);
            cancelEvent(rrepAckTimer);
        }
    }
}

void Aodv::handleRREPACKTimer()
{
    // when a node detects that its transmission of a RREP message has failed,
    // it remembers the next-hop of the failed RREP in a "blacklist" set.

    EV_INFO << "RREP-ACK didn't arrived within timeout. Adding " << failedNextHop << " to the blacklist" << endl;

    blacklist[failedNextHop] = simTime() + blacklistTimeout;    // lifetime

    if (!blacklistTimer->isScheduled())
        scheduleAt(simTime() + blacklistTimeout, blacklistTimer);
}

void Aodv::handleBlackListTimer()
{
    simtime_t nextTime = SimTime::getMaxTime();

    for (auto it = blacklist.begin(); it != blacklist.end(); ) {
        auto current = it++;

        // Nodes are removed from the blacklist set after a BLACKLIST_TIMEOUT period
        if (current->second <= simTime()) {
            EV_DETAIL << "Blacklist lifetime has expired for " << current->first << " removing it from the blacklisted addresses" << endl;
            blacklist.erase(current);
        }
        else if (nextTime > current->second)
            nextTime = current->second;
    }

    if (nextTime != SimTime::getMaxTime())
        scheduleAt(nextTime, blacklistTimer);
}

/*beratovic*/
#ifdef CONTROLLER_MODE_ENABLED
/*This function can be used to calculate distance between nodes*/
void Aodv::handleSdnControllerTimer()
{
#if 0
    /*Source will periodically check the route updates*/
    int forLoopRouteCounter = 0;
    IRoute *possibleRoute = nullptr;

    for(forLoopRouteCounter = 0; forLoopRouteCounter < routingTable->getNumRoutes(); forLoopRouteCounter++)
    {
        possibleRoute = routingTable->getRoute(forLoopRouteCounter);
        routingTable->removeRoute(possibleRoute);
        routingTable->deleteRoute(possibleRoute);
    }

    if (hasOngoingRouteDiscovery(testDestAddr1))
    {
        cancelRouteDiscovery(testDestAddr1);
    }
    if (hasOngoingRouteDiscovery(testDestAddr2))
    {
        cancelRouteDiscovery(testDestAddr2);
    }
    if (hasOngoingRouteDiscovery(testDestAddr3))
    {
        cancelRouteDiscovery(testDestAddr3);
    }
    if (hasOngoingRouteDiscovery(testDestAddr4))
    {
        cancelRouteDiscovery(testDestAddr4);
    }
    if (hasOngoingRouteDiscovery(testDestAddr5))
    {
        cancelRouteDiscovery(testDestAddr5);
    }
    nodeController_aodvRouteCreationDisabled = true;
    /* Keep fresh controller's routing table */
    createRoute(testDestAddr1, testDestAddr1, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
    createRoute(testDestAddr2, testDestAddr2, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
    createRoute(testDestAddr3, testDestAddr3, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
    createRoute(testDestAddr4, testDestAddr4, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
    createRoute(testDestAddr5, testDestAddr5, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/
    createRoute(testDestAddr6, testDestAddr6, 0, false, 0, true, SIMULATION_RUN_TIME); /*Controller can communicate directly with each node*/

    /*Reschedule to provide periodicity(1sec)*/
    scheduleAt(simTime() + simtime_t(5), sdnControllerTimer);
#endif
}

void Aodv::printDistances()
{
#if 1
        EV_INFO << "nodeDistanceTable.Dist_Source_A    : " << nodeDistanceTable.Dist_Source_A    << endl;
        EV_INFO << "nodeDistanceTable.Dist_Source_B    : " << nodeDistanceTable.Dist_Source_B    << endl;
        EV_INFO << "nodeDistanceTable.Dist_Source_E    : " << nodeDistanceTable.Dist_Source_E    << endl;
        EV_INFO << "nodeDistanceTable.Dist_Source_F    : " << nodeDistanceTable.Dist_Source_F    << endl;
        EV_INFO << "nodeDistanceTable.Dist_Source_Dest : " << nodeDistanceTable.Dist_Source_Dest << endl;
        EV_INFO << "nodeDistanceTable.Dist_A_E         : " << nodeDistanceTable.Dist_A_E         << endl;
        EV_INFO << "nodeDistanceTable.Dist_A_B         : " << nodeDistanceTable.Dist_A_B         << endl;
        EV_INFO << "nodeDistanceTable.Dist_A_F         : " << nodeDistanceTable.Dist_A_F         << endl;
        EV_INFO << "nodeDistanceTable.Dist_A_Dest      : " << nodeDistanceTable.Dist_A_Dest      << endl;
        EV_INFO << "nodeDistanceTable.Dist_E_B         : " << nodeDistanceTable.Dist_E_B         << endl;
        EV_INFO << "nodeDistanceTable.Dist_E_F         : " << nodeDistanceTable.Dist_E_F         << endl;
        EV_INFO << "nodeDistanceTable.Dist_E_Dest      : " << nodeDistanceTable.Dist_E_Dest      << endl;
        EV_INFO << "nodeDistanceTable.Dist_B_F         : " << nodeDistanceTable.Dist_B_F         << endl;
        EV_INFO << "nodeDistanceTable.Dist_B_Dest      : " << nodeDistanceTable.Dist_B_Dest      << endl;
        EV_INFO << "nodeDistanceTable.Dist_F_Dest      : " << nodeDistanceTable.Dist_F_Dest      << endl;
#endif
}


void Aodv::handleSdnControllerTimer2()
{
#if 0 /*Circular mobility kullanýlýyorsa 1 yap*/
    static CircleMobility* circleMobilityObj = nullptr;
#else /*RWP mobility*/
    static RandomWaypointMobility* circleMobilityObj = nullptr;
#endif


    static uint8_t objectController = 0;
    std::vector< signed int > whoCanTakeFromSource;
    std::vector< signed int > whoCanSendToDestination;
    bool earlyEnder = false;

    /*Create Circle Mobility object to get node positions periodically*/
    if(0 == objectController)
    {
#if 0/*Circular mobility kullanýlýyorsa 1 yap*/
        circleMobilityObj = singletonMannerCreateCircleMobObject();//new CircleMobility();
#else
        circleMobilityObj = singletonMannerCreateCircleMobObject_RWP();//new CircleMobility();
#endif
        objectController++;
    }

    /*EV_ERROR << "Node IP: "<< getSelfIPAddress() << endl;*/

    if(nullptr != circleMobilityObj)
    {
        /*Periodically calculates the node distances btw each other*/
        /*0*/  /* Controller*/
        /*1*/  nodeDistanceTable.Dist_Source_A    = sqrt((pow(circleMobilityObj->getNodeAcoordinateX() - circleMobilityObj->getNodeSourcecoordinateX(),2)) +      (pow(circleMobilityObj->getNodeAcoordinateY() - circleMobilityObj->getNodeSourcecoordinateY(),2)));
        /*2*/  nodeDistanceTable.Dist_Source_B    = sqrt((pow(circleMobilityObj->getNodeBcoordinateX() - circleMobilityObj->getNodeSourcecoordinateX(),2)) +      (pow(circleMobilityObj->getNodeBcoordinateY() - circleMobilityObj->getNodeSourcecoordinateY(),2)));
        /*3*/  nodeDistanceTable.Dist_Source_E    = sqrt((pow(circleMobilityObj->getNodeEcoordinateX() - circleMobilityObj->getNodeSourcecoordinateX(),2)) +      (pow(circleMobilityObj->getNodeEcoordinateY() - circleMobilityObj->getNodeSourcecoordinateY(),2)));
        /*4*/  nodeDistanceTable.Dist_Source_F    = sqrt((pow(circleMobilityObj->getNodeFcoordinateX() - circleMobilityObj->getNodeSourcecoordinateX(),2)) +      (pow(circleMobilityObj->getNodeFcoordinateY() - circleMobilityObj->getNodeSourcecoordinateY(),2)));
        /*5*/  nodeDistanceTable.Dist_Source_Dest = sqrt((pow(circleMobilityObj->getNodeDestinationcoordinateX() - circleMobilityObj->getNodeSourcecoordinateX(),2)) + (pow(circleMobilityObj->getNodeDestinationcoordinateY() - circleMobilityObj->getNodeSourcecoordinateY(),2)));
        /*6*/  nodeDistanceTable.Dist_A_E         = sqrt((pow(circleMobilityObj->getNodeAcoordinateX() - circleMobilityObj->getNodeEcoordinateX(),2)) +           (pow(circleMobilityObj->getNodeAcoordinateY() - circleMobilityObj->getNodeEcoordinateY(),2)));
        /*7*/  nodeDistanceTable.Dist_A_B         = sqrt((pow(circleMobilityObj->getNodeAcoordinateX() - circleMobilityObj->getNodeBcoordinateX(),2)) +           (pow(circleMobilityObj->getNodeAcoordinateY() - circleMobilityObj->getNodeBcoordinateY(),2)));
        /*8*/  nodeDistanceTable.Dist_A_F         = sqrt((pow(circleMobilityObj->getNodeAcoordinateX() - circleMobilityObj->getNodeFcoordinateX(),2)) +           (pow(circleMobilityObj->getNodeAcoordinateY() - circleMobilityObj->getNodeFcoordinateY(),2)));
        /*9*/  nodeDistanceTable.Dist_A_Dest      = sqrt((pow(circleMobilityObj->getNodeAcoordinateX() - circleMobilityObj->getNodeDestinationcoordinateX(),2)) + (pow(circleMobilityObj->getNodeAcoordinateY() - circleMobilityObj->getNodeDestinationcoordinateY(),2)));
        /*10*/ nodeDistanceTable.Dist_E_B         = sqrt((pow(circleMobilityObj->getNodeEcoordinateX() - circleMobilityObj->getNodeBcoordinateX(),2)) +           (pow(circleMobilityObj->getNodeEcoordinateY() - circleMobilityObj->getNodeBcoordinateY(),2)));
        /*11*/ nodeDistanceTable.Dist_E_F         = sqrt((pow(circleMobilityObj->getNodeEcoordinateX() - circleMobilityObj->getNodeFcoordinateX(),2)) +           (pow(circleMobilityObj->getNodeEcoordinateY() - circleMobilityObj->getNodeFcoordinateY(),2)));
        /*12*/ nodeDistanceTable.Dist_E_Dest      = sqrt((pow(circleMobilityObj->getNodeEcoordinateX() - circleMobilityObj->getNodeDestinationcoordinateX(),2)) + (pow(circleMobilityObj->getNodeEcoordinateY() - circleMobilityObj->getNodeDestinationcoordinateY(),2)));
        /*13*/ nodeDistanceTable.Dist_B_F         = sqrt((pow(circleMobilityObj->getNodeBcoordinateX() - circleMobilityObj->getNodeFcoordinateX(),2)) +           (pow(circleMobilityObj->getNodeBcoordinateY() - circleMobilityObj->getNodeFcoordinateY(),2)));
        /*14*/ nodeDistanceTable.Dist_B_Dest      = sqrt((pow(circleMobilityObj->getNodeBcoordinateX() - circleMobilityObj->getNodeDestinationcoordinateX(),2)) + (pow(circleMobilityObj->getNodeBcoordinateY() - circleMobilityObj->getNodeDestinationcoordinateY(),2)));
        /*15*/ nodeDistanceTable.Dist_F_Dest      = sqrt((pow(circleMobilityObj->getNodeFcoordinateX() - circleMobilityObj->getNodeDestinationcoordinateX(),2)) + (pow(circleMobilityObj->getNodeFcoordinateY() - circleMobilityObj->getNodeDestinationcoordinateY(),2)));

#if 0
        printDistances();
#endif

        /* Kimler source ile paket alýþveriþinde bulunabiliyor */
        if(nodeDistanceTable.Dist_Source_A < NODE_COMMUNICATION_RANGE_METERS)
        {
            whoCanTakeFromSource.push_back(1);
        }
        if(nodeDistanceTable.Dist_Source_B < NODE_COMMUNICATION_RANGE_METERS)
        {
            whoCanTakeFromSource.push_back(2);
        }
        if(nodeDistanceTable.Dist_Source_E < NODE_COMMUNICATION_RANGE_METERS)
        {
            whoCanTakeFromSource.push_back(3);
        }
        if(nodeDistanceTable.Dist_Source_F < NODE_COMMUNICATION_RANGE_METERS)
        {
            whoCanTakeFromSource.push_back(4);
        }

        /* Tersten gidelim. Destination'a kimler paket gönderebiliyor */

        if(nodeDistanceTable.Dist_A_Dest < NODE_COMMUNICATION_RANGE_METERS)
        {
            whoCanSendToDestination.push_back(9);
        }
        if(nodeDistanceTable.Dist_E_Dest < NODE_COMMUNICATION_RANGE_METERS)
        {
            whoCanSendToDestination.push_back(12);
        }
        if(nodeDistanceTable.Dist_B_Dest < NODE_COMMUNICATION_RANGE_METERS)
        {
            whoCanSendToDestination.push_back(14);
        }
        if(nodeDistanceTable.Dist_F_Dest < NODE_COMMUNICATION_RANGE_METERS)
        {
            whoCanSendToDestination.push_back(15);
        }


        int dummy1 = (int)(whoCanTakeFromSource.size());
        int dummy2 = (int)(whoCanSendToDestination.size());
        int loopCtr1;
        int loopCtr2;

        EV_INFO << "dummy1 : " << dummy1 << "and dummy2 : "<< dummy2 << endl;
        EV_INFO << "whoCanTakeFromSource: "<< whoCanTakeFromSource[0] << " " << whoCanTakeFromSource[1] << " " << whoCanTakeFromSource[2] << " " << whoCanTakeFromSource[3] << endl;

        /*Buraya kadar kim kiminle haberleþebiliyor öðrendik. Sýra Relay node'lar birbirleri ile haberleþebiliyor mu bunu öðrenelim*/
        /*þimdi buraya kadar geldiysek, bu relay node'lar source ve destination ile haberleþebiliyorlardýr zaten. Dolayýsýyla ilk yolu bul ve çýk! Ýþlem kolaylýðý olmasý açýsýndan!*/
        if((!whoCanTakeFromSource.empty()) && (!whoCanSendToDestination.empty()))
        {
            for(loopCtr1 = 0; loopCtr1 < dummy1; loopCtr1++)
            {
                if(true == earlyEnder)
                {
                    break;
                }
                for(loopCtr2 = 0; loopCtr2 < dummy2; loopCtr2++)
                {
                    EV_INFO << "whoCanTakeFromSource : " << whoCanTakeFromSource[loopCtr1] << "whoCanSendToDestination : " << whoCanSendToDestination[loopCtr2] << endl;
                    if(true == earlyEnder)
                    {
                        break;
                    }
                    switch (whoCanTakeFromSource[loopCtr1])
                    {
                        case 1: /*nodeDistanceTable.Dist_Source_A*/
                        {
                            switch(whoCanSendToDestination[loopCtr2])
                            {
                                case 9: /*nodeDistanceTable.Dist_A_Dest*/
                                {
                                    testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                    testDestAddr1_NextHop_Index = 4; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri direkt 4'e gönderebilir*/
                                    nodeA_nextHopUpdated = true;
                                    nodeSource_nextHopUpdated = true;
                                    EV_INFO << "Entered here 1" << endl;
                                    printDistances();
                                    earlyEnder = true;
                                    break;
                                }
                                case 12: /*nodeDistanceTable.Dist_E_Dest*/
                                {
                                    /*A ile E direkt haberleþebiliyor mu?*/
                                    if(((nodeDistanceTable.Dist_A_E) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                        testDestAddr1_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri E node'una göndermeli*/
                                        testDestAddr5_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeA_nextHopUpdated = true;
                                        nodeE_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 2" << endl;
                                    }
                                    /*A ile E direkt haberleþemiyorsa, A ile E arasýndaki relay node bulunmalý: B ya da F*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_B < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_B < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                            testDestAddr1_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri E node'una göndermek için B'ye göndermeli*/
                                            testDestAddr2_NextHop_Index = 5; /* Paketler B'den E'ye gidecek*/
                                            testDestAddr5_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                            EV_INFO << "Entered here 233" << endl;
                                        }
                                        else if((nodeDistanceTable.Dist_A_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                            testDestAddr1_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri E node'una göndermek için F'ye göndermeli*/
                                            testDestAddr6_NextHop_Index = 5; /* Paketler F'den E'ye gidecek*/
                                            testDestAddr5_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                            EV_INFO << "Entered here 244" << endl;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                case 14: /*nodeDistanceTable.Dist_B_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_A_B) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                        testDestAddr1_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri B node'una göndermeli*/
                                        testDestAddr2_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeA_nextHopUpdated = true;
                                        nodeB_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 3" << endl;
                                    }
                                    /*Relay node buluyoruz. A ile B arasýnda E ya da F relay node olabilir*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_E < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_B < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                            testDestAddr1_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri B node'una göndermek için E'ye göndermeli*/
                                            testDestAddr5_NextHop_Index = 2; /* Paketler E'den B'ye gidecek*/
                                            testDestAddr2_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_A_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_B_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                            testDestAddr1_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri B node'una göndermek için F'ye göndermeli*/
                                            testDestAddr6_NextHop_Index = 2; /* Paketler F'den E'ye gidecek*/
                                            testDestAddr2_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                case 15: /*nodeDistanceTable.Dist_F_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_A_F) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                        testDestAddr1_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri F node'una göndermeli*/
                                        testDestAddr6_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeA_nextHopUpdated = true;
                                        nodeF_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 4" << endl;
                                    }
                                    /*Relay node buluyoruz. A ile F arasýnda E ya da B relay node olabilir*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_E < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                            testDestAddr1_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri F node'una göndermek için E'ye göndermeli*/
                                            testDestAddr5_NextHop_Index = 6; /* Paketler E'den F'ye gidecek*/
                                            testDestAddr6_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_A_B < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_B_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                            testDestAddr1_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri B node'una göndermek için F'ye göndermeli*/
                                            testDestAddr2_NextHop_Index = 6; /* Paketler F'den E'ye gidecek*/
                                            testDestAddr6_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                default:
                                    EV_INFO << "Entered here 5" << endl;
                                    break;
                            }
                            break;
                        }





                        case 2:/*nodeDistanceTable.Dist_Source_B*/
                        {
                            switch(whoCanSendToDestination[loopCtr2])
                            {
                                case 9: /*nodeDistanceTable.Dist_A_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_A_B) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli*/
                                        testDestAddr2_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli + 2 paketleri A node'una göndermeli*/
                                        testDestAddr1_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeA_nextHopUpdated = true;
                                        nodeB_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 6" << endl;
                                    }
                                    /*Relay node buluyoruz. B ile A arasýnda E ya da F relay node olabilir*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_E_B < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_E < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli*/
                                            testDestAddr2_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli + 2 paketleri F node'una göndermek için E'ye göndermeli*/
                                            testDestAddr5_NextHop_Index = 1; /* Paketler E'den A'ye gidecek*/
                                            testDestAddr1_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_B_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli*/
                                            testDestAddr2_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli + 2 paketleri F node'una göndermek için B'ye göndermeli*/
                                            testDestAddr6_NextHop_Index = 1; /* Paketler B'den A'ye gidecek*/
                                            testDestAddr1_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }

                                    break;
                                }
                                case 12: /*nodeDistanceTable.Dist_E_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_E_B) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli*/
                                        testDestAddr2_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli + 2 paketleri E node'una göndermeli*/
                                        testDestAddr5_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeE_nextHopUpdated = true;
                                        nodeB_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 7" << endl;
                                    }
                                    /*Relay node buluyoruz. B ile E arasýnda A ya da F relay node olabilir*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_B < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_E < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli*/
                                            testDestAddr2_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli + 2 paketleri E node'una göndermek için A'ye göndermeli*/
                                            testDestAddr1_NextHop_Index = 5; /* Paketler A'den E'ye gidecek*/
                                            testDestAddr5_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_B_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli*/
                                            testDestAddr2_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli + 2 paketleri E node'una göndermek için F'ye göndermeli*/
                                            testDestAddr6_NextHop_Index = 5; /* Paketler F'den E'ye gidecek*/
                                            testDestAddr5_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeE_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                case 14: /*nodeDistanceTable.Dist_B_Dest*/
                                {
                                    testDestAddr3_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli*/
                                    testDestAddr2_NextHop_Index = 4; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli + 2 paketleri direkt gönderebilir*/
                                    nodeB_nextHopUpdated = true;
                                    nodeSource_nextHopUpdated = true;
                                    earlyEnder = true;
                                    EV_INFO << "Entered here 8" << endl;
                                    break;
                                }
                                case 15: /*nodeDistanceTable.Dist_F_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_B_F) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli*/
                                        testDestAddr2_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli + 1 paketleri F node'una göndermeli*/
                                        testDestAddr6_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeB_nextHopUpdated = true;
                                        nodeF_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 9" << endl;
                                    }
                                    /*Relay node buluyoruz. B ile F arasýnda A ya da E relay node olabilir*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_B < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli*/
                                            testDestAddr2_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 2'e göndermeli + 2 paketleri F node'una göndermek için A'ye göndermeli*/
                                            testDestAddr1_NextHop_Index = 6; /* Paketler A'den F'ye gidecek*/
                                            testDestAddr6_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_E_B < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 2;
                                            testDestAddr2_NextHop_Index = 5;
                                            testDestAddr5_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 4;
                                            nodeE_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                default:
                                    EV_INFO << "Entered here 10" << endl;
                                    break;
                            }
                            break;
                        }


                        case 3:/*nodeDistanceTable.Dist_Source_E*/
                        {
                            switch(whoCanSendToDestination[loopCtr2])
                            {
                                case 9: /*nodeDistanceTable.Dist_A_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_A_E) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce E'e göndermeli*/
                                        testDestAddr5_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce 5'e göndermeli + 5 paketleri A node'una göndermeli*/
                                        testDestAddr1_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeA_nextHopUpdated = true;
                                        nodeE_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 11" << endl;
                                    }
                                    /*A ile E direkt haberleþemiyorsa, A ile E arasýndaki relay node bulunmalý: B ya da F*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_B < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_B < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                            testDestAddr5_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri E node'una göndermek için B'ye göndermeli*/
                                            testDestAddr2_NextHop_Index = 1; /* Paketler B'den E'ye gidecek*/
                                            testDestAddr1_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                            EV_INFO << "Entered here 233" << endl;
                                        }
                                        else if((nodeDistanceTable.Dist_A_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli*/
                                            testDestAddr5_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 1'e göndermeli + 1 paketleri E node'una göndermek için F'ye göndermeli*/
                                            testDestAddr6_NextHop_Index = 1; /* Paketler F'den E'ye gidecek*/
                                            testDestAddr1_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                            EV_INFO << "Entered here 244" << endl;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                case 12: /*nodeDistanceTable.Dist_E_Dest*/
                                {
                                    testDestAddr3_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 5'e göndermeli*/
                                    testDestAddr5_NextHop_Index = 4; /*Source paketlerini 4'e iletmek için önce 5'e göndermeli + 5 paketleri direkt gönderebilir*/
                                    nodeE_nextHopUpdated = true;
                                    nodeSource_nextHopUpdated = true;
                                    earlyEnder = true;
                                    EV_INFO << "Entered here 12" << endl;
                                    break;
                                }
                                case 14: /*nodeDistanceTable.Dist_B_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_E_B) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 5'e göndermeli*/
                                        testDestAddr5_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 5'e göndermeli + 5 paketleri B node'una göndermeli*/
                                        testDestAddr2_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeB_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        nodeE_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 13" << endl;
                                    }
                                    /*Relay node buluyoruz. B ile E arasýnda A ya da F relay node olabilir*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_B < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_E < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 5;
                                            testDestAddr5_NextHop_Index = 1;
                                            testDestAddr1_NextHop_Index = 2;
                                            testDestAddr2_NextHop_Index = 4;
                                            nodeA_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_B_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 5;
                                            testDestAddr5_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 2;
                                            testDestAddr2_NextHop_Index = 4;
                                            nodeE_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                case 15: /*nodeDistanceTable.Dist_F_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_E_F) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 5'e göndermeli*/
                                        testDestAddr5_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 5'e göndermeli + 5 paketleri F node'una göndermeli*/
                                        testDestAddr6_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeE_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        nodeF_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 14" << endl;
                                    }
                                    /*E ile F direkt haberleþemiyorsa, E ile F arasýndaki relay node bulunmalý: A ya da B*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_E < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 5;
                                            testDestAddr5_NextHop_Index = 1;
                                            testDestAddr1_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 4;
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_E_B < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_B_F < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 5;
                                            testDestAddr5_NextHop_Index = 2;
                                            testDestAddr2_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 4;
                                            nodeB_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                default:
                                    EV_INFO << "Entered here 15" << endl;
                                    break;
                            }
                            break;
                        }



                        case 4:/*nodeDistanceTable.Dist_Source_F*/
                        {
                            switch(whoCanSendToDestination[loopCtr2])
                            {
                                case 9: /*nodeDistanceTable.Dist_A_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_A_F) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce F'e göndermeli*/
                                        testDestAddr6_NextHop_Index = 1; /*Source paketlerini 4'e iletmek için önce F'e göndermeli + F paketleri A node'una göndermeli*/
                                        testDestAddr1_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeA_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        nodeF_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 16" << endl;
                                    }
                                    /*F ile A direkt haberleþemiyorsa, F ile A arasýndaki relay node bulunmalý: B ya da E*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_B_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_B < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 2;
                                            testDestAddr2_NextHop_Index = 1;
                                            testDestAddr1_NextHop_Index = 4;
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_E_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_E < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 5;
                                            testDestAddr5_NextHop_Index = 1;
                                            testDestAddr1_NextHop_Index = 4;
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                case 12: /*nodeDistanceTable.Dist_E_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_E_F) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 6'e göndermeli*/
                                        testDestAddr6_NextHop_Index = 5; /*Source paketlerini 4'e iletmek için önce 6'e göndermeli + 6 paketleri E node'una göndermeli*/
                                        testDestAddr5_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeE_nextHopUpdated = true;
                                        nodeF_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 17" << endl;
                                    }
                                    /*F ile E direkt haberleþemiyorsa, F ile E arasýndaki relay node bulunmalý: A ya da B*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_E < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 1;
                                            testDestAddr1_NextHop_Index = 5;
                                            testDestAddr5_NextHop_Index = 4;
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_B_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_B < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 2;
                                            testDestAddr2_NextHop_Index = 5;
                                            testDestAddr5_NextHop_Index = 4;
                                            nodeB_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                case 14: /*nodeDistanceTable.Dist_B_Dest*/
                                {
                                    if(((nodeDistanceTable.Dist_B_F) < NODE_COMMUNICATION_RANGE_METERS))
                                    {
                                        testDestAddr3_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 6'e göndermeli*/
                                        testDestAddr6_NextHop_Index = 2; /*Source paketlerini 4'e iletmek için önce 6'e göndermeli + 6 paketleri B node'una göndermeli*/
                                        testDestAddr2_NextHop_Index = 4; /* Paketleri destination node'a göndermeli */
                                        nodeB_nextHopUpdated = true;
                                        nodeF_nextHopUpdated = true;
                                        nodeSource_nextHopUpdated = true;
                                        earlyEnder = true;
                                        EV_INFO << "Entered here 18" << endl;
                                    }
                                    /*F ile B direkt haberleþemiyorsa, F ile B arasýndaki relay node bulunmalý: A ya da E*/
                                    else
                                    {
                                        if((nodeDistanceTable.Dist_A_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_A_B < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 1;
                                            testDestAddr1_NextHop_Index = 2;
                                            testDestAddr2_NextHop_Index = 4;
                                            nodeA_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeB_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else if((nodeDistanceTable.Dist_E_F < NODE_COMMUNICATION_RANGE_METERS) && (nodeDistanceTable.Dist_E_B < NODE_COMMUNICATION_RANGE_METERS))
                                        {
                                            testDestAddr3_NextHop_Index = 6;
                                            testDestAddr6_NextHop_Index = 5;
                                            testDestAddr5_NextHop_Index = 2;
                                            testDestAddr2_NextHop_Index = 4;
                                            nodeB_nextHopUpdated = true;
                                            nodeF_nextHopUpdated = true;
                                            nodeE_nextHopUpdated = true;
                                            nodeSource_nextHopUpdated = true;
                                            earlyEnder = true;
                                        }
                                        else
                                        {
                                            /*geçmiþ olsun*/
                                        }
                                    }
                                    break;
                                }
                                case 15: /*nodeDistanceTable.Dist_F_Dest*/
                                {
                                    testDestAddr3_NextHop_Index = 6; /*Source paketlerini 4'e iletmek için önce 6'e göndermeli*/
                                    testDestAddr6_NextHop_Index = 4; /*Source paketlerini 4'e iletmek için önce 6'e göndermeli + 6 paketleri direkt gönderebilir*/
                                    nodeF_nextHopUpdated = true;
                                    nodeSource_nextHopUpdated = true;
                                    earlyEnder = true;
                                    EV_INFO << "Entered here 19" << endl;
                                    break;
                                }
                                default:
                                    EV_INFO << "Entered here 20" << endl;
                                    break;
                            }
                            break;
                        }
                        default:
                            break;
                    }
                }
            }
        }

        else
        {
            /*Nothing implemented yet*/
        }

    }


    else
    {
        /*ERROR!*/
        return;
    }

    scheduleAt(simTime() + simtime_t(0.7/*1*/), sdnControllerTimer2);

}



/*beratovic*/
void Aodv::handleSdnNodeSourceTimer()
{
    /*Source will periodically check the route updates*/
    //int forLoopRouteCounter = 0;
    //static IRoute *possibleRoute = nullptr;
    static IRoute *newRoutee = nullptr;
    static IRoute *testRouteInCase = nullptr;
    static uint64_t controlPacketCounter;

    if(routeHasChanged == false)
    {
        /*If route will stay same, no need for this handler*/
        return;
    }

    if(true == nodeSource_nextHopUpdated)
    {
        controlPacketCounter++;
        EV_DETAIL << "controlPacketCounter : " << controlPacketCounter << endl;
        testRouteInCase = routingTable->findBestMatchingRoute(testDestAddr4); /*4'e giden yol varsa kaldýr*/
        if(nullptr != testRouteInCase)
        {
            routingTable->removeRoute(testRouteInCase);
            routingTable->deleteRoute(testRouteInCase);
        }

        nodeSource_aodvRouteCreationDisabled = true;
        newRoutee = createRoute(L3Address(Ipv4Address(20,0,0,testDestAddr3_Destination_Index)),
                 L3Address(Ipv4Address(20,0,0,testDestAddr3_NextHop_Index)),
                 0, false, 0, true, SIMULATION_RUN_TIME);

         if(nullptr != newRoutee)
         {
             //routingTable->addRoute(newRoutee);
         }
         nodeSource_nextHopUpdated = false;
    }

    /* Node route configuration ends at SIMULATION_RUN_TIME*/
    if(simTime() > simtime_t(SIMULATION_RUN_TIME))
    {
        return;
    }

     if(nullptr == (routingTable->findBestMatchingRoute(testDestAddrController) ))
     {
         /*Default rule olarak, controller node'a her zaman eriþebilmemiz gerektiðini yeniden ekliyoruz*/
         nodeSource_aodvRouteCreationDisabled = true;
         newRoutee = createRoute(L3Address(Ipv4Address(20,0,0,0)),
                  L3Address(Ipv4Address(20,0,0,0)), 0, false, 0, true, SIMULATION_RUN_TIME);
     }

    /*Reschedule to provide periodicity(2sec)*/
    scheduleAt(simTime() + simtime_t(0.7/*1*/), sdnNodeSourceTimer);

}



void Aodv::handleSdnNodeATimer()
{
    /*Source will periodically check the route updates*/
    //int forLoopRouteCounter = 0;
    //static IRoute *possibleRoute = nullptr;
    static IRoute *newRoutee = nullptr;
    static IRoute *testRouteInCase = nullptr;

    if(routeHasChanged == false)
    {
        /*If route will stay same, no need for this handler*/
        return;
    }

    if(true == nodeA_nextHopUpdated)
    {

        testRouteInCase = routingTable->findBestMatchingRoute(testDestAddr4); /*4'e giden yol varsa kaldýr*/
        if(nullptr != testRouteInCase)
        {
            routingTable->removeRoute(testRouteInCase);
            routingTable->deleteRoute(testRouteInCase);
        }

        nodeA_aodvRouteCreationDisabled = true;
        newRoutee = createRoute(L3Address(Ipv4Address(20,0,0,testDestAddr1_Destination_Index)),
                 L3Address(Ipv4Address(20,0,0,testDestAddr1_NextHop_Index)),
                 0, false, 0, true, SIMULATION_RUN_TIME);

         if(nullptr != newRoutee)
         {
             //routingTable->addRoute(newRoutee);
         }
         nodeA_nextHopUpdated = false;
    }

    /* Node route configuration ends at SIMULATION_RUN_TIME*/
    if(simTime() > simtime_t(SIMULATION_RUN_TIME))
    {
        return;
    }

     if(nullptr == (routingTable->findBestMatchingRoute(testDestAddrController) ))
     {
         /*Default rule olarak, controller node'a her zaman eriþebilmemiz gerektiðini yeniden ekliyoruz*/
         nodeA_aodvRouteCreationDisabled = true;
         newRoutee = createRoute(L3Address(Ipv4Address(20,0,0,0)),
                  L3Address(Ipv4Address(20,0,0,0)), 0, false, 0, true, SIMULATION_RUN_TIME);
     }

    /*Reschedule to provide periodicity(2sec)*/
    scheduleAt(simTime() + simtime_t(0.7/*1*/), sdnNodeATimer);
}



void Aodv::handleSdnNodeBTimer()
{
    /*Source will periodically check the route updates*/
    //int forLoopRouteCounter = 0;
    //static IRoute *possibleRoute = nullptr;
    static IRoute *newRoutee = nullptr;
    static IRoute *testRouteInCase = nullptr;

    if(routeHasChanged == false)
    {
        /*If route will stay same, no need for this handler*/
        return;
    }

    if(true == nodeB_nextHopUpdated)
    {
        testRouteInCase = routingTable->findBestMatchingRoute(testDestAddr4); /*4'e giden yol varsa kaldýr*/
        if(nullptr != testRouteInCase)
        {
            routingTable->removeRoute(testRouteInCase);
            routingTable->deleteRoute(testRouteInCase);
        }

        nodeB_aodvRouteCreationDisabled = true;
        newRoutee = createRoute(L3Address(Ipv4Address(20,0,0,testDestAddr2_Destination_Index)),
                 L3Address(Ipv4Address(20,0,0,testDestAddr2_NextHop_Index)),
                 0, 1, 0, true, SIMULATION_RUN_TIME);

         if(nullptr != newRoutee)
         {
             //routingTable->addRoute(newRoutee);
         }
         nodeB_nextHopUpdated = false;
    }

    /* Node route configuration ends at SIMULATION_RUN_TIME*/
    if(simTime() > simtime_t(SIMULATION_RUN_TIME))
    {
        return;
    }

    if(nullptr == (routingTable->findBestMatchingRoute(testDestAddr4) ))
    {
        /*Default rule olarak, controller node'a her zaman eriþebilmemiz gerektiðini yeniden ekliyoruz*/
        nodeB_aodvRouteCreationDisabled = true;
        newRoutee = createRoute(L3Address(Ipv4Address(20,0,0,0)),
                 L3Address(Ipv4Address(20,0,0,0)), 0, false, 0, true, SIMULATION_RUN_TIME);
    }

    /*Reschedule to provide periodicity(2sec)*/
    scheduleAt(simTime() + simtime_t(0.7/*1*/), sdnNodeBTimer);
}


void Aodv::handleSdnNodeFTimer()
{
    /*Source will periodically check the route updates*/
    //int forLoopRouteCounter;
    //static IRoute *possibleRoute = nullptr;
    static IRoute *newRoutee = nullptr;
    static IRoute *testRouteInCase = nullptr;


    if(routeHasChanged == false)
    {
        /*If route will stay same, no need for this handler*/
        return;
    }

    if(true == nodeF_nextHopUpdated)
    {
        testRouteInCase = routingTable->findBestMatchingRoute(testDestAddr4); /*4'e giden yol varsa kaldýr*/
        if(nullptr != testRouteInCase)
        {
            routingTable->removeRoute(testRouteInCase);
            routingTable->deleteRoute(testRouteInCase);
        }

        nodeF_aodvRouteCreationDisabled = true;
        newRoutee = createRoute(L3Address(Ipv4Address(20,0,0,testDestAddr6_Destination_Index)),
                 L3Address(Ipv4Address(20,0,0,testDestAddr6_NextHop_Index)),
                 0, true, 1, true, SIMULATION_RUN_TIME);

         if(nullptr != newRoutee)
         {
             //routingTable->addRoute(newRoutee);
         }
         nodeF_nextHopUpdated = false;
    }

    /* Node route configuration ends at SIMULATION_RUN_TIME*/
    if(simTime() > simtime_t(SIMULATION_RUN_TIME))
    {
        return;
    }

     if(nullptr == (routingTable->findBestMatchingRoute(testDestAddrController) ))
     {
         /*Default rule olarak, controller node'a her zaman eriþebilmemiz gerektiðini yeniden ekliyoruz*/
         nodeF_aodvRouteCreationDisabled = true;
         newRoutee = createRoute(L3Address(Ipv4Address(20,0,0,0)),
                  L3Address(Ipv4Address(20,0,0,0)), 1, 1, 1, true, SIMULATION_RUN_TIME);
     }

    /*Reschedule to provide periodicity(2sec)*/
    scheduleAt(simTime() + simtime_t(0.7/*1*/), sdnNodeFTimer);
}



void Aodv::handleSdnNodeETimer()
{
    /*Source will periodically check the route updates*/
    //int forLoopRouteCounter = 0;
    //static IRoute *possibleRoute = nullptr;
    static IRoute *newRoutee = nullptr;
    static IRoute *testRouteInCase = nullptr;

    EV_INFO << "aaaaaa" << endl;

    if(routeHasChanged == false)
    {
        /*If route will stay same, no need for this handler*/
        return;
    }

    if(true == nodeE_nextHopUpdated)
    {
        testRouteInCase = routingTable->findBestMatchingRoute(testDestAddr4); /*4'e giden yol varsa kaldýr*/
        if(nullptr != testRouteInCase)
        {
            routingTable->removeRoute(testRouteInCase);
            routingTable->deleteRoute(testRouteInCase);
        }

        nodeE_aodvRouteCreationDisabled = true;
        newRoutee = createRoute(L3Address(Ipv4Address(20,0,0,testDestAddr5_Destination_Index)),
                 L3Address(Ipv4Address(20,0,0,testDestAddr5_NextHop_Index)),
                 0, false, 0, true, SIMULATION_RUN_TIME);

         if(nullptr != newRoutee)
         {
             //routingTable->addRoute(newRoutee);
         }
         nodeE_nextHopUpdated = false;
    }

    /* Node route configuration ends at SIMULATION_RUN_TIME*/
    if(simTime() > simtime_t(SIMULATION_RUN_TIME))
    {
        return;
    }

    if(nullptr == (routingTable->findBestMatchingRoute(testDestAddrController) ))
    {
        /*Default rule olarak, controller node'a her zaman eriþebilmemiz gerektiðini yeniden ekliyoruz*/
        nodeE_aodvRouteCreationDisabled = true;
        createRoute(L3Address(Ipv4Address(20,0,0,0)), L3Address(Ipv4Address(20,0,0,0)), 1, 1, 1, true, SIMULATION_RUN_TIME);
    }

    /*Reschedule to provide periodicity(2sec)*/
    scheduleAt(simTime() + simtime_t(0.7/*1*/), sdnNodeETimer);
}







#endif

Aodv::~Aodv()
{
    clearState();
    delete helloMsgTimer;
    delete expungeTimer;
    delete counterTimer;
    delete rrepAckTimer;
    delete blacklistTimer;
    delete sdnControllerTimer; /*beratovic*/
    delete sdnControllerTimer2;
#if 1
    delete sdnNodeSourceTimer; /*beratovic*/
    delete sdnNodeATimer;
    delete sdnNodeBTimer;
    delete sdnNodeFTimer;
    delete sdnNodeETimer;
#endif
}

} // namespace aodv
} // namespace inet

