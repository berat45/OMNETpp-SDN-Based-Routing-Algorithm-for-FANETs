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

#ifndef __INET_AODV_H
#define __INET_AODV_H

#include <map>

#include "inet/common/INETDefs.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/contract/IL3AddressType.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/networklayer/contract/IRoutingTable.h"
#include "inet/routing/aodv/AodvControlPackets_m.h"
#include "inet/routing/aodv/AodvRouteData.h"
#include "inet/routing/base/RoutingProtocolBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"


#include "inet/mobility/single/CircleMobility.h" /*beratovic*/
#include "inet/mobility/single/RandomWaypointMobility.h" /*beratovic*/
#include <omnetpp/ccomponenttype.h> /*beratovic*/



namespace inet {

/*******/
double RandomWaypointMobility::node_A_Xcoordinate = 0;
double RandomWaypointMobility::node_A_Ycoordinate = 0;

double RandomWaypointMobility::node_B_Xcoordinate = 0;
double RandomWaypointMobility::node_B_Ycoordinate = 0;

double RandomWaypointMobility::node_Source_Xcoordinate = 0;
double RandomWaypointMobility::node_Source_Ycoordinate = 0;

double RandomWaypointMobility::node_Destination_Xcoordinate = 0;
double RandomWaypointMobility::node_Destination_Ycoordinate = 0;

double RandomWaypointMobility::node_E_Xcoordinate = 0;
double RandomWaypointMobility::node_E_Ycoordinate = 0;

double RandomWaypointMobility::node_F_Xcoordinate = 0;
double RandomWaypointMobility::node_F_Ycoordinate = 0;

double RandomWaypointMobility::sourceNodeUpdatedZAxisValue = 0.0;
double RandomWaypointMobility::destinationNodeUpdatedZAxisValue = 0.0;

/********/

double CircleMobility::node_A_Xcoordinate = 0;
double CircleMobility::node_A_Ycoordinate = 0;

double CircleMobility::node_B_Xcoordinate = 0;
double CircleMobility::node_B_Ycoordinate = 0;

double CircleMobility::node_Source_Xcoordinate = 0;
double CircleMobility::node_Source_Ycoordinate = 0;

double CircleMobility::node_Destination_Xcoordinate = 0;
double CircleMobility::node_Destination_Ycoordinate = 0;

double CircleMobility::node_E_Xcoordinate = 0;
double CircleMobility::node_E_Ycoordinate = 0;

double CircleMobility::node_F_Xcoordinate = 0;
double CircleMobility::node_F_Ycoordinate = 0;

double CircleMobility::sourceNodeUpdatedZAxisValue = 0.0;
double CircleMobility::destinationNodeUpdatedZAxisValue = 0.0;



namespace aodv {

/*
 * This class implements AODV routing protocol and Netfilter hooks
 * in the IP-layer required by this protocol.
 */

class INET_API Aodv : public RoutingProtocolBase, public NetfilterBase::HookBase, public UdpSocket::ICallback, public cListener
{
  protected:
    /*
     * It implements a unique identifier for an arbitrary RREQ message
     * in the network. See: rreqsArrivalTime.
     */
    class RreqIdentifier
    {
      public:
        L3Address originatorAddr;
        unsigned int rreqID;
        RreqIdentifier(const L3Address& originatorAddr, unsigned int rreqID) : originatorAddr(originatorAddr), rreqID(rreqID) {};
        bool operator==(const RreqIdentifier& other) const
        {
            return this->originatorAddr == other.originatorAddr && this->rreqID == other.rreqID;
        }
    };

    class RreqIdentifierCompare
    {
    public:
        bool operator()(const RreqIdentifier& lhs, const RreqIdentifier& rhs) const
        {
            if (lhs.originatorAddr < rhs.originatorAddr)
                return true;
            else if (lhs.originatorAddr > rhs.originatorAddr)
                return false;
            else
                return lhs.rreqID < rhs.rreqID;
        }
    };

    // context
    IL3AddressType *addressType = nullptr;    // to support both Ipv4 and v6 addresses.

    // environment
    cModule *host = nullptr;
    IRoutingTable *routingTable = nullptr;
    IInterfaceTable *interfaceTable = nullptr;
    INetfilter *networkProtocol = nullptr;
    UdpSocket socket;
    bool usingIpv6 = false;

    // AODV parameters: the following parameters are configurable, see the NED file for more info.
    unsigned int rerrRatelimit = 0;
    unsigned int aodvUDPPort = 0;
    bool askGratuitousRREP = false;
    bool useHelloMessages = false;
    bool destinationOnlyFlag = false;
    simtime_t maxJitter;
    simtime_t activeRouteTimeout;
    simtime_t helloInterval;
    unsigned int netDiameter = 0;
    unsigned int rreqRetries = 0;
    unsigned int rreqRatelimit = 0;
    unsigned int timeoutBuffer = 0;
    unsigned int ttlStart = 0;
    unsigned int ttlIncrement = 0;
    unsigned int ttlThreshold = 0;
    unsigned int localAddTTL = 0;
    unsigned int allowedHelloLoss = 0;
    simtime_t nodeTraversalTime;
    cPar *jitterPar = nullptr;
    cPar *periodicJitter = nullptr;

    /* beratovic parameters start */
    bool controllerModeEnabled = true;  /* True : Default AODV features are disabled */
    /* beratovic parameters end   */

    // the following parameters are calculated from the parameters defined above
    // see the NED file for more info
    simtime_t deletePeriod;
    simtime_t myRouteTimeout;
    simtime_t blacklistTimeout;
    simtime_t netTraversalTime;
    simtime_t nextHopWait;
    simtime_t pathDiscoveryTime;

    // state
    unsigned int rreqId = 0;    // when sending a new RREQ packet, rreqID incremented by one from the last id used by this node
    unsigned int sequenceNum = 0;    // it helps to prevent loops in the routes (RFC 3561 6.1 p11.)
    std::map<L3Address, WaitForRrep *> waitForRREPTimers;    // timeout for Route Replies
    std::map<RreqIdentifier, simtime_t, RreqIdentifierCompare> rreqsArrivalTime;    // maps RREQ id to its arriving time
    L3Address failedNextHop;    // next hop to the destination who failed to send us RREP-ACK
    std::map<L3Address, simtime_t> blacklist;    // we don't accept RREQs from blacklisted nodes
    unsigned int rerrCount = 0;    // num of originated RERR in the last second
    unsigned int rreqCount = 0;    // num of originated RREQ in the last second
    simtime_t lastBroadcastTime;    // the last time when any control packet was broadcasted
    std::map<L3Address, unsigned int> addressToRreqRetries;    // number of re-discovery attempts per address

    // self messages
    cMessage *helloMsgTimer = nullptr;    // timer to send hello messages (only if the feature is enabled)
    cMessage *expungeTimer = nullptr;    // timer to clean the routing table out
    cMessage *counterTimer = nullptr;    // timer to set rrerCount = rreqCount = 0 in each second
    cMessage *rrepAckTimer = nullptr;    // timer to wait for RREP-ACKs (RREP-ACK timeout)
    cMessage *blacklistTimer = nullptr;    // timer to clean the blacklist out
    cMessage *sdnControllerTimer = nullptr; //SDN Controller timer message  /*beratovic*/
    cMessage *sdnControllerTimer2 = nullptr;
#if 1
    cMessage *sdnNodeSourceTimer = nullptr; //SDN Node Source timer message /*beratovic*/
    cMessage *sdnNodeATimer = nullptr;
    cMessage *sdnNodeBTimer = nullptr;
    cMessage *sdnNodeFTimer = nullptr;
    cMessage *sdnNodeETimer = nullptr;
#endif

    // lifecycle
    simtime_t rebootTime;    // the last time when the node rebooted

    // internal
    std::multimap<L3Address, Packet *> targetAddressToDelayedPackets;    // queue for the datagrams we have no route for

  public:
    /*beratovic*/
    CircleMobility* singletonMannerCreateCircleMobObject()
    {
        static CircleMobility* dummyPtr;
        static bool singletonController = true;
        if(singletonController)
        {
            dummyPtr = new CircleMobility();
            singletonController = false;
        }
        return dummyPtr;
    }

    RandomWaypointMobility* singletonMannerCreateCircleMobObject_RWP()
    {
        static RandomWaypointMobility* dummyPtr;
        static bool singletonController = true;
        if(singletonController)
        {
            dummyPtr = new RandomWaypointMobility();
            singletonController = false;
        }
        return dummyPtr;
    }


    /* Prototype 1 - beratovic */

/*Definitions are here! Define necessary parameters! */
#define CONTROLLER_MODE_ENABLED
#ifdef  CONTROLLER_MODE_ENABLED
    /*********************************************************************//*********************************************************************/
    /*********************************************************************//*********************************************************************/
    /* beratovic starts */

#define SIMULATION_RUN_TIME 1800.0
//#define NODE_COMMUNICATION_RANGE_METERS (signed int)1025 /* Hýz = 5 10 15*/
#define NODE_COMMUNICATION_RANGE_METERS (signed int)950 /* Hýz = 20*/


#define NUMBER_OF_NODES     6

    bool sdnControllerActivated = false;   /* In default there is no backup path */
    L3Address testDestAddrController = L3Address(Ipv4Address(20,0,0,0)); /*CONTROLLER*/
    L3Address testDestAddr1 = L3Address(Ipv4Address(20,0,0,1));
    L3Address testDestAddr2 = L3Address(Ipv4Address(20,0,0,2));
    L3Address testDestAddr3 = L3Address(Ipv4Address(20,0,0,3));
    L3Address testDestAddr4 = L3Address(Ipv4Address(20,0,0,4));
    L3Address testDestAddr5 = L3Address(Ipv4Address(20,0,0,5));
    L3Address testDestAddr6 = L3Address(Ipv4Address(20,0,0,6));

    /* Initial position of the nodes should be typed manually */
    typedef struct
    {
        int  node_Xcoord; //in meters
        int  node_Ycoord; //in meters
    }SDN_NODE_INITIAL_POSITION_STRUCT;
    SDN_NODE_INITIAL_POSITION_STRUCT nodePosition[NUMBER_OF_NODES];

    typedef enum
    {
        NODE_A = 0,
        NODE_B,
        NODE_SOURCE,
        NODE_DESTINATION,
        NODE_E,
        NODE_F,
    }SDN_NODE_NUMBERS_ENUM;
#define NODE_A_NODE_NUMBER_DEF              (uint8_t)0
#define NODE_B_NODE_NUMBER_DEF              (uint8_t)1
#define NODE_SOURCE_NODE_NUMBER_DEF         (uint8_t)2
#define NODE_DESTINATION_NODE_NUMBER_DEF    (uint8_t)3
#define NODE_E_NODE_NUMBER_DEF              (uint8_t)4
#define NODE_F_NODE_NUMBER_DEF              (uint8_t)5



#define UNKNOWN_INDEX 9
    /*Burada, ilgili node'un ip adresinin son sayýsýna göre paket içeriðini oluþturuyoruz!!*/
    static uint8_t testDestAddr1_Destination_Index;
    static uint8_t testDestAddr1_NextHop_Index;

    static uint8_t testDestAddr2_Destination_Index;
    static uint8_t testDestAddr2_NextHop_Index;

    static uint8_t testDestAddr3_Destination_Index;
    static uint8_t testDestAddr3_NextHop_Index;

    static uint8_t testDestAddr4_Destination_Index;
    static uint8_t testDestAddr4_NextHop_Index;

    static uint8_t testDestAddr5_Destination_Index;
    static uint8_t testDestAddr5_NextHop_Index;

    static uint8_t testDestAddr6_Destination_Index;
    static uint8_t testDestAddr6_NextHop_Index;

    static uint8_t testDestAddrController_Destination_Index;
    static uint8_t testDestAddrController_NextHop_Index;


    /*Message between PACKET SENDER NODE and CONTROLLER NODE - It is binary actually*/
    static bool routeHasChanged; /* static: Same value for all objects */
    static bool nodeA_aodvRouteCreationDisabled;
    static bool nodeB_aodvRouteCreationDisabled;
    static bool nodeSource_aodvRouteCreationDisabled;
    static bool nodeDestination_aodvRouteCreationDisabled;
    static bool nodeE_aodvRouteCreationDisabled;
    static bool nodeF_aodvRouteCreationDisabled;
    static bool nodeController_aodvRouteCreationDisabled;

    static bool nodeA_nextHopUpdated; /* A node'unda controller'da deðiþiklik varsa true'ya çekilecektir. Senkronizasyon parametresi*/
    static bool nodeB_nextHopUpdated; /* B node'unda controller'da deðiþiklik varsa true'ya çekilecektir. Senkronizasyon parametresi*/
    static bool nodeE_nextHopUpdated; /* E node'unda controller'da deðiþiklik varsa true'ya çekilecektir. Senkronizasyon parametresi*/
    static bool nodeF_nextHopUpdated; /* F node'unda controller'da deðiþiklik varsa true'ya çekilecektir. Senkronizasyon parametresi*/
    static bool nodeSource_nextHopUpdated;

//#define IEEE_80211_p_MAX_RANGE (int)1100  //in meters
#define DISTANCE_WITH_OBSTACLE (int)10000 //in meters. If obstacle exists between 2 nodes, set one of it's position to this definition !!!!!!!!!!!!!!!!!
    typedef struct
    {
        signed int Dist_Source_A;
        signed int Dist_Source_B;
        signed int Dist_Source_E;
        signed int Dist_Source_F;
        signed int Dist_Source_Dest;
        signed int Dist_A_E;
        signed int Dist_A_B;
        signed int Dist_A_F;
        signed int Dist_A_Dest;
        signed int Dist_E_B;
        signed int Dist_E_F;
        signed int Dist_E_Dest;
        signed int Dist_B_F;
        signed int Dist_B_Dest;
        signed int Dist_F_Dest;
    }SDN_C_NODE_DIST_TABLE_STRUCT;
    SDN_C_NODE_DIST_TABLE_STRUCT nodeDistanceTable;





/* -->> LIST OF IMPLEMENTED OPENFLOW MESSAGES <<-- */
/*          HELLO & HELLO_EXTENDED
 *          ECHO REQUEST & ECHO RESPONSE
 *          BARRIER MESSAGE
 *          ERROR MESSAGE
 *          PACKET-IN & PACKET-OUT
 *          ROLE_REQ & ROLE_RES                    */

    typedef enum  {
    /* Immutable messages. */
    OFPT_HELLO = 0,                 /* Symmetric message */
    OFPT_ERROR = 1,                 /* Symmetric message */
    OFPT_ECHO_REQUEST = 2,          /* Symmetric message */
    OFPT_ECHO_REPLY = 3,            /* Symmetric message */
    OFPT_EXPERIMENTER = 4,          /* Symmetric message */

    /* Switch configuration messages. */
    OFPT_FEATURES_REQUEST = 5,      /* Controller/switch message */
    OFPT_FEATURES_REPLY = 6,        /* Controller/switch message */
    OFPT_GET_CONFIG_REQUEST = 7,    /* Controller/switch message */
    OFPT_GET_CONFIG_REPLY = 8,      /* Controller/switch message */
    OFPT_SET_CONFIG = 9,            /* Controller/switch message */

    /* Asynchronous messages. */
    OFPT_PACKET_IN = 10,        /* Async message */
    OFPT_FLOW_REMOVED = 11,     /* Async message */
    OFPT_PORT_STATUS = 12,      /* Async message */

    /* Controller command messages. */
    OFPT_PACKET_OUT = 13,       /* Controller/switch message */
    OFPT_FLOW_MOD = 14,         /* Controller/switch message */
    OFPT_GROUP_MOD = 15,        /* Controller/switch message */
    OFPT_PORT_MOD = 16,         /* Controller/switch message */
    OFPT_TABLE_MOD = 17,        /* Controller/switch message */

    /* Multipart messages. */
    OFPT_MULTIPART_REQUEST = 18, /* Controller/switch message */
    OFPT_MULTIPART_REPLY = 19,   /* Controller/switch message */

    /* Barrier messages. */
    OFPT_BARRIER_REQUEST = 20,  /* Controller/switch message */
    OFPT_BARRIER_REPLY = 21,    /* Controller/switch message */

    /* Queue Configuration messages. */
    OFPT_QUEUE_GET_CONFIG_REQUEST = 22, /* Controller/switch message */
    OFPT_QUEUE_GET_CONFIG_REPLY = 23,   /* Controller/switch message */

    /* Controller role change request messages. */
    OFPT_ROLE_REQUEST = 24, /* Controller/switch message */
    OFPT_ROLE_REPLY = 25,   /* Controller/switch message */

    /* Asynchronous message configuration. */
    OFPT_GET_ASYNC_REQUEST = 26,    /* Controller/switch message */
    OFPT_GET_ASYNC_REPLY = 27,      /* Controller/switch message */
    OFPT_SET_ASYNC = 28,            /* Controller/switch message */

    /* Meters and rate limiters configuration messages. */
    OFPT_METER_MOD = 29, /* Controller/switch message */
    }OPENFLOW_OFP_TYPE;

    /* Header on all OpenFlow packets. */
    #define OFP_VERSION_FANET_v_0 (uint8_t)0
    typedef struct {
    uint8_t version;  /* OFP_VERSION. */
    uint8_t type;     /* One of the OFPT_ constants :(OPENFLOW_OFP_TYPE) */
    /*uint16_t*/uint8_t length;  /* Length including this ofp_header. */
    /*uint32_t*/uint8_t xid;     /* Transaction id associated with this packet. Replies use the same id as was in the request to facilitate pairing. */
    }OPENFLOW_OFP_HEADER;





    /*********************************************************************/
    /* OPENFLOW HELLO MESSAGE IMPLEMENTATION - EXTENDED & UPDATED VERSION */
    /*********************************************************************/
    /* With the help of the hello message, each node will introduce itself to the controller.
     * Controller takes this message and decodes it to process GPS data and mobility data according
     * to the request type. For now, it can be just routing table request.
     *
     * TODO:
     * - Mobility models should be implemented to the enumeration
     * - Request types can be extended
     * */

    typedef enum
    {

    }OPENFLOW_MOBILITY_TYPE_ENUM;

    typedef enum
    {
        NO_REQUEST = 0,
        ROUTING_TABLE = 1,
        TOTAL_NUM_OF_OPENFLOW_REQUEST_TYPE_ENUM,
    }OPENFLOW_REQUEST_TYPE_ENUM;
    #define OPENFLOW_REQUEST_TYPE_NO_REQUEST    (uint8_t)0
    #define OPENFLOW_REQUEST_TYPE_ROUTING_TABLE (uint8_t)1

    #define SDN_MOBILITY_TYPE_CIRCULAR       (uint8_t)0 /*CIRCULAR MOBILITY*/
    #define SDN_MOBILITY_TYPE_RANDOMWAYPOINT (uint8_t)1 /*RWP MOBILITY*/
    #define SDN_MOBILITY_TYPE_NONSENSE       (uint8_t)9 /*USAGE: MOBILITY TYPE IN HELLO MESSAGE IS NOT TAKEN INTO CONSIDERATION*/

    typedef struct
    {
        OPENFLOW_OFP_HEADER header;               /* Standard header field*/
        uint8_t nodeId;                           /* Node unique id */
        //#define GPS_DATA_ENTRY_NUM 2
        //signed   int gpsData[GPS_DATA_ENTRY_NUM]; /* gpsData[0] for latitude and gpsData[1] for longitude */
        uint8_t mobilityType;                /* Mobility type TODO: to be converted into ENUM */
        uint8_t reqType;                     /* Initial request type */
    }OPENFLOW_HELLO_PACKET_CONTENT_STRUCT;
#define OPENFLOW_HELLO_PACKET_CONTENT_STRUCT_SIZE sizeof(OPENFLOW_HELLO_PACKET_CONTENT_STRUCT)


    /* Capabilities supported by the datapath. */
    typedef enum
    {
        OFPC_FLOW_STATS = 1 << 0, /* Flow statistics. */
        OFPC_TABLE_STATS = 1 << 1, /* Table statistics. */
        OFPC_PORT_STATS = 1 << 2, /* Port statistics. */
        OFPC_GROUP_STATS = 1 << 3, /* Group statistics. */
        OFPC_IP_REASM = 1 << 5, /* Can reassemble IP fragments. */
        OFPC_QUEUE_STATS = 1 << 6, /* Queue statistics. */
        OFPC_PORT_BLOCKED = 1 << 8 /* Switch will block looping ports. */
    }OPENFLOW_OFP_CAPABILITIES;


    /* Since I will not implement handshake message (handshake is not considered for now between switches and controllers), some handshake messages are implemented
     * into hello packet and named as HELLO_PACKET_EXTENDED */
    typedef struct
    {
        OPENFLOW_HELLO_PACKET_CONTENT_STRUCT helloMsg;

        /*uint64_t*/uint8_t datapath_id;       /* Datapath unique ID. The lower 48-bits are for a MAC address, while the upper 16-bits are implementer-defined. */
        uint8_t n_tables;                      /* Number of tables supported by datapath. */
        /*uint32_t*/uint8_t capabilities;      /* Bitmap of support "ofp_capabilities". (bitmap -> OPENFLOW_OFP_CAPABILITIES) */

    }OPENFLOW_HELLO_PACKET_EXTENDED_CONTENT_STRUCT;





    /*********************************************************************/
    /* OPENFLOW ECHO REQUEST & ECHO REPLY MESSAGE IMPLEMENTION */
    /*********************************************************************/
    /* According to the ONF document, echo messages can be used for to check latency, to measure bandwidth, or
     * to verify liveness. For us, it will be using to guarantee liveness (think like control message
     * to increase reliability). Request message and reply message will be the same. */
    typedef struct
    {
        OPENFLOW_OFP_HEADER header; /* Standard header field*/
        unsigned int nodeId;
    }OPENFLOW_ECHO_REQUEST_HEADER_STRUCT;
#define ECHO_REQUEST_HEADER_STRUCT_SIZE sizeof(OPENFLOW_ECHO_REQUEST_HEADER_STRUCT)

    typedef enum
    {
        LIVENESS = 1,
        TOTAL_NUM_OF_ECHO_REQUEST_PAYLOAD_ENUM,
    }OPENFLOW_ECHO_REQUEST_PAYLOAD_ENUM;

    typedef struct
    {
        OPENFLOW_ECHO_REQUEST_HEADER_STRUCT header;
        OPENFLOW_ECHO_REQUEST_PAYLOAD_ENUM  payload;
    }OPENFLOW_ECHOREQ_PACKET_CONTENT_STRUCT;
#define OPENFLOW_ECHOREQ_PACKET_CONTENT_STRUCT_SIZE sizeof(OPENFLOW_ECHOREQ_PACKET_CONTENT_STRUCT)

    /* Both are the same type structures */
#define OPENFLOW_ECHOREP_PACKET_CONTENT_STRUCT  OPENFLOW_ECHOREQ_PACKET_CONTENT_STRUCT
#define OPENFLOW_ECHOREP_PACKET_CONTENT_STRUCT_SIZE  OPENFLOW_ECHOREQ_PACKET_CONTENT_STRUCT_SIZE





    /*********************************************************************/
    /* OPENFLOW BARRIER MESSAGE IMPLEMENTION */
    /*********************************************************************/
    /* According to the ONF document, Barrier messages are used to be sure about the node has completed all of the protocol handshake
     * (like hello message transfer, node internal processes etc). In this project, this packet type will be used to provide verification.
     *
     * Controller node can check all other nodes periodically/reactively to be sure about their situations by using OPENFLOW_BARRIER_STRUCT message struct. */

    typedef enum
    {
        BARRIER_VALIDATED = 0,
        BARRIER_PROCESSING,
        BARRIER_ERROR,
    }BARRIER_HEADER_TYPE_ENUM;

    typedef struct
    {
        OPENFLOW_OFP_HEADER header; /* Standard header field*/
        BARRIER_HEADER_TYPE_ENUM barrierSpecificHeader;
    }OPENFLOW_BARRIER_REQ_STRUCT;
#define OPENFLOW_BARRIER_REQ_STRUCT_SIZE sizeof(OPENFLOW_BARRIER_REQ_STRUCT)
    /* Both are the same type structures */
#define OPENFLOW_BARRIER_REP_STRUCT        OPENFLOW_BARRIER_REQ_STRUCT
#define OPENFLOW_BARRIER_REP_STRUCT_SIZE   OPENFLOW_BARRIER_REP_STRUCT_SIZE


    /*********************************************************************/
    /* OPENFLOW ERROR MESSAGE IMPLEMENTION */
    /*********************************************************************/
    /* Error message can be sent from processing node to the controller node or vice versa. It indicates the failure of the operation like:
     * -- Malformed messages
     * -- Version negotiation failure (general term. for us, there is no specific protocol packet type for this project)
     * -- State change at the processing node (switch)
     * etc.*/


#define OPENFLOW_ERROR_STATE_CHANGE             (uint8_t)0
#define OPENFLOW_ERROR_VERSION_INCONSISTENCY    (uint8_t)1
#define OPENFLOW_ERROR_MALFORMED_PACKET         (uint8_t)2

    typedef struct
    {
        OPENFLOW_OFP_HEADER header; /* Standard header field*/
        uint8_t nodeId;
        uint8_t errMsgContent;
    }OPENFLOW_ERROR_MSG_STRUCT;
#define OPENFLOW_ERROR_MSG_STRUCT_SIZE sizeof(OPENFLOW_ERROR_MSG_STRUCT)



    /*********************************************************************/
    /* OPENFLOW PACKET-IN & PACKET-OUT MESSAGES IMPLEMENTION */
    /*********************************************************************/

    /* Packet-in message is sent from switch to the controller due to explicit action or mismatch in the match table, or a ttl error */
    /* Structure is similar with the structure that is defined in the ONF document (v1.3.1)*/

    typedef enum {
        OFPR_NO_MATCH = 0,      /* No matching flow (table-miss flow entry). */
        OFPR_ACTION = 1,        /* Action explicitly output to controller. */
        OFPR_INVALID_TTL = 2,   /* Packet has invalid TTL */
    }OPENFLOW_OFP_PACKET_IN_REASON_ENUM;

    typedef struct
    {
        OPENFLOW_OFP_HEADER header;                 /* Standard header field*/
        uint32_t buffer_id;                         /* ID assigned by datapath. */
        uint16_t total_len;                         /* Full length of frame. (BE: can be used to check whether the packet is malformed or not)*/
        OPENFLOW_OFP_PACKET_IN_REASON_ENUM reason;  /* Reason packet is being sent (one of OFPR_*) */
        uint8_t table_id;                           /* ID of the table that was looked up */
        uint64_t cookie;                            /* Cookie of the flow entry that was looked up. */
#if 0
        struct ofp_match match;                     /* Packet metadata. Variable size. TODO: Paketlerin nasýl gönderileceði vs gerçeklenecek, henüz çalýþma yapýlmadý.*/
#endif
    }OPENFLOW_PACKET_IN_MSG_STRUCT;
#define OPENFLOW_PACKET_IN_MSG_STRUCT_SIZE sizeof(OPENFLOW_PACKET_IN_MSG_STRUCT)


    /* The buffer_id refers to a packet buered at the switch and sent to the controller by a packet-in
     * message. If no buered packet is associated with the
     * flow mod, it must be set to OFP_NO_BUFFER */
#define OFP_NO_BUFFER 0xffffffff

    typedef enum
    {
           OFPAT_OUTPUT = 0,           /* Output to switch port. */
           OFPAT_COPY_TTL_OUT = 11,    /* Copy TTL "outwards" -- from next-to-outermost to outermost */
           OFPAT_COPY_TTL_IN = 12,     /* Copy TTL "inwards" -- from outermost to next-to-outermost */
           OFPAT_SET_MPLS_TTL = 15,    /* MPLS TTL */
           OFPAT_DEC_MPLS_TTL = 16,    /* Decrement MPLS TTL */
           OFPAT_PUSH_VLAN = 17,       /* Push a new VLAN tag */
           OFPAT_POP_VLAN = 18,        /* Pop the outer VLAN tag */
           OFPAT_PUSH_MPLS = 19,       /* Push a new MPLS tag */
           OFPAT_POP_MPLS = 20,        /* Pop the outer MPLS tag */
           OFPAT_SET_QUEUE = 21,       /* Set queue id when outputting to a port */
           OFPAT_GROUP = 22,           /* Apply group. */
           OFPAT_SET_NW_TTL = 23,      /* IP TTL. */
           OFPAT_DEC_NW_TTL = 24,      /* Decrement IP TTL. */
           OFPAT_SET_FIELD = 25,       /* Set a header field using OXM TLV format. */
           OFPAT_PUSH_PBB = 26,        /* Push a new PBB service tag (I-TAG) */
           OFPAT_POP_PBB = 27,         /* Pop the outer PBB service tag (I-TAG) */
           OFPAT_EXPERIMENTER = 0xffff
    }OPENLOW_OFP_ACTION_TYPE_ENUM;

    typedef struct
    {
        OPENLOW_OFP_ACTION_TYPE_ENUM type;  /* One of OFPAT_**/
        uint16_t len;                  /* Length of action, including this header. This is the length of action, including any padding to make it 64-bit aligned. */
    }OPENLOW_OFP_ACTION_HEADER_STRUCT;

    typedef enum
    {
        OFPAT_OUTPUTT,       /* Output to switch port. */
        OFPAT_SET_VLAN_VID, /* Set the 802.1q VLAN id. */
        OFPAT_SET_VLAN_PCP, /* Set the 802.1q priority. */
        OFPAT_STRIP_VLAN, /* Strip the 802.1q header. */
        OFPAT_SET_DL_SRC, /* Ethernet source address. */
        OFPAT_SET_DL_DST, /* Ethernet destination address. */
        OFPAT_SET_NW_SRC, /* IP source address. */
        OFPAT_SET_NW_DST, /* IP destination address. */
        OFPAT_SET_TP_SRC, /* TCP/UDP source port. */
        OFPAT_SET_TP_DST, /* TCP/UDP destination port. */
        OFPAT_VENDOR = 0xffff   /* may not be used */
    }OPENFLOW_OFP_ACTION_TYPE;



    typedef struct {
        OPENLOW_OFP_ACTION_HEADER_STRUCT header;
        uint32_t buffer_id;     /* ID assigned by datapath (OFP_NO_BUFFER if none). */
        uint32_t in_port;       /* Packet's input port or OFPP_CONTROLLER. */
        uint16_t actions_len;   /* Size of action array in bytes. */
        OPENFLOW_OFP_ACTION_TYPE actions; /* Action list. */
        uint8_t data[0];        /* Packet data. The length is inferred from the length field in the header (Only meaningful if buffer_id == -1.) */
    }OPENFLOW_PACKET_OUT_MSG_STRUCT;
#define OPENFLOW_PACKET_IN_MSG_STRUCT_SIZE sizeof(OPENFLOW_PACKET_IN_MSG_STRUCT)




    /*********************************************************************/
    /* OPENFLOW FLOW_REMOVED MESSAGES IMPLEMENTION */
    /*********************************************************************/

    /* This message struct is not implemented. This logic can be added to the nodes since they can reach high velocities with different types of mobility models.
     * Aim: Prevent communication overhead */


    /*********************************************************************/
    /* OPENFLOW SWITCH CONFIG IMPLEMENTION */
    /*********************************************************************/

    /* GET_CONFIG_REQ and GET_CONFIG_RES will not be implemented since it is hard to apply them into UAVs
     * TODO: SET_CONFIG will be implemented later */


    /*********************************************************************/
    /* OPENFLOW ROLE_REQ & ROLE_RES IMPLEMENTION */
    /*********************************************************************/

    /* Controller roles. */
    /* If the role value is OFPCR_ROLE_MASTER, all other controllers which role was OFPCR_ROLE_MASTER are
     * changed to OFPCR_ROLE_SLAVE. If the role value is OFPCR_ROLE_NOCHANGE, the current role of the controller
     * is not changed ; this enable a controller to query its current role without changing it.  */
    typedef enum
    {
        OFPCR_ROLE_NOCHANGE = 0,    /* Don't change current role. */
        OFPCR_ROLE_EQUAL    = 1,    /* Default role, full access. */
        OFPCR_ROLE_MASTER   = 2,    /* Full access, at most one master. */
        OFPCR_ROLE_SLAVE    = 3,    /* Read-only access. */
    }OPENFLOW_OFP_CONTROLLER_ROLE;


    /* Role request and reply message. */
    typedef struct  {
        OPENLOW_OFP_ACTION_HEADER_STRUCT header;  /* !!!!!!!!! Type OFPT_ROLE_REQUEST/OFPT_ROLE_REPLY !!!!!!!!! */
        OPENFLOW_OFP_CONTROLLER_ROLE role;        /* One of NX_ROLE_*. */
        uint64_t generation_id;                   /* Master Election Generation Id */
    }OPENFLOW_OFP_ROLE_REQ_STRUCT;
#define OPENFLOW_OFP_ROLE_REQ_STRUCT_SIZE sizeof(OPENFLOW_OFP_ROLE_REQ_STRUCT)

#define OPENFLOW_OFP_ROLE_RES_STRUCT OPENFLOW_OFP_ROLE_REQ_STRUCT




    /* beratovic ends */
    /*********************************************************************//*********************************************************************/
    /*********************************************************************//*********************************************************************/


    void SDN_UpdateRoutingTable();
    typedef enum
    {
        SENDER_IS_CONTROLLER = 0,
        SENDER_IS_NODE,
    }SDN_CONTROLLER_SENDER_TYPE;

    typedef enum
    {
        MESSAGE_TYPE_UNDEFINED = 0,
        MESSAGE_TYPE_HELLO,
        MESSAGE_TYPE_ERROR,

    }SDN_CONTROLLER_MESSAGE_TYPE;

#endif


  protected:

    void handleMessageWhenUp(cMessage *msg) override;
    void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

    /* Route Discovery */
    void startRouteDiscovery(const L3Address& target, unsigned int timeToLive = 0);
    void completeRouteDiscovery(const L3Address& target);
    bool hasOngoingRouteDiscovery(const L3Address& destAddr);
    void cancelRouteDiscovery(const L3Address& destAddr);

    /* Routing Table management */
    void updateRoutingTable(IRoute *route, const L3Address& nextHop, unsigned int hopCount, bool hasValidDestNum, unsigned int destSeqNum, bool isActive, simtime_t lifeTime);
#ifdef CONTROLLER_MODE_ENABLED
    void updateRoutingTableSDNSpecific(IRoute *route, const L3Address& nextHop, unsigned int hopCount, bool hasValidDestNum, unsigned int destSeqNum, bool isActive, simtime_t lifeTime);
#endif
    IRoute *createRoute(const L3Address& destAddr, const L3Address& nextHop, unsigned int hopCount, bool hasValidDestNum, unsigned int destSeqNum, bool isActive, simtime_t lifeTime);
    bool updateValidRouteLifeTime(const L3Address& destAddr, simtime_t lifetime);
    void scheduleExpungeRoutes();
    void expungeRoutes();

    /* Control packet creators */
    const Ptr<RrepAck> createRREPACK();
    const Ptr<Rrep> createHelloMessage();
    const Ptr<Rreq> createRREQ(const L3Address& destAddr);
#ifndef  CONTROLLER_MODE_ENABLED
    const Ptr<Rrep> createRREP(const Ptr<Rreq>& rreq, IRoute *destRoute, IRoute *originatorRoute, const L3Address& sourceAddr);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    const Ptr<Rrep> createRREP(const Ptr<Rreq>& rreq, const L3Address& sourceAddr);
#endif
    const Ptr<Rrep> createGratuitousRREP(const Ptr<Rreq>& rreq, IRoute *originatorRoute);
    const Ptr<Rerr> createRERR(const std::vector<UnreachableNode>& unreachableNodes);
#ifndef  CONTROLLER_MODE_ENABLED
    /* Control Packet handlers */
    void handleRREP(const Ptr<Rrep>& rrep, const L3Address& sourceAddr);
    void handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive);
    void handleRERR(const Ptr<const Rerr>& rerr, const L3Address& sourceAddr);
    void handleHelloMessage(const Ptr<Rrep>& helloMessage);
    void handleRREPACK(const Ptr<const RrepAck>& rrepACK, const L3Address& neighborAddr);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    /* Control Packet handlers */
    void handleRREP(const Ptr<Rrep>& rrep, const L3Address& sourceAddr,unsigned int destinationHop, unsigned int nextHop);
    void handleRREQ(const Ptr<Rreq>& rreq, const L3Address& sourceAddr, unsigned int timeToLive, unsigned int controllerRequestType);
    void handleRERR(const Ptr<const Rerr>& rerr, const L3Address& sourceAddr);
    void handleHelloMessage(const Ptr<Rrep>& helloMessage);
    void handleRREPACK(const Ptr<const RrepAck>& rrepACK, const L3Address& neighborAddr);
#endif
    /* Control Packet sender methods */
    void sendRREQ(const Ptr<Rreq>& rreq, const L3Address& destAddr, unsigned int timeToLive);
    void sendRREPACK(const Ptr<RrepAck>& rrepACK, const L3Address& destAddr);
    void sendRREP(const Ptr<Rrep>& rrep, const L3Address& destAddr, unsigned int timeToLive);
    void sendGRREP(const Ptr<Rrep>& grrep, const L3Address& destAddr, unsigned int timeToLive);

    /* Control Packet forwarders */
    void forwardRREP(const Ptr<Rrep>& rrep, const L3Address& destAddr, unsigned int timeToLive);
    void forwardRREQ(const Ptr<Rreq>& rreq, unsigned int timeToLive);

    /* Self message handlers */
    void handleRREPACKTimer();
    void handleBlackListTimer();
    void sendHelloMessagesIfNeeded();
    void handleWaitForRREP(WaitForRrep *rrepTimer);
#ifdef CONTROLLER_MODE_ENABLED
    void handleSdnControllerTimer(); /*beratovic*/
    void handleSdnControllerTimer2();
    void printDistances();
    void handleSdnNodeSourceTimer(); /*beratovic*/
    void handleSdnNodeATimer();
    void handleSdnNodeBTimer();
    void handleSdnNodeFTimer();
    void handleSdnNodeETimer();
#endif

    /* General functions to handle route errors */
    void sendRERRWhenNoRouteToForward(const L3Address& unreachableAddr);
    void handleLinkBreakSendRERR(const L3Address& unreachableAddr);
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details) override;

    /* Netfilter hooks */
    Result ensureRouteForDatagram(Packet *datagram);
    virtual Result datagramPreRoutingHook(Packet *datagram) override { Enter_Method("datagramPreRoutingHook"); return ensureRouteForDatagram(datagram); }
    virtual Result datagramForwardHook(Packet *datagram) override;
    virtual Result datagramPostRoutingHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalInHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalOutHook(Packet *datagram) override { Enter_Method("datagramLocalOutHook"); return ensureRouteForDatagram(datagram); }
    void delayDatagram(Packet *datagram);

    /* Helper functions */
    L3Address getSelfIPAddress() const;
#ifndef  CONTROLLER_MODE_ENABLED
    void sendAODVPacket(const Ptr<AodvControlPacket>& packet, const L3Address& destAddr, unsigned int timeToLive, double delay);
#endif
#ifdef  CONTROLLER_MODE_ENABLED
    void sendAODVPacket(const Ptr<AodvControlPacket>& packet, const L3Address& destAddr, unsigned int timeToLive, double delay, SDN_CONTROLLER_SENDER_TYPE senderType, SDN_CONTROLLER_MESSAGE_TYPE msgType);
#endif
    void processPacket(Packet *pk);
    void clearState();
    void checkIpVersionAndPacketTypeCompatibility(AodvControlPacketType packetType);

    /* UDP callback interface */
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;

    /* Lifecycle */
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

  public:
    Aodv();
    virtual ~Aodv();
};
#ifdef CONTROLLER_MODE_ENABLED
bool Aodv::routeHasChanged = true; /*beratovic*/
bool Aodv::nodeA_aodvRouteCreationDisabled = false;
bool Aodv::nodeB_aodvRouteCreationDisabled = false;
bool Aodv::nodeSource_aodvRouteCreationDisabled = false;
bool Aodv::nodeDestination_aodvRouteCreationDisabled = false;
bool Aodv::nodeE_aodvRouteCreationDisabled = false;
bool Aodv::nodeF_aodvRouteCreationDisabled = false;
bool Aodv::nodeController_aodvRouteCreationDisabled = false;

bool Aodv::nodeA_nextHopUpdated = false; /*1*/
bool Aodv::nodeB_nextHopUpdated = false; /*2*/
bool Aodv::nodeSource_nextHopUpdated = false; /*3*/
bool Aodv::nodeE_nextHopUpdated = false; /*5*/
bool Aodv::nodeF_nextHopUpdated = false; /*6*/



uint8_t Aodv::testDestAddr1_Destination_Index = 4;
uint8_t Aodv::testDestAddr1_NextHop_Index = 2;
uint8_t Aodv::testDestAddr2_Destination_Index = 4;
uint8_t Aodv::testDestAddr2_NextHop_Index = 4/*6*/;
uint8_t Aodv::testDestAddr3_Destination_Index = 4;
uint8_t Aodv::testDestAddr3_NextHop_Index = 4;
uint8_t Aodv::testDestAddr4_Destination_Index = UNKNOWN_INDEX;
uint8_t Aodv::testDestAddr4_NextHop_Index = UNKNOWN_INDEX;
uint8_t Aodv::testDestAddr5_Destination_Index = 4;
uint8_t Aodv::testDestAddr5_NextHop_Index = 1;
uint8_t Aodv::testDestAddr6_Destination_Index = 4;
uint8_t Aodv::testDestAddr6_NextHop_Index = 4;
uint8_t Aodv::testDestAddrController_Destination_Index = 0;
uint8_t Aodv::testDestAddrController_NextHop_Index = 0;
#endif
} // namespace aodv
} // namespace inet

#endif // ifndef __INET_AODV_H

