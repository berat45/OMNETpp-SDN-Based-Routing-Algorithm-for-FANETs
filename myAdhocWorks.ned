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

//Default includes (20.02.2021)
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.INetworkNode;
import inet.physicallayer.contract.packetlevel.IRadioMedium;
import inet.visualizer.contract.IIntegratedVisualizer;
import inet.environment.common.PhysicalEnvironment;
//Update: Real world implementation (21.02.2021) -> https://inet.omnetpp.org/docs/showcases/visualizer/earth/doc/index.html
import inet.common.geometry.common.OsgGeographicCoordinateSystem;
import inet.visualizer.integrated.IntegratedVisualizer;

network myAdHocNetwork
{
    parameters:
        @display("bgb=3295.8337,1810.8287,grey95;bgg=100,1,grey95");
        @figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

		//Host Source tarafýndan gönderilen ve host destination tarafýndan alýnan paketlerin gösterilmesi
        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,18; textFormat="packets received by dest node: %g"; initialValue=0);
        @statistic[packetReceived](source=hostDestination.app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);

        @figure[sentPacketByNodeSource](type=indicatorText; pos=380,60; anchor=w; font=,18; textFormat="packets sent by node Source: %g"; initialValue=0);
        @statistic[packetSent](source=hostSource.app[0].packetSent; record=figure(count); targetFigure=sentPacketByNodeSource);

        //@figure[rcvdPkTexthostToBeDeleted2](type=indicatorText; pos=380,90; anchor=w; font=,18; textFormat="packets received by hostToBeDeleted2 node: %g"; initialValue=0);
        //@statistic[packetReceived](source=hostToBeDeleted2.app[0].packetReceived; record=figure(count); targetFigure=rcvdPkTexthostToBeDeleted2);

    submodules:
        //The visualizer submodule in this network is an IntegratedCanvasVisualizer, which is a compound 
        //module that contains all typically useful visualizers as submodules. It can display physical 
        //objects in the physical environment, movement trail, discovered network connectivity, 
        //discovered network routes, ongoing transmissions, ongoing receptions, propagating radio 
        //signals, statistics, and more.
        visualizer: <default("IntegratedCanvasVisualizer")> like IIntegratedVisualizer if hasVisualizer() {
            @display("p=3183.0486,97.120575");
        }
        // To provide ip4 IP assignment to the nodes
        configurator: Ipv4NetworkConfigurator {
            @display("p=3183.0486,172.3107");
        }
        // Physical layer modeling:
        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=3183.0486,247.50082");
        }
        // Physical environment config
        physicalEnvironment: PhysicalEnvironment {
            @display("p=3183.0486,328.9568");
        }
        //Nodes

        //Nodes
        //hostA: <default("WirelessHost")> like INetworkNode {
        //    @display("p=2249.03,1364.0096;i=misc/drone"); 		//Add zAdhocWorks -> Properties -> C/C++ General -> Paths and Symbols -> add following for images: D:\OmnetWorkspace\inet\images
        //}
        //hostB: <default("WirelessHost")> like INetworkNode {
        //    @display("p=1037.2817,345.7606;i=misc/drone");
        //}
        //hostSource: <default("WirelessHost")> like INetworkNode {
        //    @display("p=196.67116,875.5039;i=misc/drone");
        //}
        //hostDestination: <default("WirelessHost")> like INetworkNode {
        //    @display("p=3010.3376,904.0529;i=misc/drone");
        //}
        //hostE: <default("WirelessHost")> like INetworkNode {
        //    @display("p=1037.2817,1364.0096;i=misc/drone");
        //}
        //hostF: <default("WirelessHost")> like INetworkNode {
        //    @display("p=2249.03,345.7606;i=misc/drone");
        //}
        //hostController: <default("WirelessHost")> like INetworkNode {
        //    @display("p=1159.181,811.42676;i=misc/drone");
        //}


        hostA: <default("WirelessHost")> like INetworkNode {
            @display("p=1983.1396,1362.8212;i=misc/drone"); 		//Add zAdhocWorks -> Properties -> C/C++ General -> Paths and Symbols -> add following for images: D:\OmnetWorkspace\inet\images
        }
        hostB: <default("WirelessHost")> like INetworkNode {
            @display("p=880.35114,344.62143;i=misc/drone");
        }
        hostSource: <default("WirelessHost")> like INetworkNode {
            @display("p=196.67116,875.5039;i=misc/drone");
        }
        hostDestination: <default("WirelessHost")> like INetworkNode {
            @display("p=2587.7937,874.08527;i=misc/drone");
        }
        hostE: <default("WirelessHost")> like INetworkNode {
            @display("p=880.35114,1362.8212;i=misc/drone");
        }
        hostF: <default("WirelessHost")> like INetworkNode {
            @display("p=2105.3237,344.62143;i=misc/drone");
        }
        hostController: <default("WirelessHost")> like INetworkNode {
            @display("p=1002.5351,811.4268;i=misc/drone");
        }


        visualizerForRealWorld: IntegratedVisualizer {
            parameters:
                @display("p=3183.0486,573.3247");
        }
        coordinateSystem: OsgGeographicCoordinateSystem {
            parameters:
                @display("p=3183.0486,776.9646");
        }
}
