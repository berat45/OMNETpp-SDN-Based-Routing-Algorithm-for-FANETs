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

		//Host B tarafýndan receive edilen paketlerin arayüzde gösterilmesi:
        @figure[rcvdPkText](type=indicatorText; pos=380,20; anchor=w; font=,18; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=hostDestination.app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);
        
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
        hostA: <default("WirelessHost")> like INetworkNode {
            @display("p=1365.9539,864.6864;i=misc/drone");
        }
        hostB: <default("WirelessHost")> like INetworkNode {
            @display("p=1964.3419,864.6864;i=misc/drone");
        }
        hostSource: <default("WirelessHost")> like INetworkNode {
            @display("p=1030.7313,513.7992;i=misc/drone");
        }
        hostDestination: <default("WirelessHost")> like INetworkNode {
            @display("p=2377.8877,513.7992;i=misc/drone");
        }
        hostE: <default("WirelessHost")> like INetworkNode {
            @display("p=1033.8641,1152.9152;i=misc/drone");
        }
        hostF: <default("WirelessHost")> like INetworkNode {
            @display("p=2255.7036,1118.4531;i=misc/drone");
        }
        hostController: <default("WirelessHost")> like INetworkNode {
            @display("p=1704.3094,1271.9662;i=misc/drone");
        }
        //hostG: <default("WirelessHost")> like INetworkNode {
        //    @display("p=2431.1472,642.24896");
        //}
        //hostH: <default("WirelessHost")> like INetworkNode {
        //    @display("p=419.81152,748.7683");
        //}
        //hostK: <default("WirelessHost")> like INetworkNode {
        //    @display("p=1459.9415,1353.4222");
        //}
        //hostL: <default("WirelessHost")> like INetworkNode {
        //    @display("p=1337.7576,250.63374");
        //}
        visualizerForRealWorld: IntegratedVisualizer {
            parameters:
                @display("p=3183.0486,573.3247");
        }
        coordinateSystem: OsgGeographicCoordinateSystem {
            parameters:
                @display("p=3183.0486,776.9646");
        }
}
