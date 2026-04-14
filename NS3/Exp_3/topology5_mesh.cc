#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/animation-interface.h"

using namespace ns3;

int main (int argc, char *argv[])
{
  Time::SetResolution (Time::NS);

  const uint32_t nNodes = 15;

  NodeContainer nodes;
  nodes.Create (nNodes);

  InternetStackHelper internet;
  internet.Install (nodes);

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

  Ipv4AddressHelper address;
  uint32_t subnet = 1;

  // Full mesh: connect every node to every other node
  for (uint32_t i = 0; i < nNodes; ++i)
    {
      for (uint32_t j = i + 1; j < nNodes; ++j)
        {
          NodeContainer pair (nodes.Get (i), nodes.Get (j));
          NetDeviceContainer devices = p2p.Install (pair);

          std::ostringstream subnetAddr;
          subnetAddr << "10.5." << subnet++ << ".0";
          address.SetBase (subnetAddr.str ().c_str (), "255.255.255.0");
          address.Assign (devices);
        }
    }

  // Mobility: grid layout to reduce line overlap
  MobilityHelper mobility;
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes);

  uint32_t gridSize = 5;
  double spacing = 120.0;

  for (uint32_t i = 0; i < nNodes; ++i)
    {
      double x = (i % gridSize) * spacing + 100;
      double y = (i / gridSize) * spacing + 100;
      nodes.Get (i)->GetObject<MobilityModel> ()
        ->SetPosition (Vector (x, y, 0));
    }

  // UDP server on node 0
  uint16_t port = 8000;
  UdpServerHelper server (port);
  server.Install (nodes.Get (0)).Start (Seconds (1.0));

  // UDP client on last node
  UdpClientHelper client (Ipv4Address ("10.5.1.2"), port);
  client.SetAttribute ("MaxPackets", UintegerValue (100));
  client.SetAttribute ("Interval", TimeValue (Seconds (0.5)));
  client.SetAttribute ("PacketSize", UintegerValue (512));
  client.Install (nodes.Get (nNodes - 1)).Start (Seconds (2.0));

  AnimationInterface anim ("topology5_mesh.xml");

  Simulator::Stop (Seconds (20.0));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}
