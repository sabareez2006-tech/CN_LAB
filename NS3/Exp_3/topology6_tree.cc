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
  p2p.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

  Ipv4AddressHelper address;
  uint32_t subnet = 1;

  // Tree structure:
  // Node 0 = root
  // Nodes 1,2,3 = level-1
  // Remaining nodes are level-2 leaves

  // Root to level-1
  for (uint32_t i = 1; i <= 3; ++i)
    {
      NodeContainer pair (nodes.Get (0), nodes.Get (i));
      NetDeviceContainer dev = p2p.Install (pair);

      std::ostringstream subnetAddr;
      subnetAddr << "10.6." << subnet++ << ".0";
      address.SetBase (subnetAddr.str ().c_str (), "255.255.255.0");
      address.Assign (dev);
    }

  // Level-1 to level-2 leaves
  uint32_t leaf = 4;
  for (uint32_t parent = 1; parent <= 3; ++parent)
    {
      for (uint32_t k = 0; k < 4 && leaf < nNodes; ++k)
        {
          NodeContainer pair (nodes.Get (parent), nodes.Get (leaf));
          NetDeviceContainer dev = p2p.Install (pair);

          std::ostringstream subnetAddr;
          subnetAddr << "10.6." << subnet++ << ".0";
          address.SetBase (subnetAddr.str ().c_str (), "255.255.255.0");
          address.Assign (dev);

          ++leaf;
        }
    }

  // Mobility: tree layout
  MobilityHelper mobility;
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes);

  // Root
  nodes.Get (0)->GetObject<MobilityModel> ()
    ->SetPosition (Vector (400, 500, 0));

  // Level-1
  nodes.Get (1)->GetObject<MobilityModel> ()->SetPosition (Vector (200, 350, 0));
  nodes.Get (2)->GetObject<MobilityModel> ()->SetPosition (Vector (400, 350, 0));
  nodes.Get (3)->GetObject<MobilityModel> ()->SetPosition (Vector (600, 350, 0));

  // Level-2 leaves
  double xStart[3] = {120, 320, 520};
  uint32_t idx = 4;
  for (uint32_t p = 0; p < 3; ++p)
    {
      for (uint32_t k = 0; k < 4 && idx < nNodes; ++k)
        {
          nodes.Get (idx)->GetObject<MobilityModel> ()
            ->SetPosition (Vector (xStart[p] + k * 60, 200, 0));
          ++idx;
        }
    }

  // UDP server at root
  uint16_t port = 9000;
  UdpServerHelper server (port);
  server.Install (nodes.Get (0)).Start (Seconds (1.0));

  // UDP client at a leaf
  UdpClientHelper client (Ipv4Address ("10.6.1.2"), port);
  client.SetAttribute ("MaxPackets", UintegerValue (100));
  client.SetAttribute ("Interval", TimeValue (Seconds (0.5)));
  client.SetAttribute ("PacketSize", UintegerValue (512));
  client.Install (nodes.Get (nNodes - 1)).Start (Seconds (2.0));

  AnimationInterface anim ("topology6_tree.xml");

  Simulator::Stop (Seconds (20.0));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}
