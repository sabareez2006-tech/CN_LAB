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

  const uint32_t nNodes = 20;

  NodeContainer nodes;
  nodes.Create (nNodes);

  InternetStackHelper internet;
  internet.Install (nodes);

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

  Ipv4AddressHelper address;
  uint32_t subnet = 1;

  // Connect nodes in a ring
  for (uint32_t i = 0; i < nNodes; ++i)
    {
      NodeContainer pair (nodes.Get (i), nodes.Get ((i + 1) % nNodes));
      NetDeviceContainer devices = p2p.Install (pair);

      std::ostringstream subnetAddr;
      subnetAddr << "10.4." << subnet++ << ".0";
      address.SetBase (subnetAddr.str ().c_str (), "255.255.255.0");
      address.Assign (devices);
    }

  // Mobility: circular layout
  MobilityHelper mobility;
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes);

  double centerX = 400.0;
  double centerY = 300.0;
  double radius = 220.0;

  for (uint32_t i = 0; i < nNodes; ++i)
    {
      double angle = (2 * M_PI * i) / nNodes;
      double x = centerX + radius * cos (angle);
      double y = centerY + radius * sin (angle);

      nodes.Get (i)->GetObject<MobilityModel> ()
        ->SetPosition (Vector (x, y, 0));
    }

  // UDP server on node 0
  uint16_t port = 7000;
  UdpServerHelper server (port);
  server.Install (nodes.Get (0)).Start (Seconds (1.0));

  // UDP client on opposite node
  UdpClientHelper client (Ipv4Address ("10.4.1.2"), port);
  client.SetAttribute ("MaxPackets", UintegerValue (100));
  client.SetAttribute ("Interval", TimeValue (Seconds (0.5)));
  client.SetAttribute ("PacketSize", UintegerValue (512));
  client.Install (nodes.Get (nNodes / 2)).Start (Seconds (2.0));

  AnimationInterface anim ("topology4_ring.xml");

  Simulator::Stop (Seconds (20.0));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}
