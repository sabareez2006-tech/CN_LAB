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

  // Connect nodes in a line (bus)
  for (uint32_t i = 0; i < nNodes - 1; ++i)
    {
      NodeContainer pair (nodes.Get (i), nodes.Get (i + 1));
      NetDeviceContainer devices = p2p.Install (pair);

      std::ostringstream subnetAddr;
      subnetAddr << "10.2." << subnet++ << ".0";
      address.SetBase (subnetAddr.str ().c_str (), "255.255.255.0");
      address.Assign (devices);
    }

  // Mobility: straight line
  MobilityHelper mobility;
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes);

  for (uint32_t i = 0; i < nNodes; ++i)
    {
      nodes.Get (i)->GetObject<MobilityModel> ()
        ->SetPosition (Vector (50 + i * 60, 300, 0));
    }

  // UDP server on last node
  uint16_t port = 5000;
  UdpServerHelper server (port);
  server.Install (nodes.Get (nNodes - 1))
        .Start (Seconds (1.0));

  // UDP client on first node
  UdpClientHelper client (Ipv4Address ("10.2.1.2"), port);
  client.SetAttribute ("MaxPackets", UintegerValue (100));
  client.SetAttribute ("Interval", TimeValue (Seconds (0.5)));
  client.SetAttribute ("PacketSize", UintegerValue (512));
  client.Install (nodes.Get (0))
        .Start (Seconds (2.0));

  AnimationInterface anim ("topology2_bus.xml");

  Simulator::Stop (Seconds (20.0));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}

