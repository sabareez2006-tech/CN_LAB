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

  const uint32_t nLeaf = 15;
  const uint32_t hubNode = 0;

  NodeContainer nodes;
  nodes.Create (nLeaf + 1); // 1 hub + 15 leaf

  InternetStackHelper internet;
  internet.Install (nodes);

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

  Ipv4AddressHelper address;
  uint32_t subnet = 1;

  // Connect each leaf to the hub
  for (uint32_t i = 1; i <= nLeaf; ++i)
    {
      NodeContainer pair (nodes.Get (hubNode), nodes.Get (i));
      NetDeviceContainer devices = p2p.Install (pair);

      std::ostringstream subnetAddr;
      subnetAddr << "10.3." << subnet++ << ".0";
      address.SetBase (subnetAddr.str ().c_str (), "255.255.255.0");
      address.Assign (devices);
    }

  // Mobility: hub center, leaves in circle
  MobilityHelper mobility;
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes);

  nodes.Get (hubNode)->GetObject<MobilityModel> ()
    ->SetPosition (Vector (400, 300, 0));

  double radius = 200.0;
  for (uint32_t i = 1; i <= nLeaf; ++i)
    {
      double angle = (2 * M_PI * i) / nLeaf;
      double x = 400 + radius * cos (angle);
      double y = 300 + radius * sin (angle);

      nodes.Get (i)->GetObject<MobilityModel> ()
        ->SetPosition (Vector (x, y, 0));
    }

  // UDP server at hub
  uint16_t port = 6000;
  UdpServerHelper server (port);
  server.Install (nodes.Get (hubNode)).Start (Seconds (1.0));

  // UDP clients on leaves
  for (uint32_t i = 1; i <= nLeaf; ++i)
    {
      UdpClientHelper client (Ipv4Address ("10.3.1.1"), port);
      client.SetAttribute ("MaxPackets", UintegerValue (50));
      client.SetAttribute ("Interval", TimeValue (Seconds (0.5)));
      client.SetAttribute ("PacketSize", UintegerValue (512));
      client.Install (nodes.Get (i)).Start (Seconds (2.0));
    }

  AnimationInterface anim ("topology3_star.xml");

  Simulator::Stop (Seconds (20.0));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}
