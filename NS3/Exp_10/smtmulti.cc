#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("UdpMultiClientChat");

// ---------------- SERVER ----------------
class ChatServer : public Application
{
public:
  ChatServer () {}
  void Setup (uint16_t port) { m_port = port; }

private:
  virtual void StartApplication ()
  {
    m_socket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
    m_socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), m_port));
    m_socket->SetRecvCallback (MakeCallback (&ChatServer::HandleRead, this));
  }

  void HandleRead (Ptr<Socket> socket)
  {
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom (from)))
    {
      uint32_t size = packet->GetSize ();
      double time = Simulator::Now ().GetSeconds ();

      std::stringstream msg;
      msg << "ACK | Time: " << time << "s | Size: " << size;

      std::string response = msg.str();

      Ptr<Packet> pkt = Create<Packet>((uint8_t*)response.c_str(), response.length());
      socket->SendTo(pkt,0,from);

      NS_LOG_UNCOND("Server received packet");
    }
  }

  Ptr<Socket> m_socket;
  uint16_t m_port;
};


// ---------------- CLIENT ----------------
class ChatClient : public Application
{
public:
  ChatClient () {}

  void Setup (Address address, Time interval, std::string name)
  {
    m_peer = address;
    m_interval = interval;
    m_name = name;
  }

private:
  virtual void StartApplication ()
  {
    m_socket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
    m_socket->Connect (m_peer);

    m_socket->SetRecvCallback (MakeCallback (&ChatClient::HandleRead, this));

    SendMessage ();
  }

  void SendMessage ()
  {
    std::string msg = "Hello from " + m_name;

    Ptr<Packet> p = Create<Packet>((uint8_t*)msg.c_str(), msg.length());

    m_socket->Send(p);

    Simulator::Schedule(m_interval,&ChatClient::SendMessage,this);
  }

  void HandleRead (Ptr<Socket> socket)
  {
    Ptr<Packet> packet = socket->Recv();

    uint8_t buffer[1024];
    packet->CopyData(buffer,packet->GetSize());

    std::string data = std::string((char*)buffer,packet->GetSize());

    NS_LOG_UNCOND(m_name << " received -> " << data);
  }

  Ptr<Socket> m_socket;
  Address m_peer;
  Time m_interval;
  std::string m_name;
};


// ---------------- MAIN ----------------
int main ()
{
  NodeContainer nodes;
  nodes.Create(3);

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate",StringValue("5Mbps"));
  p2p.SetChannelAttribute("Delay",StringValue("2ms"));

  NetDeviceContainer d1 = p2p.Install(nodes.Get(0),nodes.Get(1));
  NetDeviceContainer d2 = p2p.Install(nodes.Get(0),nodes.Get(2));

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper address;

  address.SetBase("10.1.1.0","255.255.255.0");
  Ipv4InterfaceContainer i1 = address.Assign(d1);

  address.SetBase("10.2.1.0","255.255.255.0");
  Ipv4InterfaceContainer i2 = address.Assign(d2);

  // Server
  Ptr<ChatServer> server = CreateObject<ChatServer>();
  server->Setup(9000);
  nodes.Get(0)->AddApplication(server);

  // Client A
  Ptr<ChatClient> clientA = CreateObject<ChatClient>();
  clientA->Setup(InetSocketAddress(i1.GetAddress(0),9000),Seconds(3.0),"CLIENT_A");
  nodes.Get(1)->AddApplication(clientA);

  // Client B
  Ptr<ChatClient> clientB = CreateObject<ChatClient>();
  clientB->Setup(InetSocketAddress(i2.GetAddress(0),9000),Seconds(5.0),"CLIENT_B");
  nodes.Get(2)->AddApplication(clientB);

  Simulator::Stop(Seconds(15));
  Simulator::Run();
  Simulator::Destroy();
}
