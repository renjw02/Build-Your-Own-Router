/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
// packet 按以太帧形式发送
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  // std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  // print_hdrs(packet);
  // 先解析packet
  // type 只能是ARP或者IPV4
  // dest 必须是iface的MAC地址或是广播地址
  // 根据dest调用sendPacket
  Buffer p(packet);
  uint8_t *old_packet = p.data();  // 指向包头
  ethernet_hdr *eth_header = (ethernet_hdr *) old_packet; 
  
  // ?
  if (!isCorrectMac(eth_header->ether_dhost, *iface)) {
    std::cerr << "error input mac address, ignoring" << std::endl; 
    return; 
  }

  // 需要hton？
  if (eth_header->ether_type == htons(0x0806)) {
    handleARP(old_packet + sizeof(ethernet_hdr), iface, eth_header->ether_shost); 
  } else if (eth_header->ether_type == htons(0x0800)) { 
    handleIPV4(p, iface, eth_header->ether_shost); 
  } else { 
    std::cerr << "unknown type of packet, ignoring" << std::endl; 
    return; 
  }

}

void SimpleRouter::handleARP(uint8_t* arp_packet, const Interface* iface, uint8_t* src)
{
  arp_hdr* arp_header = (arp_hdr *) arp_packet; 

  // hardware type == 0x0001
  if (ntohs(arp_header->arp_hrd) != arp_hrd_ethernet) 
     return; 


  // opcode == 1 ARP request
  if (ntohs(arp_header->arp_op) == 1) 
  { 
    //必须正确响应相应网络接口IP地址的MAC地址ARP请求
    //必须忽略其他ARP请求

    // 目的ip地址应是我们
    if (arp_header->arp_tip != iface->ip)
       return; 

    // 发送响应ARP分组
    // int output_buf_size = sizeof(ethernet_hdr) + sizeof(arp_hdr); 
    // uint8_t output_buf[output_buf_size]; 
    uint8_t *new_packet = (uint8_t *) malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr)); 

    // 设置首部
    // 以太帧
    ethernet_hdr *new_eth_header = (ethernet_hdr *) new_packet; 
    new_eth_header->ether_type = htons(ethertype_arp); 

    for (auto i = 0; i < 6; i++) {
      new_eth_header->ether_dhost[i] = src[i];
      new_eth_header->ether_shost[i] = iface->addr[i];
    }

    // ARP 
    arp_hdr *new_arp_header = (arp_hdr *) (new_packet + sizeof(ethernet_hdr)); 
    memcpy(new_arp_header, arp_header, sizeof(arp_hdr));
    new_arp_header->arp_op = htons(arp_op_reply); 
    new_arp_header->arp_tip = arp_header->arp_sip; 

    for (auto i = 0; i < 6; i++)
      new_arp_header->arp_tha[i] =  arp_header->arp_tha[i];
    new_arp_header->arp_sip = iface->ip; 

    for (auto i = 0; i < 6; i++)
      new_arp_header->arp_sha[i] =  iface->addr[i];

    // send the packet
    Buffer output(new_packet, new_packet + sizeof(ethernet_hdr) + sizeof(arp_hdr)); 
    sendPacket(output, iface->name); 
    return; 
  } 
  // opcode == 2 ARP reply
  else if (ntohs(arp_header->arp_op) == 2) 
  { 
    //当路由器收到ARP应答时，它应该在ARP缓存中记录IP-MAC映射信息（ARP应答中的源IP/源硬件地址）。
    //之后，路由器应发送所有对应的排队分组。

    uint32_t ip = arp_header->arp_sip; 
    Buffer mac; 
    for (int i = 0; i < 6; i++) 
      mac.push_back(arp_header->arp_sha[i]); 

    // 插入ARP表
    auto request = m_arp.insertArpEntry(mac, ip); 

    // 发送所有对应的排队分组
    for (auto pending_packet: request->packets) { 
      ethernet_hdr *eth_header = (ethernet_hdr *) pending_packet.packet.data(); 
      for (auto i = 0; i < 6; i++)
        eth_header->ether_dhost[i] = mac[i];

      sendPacket(pending_packet.packet, pending_packet.iface); 
    }
      
    m_arp.removeRequest(request); 
    return; 
  } 
  else 
  {  
    std::cerr << "unknown ARP type, ignoring" << std::endl; 
    return; 
  }
}

void SimpleRouter::handleIPV4(Buffer &packet, const Interface* iface, uint8_t* src) 
{ 
  ethernet_hdr *eth_header = (ethernet_hdr *)packet.data(); 
  ip_hdr *ip_header = (ip_hdr *)(packet.data() + sizeof(ethernet_hdr));
  icmp_hdr *icmp_header = (icmp_hdr *)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

  // 长度检验
  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) {
    std::cerr << "received IP packet, but header is truncated, ignoring" << std::endl; 
    return;
  }

  // 检验和
  if (cksum(ip_header, sizeof(ip_hdr)) != 0xffff) { 
    std::cerr << "found errors in ipv4 packet by checksum" << std::endl;
    return; 
  }

  // 查找下一跳
  // ARP cache
  // cache中没有要加入
  if(m_arp.lookup(ip_header->ip_src) == nullptr) {
    Buffer mac(src, src + ETHER_ADDR_LEN);
    m_arp.insertArpEntry(mac, ip_header->ip_src);
  }

  // 如果在处理过程中由于TTL字段为0而丢弃IP数据包，则发送此消息
  // ttl结束
  // type 11 code 0
  if (ip_header->ip_ttl <= 1){
    send_t3_packet(packet, iface, 11, 0); 
    return; 
  } 

  // 目的地是router还是要转发

  // 目的地是router
  // 处理ICMP包
  if (findIfaceByIp(ip_header->ip_dst)) { 
    // 不是echo
    // 端口无法访问消息（类型3，代码3）：如果包含UDP或TCP有效负载的IP数据包被发送到路由器的一个接口，则发送。这
    // 需要traceroute才能工作。
    if (ip_header->ip_p != 1 && icmp_header->icmp_type != 8) { 
      send_t3_packet(packet, iface, 3, 3); 
      return; 
    }

    // 创建将要返回的包
    // echo reply message
    // 响应传入的回显请求消息（ping）发送到路由器的一个接口。
    // 发送到其他IP地址的回显请求应照常转发到下一跳地址。
    // 在本项目中，Echo Reply消息的IPv4报头中的初始TTL字段应为64。 
    uint8_t *new_packet = (uint8_t *)malloc(packet.size()); 
    memcpy(new_packet, packet.data(), packet.size());
    ethernet_hdr *new_eth_header = (ethernet_hdr *)new_packet; 
    ip_hdr *new_ip_header = (ip_hdr *)(new_packet + sizeof(ethernet_hdr));
    icmp_hdr *new_icmp_header = (icmp_hdr *)(new_packet + sizeof(ethernet_hdr) + sizeof(ip_hdr)); 

    for (auto i = 0; i < 6; i++) {
      new_eth_header->ether_dhost[i] = eth_header->ether_shost[i];
      new_eth_header->ether_shost[i] = eth_header->ether_dhost[i];
    }
    new_ip_header->ip_src = ip_header->ip_dst; 
    new_ip_header->ip_dst = ip_header->ip_src; 

    new_ip_header->ip_ttl = 64; 
    new_ip_header->ip_len = ip_header->ip_len;
    new_ip_header->ip_sum = 0x0; 
    new_ip_header->ip_sum = cksum(new_ip_header, sizeof(ip_hdr)); 

    new_icmp_header->icmp_type = 0x0; 
    new_icmp_header->icmp_code = 0x0; 

    new_icmp_header->icmp_sum = 0x0;
    new_icmp_header->icmp_sum = cksum(new_icmp_header, packet.size()-
                  sizeof(ethernet_hdr)-sizeof(ip_hdr));

    // 响应传入的回显请求消息（ping）发送到路由器的一个接S口
    // Buffer output(new_packet, new_packet + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr)); 
    Buffer output(new_packet, new_packet + packet.size()); 
    // print_hdrs(output); 
    sendPacket(output, iface->name); 
    // std::cout << iface->name << std::endl;
    free(new_packet); 
    return; 
  }
  
  // 要转发
  RoutingTableEntry t_entry;
  // 会匹配失败吗？
  try { 
    t_entry = m_routingTable.lookup(ip_header->ip_dst);
  } catch (...) { 
    std::cerr << "routing table entry not found, dropping" << std::endl;
    return; 
  }

  const Interface *outface = findIfaceByName(t_entry.ifName);
  if (outface == nullptr) { 
    std::cerr << "unknown output interface, dropping" << std::endl;
    return; 
  }

  // 创建新包
  Buffer out_packet(packet); 
  ethernet_hdr *out_eth_header = (ethernet_hdr *) out_packet.data();
  for (auto i = 0; i < 6; i++)
    out_eth_header->ether_shost[i] = outface->addr[i];

  // ttl减小
  ip_hdr *out_ip_header = (ip_hdr *)(out_packet.data() + sizeof(ethernet_hdr)); 
  out_ip_header->ip_ttl--; 
  // 重新计算checksum
  out_ip_header->ip_sum = 0x0; 
  out_ip_header->ip_sum = cksum(out_ip_header, sizeof(ip_hdr)); 

  // 不知道目的mac地址，发送ARP请求并加入队列
  auto arp_entry = m_arp.lookup(ip_header->ip_dst); 
  if (arp_entry == nullptr) { 
    m_arp.queueRequest(out_ip_header->ip_dst, out_packet, outface->name);
    return; 
  }

  // 设置目的mac
  for (auto i = 0; i < 6; i++)
    out_eth_header->ether_dhost[i] = arp_entry->mac[i];
  sendPacket(out_packet, outface->name);
  
}

void SimpleRouter::send_t3_packet(Buffer &packet, const Interface* iface, uint8_t type, uint8_t code)
{
  ethernet_hdr *eth_header = (ethernet_hdr *)packet.data(); 
  ip_hdr *ip_header = (ip_hdr *)(packet.data() + sizeof(ethernet_hdr));

  // 创建将要发送的包
  uint8_t *new_packet = (uint8_t *) malloc(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr)); 
  memcpy(new_packet, packet.data(), sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr)); 

  // 分配首部空间

  // 以太帧
  ethernet_hdr *new_eth_header = (ethernet_hdr *)new_packet; 

  memcpy(new_eth_header->ether_shost, eth_header->ether_dhost, ETHER_ADDR_LEN);
  memcpy(new_eth_header->ether_dhost, eth_header->ether_shost, ETHER_ADDR_LEN);

  // ip包
  ip_hdr *new_ip_header = (ip_hdr *) (new_packet + sizeof(ethernet_hdr));
  new_ip_header->ip_src = iface->ip;
  new_ip_header->ip_dst = ip_header->ip_src;

  new_ip_header->ip_ttl = 64;
  new_ip_header->ip_p = ip_protocol_icmp;
  new_ip_header->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr)); 
  new_ip_header->ip_sum = 0x0; 
  new_ip_header->ip_sum = cksum(new_ip_header, sizeof(ip_hdr)); 

  // ICMP首部
  icmp_t3_hdr *new_icmp_t3_header = (icmp_t3_hdr *) (new_packet + sizeof(ethernet_hdr) + sizeof(ip_hdr)); 

  new_icmp_t3_header->icmp_type = type; 
  new_icmp_t3_header->icmp_code = code; 
  new_icmp_t3_header->unused = 0x0; 
  memcpy(new_icmp_t3_header->data, ip_header, ICMP_DATA_SIZE); 

  new_icmp_t3_header->icmp_sum = 0x0;
  new_icmp_t3_header->icmp_sum = cksum(new_icmp_t3_header, sizeof(icmp_t3_hdr));

  // 重新封装
  Buffer output(new_packet, new_packet + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr)); 
  // Buffer output(new_packet, new_packet + packet.size()); 
  sendPacket(output, iface->name); 
  free(new_packet); 
}

bool SimpleRouter::isCorrectMac(const uint8_t* mac, const Interface& inputIface)
{
  uint8_t broadcast_mac[ETHER_ADDR_LEN]; 
  for (int i=0; i < ETHER_ADDR_LEN; i++) 
     broadcast_mac[i] = 0xFFU; 
  
  // 广播地址
  if (memcmp(mac, broadcast_mac, ETHER_ADDR_LEN) == 0)
     return true; 

  return memcmp(mac, inputIface.addr.data(), ETHER_ADDR_LEN) == 0;
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
