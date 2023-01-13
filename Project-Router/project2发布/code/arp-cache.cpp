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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  /*
   *     for each request in queued requests:
   *         handleRequest(request)
   *
   *     for each cache entry in entries:
   *         if not entry->isValid
   *             record entry for removal
   *     remove all entries marked for removal
  */ 
  uint8_t broadcast_mac[6]; 
  for (int i=0; i < 6; i++) 
     broadcast_mac[i] = 0xFF; 

  for (auto it = m_arpRequests.begin(); it != m_arpRequests.end();) {
    auto request = *it; 

    // 发5次以上没回复删掉
    if (request->nTimesSent >= MAX_SENT_TIME) {
      it = m_arpRequests.erase(it);
      continue;
    }

    // 以太帧首部
    ethernet_hdr arp_request_eth_header;
    const Interface *s_iface = m_router.findIfaceByName(request->packets.front().iface);
    for (auto i = 0; i < 6; i++) {
      arp_request_eth_header.ether_shost[i] = s_iface->addr[i];
      arp_request_eth_header.ether_dhost[i] = broadcast_mac[i];
    }
    arp_request_eth_header.ether_type = htons(ethertype_arp);

    // ARP首部
    arp_hdr arp_request_header = { 
      htons(arp_hrd_ethernet),
      htons(ethertype_ip),
      ETHER_ADDR_LEN,
      sizeof(uint32_t),
      htons(arp_op_request)
    };
    for (auto i = 0; i < 6; i++) {
      arp_request_header.arp_sha[i] = s_iface->addr[i];
      arp_request_header.arp_tha[i] = broadcast_mac[i];
    }
    arp_request_header.arp_sip = s_iface->ip;
    arp_request_header.arp_tip = request->ip;

    // 封装
    uint8_t *response_packet = (uint8_t *) malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    memcpy(response_packet, &arp_request_eth_header, sizeof(ethernet_hdr));
    memcpy(response_packet + sizeof(ethernet_hdr), &arp_request_header, sizeof(arp_hdr));
    Buffer new_arp_packet(response_packet, response_packet + sizeof(ethernet_hdr) + sizeof(arp_hdr));

    m_router.sendPacket(new_arp_packet, s_iface->name);

    request->timeSent = std::chrono::steady_clock::now();
    request->nTimesSent++;

    it++; 
  }

  // 移除无效的条目
  for (auto it = m_cacheEntries.begin(); it != m_cacheEntries.end(); ) {
    if (!(*it)->isValid) {
      it = m_cacheEntries.erase(it);
      continue;
    }
    it++;
  }

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
