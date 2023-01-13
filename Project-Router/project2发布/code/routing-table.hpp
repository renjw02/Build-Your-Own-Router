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

#ifndef SIMPLE_ROUTER_ROUTING_TABLE_HPP
#define SIMPLE_ROUTER_ROUTING_TABLE_HPP

#include "core/protocol.hpp"

#include <list>

namespace simple_router {

struct RoutingTableEntry
{
  uint32_t dest;    //目的网络地址（Dest）:标识ip包到达的目的逻辑网络或子网地址
  uint32_t gw;      //下一跳地址（Gw）:与承载路由表的路由器相接的相接的路由器端口地址
  uint32_t mask;    //掩码（Mask）:标识目的主机或路由器所在的网段的地址
  std::string ifName; //接口名
};

/**
 * Routing table of the simple router
 */
class RoutingTable
{
public:
  /**
   * IMPLEMENT THIS METHOD
   *
   * This method should lookup a proper entry in the routing table
   * using "longest-prefix match" algorithm
   *
   * If routing table not found, `throw std::runtime_error("Routing entry not found")`
   */
  RoutingTableEntry
  lookup(uint32_t ip) const;

  bool
  load(const std::string& file);

  void
  addEntry(RoutingTableEntry entry);

private:
  std::list<RoutingTableEntry> m_entries;   //转发表表项

  friend std::ostream&
  operator<<(std::ostream& os, const RoutingTable& table);
};

std::ostream&
operator<<(std::ostream& os, const RoutingTableEntry& entry);

std::ostream&
operator<<(std::ostream& os, const RoutingTable& table);

} // namespace simple_router

#endif // SIMPLE_ROUTER_ROUTING_TABLE_HPP
