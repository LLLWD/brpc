// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.


#ifndef  BRPC_TAG_CONSISTENT_HASHING_LOAD_BALANCER_H
#define  BRPC_TAG_CONSISTENT_HASHING_LOAD_BALANCER_H

#include <stdint.h>                                     // uint32_t
#include <functional>
#include <vector>                                       // std::vector
#include <unordered_map>

#include "butil/endpoint.h"                              // butil::EndPoint
#include "butil/containers/doubly_buffered_data.h"
#include "brpc/load_balancer.h"


namespace brpc {
namespace policy {

class ReplicaPolicy;

enum TagConsistentHashingLoadBalancerType {
    TAG_CONS_HASH_LB_MURMUR3 = 0,
    TAG_CONS_HASH_LB_MD5 = 1,
    TAG_CONS_HASH_LB_KETAMA = 2,

    // Identify the last one.
    TAG_CONS_HASH_LB_LAST = 3
};

class TagConsistentHashingLoadBalancer : public LoadBalancer {
public:
    struct Node {
        uint32_t hash;
        ServerId server_sock;
        butil::EndPoint server_addr;  // To make sorting stable among all clients
        bool operator<(const Node &rhs) const {
            if (hash < rhs.hash) { return true; }
            if (hash > rhs.hash) { return false; }
            return server_addr < rhs.server_addr;
        }
        bool operator<(const uint32_t code) const {
            return hash < code;
        }
    };
    explicit TagConsistentHashingLoadBalancer(TagConsistentHashingLoadBalancerType type);
    bool AddServer(const ServerId& server);
    bool RemoveServer(const ServerId& server);
    size_t AddServersInBatch(const std::vector<ServerId> &servers);
    size_t RemoveServersInBatch(const std::vector<ServerId> &servers);
    LoadBalancer *New(const butil::StringPiece& params) const;
    void Destroy();
    int SelectServer(const SelectIn &in, SelectOut *out);
    void Describe(std::ostream &os, const DescribeOptions& options);

private:
    bool SetParameters(const butil::StringPiece& params);
    void GetLoads(std::map<butil::EndPoint, double> *load_map);
    static size_t AddBatch(std::unordered_map<std::string, std::vector<Node>> &bg,
                           const std::unordered_map<std::string, std::vector<Node>> &fg,
                           const std::unordered_map<std::string, std::vector<Node>> &servers,
                           bool *executed);
    static size_t RemoveBatch(std::unordered_map<std::string, std::vector<Node>> &bg,
                              const std::unordered_map<std::string, std::vector<Node>> &fg,
                              const std::vector<ServerId> &servers, bool *executed);
    static size_t Remove(std::unordered_map<std::string, std::vector<Node>> &bg,
                         const std::unordered_map<std::string, std::vector<Node>> &fg,
                         const ServerId& server, bool *executed);
    static size_t MapSizeDiff(const std::unordered_map<std::string, std::vector<Node>> &big_map,
                       const std::unordered_map<std::string, std::vector<Node>> &small_map);
    size_t _num_replicas;
    TagConsistentHashingLoadBalancerType _type;
    butil::DoublyBufferedData<std::unordered_map<std::string, std::vector<Node>>> _db_pfb_hash_ring;
};

}  // namespace policy
} // namespace brpc


#endif  //BRPC_TAG_CONSISTENT_HASHING_LOAD_BALANCER_H
