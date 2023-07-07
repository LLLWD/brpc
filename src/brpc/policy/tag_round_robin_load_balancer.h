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


#ifndef BRPC_TAG_ROUND_ROBIN_LOAD_BALANCER_H_
#define BRPC_TAG_ROUND_ROBIN_LOAD_BALANCER_H_

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "brpc/cluster_recover_policy.h"
#include "brpc/load_balancer.h"
#include "butil/containers/doubly_buffered_data.h"

namespace brpc {
namespace policy {
class TagRoundRobinLoadBalancer : public LoadBalancer {
public:
    bool AddServer(const ServerId& id);
    bool RemoveServer(const ServerId& id);
    size_t AddServersInBatch(const std::vector<ServerId>& servers);
    size_t RemoveServersInBatch(const std::vector<ServerId>& servers);
    int SelectServer(const SelectIn& in, SelectOut* out);
    TagRoundRobinLoadBalancer* New(const butil::StringPiece&) const;
    void Destroy();
    void Describe(std::ostream& os, const DescribeOptions&);

private:
    struct Servers {
        // The value is configured weight and weight_sum for each server.
        std::unordered_map<std::string, std::vector<ServerId>> tag_server_map;
        // The value is the index of the server in "tag_server_map[tag]".
        std::map<ServerId, size_t> server_map;
    };

    struct TLS {
        TLS() : stride(0), offset(0) {}
        uint32_t stride;
        uint32_t offset;
    };
    bool SetParameters(const butil::StringPiece& params);
    static bool Add(Servers& bg, const ServerId& id);
    static bool Remove(Servers& bg, const ServerId& id);
    static size_t BatchAdd(Servers& bg, const std::vector<ServerId>& servers);
    static size_t BatchRemove(Servers& bg, const std::vector<ServerId>& servers);

    butil::DoublyBufferedData<Servers, TLS> _db_servers;
    std::shared_ptr<ClusterRecoverPolicy> _cluster_recover_policy;
};  // class TagRoundRobinLoadBalancer

}  // namespace policy
}  // namespace brpc


#endif // BRPC_TAG_ROUND_ROBIN_LOAD_BALANCER_H