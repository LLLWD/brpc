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


#include "butil/macros.h"
#include "butil/fast_rand.h"
#include "brpc/socket.h"
#include "tag_round_robin_load_balancer.h"

namespace brpc {
namespace policy {

const uint32_t prime_offset2[] = {
#include "bthread/offset_inl.list"
};

inline uint32_t GenRandomStride2() {
    return prime_offset2[butil::fast_rand_less_than(ARRAY_SIZE(prime_offset2))];
}

bool TagRoundRobinLoadBalancer::Add(Servers& bg, const ServerId& id) {
    auto& server_list = bg.tag_server_map[id.pfb_tag];
    if (server_list.capacity() < 128) {
        server_list.reserve(128);
    }
    std::map<ServerId, size_t>::iterator it = bg.server_map.find(id);
    if (it != bg.server_map.end()) {
        return false;
    }
    bg.server_map[id] = server_list.size();
    server_list.push_back(id);
    return true;
}

bool TagRoundRobinLoadBalancer::Remove(Servers& bg, const ServerId& id) {
    std::map<ServerId, size_t>::iterator it = bg.server_map.find(id);
    if (it != bg.server_map.end()) {
        const size_t index = it->second;
        auto& server_list = bg.tag_server_map[id.pfb_tag];
        server_list[index] = server_list.back();
        bg.server_map[server_list[index]] = index;
        server_list.pop_back();
        bg.server_map.erase(it);
        return true;
    }
    return false;
}

size_t TagRoundRobinLoadBalancer::BatchAdd(
    Servers& bg, const std::vector<ServerId>& servers) {
    size_t count = 0;
    for (size_t i = 0; i < servers.size(); ++i) {
        count += !!Add(bg, servers[i]);
    }
    return count;
}

size_t TagRoundRobinLoadBalancer::BatchRemove(
    Servers& bg, const std::vector<ServerId>& servers) {
    size_t count = 0;
    for (size_t i = 0; i < servers.size(); ++i) {
        count += !!Remove(bg, servers[i]);
    }
    return count;
}

bool TagRoundRobinLoadBalancer::AddServer(const ServerId& id) {
    return _db_servers.Modify(Add, id);
}

bool TagRoundRobinLoadBalancer::RemoveServer(const ServerId& id) {
    return _db_servers.Modify(Remove, id);
}

size_t TagRoundRobinLoadBalancer::AddServersInBatch(
    const std::vector<ServerId>& servers) {
    const size_t n = _db_servers.Modify(BatchAdd, servers);
    LOG_IF(ERROR, n != servers.size())
        << "Fail to AddServersInBatch, expected " << servers.size()
        << " actually " << n;
    return n;
}

size_t TagRoundRobinLoadBalancer::RemoveServersInBatch(
    const std::vector<ServerId>& servers) {
    const size_t n = _db_servers.Modify(BatchRemove, servers);
    LOG_IF(ERROR, n != servers.size())
        << "Fail to RemoveServersInBatch, expected " << servers.size()
        << " actually " << n;
    return n;
}

int TagRoundRobinLoadBalancer::SelectServer(const SelectIn& in, SelectOut* out) {
    butil::DoublyBufferedData<Servers, TLS>::ScopedPtr s;
    if (_db_servers.Read(&s) != 0) {
        return ENOMEM;
    }

    // use pfb_tag to find server list; if dont find use empty tag.
    auto server_list_it = s->tag_server_map.find(in.pfb_tag);
    if (server_list_it == s->tag_server_map.end() || server_list_it->second.size() == 0) {
        LOG(WARNING) << "select server failed, no tag " << in.pfb_tag << " was found. Or server list is empty";
        if (in.pfb_tag.empty()) {
            return ENODATA;
        }

        server_list_it = s->tag_server_map.find("");
        if (server_list_it == s->tag_server_map.end() || server_list_it->second.size() == 0) { 
            LOG(WARNING) << "select server failed, did not find empty tag. Or server list is empty";
            return ENODATA;
        }
    }

    auto& server_list = server_list_it->second;
    if (_cluster_recover_policy && _cluster_recover_policy->StopRecoverIfNecessary()) {
        if (_cluster_recover_policy->DoReject(server_list)) {
            return EREJECT;
        }
    }
    TLS tls = s.tls();
    if (tls.stride == 0) {
        tls.stride = GenRandomStride2();
        tls.offset = 0;
    }

    const size_t n = server_list.size();
    for (size_t i = 0; i < n; ++i) {
        tls.offset = (tls.offset + tls.stride) % n;
        const SocketId id = server_list[tls.offset].id;
        if (((i + 1) == n  // always take last chance
             || !ExcludedServers::IsExcluded(in.excluded, id))
            && Socket::Address(id, out->ptr) == 0
            && (*out->ptr)->IsAvailable()) {
            s.tls() = tls;
            return 0;
        }
    }
    if (_cluster_recover_policy) {
        _cluster_recover_policy->StartRecover();
    }
    s.tls() = tls;
    return EHOSTDOWN;
}

TagRoundRobinLoadBalancer* TagRoundRobinLoadBalancer::New(
    const butil::StringPiece& params) const {
    TagRoundRobinLoadBalancer* lb = new (std::nothrow) TagRoundRobinLoadBalancer;
    if (lb && !lb->SetParameters(params)) {
        delete lb;
        lb = NULL;
    }
    return lb;
}

void TagRoundRobinLoadBalancer::Destroy() {
    delete this;
}

void TagRoundRobinLoadBalancer::Describe(
    std::ostream &os, const DescribeOptions& options) {
    if (!options.verbose) {
        os << "trr";
        return;
    }
    os << "TagRoundRobinLoad{";
    butil::DoublyBufferedData<Servers, TLS>::ScopedPtr s;
    if (_db_servers.Read(&s) != 0) {
        os << "fail to read _db_servers";
    } else {
        for(auto& p : s->tag_server_map) {
            os << "\"" << p.first << "\":";
            os << "[";
            for (auto& s : p.second) {
                os << s.id;
                os << ",";
            }
            os << "],";
        }
    }
    os << '}';
}

bool TagRoundRobinLoadBalancer::SetParameters(const butil::StringPiece& params) {
    return GetRecoverPolicyByParams(params, &_cluster_recover_policy);
}

}  // namespace policy
}  // namespace brpc
