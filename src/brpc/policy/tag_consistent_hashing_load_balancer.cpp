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


#include <algorithm>                                           // std::set_union
#include <array>
#include <gflags/gflags.h>
#include "butil/containers/flat_map.h"
#include "butil/errno.h"
#include "butil/strings/string_number_conversions.h"
#include "brpc/socket.h"
#include "brpc/policy/tag_consistent_hashing_load_balancer.h"
#include "brpc/policy/hasher.h"

namespace brpc {
namespace policy {

DECLARE_int32(chash_num_replicas);

// Defined in hasher.cpp.
const char* GetHashName(HashFunc hasher);

class TagReplicaPolicy {
public:
    virtual ~TagReplicaPolicy() = default;

    virtual bool Build(ServerId server, 
                       size_t num_replicas,
                       std::vector<TagConsistentHashingLoadBalancer::Node>* replicas) const = 0;
    virtual const char* name() const = 0;
};

class DefaultTagReplicaPolicy : public TagReplicaPolicy {
public:
    DefaultTagReplicaPolicy(HashFunc hash) : _hash_func(hash) {}

    virtual bool Build(ServerId server,
                       size_t num_replicas,
                       std::vector<TagConsistentHashingLoadBalancer::Node>* replicas) const;

    virtual const char* name() const { return GetHashName(_hash_func); }

private:
    HashFunc _hash_func;
};

bool DefaultTagReplicaPolicy::Build(ServerId server,
                                 size_t num_replicas,
                                 std::vector<TagConsistentHashingLoadBalancer::Node>* replicas) const {
    SocketUniquePtr ptr;
    if (Socket::AddressFailedAsWell(server.id, &ptr) == -1) {
        return false;
    }
    replicas->clear();
    for (size_t i = 0; i < num_replicas; ++i) {
        char host[256];
        int len = snprintf(host, sizeof(host), "%s-%lu",
                           endpoint2str(ptr->remote_side()).c_str(), i);
        TagConsistentHashingLoadBalancer::Node node;
        node.hash = _hash_func(host, len);
        node.server_sock = server;
        node.server_addr = ptr->remote_side();
        replicas->push_back(node);
    }
    return true;
}

class KetamaTagReplicaPolicy : public TagReplicaPolicy {
public:
    virtual bool Build(ServerId server,
                       size_t num_replicas,
                       std::vector<TagConsistentHashingLoadBalancer::Node>* replicas) const;

    virtual const char* name() const { return "ketama"; }
};

bool KetamaTagReplicaPolicy::Build(ServerId server,
                                size_t num_replicas,
                                std::vector<TagConsistentHashingLoadBalancer::Node>* replicas) const {
    SocketUniquePtr ptr;
    if (Socket::AddressFailedAsWell(server.id, &ptr) == -1) {
        return false;
    }
    replicas->clear();
    const size_t points_per_hash = 4;
    CHECK(num_replicas % points_per_hash == 0)
        << "Ketam hash replicas number(" << num_replicas << ") should be n*4";
    for (size_t i = 0; i < num_replicas / points_per_hash; ++i) {
        char host[32];
        int len = snprintf(host, sizeof(host), "%s-%lu",
                           endpoint2str(ptr->remote_side()).c_str(), i);
        unsigned char digest[16];
        MD5HashSignature(host, len, digest);
        for (size_t j = 0; j < points_per_hash; ++j) {
            TagConsistentHashingLoadBalancer::Node node;
            node.server_sock = server;
            node.server_addr = ptr->remote_side();
            node.hash = ((uint32_t) (digest[3 + j * 4] & 0xFF) << 24)
                      | ((uint32_t) (digest[2 + j * 4] & 0xFF) << 16)
                      | ((uint32_t) (digest[1 + j * 4] & 0xFF) << 8)
                      | (digest[0 + j * 4] & 0xFF);
            replicas->push_back(node);
        }
    }
    return true;
}

namespace {

pthread_once_t s_replica_policy_once = PTHREAD_ONCE_INIT;
const std::array<const TagReplicaPolicy*, TAG_CONS_HASH_LB_LAST>* g_replica_policy = nullptr;

void InitTagReplicaPolicy() {
    g_replica_policy = new std::array<const TagReplicaPolicy*, TAG_CONS_HASH_LB_LAST>({
        new DefaultTagReplicaPolicy(MurmurHash32),
        new DefaultTagReplicaPolicy(MD5Hash32),
        new KetamaTagReplicaPolicy
    });
}

inline const TagReplicaPolicy* GetTagReplicaPolicy(TagConsistentHashingLoadBalancerType type) {
    pthread_once(&s_replica_policy_once, InitTagReplicaPolicy);
    return g_replica_policy->at(type);
}

} // namespace

TagConsistentHashingLoadBalancer::TagConsistentHashingLoadBalancer(
    TagConsistentHashingLoadBalancerType type)
    : _num_replicas(FLAGS_chash_num_replicas), _type(type) {
    CHECK(GetTagReplicaPolicy(_type))
        << "Fail to find replica policy for consistency lb type: '" << _type << '\'';
}

size_t TagConsistentHashingLoadBalancer::AddBatch(
        std::unordered_map<std::string, std::vector<Node>> &bg,
        const std::unordered_map<std::string, std::vector<Node>> &fg, 
        const std::unordered_map<std::string, std::vector<Node>> &servers, bool *executed) {
    size_t total = 0;
    for (auto tag_itor = servers.begin(); tag_itor != servers.end(); ++tag_itor) {
        std::string pfb_tag = tag_itor->first;
        LOG(INFO) << "add batch pfb_tag is:" << pfb_tag;
        std::unordered_map<std::string, std::vector<Node>>::iterator bg_iter = bg.find(pfb_tag);
        std::unordered_map<std::string, std::vector<Node>>::const_iterator fg_iter = fg.find(pfb_tag);
        std::vector<Node> bg_node_list = (bg_iter == bg.end()) ? std::vector<Node>(0): bg_iter->second;
        std::vector<Node> fg_node_list = (fg_iter == fg.end()) ? std::vector<Node>(0): fg_iter->second;
        if (*executed) {
            // Hack DBD
            total = total + fg_node_list.size() - bg_node_list.size();
            continue;
        }
        bg_node_list.resize(fg_node_list.size() + tag_itor->second.size());
        bg_node_list.resize(std::set_union(fg_node_list.begin(), fg_node_list.end(), 
                                tag_itor->second.begin(), tag_itor->second.end(), bg_node_list.begin())
                - bg_node_list.begin());
        bg.emplace(pfb_tag, bg_node_list);
        LOG(INFO) << "size is:" << bg_node_list.size() - fg_node_list.size();
        total = total + bg_node_list.size() - fg_node_list.size();
    }
    *executed = true;
    return total;
}

size_t TagConsistentHashingLoadBalancer::Remove(
        std::unordered_map<std::string, std::vector<Node>> &bg,
        const std::unordered_map<std::string, std::vector<Node>> &fg,
        const ServerId& server, bool *executed) {
    std::string pfb_tag = server.pfb_tag;
    LOG(INFO) << "remove pfb_tag is:" << pfb_tag;
    std::unordered_map<std::string, std::vector<Node>>::iterator bg_iter = bg.find(pfb_tag);
    std::unordered_map<std::string, std::vector<Node>>::const_iterator fg_iter = fg.find(pfb_tag);
    std::vector<Node> bg_node_list = (bg_iter == bg.end()) ? std::vector<Node>(0): bg_iter->second;
    std::vector<Node> fg_node_list = (fg_iter == fg.end()) ? std::vector<Node>(0): fg_iter->second;
    if (*executed) {
        return bg_node_list.size() - fg_node_list.size();
    }
    *executed = true;
    bg_node_list.clear();
    for (size_t i = 0; i < fg_node_list.size(); ++i) {
        if (fg_node_list[i].server_sock != server) {
            bg_node_list.push_back(fg_node_list[i]);
        }
    }
    bg.emplace(pfb_tag, bg_node_list);
    LOG(INFO) << "remove pfb_tag size:" << fg_node_list.size() - bg_node_list.size();
    return fg_node_list.size() - bg_node_list.size();
}

bool TagConsistentHashingLoadBalancer::AddServer(const ServerId& server) {
    std::vector<Node> add_nodes;
    add_nodes.reserve(_num_replicas);
    if (!GetTagReplicaPolicy(_type)->Build(server, _num_replicas, &add_nodes)) {
        return false;
    }
    std::sort(add_nodes.begin(), add_nodes.end());
    std::unordered_map<std::string, std::vector<Node>> node_map;
    node_map.emplace(server.pfb_tag, add_nodes);
    bool executed = false;
    LOG(INFO) << "AddServer will use AddBatch() and tag is:" << server.pfb_tag;
    const size_t ret = _db_pfb_hash_ring.ModifyWithForeground(AddBatch, node_map, &executed);
    LOG(INFO) << "add server num:" << ret;
    CHECK(ret == 0 || ret == _num_replicas) << ret;
    return ret != 0;
}

size_t TagConsistentHashingLoadBalancer::AddServersInBatch(
    const std::vector<ServerId> &servers) {
    // this key is used for storage pfb_tag which is added
    // the value is index in servers
    std::unordered_map<std::string, std::vector<size_t>> same_tag_map;
    for (size_t sId = 0; sId < servers.size(); ++sId) {
        std::string pfb_tag = servers[sId].pfb_tag;
        std::unordered_map<std::string, std::vector<size_t>>::iterator itor = same_tag_map.find(pfb_tag);
        if (itor == same_tag_map.end()) {
            same_tag_map.emplace(pfb_tag, std::vector<size_t>{sId});
        } else {
            itor->second.push_back(sId);
        }
    }

    std::unordered_map<std::string, std::vector<Node>> same_tag_node_map;
    for (auto a = same_tag_map.begin(); a != same_tag_map.end(); ++a) {
        std::vector<Node> add_nodes;
        add_nodes.reserve(a->second.size() * _num_replicas);
        std::vector<Node> replicas;
        replicas.reserve(_num_replicas);
        for (size_t i = 0; i < a->second.size(); ++i) {
            replicas.clear();
            if (GetTagReplicaPolicy(_type)->Build(servers[a->second[i]], _num_replicas, &replicas)) {
                add_nodes.insert(add_nodes.end(), replicas.begin(), replicas.end());
            }
        }
        std::sort(add_nodes.begin(), add_nodes.end());
        same_tag_node_map.emplace(a->first, add_nodes);
    }
    bool executed = false;
    const size_t ret = _db_pfb_hash_ring.ModifyWithForeground(AddBatch, same_tag_node_map, &executed);
    CHECK(ret % _num_replicas == 0);
    const size_t n = ret / _num_replicas;
    LOG_IF(ERROR, n != servers.size())
        << "Fail to AddServersInBatch, expected " << servers.size()
        << " actually " << n;
    return n;
}

bool TagConsistentHashingLoadBalancer::RemoveServer(const ServerId& server) {
    bool executed = false;
    const size_t ret = _db_pfb_hash_ring.ModifyWithForeground(Remove, server, &executed);
    CHECK(ret == 0 || ret == _num_replicas);
    return ret != 0;
}

size_t TagConsistentHashingLoadBalancer::RemoveBatch(
        std::unordered_map<std::string, std::vector<Node>> &bg,
        const std::unordered_map<std::string, std::vector<Node>> &fg,
        const std::vector<ServerId> &servers, bool *executed) {
    if (*executed) {
        return MapSizeDiff(bg, fg);
    }
    *executed = true;
    if (servers.empty()) {
        bg = fg;
        return 0;
    }

    butil::FlatSet<ServerId> id_set;
    bool use_set = true;
    if (id_set.init(servers.size() * 2) == 0) {
        for (size_t i = 0; i < servers.size(); ++i) {
            if (id_set.insert(servers[i]) == NULL) {
                use_set = false;
                break;
            }
        }
    } else {
        use_set = false;
    }
    CHECK(use_set) << "Fail to construct id_set, " << berror();

    bg.clear();
    for (auto fg_itor = fg.begin(); fg_itor != fg.end(); ++fg_itor) {
        for (size_t i = 0; i < fg_itor->second.size(); ++i) {
            const bool removed = 
                use_set ? (id_set.seek(fg_itor->second[i].server_sock) != NULL)
                        : (std::find(servers.begin(), servers.end(), 
                                    fg_itor->second[i].server_sock) != servers.end());
            if (!removed) {
                bg[fg_itor->first].push_back(fg_itor->second[i]);
            }
        }
    }

    return MapSizeDiff(fg, bg);
}

size_t TagConsistentHashingLoadBalancer::MapSizeDiff(
        const std::unordered_map<std::string, std::vector<Node>> &big_map,
        const std::unordered_map<std::string, std::vector<Node>> &small_map) {
    size_t total = 0;
    std::unordered_map<std::string, std::vector<Node>>::const_iterator small_itor;
    for (auto big_itor = big_map.begin(); big_itor != big_map.end(); ++big_itor) {
        size_t big_size = big_itor->second.size();
        small_itor = small_map.find(big_itor->first);
        size_t small_size = (small_itor == small_map.end()) ? 0 : small_itor->second.size();
        total = total + big_size - small_size;
    }
    return total;
}

size_t TagConsistentHashingLoadBalancer::RemoveServersInBatch(
    const std::vector<ServerId> &servers) {
    bool executed = false;
    const size_t ret = _db_pfb_hash_ring.ModifyWithForeground(RemoveBatch, servers, &executed);
    CHECK(ret % _num_replicas == 0);
    const size_t n = ret / _num_replicas;
    LOG_IF(ERROR, n != servers.size())
        << "Fail to RemoveServersInBatch, expected " << servers.size()
        << " actually " << n;
    return n;
}

LoadBalancer *TagConsistentHashingLoadBalancer::New(const butil::StringPiece& params) const {
    TagConsistentHashingLoadBalancer* lb = 
        new (std::nothrow) TagConsistentHashingLoadBalancer(_type);
    if (lb && !lb->SetParameters(params)) {
        delete lb;
        lb = nullptr;
    }
    return lb;
}

void TagConsistentHashingLoadBalancer::Destroy() {
    delete this;
}

int TagConsistentHashingLoadBalancer::SelectServer(
    const SelectIn &in, SelectOut *out) {
    if (!in.has_request_code) {
        LOG(ERROR) << "Controller.set_request_code() is required";
        return EINVAL;
    }
    if (in.request_code > UINT_MAX) {
        LOG(ERROR) << "request_code must be 32-bit currently";
        return EINVAL;
    }

    butil::DoublyBufferedData<std::unordered_map<std::string, std::vector<Node>>>::ScopedPtr s;
    if (_db_pfb_hash_ring.Read(&s) != 0) {
        LOG(ERROR) << "zxl1";
        return ENOMEM;
    }
    if (s->empty()) {
        LOG(ERROR) << "zxl2";
        return ENODATA;
    }

    for (auto a = s->begin(); a != s->end(); a++){
        LOG(INFO) <<  "map have key:" << a->first;
        LOG(INFO) <<  "map size is:" << a->second.size();
    }

    std::vector<Node>::const_iterator choice;
    // use pfb tag
    std::unordered_map<std::string, std::vector<Node>>::const_iterator list_iter = s->find(in.pfb_tag);
    if (list_iter == s->end() || list_iter->second.size() == 0) {
        if (in.pfb_tag.empty()) {
            LOG(INFO) << "pfb_tag is empty, and did not find value";
            return ENODATA;
        } else {
            list_iter = s->find("");
            if (list_iter == s->end() || list_iter->second.size() == 0) {
                LOG(INFO) << "dont find pfb_tag:" << in.pfb_tag << ", and did not find empty tag";
                return ENODATA;
            } else {
                std::vector<Node> hash_ring = list_iter->second;
                choice = std::lower_bound(hash_ring.begin(), hash_ring.end(), (uint32_t)in.request_code);
            }
        }
    } else {
        // find 
        std::vector<Node> hash_ring = list_iter->second;
        choice = std::lower_bound(hash_ring.begin(), hash_ring.end(), (uint32_t)in.request_code);
    }
    
    std::vector<Node> hash_ring = list_iter->second;
    // Socket::Address(choice->server_sock.id, out->ptr) == 0 
    for (size_t i = 0; i < hash_ring.size(); ++i) {
        if (((i + 1) == hash_ring.size() // always take last chance
             || !ExcludedServers::IsExcluded(in.excluded, choice->server_sock.id))
            && Socket::Address(choice->server_sock.id, out->ptr) == 0 
            && (*out->ptr)->IsAvailable()) {
            return 0;
        } else {
            if (++choice == hash_ring.end()) {
                choice = hash_ring.begin();
            }
        }
    }

    return EHOSTDOWN;
}

void TagConsistentHashingLoadBalancer::Describe(
    std::ostream &os, const DescribeOptions& options) {
    if (!options.verbose) {
        os << "tc_hash";
        return;
    }
    os << "TagConsistentHashingLoadBalancer {\n"
       << "  hash function: " << GetTagReplicaPolicy(_type)->name() << '\n'
       << "  replica per host: " << _num_replicas << '\n';
    std::map<butil::EndPoint, double> load_map;
    GetLoads(&load_map);
    os << "  number of hosts: " << load_map.size() << '\n';
    os << "  load of hosts: {\n";
    double expected_load_per_server = 1.0 / load_map.size();
    double load_sum = 0;
    double load_sqr_sum = 0;
    for (std::map<butil::EndPoint, double>::iterator 
            it = load_map.begin(); it!= load_map.end(); ++it) {
        os << "    " << it->first << ": " << it->second << '\n';
        double normalized_load = it->second / expected_load_per_server;
        load_sum += normalized_load;
        load_sqr_sum += normalized_load * normalized_load;
    }
    os << "  }\n";
    os << "deviation: "  
       << sqrt(load_sqr_sum * load_map.size() - load_sum * load_sum) 
          / load_map.size();
    os << "}\n";
}

void TagConsistentHashingLoadBalancer::GetLoads(
    std::map<butil::EndPoint, double> *load_map) {
    load_map->clear();
    std::map<butil::EndPoint, uint32_t> count_map;
    do {
        butil::DoublyBufferedData<std::unordered_map<std::string, std::vector<Node>>>::ScopedPtr s;
        if (_db_pfb_hash_ring.Read(&s) != 0) {
            break;
        }
        if (s->empty()) {
            break;
        }

        for (auto iter = s->begin(); iter != s->end(); iter++) {
            std::vector<Node> node_list = iter->second;
            count_map[node_list.begin()->server_addr] += 
                node_list.begin()->hash + (UINT_MAX - (node_list.end() - 1)->hash);
        }

        for (auto iter = s->begin(); iter != s->end(); iter++) {
            std::vector<Node> node_list = iter->second;
            for (size_t i = 1; i < node_list.size(); ++i) {
                count_map[node_list[i].server_addr] +=
                        node_list[i].hash - node_list[i - 1].hash;
            }
        }
    } while (0);
    for (std::map<butil::EndPoint, uint32_t>::iterator 
            it = count_map.begin(); it!= count_map.end(); ++it) {
        (*load_map)[it->first] = (double)it->second / UINT_MAX;
    }
}

bool TagConsistentHashingLoadBalancer::SetParameters(const butil::StringPiece& params) {
    for (butil::KeyValuePairsSplitter sp(params.begin(), params.end(), ' ', '=');
            sp; ++sp) {
        if (sp.value().empty()) {
            LOG(ERROR) << "Empty value for " << sp.key() << " in lb parameter";
            return false;
        }
        if (sp.key() == "replicas") {
            if (!butil::StringToSizeT(sp.value(), &_num_replicas)) {
                return false;
            }
            continue;
        }
        LOG(ERROR) << "Failed to set this unknown parameters " << sp.key_and_value();
    }
    return true;
}

}  // namespace policy
} // namespace brpc
