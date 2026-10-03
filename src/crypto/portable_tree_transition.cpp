// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
// Profile 3 public predicate. Groth16 and custody rules remain mandatory.
#include "crypto/poseidon_bn254.h"
#include "crypto/public_tree_transition.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace neurai::public_tree {
namespace {
using Bytes = std::vector<unsigned char>;
using Field = std::array<unsigned char, 32>;
using Path = std::array<Field, 32>;
void Need(bool yes) { if (!yes) throw std::invalid_argument("invalid C6 transition"); }
template<class T> void Append(Bytes& b, const T& value) { b.insert(b.end(), value.begin(), value.end()); }
void U32(Bytes& b, uint32_t value) { for (int i=0; i<4; ++i) b.push_back(value >> (8*i)); }
struct Reader {
    const Bytes& data; size_t position=0;
    Bytes Take(size_t n) {
        Need(n <= data.size()-position);
        Bytes out(data.begin()+position, data.begin()+position+n); position+=n; return out;
    }
    uint32_t Int() { auto v=Take(4); uint32_t n=0; for(int i=0;i<4;++i) n|=uint32_t(v[i])<<(8*i); return n; }
    Field Fr() {
        auto v=Take(32); Field f;
        std::copy(v.begin(),v.end(),f.begin());
        Need(crypto::IsCanonicalPoseidonField(f.data())); return f;
    }
    Path Siblings() { Path p; for(auto& f:p) f=Fr(); return p; }
};
struct State {
    std::array<Field,3> roots;
    std::array<uint32_t,3> counts;
    unsigned char mode;
    Field history;
    uint32_t historyCount;
    explicit State(const Bytes& raw) {
        Need(raw.size()==145); Reader r{raw};
        for(auto& f:roots) f=r.Fr();
        for(auto& n:counts) n=r.Int();
        mode=r.Take(1)[0]; history=r.Fr(); historyCount=r.Int();
        Need(mode<=1 && counts[1]>=1 && uint64_t(counts[2])==uint64_t(counts[0])+1);
        Need(historyCount<=counts[0] && bool(historyCount)==bool(counts[0]));
    }
    Bytes Encode() const {
        Bytes b; for(auto& f:roots) Append(b,f); for(auto n:counts) U32(b,n);
        b.push_back(mode); Append(b,history); U32(b,historyCount); return b;
    }
};
unsigned Count(unsigned form) { return form<2 || form==6 || form==8 ? 1 : form<5 ? form-1 : 0; }
bool Shape(const Bytes& raw,unsigned form,size_t& cost) {
    if(form>8 || raw.size()<2 || raw[0]!=(form==8 ? 3 : 2) || raw[1]!=form) return false;
    const unsigned n=Count(form), spend=form>=2;
    const unsigned nullifiers=form==8 ? 2 : spend;
    const size_t size=292+32*(nullifiers ? nullifiers : 1)+32*n+1028*spend+2120*nullifiers+3144*n+1024*(n>0);
    if(raw.size()!=size || size>15360) return false;
    cost=6+134*nullifiers+198*n+32*spend+64*(n>0)+(form<2); return true;
}
struct Verifier {
    size_t work=0,limit;
    explicit Verifier(size_t limitIn):limit(limitIn) {}
    void Charge(size_t n) { Need(n<=limit-work); work+=n; }
    Field Hash(const Bytes& bytes) {
        Charge(crypto::PoseidonPermutationCost(bytes.size())); Field f;
        crypto::PoseidonBN254(bytes.data(),bytes.size(),f.data()); return f;
    }
    Field Root(Field f,uint32_t index,const Path& path) {
        for(const auto& sibling:path) {
            Charge(1); Field out;
            Need(index&1 ? crypto::PoseidonMerkleNode(sibling.data(),f.data(),out.data())
                         : crypto::PoseidonMerkleNode(f.data(),sibling.data(),out.data()));
            f=out; index>>=1;
        }
        return f;
    }
    Field Leaf(bool cm,const Field& value,const Field& next,uint32_t index) {
        const std::string tag=cm?"NIP043/cmleaf":"NIP043/nfleaf";
        Bytes b(tag.begin(),tag.end()); Append(b,value); Append(b,next); U32(b,index); return Hash(b);
    }
    Field Insert(Reader& r,bool cm,const Field& old,uint32_t next,const Field& value) {
        const uint32_t pred=r.Int(); const Field pv=r.Fr(), nv=r.Fr(); const uint32_t ni=r.Int();
        const Path pp=r.Siblings(), ep=r.Siblings(); const Field zero{};
        Need(next>=1 && next<=UINT32_MAX-1 && pred<next && ni<next);
        Need((nv==zero)==(ni==0) && (pv==zero)==(pred==0));
        Need(pv<value && (nv==zero || value<nv));
        Need(Root(Leaf(cm,pv,nv,ni),pred,pp)==old);
        const auto mid=Root(Leaf(cm,pv,value,next),pred,pp);
        Need(Root(zero,next,ep)==mid);
        return Root(Leaf(cm,value,nv,ni),next,ep);
    }
    bool Check(const Bytes& raw,unsigned form,const Bytes& oldDigest,const Bytes& newDigest,const Bytes& publicBytes) {
        const bool join=form==8;
        const unsigned n=Count(form), expected=join?7:form<2?5:form<5?5+n:8;
        Need(publicBytes.size()==expected*32 && oldDigest.size()==32 && newDigest.size()==32);
        Reader publics{publicBytes}; std::vector<Field> inputs;
        for(unsigned i=0;i<expected;++i) inputs.push_back(publics.Fr());
        Need(crypto::IsCanonicalPoseidonField(oldDigest.data()) && crypto::IsCanonicalPoseidonField(newDigest.data()));
        Reader r{raw}; r.Take(2); const auto old=r.Take(145), next=r.Take(145);
        const auto oh=Hash(old),nh=Hash(next);
        Need(std::equal(oh.begin(),oh.end(),oldDigest.begin()) && std::equal(nh.begin(),nh.end(),newDigest.begin()));
        State state(old), newState(next);
        Need(state.mode==(form!=0));
        const Field nf=r.Fr(),zero{};
        const Field second=join?r.Fr():zero;
        std::vector<Field> cms;
        for(unsigned i=0;i<n;++i) cms.push_back(r.Fr());
        if(form<2) {
            Need(nf==zero);
            Need(std::all_of(inputs[3].begin(),inputs[3].begin()+24,[](unsigned char x){return x==0;}));
            uint64_t amount=0; for(size_t i=24;i<32;++i) amount=(amount<<8)|inputs[3][i];
            Need(amount>0 && amount<=2100000000000000000ULL);
            const std::string tag="NIP045/dep"; Bytes b(tag.begin(),tag.end()); b.push_back(1);
            for(int i=0;i<8;++i) b.push_back(amount>>(8*i)); Append(b,cms[0]);
            Need(Hash(b)==inputs[1]);
        } else {
            Need(nf==inputs[2] && nf!=zero);
            if(join) Need(second==inputs[3] && second!=zero && second!=nf);
            const uint32_t index=r.Int(); const Path path=r.Siblings();
            Need(inputs[1]!=zero && index<state.historyCount);
            Need(Root(inputs[1],index,path)==state.history);
            if(join) Need(cms[0]==inputs[6] && cms[0]!=zero);
            else if(form<5) Need(std::equal(cms.begin(),cms.end(),inputs.begin()+5));
            else if(n) Need(cms[0]==inputs[6] && inputs[6]!=zero);
            else {
                // Independently frozen PoseidonBytes("NeuraiPoolC6/no-publication" || 01).
                // A constant avoids any uncharged hashing during verification.
                static const Field empty = {
                    0x04,0xbf,0x93,0x8a,0x28,0xaf,0x8b,0xc7,0xab,0x28,0x10,0xe0,0xad,0xf3,0xcb,0xbb,
                    0x55,0xaa,0x4f,0xeb,0x79,0x82,0x7f,0xee,0xd2,0x72,0x2c,0x51,0x23,0xba,0xac,0x15};
                Need(inputs[6]==zero && inputs[7]==empty);
            }
            // J2 inserts in public-input order. The second proof authenticates
            // the intermediate tree, never the same old tree as the first.
            if(join) Need(state.counts[1]<=UINT32_MAX-2);
            state.roots[1]=Insert(r,false,state.roots[1],state.counts[1],nf); ++state.counts[1];
            if(join) {
                state.roots[1]=Insert(r,false,state.roots[1],state.counts[1],second);
                ++state.counts[1];
            }
        }
        for(const auto& cm:cms) {
            Need(cm!=zero && state.counts[0]<=UINT32_MAX-2);
            const Path path=r.Siblings();
            Need(Root(zero,state.counts[0],path)==state.roots[0]);
            state.roots[0]=Root(cm,state.counts[0],path);
            state.roots[2]=Insert(r,true,state.roots[2],state.counts[2],cm);
            ++state.counts[0]; ++state.counts[2];
        }
        if(n) {
            Need(state.historyCount<UINT32_MAX);
            const Path path=r.Siblings();
            Need(Root(zero,state.historyCount,path)==state.history);
            state.history=Root(state.roots[0],state.historyCount,path); ++state.historyCount;
        }
        state.mode=form!=7;
        Need(state.Encode()==next && r.position==raw.size()); return true;
    }
};
} // namespace

bool PortableTransitionCost(const Bytes& transcript, unsigned form, size_t& cost)
{
    return Shape(transcript, form, cost);
}

bool VerifyPortableTransition(const Bytes& transcript, unsigned form,
                              const Bytes& oldDigest, const Bytes& newDigest,
                              const Bytes& inputs)
{
    size_t cost = 0;
    if (!PortableTransitionCost(transcript, form, cost) || cost > MAX_WORK_PER_SCRIPT) return false;
    try {
        Verifier verifier(cost);
        return verifier.Check(transcript, form, oldDigest, newDigest, inputs) && verifier.work == cost;
    } catch (const std::invalid_argument&) {
        return false;
    }
}
} // namespace neurai::public_tree
