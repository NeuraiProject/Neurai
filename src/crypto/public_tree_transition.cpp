// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "crypto/public_tree_transition.h"
#include "crypto/poseidon_bn254.h"
#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>

namespace neurai::public_tree {
namespace {
using Field = std::array<unsigned char,32>;
using Path = std::array<Field,32>;
static void Need(bool yes) { if (!yes) throw std::invalid_argument("invalid transition"); }
template<class T> static void Append(Bytes& out,const T& v) { out.insert(out.end(),v.begin(),v.end()); }
static void U32(Bytes& out,uint32_t n) { for(int i=0;i<4;++i) out.push_back(n>>(8*i)); }
struct Reader {
    const Bytes& b; size_t i=0;
    Bytes Take(size_t n) { Need(n<=b.size()-i); Bytes v(b.begin()+i,b.begin()+i+n); i+=n; return v; }
    uint32_t Int() { auto v=Take(4); uint32_t n=0; for(int j=0;j<4;++j) n|=uint32_t(v[j])<<(8*j); return n; }
    Field Fr() { auto v=Take(32); Field f; std::copy(v.begin(),v.end(),f.begin()); Need(crypto::IsCanonicalPoseidonField(f.data())); return f; }
    Path Siblings() { Path p; for(auto& v:p) v=Fr(); return p; }
};
struct State {
    std::array<Field,3> roots; std::array<uint32_t,3> counts; unsigned char mode;
    explicit State(const Bytes& raw) {
        Need(raw.size()==109); Reader r{raw}; for(auto& f:roots) f=r.Fr(); for(auto& n:counts) n=r.Int(); mode=r.Take(1)[0];
        Need(mode<=1 && counts[1]>=1 && uint64_t(counts[2])==uint64_t(counts[0])+1);
    }
    Bytes Encode() const { Bytes b; for(auto& f:roots) Append(b,f); for(auto n:counts) U32(b,n); b.push_back(mode); return b; }
};
struct Verifier {
    size_t work=0,limit;
    explicit Verifier(size_t cap):limit(cap) {}
    void Charge(size_t n) { Need(n<=limit-work); work+=n; }
    Field Hash(const Bytes& b) { Charge(crypto::PoseidonPermutationCost(b.size())); Field f; crypto::PoseidonBN254(b.data(),b.size(),f.data()); return f; }
    Field Root(Field f,uint32_t i,const Path& p) {
        for(const auto& s:p) { Charge(1); Field out; Need((i&1) ? crypto::PoseidonMerkleNode(s.data(),f.data(),out.data()):crypto::PoseidonMerkleNode(f.data(),s.data(),out.data())); f=out; i>>=1; } return f;
    }
    Field Leaf(bool cm,const Field& v,const Field& nv,uint32_t ni) {
        std::string tag=cm?"NIP043/cmleaf":"NIP043/nfleaf"; Bytes b(tag.begin(),tag.end()); Append(b,v); Append(b,nv); U32(b,ni); return Hash(b);
    }
    Field Insert(Reader& r,bool cm,const Field& old,uint32_t next,const Field& value) {
        uint32_t pred=r.Int(); Field pv=r.Fr(),nv=r.Fr(); uint32_t ni=r.Int(); Path pp=r.Siblings(),ep=r.Siblings();
        const Field zero{};
        Need(next>=1 && next<=UINT32_MAX-1 && pred<next && ni<next);
        Need((nv==zero)==(ni==0) && (pv==zero)==(pred==0));
        Need(pv<value && (nv==zero || value<nv));
        Need(Root(Leaf(cm,pv,nv,ni),pred,pp)==old);
        auto mid=Root(Leaf(cm,pv,value,next),pred,pp);
        Need(Root(zero,next,ep)==mid);
        return Root(Leaf(cm,value,nv,ni),next,ep);
    }
    bool Check(const Bytes& raw,const Bytes& binding) {
        Need(raw.size()<=16384); Reader r{raw}; Need(r.Take(1)[0]==1); unsigned code=r.Take(1)[0]; Need(code<8);
        unsigned n=code<2?1:code<6?code-1:0;
        auto oldraw=r.Take(109),newraw=r.Take(109); State state(oldraw),next(newraw);
        Field nf=r.Fr(); std::vector<Field> cms; for(unsigned i=0;i<n;++i) cms.push_back(r.Fr());
        Bytes wanted{static_cast<unsigned char>(code)}; Append(wanted,Hash(oldraw)); Append(wanted,Hash(newraw)); Append(wanted,nf); for(auto& f:cms) Append(wanted,f);
        Need(wanted==binding && state.mode==(code!=0));
        if(code<2) Need(nf==Field{});
        else { state.roots[1]=Insert(r,false,state.roots[1],state.counts[1],nf); ++state.counts[1]; }
        for(const auto& cm:cms) {
            Need(cm!=Field{} && state.counts[0]<=UINT32_MAX-2);
            auto path=r.Siblings(); Need(Root(Field{},state.counts[0],path)==state.roots[0]);
            state.roots[0]=Root(cm,state.counts[0],path);
            state.roots[2]=Insert(r,true,state.roots[2],state.counts[2],cm);
            ++state.counts[0]; ++state.counts[2];
        }
        state.mode=code!=7;
        Need(state.Encode()==newraw && r.i==raw.size()); return true;
    }
};
} // namespace

bool TransitionCost(const Bytes& transcript, unsigned form, size_t& cost)
{
    if (form >= 8 || transcript.size() < 2 || transcript[0] != 1 || transcript[1] != form) return false;
    const size_t outputs = form < 2 ? 1 : form < 6 ? form - 1 : 0;
    const size_t spends = form < 2 ? 0 : 1;
    if (transcript.size() != 252 + outputs * 32 + spends * 2120 + outputs * 3144) return false;
    // Charge the maximum exact valid-path cost BEFORE any hashing, even on
    // cryptographically invalid paths. Deposits also bind amount + commitment.
    cost = 4 + spends * 134 + outputs * 198 + (form < 2 ? 1 : 0);
    return true;
}

bool VerifyTransition(const Bytes& transcript, unsigned form, const Bytes& inputs)
{
    size_t cost;
    if (!TransitionCost(transcript, form, cost)) return false;
    const size_t outputs = form < 2 ? 1 : form < 6 ? form - 1 : 0;
    const size_t expected = form < 2 ? 9 : form < 6 ? 6 + outputs : 8;
    if (inputs.size() != expected * 32) return false;
    for (size_t i = 0; i < inputs.size(); i += 32)
        if (!crypto::IsCanonicalPoseidonField(inputs.data() + i)) return false;
    try {
        Verifier verifier(cost);
        Bytes binding{static_cast<unsigned char>(form)};
        binding.insert(binding.end(), inputs.begin() + 32, inputs.begin() + 96);
        if (form < 2) {
            // The commitment is private to the deposit circuit, but its public
            // dep digest commits to the same amount and cm. Tie it here too.
            binding.insert(binding.end(), 32, 0);
            binding.insert(binding.end(), transcript.begin() + 252, transcript.begin() + 284);
            const auto amount = inputs.begin() + 8 * 32;
            if (!std::all_of(amount, amount + 24, [](unsigned char c) { return c == 0; })) return false;
            const std::string tag = "NIP045/dep";
            Bytes preimage(tag.begin(), tag.end()); preimage.push_back(1);
            for (int j = 31; j >= 24; --j) preimage.push_back(amount[j]);
            preimage.insert(preimage.end(), transcript.begin() + 252, transcript.begin() + 284);
            const auto dep = verifier.Hash(preimage);
            if (!std::equal(dep.begin(), dep.end(), inputs.begin() + 3 * 32)) return false;
        } else {
            binding.insert(binding.end(), inputs.begin() + 3 * 32, inputs.begin() + 4 * 32);
            if (outputs) binding.insert(binding.end(), inputs.begin() + 6 * 32, inputs.end());
        }
        return verifier.Check(transcript, binding) && verifier.work == cost;
    } catch (const std::invalid_argument&) {
        return false;
    }
}
} // namespace neurai::public_tree
