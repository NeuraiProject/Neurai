// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-036: Poseidon over BN254 scalar field Fr (t = 3, R_F = 8,
// R_P = 57, S-box = x^5).
//
// =====================================================================
// UPSTREAM PIN — DO NOT EDIT WITHOUT REVIEWING AS A CONSENSUS CHANGE.
// =====================================================================
//
// Source repository:  arnaucube/poseidon-rs
// Source commit-sha:  f4ba1f7c32905cd2ae5a71e7568564bb150a9862
// Source file:        src/constants.rs
//   - C  ← second `vec![` block (state size t=3): lines 134..328
//   - M  ← second `vec![` block of `m_str` (t=3): lines 10903..10917
//
// arnaucube/poseidon-rs README (at the pinned commit) claims
// compatibility with the Sage reference, go-iden3-crypto (Go) and
// circomlib (JS / circom). The canonical interop check is:
//
//   Poseidon([1, 2]) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
//
// which is the well-known reference output produced by
// circomlibjs / go-iden3-crypto / arnaucube/poseidon-rs alike.
// poseidon_tests.cpp asserts this end-to-end.
//
// "Unoptimized" form: this header stores the full (R_F + R_P) * t =
// 195 round constants and a single 3x3 MDS matrix M (no separately
// stored S or P arrays). Both full and partial rounds use the same
// MDS in this form. The optimization that absorbs partial-round
// constants into the matrix multiply (used by go-iden3-crypto for
// circuit efficiency) is mathematically equivalent — same hash
// output for any input. We choose the unoptimized form so the
// permutation in poseidon_bn254.cpp can mirror the standard Poseidon
// paper algorithm without optimization-specific code paths.
//
// Numeric encoding: each Fr element is stored as 4 little-endian
// 64-bit limbs — limbs[0] holds bits 0..63, limbs[3] holds bits
// 192..255. Values are in *canonical* (non-Montgomery) form — they
// are the actual Fr integers as published upstream. The runtime
// Montgomery conversion (if used) happens at first access, not
// here. To audit a constant against upstream, reassemble:
//   x = limbs[0] + (limbs[1] << 64) + (limbs[2] << 128) + (limbs[3] << 192)
// and decimal-print x; compare against the matching string literal
// in arnaucube/poseidon-rs/src/constants.rs at the pinned commit.

#ifndef NEURAI_CRYPTO_POSEIDON_BN254_CONSTANTS_H
#define NEURAI_CRYPTO_POSEIDON_BN254_CONSTANTS_H

#include <cstdint>

namespace crypto {
namespace poseidon_bn254_detail {

// BN254 scalar field modulus, little-endian limbs.
//   r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//     = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
static constexpr uint64_t MODULUS_R[4] = {
    0x43e1f593f0000001ULL,
    0x2833e84879b97091ULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL,
};

// Round constants C[(R_F + R_P) * t] = C[195] for t = 3.
// Indexed [round * t + element] with round in [0, R_F + R_P) and
// element in [0, t). For full rounds (rounds 0..R_F/2 and
// R_F/2+R_P..R_F+R_P) all t entries are added to state[0..t]
// before the S-box. For partial rounds (R_F/2..R_F/2+R_P) only
// state[0] gets the S-box; the constants for the other elements
// still get added (this differs from the optimized variant which
// merges them into the MDS matrix multiply).
static constexpr uint64_t POSEIDON_BN254_RC[195][4] = {
    { 0x8d21d47304cd8e6eULL, 0x14c4993c11bb2993ULL, 0xd05986d656f40c21ULL, 0x0ee9a592ba9a9518ULL }, // C[0]
    { 0x5696fff40956e864ULL, 0x887b08d4d00868dfULL, 0x5986587169fc1bcdULL, 0x00f1445235f2148cULL }, // C[1]
    { 0xe879f3890ecf73f5ULL, 0x30c728730b7ab36cULL, 0x1f29a058d0fa80b9ULL, 0x08dff3487e8ac99eULL }, // C[2]
    { 0x20966310fadc01d0ULL, 0x56c35342c84bda6eULL, 0xc3ce28f7532b13c8ULL, 0x2f27be690fdaee46ULL }, // C[3]
    { 0x8b8327bebca16cf2ULL, 0xb763fe04b8043ee4ULL, 0x2416bebf3d4f6234ULL, 0x2b2ae1acf68b7b8dULL }, // C[4]
    { 0xe64b44c7dbf11cfaULL, 0x5952c175ab6b03eaULL, 0xcca5eac06f97d4d5ULL, 0x0319d062072bef7eULL }, // C[5]
    { 0x8ef7b387bf28526dULL, 0xc8b7bf27ad49c629ULL, 0x8a376df87af4a63bULL, 0x28813dcaebaeaa82ULL }, // C[6]
    { 0x150928adddf9cb78ULL, 0x2033865200c352bcULL, 0xf181bf38e1c1d40dULL, 0x2727673b2ccbc903ULL }, // C[7]
    { 0xb8fb9e31e65cc632ULL, 0x6efbd43e340587d6ULL, 0xe74abd2b2a1494cdULL, 0x234ec45ca27727c2ULL }, // C[8]
    { 0xcd99ff6e8797d428ULL, 0xab10a8150a337b1cULL, 0x7f862cb2cf7cf760ULL, 0x15b52534031ae18fULL }, // C[9]
    { 0xd701d4eecf68d1f6ULL, 0x8e0e8a8d1b58b132ULL, 0x5ed9a3d186b79ce3ULL, 0x0dc8fad6d9e4b35fULL }, // C[10]
    { 0x97805518a47e4d9cULL, 0xea4eb378f62e1fecULL, 0x600f705fad3fb567ULL, 0x1bcd95ffc211fbcaULL }, // C[11]
    { 0x17cb978d069de559ULL, 0xc76da36c25789378ULL, 0xe9eff81b016fc34dULL, 0x10520b0ab721cadfULL }, // C[12]
    { 0xe88a9eb81f5627f6ULL, 0x2932498075fed0acULL, 0x9b257d8ed5fbbaf4ULL, 0x1f6d48149b8e7f7dULL }, // C[13]
    { 0xca34bdb5460c8705ULL, 0xfff8dc1c816f0dc9ULL, 0xd29e00ef35a2089bULL, 0x1d9655f652309014ULL }, // C[14]
    { 0x8fe3d4185697cc7dULL, 0xa731ff67e4703205ULL, 0xb051f7b1cd43a99bULL, 0x04df5a56ff95bcafULL }, // C[15]
    { 0xf6ec282b6e4be828ULL, 0x8690a10a8c8424a7ULL, 0x151b3d290cedaf14ULL, 0x0672d995f8fff640ULL }, // C[16]
    { 0x9fc1d8209b5c75b9ULL, 0x0c9a9dcc06f2708eULL, 0xb21200d7ffafdd5fULL, 0x099952b414884454ULL }, // C[17]
    { 0x83fd0e843a6b9fa6ULL, 0x48e43586a9b4cd91ULL, 0x7c483143ba8d4694ULL, 0x052cba2255dfd00cULL }, // C[18]
    { 0x16077cb93c464ddcULL, 0x82de55707251ad77ULL, 0xb0bd74712b7999afULL, 0x0b8badee690adb8eULL }, // C[19]
    { 0xb963d0a8e4b2bdd1ULL, 0x49c15d60683a8050ULL, 0x5a1ee651020c07c7ULL, 0x119b1590f13307afULL }, // C[20]
    { 0xce15be0bfb4a8d09ULL, 0x2c4acfc884ef4ee5ULL, 0x2529d36be0f67b83ULL, 0x03150b7cd6d5d17bULL }, // C[21]
    { 0xbe69cb317c9ea565ULL, 0x5374efb83d80898aULL, 0x3cf1951f17391235ULL, 0x2cc6182c5e14546eULL }, // C[22]
    { 0x92d2cd73111bf0f9ULL, 0x4218cadedac14e2bULL, 0x50cfe129a404b376ULL, 0x005032551e6378c4ULL }, // C[23]
    { 0x88f9da2cc28276b5ULL, 0x6469c399fcc069fbULL, 0xbb147e972ebcb951ULL, 0x233237e3289baa34ULL }, // C[24]
    { 0xe80c2d4c24d60280ULL, 0x23037f21b34ae5a4ULL, 0xc980d31674bfbe63ULL, 0x05c8f4f4ebd4a6e3ULL }, // C[25]
    { 0xee1f09b2590fc65bULL, 0x52bcf35ef3aeed91ULL, 0xba05d818a319f252ULL, 0x0a7b1db13042d396ULL }, // C[26]
    { 0x5df542365a404ec0ULL, 0xf156e2b086ff47dcULL, 0xb14296572c9d32dbULL, 0x2a73b71f9b210cf5ULL }, // C[27]
    { 0x76a760bb5c50c460ULL, 0xec18f2c4dbe7f229ULL, 0x935107e9ffc91dc3ULL, 0x1ac9b0417abcc9a1ULL }, // C[28]
    { 0x9015ee046dc93fc0ULL, 0x269f3e4d6cb10434ULL, 0x3fabb076707ef479ULL, 0x12c0339ae0837482ULL }, // C[29]
    { 0x8246682e56e9a28eULL, 0x52900aa3253baac6ULL, 0x7f5b18db4e1e704fULL, 0x0b7475b102a165adULL }, // C[30]
    { 0x32ab3aa88d7f8448ULL, 0x7c843e379366f2eaULL, 0xdb1c5e49f6e8b891ULL, 0x037c2849e191ca3eULL }, // C[31]
    { 0x45fdb176a716346fULL, 0xd5206c5c93a07dc1ULL, 0xe92674661e217e9bULL, 0x05a6811f8556f014ULL }, // C[32]
    { 0x7b675ef5f38bd66eULL, 0x4076e87a7b2883b4ULL, 0x6e947b75d54e9f04ULL, 0x29a795e7d9802894ULL }, // C[33]
    { 0x507be199981fd22fULL, 0x6e8c7382c8a1585cULL, 0x45a3857afc18f582ULL, 0x20439a0c84b322ebULL }, // C[34]
    { 0x4a2a6f2a0982c887ULL, 0xbb50f27799a84b6dULL, 0x94ec2050c7371ff1ULL, 0x2e0ba8d94d9ecf4aULL }, // C[35]
    { 0xe6d0ddcca17d71c8ULL, 0x17822cd2109048d2ULL, 0xca38eb7cce822b45ULL, 0x143fd115ce08fb27ULL }, // C[36]
    { 0xc84323623be9caf1ULL, 0xf8611659323dbcbfULL, 0x57968dbbdcf813cdULL, 0x0c64cbecb1c734b8ULL }, // C[37]
    { 0xf1426cef9403da53ULL, 0xe74f348d62c2b670ULL, 0x46fca925c163ff5aULL, 0x028a305847c683f6ULL }, // C[38]
    { 0x24d6755b5db9e30cULL, 0x6a6bcb64d89427b8ULL, 0x5fa940ab4c4380f2ULL, 0x2e4ef510ff0b6fdaULL }, // C[39]
    { 0xb96384f50579400eULL, 0x8925b4f6d033b078ULL, 0x63d79270c956ce3bULL, 0x0081c95bc43384e6ULL }, // C[40]
    { 0xba8a9f4023a0bb38ULL, 0xe2491b349c039a0bULL, 0x187e2fade687e05eULL, 0x2ed5f0c91cbd9749ULL }, // C[41]
    { 0x990f01f33a735206ULL, 0x3448a22c76234c8cULL, 0x4bbf374ed5aae2f0ULL, 0x30509991f88da350ULL }, // C[42]
    { 0xa7529094424ec6adULL, 0xf0a1119fb2067b41ULL, 0x221b7c4d49a356b9ULL, 0x1c3f20fd55409a53ULL }, // C[43]
    { 0x170887b47ddcb96cULL, 0xc46bb2213e8e131eULL, 0x049514459b6e18eeULL, 0x10b4e7f3ab5df003ULL }, // C[44]
    { 0x039aa3502e43adefULL, 0xdd80f804c077d775ULL, 0x3ddd543d891c2abdULL, 0x2a1982979c3ff7f4ULL }, // C[45]
    { 0x5cad0f1315bd5c91ULL, 0xba431ebc396c9af9ULL, 0xfeddbead56d6d55dULL, 0x1c74ee64f15e1db6ULL }, // C[46]
    { 0x9c2fe45a0ae146a0ULL, 0x9e4f2e8b82708cfaULL, 0xeab9303cace01b4bULL, 0x07533ec850ba7f98ULL }, // C[47]
    { 0x8a11abf3764c0750ULL, 0x285c68f42d42c180ULL, 0xa151e4eeaf17b154ULL, 0x21576b438e500449ULL }, // C[48]
    { 0x743d6930836d4a9eULL, 0xbce8384c815f0906ULL, 0x08ad5ca193d62f10ULL, 0x2f17c0559b8fe796ULL }, // C[49]
    { 0xe665b0b1b7e2730eULL, 0x9775a4201318474aULL, 0xa79e8aae946170bcULL, 0x2d477e3862d07708ULL }, // C[50]
    { 0xd89be0f5b2747eabULL, 0xafba2266c38f5abcULL, 0x90e095577984f291ULL, 0x162f5243967064c3ULL }, // C[51]
    { 0x7777a70092393311ULL, 0xd7a8596a87f29f8aULL, 0x264ecd2c8ae50d1aULL, 0x2b4cb233ede9ba48ULL }, // C[52]
    { 0x4254e7c35e03b07aULL, 0x6db2eece6d85c4cfULL, 0x1dbaf8f462285477ULL, 0x2c8fbcb2dd8573dcULL }, // C[53]
    { 0xe5e88db870949da9ULL, 0x9e1b61e9f601e9adULL, 0xf2ff453f0cd56b19ULL, 0x1d6f347725e4816aULL }, // C[54]
    { 0x4cd49af5c4565529ULL, 0xf9e6ac02b68d3132ULL, 0xebc2d8b3df5b913dULL, 0x204b0c397f4ebe71ULL }, // C[55]
    { 0x4ff8fb75bc79c502ULL, 0x9ecb827cd7dc2553ULL, 0x4f1149b3c63c3c2fULL, 0x0c4cb9dc3c4fd817ULL }, // C[56]
    { 0x9a616ddc45bc7b54ULL, 0x1e5c49475279e063ULL, 0xa25416474f493030ULL, 0x174ad61a1448c899ULL }, // C[57]
    { 0x3a9816d49a38d2efULL, 0xeaaa28c177cc0fa1ULL, 0xf759df4ec2f3cde2ULL, 0x1a96177bcf4d8d89ULL }, // C[58]
    { 0x8242ace360b8a30aULL, 0x05202c126a233c1aULL, 0xd0ef8054bc60c4ffULL, 0x066d04b24331d71cULL }, // C[59]
    { 0x27037a62aa1bd804ULL, 0x381cc65f72e02ad5ULL, 0x2195782871c6dd3bULL, 0x2a4c4fc6ec0b0cf5ULL }, // C[60]
    { 0xe55afc01219fd649ULL, 0x5e727f8446f6d9d7ULL, 0x47e9f2e14a7cedc9ULL, 0x13ab2d136ccf37d4ULL }, // C[61]
    { 0x4c2e3e869acc6a9aULL, 0xc1b04fcec26f5519ULL, 0x19d24d843dc82769ULL, 0x1121552fca260616ULL }, // C[62]
    { 0x09a5546c7c97cff1ULL, 0xa6cd267d595c4a89ULL, 0x889bc81715c37d77ULL, 0x00ef653322b13d6cULL }, // C[63]
    { 0x845aca35d8a397d3ULL, 0x400c776d652595d9ULL, 0x8b261d8ba74051e6ULL, 0x0e25483e45a66520ULL }, // C[64]
    { 0x46448db979eeba89ULL, 0x395ac3d4dde92d8cULL, 0x245264659e15d88eULL, 0x29f536dcb9dd7682ULL }, // C[65]
    { 0x0e456baace0fa5beULL, 0x5a124e2780bbea17ULL, 0xdfda33575dbdbd88ULL, 0x2a56ef9f2c53febaULL }, // C[66]
    { 0xee416240a8cb9af1ULL, 0xf2ae2999a46762e8ULL, 0xecfb7a2d17b5c409ULL, 0x1c8361c78eb5cf5dULL }, // C[67]
    { 0xd3d0ab4be74319c5ULL, 0x83e8e68a764507bfULL, 0xc0473089aaf0206bULL, 0x151aff5f38b20a0fULL }, // C[68]
    { 0xe76e47615b51f100ULL, 0xa9f52fc8c8b6cdd1ULL, 0xc1b239c88f7f9d43ULL, 0x04c6187e41ed881dULL }, // C[69]
    { 0x9e801b7ddc9c2967ULL, 0x4b81c61ed1577644ULL, 0x10d84331f6fb6d53ULL, 0x13b37bd80f4d27fbULL }, // C[70]
    { 0x9321ceb1c4e8a8e4ULL, 0x2ce3664c2a52032cULL, 0xf578bfbd32c17b7aULL, 0x01a5c536273c2d9dULL }, // C[71]
    { 0x832239065b7c3b02ULL, 0x4a9a2c666b9726daULL, 0x5ad05f5d7acb950bULL, 0x2ab3561834ca7383ULL }, // C[72]
    { 0x9f7ed516a597b646ULL, 0xacaf6af4e95d3bf6ULL, 0x200fe6d686c0d613ULL, 0x1d4d8ec291e720dbULL }, // C[73]
    { 0x1514c9c80b65af1dULL, 0xb925351240a04b71ULL, 0x8f5784fe7919fd2bULL, 0x041294d2cc484d22ULL }, // C[74]
    { 0x042971dd90e81fc6ULL, 0x98f57939d126e392ULL, 0x1c4fa715991f0048ULL, 0x154ac98e01708c61ULL }, // C[75]
    { 0x4524563bc6ea4da4ULL, 0x50b3684c88f8b0b0ULL, 0x3eedd84093aef510ULL, 0x0b339d8acca7d4f8ULL }, // C[76]
    { 0x81ed95b50839c82eULL, 0x98f0e71eaff4a7ddULL, 0x54a4f84cfbab3445ULL, 0x0955e49e6610c942ULL }, // C[77]
    { 0x3525401ea0654626ULL, 0xa9a6f41e6f535c6fULL, 0x26b9e22206f15abcULL, 0x06746a6156eba544ULL }, // C[78]
    { 0xac917c7ff32077fbULL, 0x38e5790e2bd0a196ULL, 0x496f3820c549c278ULL, 0x0f18f5a0ecd1423cULL }, // C[79]
    { 0x2a738223d6f76e13ULL, 0x4bb563583ede7bc9ULL, 0x8ac59eff5beb261eULL, 0x04f6eeca1751f730ULL }, // C[80]
    { 0xc1768d26fc0b3758ULL, 0x8811eb116fb3e45bULL, 0xc1a3ec4da3cdce03ULL, 0x2b56973364c4c4f5ULL }, // C[81]
    { 0x83feb65d437f29efULL, 0x8e1392b385716a5dULL, 0xdcd76b89804b1bcbULL, 0x123769dd49d5b054ULL }, // C[82]
    { 0x94257b2fb01c63e9ULL, 0xa989f64464711509ULL, 0x88ee52b91169aaceULL, 0x2147b424fc48c80aULL }, // C[83]
    { 0xea54ad897cebe54dULL, 0x647e6f34ad4243c2ULL, 0x1a6c5505ea332a29ULL, 0x0fdc1f58548b8570ULL }, // C[84]
    { 0x944f685cc0a0b1f2ULL, 0xbceff28c5dbbe0c3ULL, 0xdf68abcf0f7786d4ULL, 0x12373a8251fea004ULL }, // C[85]
    { 0xdd8a1f35c1a90035ULL, 0xa642756b6af44203ULL, 0xad7ea52ff742c9e8ULL, 0x21e4f4ea5f35f85bULL }, // C[86]
    { 0x8a81934f1bc3b147ULL, 0xb57366492f45e90dULL, 0xdfb4722224d4c462ULL, 0x16243916d69d2ca3ULL }, // C[87]
    { 0xa13a4159cac04ac2ULL, 0xabc21566e1a0453cULL, 0xf66f9adbc88b4378ULL, 0x1efbe46dd7a578b4ULL }, // C[88]
    { 0x3b672cc96a88969aULL, 0xd468d5525be66f85ULL, 0x8886020e23a7f387ULL, 0x07ea5e8537cf5dd0ULL }, // C[89]
    { 0xa9fe16c0b76c00bcULL, 0x650f19a75e7ce11cULL, 0xb7b478a30f9a5b63ULL, 0x05a8c4f9968b8aa3ULL }, // C[90]
    { 0x2d9d57b72a32e83fULL, 0x3f7818c701b9c788ULL, 0xfbfe59bd345e8dacULL, 0x20f057712cc21654ULL }, // C[91]
    { 0x9bd90b33eb33db69ULL, 0x6dcd8e88d01d4901ULL, 0x9672f8c67fee3163ULL, 0x04a12ededa9dfd68ULL }, // C[92]
    { 0xe49ec9544ccd101aULL, 0xbd136ce5091a6767ULL, 0xe44f1e5425a51decULL, 0x27e88d8c15f37dceULL }, // C[93]
    { 0x176c41ee433de4d1ULL, 0x6e096619a7703223ULL, 0xb8a5c8c5e95a41f6ULL, 0x2feed17b84285ed9ULL }, // C[94]
    { 0x6972b8bd53aff2b8ULL, 0x94e5942911312a0dULL, 0x404241420f729cf3ULL, 0x1ed7cc76edf45c7cULL }, // C[95]
    { 0xdf2874be45466b1aULL, 0xac6783476144cdcaULL, 0x157ff8c586f5660eULL, 0x15742e99b9bfa323ULL }, // C[96]
    { 0x284f033f27d0c785ULL, 0x77107454c6ec0317ULL, 0xc895fc6887ddf405ULL, 0x1aac285387f65e82ULL }, // C[97]
    { 0xec75a96554d67c77ULL, 0x832e2e7a49775f71ULL, 0xf9ddadbdb6057357ULL, 0x25851c3c845d4790ULL }, // C[98]
    { 0x0ddccc3d9f146a67ULL, 0x53b7ebba2c552337ULL, 0xce78457db197edf3ULL, 0x15a5821565cc2ec2ULL }, // C[99]
    { 0x2f15485f28c71727ULL, 0xdcf64f3604427750ULL, 0x0efa7e31a1db5966ULL, 0x2411d57a4813b998ULL }, // C[100]
    { 0x58828b5ef6cb4c9bULL, 0x47e9a98e12f4cd25ULL, 0x13e335b8c0b6d2e6ULL, 0x002e6f8d6520cd47ULL }, // C[101]
    { 0x398834609e0315d2ULL, 0xaf8f0e91e2fe1ed7ULL, 0x97da00b616b0fcd1ULL, 0x2ff7bc8f4380cde9ULL }, // C[102]
    { 0xe93be4febb0d3cbeULL, 0x2e9521f6b7bb68f1ULL, 0x5ee02724471bcd18ULL, 0x00b9831b94852559ULL }, // C[103]
    { 0x7d77adbf0c9c3512ULL, 0x1ca408648a4743a8ULL, 0x86913b0e57c04e01ULL, 0x0a2f53768b8ebf6aULL }, // C[104]
    { 0x7f2a290305e1198dULL, 0x0f599ff7e94be69bULL, 0x3a479f91ff239e96ULL, 0x00248156142fd037ULL }, // C[105]
    { 0x50eb512a2b2bcda9ULL, 0x397196aa6a542c23ULL, 0x28cf8c02ab3f0c9aULL, 0x171d5620b87bfb13ULL }, // C[106]
    { 0x9d1045e4ec34a808ULL, 0x60c952172dd54dd9ULL, 0x70087c7c10d6fad7ULL, 0x170a4f55536f7dc9ULL }, // C[107]
    { 0x482eca17e2dbfae1ULL, 0xcc37e38c1cd211baULL, 0x2ef3134aea04336eULL, 0x29aba33f799fe66cULL }, // C[108]
    { 0xb5ba650369e64973ULL, 0xe70d114a03f6a0e8ULL, 0xfdd1bb1945088d47ULL, 0x1e9bc179a4fdd758ULL }, // C[109]
    { 0x9c9e1c43bdaf8f09ULL, 0xfeaad869a9c4b44fULL, 0x58f7f4892dfb0b5aULL, 0x1dd269799b660fadULL }, // C[110]
    { 0x5d1dd2cb0f24af38ULL, 0x7ccd426fe869c7c9ULL, 0x401181d02e15459eULL, 0x22cdbc8b70117ad1ULL }, // C[111]
    { 0xd5ba93b9c7dacefdULL, 0xfd3150f52ed94a7cULL, 0x3a9f57a55c503fceULL, 0x0ef042e454771c53ULL }, // C[112]
    { 0x3b304ffca62e8284ULL, 0x1318e8b08a0359a0ULL, 0xf287f3036037e885ULL, 0x11609e06ad6c8fe2ULL }, // C[113]
    { 0x08b08f5b783aa9afULL, 0xfecd58c076dfe427ULL, 0x9e753eea427c17b7ULL, 0x1166d9e554616dbaULL }, // C[114]
    { 0xf855a888357ee466ULL, 0x177fbf4cd2ac0b56ULL, 0x93413026354413dbULL, 0x2de52989431a8595ULL }, // C[115]
    { 0x74bf01cf5f71e9adULL, 0xf51aee5b17b8e89dULL, 0x9a6da492f3a8ac1dULL, 0x3006eb4ffc7a8581ULL }, // C[116]
    { 0x62344c8225145086ULL, 0x2993fe8f0a4639f9ULL, 0xfdcf6fff9e3f6f42ULL, 0x2af41fbb61ba8a80ULL }, // C[117]
    { 0x81b214bace4827c3ULL, 0x8718ab27889e85e7ULL, 0xe5a6b41a8ebc85dbULL, 0x119e684de476155fULL }, // C[118]
    { 0xcff784b97b3fd800ULL, 0xb51248c23828f047ULL, 0x188bea59ae363537ULL, 0x1835b786e2e8925eULL }, // C[119]
    { 0x6c40e285ab32eeb6ULL, 0xd152bac2a7905c92ULL, 0x4d794996c6433a20ULL, 0x28201a34c594dfa3ULL }, // C[120]
    { 0x4a761f88c22cc4e7ULL, 0x864c82eb57118772ULL, 0x94e80fefaf78b000ULL, 0x083efd7a27d17510ULL }, // C[121]
    { 0x9e079564f61fd13bULL, 0x11c16df7774dd851ULL, 0x6158e61ceea27be8ULL, 0x0b6f88a357719952ULL }, // C[122]
    { 0x14390e6ee4254f5bULL, 0x589511ca00d29e10ULL, 0x644f66e1d6471a94ULL, 0x0ec868e6d15e51d9ULL }, // C[123]
    { 0x00d937ab84c98591ULL, 0xecd3e74b939cd40dULL, 0x1ac0c9b3ed2e1142ULL, 0x2af33e3f86677127ULL }, // C[124]
    { 0x364ce5e47951f178ULL, 0x34568c547dd6858bULL, 0xd09b5d961c6ace77ULL, 0x0b520211f904b5e7ULL }, // C[125]
    { 0xca228620188a1d40ULL, 0xa0c56ac4270e822cULL, 0xd8db58f10062a92eULL, 0x0b2d722d0919a1aaULL }, // C[126]
    { 0xe0061d1ed6e562d4ULL, 0x57b54a9991ca38bbULL, 0xd980ceb37c2453e9ULL, 0x1f790d4d7f8cf094ULL }, // C[127]
    { 0xda92ceb01e504233ULL, 0x0885c16235a2a6a8ULL, 0xaea97cd385f78015ULL, 0x0171eb95dfbf7d1eULL }, // C[128]
    { 0x762305381b168873ULL, 0x790b40defd2c8650ULL, 0x329bf6885da66b9bULL, 0x0c2d0e3b5fd57549ULL }, // C[129]
    { 0x5d3803054407a18dULL, 0x7cbcafa589e283c3ULL, 0x4e5a8228b4e72b37ULL, 0x1162fb28689c2715ULL }, // C[130]
    { 0x1623ef8249711bc0ULL, 0x282c5a92a89e1992ULL, 0x64ad386a91e8310fULL, 0x2f1459b65dee441bULL }, // C[131]
    { 0xc243f70d1b53cfbbULL, 0xbc489d46754eb712ULL, 0x996d74367d5cd4c1ULL, 0x1e6ff3216b688c3dULL }, // C[132]
    { 0x76881f9326478875ULL, 0xd741a6f36cdc2a05ULL, 0x681487d27d157802ULL, 0x01ca8be73832b8d0ULL }, // C[133]
    { 0x0b9b5de315f9650eULL, 0x680286080b10cea0ULL, 0x86f976d5bdf223dcULL, 0x1f7735706ffe9fc5ULL }, // C[134]
    { 0x4745ca838285f019ULL, 0x21ac10a3d5f096efULL, 0x40a0c2dce041fba9ULL, 0x2522b60f4ea33076ULL }, // C[135]
    { 0x8ce16c235572575bULL, 0x3418cad4f52b6c3fULL, 0x5255075ddc957f83ULL, 0x23f0bee001b1029dULL }, // C[136]
    { 0x66d9401093082d59ULL, 0x5d142633e9df905fULL, 0xcaac2d44555ed568ULL, 0x2bc1ae8b8ddbb81fULL }, // C[137]
    { 0x8011fcd6ad72205fULL, 0x62371273a07b1fc9ULL, 0x7304507b8dba3ed1ULL, 0x0f9406b8296564a3ULL }, // C[138]
    { 0xcb126c8cd995f0a8ULL, 0x17e75b174a52ee4aULL, 0x67b72998de90714eULL, 0x2360a8eb0cc7defaULL }, // C[139]
    { 0x6dcbbc2767f88948ULL, 0xb4815a5e96df8b00ULL, 0x804c803cbaef255eULL, 0x15871a5cddead976ULL }, // C[140]
    { 0x4f957ccdeefb420fULL, 0x362f4f54f7237954ULL, 0x0a8652dd2f3b1da0ULL, 0x193a56766998ee9eULL }, // C[141]
    { 0xe4309805e777ae0fULL, 0x3b2e63c8ad334834ULL, 0x2f9be56ff4fab170ULL, 0x2a394a43934f8698ULL }, // C[142]
    { 0xb4166e8876c0d142ULL, 0x892cd11223443ba7ULL, 0x3e8b635dcb345192ULL, 0x1859954cfeb8695fULL }, // C[143]
    { 0x408d3819f4fed32bULL, 0x2b11bc25d90bbdcaULL, 0x013444dbcb99f190ULL, 0x04e1181763050e58ULL }, // C[144]
    { 0x1f5e5552bfd05f23ULL, 0xb10eb82db08b5e8bULL, 0x40c335ea64de8c5bULL, 0x0fdb253dee83869dULL }, // C[145]
    { 0xa9d7c5bae9b4f1c0ULL, 0x75f08686f1c08984ULL, 0xaa4efb623adead62ULL, 0x058cbe8a9a5027bdULL }, // C[146]
    { 0xd15228b4cceca59aULL, 0x23b4b83bef023ab0ULL, 0x497eadb1aeb1f52bULL, 0x1382edce9971e186ULL }, // C[147]
    { 0xe1e6634601d9e8b5ULL, 0x7f61b8eb99f14b77ULL, 0x0819ca51fd11b0beULL, 0x03464990f045c6eeULL }, // C[148]
    { 0xaa5bc137aeb70a58ULL, 0x6fcab4605db2eb5aULL, 0xfff33b41f98ff83cULL, 0x23f7bfc8720dc296ULL }, // C[149]
    { 0x19636158bbaf62f2ULL, 0x18c3ffd5e1531a92ULL, 0x7e6e94e7f0e9decfULL, 0x0a59a158e3eec211ULL }, // C[150]
    { 0xf4c23ed0075fd07bULL, 0xe2c4eba065420af8ULL, 0xb58bf23b312ffd3cULL, 0x06ec54c80381c052ULL }, // C[151]
    { 0x962f0ff9ed1f9d01ULL, 0xb09340f7a7bcb1b4ULL, 0x476b56648e867ec8ULL, 0x118872dc832e0eb5ULL }, // C[152]
    { 0x95e1906b520921b1ULL, 0x52e0b0f0e42d7feaULL, 0x5ad5c7cba7ad59edULL, 0x13d69fa127d83416ULL }, // C[153]
    { 0xfd8a49f19f10c77bULL, 0xde143942fb71dc55ULL, 0x70b1c6877a73d21bULL, 0x169a177f63ea6812ULL }, // C[154]
    { 0xfb7e9a5a7450544dULL, 0x3abeb032b922f66fULL, 0xef42f287adce40d9ULL, 0x04ef51591c6ead97ULL }, // C[155]
    { 0xd5f45ee6dd0f69ecULL, 0x19ec61805d4f03ceULL, 0x0ecd7ca703fb2e3bULL, 0x256e175a1dc07939ULL }, // C[156]
    { 0xa002813d3e2ceeb2ULL, 0x75cc360d3205dd2dULL, 0xe5f2af412ff6004fULL, 0x30102d28636abd5fULL }, // C[157]
    { 0x1fd31be182fcc792ULL, 0x0443a3fa99bef4a3ULL, 0x1c0714bc73eb1bf4ULL, 0x10998e42dfcd3bbfULL }, // C[158]
    { 0xecad76f879e36860ULL, 0x9f3362eaf4d582efULL, 0x25fa7d24b598a1d8ULL, 0x193edd8e9fcf3d76ULL }, // C[159]
    { 0xf2664d7aa51f0b5dULL, 0xd1c7a561ce611425ULL, 0xd0368ce80b7b3347ULL, 0x18168afd34f2d915ULL }, // C[160]
    { 0x29e2e95b33ea6111ULL, 0xa328ec77bc33626eULL, 0x0c017656ebe658b6ULL, 0x29383c01ebd3b6abULL }, // C[161]
    { 0x00bf573f9010c711ULL, 0x702db6e86fb76ab6ULL, 0xa1f4ae5e7771a64aULL, 0x10646d2f2603de39ULL }, // C[162]
    { 0x64d0242dcb1117fbULL, 0x2f90c25b40da7b38ULL, 0xf575f1395a55bf13ULL, 0x0beb5e07d1b27145ULL }, // C[163]
    { 0xdffbf018d96fa336ULL, 0x30f95bb2e54b59abULL, 0xdc0d3ecad62b5c88ULL, 0x16d685252078c133ULL }, // C[164]
    { 0xfd672dd62047f01aULL, 0x0a555bbbec21ddfaULL, 0x3c74154e0404b4b4ULL, 0x0a6abd1d833938f3ULL }, // C[165]
    { 0x70a6f19b34cf1860ULL, 0xb12dffeec4503172ULL, 0x8ea12a4c2dedc8feULL, 0x1a679f5d36eb7b5cULL }, // C[166]
    { 0xfbc7592e3f1b93d6ULL, 0x26a423eada4e8f6fULL, 0x3974d50e0ebfde47ULL, 0x0980fb233bd456c2ULL }, // C[167]
    { 0x03ebacb5c312c72bULL, 0xcece3d5628c92820ULL, 0xbf1810af93a38fc0ULL, 0x161b42232e61b84cULL }, // C[168]
    { 0xd09203db47de1a0bULL, 0x493f09787f1564e5ULL, 0x950f7d47a60d5e6aULL, 0x0ada10a90c7f0520ULL }, // C[169]
    { 0xb50ddb9af407f451ULL, 0xd3f07a8a2b4e121bULL, 0x320345a29ac4238eULL, 0x1a730d372310ba82ULL }, // C[170]
    { 0xfbda10ef58e8c556ULL, 0x908377feaba5c4dfULL, 0x817064c369dda7eaULL, 0x2c8120f268ef054fULL }, // C[171]
    { 0x6e7b8649a4968f70ULL, 0xb930e95313bcb73eULL, 0xa57c00789c684217ULL, 0x1c7c8824f758753fULL }, // C[172]
    { 0xb47b27fa3fd1cf77ULL, 0xf400ad8b491eb3f7ULL, 0x8e39e4077a74faa0ULL, 0x2cd9ed31f5f8691cULL }, // C[173]
    { 0x854ae23918a22eeaULL, 0xa5e022ac321ca550ULL, 0xcf60d92f57618399ULL, 0x23ff4f9d46813457ULL }, // C[174]
    { 0xdff1ea58f180426dULL, 0xaf5a2c5103529407ULL, 0xceece6405dddd9d0ULL, 0x09945a5d147a4f66ULL }, // C[175]
    { 0x8a6dd223ec6fc630ULL, 0x7c7da6eaa29d3f26ULL, 0xb67660c6b771b90fULL, 0x188d9c528025d4c2ULL }, // C[176]
    { 0xe0c0d8ddf4f0f47fULL, 0xdba7d926d3633595ULL, 0x81f68311431d8734ULL, 0x3050e37996596b7fULL }, // C[177]
    { 0x9d829518d30afd78ULL, 0x6ceae5461e3f95d8ULL, 0x1600ca8102c35c42ULL, 0x15af1169396830a9ULL }, // C[178]
    { 0x04284da3320d8accULL, 0xdae933e351466b29ULL, 0xa06d9f37f873d985ULL, 0x1da6d09885432ea9ULL }, // C[179]
    { 0xe546ee411ddaa9cbULL, 0x4e4fad3dbe658945ULL, 0xf5f8acf33921124eULL, 0x2796ea90d269af29ULL }, // C[180]
    { 0x7cb0319e01d32d60ULL, 0x1e15612ec8e9304aULL, 0x0325c8b3307742f0ULL, 0x202d7dd1da0f6b4bULL }, // C[181]
    { 0xa29dace4c0f8be5fULL, 0xa2d7f9c788f4c831ULL, 0x156a952ba263d672ULL, 0x096d6790d05bb759ULL }, // C[182]
    { 0x63798cb1447d25a4ULL, 0x438da23ce5b13e19ULL, 0x83808965275d877bULL, 0x054efa1f65b0fce2ULL }, // C[183]
    { 0x64ccf6e18e4165f1ULL, 0xd8aa690113b2e148ULL, 0xdb3308c29802deb9ULL, 0x1b162f83d917e93eULL }, // C[184]
    { 0xc5ceb745a0506edcULL, 0xedfefc1466cc568eULL, 0xfd9f1cdd2a0de39eULL, 0x21e5241e12564dd6ULL }, // C[185]
    { 0x7b4349e10e4bdf08ULL, 0xcb73ab5f87e16192ULL, 0x226a80ee17b36abeULL, 0x1cfb5662e8cf5ac9ULL }, // C[186]
    { 0x29c53f666eb24100ULL, 0x2c99af346220ac01ULL, 0xbae6d8d1ecb373b6ULL, 0x0f21177e302a771bULL }, // C[187]
    { 0xbcef7e1f515c2320ULL, 0xc4236aede6290546ULL, 0xaffb0dd7f71b12beULL, 0x1671522374606992ULL }, // C[188]
    { 0xd419d2a692cad870ULL, 0xbe2ec9e42c5cc8ccULL, 0x2eb4cf24501bfad9ULL, 0x0fa3ec5b9488259cULL }, // C[189]
    { 0x85e8c57b1ab54bbaULL, 0xd36edce85c648cc0ULL, 0x57cb266c1506080eULL, 0x193c0e04e0bd2983ULL }, // C[190]
    { 0xce14ea2adaba68f8ULL, 0x9f6f7291cd406578ULL, 0x7e9128306dcbc3c9ULL, 0x102adf8ef74735a2ULL }, // C[191]
    { 0x40a6d0cb70c3eab1ULL, 0x316aa24bfbdd23aeULL, 0xe2a54d6f1ad945b1ULL, 0x0fe0af7858e49859ULL }, // C[192]
    { 0xe8a5ea7344798d22ULL, 0x2da5f1daa9ebdefdULL, 0x08536a2220843f4eULL, 0x216f6717bbc7dedbULL }, // C[193]
    { 0xf88e2e4228325161ULL, 0x3c23b2ac773c6b3eULL, 0x4a3e694391918a1bULL, 0x1da55cc900f0d21fULL }, // C[194]
};

// 3x3 MDS matrix M for t = 3. Indexed [row][col][limb].
// state' = M * state in Fr, applied at the end of every round
// (full and partial alike, in this unoptimized variant).
static constexpr uint64_t POSEIDON_BN254_MDS[3][3][4] = {
    { { 0xfedb68592ba8118bULL, 0x94be7c11ad24378bULL, 0xb2b70caf5c36a7b1ULL, 0x109b7f411ba0e4c9ULL }, { 0xd6c64543dc4903e0ULL, 0x9314dc9fdbdeea55ULL, 0x6ae119424fddbcbcULL, 0x16ed41e13bb9c0c6ULL }, { 0x791a93b74e36736dULL, 0xf706ab640ceb247bULL, 0xf617e7dcbfe82e0dULL, 0x2b90bba00fca0589ULL } }, // M[0]
    { { 0xd62940bcde0bd771ULL, 0x2cc8fdd1415c3ddeULL, 0xb9c36c764379dbcaULL, 0x2969f27eed31a480ULL }, { 0x29b2311687b1fe23ULL, 0xb89d743c8c7b9640ULL, 0x4c9871c832963dc1ULL, 0x2e2419f9ec02ec39ULL }, { 0xc8aacc55a0f89bfaULL, 0x148d4e109f5fb065ULL, 0x97315876690f053dULL, 0x101071f0032379b6ULL } }, // M[1]
    { { 0x326244ee65a1b1a7ULL, 0xe6cd79e28c5b3753ULL, 0x0d5f9e654638065cULL, 0x143021ec686a3f33ULL }, { 0xb16cdfabc8ee2911ULL, 0xd057e12e58e7d7b6ULL, 0x82a70eff08a6fd99ULL, 0x176cc029695ad025ULL }, { 0x73279cd71d25d5e0ULL, 0xa644470307043f77ULL, 0x17ba7fee3802593fULL, 0x19a3fc0a56702bf4ULL } }, // M[2]
};

} // namespace poseidon_bn254_detail
} // namespace crypto

#endif // NEURAI_CRYPTO_POSEIDON_BN254_CONSTANTS_H
