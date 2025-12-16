#!/usr/bin/env python3
"""
Example: Using depinpoolpkey RPC for DePIN Pool Node Identity

This script demonstrates how to:
1. Retrieve the pool public key
2. Verify node identity
3. Sign and verify messages with the pool key
4. Register node in a distributed pool
"""

import json
import sys
import subprocess
from typing import Dict, Optional


class NeuraiRPC:
    """Simple Neurai RPC client"""
    
    def __init__(self, cli_path="neurai-cli", testnet=False):
        self.cli_path = cli_path
        self.testnet = testnet
    
    def call(self, method: str, *params) -> Dict:
        """Call RPC method"""
        cmd = [self.cli_path]
        if self.testnet:
            cmd.append("-testnet")
        cmd.append(method)
        cmd.extend(str(p) for p in params)
        
        try:
            result = subprocess.check_output(cmd, stderr=subprocess.PIPE)
            return json.loads(result)
        except subprocess.CalledProcessError as e:
            print(f"RPC Error: {e.stderr.decode()}", file=sys.stderr)
            sys.exit(1)
    
    def depinpoolpkey(self) -> Dict:
        """Get DePIN pool public key"""
        return self.call("depinpoolpkey")
    
    def signmessage(self, address: str, message: str) -> str:
        """Sign message with address"""
        return self.call("signmessage", address, message)
    
    def verifymessage(self, address: str, signature: str, message: str) -> bool:
        """Verify message signature"""
        return self.call("verifymessage", address, signature, message)


def get_pool_identity(rpc: NeuraiRPC) -> Dict:
    """
    Retrieve pool node identity
    
    Returns:
        dict: Pool identity with pubkey, address, and path
    """
    print("🔑 Retrieving DePIN pool identity...")
    identity = rpc.depinpoolpkey()
    
    print(f"✅ Pool Identity Retrieved:")
    print(f"   Public Key: {identity['pubkey']}")
    print(f"   Address:    {identity['address']}")
    print(f"   Path:       {identity['path']}")
    print()
    
    return identity


def sign_pool_message(rpc: NeuraiRPC, address: str, message: str) -> str:
    """
    Sign a message with the pool address
    
    Args:
        rpc: RPC client
        address: Pool address
        message: Message to sign
    
    Returns:
        str: Base64 signature
    """
    print(f"✍️  Signing message with pool address...")
    print(f"   Message: {message}")
    
    signature = rpc.signmessage(address, message)
    
    print(f"✅ Signature: {signature}")
    print()
    
    return signature


def verify_pool_message(rpc: NeuraiRPC, address: str, signature: str, message: str) -> bool:
    """
    Verify a message signature
    
    Args:
        rpc: RPC client
        address: Pool address
        signature: Base64 signature
        message: Original message
    
    Returns:
        bool: True if signature is valid
    """
    print(f"🔍 Verifying message signature...")
    
    is_valid = rpc.verifymessage(address, signature, message)
    
    if is_valid:
        print(f"✅ Signature is VALID")
    else:
        print(f"❌ Signature is INVALID")
    
    print()
    return is_valid


def register_node_to_pool(identity: Dict, pool_api_url: Optional[str] = None) -> None:
    """
    Register node identity to a distributed pool
    
    Args:
        identity: Pool identity dict
        pool_api_url: Optional pool API URL for registration
    """
    print("📡 Node Registration Information:")
    print(json.dumps({
        "pubkey": identity["pubkey"],
        "address": identity["address"],
        "derivation_path": identity["path"],
        "timestamp": "2025-12-15T00:00:00Z"
    }, indent=2))
    print()
    
    if pool_api_url:
        print(f"⚠️  Pool API registration not implemented")
        print(f"   Would POST to: {pool_api_url}/register")
    else:
        print("💡 TIP: Use this identity to register with your pool coordinator")


def compare_keys(testnet_identity: Dict, mainnet_identity: Dict) -> None:
    """
    Compare testnet and mainnet keys (for educational purposes)
    
    Args:
        testnet_identity: Testnet pool identity
        mainnet_identity: Mainnet pool identity
    """
    print("🔬 Network Comparison:")
    print()
    print("Testnet:")
    print(f"  Path:    {testnet_identity['path']}")
    print(f"  Address: {testnet_identity['address']}")
    print()
    print("Mainnet:")
    print(f"  Path:    {mainnet_identity['path']}")
    print(f"  Address: {mainnet_identity['address']}")
    print()
    
    if testnet_identity['pubkey'] == mainnet_identity['pubkey']:
        print("⚠️  WARNING: Same public key on both networks (using same seed)")
    else:
        print("✅ Different public keys (correct network isolation)")
    print()


def main():
    """Main example workflow"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DePIN Pool Key Example")
    parser.add_argument("--testnet", action="store_true", help="Use testnet")
    parser.add_argument("--compare", action="store_true", 
                       help="Compare mainnet and testnet keys")
    parser.add_argument("--sign", type=str, 
                       help="Sign a message with pool key")
    parser.add_argument("--pool-api", type=str, 
                       help="Pool API URL for registration")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("DePIN Pool Public Key - Example Usage")
    print("=" * 60)
    print()
    
    # Initialize RPC
    rpc = NeuraiRPC(testnet=args.testnet)
    
    # Get pool identity
    identity = get_pool_identity(rpc)
    
    # Sign message if requested
    if args.sign:
        signature = sign_pool_message(rpc, identity['address'], args.sign)
        verify_pool_message(rpc, identity['address'], signature, args.sign)
    
    # Register to pool if API provided
    if args.pool_api:
        register_node_to_pool(identity, args.pool_api)
    else:
        register_node_to_pool(identity)
    
    # Compare networks if requested
    if args.compare:
        print("Retrieving mainnet key for comparison...")
        mainnet_rpc = NeuraiRPC(testnet=False)
        mainnet_identity = mainnet_rpc.depinpoolpkey()
        
        print("Retrieving testnet key for comparison...")
        testnet_rpc = NeuraiRPC(testnet=True)
        testnet_identity = testnet_rpc.depinpoolpkey()
        
        compare_keys(testnet_identity, mainnet_identity)
    
    print("=" * 60)
    print("✅ Example completed successfully")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
