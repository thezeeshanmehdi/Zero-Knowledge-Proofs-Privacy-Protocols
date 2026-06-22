import hashlib

# Standard placeholder for empty leaves in the Merkle Tree
EMPTY_HASH = hashlib.sha256(b"empty_leaf_placeholder").hexdigest()

def hash_data(data: str) -> str:
    """Computes the SHA-256 hash of a string data value."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def hash_pair(left: str, right: str) -> str:
    """Concatenates and hashes two hex strings (parent node calculation)."""
    return hashlib.sha256((left + right).encode('utf-8')).hexdigest()

class MerkleTree:
    """
    A Merkle Tree implementation of fixed depth (default 4, representing 16 leaves)
    which simulates a simple deposit anonymity pool.
    """
    def __init__(self, depth: int = 4):
        self.depth = depth
        self.capacity = 2 ** depth
        # Populate leaves with empty placeholder hashes
        self.leaves = [EMPTY_HASH] * self.capacity
        # Store layers: tree[0] is leaves, tree[depth] is the root
        self.tree = [[] for _ in range(self.depth + 1)]
        self.rebuild()

    def rebuild(self):
        """Rebuilds the tree layers from bottom to top."""
        self.tree[0] = list(self.leaves)
        for d in range(self.depth):
            level = []
            for i in range(0, len(self.tree[d]), 2):
                left = self.tree[d][i]
                right = self.tree[d][i+1]
                level.append(hash_pair(left, right))
            self.tree[d+1] = level

    def insert(self, coin: str) -> int:
        """
        Inserts a coin (unique string) into the Merkle Tree at the first empty slot.
        Returns the leaf index where it was inserted.
        """
        leaf_hash = hash_data(coin)
        try:
            # Find first index filled with the empty placeholder hash
            idx = self.leaves.index(EMPTY_HASH)
        except ValueError:
            raise ValueError("Merkle Tree is full! Cannot add more deposits.")
        
        self.leaves[idx] = leaf_hash
        self.rebuild()
        return idx

    def get_root(self) -> str:
        """Returns the Merkle root hash of the tree."""
        return self.tree[self.depth][0]

    def generateProof(self, leafIndex: int) -> list:
        """
        Generates the Merkle proof (path of sibling hashes) for the leaf at leafIndex.
        Each element in the proof path is a dict: {'hash': sibling_hash, 'is_left': bool}
        representing whether the sibling is a left or right child.
        """
        if leafIndex < 0 or leafIndex >= self.capacity:
            raise IndexError("Leaf index out of bounds")
        
        proof = []
        curr_idx = leafIndex
        for d in range(self.depth):
            # Sibling index calculation:
            # If current index is even, sibling is next (odd). If odd, sibling is previous (even).
            sibling_idx = curr_idx + 1 if curr_idx % 2 == 0 else curr_idx - 1
            sibling_hash = self.tree[d][sibling_idx]
            is_left = (sibling_idx % 2 == 0)
            
            proof.append({
                'hash': sibling_hash,
                'is_left': is_left
            })
            curr_idx = curr_idx // 2
        return proof

def verifyProof(leaf: str, proof: list, root: str) -> bool:
    """
    Verifies that the provided 'leaf' (raw coin string) is part of the Merkle Tree
    matching the given 'root' using the cryptographic sibling 'proof' path.
    This function verifies the proof WITHOUT requiring the leafIndex.
    """
    # Start by hashing the leaf node
    curr_hash = hash_data(leaf)
    
    # Climb up the tree using the sibling hashes in the proof path
    for step in proof:
        sibling = step['hash']
        is_left = step['is_left']
        
        if is_left:
            # Sibling is on the left
            curr_hash = hash_pair(sibling, curr_hash)
        else:
            # Sibling is on the right
            curr_hash = hash_pair(curr_hash, sibling)
            
    return curr_hash == root
