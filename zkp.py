import hashlib
import secrets

def hash_data(data: str) -> str:
    """Computes SHA-256 hash of a string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

class PINProver:
    """
    Represents the honest prover who knows the secret 4-digit PIN.
    The prover commits to values in a way that allows them to satisfy
    random binary challenges (0 or 1) without revealing the PIN.
    """
    def __init__(self, pin: int):
        if not (0 <= pin <= 9999):
            raise ValueError("PIN must be a 4-digit number (0-9999).")
        self.pin = pin

    def commit(self):
        """
        Commitment Phase for one iteration:
        1. Choose a random 16-bit blinding factor (mask) r.
        2. Generate two random salts.
        3. Compute commitment C0 = Hash(r || salt_0).
        4. Compute commitment C1 = Hash((PIN ^ r) || salt_1).
        
        Returns:
            commitments: (C0, C1)
            salts: (salt_0, salt_1)
            state: dictionary storing the private witnesses (r, PIN ^ r) to be opened later
        """
        # Generate a random masking value
        r = secrets.randbelow(65536)  # 16-bit random integer
        s_val = self.pin ^ r          # XORed value acting as a one-time pad
        
        # Generate cryptographically secure salts to prevent brute forcing
        salt_0 = secrets.token_hex(8)
        salt_1 = secrets.token_hex(8)
        
        # Commitments
        c0 = hash_data(f"{r}:{salt_0}")
        c1 = hash_data(f"{s_val}:{salt_1}")
        
        state = {
            'r': r,
            's_val': s_val,
            'salt_0': salt_0,
            'salt_1': salt_1
        }
        
        return (c0, c1), (salt_0, salt_1), state

    def respond(self, challenge: int, state: dict):
        """
        Response Phase:
        - If challenge is 0: Open commitment C0 by revealing the blinding factor r.
        - If challenge is 1: Open commitment C1 by revealing the masked value (PIN ^ r).
        """
        if challenge == 0:
            return {
                'value': state['r'],
                'salt': state['salt_0']
            }
        elif challenge == 1:
            return {
                'value': state['s_val'],
                'salt': state['salt_1']
            }
        else:
            raise ValueError("Challenge must be 0 or 1.")


class CheatingProver:
    """
    Represents a cheating prover who does NOT know the PIN.
    They try to cheat by guessing the challenge (0 or 1) in advance.
    """
    def __init__(self):
        pass

    def commit(self):
        """
        Commitment Phase for a cheater:
        The cheater must predict the challenge:
        - If they guess 0: They commit to a valid random value for C0, and use a dummy for C1.
        - If they guess 1: They commit to a valid random value for C1, and use a dummy for C0.
        """
        predicted_challenge = secrets.randbelow(2)
        salt_0 = secrets.token_hex(8)
        salt_1 = secrets.token_hex(8)
        
        r_or_s = secrets.randbelow(65536)
        
        if predicted_challenge == 0:
            # Commit to a real value on C0, dummy on C1
            c0 = hash_data(f"{r_or_s}:{salt_0}")
            c1 = hash_data("dummy_cheater_hash_1")
            state = {
                'r': r_or_s,
                's_val': 99999,  # Invalid dummy value
                'salt_0': salt_0,
                'salt_1': salt_1,
                'predicted_challenge': 0
            }
        else:
            # Commit to a real value on C1, dummy on C0
            c0 = hash_data("dummy_cheater_hash_0")
            c1 = hash_data(f"{r_or_s}:{salt_1}")
            state = {
                'r': 99999,      # Invalid dummy value
                's_val': r_or_s,
                'salt_0': salt_0,
                'salt_1': salt_1,
                'predicted_challenge': 1
            }
            
        return (c0, c1), (salt_0, salt_1), state

    def respond(self, challenge: int, state: dict):
        """
        Response Phase for a cheater:
        They return their pre-committed value.
        """
        if challenge == 0:
            return {
                'value': state['r'],
                'salt': state['salt_0']
            }
        elif challenge == 1:
            return {
                'value': state['s_val'],
                'salt': state['salt_1']
            }
        else:
            raise ValueError("Challenge must be 0 or 1.")


class PINVerifier:
    """
    Represents the Verifier who validates the Prover's responses.
    The Verifier knows the correct PIN and validates that:
    1. The opened value matches the corresponding commitment.
    2. The relation between commitments matches the secret PIN (for challenge 1,
       they reconstruct r = s_val ^ PIN and verify it hashes to C0).
    """
    def __init__(self, pin: int):
        self.pin = pin
        self.pin_hash = hash_data(str(pin))

    def verify(self, commitments: tuple, salts: tuple, challenge: int, response: dict) -> bool:
        """
        Verification Phase:
        - If challenge is 0: Verifier receives the blinding factor r.
          Checks that Hash(r || salt_0) == C0.
        - If challenge is 1: Verifier receives the masked value s_val = (PIN ^ r).
          Checks that:
            1. Hash(s_val || salt_1) == C1.
            2. Reconstructed blinding factor r = s_val ^ PIN hashes to C0: Hash(r || salt_0) == C0.
        """
        c0, c1 = commitments
        salt_0, salt_1 = salts
        val = response['value']
        salt = response['salt']
        
        if challenge == 0:
            # Check C0 opening
            expected_c0 = hash_data(f"{val}:{salt_0}")
            return expected_c0 == c0
        elif challenge == 1:
            # Check C1 opening
            expected_c1 = hash_data(f"{val}:{salt_1}")
            if expected_c1 != c1:
                return False
            
            # Reconstruct the blinding factor r using the known PIN
            reconstructed_r = val ^ self.pin
            # Verify reconstructed r matches commitment C0
            expected_c0 = hash_data(f"{reconstructed_r}:{salt_0}")
            return expected_c0 == c0
        return False

def run_protocol_simulation(pin: int, iterations: int = 100, cheat: bool = False):
    """
    Simulates the ZKP protocol for a specified number of iterations.
    Can run with either an honest prover or a cheating prover.
    Returns:
        results: list of dicts detailing each step
        success: bool indicating if all iterations passed
        success_rate: float
    """
    verifier = PINVerifier(pin)
    prover = PINProver(pin) if not cheat else CheatingProver()
    
    results = []
    all_passed = True
    
    for i in range(iterations):
        # 1. Commit
        commitments, salts, state = prover.commit()
        
        # 2. Challenge
        challenge = secrets.randbelow(2)
        
        # 3. Respond
        response = prover.respond(challenge, state)
        
        # 4. Verify
        passed = verifier.verify(commitments, salts, challenge, response)
        if not passed:
            all_passed = False
            
        results.append({
            'iteration': i + 1,
            'commitments': commitments,
            'challenge': challenge,
            'response': response,
            'verified': passed
        })
        
    passed_count = sum(1 for r in results if r['verified'])
    success_rate = (passed_count / iterations) * 100
    
    return results, all_passed, success_rate
