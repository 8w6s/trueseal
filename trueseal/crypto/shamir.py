import secrets
import itertools

class Shamir:
    """Shamir's Secret Sharing (SSS) implementation"""
    
    # Standard 256-bit prime (e.g., closest prime to 2^256 used in some crypto operations)
    PRIME = 2**256 - 189
    MAX_BYTE_LENGTH = 32  # Safe for AES-256 / ChaCha20 keys

    def __init__(self, secret, parts, threshold):
        if parts < threshold or threshold < 2:
            raise ValueError(f"Invalid: parts={parts}, threshold={threshold}")
        
        if isinstance(secret, bytes):
            if len(secret) > self.MAX_BYTE_LENGTH:
                raise ValueError(f"Secret too large. Max {self.MAX_BYTE_LENGTH} bytes for this prime.")
            self.secret_len = len(secret)
            self.secret = int.from_bytes(secret, 'big')
        elif isinstance(secret, int):
            self.secret_len = (secret.bit_length() + 7) // 8
            self.secret = secret
        else:
            raise TypeError("Secret must be bytes or int")
            
        self.parts = parts
        self.threshold = threshold
        self.coeffs = []
    
    def split(self):
        """Generate shares"""
        coeffs = [self.secret] + [secrets.randbelow(self.PRIME) for _ in range(self.threshold - 1)]
        shares = []
        used_x = set()
        while len(shares) < self.parts:
            x = secrets.randbelow(self.PRIME - 1) + 1 # Random X from 1 to PRIME-1
            if x in used_x:
                continue
            used_x.add(x)
            y = self._eval_poly(x, coeffs)
            shares.append({
                'x': x, 
                'y': y, 
                'threshold': self.threshold, 
                'total': self.parts,
                'len': self.secret_len
            })
        return shares
    
    @staticmethod
    def combine(shares, expected_len=None):
        """Reconstruct secret"""
        if not shares:
            raise ValueError("No shares provided")
            
        x_coords = [s['x'] for s in shares]
        if len(x_coords) != len(set(x_coords)):
            raise ValueError("Duplicate shares detected. All x-coordinates must be unique.")
            
        threshold = shares[0].get('threshold', len(shares))
        if len(shares) < threshold:
            raise ValueError(f"Need at least {threshold} unique shares, got {len(shares)}")
        
        secret_len = shares[0].get('len', expected_len)
        if secret_len is None:
            raise ValueError("Cannot determine original byte length of the secret.")
        
        prime = Shamir.PRIME
        
        # Try different combinations of shares to handle corrupted shares.
        for active_shares in itertools.combinations(shares, threshold):
            result_int = 0
            for share in active_shares:
                lagrange = Shamir._lagrange(share['x'], active_shares, prime)
                result_int = (result_int + share['y'] * lagrange) % prime
            
            try:
                # Return the reconstructed secret when conversion to bytes succeeds.
                # Standard SSS has no MAC, so application-level validation must catch logical corruption.
                return result_int.to_bytes(secret_len, 'big')
            except OverflowError:
                continue
                
        raise ValueError(f"Failed to reconstruct secret from the provided shares. Corrupted data?")
    
    def _eval_poly(self, x, coeffs):
        """Horner's method"""
        y = 0
        for coeff in reversed(coeffs):
            y = (y * x + coeff) % self.PRIME
        return y
    
    @staticmethod
    def _lagrange(x, shares, prime):
        """Lagrange basis polynomial"""
        num, den = 1, 1
        for share in shares:
            if share['x'] == x:
                continue
            xi = share['x']
            num = (num * (-xi % prime)) % prime
            den = (den * ((x - xi) % prime)) % prime
        return (num * pow(den, prime - 2, prime)) % prime