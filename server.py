import os
from flask import Flask, render_template, jsonify, request
from zkp import run_protocol_simulation
from merkle import MerkleTree, verifyProof, hash_data

app = Flask(__name__)

# In-memory application state
current_pin = 1234
merkle_tree = MerkleTree(depth=4)
deposited_coins = []

@app.route('/')
def home():
    """Renders the main dashboard HTML."""
    return render_template('index.html')

@app.route('/api/zkp/setup', methods=['POST'])
def zkp_setup():
    """Sets a new 4-digit PIN for the ZKP simulation."""
    global current_pin
    data = request.json or {}
    pin_str = data.get('pin')
    
    if not pin_str or not pin_str.isdigit() or len(pin_str) != 4:
        return jsonify({'error': 'PIN must be exactly a 4-digit number.'}), 400
        
    current_pin = int(pin_str)
    return jsonify({
        'message': f'PIN successfully set to {pin_str} on the server.',
        'pin': pin_str
    })

@app.route('/api/zkp/simulate', methods=['POST'])
def zkp_simulate():
    """Runs a 100-iteration ZKP simulation using the configured PIN."""
    global current_pin
    data = request.json or {}
    cheat = data.get('cheat', False)
    
    # Run the simulation for 100 rounds
    results, all_passed, success_rate = run_protocol_simulation(current_pin, iterations=100, cheat=cheat)
    
    # Calculate cheating prover probability of success: 0.5^100
    cheat_probability = 0.5 ** 100
    
    return jsonify({
        'success': all_passed,
        'success_rate': success_rate,
        'cheating_probability': cheat_probability,
        'results': results[:10],  # Return first 10 for detailed visual step-by-step rendering
        'total_iterations': 100,
        'cheat_simulated': cheat
    })

@app.route('/api/merkle/reset', methods=['POST'])
def merkle_reset():
    """Resets the Merkle Tree anonymity set to empty state."""
    global merkle_tree, deposited_coins
    merkle_tree = MerkleTree(depth=4)
    deposited_coins = []
    return jsonify({
        'message': 'Merkle Tree reset successful.',
        'root': merkle_tree.get_root(),
        'leaves': merkle_tree.leaves,
        'deposited_coins': deposited_coins
    })

@app.route('/api/merkle/state', methods=['GET'])
def merkle_state():
    """Returns the current Merkle tree state."""
    global merkle_tree, deposited_coins
    return jsonify({
        'root': merkle_tree.get_root(),
        'leaves': merkle_tree.leaves,
        'deposited_coins': deposited_coins
    })

@app.route('/api/merkle/deposit', methods=['POST'])
def merkle_deposit():
    """Deposits a new coin string into the Merkle Tree."""
    global merkle_tree, deposited_coins
    data = request.json or {}
    coin = data.get('coin')
    
    if not coin or not isinstance(coin, str) or len(coin.strip()) == 0:
        return jsonify({'error': 'Deposit coin string cannot be empty.'}), 400
        
    coin = coin.strip()
    
    if coin in deposited_coins:
        return jsonify({'error': f'Coin "{coin}" has already been deposited!'}), 400
        
    try:
        idx = merkle_tree.insert(coin)
        deposited_coins.append(coin)
        return jsonify({
            'message': 'Coin deposited successfully!',
            'coin': coin,
            'index': idx,
            'leaf_hash': hash_data(coin),
            'root': merkle_tree.get_root(),
            'leaves': merkle_tree.leaves,
            'deposited_coins': deposited_coins
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/merkle/proof', methods=['GET'])
def merkle_proof():
    """Generates the Merkle proof path for a specific leaf index."""
    global merkle_tree
    index_str = request.args.get('index')
    
    if index_str is None or not index_str.isdigit():
        return jsonify({'error': 'Valid leaf index is required.'}), 400
        
    index = int(index_str)
    
    try:
        proof = merkle_tree.generateProof(index)
        leaf_hash = merkle_tree.leaves[index]
        return jsonify({
            'index': index,
            'leaf_hash': leaf_hash,
            'proof': proof,
            'root': merkle_tree.get_root()
        })
    except IndexError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/merkle/verify', methods=['POST'])
def merkle_verify():
    """Verifies a Merkle proof for a given coin string and root."""
    data = request.json or {}
    leaf = data.get('leaf')
    proof = data.get('proof')
    root = data.get('root')
    
    if leaf is None or proof is None or root is None:
        return jsonify({'error': 'Missing leaf, proof, or root parameter.'}), 400
        
    valid = verifyProof(leaf, proof, root)
    
    return jsonify({
        'valid': valid,
        'message': 'Merkle proof successfully verified!' if valid else 'Invalid Merkle proof.'
    })

if __name__ == '__main__':
    # Start the Flask app locally on port 5000
    app.run(host='127.0.0.1', port=5000, debug=True)
