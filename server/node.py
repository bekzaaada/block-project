import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Building Blockchain

class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.nodes = set()
        self.create_block(proof=1, previous_hash = '0')
        

    def create_block(self, proof, previous_hash):
        merkle_root = self.calculate_merkle_root(self.transactions)
        block = {
            "index": len(self.chain) + 1,
            "miner": "miner_address",
            "timestamp": str(datetime.datetime.now()),
            "proof": proof,
            "previous_hash": previous_hash,
            "merkle_root": merkle_root,
            "transactions": self.transactions,
        }
        hash = self.hash(block)
        block["hash"] = hash
        self.transactions = []
        self.chain.append(block)
        return block
    
    def calculate_merkle_root(self, transactions):
        if len(transactions) == 0:
            return hashlib.sha256(b'').hexdigest()

        if len(transactions) == 1:
            return hashlib.sha256(json.dumps(transactions[0]).encode()).hexdigest()

        # Create a list to hold intermediate hashes
        intermediate_hashes = []

        # Hash each transaction individually and add it to the list
        for transaction in transactions:
            transaction_hash = hashlib.sha256(json.dumps(transaction).encode()).hexdigest()
            intermediate_hashes.append(transaction_hash)

        # Recursively compute the Merkle root from the intermediate hashes
        return self.compute_merkle_root(intermediate_hashes)

    def compute_merkle_root(self, hashes):
        if len(hashes) == 1:
            return hashes[0]

        # Pair up and hash the hashes
        new_hashes = []
        for i in range(0, len(hashes), 2):
            hash1 = hashes[i]
            hash2 = hashes[i + 1] if i + 1 < len(hashes) else hash1
            combined_hash = hashlib.sha256(hash1.encode() + hash2.encode()).hexdigest()
            new_hashes.append(combined_hash)

        # Recursively compute the Merkle root from the new hashes
        return self.compute_merkle_root(new_hashes)

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:5] == '00000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block["previous_hash"] != self.hash(previous_block):
                return False
            previous_proof = previous_block["proof"]
            proof = block["proof"]
            hash_operation =  hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != "0000":
                return False
            previous_block = block
            block_index += 1
        return True

    def add_transactions(self, sender, recipient, amount, public_key, add_info):
        self.transactions.append({
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "public_key": public_key,
            "add_info": add_info
        })
        previous_block = self.get_previous_block()
        return previous_block["index"] + 1

    def add_node(self, address):
        paresed_url = urlparse(address)
        self.nodes.add(paresed_url.netloc)

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()["length"]
                chain = response.json()["chain"]
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain 
        if longest_chain:
            self.chain = longest_chain
            return True
        return False
    
    

# Mining Blockchain

app = Flask(__name__)

CORS(app)

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem

node_address = str(uuid4()).replace('-', '')

blockchain = Blockchain()

@app.route("/mine_block", methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    previous_hash = previous_block["hash"]
    proof = blockchain.proof_of_work(previous_proof)
    miner_address = "miner_address"

    block = blockchain.create_block(proof, previous_hash, miner_address)

    response = {
        "message": "Congratulation, you just mined a block!",
        "index": block["index"],
        "timestamp": block["timestamp"],
        "proof": block["proof"],
        "previous_hash": block["previous_hash"],
        "transactions": block["transactions"],
    }

    return jsonify(response), 200

@app.route("/get_chain", methods=["GET"])
def get_chain():
    response = {
        "chain": blockchain.chain,
        "active_nodes": list(blockchain.nodes),
        "length": len(blockchain.chain)
    }

    return jsonify(response)

@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    private_key, public_key = generate_rsa_keys()
    return jsonify({'private_key': private_key, 'public_key': public_key})


@app.route("/is_valid", methods=["GET"])
def is_valid():
    is_valid =  blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': "All Good!. The Blockchain is valid."}
    else:
        response = {'message': "We have a problem. The Blockchain is not valid."}
    return jsonify(response), 200

@app.route("/add_transaction", methods=['POST'])
def add_transactions():
    json = request.json
    transaction_keys = ["sender", "recipient", "amount", "public_key", "add_info"]

    if not all(key in json for key in transaction_keys):
        return "Some elements of the transaction are missing", 400

    index = blockchain.add_transaction(
        json["sender"],
        json["recipient"],
        json["amount"],
        json["public_key"],  # Include public key
        json["add_info"]  # Include additional info
    )
    response = {
        "message": f"This transaction will be added to Block {index}"
    }
    return jsonify(response), 201


app.run(host='0.0.0.0', port=5000, debug=True)