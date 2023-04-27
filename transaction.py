from decimal import Decimal
import binascii

def create_transaction(sender_address: str, sender_private_key: RSAPrivateKey, recipient_address: str, value: Decimal) -> Transaction:
    # Verify that the sender has enough cryptocurrency to complete the transaction
    if check_balance(sender_address, blockchain) < value:
        return None
    # Verify that the sender's private key and address are valid
    private_key_dict = {address: key_dict[address] for address in key_dict if isinstance(key_dict[address], RSAPrivateKey)}
    if sender_address not in private_key_dict or private_key_dict.get(sender_address) is not sender_private_key:
        return None
    # Verify that the recipient's address is valid
    if not is_valid_address(recipient_address):
        return None
    # Create a new transaction
    timestamp = int(time.time())
    signature = sign_data(sender_private_key, str({'sender_address': sender_address, 'recipient_address': recipient_address, 'value': value, 'timestamp': timestamp}).encode('utf-8'))
    return Transaction(sender_address, recipient_address, value, timestamp, binascii.unhexlify(signature))


def check_balance(address: str, blockchain) -> Decimal:
    balance = Decimal(0.0)
    for block in blockchain:
        for tx in block.transactions:
            if tx.recipient_address == address:
                balance += tx.value
            if tx.sender_address == address:
                balance -= tx.value
    return balance


def is_valid_address(address: str) -> bool:
    return bool(re.match(r'^[a-fA-F0-9]{40}$', address))


def is_used_address(address: str, blockchain) -> bool:
    return any(tx.hash in [tx.hash for block in blockchain for tx in block.transactions] for tx in block.transactions)