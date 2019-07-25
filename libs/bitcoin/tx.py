from io import BytesIO
from binascii import hexlify

from .ecc import PrivateKey
from .helper import (
    encode_varint,
    double_sha256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    SIGHASH_ALL,
    reverse_bytes
)
from .script import Script, p2pkh_script, p2sh_script


class Tx:

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False, segwit=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def id(self):
        '''Human-readable hexadecimal of the transaction hash'''
        return hexlify(self.hash())

    def hash(self):
        '''Binary hash of the legacy serialization'''
        return reverse_bytes(double_sha256(self.serialize()))

    @classmethod
    def parse(cls, s, testnet=False):
        '''Parses a transaction from stream'''
        # read to segwit marker (5th byte), route to appropriate function
        s.read(4)
        if s.read(1) == b'\x00':
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        # rewind bytestream afterwards
        s.seek(-5, 1)
        return parse_method(s, testnet=testnet)

    @classmethod
    def parse_legacy(cls, s, testnet=False):
        '''Parses a legacy transaction from stream'''
        # read version
        version = little_endian_to_int(s.read(4))
        # read inputs
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # read outputs
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # read locktime
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime,
                   testnet=testnet, segwit=False)

    @classmethod
    def parse_segwit(cls, s, testnet=False):
        '''Parses a segwit transaction from stream'''
        # read version
        # read version
        version = little_endian_to_int(s.read(4))
        # read segwit market, only accept version 1
        marker = s.read(2)
        if marker != b'\x00\x01':
            raise RuntimeError('Not a segwit transaction {}'.format(marker))
        # read inputes
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # read outputs
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # read witness
        for tx_in in inputs:
            num_items = read_varint(s)
            items = []
            for _ in range(num_items):
                item_len = read_varint(s)
                if item_len == 0:
                    items.append(0)
                else:
                    items.append(s.read(item_len))
            tx_in.witness = items
        # read locktime
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, 
                   testnet=testnet, segwit=True)

    def serialize(self):
        '''Returns the byte serialization of the transaction'''
        # legacy and segwit transactions are serialized differently
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    def serialize_legacy(self):
        '''Returns the byte serialization of legacy transactions'''
        # write version
        result = int_to_little_endian(self.version, 4)
        # write inputs
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        # write outputs
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        # write locktime
        result += int_to_little_endian(self.locktime, 4)
        return result

    def serialize_segwit(self):
        '''Returns the byte serialization of segwit transactions'''
        # write version
        result = int_to_little_endian(self.version, 4)
        # write segwit marker (0) and version number (1)
        result += b'\x00\x01'
        # write inputs
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        # write outputs
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        # write witness
        for tx_in in self.tx_ins:
            result += int_to_little_endian(len(tx_in.witness), 1)
            for item in tx_in.witness:
                if type(item) == int:
                    result += int_to_little_endian(item, 1)
                else:
                    result += encode_varint(len(item)) + item
        # write locktime
        result += int_to_little_endian(self.locktime, 4)
        return result

    def sig_hash(self, input_index, script_pubkey=None, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        if not (script_pubkey or redeem_script):
            raise ValueError("you must supply either script_pubkey or redeem_script")
        # start the serialization with version
        # use int_to_little_endian in 4 bytes
        s = int_to_little_endian(self.version, 4)
        # add how many inputs there are using encode_varint
        s += encode_varint(len(self.tx_ins))
        # loop through each input using enumerate, so we have the input index
        for i, tx_in in enumerate(self.tx_ins):
            # ScriptSig is the script_pubkey if this index is the one we're signing
            if i == input_index:
                if redeem_script:
                    script_sig = redeem_script
                else:
                    script_sig = script_pubkey
            # Otherwise, the ScriptSig is empty
            else:
                script_sig = None
            # add the serialization of the input with the ScriptSig we want
            s += TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                sequence=tx_in.sequence,
            ).serialize()
        # add how many outputs there are using encode_varint
        s += encode_varint(len(self.tx_outs))
        # add the serialization of each output
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        # add the locktime using int_to_little_endian in 4 bytes
        s += int_to_little_endian(self.locktime, 4)
        # add SIGHASH_ALL using int_to_little_endian in 4 bytes
        s += int_to_little_endian(SIGHASH_ALL, 4)
        # double_sha256 the serialization
        h256 = double_sha256(s)
        # convert the result to an integer using int.from_bytes(x, 'big')
        return int.from_bytes(h256, 'big')

    def hash_prevouts(self):
        if self._hash_prevouts is None:
            all_prevouts = b''
            all_sequence = b''
            for tx_in in self.tx_ins:
                all_prevouts += reverse_bytes(tx_in.prev_tx) + \
                                int_to_little_endian(tx_in.prev_index, 4)
                all_sequence += int_to_little_endian(tx_in.sequence, 4)
            self._hash_prevouts = double_sha256(all_prevouts)
            self._hash_sequence = double_sha256(all_sequence)
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            self.hash_prevouts()  # this should calculate self._hash_prevouts
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            all_outputs = b''
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = double_sha256(all_outputs)
        return self._hash_outputs

    def sig_hash_bip143(self, input_index, input_value, script_pubkey=None, 
                        redeem_script=None, witness_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        if not (script_pubkey or redeem_script or witness_script):
            raise RuntimeError('No script supplied to sig_hash_bip143')
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += reverse_bytes(tx_in.prev_tx) + int_to_little_endian(tx_in.prev_index, 4)
        if witness_script:
            script_code = witness_script.serialize()
        elif redeem_script:
            script_code = p2pkh_script(redeem_script.cmds[1]).serialize()
        else:
            script_code = p2pkh_script(script_pubkey.cmds[1]).serialize()
        s += script_code
        s += int_to_little_endian(input_value, 8)  # FIXME: hack
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        return int.from_bytes(double_sha256(s), 'big')

    def sign_input_p2pkh(self, input_index, private_key, script_pubkey):
        '''Signs input spending P2PKH output'''
        # get the signature hash (z)
        z = self.sig_hash(input_index, script_pubkey)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the SIGHASH_ALL to der
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # calculate the sec
        sec = private_key.public_key.sec()
        # change this input's script to the P2PKH solution [sig, sec]
        self.tx_ins[input_index].script_sig = Script([sig, sec])

    def sign_input_p2sh(self, input_index, private_key, redeem_script):
        '''Signs input spending P2SH output'''
        # get the signature hash (z)
        z = self.sig_hash(input_index, redeem_script)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the SIGHASH_ALL to der
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # calculate the sec
        sec = private_key.public_key.sec()
        # change this input's script to the P2SH solution [sig, raw_redeem]
        self.tx_ins[input_index].script_sig = Script([sig, redeem_script.raw_serialize()])

    def sign_input_p2wpkh(self, input_index, input_value, private_key, script_pubkey):
        '''Signs input spending P2WPKH output'''
        # get the signature hash (z)
        z = self.sig_hash_bip143(input_index, input_value, script_pubkey=script_pubkey)
        # calculate the signature
        der = private_key.sign(z).der()
        # signature is der + sighash type
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # get sec pubkey
        sec = private_key.public_key.sec()
        # set the witness
        self.tx_ins[input_index].witness = [sig, sec]

    def sign_input_p2wsh(self, input_index, input_value, private_key, witness_script):
        '''Signs the input using the private key'''
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, input_value, witness_script=witness_script)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # witness is signature + witness script
        self.tx_ins[input_index].witness = [sig, witness_script.raw_serialize()]


class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence
        self.witness = b''

    def __repr__(self):
        return '{}:{}'.format(
            hexlify(self.prev_tx),
            self.prev_index,
        )

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        # prev_tx is 32 bytes, little endian
        prev_tx = reverse_bytes(s.read(32))
        # prev_index is an integer in 4 bytes, little endian
        prev_index = little_endian_to_int(s.read(4))
        # use Script.parse to get the ScriptSig
        script_sig = Script.parse(s)
        # sequence is an integer in 4 bytes, little-endian
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (see __init__ for args)
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction input'''
        # serialize prev_tx, little endian
        result = reverse_bytes(self.prev_tx)
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # amount is an integer in 8 bytes, little endian
        amount = little_endian_to_int(s.read(8))
        # use Script.parse to get the ScriptPubKey
        script_pubkey = Script.parse(s)
        # return an instance of the class (see __init__ for args)
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result

