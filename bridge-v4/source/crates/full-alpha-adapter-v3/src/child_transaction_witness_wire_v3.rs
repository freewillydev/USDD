//! Binary serde for execution witnesses. rust-elements' map-only struct
//! deserializers cannot consume bincode sequences. Encode native outpoints as
//! their 32-byte internal txid and u32 index; encode both halves of each output
//! separately because consensus TxOut serialization excludes its witness.
use ecx_full_consensus_validator_v2::elements_v2::*;
use elements::{OutPoint, TxOut, TxOutWitness};
use elements::hashes::Hash as _;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutPointWire { txid: [u8;32], vout: u32 }
impl From<OutPoint> for OutPointWire {
    fn from(value: OutPoint) -> Self { Self { txid: value.txid.to_byte_array(), vout: value.vout } }
}
impl From<OutPointWire> for OutPoint {
    fn from(value: OutPointWire) -> Self {
        Self { txid: elements::Txid::from_byte_array(value.txid), vout: value.vout }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputWire { output: Vec<u8>, witness: Vec<u8> }
impl From<&TxOut> for OutputWire {
    fn from(value: &TxOut) -> Self {
        Self { output: elements::encode::serialize(value), witness: elements::encode::serialize(&value.witness) }
    }
}
impl OutputWire {
    fn decode(self) -> Result<TxOut, &'static str> {
        let mut output: TxOut = elements::encode::deserialize(&self.output)
            .map_err(|_| "invalid native output consensus encoding")?;
        let witness: TxOutWitness = elements::encode::deserialize(&self.witness)
            .map_err(|_| "invalid native output witness consensus encoding")?;
        if elements::encode::serialize(&output) != self.output || elements::encode::serialize(&witness) != self.witness {
            return Err("noncanonical native output encoding");
        }
        output.witness = witness;
        Ok(output)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeafWire {
    outpoint: OutPointWire, output: OutputWire,
    creation_height: u32, creation_parent_mtp: u32,
    coinbase: bool, created_by_issuance: bool, created_by_pegin: bool,
}
impl From<&ElementsUtxoLeafV2> for LeafWire {
    fn from(value: &ElementsUtxoLeafV2) -> Self {
        Self { outpoint: value.outpoint.into(), output: (&value.output).into(),
            creation_height: value.creation_height, creation_parent_mtp: value.creation_parent_mtp,
            coinbase: value.coinbase, created_by_issuance: value.created_by_issuance,
            created_by_pegin: value.created_by_pegin }
    }
}
impl LeafWire {
    fn decode(self) -> Result<ElementsUtxoLeafV2, &'static str> {
        Ok(ElementsUtxoLeafV2 { outpoint: self.outpoint.into(), output: self.output.decode()?,
            creation_height: self.creation_height, creation_parent_mtp: self.creation_parent_mtp,
            coinbase: self.coinbase, created_by_issuance: self.created_by_issuance,
            created_by_pegin: self.created_by_pegin })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UtxoMutationWire {
    outpoint: OutPointWire, old_leaf: Option<LeafWire>, new_leaf: Option<LeafWire>,
    path: ElementsSparseUtxoPathV2,
}
impl From<&ElementsSparseUtxoMutationV2> for UtxoMutationWire {
    fn from(value: &ElementsSparseUtxoMutationV2) -> Self {
        Self { outpoint: value.outpoint.into(), old_leaf: value.old_leaf.as_ref().map(Into::into),
            new_leaf: value.new_leaf.as_ref().map(Into::into), path: value.path.clone() }
    }
}
impl UtxoMutationWire {
    fn decode(self) -> Result<ElementsSparseUtxoMutationV2, &'static str> {
        Ok(ElementsSparseUtxoMutationV2 { outpoint: self.outpoint.into(),
            old_leaf: self.old_leaf.map(LeafWire::decode).transpose()?,
            new_leaf: self.new_leaf.map(LeafWire::decode).transpose()?, path: self.path })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicLeafWire {
    utxo: LeafWire, asset_id: [u8;32], amount: u64,
    asset_blinding_factor: [u8;32], value_blinding_factor: [u8;32], role: ElementsLiveEconomicRoleV2,
}
impl From<&ElementsEconomicLeafV2> for EconomicLeafWire {
    fn from(value: &ElementsEconomicLeafV2) -> Self {
        Self { utxo: (&value.utxo).into(), asset_id: value.asset_id, amount: value.amount,
            asset_blinding_factor: value.asset_blinding_factor, value_blinding_factor: value.value_blinding_factor,
            role: value.role }
    }
}
impl EconomicLeafWire {
    fn decode(self) -> Result<ElementsEconomicLeafV2, &'static str> {
        Ok(ElementsEconomicLeafV2 { utxo: self.utxo.decode()?, asset_id: self.asset_id,
            amount: self.amount, asset_blinding_factor: self.asset_blinding_factor,
            value_blinding_factor: self.value_blinding_factor, role: self.role })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicMutationWire {
    outpoint: OutPointWire, old_leaf: Option<EconomicLeafWire>, new_leaf: Option<EconomicLeafWire>,
    path: ElementsSparseEconomicPathV2,
}
impl From<&ElementsSparseEconomicMutationV2> for EconomicMutationWire {
    fn from(value: &ElementsSparseEconomicMutationV2) -> Self {
        Self { outpoint: value.outpoint.into(), old_leaf: value.old_leaf.as_ref().map(Into::into),
            new_leaf: value.new_leaf.as_ref().map(Into::into), path: value.path.clone() }
    }
}
impl EconomicMutationWire {
    fn decode(self) -> Result<ElementsSparseEconomicMutationV2, &'static str> {
        Ok(ElementsSparseEconomicMutationV2 { outpoint: self.outpoint.into(),
            old_leaf: self.old_leaf.map(EconomicLeafWire::decode).transpose()?,
            new_leaf: self.new_leaf.map(EconomicLeafWire::decode).transpose()?, path: self.path })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyMutationWire {
    outpoint: OutPointWire,
    old_leaf: Option<EconomicLeafWire>,
    new_leaf: Option<EconomicLeafWire>,
    siblings: Vec<ElementsSparseCustodyNodeV3>,
}
impl From<&ElementsSparseCustodyMutationV3> for CustodyMutationWire {
    fn from(value: &ElementsSparseCustodyMutationV3) -> Self {
        Self { outpoint: value.outpoint.into(),
            old_leaf: value.old_leaf.as_ref().map(Into::into),
            new_leaf: value.new_leaf.as_ref().map(Into::into),
            siblings: value.siblings.clone() }
    }
}
impl CustodyMutationWire {
    fn decode(self) -> Result<ElementsSparseCustodyMutationV3, &'static str> {
        Ok(ElementsSparseCustodyMutationV3 { outpoint: self.outpoint.into(),
            old_leaf: self.old_leaf.map(EconomicLeafWire::decode).transpose()?,
            new_leaf: self.new_leaf.map(EconomicLeafWire::decode).transpose()?,
            siblings: self.siblings })
    }
}

macro_rules! witness_serde {
    ($module:ident, $native:ident, $mutation:ident) => {
        pub(super) mod $module {
            use super::*;
            #[derive(Serialize, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Wire { spends: Vec<$mutation>, creates: Vec<$mutation> }
            pub(crate) fn serialize<S: serde::Serializer>(value: &$native, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() { return value.serialize(serializer); }
                Wire { spends: value.spends.iter().map(Into::into).collect(),
                    creates: value.creates.iter().map(Into::into).collect() }.serialize(serializer)
            }
            pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<$native, D::Error> {
                if deserializer.is_human_readable() { return $native::deserialize(deserializer); }
                let wire = Wire::deserialize(deserializer)?;
                Ok($native {
                    spends: wire.spends.into_iter().map($mutation::decode).collect::<Result<_, _>>()
                        .map_err(serde::de::Error::custom)?,
                    creates: wire.creates.into_iter().map($mutation::decode).collect::<Result<_, _>>()
                        .map_err(serde::de::Error::custom)?,
                })
            }
        }
    }
}
witness_serde!(utxo, ElementsTransactionUtxoWitnessV2, UtxoMutationWire);
witness_serde!(economic, ElementsTransactionEconomicWitnessV2, EconomicMutationWire);
witness_serde!(custody, ElementsTransactionCustodyWitnessV3, CustodyMutationWire);

/// Shared with the owned capital witness. Keep one output/witness codec so
/// activation cannot accidentally strip proofs that transaction execution kept.
pub(crate) mod leaf {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &ElementsUtxoLeafV2, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() { return value.serialize(serializer); }
        LeafWire::from(value).serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<ElementsUtxoLeafV2, D::Error> {
        if deserializer.is_human_readable() { return ElementsUtxoLeafV2::deserialize(deserializer); }
        LeafWire::deserialize(deserializer)?.decode().map_err(serde::de::Error::custom)
    }
}

pub(crate) mod outpoint {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &OutPoint, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() { return value.serialize(serializer); }
        OutPointWire::from(*value).serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<OutPoint, D::Error> {
        if deserializer.is_human_readable() { return OutPoint::deserialize(deserializer); }
        Ok(OutPointWire::deserialize(deserializer)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{ChildTransactionStateWitness, decode_child_transaction_witness_v3};
    use bincode::Options;

    fn nonempty_witness() -> ChildTransactionStateWitness {
        use elements::secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, Secp256k1, SecretKey, Tag, Tweak};
        let secp = Secp256k1::new();
        let generator = Generator::new_unblinded(&secp, Tag::from([7;32]));
        let blinder = Tweak::from_slice(&[3;32]).unwrap();
        let commitment = PedersenCommitment::new(&secp, 100, blinder, generator);
        let proof = RangeProof::new(&secp, 1, commitment, 100, blinder, b"wire test", &[],
            SecretKey::from_slice(&[2;32]).unwrap(), 0, 8, generator).unwrap();
        let output = TxOut {
            asset: elements::confidential::Asset::Confidential(generator),
            value: elements::confidential::Value::Confidential(commitment),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: elements::Script::from(vec![0x51]),
            witness: TxOutWitness { surjection_proof: None, rangeproof: Some(Box::new(proof)) },
        };
        let outpoint = OutPoint { txid: elements::Txid::from_byte_array([9;32]), vout: 17 };
        let leaf = ElementsUtxoLeafV2 { outpoint, output, creation_height: 11,
            creation_parent_mtp: 22, coinbase: false, created_by_issuance: true, created_by_pegin: false };
        let path = ElementsSparseUtxoPathV2 { siblings: vec![ElementsSparseUtxoNodeV2 {
            hash: [4;32], aggregate: ElementsUtxoAggregateV2 { count: 7 } }] };
        let economic_leaf = ElementsEconomicLeafV2 { utxo: leaf.clone(), asset_id: [7;32], amount: 100,
            asset_blinding_factor: [0;32], value_blinding_factor: [3;32], role: ElementsLiveEconomicRoleV2::OutstandingBase };
        let economic_path = ElementsSparseEconomicPathV2 { siblings: vec![ElementsSparseEconomicNodeV2 {
            hash: [5;32], aggregate: ElementsEconomicAggregateV2 { count: 7,
                outstanding_base_atoms: 11, redeemable_reserve_quote_atoms: 13 } }] };
        ChildTransactionStateWitness {
            utxo: ElementsTransactionUtxoWitnessV2 {
                spends: vec![ElementsSparseUtxoMutationV2 { outpoint, old_leaf: Some(leaf.clone()), new_leaf: None, path: path.clone() }],
                creates: vec![ElementsSparseUtxoMutationV2 { outpoint, old_leaf: None, new_leaf: Some(leaf), path }],
            },
            economic: ElementsTransactionEconomicWitnessV2 {
                spends: vec![ElementsSparseEconomicMutationV2 { outpoint, old_leaf: Some(economic_leaf.clone()), new_leaf: None, path: economic_path.clone() }],
                creates: vec![ElementsSparseEconomicMutationV2 { outpoint, old_leaf: None, new_leaf: Some(economic_leaf), path: economic_path }],
            },
            kernel: ElementsTransactionKernelWitnessV2::Ordinary,
        }
    }

    #[test]
    fn custody_binary_witness_preserves_populated_leaves_and_rejects_bad_transport() {
        use super::super::{ChildTransactionCustodyWitnessV3, decode_child_transaction_custody_witness_v3};
        let original = nonempty_witness();
        let mutation = |value: &ElementsSparseEconomicMutationV2| ElementsSparseCustodyMutationV3 {
            outpoint: value.outpoint, old_leaf: value.old_leaf.clone(),
            new_leaf: value.new_leaf.clone(),
            siblings: vec![ElementsSparseCustodyNodeV3 {
                hash: [19;32], count: 7, custody_supply_atoms: 100,
            }; 256],
        };
        let witness = ChildTransactionCustodyWitnessV3 {
            utxo: original.utxo,
            custody: ElementsTransactionCustodyWitnessV3 {
                spends: original.economic.spends.iter().map(mutation).collect(),
                creates: original.economic.creates.iter().map(mutation).collect(),
            }, kernel: original.kernel,
        };
        let options = bincode::DefaultOptions::new().with_fixint_encoding()
            .reject_trailing_bytes().with_limit(1_000_000);
        let bytes = options.serialize(&witness).unwrap();
        let decoded: ChildTransactionCustodyWitnessV3 = options.deserialize(&bytes).unwrap();
        assert_eq!(decoded, witness);
        assert_eq!(options.serialize(&decoded).unwrap(), bytes);
        assert!(decoded.custody.spends[0].old_leaf.as_ref().unwrap().utxo.output.witness.rangeproof.is_some());
        assert_eq!(serde_json::from_slice::<ChildTransactionCustodyWitnessV3>(
            &serde_json::to_vec(&witness).unwrap()).unwrap(), witness);
        let mut trailing = bytes.clone(); trailing.push(0);
        assert!(options.deserialize::<ChildTransactionCustodyWitnessV3>(&trailing).is_err());
        assert!(options.deserialize::<ChildTransactionCustodyWitnessV3>(&bytes[..bytes.len()-1]).is_err());
        assert_eq!(decode_child_transaction_custody_witness_v3(&bytes, bytes.len() as u64).unwrap(), witness);
        assert!(decode_child_transaction_custody_witness_v3(&bytes, bytes.len() as u64 - 1).is_err());
        let mut bad_length = bytes;
        bad_length[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(options.deserialize::<ChildTransactionCustodyWitnessV3>(&bad_length).is_err());
        // Transport preservation is not proof of membership, asset role or execution.
    }

    #[test]
    fn owned_activation_coin_preserves_rangeproof_and_canonical_outpoint() {
        use crate::capital_genesis_utxos_v4::OwnedActivationCoinWitnessV4;
        let witness = nonempty_witness();
        let coin = OwnedActivationCoinWitnessV4 {
            leaf: witness.utxo.spends[0].old_leaf.clone().unwrap(),
            path: witness.utxo.spends[0].path.clone(),
        };
        let options = bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes();
        let bytes = options.serialize(&coin).unwrap();
        assert_eq!(&bytes[..36], elements::encode::serialize(&coin.leaf.outpoint));
        let decoded: OwnedActivationCoinWitnessV4 = options.deserialize(&bytes).unwrap();
        assert_eq!(decoded, coin);
        assert!(decoded.as_witness().leaf.output.witness.rangeproof.is_some());
        assert_eq!(serde_json::from_slice::<OwnedActivationCoinWitnessV4>(
            &serde_json::to_vec(&coin).unwrap()).unwrap(), coin);
        let mut trailing = bytes.clone(); trailing.push(0);
        assert!(options.deserialize::<OwnedActivationCoinWitnessV4>(&trailing).is_err());
        assert!(options.deserialize::<OwnedActivationCoinWitnessV4>(&bytes[..bytes.len()-1]).is_err());
    }

    #[test]
    fn nonempty_binary_witness_preserves_native_outputs_and_rangeproofs() {
        let witness = nonempty_witness();
        let old_leaf = witness.utxo.spends[0].old_leaf.as_ref().unwrap();
        assert!(!old_leaf.output.witness.is_empty());
        let native_output_bytes = elements::encode::serialize(&old_leaf.output);
        let base_decoded: TxOut = elements::encode::deserialize(&native_output_bytes).unwrap();
        assert!(base_decoded.witness.is_empty(), "base TxOut bytes omit the proof witness");
        let options = bincode::DefaultOptions::new().with_fixint_encoding();
        assert_eq!(options.serialize(&OutPointWire::from(old_leaf.outpoint)).unwrap(),
            elements::encode::serialize(&old_leaf.outpoint));
        let bytes = options.serialize(&witness).unwrap();
        assert_eq!(decode_child_transaction_witness_v3(&bytes, bytes.len() as u64).unwrap(), witness);
        let json = serde_json::to_vec(&witness).unwrap();
        assert_eq!(serde_json::from_slice::<ChildTransactionStateWitness>(&json).unwrap(), witness);
        let human = serde_json::to_value(&witness).unwrap();
        assert_eq!(human["utxo"], serde_json::to_value(&witness.utxo).unwrap());
        assert_eq!(human["economic"], serde_json::to_value(&witness.economic).unwrap());
    }

    #[test]
    fn witness_rejects_bad_nested_consensus_bytes_and_bounded_input() {
        let witness = nonempty_witness();
        let output = &witness.utxo.spends[0].old_leaf.as_ref().unwrap().output;
        let mut wire = OutputWire::from(output);
        wire.output.push(0);
        assert!(wire.decode().is_err());
        let mut wire = OutputWire::from(output);
        wire.witness.push(0);
        assert!(wire.decode().is_err());
        let mut wire = OutputWire::from(output);
        wire.witness.pop();
        assert!(wire.decode().is_err());
        let mut wire = OutputWire::from(output);
        // Nonminimal CompactSize zero for the absent surjection proof.
        assert_eq!(wire.witness[0], 0);
        wire.witness.splice(..1, [0xfd, 0, 0]);
        assert!(wire.decode().is_err());
        let options = bincode::DefaultOptions::new().with_fixint_encoding();
        let bytes = options.serialize(&witness).unwrap();
        let length = bytes.len() as u64;
        assert!(decode_child_transaction_witness_v3(&bytes, length - 1).is_err());
        for end in [0, 1, 8, bytes.len()/2, bytes.len()-1] {
            assert!(decode_child_transaction_witness_v3(&bytes[..end], length).is_err());
        }
        let mut corrupted = bytes.clone();
        let native_output = elements::encode::serialize(output);
        let offset = corrupted.windows(native_output.len()).position(|part| part == native_output).unwrap();
        corrupted[offset] = 0xff; // Invalid asset encoding inside a populated leaf.
        assert!(decode_child_transaction_witness_v3(&corrupted, length).is_err());
        corrupted = bytes.clone();
        corrupted[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_child_transaction_witness_v3(&corrupted, length).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_child_transaction_witness_v3(&trailing, length+1).is_err());
    }
}
