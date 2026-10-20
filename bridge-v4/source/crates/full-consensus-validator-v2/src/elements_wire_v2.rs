//! Canonical native Elements wire components shared by proof input relations.
//! Decoding preserves evidence; it does not authenticate a UTXO or its opening.

use elements::{TxOut, TxOutWitness};

pub const MAX_ELEMENTS_OUTPUT_COMPONENT_BYTES_V2: usize = 1_000_000;

/// Reattach the mandatory, separately encoded witness. Native consensus
/// `TxOut` serialization alone omits both rangeproof and surjection proof.
pub fn decode_elements_output_with_witness_v2(
    output_bytes: &[u8],
    witness_bytes: &[u8],
) -> Result<TxOut, &'static str> {
    if output_bytes.is_empty()
        || output_bytes.len() > MAX_ELEMENTS_OUTPUT_COMPONENT_BYTES_V2
        || witness_bytes.is_empty()
        || witness_bytes.len() > MAX_ELEMENTS_OUTPUT_COMPONENT_BYTES_V2
    {
        return Err("missing or oversized Elements output component");
    }
    let mut output: TxOut = elements::encode::deserialize(output_bytes)
        .map_err(|_| "invalid Elements output consensus encoding")?;
    let witness: TxOutWitness = elements::encode::deserialize(witness_bytes)
        .map_err(|_| "invalid Elements output witness consensus encoding")?;
    if elements::encode::serialize(&output) != output_bytes
        || elements::encode::serialize(&witness) != witness_bytes
    {
        return Err("noncanonical Elements output component");
    }
    output.witness = witness;
    Ok(output)
}

/// Native OutPoint's map-only serde cannot consume bincode sequences. Binary
/// bytes are exactly txid[32] || vout_le[4], independently of bincode endianness.
/// Human-readable serde retains the native JSON representation.
pub mod outpoint {
    use elements::{hashes::Hash as _, OutPoint};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Wire {
        txid: [u8; 32],
        vout_le: [u8; 4],
    }

    pub fn serialize<S: serde::Serializer>(
        value: &OutPoint,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            return value.serialize(serializer);
        }
        Wire {
            txid: value.txid.to_byte_array(),
            vout_le: value.vout.to_le_bytes(),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OutPoint, D::Error> {
        if deserializer.is_human_readable() {
            return OutPoint::deserialize(deserializer);
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(OutPoint {
            txid: elements::Txid::from_byte_array(wire.txid),
            vout: u32::from_le_bytes(wire.vout_le),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::Options;
    use elements::{hashes::Hash as _, OutPoint, Txid};
    use serde::{Deserialize, Serialize};

    #[test]
    fn outpoint_is_exact_consensus_bytes_under_both_endiannesses() {
        #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
        struct Wrapper(#[serde(with = "outpoint")] OutPoint);
        let value = Wrapper(OutPoint {
            txid: Txid::from_byte_array(std::array::from_fn(|i| i as u8)),
            vout: 0x01020304,
        });
        let little = bincode::DefaultOptions::new().with_fixint_encoding();
        let big = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();
        let expected = elements::encode::serialize(&value.0);
        assert_eq!(expected.len(), 36);
        assert_eq!(&expected[32..], &[4, 3, 2, 1]);
        assert_eq!(little.serialize(&value).unwrap(), expected);
        assert_eq!(big.serialize(&value).unwrap(), expected);
        assert_eq!(little.deserialize::<Wrapper>(&expected).unwrap(), value);
        assert_eq!(big.deserialize::<Wrapper>(&expected).unwrap(), value);
        let json = serde_json::to_value(value.0).unwrap();
        assert_eq!(serde_json::to_value(&value).unwrap(), json);
        assert_eq!(serde_json::from_value::<Wrapper>(json).unwrap(), value);
    }
}
