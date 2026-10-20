//! Native GenericVerifyScript ECDSA primitive, not a complete header verifier.
//! The caller must authenticate the native header digest and script flags.
//! Legacy proofs omit the sighash byte; nonempty DynaFed witnesses use it.
use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use bitcoin::hashes::Hash as _;
use ecx_full_consensus_validator_v2::elements_v2::{ElementsBlockAuthorizationVerifierV2, ElementsStateErrorV2};
use ecx_full_consensus_validator_v2::script_v2::{
    ScriptPrimitiveErrorV2, ScriptSignatureCheckerV2,
};

pub struct NativeHeaderSignatureChecker {
    pub header_digest: [u8; 32],
    pub has_sighash_byte: bool,
}

/// Script authorization for the standard serialized Elements header used by
/// this adapter. Full native opcode/differential qualification remains required;
/// this does not authenticate the challenge or support patched header formats.
pub struct NativeHeaderScriptVerifier;

pub trait NativeHeaderAuthorization {
    fn authorize(&self, header: &super::native_header_v3::NativeHeader,
        context: &ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2)
        -> Result<(), ElementsStateErrorV2>;
}

impl NativeHeaderAuthorization for NativeHeaderScriptVerifier {
    fn authorize(&self, header: &super::native_header_v3::NativeHeader,
        context: &ecx_full_consensus_validator_v2::elements_v2::ElementsHeaderConsensusContextV2)
        -> Result<(), ElementsStateErrorV2> {
        ecx_full_consensus_validator_v2::elements_v2::verify_elements_contextual_header_native_v3(
            &elements::Block {header:header.base.clone(),txdata:vec![]},context,
            &BoundNativeHeaderVerifier(header))
    }
}

impl NativeHeaderScriptVerifier {
    fn verify(&self, header: &elements::BlockHeader, challenge: &elements::Script,
        solution: &[u8], witness: &[Vec<u8>]) -> Result<(), ElementsStateErrorV2> {
        Self::verify_digest(header.block_hash().to_byte_array(),challenge,solution,witness)
    }

    fn verify_digest(digest: [u8;32], challenge: &elements::Script,
        solution: &[u8], witness: &[Vec<u8>]) -> Result<(), ElementsStateErrorV2> {
        use ecx_full_consensus_validator_v2::script_v2::*;
        if !script_is_push_only_v2(solution).map_err(|_| ElementsStateErrorV2::HeaderConsensus)? {
            return Err(ElementsStateErrorV2::HeaderConsensus);
        }
        let checker = NativeHeaderSignatureChecker {
            header_digest: digest,
            // Native CheckProofGeneric selects this flag from witness emptiness.
            has_sighash_byte: !witness.is_empty(),
        };
        verify_native_script_components_v3(solution, challenge.as_bytes(), witness,
            ScriptLockContextV2 { null_dummy: true, ..Default::default() },
            &checker, &checker, LegacyScriptFlagsV2 {
                require_minimal_push: true, verify_p2sh: true, clean_stack: true,
                verify_witness: true, strict_der: true, strict_encoding: true,
                low_s: true, ..Default::default()
            }).map_err(|_| ElementsStateErrorV2::HeaderConsensus)
    }
}

/// Bind the existing contextual rules to an exact native header. The callback
/// refuses any different projection and derives the signature digest itself;
/// callers cannot inject an independently selected digest.
pub struct BoundNativeHeaderVerifier<'a>(pub &'a super::native_header_v3::NativeHeader);

impl BoundNativeHeaderVerifier<'_> {
    fn verify(&self, header: &elements::BlockHeader, challenge: &elements::Script,
        solution: &[u8], witness: &[Vec<u8>]) -> Result<(), ElementsStateErrorV2> {
        if elements::encode::serialize(header) != elements::encode::serialize(&self.0.base) {
            return Err(ElementsStateErrorV2::HeaderConsensus);
        }
        let digest = self.0.hash_internal().map_err(|_| ElementsStateErrorV2::HeaderConsensus)?;
        NativeHeaderScriptVerifier::verify_digest(digest,challenge,solution,witness)
    }
}

impl ElementsBlockAuthorizationVerifierV2 for BoundNativeHeaderVerifier<'_> {
    fn verify_legacy_proof(&self, header: &elements::BlockHeader,
        challenge: &elements::Script, solution: &elements::Script) -> Result<(), ElementsStateErrorV2> {
        self.verify(header,challenge,solution.as_bytes(),&[])
    }
    fn verify_dynafed_proof(&self, header: &elements::BlockHeader,
        challenge: &elements::Script, witness: &[Vec<u8>]) -> Result<(), ElementsStateErrorV2> {
        self.verify(header,challenge,&[],witness)
    }
}

impl ElementsBlockAuthorizationVerifierV2 for NativeHeaderScriptVerifier {
    fn verify_legacy_proof(&self, header: &elements::BlockHeader,
        challenge: &elements::Script, solution: &elements::Script) -> Result<(), ElementsStateErrorV2> {
        self.verify(header, challenge, solution.as_bytes(), &[])
    }
    fn verify_dynafed_proof(&self, header: &elements::BlockHeader,
        challenge: &elements::Script, witness: &[Vec<u8>]) -> Result<(), ElementsStateErrorV2> {
        self.verify(header, challenge, &[], witness)
    }
}

impl ScriptSignatureCheckerV2 for NativeHeaderSignatureChecker {
    fn check_signature_from_stack(
        &self, signature: &[u8], data: &[u8], public_key: &[u8],
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        // CSFS always hashes stack data once and never takes a sighash byte,
        // even when the enclosing header proof uses a witness.
        NativeHeaderSignatureChecker {
            header_digest: bitcoin::hashes::sha256::Hash::hash(data).to_byte_array(),
            has_sighash_byte: false,
        }.check_ecdsa_signature(signature, public_key, &[], 0)
    }

    fn check_ecdsa_signature(
        &self,
        signature: &[u8],
        public_key: &[u8],
        _script_code: &[u8],
        _code_separator_position: usize,
    ) -> Result<bool, ScriptPrimitiveErrorV2> {
        // STRICTENC validates key shape even for an empty signature.
        if !matches!(public_key, [2 | 3, ..] if public_key.len() == 33)
            && !matches!(public_key, [4, ..] if public_key.len() == 65)
        {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        if signature.is_empty() {
            return Ok(false);
        }
        let (der, hash_type) = if self.has_sighash_byte {
            (&signature[..signature.len() - 1], signature[signature.len() - 1])
        } else {
            (signature, 1)
        };
        let parsed = Signature::from_der(der)
            .map_err(|_| ScriptPrimitiveErrorV2::Signature)?;
        // Round-trip enforces byte-exact minimal DER, including integer padding.
        if parsed.serialize_der().as_ref() != der {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        let mut normalized = parsed;
        normalized.normalize_s();
        if normalized != parsed || !matches!(hash_type & !0x80, 1..=3) {
            return Err(ScriptPrimitiveErrorV2::Signature);
        }
        // Defined but unsupported hash types are false, not encoding errors.
        if hash_type != 1 {
            return Ok(false);
        }
        let key = match PublicKey::from_slice(public_key) {
            Ok(key) => key,
            Err(_) => return Ok(false),
        };
        Ok(Secp256k1::verification_only()
            .verify_ecdsa(&Message::from_digest(self.header_digest), &parsed, &key)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;

    #[test]
    fn stack_signatures_use_data_hash_and_fail_unconditionally() {
        use ecx_full_consensus_validator_v2::script_v2::*;
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secp, &secret).serialize();
        let data = b"Alpha synthetic CSFS case";
        let digest = bitcoin::hashes::sha256::Hash::hash(data).to_byte_array();
        let signature = secp.sign_ecdsa(&Message::from_digest(digest), &secret).serialize_der().to_vec();
        let checker = NativeHeaderSignatureChecker { header_digest: [0; 32], has_sighash_byte: true };
        let run = |sig: &[u8], message: &[u8], opcode, suffix: &[u8]| {
            let mut solution = Vec::new();
            for item in [sig, message, public.as_slice()] {
                solution.push(item.len() as u8);
                solution.extend_from_slice(item);
            }
            let mut challenge = vec![opcode];
            challenge.extend_from_slice(suffix);
            verify_native_script_components_v3(&solution, &challenge, &[],
                ScriptLockContextV2::default(), &checker, &checker,
                LegacyScriptFlagsV2 { clean_stack: true, ..Default::default() })
        };
        assert!(run(&signature, data, 0xc1, &[]).is_ok());
        assert!(run(&signature, data, 0xc2, &[0x51]).is_ok());
        assert!(run(&signature, b"changed", 0xc1, &[0x91]).is_err());
        assert!(run(&[], data, 0xc1, &[0x91]).is_err());
        let mut typed = signature.clone(); typed.push(1);
        assert!(run(&typed, data, 0xc1, &[]).is_err());
    }

    #[test]
    fn matches_native_header_signature_corpus() {
        use ecx_full_consensus_validator_v2::script_v2::*;
        #[derive(serde::Deserialize)]
        struct Corpus { vectors: Vec<Vector> }
        #[derive(serde::Deserialize)]
        struct Vector {
            name: String, dynamic: bool, digest: String, solution: String,
            challenge: String, witness: Vec<String>, accepted: bool,
        }
        fn bytes(hex: &str) -> Vec<u8> {
            assert_eq!(hex.len() % 2, 0);
            (0..hex.len()).step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
        }
        // Generated by native-script-flags.mjs --export-vectors using the
        // recorded native consensus library. Synthetic keys, not live evidence.
        let corpus: Corpus = serde_json::from_str(include_str!(
            "../test-vectors/native-header-signatures.json")).unwrap();
        assert_eq!(corpus.vectors.len(), 33);
        assert_eq!(corpus.vectors.iter().filter(|v| v.accepted).count(), 14);
        for v in corpus.vectors {
            let solution = bytes(&v.solution);
            let challenge = bytes(&v.challenge);
            let witness: Vec<Vec<u8>> = v.witness.iter().map(|s| bytes(s)).collect();
            assert_eq!(v.dynamic, !witness.is_empty(), "{}", v.name);
            let checker = NativeHeaderSignatureChecker {
                header_digest: bytes(&v.digest).try_into().unwrap(),
                has_sighash_byte: !witness.is_empty(),
            };
            let accepted = script_is_push_only_v2(&solution).unwrap()
                && verify_native_script_components_v3(&solution, &challenge, &witness,
                    ScriptLockContextV2 { null_dummy: true, ..Default::default() },
                    &checker, &checker, LegacyScriptFlagsV2 {
                        require_minimal_push: true, verify_p2sh: true, clean_stack: true,
                        verify_witness: true, strict_der: true, strict_encoding: true,
                        low_s: true, ..Default::default()
                    }).is_ok();
            assert_eq!(accepted, v.accepted, "native disagreement: {}", v.name);
        }
    }

    #[test]
    fn extended_header_signature_uses_native_digest_and_exact_projection() {
        use elements::{BlockHeader, BlockHash, TxMerkleNode, BlockExtData, Script};
        use super::super::native_header_v3::{NativeHeader, EXCHANGE};
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[9;32]).unwrap();
        let public = PublicKey::from_secret_key(&secp,&key).serialize();
        let mut script = vec![33]; script.extend_from_slice(&public); script.push(0xac);
        let challenge = Script::from(script);
        let mut native = NativeHeader::from_standard(BlockHeader {
            version:1 | EXCHANGE, prev_blockhash:BlockHash::from_byte_array([1;32]),
            merkle_root:TxMerkleNode::from_byte_array([2;32]),time:123,height:7,
            ext:BlockExtData::Proof {challenge:challenge.clone(),solution:Script::new()},
        });
        native.exchange = [8;32];
        let der = secp.sign_ecdsa(&Message::from_digest(native.hash_internal().unwrap()),&key).serialize_der();
        let mut bytes = vec![der.len() as u8]; bytes.extend_from_slice(&der);
        let solution = Script::from(bytes);
        let verifier = BoundNativeHeaderVerifier(&native);
        assert!(verifier.verify_legacy_proof(&native.base,&challenge,&solution).is_ok());
        assert!(NativeHeaderScriptVerifier.verify_legacy_proof(&native.base,&challenge,&solution).is_err());
        let mut wrong_projection = native.base.clone(); wrong_projection.time += 1;
        assert!(verifier.verify_legacy_proof(&wrong_projection,&challenge,&solution).is_err());
        native.exchange[0] ^= 1;
        assert!(BoundNativeHeaderVerifier(&native).verify_legacy_proof(&native.base,&challenge,&solution).is_err());
    }
    #[test]
    fn header_script_verifies_real_legacy_and_witness_signatures() {
        use elements::{BlockHeader, BlockHash, TxMerkleNode, BlockExtData, Script};
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[9; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secp, &key).serialize();
        let mut script = vec![33];
        script.extend_from_slice(&public);
        script.push(0xac);
        let challenge = Script::from(script.clone());
        let mut header = BlockHeader { version: 1,
            prev_blockhash: BlockHash::from_byte_array([1; 32]),
            merkle_root: TxMerkleNode::from_byte_array([2; 32]), time: 123, height: 7,
            ext: BlockExtData::Proof { challenge: challenge.clone(), solution: Script::new() } };
        let sign = |h: &BlockHeader| secp.sign_ecdsa(
            &Message::from_digest(h.block_hash().to_byte_array()), &key).serialize_der().to_vec();
        let der = sign(&header);
        let mut solution = vec![der.len() as u8];
        solution.extend_from_slice(&der);
        let verifier = NativeHeaderScriptVerifier;
        assert_eq!(verifier.verify_legacy_proof(&header, &challenge, &Script::from(solution.clone())), Ok(()));
        header.time += 1;
        assert!(verifier.verify_legacy_proof(&header, &challenge, &Script::from(solution)).is_err());
        let mut program = vec![0, 32];
        program.extend_from_slice(&bitcoin::hashes::sha256::Hash::hash(&script).to_byte_array());
        let program = Script::from(program);
        // Tests the witness callback's header digest, not a full DynaFed epoch.
        let mut witness_signature = sign(&header);
        witness_signature.push(1);
        let witness = vec![witness_signature.clone(), script.clone()];
        assert_eq!(verifier.verify_dynafed_proof(&header, &program, &witness), Ok(()));
        header.time += 1;
        assert!(verifier.verify_dynafed_proof(&header, &program, &witness).is_err());
        header.time -= 1;
        witness_signature.pop();
        assert!(verifier.verify_dynafed_proof(&header, &program, &[witness_signature, script]).is_err());
        assert!(verifier.verify_legacy_proof(&header, &Script::from(vec![0x51]), &Script::from(vec![0x61])).is_err());
    }

    #[test]
    fn real_ecdsa_binds_digest_and_distinguishes_signature_modes() {
        // Synthetic test key only; never an operator or federation key.
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[7; 32]).unwrap();
        let public = PublicKey::from_secret_key(&secp, &key);
        let signature = secp.sign_ecdsa(&Message::from_digest([42; 32]), &key);
        let der = signature.serialize_der().to_vec();
        let legacy = NativeHeaderSignatureChecker { header_digest: [42; 32], has_sighash_byte: false };
        let dynamic = NativeHeaderSignatureChecker { has_sighash_byte: true, ..legacy };
        let check = |checker: &NativeHeaderSignatureChecker, bytes: &[u8]| {
            checker.check_ecdsa_signature(bytes, &public.serialize(), &[], 0)
        };
        assert_eq!(check(&legacy, &der), Ok(true));
        let mut with_type = der.clone();
        with_type.push(1);
        assert_eq!(check(&dynamic, &with_type), Ok(true));
        assert!(check(&legacy, &with_type).is_err());
        assert!(check(&dynamic, &der).is_err());
        let changed = NativeHeaderSignatureChecker { header_digest: [43; 32], ..legacy };
        assert_eq!(check(&changed, &der), Ok(false));
        for hash_type in [2, 3, 0x81, 0x82, 0x83] {
            *with_type.last_mut().unwrap() = hash_type;
            assert_eq!(check(&dynamic, &with_type), Ok(false));
        }
        *with_type.last_mut().unwrap() = 0;
        assert!(check(&dynamic, &with_type).is_err());
        assert_eq!(check(&legacy, &[]), Ok(false));
        assert!(legacy.check_ecdsa_signature(&[], &[5; 33], &[], 0).is_err());
        assert_eq!(legacy.check_ecdsa_signature(&der, &public.serialize_uncompressed(), &[], 0), Ok(true));
    }
}
