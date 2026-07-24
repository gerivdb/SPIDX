//! SPIDX-FUZZ — Targets de fuzzing pour libfuzzer
//!
//! Cibles :
//! - canon_fuzz : canonicalisation déterministe
//! - apply_fuzz : application de patches
//! - guard_fuzz : validation des gardes
//! - replay_fuzz : rejeu WAL

#![no_main]
use libfuzzer_sys::fuzz_target;
use spidx_core::{Graph, Node, NodeId, NodeAttrs, AttrValue, Hash, Patch, PatchOp};
use spidx_canon::canonicalize;
use spidx_guard::{AcyclicGuard, P4SparseGuard, GuardContext, Guard};
use spidx_proof::{Proof, ProofChain};
use spidx_wal::{Wal, WalEntry};
use std::collections::BTreeMap;

fuzz_target!(|data: &[u8]| {
    // Test 1: Canonicalisation déterministe
    if let Ok(mut graph) = bincode::deserialize::<Graph>(data) {
        let h1 = canonicalize(&mut graph);
        let mut graph2 = graph.clone();
        let h2 = canonicalize(&mut graph2);
        assert_eq!(h1, h2, "Canonicalization not deterministic");
    }
});
