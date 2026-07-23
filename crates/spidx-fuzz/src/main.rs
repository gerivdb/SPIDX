//! SPIDX-FUZZ — Targets de fuzzing pour libfuzzer
//!
//! Cibles :
//! - canon_fuzz : canonicalisation déterministe
//! - apply_fuzz : application de patches
//! - guard_fuzz : validation des gardes
//! - replay_fuzz : rejeu WAL

#![no_main]
use libfuzzer_sys::fuzz_target;
use spidx_core::{Graph, Node, NodeId, ZoneId, NodeAttrs, AttrValue, Hash, Patch, PatchOp};
use spidx_canon::canonicalize;
use spidx_guard::{AcyclicGuard, P4SparseGuard, GuardContext};
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

fuzz_target!(|data: &[u8]| {
    // Test 2: Application de patch + rejet
    if let Ok(patch) = bincode::deserialize::<Patch>(data) {
        let mut graph = Graph::new();
        for i in 1..=10 {
            let mut node = Node::new(NodeId(i));
            node.attrs.0.insert("val".into(), AttrValue::U64(i as u64));
            graph.add_node(node);
        }
        canonicalize(&mut graph);
        
        // Try to apply (may fail, that's OK for fuzzing)
        let _ = apply_patch_safe(&mut graph, &patch);
    }
});

fuzz_target!(|data: &[u8]| {
    // Test 3: Gardes sur graphes aléatoires
    if let Ok(graph) = bincode::deserialize::<Graph>(data) {
        let ctx = GuardContext { graph: &graph, bindings: &BTreeMap::new() };
        let _ = AcyclicGuard.check(&ctx);
        let _ = P4SparseGuard.check(&ctx);
    }
});

fuzz_target!(|data: &[u8]| {
    // Test 4: Vérification chaîne de preuves
    if let Ok(chain) = bincode::deserialize::<ProofChain>(data) {
        if let Ok(initial) = bincode::deserialize::<Graph>(data) {
            // Just test the verification logic doesn't panic
            let _ = chain.verify_chain(&initial, &[]);
        }
    }
});

fn apply_patch_safe(graph: &mut Graph, patch: &Patch) -> Result<(), String> {
    for op in &patch.ops {
        match op {
            PatchOp::AddNode { id, node } => {
                if graph.nodes.contains_key(id) { return Err("Node exists".into()); }
                graph.nodes.insert(*id, node.clone());
            }
            PatchOp::RemoveNode { id } => {
                graph.nodes.remove(id);
                graph.edges.retain(|_, e| e.src != *id && e.dst != *id);
            }
            PatchOp::AddEdge { id, edge } => {
                if graph.edges.contains_key(id) { return Err("Edge exists".into()); }
                graph.edges.insert(*id, edge.clone());
            }
            PatchOp::RemoveEdge { id } => { graph.edges.remove(id); }
            _ => {}
        }
    }
    Ok(())
}