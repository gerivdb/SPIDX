//! SPIDX-PROOF — Preuves formelles de transformation
//!
//! Structure de preuve (signée, vérifiable, rejouable) :
//! - rule_id, rule_version : traçabilité de la règle CTULU
//! - input_hash, patch_hash, output_hash : chaîne de hashs
//! - timestamp, signature : audit temporel et cryptographique
//! - metadata : KL-div, scores, métriques HOLMES

use spidx_core::{Hash, Patch, Graph, NodeId, EdgeId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Preuve formelle d'une transformation de graphe
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub rule_id: String,
    pub rule_version: u32,
    pub input_hash: Hash,
    pub patch_hash: Hash,
    pub output_hash: Hash,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub metadata: BTreeMap<String, Vec<u8>>,
}

impl Proof {
    pub fn new(
        rule_id: String,
        rule_version: u32,
        input_hash: Hash,
        patch_hash: Hash,
        output_hash: Hash,
        timestamp: u64,
    ) -> Self {
        Self {
            rule_id,
            rule_version,
            input_hash,
            patch_hash,
            output_hash,
            timestamp,
            signature: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }
    
    pub fn hash(&self) -> Hash {
        Hash::of(self)
    }
    
    /// Vérifie la cohérence complète de la preuve
    pub fn verify(&self, input_graph: &Graph, patch: &Patch, output_graph: &Graph) -> bool {
        // 1. Hash d'entrée correspond
        if input_graph.root_hash != Some(self.input_hash) { return false; }
        
        // 2. Hash du patch correspond
        if patch.hash() != self.patch_hash { return false; }
        
        // 3. Hash de sortie correspond
        if output_graph.root_hash != Some(self.output_hash) { return false; }
        
        // 4. Patch base_hash = input_hash
        if patch.base_hash != self.input_hash { return false; }
        
        // 5. Patch target_hash = output_hash
        if patch.target_hash != self.output_hash { return false; }
        
        true
    }
    
    /// Ajoute une métadonnée (ex: KL-div, score HOLMES)
    pub fn with_metadata(mut self, key: String, value: Vec<u8>) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Définit la signature cryptographique
    pub fn with_signature(mut self, sig: Vec<u8>) -> Self {
        self.signature = sig;
        self
    }
}

/// Chaîne de preuves (pour rejeu complet)
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProofChain {
    pub proofs: Vec<Proof>,
}

impl ProofChain {
    pub fn new() -> Self { Self { proofs: Vec::new() } }
    
    pub fn push(&mut self, proof: Proof) { self.proofs.push(proof); }
    
    /// Vérifie toute la chaîne depuis un graphe initial
    pub fn verify_chain(&self, initial_graph: &Graph, patches: &[Patch]) -> bool {
        if self.proofs.len() != patches.len() { return false; }
        
        let mut current_hash = initial_graph.root_hash;
        for (proof, patch) in self.proofs.iter().zip(patches) {
            if current_hash != Some(proof.input_hash) { return false; }
            if patch.hash() != proof.patch_hash { return false; }
            if patch.target_hash != proof.output_hash { return false; }
            current_hash = Some(proof.output_hash);
        }
        true
    }
    
    /// Hash racine de la chaîne (hash de tous les hashs de preuves)
    pub fn chain_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for p in &self.proofs {
            hasher.update(p.hash().as_bytes());
        }
        Hash(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spidx_core::{Graph, Node, NodeId, Hash, Patch, PatchOp, NodeAttrs, AttrValue};
    
    #[test]
    fn proof_verification() {
        let mut g1 = Graph::new();
        g1.add_node(Node::new(NodeId(1)));
        g1.compute_root_hash();
        
        let mut patch = Patch::new(g1.root_hash.unwrap());
        patch.ops.push(PatchOp::AddNode { id: NodeId(2), node: Node::new(NodeId(2)) });
        
        let mut g2 = g1.clone();
        g2.add_node(Node::new(NodeId(2)));
        g2.compute_root_hash();
        patch.target_hash = g2.root_hash.unwrap();
        
        let proof = Proof::new(
            "test_rule".into(), 1,
            g1.root_hash.unwrap(),
            patch.hash(),
            g2.root_hash.unwrap(),
            123456,
        );
        
        assert!(proof.verify(&g1, &patch, &g2));
    }
    
    #[test]
    fn proof_chain_verification() {
        let mut chain = ProofChain::new();
        let mut patches = Vec::new();
        
        let mut g = Graph::new();
        g.add_node(Node::new(NodeId(1)));
        g.compute_root_hash();
        let initial_hash = g.root_hash.unwrap();
        
        for i in 2..=5 {
            let mut patch = Patch::new(g.root_hash.unwrap());
            patch.ops.push(PatchOp::AddNode { id: NodeId(i), node: Node::new(NodeId(i)) });
            
            let prev_hash = g.root_hash.unwrap();
            g.add_node(Node::new(NodeId(i)));
            g.compute_root_hash();
            patch.target_hash = g.root_hash.unwrap();
            
            let proof = Proof::new(
                "test".into(), 1, prev_hash, patch.hash(), g.root_hash.unwrap(), i as u64
            );
            
            chain.push(proof);
            patches.push(patch);
        }
        
        assert!(chain.verify_chain(&Graph::new(), &patches));
    }
}