# SPIDX

> Spider Graph Rewriting Kernel — deterministe, pur, rejouable.

SPIDX est un noyau de preuve pour l'écosystème gerivdb. Il fournit :
- un moteur de réécriture de graphe déterministe ;
- une couche de preuve (`spidx-proof`) ;
- un WAL (`spidx-wal`) pour la rejouabilité ;
- un CLI (`spidx-cli`) pour l'intégration KIVA / CI locale.

## Workspace

| Crate | Rôle |
|-------|------|
| `spidx-core` | Types et fondations du noyau |
| `spidx-canon` | Forme canonique des graphes |
| `spidx-rewrite` | Moteur de réécriture |
| `spidx-guard` | Gardes et invariants |
| `spidx-proof` | Génération de preuves SPIDX |
| `spidx-wal` | Write-Ahead Log pour rejouabilité |
| `spidx-cli` | Interface en ligne de commande |
| `spidx-fuzz` | Fuzzing |

## Intégrations

- **KIVA-CLI** : pipelines `.kiva/pipelines/*.yaml`
- **WAL** : événements `CI_RUN` avec `proof_hex`
- **CI locale** : `ci/local_pipeline.ps1` + `.kiva/pipelines/*.yaml`

## Statut

- Version : `0.1.0`
- Licence : MIT
- Toolchain : Rust 2024, edition 2024
- Profile release : LTO + codegen-units = 1

## Utilisation

```powershell
# Depuis le repo SPIDX
cargo build --release
cargo test --workspace
```

```powershell
# CI locale
powershell -ExecutionPolicy Bypass -File ci\local_pipeline.ps1 -DryRun
```
