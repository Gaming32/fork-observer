//! Identifies the mining pool of a block from its coinbase transaction, the
//! same way mempool's `matchBlockMiner` does, using the bundled pool list from
//! `mining-pools/pools-v2.json`.

use bitcoin_pool_identification::Pool;
use corepc_client::bitcoin::{Address, Network, Transaction};
use itertools::Itertools;
use log::warn;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::str::FromStr;

/// A mining pool from the pool list, prepared for matching against coinbases.
pub struct MatchablePool {
    pub name: String,
    /// Addresses valid for the network being identified on.
    addresses: Vec<String>,
    /// The pool's tags, compiled as case-insensitive regexes.
    tags: Vec<Regex>,
}

/// Loads the bundled pool list for `network`, DATUM pools first (their
/// coinbases may also contain the tag of the miner's own pool), with each
/// pool's addresses filtered to `network` and its tags compiled as
/// case-insensitive regexes, as mempool does.
pub fn load_pools(network: Network) -> Vec<MatchablePool> {
    #[derive(Deserialize)]
    struct PoolWithDatum {
        #[serde(default, rename = "DATUM")]
        datum: bool,
        #[serde(flatten)]
        pool: Pool,
    }
    let (datum_pools, non_datum_pools) =
        serde_json::from_str::<Vec<PoolWithDatum>>(include_str!("../mining-pools/pools-v2.json"))
            .expect("the pool JSON list should be parseable")
            .into_iter()
            .partition::<Vec<_>, _>(|pool| pool.datum);
    datum_pools
        .into_iter()
        .chain(non_datum_pools)
        .map(|PoolWithDatum { pool, .. }| MatchablePool {
            addresses: pool
                .addresses
                .into_iter()
                .filter(|addr| {
                    Address::from_str(addr)
                        .unwrap()
                        .is_valid_for_network(network)
                })
                .collect(),
            tags: pool
                .tags
                .iter()
                .filter_map(|tag| {
                    RegexBuilder::new(tag)
                        .case_insensitive(true)
                        .build()
                        .inspect_err(|e| {
                            warn!(
                                "Skipping invalid tag regex {:?} of pool {}: {}",
                                tag, pool.name, e
                            )
                        })
                        .ok()
                })
                .collect(),
            name: pool.name,
        })
        .collect_vec()
}

/// Identifies the mining pool of a coinbase transaction the way mempool's
/// `matchBlockMiner` does. Pools are checked one at a time, in order: a pool's
/// addresses are compared against the coinbase output addresses first, then
/// its tag regexes against the coinbase script_sig, before moving on to the
/// next pool. The script_sig is decoded one byte per character (like
/// mempool's `hex2ascii`), not as UTF-8.
pub fn identify_pool<'a>(
    coinbase: &Transaction,
    network: Network,
    pools: &'a [MatchablePool],
) -> Option<&'a MatchablePool> {
    let addresses = coinbase
        .output
        .iter()
        .filter_map(|out| Address::from_script(&out.script_pubkey, network).ok())
        .map(|addr| addr.to_string())
        .collect::<BTreeSet<_>>();
    let script_sig = coinbase
        .input
        .first()?
        .script_sig
        .as_bytes()
        .iter()
        .map(|&b| char::from(b))
        .collect::<String>();
    pools.iter().find(|pool| {
        pool.addresses.iter().any(|addr| addresses.contains(addr))
            || pool.tags.iter().any(|tag| tag.is_match(&script_sig))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use corepc_client::bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness, absolute::LockTime,
        transaction::Version,
    };

    fn coinbase(script_sig: &[u8], output_address: Option<&str>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: output_address
                    .map(|a| {
                        Address::from_str(a)
                            .unwrap()
                            .assume_checked()
                            .script_pubkey()
                    })
                    .unwrap_or_default(),
            }],
        }
    }

    fn pool(name: &str, addresses: &[&str], tags: &[&str]) -> MatchablePool {
        MatchablePool {
            name: name.to_string(),
            addresses: addresses.iter().map(|a| a.to_string()).collect(),
            tags: tags
                .iter()
                .map(|t| RegexBuilder::new(t).case_insensitive(true).build().unwrap())
                .collect(),
        }
    }

    const ADDR: &str = "1PzVut5X6Nx7Mv4JHHKPtVM9Jr9LJ4Rbry";

    #[test]
    fn all_bundled_tags_compile() {
        let raw: Vec<Pool> =
            serde_json::from_str(include_str!("../mining-pools/pools-v2.json")).unwrap();
        let expected: usize = raw.iter().map(|p| p.tags.len()).sum();
        let loaded: usize = load_pools(Network::Bitcoin)
            .iter()
            .map(|p| p.tags.len())
            .sum();
        assert_eq!(loaded, expected);
    }

    #[test]
    fn earlier_pool_tag_beats_later_pool_address() {
        let pools = [
            pool("Tagged", &[], &["/tagged/"]),
            pool("Addressed", &[ADDR], &[]),
        ];
        let tx = coinbase(b"\x03abc/tagged/", Some(ADDR));
        let found = identify_pool(&tx, Network::Bitcoin, &pools).unwrap();
        assert_eq!(found.name, "Tagged");
    }

    #[test]
    fn address_matches_without_tag() {
        let pools = [
            pool("Other", &[], &["/other/"]),
            pool("Addressed", &[ADDR], &[]),
        ];
        let tx = coinbase(b"\x03abc/nothing/", Some(ADDR));
        let found = identify_pool(&tx, Network::Bitcoin, &pools).unwrap();
        assert_eq!(found.name, "Addressed");
    }

    #[test]
    fn tags_match_case_insensitively_as_regexes() {
        let pools = [pool("Dot", &[], &["pool.io"])];
        assert!(identify_pool(&coinbase(b"\xffPOOL.IO", None), Network::Bitcoin, &pools).is_some());
        // `.` is a regex wildcard, as in mempool
        assert!(identify_pool(&coinbase(b"poolxio", None), Network::Bitcoin, &pools).is_some());
        assert!(identify_pool(&coinbase(b"nope", None), Network::Bitcoin, &pools).is_none());
    }

    #[test]
    fn script_sig_is_decoded_byte_per_char() {
        // Like mempool's hex2ascii, multi-byte UTF-8 in the script_sig does not
        // decode to the original character.
        let pools = [pool("Fish", &[], &["🐟"])];
        let tx = coinbase("🐟".as_bytes(), None);
        assert!(identify_pool(&tx, Network::Bitcoin, &pools).is_none());
    }
}
