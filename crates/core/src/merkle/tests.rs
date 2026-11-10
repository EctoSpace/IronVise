use super::*;

/// Roots computed independently (Python `hashlib`, from the rules at the
/// top of this file). Every certificate's `merkle_root` and every SDK
/// verifier depends on these bytes; a change to the prefixes, the child
/// order or the odd-leaf rule fails here even if builder and verifier
/// change together.
#[test]
fn roots_match_independently_computed_values() {
    for (leaves, want) in [
        (
            &["abc123"][..],
            "f49c83b211209d6a87e0bbdf83ce5a3031b1f309f3b0406c98a281e311d48beb",
        ),
        (
            &["a", "b"][..],
            "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb",
        ),
        (
            &["a", "b", "c"][..],
            "e9636069c740c9ff51625b01a0b040396d265a9b920cc6febdfa5ecc9f58ecce",
        ),
        (
            &["a", "b", "c", "d", "e"][..],
            "605c72ca9351dd39f38678f4c1326df06d8fb1a58272792acaf70e8c191fb823",
        ),
    ] {
        let tree = build_merkle_tree(leaves).unwrap();
        assert_eq!(root(&tree).unwrap(), want, "{leaves:?}");
    }
}

/// The proof for the odd leaf out: its own duplicate on the right, then
/// the left pair's node on the left, with those exact hashes.
#[test]
fn a_proof_names_each_sibling_and_its_side() {
    let tree = build_merkle_tree(&["a", "b", "c"]).unwrap();
    let p = proof(&tree, 2).unwrap();
    assert_eq!(p.leaf_index, 2);
    let path: Vec<(&str, &str)> = p
        .path
        .iter()
        .map(|n| (n.side.as_str(), n.hash.as_str()))
        .collect();
    assert_eq!(
        path,
        [
            (
                "right",
                "597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8"
            ),
            (
                "left",
                "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb"
            ),
        ]
    );
    let p = proof(&tree, 1).unwrap();
    assert_eq!(p.path[0].side, "left");
    assert_eq!(p.path[1].side, "right");
}

/// A valid proof for one leaf proves nothing about another, and a proof
/// whose sides are swapped or unknown does not verify.
#[test]
fn a_proof_is_bound_to_its_leaf_and_its_sides() {
    let tree = build_merkle_tree(&["a", "b", "c", "d"]).unwrap();
    let r = root(&tree).unwrap();
    let p = proof(&tree, 1).unwrap();
    assert!(verify_proof(&r, "b", &p).unwrap());
    assert!(!verify_proof(&r, "a", &p).unwrap());
    let mut swapped = p.clone();
    for n in &mut swapped.path {
        n.side = if n.side == "left" { "right" } else { "left" }.into();
    }
    assert!(!verify_proof(&r, "b", &swapped).unwrap());
    let mut unknown = p.clone();
    unknown.path[0].side = "up".into();
    assert!(!verify_proof(&r, "b", &unknown).unwrap());
    assert!(matches!(
        verify_proof("not hex", "b", &p),
        Err(MerkleError::InvalidHex(_))
    ));
}

#[test]
fn a_proof_for_a_leaf_that_is_not_there_is_refused() {
    let tree = build_merkle_tree(&["a", "b", "c"]).unwrap();
    assert!(matches!(
        proof(&tree, 3),
        Err(MerkleError::IndexOutOfRange {
            leaf_idx: 3,
            leaf_count: 3
        })
    ));
    assert!(proof(&tree, 2).is_ok());
    let empty = build_merkle_tree(&[]).unwrap();
    assert!(matches!(proof(&empty, 0), Err(MerkleError::EmptyTree)));
}

#[test]
fn test_single_leaf() {
    let tree = build_merkle_tree(&["abc123"]).unwrap();
    let r = root(&tree).unwrap();
    assert!(!r.is_empty());
    let p = proof(&tree, 0).unwrap();
    assert!(verify_proof(&r, "abc123", &p).unwrap());
}

#[test]
fn test_even_leaves() {
    let hashes = ["a", "b", "c", "d"];
    let tree = build_merkle_tree(&hashes).unwrap();
    let r = root(&tree).unwrap();
    for (i, h) in hashes.iter().enumerate() {
        let p = proof(&tree, i).unwrap();
        assert!(
            verify_proof(&r, h, &p).unwrap(),
            "proof failed for leaf {i}"
        );
    }
}

#[test]
fn test_odd_leaves() {
    let hashes = ["a", "b", "c"];
    let tree = build_merkle_tree(&hashes).unwrap();
    let r = root(&tree).unwrap();
    for (i, h) in hashes.iter().enumerate() {
        let p = proof(&tree, i).unwrap();
        assert!(
            verify_proof(&r, h, &p).unwrap(),
            "proof failed for leaf {i}"
        );
    }
}

#[test]
fn test_invalid_proof() {
    let tree = build_merkle_tree(&["real_hash"]).unwrap();
    let r = root(&tree).unwrap();
    let p = proof(&tree, 0).unwrap();
    assert!(!verify_proof(&r, "wrong_hash", &p).unwrap());
}

#[test]
fn test_empty_tree() {
    let tree = build_merkle_tree(&[]).unwrap();
    assert!(matches!(root(&tree), Err(MerkleError::EmptyTree)));
}

#[test]
fn test_malformed_proof_node_returns_err() {
    let tree = build_merkle_tree(&["hash1", "hash2"]).unwrap();
    let r = root(&tree).unwrap();
    let mut p = proof(&tree, 0).unwrap();
    // Corrupt the proof path with an invalid hex string.
    p.path[0].hash = "not-valid-hex!!!".to_string();
    assert!(
        matches!(
            verify_proof(&r, "hash1", &p),
            Err(MerkleError::InvalidHex(_))
        ),
        "expected InvalidHex error for malformed proof node"
    );
}

#[test]
fn proof_index_at_usize_max_is_out_of_range_not_a_panic() {
    let tree = build_merkle_tree(&["a", "b", "c"]).unwrap();
    assert!(matches!(
        proof(&tree, usize::MAX),
        Err(MerkleError::IndexOutOfRange { leaf_idx, leaf_count })
            if leaf_idx == usize::MAX && leaf_count == 3
    ));
}

#[test]
fn leaves_need_not_be_valid_hex() {
    // Only internal `combine()` nodes are hex-decoded; raw leaf content
    // (here, content hashes are hashed as bytes, not parsed as hex) may
    // be any string.
    let leaves = ["not-hex-at-all!!", "😀 unicode", ""];
    let tree = build_merkle_tree(&leaves).unwrap();
    let r = root(&tree).unwrap();
    for (i, leaf) in leaves.iter().enumerate() {
        let p = proof(&tree, i).unwrap();
        assert!(verify_proof(&r, leaf, &p).unwrap(), "leaf {i}");
    }
}

#[test]
fn power_of_two_and_boundary_leaf_counts_all_verify() {
    for n in [1usize, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33] {
        let leaves: Vec<String> = (0..n).map(|i| format!("leaf-{i}")).collect();
        let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let tree = build_merkle_tree(&leaf_refs).unwrap();
        let r = root(&tree).unwrap();
        for (i, leaf) in leaf_refs.iter().enumerate() {
            let p = proof(&tree, i).unwrap();
            assert!(verify_proof(&r, leaf, &p).unwrap(), "n={n} i={i}");
        }
    }
}

#[test]
fn a_thousand_leaves_all_verify() {
    let leaves: Vec<String> = (0..1000).map(|i| format!("event-{i}")).collect();
    let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    let tree = build_merkle_tree(&leaf_refs).unwrap();
    let r = root(&tree).unwrap();
    for i in [0usize, 1, 499, 500, 998, 999] {
        let p = proof(&tree, i).unwrap();
        assert!(verify_proof(&r, &leaves[i], &p).unwrap(), "i={i}");
    }
    // Proof depth is ceil(log2(1000)) = 10.
    assert_eq!(proof(&tree, 0).unwrap().path.len(), 10);
}

#[test]
fn verify_proof_rejects_the_wrong_root() {
    let tree = build_merkle_tree(&["a", "b", "c", "d"]).unwrap();
    let p = proof(&tree, 0).unwrap();
    let other_tree = build_merkle_tree(&["x", "y", "z", "w"]).unwrap();
    let other_root = root(&other_tree).unwrap();
    assert!(!verify_proof(&other_root, "a", &p).unwrap());
}

#[test]
fn verify_proof_with_empty_path_only_matches_a_single_leaf_tree() {
    let tree = build_merkle_tree(&["only"]).unwrap();
    let r = root(&tree).unwrap();
    let empty_proof = MerkleProof {
        leaf_index: 0,
        path: vec![],
    };
    assert!(verify_proof(&r, "only", &empty_proof).unwrap());

    // The same empty-path proof against a multi-leaf root does not verify
    // (it only re-derives the bare leaf hash, never reaching the root).
    let multi = build_merkle_tree(&["a", "b"]).unwrap();
    let multi_root = root(&multi).unwrap();
    assert!(!verify_proof(&multi_root, "a", &empty_proof).unwrap());
}

#[test]
fn verify_proof_rejects_an_overlong_proof() {
    let tree = build_merkle_tree(&["a", "b"]).unwrap();
    let r = root(&tree).unwrap();
    let mut p = proof(&tree, 0).unwrap();
    let extra = p.path[0].clone();
    p.path.push(extra);
    assert!(!verify_proof(&r, "a", &p).unwrap());
}

/// Documents intended behaviour (cf. CVE-2012-2459 for why other Merkle
/// implementations treat this differently): an odd-length leaf layer is
/// extended by duplicating the last leaf, so a tree with an explicit
/// trailing duplicate produces the same root as the corresponding
/// odd-length tree without it. This is a compatibility contract - do not
/// change `build_merkle_tree`'s odd-leaf handling to alter this.
#[test]
fn odd_leaf_is_paired_with_itself_so_trailing_duplicate_has_same_root() {
    let odd = build_merkle_tree(&["a", "b", "c"]).unwrap();
    let padded = build_merkle_tree(&["a", "b", "c", "c"]).unwrap();
    assert_eq!(
        root(&odd).unwrap(),
        root(&padded).unwrap(),
        "a 3-leaf tree's root must equal an explicit 4-leaf tree with a repeated last leaf"
    );
}
