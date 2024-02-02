use chia_protocol::{Bytes32, Coin};
use chia_wallet_sdk::{Condition, CreateCoin};
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::{curry_tree_hash, tree_hash_atom};
use clvmr::NodePtr;
use hex_literal::hex;
use num_bigint::BigInt;

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct MirrorArgs<M> {
    pub morpher: M,
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct MirrorSolution<I, S> {
    pub parent_parent_id: Bytes32,
    pub parent_inner_puzzle: I,
    pub parent_amount: u64,
    pub parent_solution: S,
}

pub const MIRROR_PUZZLE: [u8; 242] = hex!(
    "
    ff02ffff01ff04ffff04ff08ffff04ffff02ff0affff04ff02ffff04ff0bffff
    04ffff02ff05ffff02ff0effff04ff02ffff04ff17ff8080808080ffff04ff2f
    ff808080808080ff808080ffff02ff17ff5f8080ffff04ffff01ffff4720ffff
    02ffff03ffff22ffff09ffff0dff0580ff0c80ffff09ffff0dff0b80ff0c80ff
    ff15ff17ffff0181ff8080ffff01ff0bff05ff0bff1780ffff01ff088080ff01
    80ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff0effff04ff02ff
    ff04ff09ff80808080ffff02ff0effff04ff02ffff04ff0dff8080808080ffff
    01ff0bffff0101ff058080ff0180ff018080
    "
);

pub const MIRROR_PUZZLE_HASH: [u8; 32] = hex!(
    "
    b10ce2d0b18dcf8c21ddfaf55d9b9f0adcbf1e0beb55b1a8b9cad9bbff4e5f22
    "
);

pub fn morph_launcher_id(launcher_id: [u8; 32]) -> [u8; 32] {
    let launcher_id_int = BigInt::from_signed_bytes_be(&launcher_id);
    let morphed_int = launcher_id_int + BigInt::from(1);

    let mut bytes = morphed_int.to_signed_bytes_be();
    if bytes.len() > 32 {
        return [0; 32];
    }

    while bytes.len() < 32 {
        bytes.insert(0, 0u8);
    }

    bytes.try_into().unwrap()
}

pub fn urls_from_conditions(
    coin: &Coin,
    parent_conditions: &[Condition<NodePtr>],
) -> Option<Vec<String>> {
    parent_conditions.iter().find_map(|condition| {
        let Condition::CreateCoin(CreateCoin::Memos {
            puzzle_hash,
            amount,
            memos,
        }) = condition
        else {
            return None;
        };

        if puzzle_hash != &coin.puzzle_hash || *amount != coin.amount {
            return None;
        }

        memos
            .iter()
            .skip(1)
            .map(|memo| String::from_utf8(memo.as_ref().to_vec()).ok())
            .collect()
    })
}

pub fn server_coin_hash() -> [u8; 32] {
    let morpher = tree_hash_atom(&u64_to_bytes(1));
    mirror_puzzle_hash(morpher)
}

pub fn mirror_puzzle_hash(morpher: [u8; 32]) -> [u8; 32] {
    curry_tree_hash(MIRROR_PUZZLE_HASH, &[morpher])
}

fn u64_to_bytes(amount: u64) -> Vec<u8> {
    let bytes: Vec<u8> = amount.to_be_bytes().into();
    let mut slice = bytes.as_slice();

    // Remove leading zeros.
    while (!slice.is_empty()) && (slice[0] == 0) {
        if slice.len() > 1 && (slice[1] & 0x80 == 0x80) {
            break;
        }
        slice = &slice[1..];
    }

    slice.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_morph() {
        let mut id = [3u8; 32];
        id[31] = 255;

        let mut expected = id;
        expected[31] = 0;
        expected[30] = 4;

        let actual = morph_launcher_id(id);

        assert_eq!(hex::encode(actual), hex::encode(expected));
    }
}
