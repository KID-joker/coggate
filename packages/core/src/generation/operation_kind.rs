use super::Operation;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[allow(
    dead_code,
    reason = "Operation taxonomy is consumed by diversity planning"
)]
pub(crate) enum OperationFamily {
    Structural,
    ByteArithmetic,
    CodecDigest,
    Composition,
}

macro_rules! define_operation_kind_catalog {
    ($( $kind:ident => $family:ident, )+) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub(crate) enum OperationKind {
            $(
                $kind,
            )+
        }

        impl OperationKind {
            #[allow(
                dead_code,
                reason = "Operation taxonomy is consumed by diversity planning"
            )]
            pub(crate) const ALL: [Self; 18] = [
                $(
                    Self::$kind,
                )+
            ];

            #[allow(
                dead_code,
                reason = "Operation taxonomy is consumed by diversity planning"
            )]
            pub(crate) const fn family(self) -> OperationFamily {
                match self {
                    $(
                        Self::$kind => OperationFamily::$family,
                    )+
                }
            }
        }
    };
}

define_operation_kind_catalog! {
    Reverse => Structural,
    RotateLeft => Structural,
    RotateRight => Structural,
    EvenBytes => Structural,
    OddBytes => Structural,
    Permute => Structural,
    Slice => Structural,
    Xor => ByteArithmetic,
    AddModulo => ByteArithmetic,
    SubModulo => ByteArithmetic,
    HexEncode => CodecDigest,
    HexDecode => CodecDigest,
    Base64UrlEncode => CodecDigest,
    Base64UrlDecode => CodecDigest,
    Sha256Prefix => CodecDigest,
    Concat => Composition,
    RotateLeftDerived => Composition,
    ConditionalOrder => Composition,
}

impl From<&Operation> for OperationKind {
    fn from(operation: &Operation) -> Self {
        match operation {
            Operation::Reverse => Self::Reverse,
            Operation::RotateLeft(_) => Self::RotateLeft,
            Operation::RotateRight(_) => Self::RotateRight,
            Operation::EvenBytes => Self::EvenBytes,
            Operation::OddBytes => Self::OddBytes,
            Operation::Permute(_) => Self::Permute,
            Operation::Slice { .. } => Self::Slice,
            Operation::Xor(_) => Self::Xor,
            Operation::AddModulo => Self::AddModulo,
            Operation::SubModulo => Self::SubModulo,
            Operation::HexEncode => Self::HexEncode,
            Operation::HexDecode => Self::HexDecode,
            Operation::Base64UrlEncode => Self::Base64UrlEncode,
            Operation::Base64UrlDecode => Self::Base64UrlDecode,
            Operation::Sha256Prefix(_) => Self::Sha256Prefix,
            Operation::Concat => Self::Concat,
            Operation::RotateLeftDerived => Self::RotateLeftDerived,
            Operation::ConditionalOrder => Self::ConditionalOrder,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::generation::{Operation, OperationFamily, OperationKind};

    #[test]
    fn classifies_every_operation_kind_and_family() {
        let cases = [
            (
                Operation::Reverse,
                OperationKind::Reverse,
                OperationFamily::Structural,
            ),
            (
                Operation::RotateLeft(1),
                OperationKind::RotateLeft,
                OperationFamily::Structural,
            ),
            (
                Operation::RotateRight(1),
                OperationKind::RotateRight,
                OperationFamily::Structural,
            ),
            (
                Operation::EvenBytes,
                OperationKind::EvenBytes,
                OperationFamily::Structural,
            ),
            (
                Operation::OddBytes,
                OperationKind::OddBytes,
                OperationFamily::Structural,
            ),
            (
                Operation::Permute(vec![2, 0, 1]),
                OperationKind::Permute,
                OperationFamily::Structural,
            ),
            (
                Operation::Slice { start: 1, end: 3 },
                OperationKind::Slice,
                OperationFamily::Structural,
            ),
            (
                Operation::Xor(vec![0x20]),
                OperationKind::Xor,
                OperationFamily::ByteArithmetic,
            ),
            (
                Operation::AddModulo,
                OperationKind::AddModulo,
                OperationFamily::ByteArithmetic,
            ),
            (
                Operation::SubModulo,
                OperationKind::SubModulo,
                OperationFamily::ByteArithmetic,
            ),
            (
                Operation::HexEncode,
                OperationKind::HexEncode,
                OperationFamily::CodecDigest,
            ),
            (
                Operation::HexDecode,
                OperationKind::HexDecode,
                OperationFamily::CodecDigest,
            ),
            (
                Operation::Base64UrlEncode,
                OperationKind::Base64UrlEncode,
                OperationFamily::CodecDigest,
            ),
            (
                Operation::Base64UrlDecode,
                OperationKind::Base64UrlDecode,
                OperationFamily::CodecDigest,
            ),
            (
                Operation::Sha256Prefix(8),
                OperationKind::Sha256Prefix,
                OperationFamily::CodecDigest,
            ),
            (
                Operation::Concat,
                OperationKind::Concat,
                OperationFamily::Composition,
            ),
            (
                Operation::RotateLeftDerived,
                OperationKind::RotateLeftDerived,
                OperationFamily::Composition,
            ),
            (
                Operation::ConditionalOrder,
                OperationKind::ConditionalOrder,
                OperationFamily::Composition,
            ),
        ];

        assert_eq!(cases.len(), OperationKind::ALL.len());
        for kind in OperationKind::ALL {
            assert_eq!(
                cases
                    .iter()
                    .filter(|(_, expected_kind, _)| *expected_kind == kind)
                    .count(),
                1
            );
        }

        for (operation, expected_kind, expected_family) in cases {
            let kind = OperationKind::from(&operation);
            assert_eq!(kind, expected_kind);
            assert_eq!(kind.family(), expected_family);
        }
    }

    #[test]
    fn all_contains_each_operation_kind_exactly_once() {
        assert_eq!(OperationKind::ALL.len(), 18);

        for kind in OperationKind::ALL {
            assert_eq!(
                OperationKind::ALL
                    .iter()
                    .filter(|candidate| **candidate == kind)
                    .count(),
                1
            );
        }
    }
}
