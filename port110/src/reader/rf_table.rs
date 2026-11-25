//! RF configuration table adjustment that Sony's driver applies to some
//! firmware after every RF setting.
//!
//! The driver selects a 16-byte table key by two GetProperty bytes and the
//! GetPDDataVersion value, reads the table with InGetRCT, sets entry `1A C0`
//! of its second list to `40`, and writes the table back with InSetRCT only
//! when that changed it. Whether the reader keeps the written table across
//! power cycles is not established.

use alloc::vec::Vec;

/// Key of InGetRCT and InSetRCT.
pub(super) type Key = [u8; 16];

/// One firmware the driver adjusts.
struct Row {
    /// GetProperty bytes 14 and 15.
    property: [u8; 2],
    /// GetPDDataVersion value.
    pd_data: u16,
    key: Key,
}

const ROWS: [Row; 3] = [
    Row {
        property: [0x00, 0x07],
        pd_data: 0x0102,
        key: [
            0xf1, 0x2b, 0xce, 0x90, 0x7d, 0x8f, 0x93, 0x69, 0xa8, 0xd6, 0x93, 0xc1, 0xa5, 0xe8,
            0x89, 0xa2,
        ],
    },
    Row {
        property: [0x00, 0x13],
        pd_data: 0x0200,
        key: [
            0xf7, 0x1a, 0xd8, 0x22, 0x37, 0xeb, 0x0f, 0xb1, 0xae, 0xcf, 0xb0, 0x4b, 0x3a, 0xff,
            0x07, 0x12,
        ],
    },
    Row {
        property: [0x00, 0x14],
        pd_data: 0x0300,
        key: [
            0x0f, 0x39, 0x42, 0x89, 0x65, 0x6b, 0x78, 0xe7, 0x71, 0x0e, 0x70, 0xd2, 0xa3, 0x07,
            0x63, 0xf3,
        ],
    },
];

/// Entry that the driver requires in the second list.
const ENTRY: Entry = [0x1a, 0xc0, 0x40];
/// Most entries in one list.
const MAX_ENTRIES: u8 = 16;

type Entry = [u8; 3];

/// The table key of a reader, or `None` when the driver leaves its table alone.
pub(super) fn key(property: &[u8; 32], pd_data: u16) -> Option<&'static Key> {
    ROWS.iter()
        .find(|row| row.property == property[14..16] && row.pd_data == pd_data)
        .map(|row| &row.key)
}

/// One counted entry list, holding at most [`MAX_ENTRIES`] entries.
#[derive(Debug, PartialEq, Eq)]
struct List {
    count: u8,
    entries: [Entry; MAX_ENTRIES as usize],
}

impl List {
    fn entries(&self) -> &[Entry] {
        &self.entries[..usize::from(self.count)]
    }

    fn entries_mut(&mut self) -> &mut [Entry] {
        &mut self.entries[..usize::from(self.count)]
    }

    /// Append `entry` unless the list is full.
    fn push(&mut self, entry: Entry) -> bool {
        let Some(slot) = self.entries.get_mut(usize::from(self.count)) else {
            return false;
        };
        *slot = entry;
        self.count += 1;
        true
    }

    /// Decode one counted list from the front of `data`.
    fn parse(data: &[u8]) -> Result<(Self, &[u8]), TableError> {
        let (&count, rest) = data.split_first().ok_or(TableError::Layout)?;
        if count > MAX_ENTRIES {
            return Err(TableError::Count);
        }
        let (bytes, rest) = rest
            .split_at_checked(3 * usize::from(count))
            .ok_or(TableError::Layout)?;
        let mut entries = [[0; 3]; MAX_ENTRIES as usize];
        let (counted, _) = bytes.as_chunks::<3>();
        entries[..counted.len()].copy_from_slice(counted);
        Ok((Self { count, entries }, rest))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.count);
        out.extend(self.entries().iter().flatten());
    }
}

/// Two entry lists of an RF configuration table.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Table {
    first: List,
    second: List,
}

/// Why InGetRCT data does not hold a table.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TableError {
    /// The data does not consist of exactly two counted lists.
    Layout,
    /// A list counts more than 16 entries.
    Count,
    /// The second list is full and lacks entry `1A C0`.
    Full,
}

impl TableError {
    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::Layout => "InGetRCT list layout",
            Self::Count => "InGetRCT list count",
            Self::Full => "InGetRCT second list is full",
        }
    }
}

impl Table {
    /// Decode the lists that follow InGetRCT's status byte.
    pub(super) fn parse(data: &[u8]) -> Result<Self, TableError> {
        let (first, rest) = List::parse(data)?;
        let (second, rest) = List::parse(rest)?;
        if !rest.is_empty() {
            return Err(TableError::Layout);
        }
        Ok(Self { first, second })
    }

    /// Set entry `1A C0` of the second list to `40`, appending it when
    /// absent. Returns whether the table changed.
    pub(super) fn adjust(&mut self) -> Result<bool, TableError> {
        let [high, low, value] = ENTRY;
        if let Some(entry) = self
            .second
            .entries_mut()
            .iter_mut()
            .find(|entry| entry[..2] == [high, low])
        {
            let changed = entry[2] != value;
            entry[2] = value;
            Ok(changed)
        } else if self.second.push(ENTRY) {
            Ok(true)
        } else {
            Err(TableError::Full)
        }
    }

    /// InSetRCT arguments that write this table under `key`.
    pub(super) fn encode(&self, key: &Key) -> Vec<u8> {
        let entries = self.first.entries().len() + self.second.entries().len();
        let mut args = Vec::with_capacity(key.len() + 2 + 3 * entries);
        args.extend_from_slice(key);
        self.first.encode(&mut args);
        self.second.encode(&mut args);
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_requires_both_the_property_and_the_pd_data_version() {
        let mut property = [0; 32];
        property[14..16].copy_from_slice(&[0x00, 0x13]);
        assert_eq!(key(&property, 0x0200), Some(&ROWS[1].key));
        assert_eq!(key(&property, 0x0102), None);
        property[15] = 0x15;
        assert_eq!(key(&property, 0x0200), None);
    }

    #[test]
    fn adjustment_replaces_or_appends_the_entry_only_when_needed() -> Result<(), TableError> {
        let mut table = Table::parse(&[1, 0x10, 0x20, 0x30, 1, 0x1a, 0xc0, 0x00])?;
        assert!(table.adjust()?);
        assert_eq!(
            table.encode(&[0; 16])[16..],
            [1, 0x10, 0x20, 0x30, 1, 0x1a, 0xc0, 0x40]
        );
        assert!(!table.adjust()?);
        let mut table = Table::parse(&[0, 0])?;
        assert!(table.adjust()?);
        assert_eq!(table.encode(&[0; 16])[16..], [0, 1, 0x1a, 0xc0, 0x40]);
        Ok(())
    }

    #[test]
    fn rejects_full_overlong_and_malformed_lists() {
        let mut full = alloc::vec![0, 16];
        full.extend((0..16).flat_map(|n| [0x20, n, 0]));
        assert_eq!(
            Table::parse(&full).map(|mut t| t.adjust()),
            Ok(Err(TableError::Full))
        );
        assert_eq!(Table::parse(&[17]), Err(TableError::Count));
        assert_eq!(Table::parse(&[1, 0, 0]), Err(TableError::Layout));
        assert_eq!(Table::parse(&[0, 0, 0]), Err(TableError::Layout));
    }
}
