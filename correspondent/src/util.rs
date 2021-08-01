/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

use std::path::Path;

#[derive(Clone, Debug)]
pub struct ConnectionSet<K> {
    inner: std::collections::BTreeSet<ConnectionEntry<K>>,
}

impl<K: Ord> Default for ConnectionSet<K> {
    fn default() -> Self {
        Self {
            inner: std::collections::BTreeSet::default(),
        }
    }
}

impl<K> ConnectionSet<K> {
    pub fn iter(&self) -> impl Iterator<Item = &quinn::Connection> {
        self.inner.iter().map(|entry| &entry.connection)
    }
}

impl<K: Ord> ConnectionSet<K> {
    pub fn insert(&mut self, key: K, connection: quinn::Connection) {
        let value = ConnectionEntry {
            id: ConnectionEntryId {
                key,
                conn_id: connection.stable_id(),
            },
            connection,
        };
        self.inner.insert(value);
    }

    pub fn remove(&mut self, key: K, connection: &quinn::Connection) {
        self.inner.remove(&ConnectionEntryId {
            key,
            conn_id: connection.stable_id(),
        });
    }
}

impl<K: Ord + Clone> ConnectionSet<K> {
    fn get_range(key: K) -> std::ops::RangeInclusive<ConnectionEntryId<K>> {
        std::ops::RangeInclusive::new(
            ConnectionEntryId {
                key: key.clone(),
                conn_id: usize::MIN,
            },
            ConnectionEntryId {
                key,
                conn_id: usize::MAX,
            },
        )
    }

    pub fn remove_all(&mut self, key: K) {
        let range = Self::get_range(key);
        while let Some(entry) = self.inner.range(range.clone()).next() {
            let id = entry.id.clone();
            self.inner.remove(&id);
        }
    }

    pub fn connections(
        &self,
        key: K,
    ) -> impl Iterator<Item = &quinn::Connection> {
        self.inner
            .range(Self::get_range(key))
            .map(|entry| &entry.connection)
    }

    pub fn contains(&self, key: K) -> bool {
        self.connections(key).next().is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ConnectionEntryId<K> {
    pub key: K,
    pub conn_id: usize,
}

#[derive(Clone, Debug)]
struct ConnectionEntry<K> {
    pub id: ConnectionEntryId<K>,
    pub connection: quinn::Connection,
}

impl<K> std::borrow::Borrow<ConnectionEntryId<K>> for ConnectionEntry<K> {
    fn borrow(&self) -> &ConnectionEntryId<K> {
        &self.id
    }
}

impl<K: PartialEq> PartialEq for ConnectionEntry<K> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<K: Eq> Eq for ConnectionEntry<K> {}

impl<K: PartialOrd> PartialOrd for ConnectionEntry<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.id.partial_cmp(&other.id)
    }
}

impl<K: Ord> Ord for ConnectionEntry<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

pub async fn send_buf<'a, S: 'a + quinn::crypto::Session>(
    conn: quinn::generic::Connection<S>,
    buf: &'a [u8],
) {
    if let Ok(mut stream) = conn.open_uni().await {
        let _ = stream.write_all(buf).await;
    } else {
        //println!("failed to open stream!");
    }
}

pub async fn write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut new_save = path.to_path_buf();
    let mut name = path
        .file_name()
        .expect("Tried to save a file without a filename")
        .to_os_string();
    name.push("~");
    new_save.set_file_name(name);
    tokio::fs::write(&new_save, data).await?;
    tokio::fs::rename(new_save, path).await?;
    Ok(())
}
