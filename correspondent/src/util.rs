/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

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

    pub fn get_connection(
        &self,
        key: K,
        conn_stable_id: usize,
    ) -> Option<quinn::Connection> {
        self.inner
            .get(&ConnectionEntryId {
                key,
                conn_id: conn_stable_id,
            })
            .map(|entry| entry.connection.clone())
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

pub async fn send_buf(conn: quinn::Connection, buf: &[u8]) {
    if let Ok(mut stream) = conn.open_uni().await {
        let _ = stream.write_all(buf).await;
    } else {
        //println!("failed to open stream!");
    }
}

pub mod insert {
    use futures_util::stream::{Chain, Stream, StreamExt};
    use std::{
        future::Future,
        marker::{PhantomData, Unpin},
        pin::Pin,
        task::{Context, Poll},
    };

    pub struct Insert<F, T>(F, PhantomData<Box<T>>);
    impl<F, T> Insert<F, T> {
        pub fn new(fut: F) -> Self {
            Self(fut, PhantomData)
        }
    }
    impl<F, T> Insert<Pin<Box<F>>, T> {
        pub fn new_boxed(fut: F) -> Self {
            Self::new(Box::pin(fut))
        }
    }
    impl<T, F: Future<Output = ()> + Unpin> Stream for Insert<F, T> {
        type Item = T;
        fn poll_next(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            match Pin::new(&mut self.get_mut().0).poll(cx) {
                Poll::Ready(()) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    pub trait StreamInsertExt: StreamExt + Sized {
        fn insert<F: Future<Output = ()> + Unpin>(
            self,
            fut: F,
        ) -> Chain<Self, Insert<F, Self::Item>> {
            self.chain(Insert::new(fut))
        }

        fn insert_boxed<F: Future<Output = ()>>(
            self,
            fut: F,
        ) -> Chain<Self, Insert<Pin<Box<F>>, Self::Item>> {
            self.chain(Insert::new_boxed(fut))
        }
    }

    impl<S: StreamExt + Sized> StreamInsertExt for S {}
}
