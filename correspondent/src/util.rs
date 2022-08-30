/* SPDX-License-Identifier: (Apache-2.0 OR MIT OR Zlib) */
/* Copyright © 2021 Violet Leonard */

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
