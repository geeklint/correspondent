use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId<T>(pub T, usize);

pub type Peer = ();

#[derive(Debug)]
pub struct Socket<App> {
    app: Arc<App>,
}

impl<App> Clone for Socket<App> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
        }
    }
}

impl<App> Socket<App> {
    pub fn port(&self) -> Option<u16> {
        todo!()
    }
}

impl<App: crate::application::Application> Socket<App> {
    pub fn identity(&self) -> &App::Identity {
        todo!()
    }

    pub async fn connect_local(
        &self,
        peer: crate::nsd::PeerEntry<App::Identity>,
    ) -> Result<(), ()> {
        todo!()
    }
}
