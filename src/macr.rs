/// Creates and exports RBTL structs
macro_rules! rbtl_structs {
    ( $([$name:ident, $struct:ty] $(,)* )* ) => {
        paste::paste! {
            pub struct RBTLListener {
                pub $( [<$name:snake>] : $struct ,)*
            }

            pub struct RBTLSendOptions {
                pub $( [<$name:snake>] : <$struct as $crate::Server>::SendOptions ,)*
            }

            pub struct RBTLConnectInfo {
                pub $( [<$name:snake>] : <$struct as $crate::Server>::ConnectInfo ,)*
            }
        }

        /// A Client, e.g. connected to a server which we don't own
        ///
        /// Basically unique, unless we are connected to multiple servers
        pub enum RBTLClient {
            $( $name(<$struct as $crate::Server>::ConnectingClient), )*
        }

        pub enum RBTLKey {
            $( $name(<$struct as $crate::Server>::Key) ,)*
        }

        pub enum RBTLMessageId {
            $( $name(<$struct as $crate::Server>::MessageId) ,)*
        }

        /// A Server Client, e.g. represents the connection to a specific client (them) from a server (us)
        /// 
        /// Basically a server holds multiple of those
        pub enum RBTLServClient<'a> {
            $( $name(&'a <$struct as $crate::Server>::ServClient), )*
        }

        /// A mutable Server Client, e.g. represents the connection to a specific client (them) from a server (us)
        ///
        /// Basically a server holds multiple of those
        pub enum RBTLServClientMut<'a> {
            $( $name(&'a mut <$struct as $crate::Server>::ServClient), )*
        }

        impl<'a> RBTLServClientMut<'a> {
            fn unmut<'b>(&'b self) -> RBTLServClient<'b> where 'a: 'b {
                match self {
                    $( RBTLServClientMut::$name(s) => RBTLServClient::$name(s) ,)*
                }
            }
        }

        paste::paste! {
            impl RBTLClient {
                // TODO
                // pub fn new() -> Self {
                
                pub fn status(&self) -> $crate::rbtl_core::Status {
                    match self {
                        $( Self::$name(client) => {
                            <<$struct as $crate::Server>::ConnectingClient as $crate::Client>::status(client)
                        } ,)*
                    }
                }

                pub fn process(&mut self) {
                    match self {
                        $( Self::$name(client) => {
                            <<$struct as $crate::Server>::ConnectingClient as $crate::Client>::process(client)
                        } ,)*
                    }
                }

                pub fn drain_events<'a>(&'a mut self) -> Box<dyn Iterator<Item=rbtl_core::Event> + 'a> {
                    match self {
                        $( Self::$name(client) => {
                            Box::new(<<$struct as $crate::Server>::ConnectingClient as $crate::Client>::drain_events(client))
                        } ,)*
                    }
                }

                pub fn send<B>(&mut self, bytes: B, send_options: RBTLSendOptions) -> Result<RBTLMessageId, Box<dyn std::error::Error>>
                    where B: Into<std::sync::Arc<[u8]>> + AsRef<[u8]> + Clone {
                    match self {
                        $( Self::$name(client) => {
                            let id = <<$struct as $crate::Server>::ConnectingClient as $crate::Client>::send(
                                client,
                                bytes,
                                send_options.[<$name:snake>]
                            )?;
                            Ok(RBTLMessageId::$name(id))
                        } ,)*
                    }
                }
            }

            impl<'a> RBTLServClientMut<'a> {
                pub fn send<B>(&mut self, bytes: B, send_options: RBTLSendOptions) -> Result<RBTLMessageId, Box<dyn std::error::Error>>
                    where B: Into<std::sync::Arc<[u8]>> + AsRef<[u8]> + Clone {
                    match self {
                        $( Self::$name(client) => {
                            let id = <<$struct as $crate::Server>::ServClient as $crate::ServClient>::send(
                                client,
                                bytes,
                                send_options.[<$name:snake>]
                            )?;
                            Ok(RBTLMessageId::$name(id))
                        } ,)*
                    }
                }

                #[inline]
                /// Returns the average ping in ms over the last given seconds.
                ///
                /// Returns `None` if there are no records yet or if the functionality is not available,
                /// but returns the latest value if the amount of seconds is too small
                pub fn ping(&self, seconds: f32) -> Option<f32> {
                    self.unmut().ping(seconds)
                }

                #[inline]
                pub fn status(&self) -> $crate::Status {
                    self.unmut().status()
                }
            }

            impl<'a> RBTLServClient<'a> {
                /// Returns the average ping in ms over the last given seconds.
                ///
                /// Returns `None` if there are no records yet or if the functionality is not available,
                /// but returns the latest value if the amount of seconds is too small
                pub fn ping(&self, seconds: f32) -> Option<f32> {
                    match self {
                        $( Self::$name(client) => {
                            <<$struct as $crate::Server>::ServClient as $crate::ServClient>::ping(client, seconds)
                        } ,)*
                    }
                }

                pub fn status(&self) -> $crate::Status {
                    match self {
                        $( Self::$name(client) => {
                            <<$struct as $crate::Server>::ServClient as $crate::ServClient>::status(client)
                        } ,)*
                    }
                }
            }

            impl RBTLListener {
                /// Create a listener with sensible defaults for each listener type
                pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
                    Ok(Self {
                        $( [<$name:snake>] : <$struct as $crate::rbtl_core::Server>::new()? ,)*
                    })
                }

                /// Send a message to all remotes
                pub fn send_all<B>(&mut self, bytes: B, send_options: RBTLSendOptions) -> Result<(), Box<dyn std::error::Error>>
                    where B: Into<std::sync::Arc<[u8]>> + AsRef<[u8]> + Clone 
                {
                    $( <$struct as $crate::Server>::send_all(
                        &mut self.[<$name:snake>],
                        bytes.clone(),
                        send_options.[<$name:snake>]
                    )?; )*
                    Ok(())
                }

                pub fn get<'a>(&'a self, key: &RBTLKey) -> Option<RBTLServClient<'a>> {
                    match key {
                        $( RBTLKey::$name(k) => <$struct as $crate::Server>::get(&self.[<$name:snake>], k)
                            .map(|serv_client| RBTLServClient::$name(serv_client)),
                        )*
                    }
                }

                pub fn get_mut<'a>(&'a mut self, key: &RBTLKey) -> Option<RBTLServClientMut<'a>> {
                    match key {
                        $( RBTLKey::$name(k) => <$struct as $crate::Server>::get_mut(&mut self.[<$name:snake>], k)
                            .map(|serv_client| RBTLServClientMut::$name(serv_client)),
                        )*
                    }
                }

                /// Returns the amount of remotes registered
                pub fn len(&self) -> usize {
                    $( <$struct as $crate::Server>::len(&self.[<$name:snake>]) + )*
                    0
                }

                /// Iters mutably through all remotes
                pub fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item=(RBTLKey, RBTLServClientMut<'a>)> {
                    std::iter::empty::<(RBTLKey, RBTLServClientMut)>()
                        $(
                            .chain( <$struct as $crate::Server>::iter_mut(&mut self.[<$name:snake>])
                                .map(|(key, sclient)| (RBTLKey::$name(key.clone()), RBTLServClientMut::$name(sclient)) )
                            )
                        )*
                }

                /// Iters through all remotes
                pub fn iter<'a>(&'a self) -> impl Iterator<Item=(RBTLKey, RBTLServClient<'a>)> {
                    std::iter::empty::<(RBTLKey, RBTLServClient)>()
                        $(
                            .chain( <$struct as $crate::Server>::iter(&self.[<$name:snake>])
                                .map(|(key, sclient)| (RBTLKey::$name(key.clone()), RBTLServClient::$name(sclient)) )
                            )
                        )*
                }

                /// Drains all events of all remotes. Must call `process` beforehand
                pub fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=(RBTLKey, rbtl_core::Event)> + 'a {
                    std::iter::empty::<(RBTLKey, rbtl_core::Event)>()
                        $(
                            .chain( <$struct as $crate::Server>::drain_events(&mut self.[<$name:snake>])
                                .map(|(key, event)| (RBTLKey::$name(key), event) )
                            )
                        )*
                }

                pub fn connect_info(&self) -> RBTLConnectInfo {
                    RBTLConnectInfo {
                        $( [<$name:snake>] : <$struct as $crate::rbtl_core::Server>::connect_info(&self.[<$name:snake>]) ,)*
                    }
                }

                /// processes event to be drained at a later time
                pub fn process(&mut self) {
                    $( <$struct as $crate::Server>::process(&mut self.[<$name:snake>]); )*
                }
            }
        }
    }
}

pub (crate) use rbtl_structs;