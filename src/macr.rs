#[macro_export]
/// Do not use, internal use only
macro_rules! _rbtl_structs_impl {
    ( $([$name:ident, $struct:ty] $(,)* )* ) => {
        paste::paste! {
            pub struct RBTLListener {
                pub $( [<$name:snake>] : $struct ,)*
            }

            pub struct RBTLSendOptions {
                pub $( [<$name:snake>] : <$struct as $crate::Server>::SendOptions ,)*
            }

            /// a ConnectInfo that can only be serialized
            #[derive(Clone)]
            pub struct RBTLConnectInfo {
                pub $( [<$name:snake>] : Result<<$struct as $crate::Server>::ConnectInfo, ()> ,)*
            }

            /// a ConnectInfoParsed that can only be deserialized, using the same payload as ConnectInfo's ser payload
            #[derive(Clone)]
            pub struct RBTLConnectInfoParsed {
                pub $( [<$name:snake>] : Option<<$struct as $crate::Server>::ConnectInfo> ,)*
                pub unknown: Vec<(u8, Box<[u8]>)>,
            }

            impl RBTLConnectInfoParsed {
                pub fn num_available(&self) -> usize {
                    0
                    $( + if self.[<$name:snake>].is_none() { 0 } else { 1 } )*
                }
            }

            /// a ConnectInfo that can only be serialized
            #[derive(Clone)]
            pub struct RBTLConnectOptions {
                pub $( [<$name:snake>] : <<$struct as $crate::Server>::ConnectingClient as $crate::Client>::ConnectOptions ,)*
            }

            #[derive(Clone, Debug)]
            pub struct RBTLServConfig {
                pub $( [<$name:snake>] : <$struct as $crate::Server>::ServerConfig,)*
            }

            #[derive(Clone, Debug)]
            pub struct RBTLClientConfig {
                pub $( [<$name:snake>] : <<$struct as $crate::Server>::ConnectingClient as $crate::Client>::ClientConfig,)*
            }

            #[derive(Clone, Debug)]
            pub enum RBTLClientConfigSingle {
                $( $name(<<$struct as $crate::Server>::ConnectingClient as $crate::Client>::ClientConfig ),)*
            }

            struct RBTLConnectorInner {
                pub connect_info: RBTLConnectInfoParsed,
                pub options: RBTLConnectOptions,
                pub $( [<$name:snake _done>]: bool,)*
            }

            /// A struct to help you connect to a remote.
            ///
            /// Will try all the possible ways to connect to this remote, and if none of them are available
            /// it will output an error
            pub struct RBTLConnector {
                client: Option<RBTLClient>,
                inner: RBTLConnectorInner,
            }

            impl RBTLConnectorInner {
                fn next(&mut self) -> Option<RBTLClient> {
                    $(
                    if !self.[<$name:snake _done>] {
                        self.[<$name:snake _done>] = true;
                        if let Some(conn_info) = &self.connect_info.[<$name:snake>] {
                            let client = <<$struct as $crate::Server>::ConnectingClient as $crate::Client>::from_connect_info(
                                conn_info.clone(),
                                self.options.[<$name:snake>].clone()
                            );
                            match client {
                                Ok(client) => return Some(RBTLClient::$name(client)),
                                Err(e) => {
                                    log::error!(
                                        "protocol {} had initialization error: {}",
                                        <$struct as $crate::Server>::RBTL_PROTOCOL_NAME,
                                        e
                                    );
                                }
                            }
                        } else {
                            log::info!(
                                "protocol {} not provided in connect_info",
                                <$struct as $crate::Server>::RBTL_PROTOCOL_NAME
                            )
                        }
                    };
                    )*
                    None
                }
            }

            impl RBTLConnector {
                pub fn new(connect_info_parsed: RBTLConnectInfoParsed, options: RBTLConnectOptions) -> Result<Self, $crate::Error> {
                    let mut inner = RBTLConnectorInner {
                        connect_info: connect_info_parsed,
                        options,
                        $([<$name:snake _done>]: false,)*
                    };
                    match inner.next() {
                        Some(client) => Ok(Self { inner, client: Some(client) }),
                        None => {
                            let err = $crate::Error::new(
                                format!("no rbtl protocols are both available and compatible to connect"
                            ));
                            Err(err)
                        }
                    }
                }

                /// Does all the processing and tries to connect with any protocol available in the connector.
                ///
                /// You should loop this call regularly until it returns Some; if the inner result is Ok,
                /// you can then discard this and use the connected client. If the inner result is Err, the
                /// client couldn't connect no matter the protocol, and the connection is impossible.
                pub fn attempt_connect(&mut self) -> Option<Result<RBTLClient, $crate::Error>> {
                    let Some(client) = &mut self.client else {
                        let n = self.inner.connect_info.num_available();
                        let err = $crate::Error::new(format!("failed to connect through any of the {} protocols", n));
                        return Some(Err(err));
                    };
                    let _r = client.process();
                    match client.status() {
                        $crate::rbtl_core::Status::Connecting => None,
                        $crate::rbtl_core::Status::Ok => self.client.take().map(|c| Ok(c)),
                        _ => {
                            let n = self.inner.connect_info.num_available();
                            let err = $crate::Error::new(format!("failed to connect through any of the {} protocols", n));
                            Some(Err(err))
                        }
                    }
                }
            }
        }



        #[derive(Clone, Copy, Debug)]
        pub enum RBTLProtocolKind {
            $($name,)*
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

                pub fn set_config(&mut self, config: RBTLClientConfig) {
                    match self {
                        $( Self::$name(client) => {
                            <<$struct as $crate::Server>::ConnectingClient as $crate::Client>::set_config(
                                client,
                                config.[<$name:snake>]
                            )
                        } ,)*
                    }
                }

                pub fn get_config(&mut self) -> RBTLClientConfigSingle {
                    match self {
                        $( Self::$name(client) => {
                            let config = <<$struct as $crate::Server>::ConnectingClient as $crate::Client>::get_config(
                                client
                            );
                            RBTLClientConfigSingle::$name(config)
                        } ,)*
                    }
                }

                pub fn kind(&self) -> RBTLProtocolKind {
                    match self {
                        $( Self::$name(_) => RBTLProtocolKind::$name, )*
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

                pub fn kind(&self) -> RBTLProtocolKind {
                    match self {
                        $( Self::$name(_) => RBTLProtocolKind::$name, )*
                    }
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

                pub fn kind(&self) -> RBTLProtocolKind {
                    match self {
                        $( Self::$name(_) => RBTLProtocolKind::$name, )*
                    }
                }
            }

            impl RBTLProtocolKind {
                pub fn rbtl_protocol_name(&self) -> &'static str {
                    match self {
                        $( Self::$name => <$struct as $crate::rbtl_core::Server>::RBTL_PROTOCOL_NAME, )*
                    }
                }

                pub fn rbtl_protocol_id(&self) -> u8 {
                    match self {
                        $( Self::$name => <$struct as $crate::rbtl_core::Server>::RBTL_PROTOCOL_ID, )*
                    }
                }

                pub fn from_rbtl_protocol_id(id: u8) -> Option<Self> {
                    $( if <$struct as $crate::rbtl_core::Server>::RBTL_PROTOCOL_ID == id {
                        return Some(Self::$name)
                    } )*
                    None
                }
            }

            impl std::fmt::Display for RBTLProtocolKind {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                    write!(f, "{}", self.rbtl_protocol_name())
                }
            }

            impl RBTLListener {
                /// Create a listener with sensible defaults for each listener type
                pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
                    Ok(Self {
                        $( [<$name:snake>] : <$struct as $crate::rbtl_core::Server>::new()? ,)*
                    })
                }

                /// Returns the amount of adapters currently coded
                pub fn adapters_len() -> usize {
                    0
                        $( + <$struct as $crate::rbtl_core::Server>::RBTL_PROTOCOL_ID as usize * 0 + 1 )*
                }

                pub fn set_config(&mut self, config: RBTLServConfig) {
                    $(
                        <$struct as $crate::Server>::set_config(
                            &mut self.[<$name:snake>],
                            config.[<$name:snake>]
                        );
                    )*
                }

                pub fn get_config(&mut self) -> RBTLServConfig {
                    RBTLServConfig {
                        $( [<$name:snake>]: <$struct as $crate::Server>::get_config(&self.[<$name:snake>]), )*
                    }
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

#[macro_export]
#[cfg(feature = "serde")]
/// Creates and exports RBTL structs (serde version)
macro_rules! rbtl_structs {
    ( $([$name:ident, $struct:ty] $(,)* )* ) => {
        $crate::_rbtl_structs_impl! {
            $([$name, $struct],)*
        }

        paste::paste! {
            use $crate::serde::{Serialize, Deserialize, Serializer, Deserializer};
            use $crate::serde::de::{MapAccess, Visitor};
            use std::fmt;
            use super::*;

            impl Serialize for RBTLConnectInfo {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
                    use serde::ser::SerializeMap;

                    let mut n = 0;
                    $( if self.[<$name:snake>].is_ok() { n += 1 }; )*

                    let mut map = serializer.serialize_map(Some(n))?;

                    $(
                        let bytes: Option<Vec<u8>> = self.[<$name:snake>]
                            .as_ref()
                            .ok()
                            .and_then(|r| r.clone().try_into().ok());
                        if let Some(bytes) = bytes {
                            map.serialize_entry(&<$struct as $crate::Server>::RBTL_PROTOCOL_ID, &bytes.into_boxed_slice())?
                        }
                    )*
                    map.end()
                }
            }

            impl<'de> Deserialize<'de> for RBTLConnectInfoParsed {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    struct ConnectInfoParsedVisitor;
                    
                    impl<'de> Visitor<'de> for ConnectInfoParsedVisitor {
                        type Value = RBTLConnectInfoParsed;
                        
                        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                            formatter.write_str("ConnectInfo")
                        }
                        
                        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                        where
                            A: MapAccess<'de>,
                        {
                            let mut unknown = Vec::new();
                            $( let mut [<$name:snake>]: Option<<$struct as $crate::Server>::ConnectInfo> = None; )*
                            
                            while let Some((key, value)) = map.next_entry::<u8, Box<[u8]>>()? {
                                let mut found = false;
                                $(
                                    if key == <$struct as $crate::Server>::RBTL_PROTOCOL_ID {
                                        [<$name:snake>] = <$struct as $crate::Server>::ConnectInfo::try_from(&*value).ok();
                                        found = true;
                                    }
                                )*
                                if !found {
                                    unknown.push((key, value));
                                }
                            }
                            
                            Ok(RBTLConnectInfoParsed {
                                $([<$name:snake>],)*
                                unknown
                            })
                        }
                    }
                    
                    deserializer.deserialize_map(ConnectInfoParsedVisitor)
                }
            }
        }
    }
}


#[cfg(not(feature = "serde"))]
#[macro_export]
/// Creates and exports RBTL structs (non-serde version)
macro_rules! rbtl_structs {
    ( $([$name:ident, $struct:ty] $(,)* )* ) => {
        $crate::_rbtl_structs_impl! {
            $([$name, $struct],)*
        }
    }
}

pub (crate) use rbtl_structs;