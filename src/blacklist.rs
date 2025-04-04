use arc_swap::ArcSwap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iprange::IpRange;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct BlacklistCache(pub ArcSwap<IpRangeMixed>);

impl BlacklistCache {
    pub fn new(range: IpRangeMixed) -> Self {
        Self(ArcSwap::new(Arc::new(range)))
    }
    pub fn store(&self, blacklist: IpRangeMixed) {
        let mut blacklist = blacklist;
        blacklist.simplify();

        self.0.store(Arc::new(blacklist));
    }
    pub fn load(&self) -> Arc<IpRangeMixed> {
        self.0.load_full()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.load().contains(&ip)
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct IpRangeMixed {
    pub v4: IpRange<Ipv4Net>,
    pub v6: IpRange<Ipv6Net>,
}

impl IpRangeMixed {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    fn simplify(&mut self) {
        self.v4.simplify();
        self.v6.simplify();
    }

    pub fn into_ips(self) -> Vec<IpAddr> {
        self.v4
            .iter()
            .flat_map(|net| net.hosts())
            .map(IpAddr::V4)
            .chain(self.v6.iter().flat_map(|net| net.hosts()).map(IpAddr::V6))
            .collect()
    }

    pub fn into_nets(self) -> Vec<IpNet> {
        self.v4
            .iter()
            .map(IpNet::V4)
            .chain(self.v6.iter().map(IpNet::V6))
            .collect()
    }

    /// Returns a new `IpRangeMixed` which contains all networks
    /// that are in `self` while not in `other`.
    pub fn exclude(&self, other: &IpRangeMixed) -> Self {
        Self {
            v4: self.v4.exclude(&other.v4),
            v6: self.v6.exclude(&other.v6),
        }
    }

    /// Returns a new `IpRangeMixed` which contains all networks
    /// that are in `self` or in `other`.
    pub fn merge(&self, other: &IpRangeMixed) -> Self {
        Self {
            v4: self.v4.merge(&other.v4),
            v6: self.v6.merge(&other.v6),
        }
    }

    /// Returns a new `IpRangeMixed` which contains all networks
    /// that are in both `self` and `other`.
    pub fn intersect(&self, other: &IpRangeMixed) -> Self {
        Self {
            v4: self.v4.intersect(&other.v4),
            v6: self.v6.intersect(&other.v6),
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.v4.contains(ip),
            IpAddr::V6(ip) => self.v6.contains(ip),
        }
    }
}
impl<I: IntoIterator<Item = IpNet>> From<I> for IpRangeMixed {
    fn from(value: I) -> Self {
        let (allow_list_v4, allow_list_v6) = split_nets(value);

        Self {
            v4: iprange::IpRange::from_iter(allow_list_v4),
            v6: iprange::IpRange::from_iter(allow_list_v6),
        }
    }
}

fn split_nets(nets: impl IntoIterator<Item = IpNet>) -> (Vec<Ipv4Net>, Vec<Ipv6Net>) {
    let mut nets_ipv4 = Vec::new();
    let mut nets_ipv6 = Vec::new();

    for net in nets {
        match net {
            IpNet::V4(ipv4) => nets_ipv4.push(ipv4),
            IpNet::V6(ipv6) => nets_ipv6.push(ipv6),
        }
    }

    (nets_ipv4, nets_ipv6)
}
