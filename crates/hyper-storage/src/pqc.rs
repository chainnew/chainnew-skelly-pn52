#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridKemSuite {
    pub classical: &'static str,
    pub pqc: &'static str,
    pub combiner: &'static str,
}

pub const DEFAULT_TRANSITION_SUITE: HybridKemSuite = HybridKemSuite {
    classical: "x25519",
    pqc: "ml-kem-768",
    combiner: "hkdf-sha384",
};

pub fn combiner_context(volume_id: &str, device_id: &str, policy_version: u64) -> String {
    format!("chainnew-hyper-slate:v1:{volume_id}:{device_id}:{policy_version}")
}
