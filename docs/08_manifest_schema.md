# Manifest Schema Notes

Manifests are versioned, signed, and hashable. They deliberately separate:

- boot policy;
- volume encryption policy;
- VM image/capsule policy;
- remote unlock policy;
- recovery policy.

A manifest hash should be stable under canonical JSON serialization. The skeleton stores schemas in `manifests/`.
