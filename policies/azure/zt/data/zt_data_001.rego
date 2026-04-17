package argus.azure.zt.data.zt_data_001

import future.keywords.if
import future.keywords.contains

metadata := {
    "id": "zt_data_001",
    "source": "argus-zt",
    "severity": "CRITICAL",
    "pillar": "Data",
    "title": "Storage account allows public blob access",
    "description": "Storage accounts with allowBlobPublicAccess=true can expose any container marked public, leading to data leaks like the infamous AWS S3 bucket exposures.",
    "zt_tenet": "Tenet 1",
    "nist_800_207": "Tenet 1 - All resources considered",
    "nist_800_53": "AC-3",
    "cis_rule": "",
    "mitre_technique": "T1530",
    "mitre_tactic": "Collection",
    "chain_role": "ANCHOR",
    "frameworks": ["nist-800-207", "argus-zt"]
}

violation contains msg if {
    sa := input.storage_accounts[_]
    props := object.get(sa, "properties", {})
    object.get(props, "allowBlobPublicAccess", false) == true
    msg := {
        "rule_id": metadata.id,
        "resource_id": object.get(sa, "id", ""),
        "resource_type": "Microsoft.Storage/storageAccounts",
        "resource_name": object.get(sa, "name", ""),
        "severity": metadata.severity,
        "title": metadata.title,
        "detail": sprintf("Storage account '%s' has allowBlobPublicAccess=true.", [object.get(sa, "name", "")]),
        "evidence": {
            "allowBlobPublicAccess": true
        },
        "chain_role": metadata.chain_role
    }
}
